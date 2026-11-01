#!/usr/bin/env python3
"""
从本地 Clash 配置提取「模板」—— 保留规则/DNS/嗅探等，去掉节点信息

用法：
  python scripts/online/extract_template.py <输入配置> <输出模板>

安全设计：
  - **不在脚本里硬编码任何凭据**（本脚本会被提交到公开仓库）
  - 凭据检测改为「启发式」：检查 UUID 格式、长随机串、私钥格式等
  - 若检测到疑似凭据则拒绝输出

⚠️ 生成的模板文件也不含凭据，可安全提交。
"""
import io, re, sys
from pathlib import Path

if len(sys.argv) >= 3:
    SRC = Path(sys.argv[1])
    OUT = Path(sys.argv[2])
else:
    print("用法: extract_template.py <输入配置> <输出模板>")
    print("例:   extract_template.py ~/.config/clash/config.yaml worker/src/default-template.yaml")
    sys.exit(1)

if not SRC.exists():
    print(f"❌ 输入文件不存在: {SRC}")
    sys.exit(1)

text = SRC.read_text(encoding="utf-8")
lines = text.split("\n")
print(f"源文件: {len(lines)} 行")

# ── 1. 定位要移除的段 ──
top_keys = []
for i, l in enumerate(lines):
    if re.match(r"^[a-zA-Z][a-zA-Z0-9_-]*:", l):
        top_keys.append((i, l.split(":", 1)[0]))

def section_end(start):
    """返回该段的结束行（下一个顶层 key 之前）"""
    for i, k in top_keys:
        if i > start:
            return i
    return len(lines)

# 要移除的段（含节点/凭据）
REMOVE = ["proxy-groups", "proxies", "proxy-providers"]

keep = []
removed_info = []
i = 0
while i < len(lines):
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9_-]*):", lines[i])
    if m and m.group(1) in REMOVE:
        name = m.group(1)
        end = section_end(i)
        removed_info.append((name, i + 1, end))
        i = end
        continue
    keep.append(lines[i])
    i += 1

print(f"移除段落: {[(n, f'{a}-{b}') for n, a, b in removed_info]}")
print(f"保留: {len(keep)} 行")

result = "\n".join(keep)

# ── 2. 安全检查：启发式检测疑似凭据 ──
# 不硬编码具体值，改用通用模式
SUSPICIOUS = [
    # UUID 格式（vless/vmess 凭据）
    (r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "UUID 格式"),
    # base64url 长串（Reality 公私钥、sub token）
    (r"(?<![a-zA-Z0-9+/=_-])[A-Za-z0-9_-]{40,}(?![a-zA-Z0-9+/=_-])", "长随机串(≥40)"),
    # hysteria2/vless 等节点 URI
    (r"(?:hy2|hysteria2|vless|vmess|trojan|ss)://", "节点 URI"),
    # 私钥/公钥字段
    (r"(?:private-?key|public-?key|password|short-?id|uuid)\s*[:=]\s*\S+", "凭据字段"),
]

danger = []
for pat, name in SUSPICIOUS:
    found = re.findall(pat, result, re.I)
    if found:
        danger.append((name, len(found), found[:2]))

if danger:
    print("\n❌ 检测到疑似凭据，拒绝输出：")
    for name, count, samples in danger:
        print(f"   - {name}: {count} 处，例如 {samples}")
    sys.exit(1)

print("✅ 安全扫描通过（无凭据残留）")

# ── 3. 清理规则里对节点的引用 ──
group_names = set()
in_groups = False
for l in lines:
    if re.match(r"^proxy-groups:", l):
        in_groups = True
        continue
    if in_groups and re.match(r"^[a-zA-Z][a-zA-Z0-9_-]*:", l):
        in_groups = False
        continue
    if in_groups:
        m = re.match(r'\s*-\s*name:\s*"([^"]+)"', l)
        if m:
            group_names.add(m.group(1))

print(f"原策略组: {len(group_names)} 个")

# 在 rules 里，把已删除的组名替换为 {{PROXY}} 占位符
for g in group_names:
    result = result.replace(f",{g}", ",{{PROXY}}")
    result = result.replace(f", {g}", ", {{PROXY}}")

placeholders = result.count("{{PROXY}}")
print(f"规则中的组引用 → 占位符: {placeholders} 处")

# ── 4. 加模板头部说明 ──
header = """# ═══════════════════════════════════════════════════════════
#  订阅模板（自动生成）
# ═══════════════════════════════════════════════════════════
#
#  结构：[本模板：DNS / 分流规则 / 嗅探 / 规则集]
#           +  [运行时注入：节点与策略组]
#
#  占位符：{{PROXY}} = 策略组入口名（注入时替换）
#
#  ⚠️ 本文件不含任何节点信息或凭据
#  生成：python scripts/online/extract_template.py <config> <out>
# ═══════════════════════════════════════════════════════════

"""

result = header + result

# ── 5. 输出 ──
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(result, encoding="utf-8")
print(f"\n✅ 已写入: {OUT}")
print(f"   行数: {len(result.split(chr(10)))}")

print("\n保留的顶层段:")
for l in result.split("\n"):
    if re.match(r"^[a-zA-Z][a-zA-Z0-9_-]*:", l):
        print(f"   {l[:60]}")
