#!/usr/bin/env python3
"""渲染模板（注入假节点 + 策略组）→ 供 mihomo -t 校验

⚠️ 用行处理而非正则：
   之前用 (?ms)^proxy-groups:\n(?:.*\n)*?(?=^rules:) 触发灾难性回溯，脚本卡死。

用法：
  python scripts/online/render_template_check.py [输出路径]
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TPL = ROOT / "worker" / "src" / "default-template.yaml"
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(r"E:\temp\tpl-check\config.yaml")

NODE_LINES = [
    "  - name: TEST-NODE",
    "    type: vless",
    "    server: 1.2.3.4",
    "    port: 443",
    "    uuid: 00000000-0000-0000-0000-000000000000",
    "    network: tcp",
    "    tls: true",
    "    udp: true",
]

GROUP_LINES = [
    "proxy-groups:",
    "  - name: PROXY",
    "    type: select",
    "    proxies:",
    "      - TEST-NODE",
    "      - DIRECT",
    "      - REJECT",
    "",
]


def main() -> int:
    text = TPL.read_text(encoding="utf-8")
    text = text.replace("{{PROXY}}", "PROXY")
    lines = text.split("\n")

    out: list[str] = []
    seen_proxies = False
    seen_groups = False
    in_section = None            # 当前正在跳过的段

    SKIP_SECTIONS = {"proxies", "proxy-groups"}

    for line in lines:
        # 顶层键（列 0 且形如 key:）
        if line and not line[0].isspace() and line.rstrip().endswith(":") \
                and ":" in line:
            key = line.split(":", 1)[0]
            in_section = None

            if key == "proxies":
                out.append("proxies:")
                out.extend(NODE_LINES)
                seen_proxies = True
                in_section = "proxies"       # 跳过原有节点
                continue
            if key == "proxy-groups":
                out.extend(GROUP_LINES)
                seen_groups = True
                in_section = "proxy-groups"
                continue

            out.append(line)
            continue

        # 在跳过的段里 → 丢弃原有内容
        if in_section in SKIP_SECTIONS:
            # 遇到下一个顶层键就退出（上面已处理）
            continue

        out.append(line)

    # 若原模板没有 proxies / proxy-groups，在 rules 前插入
    if not seen_proxies or not seen_groups:
        final: list[str] = []
        inserted = False
        for line in out:
            if not inserted and line.startswith("rules:"):
                if not seen_proxies:
                    final.append("proxies:")
                    final.extend(NODE_LINES)
                if not seen_groups:
                    final.extend(GROUP_LINES)
                inserted = True
            final.append(line)
        out = final

    rendered = "\n".join(out)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, encoding="utf-8")

    n_rules = sum(
        1 for l in out
        if l.lstrip().startswith("- ")
        and any(l.lstrip()[2:].startswith(p) for p in
                ("DOMAIN", "GEOIP", "IP-CIDR", "RULE-SET", "PROCESS", "MATCH", "DST"))
    )
    n_nodes = sum(1 for l in out if l.strip() == "- name: TEST-NODE")
    n_groups = sum(1 for l in out if l.strip() == "- name: PROXY")

    print(f"  输出: {OUT}")
    print(f"  节点: {n_nodes}   策略组: {n_groups}   规则: {n_rules}")

    if n_nodes < 1 or n_groups < 1:
        print("  ⚠️ 注入失败")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
