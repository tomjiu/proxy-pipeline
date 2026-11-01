#!/usr/bin/env python3
"""
节点重命名 —— 🇯🇵 JP Tokyo 01 格式 + 按地区分组

输入：
  - dist/clean/clash.yaml     已测活节点
  - dist/clean/geo.json       IP 地理定位（geo_lookup.py 产出）
  - dist/clean/quality_tiers.json  质量分档（ai_probe.py 产出，可选）

输出：
  - dist/clean/clash-renamed.yaml   重命名 + 按国家分组的订阅

命名规则：
  🇯🇵 JP Tokyo 01
  ↑ 国旗  ↑国家码 ↑城市 ↑同地区序号

分组策略：
  - 按国家建 url-test 组（自动选最快）
  - 按质量分档建 select 组（S 档优先）
  - 保留一个 AUTO 总组

用法：
  python scripts/online/rename_nodes.py
  python scripts/online/rename_nodes.py --min-tier S    # 只要优质节点
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLEAN = ROOT / "dist" / "clean"

# 国家代码 → 中文名（常用）
CN_NAME = {
    "US": "美国", "JP": "日本", "KR": "韩国", "SG": "新加坡", "HK": "香港",
    "TW": "台湾", "DE": "德国", "NL": "荷兰", "GB": "英国", "FR": "法国",
    "CA": "加拿大", "AU": "澳大利亚", "RU": "俄罗斯", "IT": "意大利",
    "SE": "瑞典", "FI": "芬兰", "PL": "波兰", "EE": "爱沙尼亚",
    "CH": "瑞士", "AT": "奥地利", "BE": "比利时", "DK": "丹麦",
    "NO": "挪威", "IE": "爱尔兰", "ES": "西班牙", "PT": "葡萄牙",
    "TR": "土耳其", "IN": "印度", "ID": "印尼", "MY": "马来西亚",
    "TH": "泰国", "VN": "越南", "PH": "菲律宾", "BR": "巴西",
    "AR": "阿根廷", "MX": "墨西哥", "CL": "智利", "ZA": "南非",
    "AE": "阿联酋", "IL": "以色列", "SA": "沙特", "UA": "乌克兰",
    "CZ": "捷克", "RO": "罗马尼亚", "HU": "匈牙利", "BG": "保加利亚",
    "LT": "立陶宛", "LV": "拉脱维亚", "MD": "摩尔多瓦", "RS": "塞尔维亚",
    "CN": "中国", "MO": "澳门", "NZ": "新西兰", "IS": "冰岛",
}

# 从节点名解析地区的正则（做 geo.json 缺失时的兜底）
NAME_PATTERNS = [
    (re.compile(r"[\U0001F1E6-\U0001F1FF]{2}"), "flag"),
    (re.compile(r"\b(US|JP|KR|SG|HK|TW|DE|NL|GB|FR|CA|AU|RU|IT|SE|FI|PL|EE|CH|TR|IN|ID|MY|TH|VN|PH|BR|AR|MX|ZA|AE|IL)\b"), "cc"),
]


def flag_of(code: str) -> str:
    if not code or len(code) != 2 or not code.isalpha():
        return "🏴"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())


def parse_region_from_name(name: str) -> tuple[str, str]:
    """从节点名解析 (国家码, 城市)。返回空字符串表示未识别。"""
    # 国旗 emoji
    m = re.search(r"[\U0001F1E6-\U0001F1FF]{2}", name)
    if m:
        code = "".join(chr(ord(c) - 0x1F1E6 + ord("A")) for c in m.group(0))
        # 尝试从名字里找城市
        city = ""
        cm = re.search(r"[-\s]([A-Z][a-z]{3,})", name)
        if cm:
            city = cm.group(1)
        return code, city
    # 2 字母国家码
    m = re.search(r"\b(US|JP|KR|SG|HK|TW|DE|NL|GB|FR|CA|AU|RU|IT|SE|FI|PL|EE|CH|TR|IN|ID|MY|TH|VN|PH|BR|AR|MX|ZA|AE|IL)\b", name)
    if m:
        return m.group(1), ""
    return "", ""


def extract_proxies(yaml_text: str) -> list[dict]:
    """
    解析 clash.yaml 的 proxies 段，返回节点列表。
    每个节点: {name, type, server, port, raw_block, fields}
    """
    m = re.search(r"(?m)^proxies:\s*$", yaml_text)
    if not m:
        return []
    rest = yaml_text[m.end():]
    end = re.search(r"(?m)^proxy-groups:\s*$", rest)
    body = rest[: end.start()] if end else rest

    out = []
    for ch in re.split(r"(?m)^  - name: ", body)[1:]:
        raw = "  - name: " + ch.rstrip() + "\n"
        first = ch.split("\n", 1)[0].strip()
        name = first.strip().strip('"').replace('\\"', '"')

        def field(k):
            mm = re.search(rf"(?m)^    {re.escape(k)}:\s*(.+?)\s*$", ch)
            if not mm:
                return ""
            v = mm.group(1).strip()
            if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                v = v[1:-1]
            return v

        typ = field("type")
        server = field("server")
        port = field("port")
        if name and typ and server:
            out.append({
                "name": name, "type": typ, "server": server,
                "port": port, "raw": raw,
            })
    return out


def rename_block(raw: str, old_name: str, new_name: str) -> str:
    """替换节点块里的 name 字段。"""
    # 第一行是 "  - name: xxx"
    lines = raw.split("\n")
    # 安全引用
    if re.search(r'[:#{}[\],&*?|>!%@"`]', new_name) or " " in new_name:
        quoted = '"' + new_name.replace("\\", "\\\\").replace('"', '\\"') + '"'
    else:
        quoted = new_name
    lines[0] = "  - name: " + quoted
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path, default=CLEAN / "clash.yaml")
    ap.add_argument("--geo", type=Path, default=CLEAN / "geo.json")
    ap.add_argument("--quality", type=Path, default=CLEAN / "quality_tiers.json")
    ap.add_argument("--out", type=Path, default=CLEAN / "clash-renamed.yaml")
    ap.add_argument("--min-tier", choices=("S", "A", "all"), default="all",
                    help="只保留该档及以上的节点")
    ap.add_argument("--group-by-country", action="store_true", default=True)
    args = ap.parse_args()

    if not args.input.exists():
        print(f"missing {args.input}")
        return 1

    text = args.input.read_text(encoding="utf-8", errors="ignore")
    proxies = extract_proxies(text)
    print(f"[rename] proxies: {len(proxies)}")
    if not proxies:
        return 1

    # ── 加载地理数据 ──
    geo = {}
    if args.geo.exists():
        try:
            geo = (json.loads(args.geo.read_text(encoding="utf-8")) or {}).get("ips") or {}
        except Exception:
            pass
    print(f"[rename] geo entries: {len(geo)}")

    # ── 加载质量分档 ──
    tiers = {}
    if args.quality.exists():
        try:
            q = json.loads(args.quality.read_text(encoding="utf-8"))
            for n in (q.get("tier_S") or []):
                tiers[n] = "S"
            for n in (q.get("tier_A") or []):
                tiers[n] = "A"
        except Exception:
            pass
    print(f"[rename] quality entries: {len(tiers)}")

    # ── 过滤 + 命名 ──
    filtered = []
    if args.min_tier != "all":
        want = {"S": {"S"}, "A": {"S", "A"}}[args.min_tier]
        for p in proxies:
            if tiers.get(p["name"]) in want:
                filtered.append(p)
        print(f"[rename] after tier filter ({args.min_tier}): {len(filtered)}")
    else:
        filtered = proxies

    # 统计每个 (国家, 城市) 的数量以生成序号
    region_counter: dict[tuple, int] = defaultdict(int)
    renamed = []
    unknown = 0

    for p in filtered:
        ip = p["server"]
        g = geo.get(ip) or {}

        code = (g.get("code") or "").upper()
        city = g.get("city") or ""

        # geo 缺失时从节点名兜底
        if not code:
            code, name_city = parse_region_from_name(p["name"])
            if not city:
                city = name_city

        if not code:
            unknown += 1
            code = "XX"
            city = "Unknown"

        region_counter[(code, city)] += 1
        idx = region_counter[(code, city)]

        flag = flag_of(code)
        city_clean = re.sub(r"[^\w\s\-]", "", city)[:18] or "Unknown"
        new_name = f"{flag} {code} {city_clean} {idx:02d}"

        renamed.append({
            **p,
            "old_name": p["name"],
            "new_name": new_name,
            "code": code,
            "city": city_clean,
            "tier": tiers.get(p["name"], "?"),
            "raw": rename_block(p["raw"], p["name"], new_name),
        })

    print(f"[rename] renamed: {len(renamed)}  (unknown region: {unknown})")

    # ── 国家统计 ──
    by_country = defaultdict(list)
    for n in renamed:
        by_country[n["code"]].append(n)
    print("[rename] top countries:")
    for code, items in sorted(by_country.items(), key=lambda kv: -len(kv[1]))[:12]:
        print(f"    {flag_of(code)} {code} ({CN_NAME.get(code, code)}): {len(items)}")

    # ── 生成 YAML ──
    now = datetime.now(timezone.utc).isoformat()
    lines = [
        "# Renamed subscription — country/city labels",
        f"# updated: {now}",
        f"# nodes: {len(renamed)}  filter: tier>={args.min_tier}",
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: warning",
        "external-controller: 127.0.0.1:9090",
        "proxies:",
    ]
    for n in renamed:
        lines.append(n["raw"].rstrip("\n"))

    # 策略组
    def q(name: str) -> str:
        if re.search(r'[:#{}[\],&*?|>!%@"`\s]', name):
            return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'
        return name

    lines.append("proxy-groups:")
    # 总入口
    all_names = [n["new_name"] for n in renamed]
    lines.append('  - name: "🚀 PROXY"')
    lines.append("    type: select")
    lines.append("    proxies:")
    lines.append('      - "⚡ AUTO"')
    lines.append('      - "🏆 BEST"')
    lines.append('      - DIRECT')
    for cn in sorted(by_country.keys(), key=lambda c: -len(by_country[c]))[:15]:
        lines.append(f"      - {q(flag_of(cn) + ' ' + cn + ' ' + CN_NAME.get(cn, cn))}")
    lines.append("      - " + q("🇺🇳 ALL"))

    # AUTO（全部）
    lines.append('  - name: "⚡ AUTO"')
    lines.append("    type: url-test")
    lines.append("    url: \"http://www.gstatic.com/generate_204\"")
    lines.append("    interval: 300")
    lines.append("    tolerance: 50")
    lines.append("    proxies:")
    for n in renamed:
        lines.append("      - " + q(n["new_name"]))

    # BEST（仅 S 档）
    s_nodes = [n for n in renamed if n["tier"] == "S"]
    if s_nodes:
        lines.append('  - name: "🏆 BEST"')
        lines.append("    type: url-test")
        lines.append("    url: \"http://www.gstatic.com/generate_204\"")
        lines.append("    interval: 300")
        lines.append("    tolerance: 50")
        lines.append("    proxies:")
        for n in s_nodes:
            lines.append("      - " + q(n["new_name"]))

    # 按国家分组
    for code in sorted(by_country.keys(), key=lambda c: -len(by_country[c])):
        items = by_country[code]
        label = f"{flag_of(code)} {code} {CN_NAME.get(code, code)}"
        lines.append(f"  - name: {q(label)}")
        lines.append("    type: url-test")
        lines.append("    url: \"http://www.gstatic.com/generate_204\"")
        lines.append("    interval: 300")
        lines.append("    proxies:")
        for n in items:
            lines.append("      - " + q(n["new_name"]))

    # ALL
    lines.append('  - name: "🇺🇳 ALL"')
    lines.append("    type: select")
    lines.append("    proxies:")
    for n in renamed:
        lines.append("      - " + q(n["new_name"]))

    # 规则
    lines.append("rules:")
    lines.append("  - GEOIP,LAN,DIRECT,no-resolve")
    lines.append("  - GEOIP,CN,DIRECT")
    lines.append('  - MATCH,"🚀 PROXY"')

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[rename] wrote {args.out}")

    # 元数据
    meta = {
        "updated_at": now,
        "total": len(renamed),
        "filter": f"tier>={args.min_tier}",
        "countries": {c: len(v) for c, v in sorted(by_country.items(), key=lambda kv: -len(kv[1]))},
        "unknown_region": unknown,
        "tier_counts": {
            t: len([n for n in renamed if n["tier"] == t])
            for t in ("S", "A", "B", "X", "?")
        },
    }
    (CLEAN / "rename_report.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(meta["countries"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
