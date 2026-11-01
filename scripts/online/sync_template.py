#!/usr/bin/env python3
"""把 default-template.yaml 同步进 default-template.ts

⚠️ 为什么需要：
  Worker 运行时用的是 .ts 里内嵌的字符串（打包时无法读 .yaml 文件）。
  yaml 只是源文件，改完必须重新生成 ts，否则改动不生效 —— 这个坑踩过 3 次。

用法：
  python scripts/online/sync_template.py          # 同步
  python scripts/online/sync_template.py --check  # 只检查是否一致
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "worker" / "src" / "default-template.yaml"
DST = ROOT / "worker" / "src" / "default-template.ts"

HEADER = '''/**
 * 默认订阅模板 —— 由用户的本地 Clash 配置提取（已移除全部节点与凭据）
 *
 * 包含：DNS（fake-ip + 分流）、嗅探、rule-providers、分流规则
 * 占位符：{{PROXY}} = 策略组入口名，由 buildClash 注入
 *
 * ⚠️ 本文件由 default-template.yaml 生成 —— 不要直接改这个文件
 *    改完 yaml 后运行：python scripts/online/sync_template.py
 *
 * ⚠️ 本文件不含任何节点信息或凭据
 */

export const DEFAULT_TEMPLATE = '''


def extract_embedded(ts_text: str) -> str | None:
    """从 ts 里把内嵌的字符串取出来（用于 --check）"""
    m = re.search(r"export const DEFAULT_TEMPLATE = (.*);\s*$", ts_text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except Exception:
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="只检查是否一致")
    args = ap.parse_args()

    if not SRC.exists():
        print(f"❌ 找不到 {SRC}")
        return 1

    yaml_text = SRC.read_text(encoding="utf-8")
    new_ts = HEADER + json.dumps(yaml_text, ensure_ascii=False) + ";\n"

    rules = re.findall(
        r"(?m)^\s+-\s+((?:DOMAIN|GEOIP|IP-CIDR|RULE-SET|PROCESS|MATCH|DST)[^\n#]*)$",
        yaml_text)

    if args.check:
        if not DST.exists():
            print("❌ ts 不存在")
            return 1
        old = extract_embedded(DST.read_text(encoding="utf-8"))
        if old == yaml_text:
            print(f"✅ 一致（{len(yaml_text)} 字节，{len(rules)} 条规则）")
            return 0
        print(f"❌ 不一致！yaml {len(yaml_text)} 字节 vs ts 内嵌 "
              f"{len(old) if old else 0} 字节")
        print("   运行 python scripts/online/sync_template.py 修复")
        return 1

    DST.write_text(new_ts, encoding="utf-8")
    print(f"  源:   {SRC.name}  {len(yaml_text)} 字节")
    print(f"  目标: {DST.name}  {len(new_ts)} 字节")
    print(f"  规则: {len(rules)} 条")

    # 关键规则自检
    problems = []
    for r in rules:
        if re.match(r"RULE-SET,(cn|geolocation-cn|cn-ip|private|private-ip)", r):
            if "DIRECT" not in r:
                problems.append(f"CN 规则未走直连: {r}")
    if problems:
        print()
        for p in problems:
            print(f"  ⚠️ {p}")
        return 2

    print("  ✅ CN/private 规则均为 DIRECT")
    return 0


if __name__ == "__main__":
    sys.exit(main())
