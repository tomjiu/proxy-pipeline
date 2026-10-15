#!/usr/bin/env python3
"""输出 CN 测活报告为 markdown（供 GitHub Step Summary）"""
import json
from pathlib import Path

P = Path("dist/clean/cn-result.json")


def main() -> int:
    if not P.exists():
        print("(无 cn-result.json)")
        return 0

    try:
        d = json.loads(P.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"(解析失败: {e})")
        return 0

    print("| 项 | 值 |")
    print("|---|---|")
    print(f"| 输入 | {d.get('input', 0)} |")
    print(f"| 实测 | {d.get('tested', 0)} |")
    print(f"| **CN 可用** | **{d.get('cn_ok', 0)}** |")
    print(f"| 耗时 | {d.get('elapsed_s', 0)}s |")
    print(f"| 时间 | {d.get('at', '')} |")

    v = d.get("verdicts") or {}
    if v:
        print("")
        print("判定分布:")
        for k, n in v.items():
            print(f"- {k}: {n}")

    bt = d.get("by_type") or {}
    if bt:
        print("")
        print("可用协议:")
        for k, n in sorted(bt.items(), key=lambda x: -x[1]):
            print(f"- {k}: {n}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
