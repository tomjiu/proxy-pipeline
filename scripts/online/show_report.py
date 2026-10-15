#!/usr/bin/env python3
"""
输出测活报告为 markdown 表格（供 GitHub Step Summary 使用）
"""
import json
import sys
from pathlib import Path

REPORT = Path("dist/clean/check_report.json")

FIELDS = [
    ("mode", "模式"),
    ("input", "输入"),
    ("tested", "实测"),
    ("tested_ok", "通过"),
    ("tested_fail", "失败"),
    ("kept_skip_retest", "跳过重测"),
    ("alive_output", "存活输出"),
    ("clean_output", "洁净输出"),
    ("db_size", "数据库"),
    ("timeout_ms", "超时(ms)"),
]


def main() -> int:
    if not REPORT.exists():
        print("(无 check_report.json)")
        return 0

    try:
        d = json.loads(REPORT.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"(解析失败: {e})")
        return 0

    print("| 项 | 值 |")
    print("|---|---|")
    for key, label in FIELDS:
        if key in d:
            print(f"| {label} | {d[key]} |")

    # 通过率
    tested = d.get("tested") or 0
    ok = d.get("tested_ok") or 0
    if tested:
        print(f"| 通过率 | {ok * 100 // tested}% |")

    reasons = d.get("clean_reasons")
    if reasons:
        print("")
        print("洁净判定:")
        for k, v in reasons.items():
            print(f"- {k}: {v}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
