#!/usr/bin/env python3
"""
显示订阅统计（供 sub-refresh.yml 调用）

从 stdin 读 Worker 的 /sub/<token>.json 输出，格式化为易读文本。
"""
import json
import sys


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        print("    (empty response)")
        return 0
    try:
        d = json.loads(raw)
    except Exception as e:
        print(f"    (parse failed: {e})")
        return 0

    nodes = d.get("nodes")
    dups = d.get("duplicates")
    print(f"    nodes: {nodes}  duplicates: {dups}")

    t = d.get("traffic") or {}
    if t:
        print(
            "    traffic: %.2f / %.0f GB (%.3f%%)  remain %.2f GB"
            % (
                t.get("used_gb", 0),
                t.get("total_gb", 0),
                t.get("pct", 0),
                t.get("remain_gb", 0),
            )
        )

    sources = d.get("sources") or []
    bad = [s for s in sources if not s.get("ok")]
    if bad:
        print("    failed sources:")
        for s in bad:
            url = (s.get("url") or "")[:48]
            print(f"      - {url}  {s.get('error') or ''}")
    else:
        print(f"    sources: all ok ({len(sources)})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
