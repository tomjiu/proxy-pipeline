#!/usr/bin/env python3
"""
Local / VPS clean filter — run off home IP (use VPS or proxied env).

Reads dist/online (and optional dist/local raw), applies stricter checks,
writes dist/clean/.

Examples:
  python scripts/local/clean_filter.py --input dist/online/http.txt --out dist/clean/http.txt
  python scripts/local/clean_filter.py --nodes dist/online/nodes.txt --out-nodes dist/clean/nodes.txt
"""
from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[2]


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [ln.strip() for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip() and not ln.startswith("#")]


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def check_http(proxy: str, judge: str, timeout: float, require_json_ip: bool) -> tuple[bool, str]:
    try:
        opener = build_opener(ProxyHandler({"http": f"http://{proxy}", "https": f"http://{proxy}"}))
        req = Request(judge, headers={"User-Agent": "proxy-pipeline-clean/1.0"})
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(2000).decode("utf-8", errors="ignore")
            code = getattr(resp, "status", 200) or 200
        if code >= 400:
            return False, "bad_status"
        if require_json_ip:
            if "origin" not in body and "ip" not in body.lower():
                # hijack / captive portal heuristic
                if "<html" in body.lower() or "advert" in body.lower():
                    return False, "hijack_html"
        if "<html" in body.lower() and "ip" not in body.lower():
            return False, "html_hijack"
        return True, "ok"
    except Exception as e:  # noqa: BLE001
        return False, type(e).__name__


def main() -> int:
    ap = argparse.ArgumentParser(description="Strict clean filter for local/VPS")
    ap.add_argument("--input", type=Path, default=ROOT / "dist" / "online" / "http.txt")
    ap.add_argument("--out", type=Path, default=ROOT / "dist" / "clean" / "http.txt")
    ap.add_argument("--nodes", type=Path, default=None, help="optional nodes.txt pass-through copy + count")
    ap.add_argument("--out-nodes", type=Path, default=ROOT / "dist" / "clean" / "nodes.txt")
    ap.add_argument("--judge", default="https://httpbin.org/ip")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--workers", type=int, default=80)
    ap.add_argument("--limit", type=int, default=0, help="0 = all")
    args = ap.parse_args()

    proxies = read_lines(args.input)
    if args.limit and len(proxies) > args.limit:
        proxies = proxies[: args.limit]

    print(f"[clean] input={len(proxies)} judge={args.judge}")
    live: list[str] = []
    reasons: dict[str, int] = {}

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(check_http, p, args.judge, args.timeout, True): p for p in proxies}
        for fut in as_completed(futs):
            p = futs[fut]
            ok, reason = fut.result()
            reasons[reason] = reasons.get(reason, 0) + 1
            if ok:
                live.append(p)

    live = sorted(set(live))
    write_text(args.out, "\n".join(live) + ("\n" if live else ""))

    if args.nodes and args.nodes.exists():
        # Node protocol check needs mihomo/xray — copy for now; hook external checker here.
        nodes = read_lines(args.nodes)
        write_text(args.out_nodes, "\n".join(nodes) + ("\n" if nodes else ""))
        print(f"[clean] nodes copied count={len(nodes)} (wire mihomo check later)")

    report = {
        "at": datetime.now(timezone.utc).isoformat(),
        "input": len(proxies),
        "live": len(live),
        "reasons": reasons,
        "out": str(args.out),
    }
    write_text(ROOT / "dist" / "clean" / "report.json", json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("[clean] run on VPS or proxied env — not bare home IP if targets ban scanners")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
