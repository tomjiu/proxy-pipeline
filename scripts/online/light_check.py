#!/usr/bin/env python3
"""Optional light connectivity check on a sample of online pool (Actions-friendly cap)."""
from __future__ import annotations

import argparse
import json
import random
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DIST_ONLINE, SOURCES, read_lines, write_text  # noqa: E402

try:
    import socks  # type: ignore
    from sockshandler import SocksiPyHandler  # type: ignore
    import urllib.request as ureq

    HAS_SOCKS = True
except Exception:  # noqa: BLE001
    HAS_SOCKS = False


def check_http_proxy(proxy: str, judge: str, timeout: float) -> bool:
    # proxy is host:port — try as HTTP proxy
    try:
        from urllib.request import build_opener, ProxyHandler

        opener = build_opener(ProxyHandler({"http": f"http://{proxy}", "https": f"http://{proxy}"}))
        req = Request(judge, headers={"User-Agent": "proxy-pipeline-check/1.0"})
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(500)
        return bool(body)
    except Exception:  # noqa: BLE001
        return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=300, help="max proxies to test")
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--workers", type=int, default=40)
    args = ap.parse_args()

    judges = read_lines(SOURCES / "judge-urls.txt") or ["https://api.ipify.org"]
    judge = judges[0]

    http_list = read_lines(DIST_ONLINE / "http.txt")
    if not http_list:
        print("[check] no http.txt — skip")
        write_text(DIST_ONLINE / "http.live.txt", "")
        return 0

    sample = http_list if len(http_list) <= args.sample else random.sample(http_list, args.sample)
    live: list[str] = []
    print(f"[check] testing {len(sample)}/{len(http_list)} via {judge} socks_lib={HAS_SOCKS}")

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(check_http_proxy, p, judge, args.timeout): p for p in sample}
        for fut in as_completed(futs):
            p = futs[fut]
            try:
                ok = fut.result()
            except Exception:  # noqa: BLE001
                ok = False
            if ok:
                live.append(p)

    live = sorted(set(live))
    write_text(DIST_ONLINE / "http.live.txt", "\n".join(live) + ("\n" if live else ""))
    meta_path = DIST_ONLINE / "meta.json"
    meta = {}
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["light_check"] = {
        "at": datetime.now(timezone.utc).isoformat(),
        "sampled": len(sample),
        "live_http": len(live),
        "judge": judge,
    }
    write_text(meta_path, json.dumps(meta, ensure_ascii=False, indent=2) + "\n")
    print(f"[check] live_http={len(live)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
