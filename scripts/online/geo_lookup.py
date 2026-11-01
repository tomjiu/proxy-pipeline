#!/usr/bin/env python3
"""
IP 地理定位 —— 为节点生成 国家+城市 标签

设计：
  - 三级 fallback：ip-api.com → ipwho.is → ipinfo.io
  - 本地缓存 dist/geo-cache.json（IP → 地区，永久有效，IP 归属不会变）
  - 并发查询（默认 10 并发，ip-api 免费限 45/分钟）
  - 缓存命中则零网络请求

用法：
  python scripts/online/geo_lookup.py --input dist/clean/clash.yaml
  python scripts/online/geo_lookup.py --ips "1.2.3.4,5.6.7.8"

输出：
  - 更新 dist/geo-cache.json
  - 输出 dist/clean/geo.json（本次用到的 IP → 地区）
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / "dist" / "geo-cache.json"

UA = {"User-Agent": "Mozilla/5.0 (compatible; proxy-pipeline/1.0)"}

# 国家代码 → 国旗 emoji
def flag_of(code: str) -> str:
    if not code or len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())


# ── 查询后端 ──

def _get_json(url: str, timeout: float = 8.0):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="ignore"))


def via_ipapi(ip: str):
    """ip-api.com — 快（11 req/s），含城市，免费限 45/分钟"""
    d = _get_json(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city")
    if d.get("status") != "success":
        return None
    return {
        "code": (d.get("countryCode") or "").upper(),
        "country": d.get("country") or "",
        "city": d.get("city") or "",
        "src": "ip-api",
    }


def via_ipwho(ip: str):
    """ipwho.is — 稳定，含城市"""
    d = _get_json(f"https://ipwho.is/{ip}")
    if not d.get("success"):
        return None
    return {
        "code": (d.get("country_code") or "").upper(),
        "country": d.get("country") or "",
        "city": d.get("city") or "",
        "src": "ipwho",
    }


def via_ipinfo(ip: str):
    """ipinfo.io — 备用，通常无城市名"""
    d = _get_json(f"https://ipinfo.io/{ip}/json")
    if "country" not in d:
        return None
    return {
        "code": (d.get("country") or "").upper(),
        "country": "",
        "city": d.get("city") or "",
        "src": "ipinfo",
    }


BACKENDS = [via_ipapi, via_ipwho, via_ipinfo]


def lookup(ip: str) -> dict | None:
    """三级 fallback 查询单个 IP。"""
    for fn in BACKENDS:
        try:
            r = fn(ip)
            if r and r.get("code"):
                return r
        except urllib.error.HTTPError as e:
            if e.code == 429:      # 限流，换下一个
                continue
        except Exception:
            continue
    return None


# ── 主逻辑 ──

def load_cache() -> dict:
    if CACHE.exists():
        try:
            return json.loads(CACHE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"ips": {}, "updated_at": None}


def save_cache(cache: dict) -> None:
    cache["updated_at"] = datetime.now(timezone.utc).isoformat()
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(
        json.dumps(cache, ensure_ascii=False, indent=1, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def extract_ips(yaml_text: str) -> list[str]:
    """从 clash.yaml 提取所有 server IP（排除域名）。"""
    servers = re.findall(r"^\s+server:\s*\"?([0-9a-zA-Z\.\-]+)\"?", yaml_text, re.M)
    ips = []
    seen = set()
    for s in servers:
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", s) and s not in seen:
            seen.add(s)
            ips.append(s)
    return ips


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path, help="clash.yaml 路径")
    ap.add_argument("--ips", help="逗号分隔的 IP 列表")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--limit", type=int, default=0, help="最多查询几个（0=不限）")
    ap.add_argument("--out", type=Path, help="输出 geo.json 路径")
    args = ap.parse_args()

    ips: list[str] = []
    if args.ips:
        ips = [s.strip() for s in args.ips.split(",") if s.strip()]
    elif args.input and args.input.exists():
        ips = extract_ips(args.input.read_text(encoding="utf-8", errors="ignore"))
    else:
        print("need --input or --ips", file=sys.stderr)
        return 1

    if args.limit:
        ips = ips[: args.limit]

    print(f"[geo] total IPs: {len(ips)}")

    cache = load_cache()
    cached = cache.setdefault("ips", {})

    todo = [ip for ip in ips if ip not in cached]
    hit = len(ips) - len(todo)
    print(f"[geo] cache hit: {hit} / {len(ips)}  → need lookup: {len(todo)}")

    if todo:
        # 限流安全：ip-api 免费 45/分钟 → 8 并发足够
        t0 = time.time()
        ok, fail = 0, 0
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(lookup, ip): ip for ip in todo}
            for i, f in enumerate(as_completed(futs), 1):
                ip = futs[f]
                r = f.result()
                if r:
                    cached[ip] = r
                    ok += 1
                else:
                    cached[ip] = {"code": "", "country": "", "city": "", "src": "fail"}
                    fail += 1
                if i % 25 == 0 or i == len(todo):
                    rate = i / max(time.time() - t0, 0.1)
                    print(f"  … {i}/{len(todo)}  ok={ok} fail={fail}  ({rate:.1f} ip/s)")
        save_cache(cache)

    # 统计
    from collections import Counter
    codes = Counter(v.get("code") or "??" for ip, v in cached.items() if ip in ips)
    print(f"[geo] resolved: {len([1 for ip in ips if cached.get(ip, {}).get('code')])} / {len(ips)}")
    print(f"[geo] top countries: {codes.most_common(10)}")

    if args.out:
        out = {ip: cached.get(ip, {}) for ip in ips}
        # 附加国旗
        for ip, v in out.items():
            v["flag"] = flag_of(v.get("code") or "")
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            json.dumps({"updated_at": datetime.now(timezone.utc).isoformat(),
                        "ips": out}, ensure_ascii=False, indent=1) + "\n",
            encoding="utf-8",
        )
        print(f"[geo] wrote {args.out} ({len(out)} entries)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
