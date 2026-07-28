#!/usr/bin/env python3
"""
Online job: mirror many public raw lists + optional TG/subs, then DEDupe.

Pool sources: sources/pool-urls.txt  lines =  proto|url
  proto in http|https|socks4|socks5|auto
Dedup key: ip:port (and per-protocol files). Same host:port from 10 repos → 1 line.
"""
from __future__ import annotations

import base64
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (  # noqa: E402
    DIST_ONLINE,
    SOURCES,
    extract_node_uris,
    is_public_ip,
    parse_ip_ports,
    read_lines,
    write_text,
)

UA = "Mozilla/5.0 (compatible; proxy-pipeline-mirror/1.1)"
TIMEOUT = 30
MAX_WORKERS = 16
# skip absurdly huge single responses (bytes)
MAX_BODY = 12 * 1024 * 1024


def fetch(url: str) -> tuple[str, str | None]:
    try:
        req = Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
        with urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            return "", f"body_too_large>{MAX_BODY}"
        for enc in ("utf-8", "gbk", "latin-1"):
            try:
                return raw.decode(enc), None
            except UnicodeDecodeError:
                continue
        return raw.decode("utf-8", errors="ignore"), None
    except Exception as e:  # noqa: BLE001
        return "", f"{type(e).__name__}: {e}"


def parse_pool_sources() -> list[tuple[str, str]]:
    """Return list of (proto, url)."""
    rows: list[tuple[str, str]] = []
    path = SOURCES / "pool-urls.txt"
    for line in read_lines(path):
        if "|" in line:
            proto, url = line.split("|", 1)
            proto, url = proto.strip().lower(), url.strip()
        else:
            # backward compatible: bare URL
            proto, url = "auto", line.strip()
        if not url.startswith("http"):
            continue
        if proto == "https":
            proto = "http"
        if proto not in ("http", "socks4", "socks5", "auto"):
            proto = "auto"
        rows.append((proto, url))
    # dedupe identical URLs keep first proto
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for proto, url in rows:
        if url in seen:
            continue
        seen.add(url)
        out.append((proto, url))
    return out


def hint_proto_from_url(url: str) -> str:
    u = url.lower()
    if "socks5" in u:
        return "socks5"
    if "socks4" in u:
        return "socks4"
    if "socks" in u and "socks5" not in u and "socks4" not in u:
        return "socks5"
    if "http" in u:
        return "http"
    return "unknown"


def short_name(url: str) -> str:
    try:
        p = urlparse(url)
        path = p.path.rstrip("/").split("/")
        host = p.netloc.replace("raw.githubusercontent.com", "gh").replace("cdn.jsdelivr.net", "jsd")
        tail = "/".join(path[-2:]) if len(path) >= 2 else (path[-1] if path else "")
        return f"{host}/{tail}"[:80]
    except Exception:  # noqa: BLE001
        return url[:80]


def mirror_pools() -> tuple[dict[str, set[str]], list[dict]]:
    """
    buckets: http/socks4/socks5/unknown -> set of ip:port
    Global dedupe: each ip:port assigned to strongest known proto if conflict:
      socks5 > socks4 > http > unknown
    """
    sources = parse_pool_sources()
    print(f"[pool] mirror sources={len(sources)}")

    # addr -> set of protos seen
    addr_protos: dict[str, set[str]] = {}
    per_source: list[dict] = []

    def one(item: tuple[str, str]) -> tuple[str, str, list[tuple[str, str]], str | None]:
        proto_hint, url = item
        body, err = fetch(url)
        if err:
            return proto_hint, url, [], err
        hint = proto_hint if proto_hint != "auto" else hint_proto_from_url(url)
        pairs: list[tuple[str, str]] = []
        for ip, port, proto in parse_ip_ports(body):
            p = (proto or hint or "unknown").lower()
            if p == "https":
                p = "http"
            if p not in ("http", "socks4", "socks5"):
                p = hint if hint in ("http", "socks4", "socks5") else "unknown"
            pairs.append((p, f"{ip}:{port}"))
        # also plain line ip:port without regex miss — parse_ip_ports covers most
        return proto_hint, url, pairs, None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = [ex.submit(one, s) for s in sources]
        for fut in as_completed(futs):
            proto_hint, url, pairs, err = fut.result()
            name = short_name(url)
            if err:
                print(f"  ! {name} -> {err}")
                per_source.append({"source": name, "url": url, "ok": False, "error": err, "count": 0})
                continue
            # local dedupe in this file
            local: dict[str, str] = {}
            for p, addr in pairs:
                # prefer socks5 over http if same file lists both styles
                prev = local.get(addr)
                if prev is None or _rank(p) > _rank(prev):
                    local[addr] = p
            for addr, p in local.items():
                addr_protos.setdefault(addr, set()).add(p)
            print(f"  + {name} unique={len(local)}")
            per_source.append(
                {
                    "source": name,
                    "url": url,
                    "ok": True,
                    "count": len(local),
                    "hint": proto_hint,
                }
            )

    buckets: dict[str, set[str]] = {"http": set(), "socks4": set(), "socks5": set(), "unknown": set()}
    for addr, protos in addr_protos.items():
        best = max(protos, key=_rank)
        if best not in buckets:
            best = "unknown"
        buckets[best].add(addr)

    return buckets, per_source


def _rank(proto: str) -> int:
    return {"socks5": 3, "socks4": 2, "http": 1, "unknown": 0}.get(proto, 0)


def scrape_tg_channels() -> tuple[set[str], set[str]]:
    channels = read_lines(SOURCES / "tg-channels.txt")
    nodes: set[str] = set()
    proxies: set[str] = set()
    print(f"[tg] channels={len(channels)}")
    for name in channels:
        name = name.lstrip("@")
        url = f"https://t.me/s/{name}"
        body, err = fetch(url)
        if err or not body:
            print(f"  ! {name} -> {err or 'empty'}")
            continue
        body = unquote(body.replace("&amp;", "&"))
        uris = extract_node_uris(body)
        for u in uris:
            nodes.add(u)
        for ip, port, _proto in parse_ip_ports(body):
            if is_public_ip(ip):
                proxies.add(f"{ip}:{port}")
        print(f"  + {name}: nodes={len(uris)}")
        time.sleep(0.6)
    return nodes, proxies


def maybe_decode_subscription(text: str) -> str:
    """Decode base64 whole-file subs; keep plain/URI/yaml as-is."""
    raw = text.strip()
    if "proxies:" in raw or raw.startswith("ss://") or raw.startswith("vless://"):
        return raw
    # single-line or compact base64
    compact = re.sub(r"\s+", "", raw)
    if len(compact) < 32:
        return raw
    try:
        pad = "=" * (-len(compact) % 4)
        dec = base64.b64decode(compact + pad, validate=False).decode("utf-8", errors="ignore")
        if any(
            s in dec
            for s in (
                "ss://",
                "vmess://",
                "trojan://",
                "vless://",
                "hysteria2://",
                "hy2://",
                "proxies:",
            )
        ):
            return dec
    except Exception:  # noqa: BLE001
        pass
    # line-wise base64 (some lists)
    lines_out: list[str] = []
    for line in raw.splitlines():
        s = line.strip()
        if not s:
            continue
        if any(s.lower().startswith(x) for x in ("ss://", "vmess://", "vless://", "trojan://", "hy2://", "hysteria2://")):
            lines_out.append(s)
            continue
        try:
            pad = "=" * (-len(s) % 4)
            dec = base64.b64decode(s + pad, validate=False).decode("utf-8", errors="ignore")
            if any(dec.lower().startswith(x) for x in ("ss://", "vmess://", "vless://", "trojan://", "hy2", "hysteria")):
                lines_out.append(dec.strip())
            elif "://" in dec:
                lines_out.append(dec.strip())
        except Exception:  # noqa: BLE001
            lines_out.append(s)
    return "\n".join(lines_out) if lines_out else raw


def scrape_subs() -> set[str]:
    urls = read_lines(SOURCES / "sub-urls.txt")
    nodes: set[str] = set()
    print(f"[sub] sources={len(urls)}")
    for url in urls:
        body, err = fetch(url)
        if err or not body:
            print(f"  ! sub {short_name(url)} -> {err or 'empty'}")
            continue
        text = maybe_decode_subscription(body)
        before = len(nodes)
        for u in extract_node_uris(text):
            nodes.add(u)
        print(f"  + sub {short_name(url)} new_uris={len(nodes) - before} total={len(nodes)}")
        time.sleep(0.25)
        # soft cap — still fetch remaining sources if we lack non-ss diversity
        if len(nodes) >= 25000:
            schemes = {u.split("://", 1)[0].lower() for u in nodes}
            if len(schemes) >= 4:
                print("  ~ node cap reached with diverse schemes, stop")
                break
    return nodes


def main() -> int:
    DIST_ONLINE.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc).isoformat()

    buckets, per_source = mirror_pools()
    tg_nodes, tg_proxies = scrape_tg_channels()
    sub_nodes = scrape_subs()

    for addr in tg_proxies:
        # don't invent proto — unknown unless already known
        if not any(addr in buckets[k] for k in buckets):
            buckets["http"].add(addr)  # bare ip:port from TG often http gateways; VPS clean later

    # cross-file: ensure each ip:port appears in only one protocol file (already via best rank)
    http = sorted(buckets["http"])
    socks4 = sorted(buckets["socks4"])
    socks5 = sorted(buckets["socks5"])
    unknown = sorted(buckets["unknown"])
    # unknown merged into http for usability
    http_all = sorted(set(http) | set(unknown))

    all_pool = sorted(set(http_all) | set(socks4) | set(socks5))
    # diversify by scheme so vless/vmess/trojan/hy2 not wiped by sorted ss flood
    merged = list(tg_nodes | sub_nodes)
    by_scheme: dict[str, list[str]] = {}
    for u in merged:
        sch = u.split("://", 1)[0].lower()
        if sch == "hy2":
            sch = "hysteria2"
        by_scheme.setdefault(sch, []).append(u)
    for sch in by_scheme:
        by_scheme[sch] = sorted(set(by_scheme[sch]))

    # round-robin pick up to NODE_CAP
    NODE_CAP = 12000
    all_nodes: list[str] = []
    keys = sorted(by_scheme.keys())
    idxs = {k: 0 for k in keys}
    while len(all_nodes) < NODE_CAP and keys:
        progress = False
        for k in list(keys):
            i = idxs[k]
            lst = by_scheme[k]
            if i >= len(lst):
                keys.remove(k)
                continue
            all_nodes.append(lst[i])
            idxs[k] = i + 1
            progress = True
            if len(all_nodes) >= NODE_CAP:
                break
        if not progress:
            break

    scheme_counts: dict[str, int] = {}
    for u in all_nodes:
        sch = u.split("://", 1)[0].lower()
        scheme_counts[sch] = scheme_counts.get(sch, 0) + 1

    write_text(DIST_ONLINE / "http.txt", "\n".join(http_all) + ("\n" if http_all else ""))
    write_text(DIST_ONLINE / "socks4.txt", "\n".join(socks4) + ("\n" if socks4 else ""))
    write_text(DIST_ONLINE / "socks5.txt", "\n".join(socks5) + ("\n" if socks5 else ""))
    write_text(DIST_ONLINE / "all.txt", "\n".join(all_pool) + ("\n" if all_pool else ""))
    write_text(DIST_ONLINE / "nodes.txt", "\n".join(all_nodes) + ("\n" if all_nodes else ""))

    if all_nodes:
        b64 = base64.b64encode("\n".join(all_nodes).encode()).decode()
        write_text(DIST_ONLINE / "nodes.base64.txt", b64 + "\n")
    else:
        write_text(DIST_ONLINE / "nodes.base64.txt", "")

    # Clash Meta YAML from share links
    try:
        from nodes_to_clash import main as clash_main  # type: ignore

        clash_main()
    except Exception as e:  # noqa: BLE001
        print(f"[clash] skip: {e}")

    ok_sources = sum(1 for s in per_source if s.get("ok"))
    meta = {
        "generated_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "mode": "mirror-dedupe+nodes",
        "counts": {
            "http": len(http_all),
            "socks4": len(socks4),
            "socks5": len(socks5),
            "all_pool": len(all_pool),
            "nodes": len(all_nodes),
            "tg_nodes": len(tg_nodes),
            "sub_nodes": len(sub_nodes),
            "nodes_by_scheme": scheme_counts,
            "sources_ok": ok_sources,
            "sources_total": len(per_source),
        },
        "dedupe": "ip:port unique; nodes unique share-URI; protocol socks5>socks4>http",
        "sources": per_source,
        "note": "pool=HTTP/SOCKS; nodes/clash=ss/vmess/vless/trojan/hy2 for clients",
    }
    write_text(DIST_ONLINE / "meta.json", json.dumps(meta, ensure_ascii=False, indent=2) + "\n")
    write_text(
        DIST_ONLINE / "sources_report.json",
        json.dumps(per_source, ensure_ascii=False, indent=2) + "\n",
    )
    print(json.dumps(meta["counts"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
