#!/usr/bin/env python3
"""
CN 连通性测活（Actions 版）—— ip112.cn 双端 API

判断逻辑：
  国内端通 + 国外端通  → ok       （可用）
  国内端通 + 国外端不通 → cn_only  （少见，但保留）
  国内端不通           → cn_blocked（被墙，剔除）

产出：
  --out        JSON 详细结果
  --out-yaml   仅 CN 可达节点的 Clash YAML（供订阅使用）
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

EN_API = "https://api.52bwg.com/ipcheck/ipcheck.php"
CN_API = "https://api.ycwxgzs.com/ipcheck/index.php"

SKIP_TYPES = {"hysteria2", "hy2", "tuic"}   # UDP


def strip_html(s: str) -> str:
    return re.sub(r"<[^>]+>", "", s or "").strip()


def call(api: str, ip: str, port: str, retry: int = 3) -> dict:
    data = urllib.parse.urlencode({"ip": ip, "port": port}).encode()
    for attempt in range(retry + 1):
        try:
            req = urllib.request.Request(api, data=data, headers={
                "User-Agent": UA,
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://ip112.cn",
                "Referer": "https://ip112.cn/",
            })
            with urllib.request.urlopen(req, timeout=50) as r:
                return json.loads(r.read().decode("utf-8", errors="ignore"))
        except Exception as e:
            if attempt >= retry:
                return {"error": f"{type(e).__name__}: {str(e)[:60]}"}
            time.sleep(2 * (attempt + 1))
    return {"error": "unreachable"}


def probe(node: dict) -> dict:
    ip, port = node["server"], node["port"]
    t0 = time.time()

    cn = call(CN_API, ip, port)
    cn_tcp = strip_html(cn.get("tcp", ""))
    cn_ok = "可用" in cn_tcp and "不可用" not in cn_tcp

    if not cn_ok:
        return {**node, "cn_ok": False, "cn_tcp": cn_tcp, "en_ok": None,
                "verdict": "cn_blocked", "elapsed": round(time.time() - t0, 1)}

    en = call(EN_API, ip, port)
    en_tcp = strip_html(en.get("tcp", ""))
    en_ok = "可用" in en_tcp and "不可用" not in en_tcp

    return {**node, "cn_ok": True, "cn_tcp": cn_tcp, "en_ok": en_ok,
            "en_tcp": en_tcp, "verdict": "ok" if en_ok else "cn_only",
            "elapsed": round(time.time() - t0, 1)}


def parse_nodes(text: str):
    m = re.search(r"(?m)^proxies:\s*$", text)
    if not m:
        return []
    rest = text[m.end():]
    end = re.search(r"(?m)^[A-Za-z][\w-]*:", rest)
    if end:
        rest = rest[: end.start()]

    out = []
    for ch in re.split(r"(?m)^  - ", rest)[1:]:
        nm = re.search(r'(?m)^\s*name:\s*"?(.+?)"?\s*$', ch.split("\n", 1)[0])
        tp = re.search(r"(?m)^\s*type:\s*\"?(\w+)\"?", ch)
        sv = re.search(r"(?m)^\s*server:\s*\"?([^\"\s,}]+)\"?", ch)
        pt = re.search(r"(?m)^\s*port:\s*\"?(\d+)\"?", ch)
        if nm and tp and sv and pt:
            out.append({
                "name": nm.group(1).strip(),
                "type": tp.group(1).lower(),
                "server": sv.group(1),
                "port": pt.group(1),
                "raw": "  - " + ch.rstrip(),
            })
    return out


def build_yaml(nodes, title="CN-Alive"):
    """生成仅含 CN 可用节点的 Clash YAML"""
    names = [n["name"] for n in nodes]
    lines = [
        f"# {title} — 仅 CN 实测可达（ip112 双端验证）",
        f"# updated: {datetime.now(timezone.utc).isoformat()}",
        f"# count: {len(nodes)}",
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: warning",
        "proxies:",
    ]
    for n in nodes:
        lines.append(n["raw"].rstrip())

    if not names:
        lines += ["proxy-groups: []", "rules:", "  - MATCH,DIRECT"]
        return "\n".join(lines) + "\n"

    def q(s):
        if re.search(r'[:#{}[\],&*?|>!%@"`]', s) or " " in s:
            return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
        return s

    lines.append("proxy-groups:")
    lines.append('  - name: "PROXY"')
    lines.append("    type: select")
    lines.append("    proxies:")
    lines.append('      - "AUTO"')
    lines.append("      - DIRECT")
    for n in names:
        lines.append(f"      - {q(n)}")
    lines.append('  - name: "AUTO"')
    lines.append("    type: url-test")
    lines.append("    url: http://www.gstatic.com/generate_204")
    lines.append("    interval: 300")
    lines.append("    proxies:")
    for n in names:
        lines.append(f"      - {q(n)}")
    lines.append("rules:")
    lines.append("  - MATCH,PROXY")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--out", default="dist/clean/cn-result.json")
    ap.add_argument("--out-yaml", default="dist/clean/cn-alive.yaml")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--skip-udp", action="store_true")
    args = ap.parse_args()

    text = Path(args.input).read_text(encoding="utf-8")
    nodes = parse_nodes(text)
    print(f"[cn] 解析: {len(nodes)} 个节点")

    if args.skip_udp:
        before = len(nodes)
        nodes = [n for n in nodes if n["type"] not in SKIP_TYPES]
        print(f"[cn] 跳过 UDP: -{before - len(nodes)}")

    seen, uniq = set(), []
    for n in nodes:
        k = f"{n['server']}:{n['port']}"
        if k not in seen:
            seen.add(k)
            uniq.append(n)
    print(f"[cn] 去重: {len(uniq)}")

    if args.limit:
        uniq = uniq[: args.limit]

    if not uniq:
        print("[cn] 无节点可测")
        Path(args.out_yaml).write_text(build_yaml([]), encoding="utf-8")
        return 0

    print(f"[cn] 并发 {args.workers}，开始测活")
    t0 = time.time()
    results = []
    done = 0

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(probe, n) for n in uniq]
        for f in as_completed(futs):
            results.append(f.result())
            done += 1
            if done % 20 == 0 or done == len(uniq):
                ok = sum(1 for x in results if x.get("cn_ok"))
                el = time.time() - t0
                eta = (el / done) * (len(uniq) - done) if done else 0
                print(f"  … {done}/{len(uniq)} CN可用 {ok}  {el:.0f}s (ETA {eta:.0f}s)")

    from collections import Counter
    verdicts = Counter(r.get("verdict") for r in results)
    by_type = Counter(r["type"] for r in results if r.get("cn_ok"))
    alive = [r for r in results if r.get("cn_ok")]

    doc = {
        "at": datetime.now(timezone.utc).isoformat(),
        "input": len(nodes),
        "tested": len(results),
        "cn_ok": len(alive),
        "verdicts": dict(verdicts),
        "by_type": dict(by_type),
        "elapsed_s": round(time.time() - t0, 1),
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(
        json.dumps({**doc, "nodes": results}, ensure_ascii=False, indent=1) + "\n",
        encoding="utf-8")

    Path(args.out_yaml).write_text(build_yaml(alive), encoding="utf-8")

    print(f"\n[cn] 结果: {len(alive)}/{len(results)} CN 可用")
    print(f"[cn] 判定: {dict(verdicts)}")
    print(f"[cn] 协议: {dict(by_type)}")
    print(f"[cn] JSON: {args.out}")
    print(f"[cn] YAML: {args.out_yaml}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
