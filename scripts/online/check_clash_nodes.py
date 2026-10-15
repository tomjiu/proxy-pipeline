#!/usr/bin/env python3
"""
Probe Clash Meta nodes via mihomo delay API.

  full         — retest every proxy in dist/online/clash.yaml
  incremental  — only NEW fingerprints + last-dead; keep last-alive

Writes dist/clean/clash.yaml, alive.json, check_report.json
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

ROOT = Path(__file__).resolve().parents[2]
DIST_ONLINE = ROOT / "dist" / "online"
DIST_CLEAN = ROOT / "dist" / "clean"
CONTROLLER = "127.0.0.1:9090"
MIXED_PORT = 7890
SELECT_GROUP = "PROXY"
TEST_URL = "http://www.gstatic.com/generate_204"
CLEAN_JUDGE = "https://api.ipify.org"


def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def extract_proxy_blocks(yaml_text: str) -> list[tuple[str, str, str]]:
    """
    Return list of (name, fingerprint_hint, raw_block) from generated clash.yaml.
    fingerprint_hint = type|server|port from simple field scan.
    """
    m = re.search(r"(?m)^proxies:\s*$", yaml_text)
    if not m:
        return []
    rest = yaml_text[m.end() :]
    end = re.search(r"(?m)^proxy-groups:\s*$", rest)
    body = rest[: end.start()] if end else rest

    blocks: list[tuple[str, str, str]] = []
    # split on "  - name:"
    chunks = re.split(r"(?m)^  - name: ", body)
    for i, ch in enumerate(chunks):
        if i == 0:
            continue
        raw = "  - name: " + ch.rstrip() + "\n"
        # name
        first = ch.split("\n", 1)[0].strip()
        name = first.strip().strip('"').replace('\\"', '"')
        typ = _field(ch, "type") or ""
        server = _field(ch, "server") or ""
        port = _field(ch, "port") or ""
        secret = _field(ch, "uuid") or _field(ch, "password") or ""
        fp = f"{typ}|{server}|{port}|{secret}"
        if name and typ and server:
            blocks.append((name, fp, raw))
    return blocks


def _field(block: str, key: str) -> str | None:
    m = re.search(rf"(?m)^    {re.escape(key)}:\s*(.+)\s*$", block)
    if not m:
        return None
    v = m.group(1).strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        v = v[1:-1]
    return v


def rebuild_yaml(alive_blocks: list[str], names: list[str]) -> str:
    header = [
        "# Alive only — mihomo delay-tested (GitHub Actions)",
        f"# updated: {datetime.now(timezone.utc).isoformat()}",
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: warning",
        "external-controller: 127.0.0.1:9090",
        "proxies:",
    ]
    lines = header + [b.rstrip("\n") for b in alive_blocks]
    if not names:
        lines += ["proxy-groups: []", "rules:", "  - MATCH,DIRECT"]
        return "\n".join(lines) + "\n"

    def q(n: str) -> str:
        if re.search(r'[:#{}[\],&*?|>!%@"`]', n) or " " in n:
            return '"' + n.replace("\\", "\\\\").replace('"', '\\"') + '"'
        return n

    lines.append("proxy-groups:")
    lines.append('  - name: "PROXY"')
    lines.append("    type: select")
    lines.append("    proxies:")
    for n in names:
        lines.append(f"      - {q(n)}")
    lines.append('  - name: "AUTO"')
    lines.append("    type: url-test")
    lines.append("    url: http://www.gstatic.com/generate_204")
    lines.append("    interval: 300")
    lines.append("    proxies:")
    for n in names[: min(150, len(names))]:
        lines.append(f"      - {q(n)}")
    lines.append("rules:")
    # ⚠️ 不要用 GEOIP,CN —— 它依赖 MMDB 文件，
    #    CI 环境或首次运行时若无法下载 MMDB（网络受限），mihomo 会直接 fatal 退出，
    #    导致**全部节点被误判为死**。
    #    测活只需要能建立连接，用 MATCH 即可。
    lines.append("  - MATCH,PROXY")
    return "\n".join(lines) + "\n"


def find_mihomo() -> str:
    """查找 mihomo（兼容 Windows 的 .exe 后缀）"""
    candidates = [
        "mihomo",
        "mihomo.exe",
        str(ROOT / "bin" / "mihomo"),
        str(ROOT / "bin" / "mihomo.exe"),
    ]
    for cand in candidates:
        p = shutil.which(cand)
        if p:
            return p
        if Path(cand).exists():
            return cand
    raise SystemExit("mihomo not found")


def wait_api(proc: subprocess.Popen, timeout: float = 90) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"mihomo exited early code={proc.returncode}")
        try:
            with urllib.request.urlopen(f"http://{CONTROLLER}/version", timeout=2) as r:
                print(f"[check] api ok: {r.read()[:120]!r}")
            return
        except Exception:
            time.sleep(0.5)
    raise SystemExit("mihomo API not ready")


def delay_test(name: str, timeout_ms: int) -> int | None:
    q = urllib.parse.quote(name, safe="")
    url = (
        f"http://{CONTROLLER}/proxies/{q}/delay"
        f"?timeout={timeout_ms}&url={urllib.parse.quote(TEST_URL, safe='')}"
    )
    try:
        with urllib.request.urlopen(url, timeout=timeout_ms / 1000 + 5) as resp:
            data = json.loads(resp.read().decode())
        d = data.get("delay")
        return d if isinstance(d, int) and d > 0 else None
    except Exception:
        return None


def judge_sanity(timeout: int) -> bool:
    """Ensure the cleanliness judge is reachable directly (guards against
    judge-side outages poisoning the whole clean feed)."""
    try:
        req = urllib.request.Request(CLEAN_JUDGE, headers={"User-Agent": "proxy-pipeline-clean/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(128).decode("utf-8", errors="ignore").strip()
        ipaddress.ip_address(body)
        return True
    except Exception:
        return False


def select_proxy(name: str) -> bool:
    """Point the PROXY select group at a specific node via mihomo controller."""
    q = urllib.parse.quote(SELECT_GROUP, safe="")
    body = json.dumps({"name": name}).encode()
    req = urllib.request.Request(
        f"http://{CONTROLLER}/proxies/{q}",
        data=body,
        method="PUT",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status in (200, 204)
    except Exception:
        return False


def clean_probe(name: str, timeout_ms: int) -> tuple[bool, str]:
    """
    Route one request to the judge through the selected node and verify the
    response is the expected plain IP — not a captive portal, injected ads,
    or hijack HTML. Mirrors scripts/local/clean_filter.py heuristics.
    """
    if not select_proxy(name):
        return False, "select_failed"
    opener = build_opener(
        ProxyHandler(
            {
                "http": f"http://127.0.0.1:{MIXED_PORT}",
                "https": f"http://127.0.0.1:{MIXED_PORT}",
            }
        )
    )
    try:
        req = urllib.request.Request(CLEAN_JUDGE, headers={"User-Agent": "proxy-pipeline-clean/1.0"})
        with opener.open(req, timeout=timeout_ms / 1000 + 3) as resp:
            body = resp.read(512).decode("utf-8", errors="ignore")
            code = resp.status
    except Exception as e:
        return False, type(e).__name__
    if code >= 400:
        return False, "bad_status"
    text = body.strip()
    try:
        ipaddress.ip_address(text)
        return True, "ok"
    except ValueError:
        pass
    low = text.lower()
    if "<html" in low or "<!doctype" in low:
        return False, "html_hijack"
    if "advert" in low or "redirect" in low:
        return False, "hijack_html"
    return False, "unexpected_body"


def force_test_dns(text: str) -> str:
    """
    把配置里的 DNS 段替换成「测试专用」

    为什么必须做：
      - 订阅模板常用 fake-ip（198.18.0.1/16），会把节点域名解析成假 IP
        → 所有用域名的节点测活必然失败
      - 完全没有 dns 段时，mihomo 用内置默认，在国内网络下解析节点域名
        会被污染/超时 → 同样全部失败

    测试要求：真实解析 + 国内可达的 DNS
    """
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    replaced = False

    while i < len(lines):
        line = lines[i]

        # 替换/删除原 dns 段
        if re.match(r"^dns:\s*$", line):
            i += 1
            while i < len(lines) and (lines[i].startswith((" ", "\t")) or not lines[i].strip()):
                i += 1
            if not replaced:
                out.extend(TEST_DNS_BLOCK)
                replaced = True
            continue

        # 删除 sniffer（避免干扰）
        if re.match(r"^sniffer:\s*$", line):
            i += 1
            while i < len(lines) and (lines[i].startswith((" ", "\t")) or not lines[i].strip()):
                i += 1
            continue

        # 删除依赖 MMDB 的段
        if re.match(r"^geox-url:\s*$", line):
            i += 1
            while i < len(lines) and (lines[i].startswith((" ", "\t")) or not lines[i].strip()):
                i += 1
            continue

        out.append(line)
        i += 1

    if not replaced:
        # 插到 mixed-port 之后（或开头）
        ins = 0
        for idx, l in enumerate(out):
            if l.startswith("mixed-port:") or l.startswith("port:"):
                ins = idx + 1
                break
        out[ins:ins] = TEST_DNS_BLOCK

    return "\n".join(out)


TEST_DNS_BLOCK = [
    "dns:",
    "  enable: true",
    "  ipv6: false",
    "  enhanced-mode: normal",       # 关键：不用 fake-ip
    "  nameserver:",
    "    - 223.5.5.5",               # 阿里 DNS
    "    - 119.29.29.29",            # DNSPod
    "  fallback:",
    "    - 8.8.8.8",
    "    - 1.1.1.1",
    "  fallback-filter:",
    "    geoip: false",              # 避免依赖 MMDB
    "    ipcidr:",
    "      - 240.0.0.0/4",
]


def main() -> int:
    global CLEAN_JUDGE
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("full", "incremental"), default="incremental")
    ap.add_argument("--timeout-ms", type=int, default=5000)
    ap.add_argument("--input", type=Path, default=DIST_ONLINE / "clash.yaml")
    ap.add_argument("--pause", type=float, default=0.03)
    ap.add_argument("--workers", type=int, default=16,
                    help="并发测活线程数（串行时 3955 节点需 7.8 小时，16 并发约几分钟）")
    ap.add_argument("--skip-clean", action="store_true", help="skip content cleanliness probe")
    ap.add_argument("--clean-timeout-ms", type=int, default=5000)
    ap.add_argument("--clean-judge", default=CLEAN_JUDGE, help="judge URL for cleanliness probe")
    args = ap.parse_args()

    CLEAN_JUDGE = args.clean_judge

    if not args.input.exists():
        print(f"missing {args.input}")
        return 1

    text = args.input.read_text(encoding="utf-8", errors="ignore")
    # ensure controller present for API
    if "external-controller:" not in text:
        text = text.replace("log-level:", "external-controller: 127.0.0.1:9090\nlog-level:", 1)

    blocks = extract_proxy_blocks(text)
    print(f"[check] proxies={len(blocks)} mode={args.mode}")
    if not blocks:
        print("no proxies parsed")
        return 1

    alive_db = load_json(DIST_CLEAN / "alive.json", {"nodes": {}})
    nodes_db: dict = alive_db.get("nodes") or {}
    now = datetime.now(timezone.utc).isoformat()

    to_test: list[tuple[str, str, str]] = []  # name, fp, raw
    keep: list[tuple[str, str, str, int]] = []  # + delay

    for name, fp, raw in blocks:
        prev = nodes_db.get(fp) or {}
        if args.mode == "full":
            to_test.append((name, fp, raw))
        elif not prev or not prev.get("alive"):
            to_test.append((name, fp, raw))
        else:
            keep.append((name, fp, raw, int(prev.get("delay") or 1)))

    print(f"[check] test={len(to_test)} keep={len(keep)}")

    tmp = ROOT / ".mihomo-run"
    if tmp.exists():
        shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(exist_ok=True)
    cfg = tmp / "config.yaml"
    # force controller + quiet log for CI
    if "external-controller:" not in text:
        text = "external-controller: 127.0.0.1:9090\n" + text
    else:
        text = re.sub(
            r"(?m)^external-controller:.*$",
            "external-controller: 127.0.0.1:9090",
            text,
        )
    text = re.sub(r"(?m)^log-level:.*$", "log-level: error", text)
    if "mixed-port:" in text:
        text = re.sub(r"(?m)^mixed-port:.*$", f"mixed-port: {MIXED_PORT}", text)
    else:
        text = f"mixed-port: {MIXED_PORT}\n" + text

    # ⚠️ 关键：注入测试专用 DNS
    #    没有 dns 段时 mihomo 用内置默认，在国内网络下解析节点域名会失败
    #    （DNS 污染/超时）→ 所有域名型节点被误判为死。
    #    必须用 enhanced-mode: normal + 国内可达的 DNS。
    text = force_test_dns(text)

    # disable geodata auto-update noise in CI if present
    cfg.write_text(text, encoding="utf-8")

    mihomo = find_mihomo()
    log_path = tmp / "mihomo.log"
    logf = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [
            mihomo,
            "-d",
            str(tmp),
            "-f",
            str(cfg),
            "-ext-ctl",
            CONTROLLER,
        ],
        stdout=logf,
        stderr=subprocess.STDOUT,
    )
    try:
        try:
            wait_api(proc, 90)
        except SystemExit:
            logf.flush()
            tail = log_path.read_text(encoding="utf-8", errors="ignore")[-2000:]
            print("[check] mihomo log tail:\n", tail)
            raise
        alive_rows: list[tuple[str, str, str, int]] = list(keep)
        ok = fail = 0

        # ── 并发测活 ──
        # 原来串行：3955 节点需 7.8 小时（每节点等 timeout + pause）
        # 改为并发后，实测可压到几分钟
        #
        # 注意：mihomo 的 /proxies/<name>/delay 是独立的 HTTP 请求，
        #       mihomo 内部会并发发起，所以并发调用是安全的（只是排队）。
        workers = max(1, getattr(args, "workers", 16))
        print(f"[check] 并发 {workers}，待测 {len(to_test)} 个")

        done_count = 0

        def probe_one(item):
            name, fp, raw = item
            d = delay_test(name, args.timeout_ms)
            return item, d

        from concurrent.futures import ThreadPoolExecutor, as_completed

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(probe_one, it) for it in to_test]
            for fut in as_completed(futs):
                (name, fp, raw), d = fut.result()
                if d is not None:
                    ok += 1
                    alive_rows.append((name, fp, raw, d))
                    nodes_db[fp] = {
                        "alive": True,
                        "delay": d,
                        "name": name,
                        "checked_at": now,
                    }
                else:
                    fail += 1
                    nodes_db[fp] = {
                        "alive": False,
                        "delay": None,
                        "name": name,
                        "checked_at": now,
                    }
                done_count += 1
                if done_count % 100 == 0:
                    print(f"  … {done_count}/{len(to_test)} ok={ok} fail={fail}")
                if args.pause:
                    time.sleep(args.pause / workers)

        # cleanliness phase: content-verify each alive node through mihomo
        clean_rows: list[tuple[str, str, str, int]] = []
        clean_reasons: dict[str, int] = {}
        clean_checked = 0
        feed_mode = "clean"
        kept_fps = {fp for _, fp, _, _ in keep}
        if not args.skip_clean:
            if not judge_sanity(8):
                print("[clean] judge unreachable directly — skipping, feeding alive-only")
                feed_mode = "alive-only"
            else:
                for i, (name, fp, raw, d) in enumerate(alive_rows):
                    if fp in kept_fps and nodes_db.get(fp, {}).get("clean") is not None:
                        if nodes_db[fp]["clean"]:
                            clean_rows.append((name, fp, raw, d))
                        continue
                    okc, reason = clean_probe(name, args.clean_timeout_ms)
                    clean_checked += 1
                    clean_reasons[reason] = clean_reasons.get(reason, 0) + 1
                    nodes_db[fp]["clean"] = okc
                    nodes_db[fp]["clean_reason"] = reason
                    nodes_db[fp]["clean_at"] = now
                    if okc:
                        clean_rows.append((name, fp, raw, d))
                    if (i + 1) % 20 == 0:
                        print(f"  [clean] {i+1}/{len(alive_rows)} clean={len(clean_rows)}")
                if clean_rows:
                    feed_mode = "clean"
                else:
                    print("[clean] zero clean nodes — falling back to alive-only to keep feed non-empty")
                    feed_mode = "alive-only"
        else:
            feed_mode = "clean-skipped"

        feed_rows = clean_rows if feed_mode == "clean" else alive_rows

        # dedupe by fp, best delay
        alive_best: dict[str, tuple[str, str, str, int]] = {}
        for name, fp, raw, d in alive_rows:
            if fp not in alive_best or d < alive_best[fp][3]:
                alive_best[fp] = (name, fp, raw, d)

        best: dict[str, tuple[str, str, str, int]] = {}
        for name, fp, raw, d in feed_rows:
            if fp not in best or d < best[fp][3]:
                best[fp] = (name, fp, raw, d)

        ordered = sorted(best.values(), key=lambda x: x[3])
        names = [x[0] for x in ordered]
        raws = [x[2] for x in ordered]

        DIST_CLEAN.mkdir(parents=True, exist_ok=True)
        (DIST_CLEAN / "clash.yaml").write_text(rebuild_yaml(raws, names), encoding="utf-8")

        # prune ghost entries from the persisted DB: nodes that vanished from
        # the current online feed. Full mode is authoritative (drop any entry
        # not in the feed); incremental only drops stale dead entries so a
        # temporarily-missing feed node is kept until the next full retest.
        current_fps = {fp for _, fp, _ in blocks}
        stale: list[str] = []
        if args.mode == "full":
            stale = [fp for fp in list(nodes_db) if fp not in current_fps]
        else:
            stale = [
                fp
                for fp in list(nodes_db)
                if fp not in current_fps and not nodes_db[fp].get("alive")
            ]
        for fp in stale:
            del nodes_db[fp]

        alive_db["nodes"] = nodes_db
        alive_db["updated_at"] = now
        alive_db["mode_last"] = args.mode
        write_json(DIST_CLEAN / "alive.json", alive_db)

        report = {
            "at": now,
            "mode": args.mode,
            "input": len(blocks),
            "tested": len(to_test),
            "tested_ok": ok,
            "tested_fail": fail,
            "kept_skip_retest": len(keep),
            "alive_output": len(alive_best),
            "clean_checked": clean_checked,
            "clean_output": len(clean_rows),
            "clean_reasons": clean_reasons,
            "feed_output": len(best),
            "feed_mode": feed_mode,
            "pruned_db": len(stale),
            "db_size": len(nodes_db),
            "timeout_ms": args.timeout_ms,
        }
        write_json(DIST_CLEAN / "check_report.json", report)
        print(json.dumps(report, ensure_ascii=False))
        return 0
    finally:
        try:
            logf.close()
        except Exception:
            pass
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
