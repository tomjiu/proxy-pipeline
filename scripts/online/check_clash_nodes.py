#!/usr/bin/env python3
"""
Probe Clash Meta nodes via mihomo delay API.

  full         — retest every proxy in dist/online/clash.yaml
  incremental  — only NEW fingerprints + last-dead; keep last-alive

Writes dist/clean/clash.yaml, alive.json, check_report.json
"""
from __future__ import annotations

import argparse
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

ROOT = Path(__file__).resolve().parents[2]
DIST_ONLINE = ROOT / "dist" / "online"
DIST_CLEAN = ROOT / "dist" / "clean"
CONTROLLER = "127.0.0.1:9090"
TEST_URL = "http://www.gstatic.com/generate_204"


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
    lines.append("  - GEOIP,CN,DIRECT")
    lines.append("  - MATCH,PROXY")
    return "\n".join(lines) + "\n"


def find_mihomo() -> str:
    for cand in ("mihomo", str(ROOT / "bin" / "mihomo")):
        if cand == "mihomo":
            p = shutil.which(cand)
            if p:
                return p
        elif Path(cand).exists():
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("full", "incremental"), default="incremental")
    ap.add_argument("--timeout-ms", type=int, default=5000)
    ap.add_argument("--input", type=Path, default=DIST_ONLINE / "clash.yaml")
    ap.add_argument("--pause", type=float, default=0.03)
    args = ap.parse_args()

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
        for i, (name, fp, raw) in enumerate(to_test):
            d = delay_test(name, args.timeout_ms)
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
            if (i + 1) % 40 == 0:
                print(f"  … {i+1}/{len(to_test)} ok={ok} fail={fail}")
            time.sleep(args.pause)

        # dedupe by fp, best delay
        best: dict[str, tuple[str, str, str, int]] = {}
        for name, fp, raw, d in alive_rows:
            if fp not in best or d < best[fp][3]:
                best[fp] = (name, fp, raw, d)

        ordered = sorted(best.values(), key=lambda x: x[3])
        names = [x[0] for x in ordered]
        raws = [x[2] for x in ordered]

        DIST_CLEAN.mkdir(parents=True, exist_ok=True)
        (DIST_CLEAN / "clash.yaml").write_text(rebuild_yaml(raws, names), encoding="utf-8")

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
            "alive_output": len(ordered),
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
