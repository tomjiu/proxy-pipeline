#!/usr/bin/env python3
"""
Build client Clash from quality YAML feeds (少而精).
Handles both `  - name:` and `    - name:` indent styles.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DIST_ONLINE, SOURCES, read_lines, write_text  # noqa: E402

UA = "Mozilla/5.0 (compatible; proxy-pipeline-feeds/1.0)"
MAX_PROXIES = 180
TIMEOUT = 45

SS_CIPHERS = {
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "chacha20-ietf-poly1305",
    "chacha20-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "rc4-md5",
    "plain",
    "none",
}


def fetch(url: str) -> tuple[str, str | None]:
    try:
        req = Request(url, headers={"User-Agent": UA})
        with urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read(6 * 1024 * 1024)
        return raw.decode("utf-8", errors="ignore"), None
    except Exception as e:  # noqa: BLE001
        return "", f"{type(e).__name__}: {e}"


def clean_str(s: str) -> str:
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s).replace("\r", "")


def extract_proxy_blocks(yaml_text: str) -> list[str]:
    """Split proxies section into individual node blocks (any indent)."""
    m = re.search(r"(?m)^proxies:\s*$", yaml_text)
    if not m:
        return []
    rest = yaml_text[m.end() :]
    end = re.search(
        r"(?m)^(proxy-groups|proxy-providers|rule-providers|rules|port:|mixed-port:)\s*",
        rest,
    )
    body = rest[: end.start()] if end else rest

    # Detect list item indent: lines matching ^\s+- 
    # Split on newline + spaces + "- " that start a new proxy (has type or name soon)
    parts = re.split(r"(?m)^([ \t]*- )", body)
    # parts: [pre, indent1, content1, indent2, content2, ...]
    blocks: list[str] = []
    i = 1
    while i + 1 < len(parts):
        indent, content = parts[i], parts[i + 1]
        raw = indent + content
        # stop content at next top-level non-list? already split
        if re.search(r"(?m)^\s*type:\s*\S", raw) or re.search(
            r"(?m)type:\s*\S", raw
        ):
            # normalize to 2-space clash style for output
            blocks.append(raw)
        i += 2
    return blocks


def normalize_block(block: str, idx: int) -> str | None:
    """Convert flow/odd indent block into standard 2-space mapping list item."""
    block = clean_str(block)
    # collect key: value at any indent under this item
    fields: dict[str, str] = {}
    name = None
    # first line may be "- name: x" or "- { name: ..."
    first = block.strip()
    if first.startswith("-"):
        first = first[1:].strip()
    # flow style single line
    if first.startswith("{"):
        # crude: extract name and type
        nm = re.search(r"name:\s*[\"']?([^,\"'}]+)", first)
        if nm:
            name = clean_str(nm.group(1).strip())
        for key in (
            "type",
            "server",
            "port",
            "uuid",
            "password",
            "cipher",
            "udp",
            "tls",
            "network",
            "servername",
            "sni",
            "flow",
            "client-fingerprint",
            "skip-cert-verify",
            "alterId",
        ):
            m = re.search(rf"{key}:\s*([^,}}]+)", first)
            if m:
                fields[key] = clean_str(m.group(1).strip().strip("\"'"))
    else:
        lines = block.splitlines()
        for line in lines:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if s.startswith("- "):
                s = s[2:].strip()
            if s.startswith("name:"):
                name = clean_str(s[5:].strip().strip("\"'"))
                continue
            m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", s)
            if not m:
                continue
            k, v = m.group(1), m.group(2).strip()
            if v == "" or v.startswith("{") or v.startswith("["):
                # skip nested objects for simplicity unless simple
                if v.startswith("[") and v.endswith("]"):
                    fields[k] = v
                continue
            fields[k] = clean_str(v.strip("\"'"))

    typ = (fields.get("type") or "").lower()
    server = fields.get("server") or ""
    port = fields.get("port") or ""
    if not typ or not server or not port:
        return None
    try:
        port_i = int(str(port).strip())
    except ValueError:
        return None

    if typ == "ss":
        cipher = (fields.get("cipher") or "").lower()
        if cipher not in SS_CIPHERS:
            return None
        if not fields.get("password"):
            return None
    if typ in ("vless", "vmess"):
        uid = fields.get("uuid") or ""
        if len(uid) < 8 or uid.startswith("@") or " " in uid:
            return None
    if typ in ("trojan", "hysteria2") and not fields.get("password"):
        return None

    name = re.sub(r"[\r\n#]+", " ", name or f"{typ}-{server}")[:40]
    name = f"{name}-{idx}".replace('"', "")

    def yv(v: object) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, int):
            return str(v)
        s = str(v)
        if s in ("true", "false"):
            return s
        if re.fullmatch(r"-?\d+", s):
            return s
        s = s.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{s}"'

    # coerce bools
    out_fields: list[tuple[str, object]] = [("name", name), ("type", typ), ("server", server), ("port", port_i)]
    skip = {"name", "type", "server", "port"}
    for k, v in fields.items():
        if k in skip:
            continue
        if k in ("udp", "tls", "skip-cert-verify"):
            out_fields.append((k, str(v).lower() in ("true", "1", "yes")))
        elif k == "alterId":
            try:
                out_fields.append((k, int(v)))
            except ValueError:
                continue
        else:
            out_fields.append((k, v))

    lines = [f"  - name: {yv(name)}"]
    for k, v in out_fields:
        if k == "name":
            continue
        lines.append(f"    {k}: {yv(v)}")
    return "\n".join(lines) + "\n"


def fingerprint(block: str) -> str:
    def f(k: str) -> str:
        m = re.search(rf"(?m)^    {k}:\s*(.+)$", block)
        return (m.group(1).strip().strip('"') if m else "")

    return f"{f('type')}|{f('server')}|{f('port')}|{f('uuid') or f('password')}"


def rebuild(blocks: list[str], names: list[str]) -> str:
    lines = [
        "# proxy-pipeline — quality free feeds (少而精, not mega dead dumps)",
        f"# built: {datetime.now(timezone.utc).isoformat()}",
        "# Use group AUTO. Public free nodes still die; not a paid airport.",
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: info",
        "external-controller: 127.0.0.1:9090",
        "proxies:",
    ]
    for b in blocks:
        lines.append(b.rstrip("\n"))

    def q(n: str) -> str:
        return '"' + n.replace("\\", "\\\\").replace('"', '\\"') + '"'

    lines += [
        "proxy-groups:",
        '  - name: "PROXY"',
        "    type: select",
        "    proxies:",
        '      - "AUTO"',
        "      - DIRECT",
    ]
    for n in names:
        lines.append(f"      - {q(n)}")
    lines += [
        '  - name: "AUTO"',
        "    type: url-test",
        '    url: "http://www.gstatic.com/generate_204"',
        "    interval: 300",
        "    tolerance: 50",
        "    lazy: true",
        "    proxies:",
    ]
    for n in names:
        lines.append(f"      - {q(n)}")
    lines += ["rules:", "  - GEOIP,CN,DIRECT", "  - MATCH,PROXY"]
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", "\n".join(lines) + "\n")


def main() -> int:
    feeds = read_lines(SOURCES / "clash-feeds.txt")
    print(f"[feeds] {len(feeds)}")
    collected: list[str] = []
    report = []

    for url in feeds:
        body, err = fetch(url)
        if err or not body:
            print(f"  ! {url} -> {err}")
            report.append({"url": url, "ok": False, "error": str(err)})
            continue
        raw_blocks = extract_proxy_blocks(body)
        kept = 0
        for b in raw_blocks:
            nb = normalize_block(b, len(collected) + kept)
            if not nb:
                continue
            collected.append(nb)
            kept += 1
        print(f"  + {url.rsplit('/', 1)[-1]} raw={len(raw_blocks)} kept={kept}")
        report.append({"url": url, "ok": True, "raw": len(raw_blocks), "kept": kept})

    seen: set[str] = set()
    blocks: list[str] = []
    names: list[str] = []
    for b in collected:
        fp = fingerprint(b)
        if fp in seen:
            continue
        seen.add(fp)
        nm = re.search(r'(?m)^  - name:\s*"([^"]+)"', b)
        n = nm.group(1) if nm else f"n{len(blocks)}"
        # re-index name uniqueness
        base = n
        c = 1
        while n in names:
            c += 1
            n = f"{base}-{c}"
        if nm:
            b = re.sub(r'(?m)^  - name:\s*"[^"]+"', f'  - name: "{n}"', b, count=1)
        blocks.append(b)
        names.append(n)
        if len(blocks) >= MAX_PROXIES:
            break

    write_text(DIST_ONLINE / "clash.yaml", rebuild(blocks, names) if blocks else "proxies: []\n")
    write_text(
        DIST_ONLINE / "clash_feeds_report.json",
        json.dumps(
            {
                "at": datetime.now(timezone.utc).isoformat(),
                "proxies": len(blocks),
                "feeds": report,
                "strategy": "quality-feeds-first",
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
    )
    print(json.dumps({"clash_proxies": len(blocks)}, ensure_ascii=False))
    return 0 if blocks else 1


if __name__ == "__main__":
    raise SystemExit(main())
