from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ROOT / "sources"
DIST_ONLINE = ROOT / "dist" / "online"

IP_PORT_RE = re.compile(
    r"(?:(?P<proto>https?|socks4|socks5)://)?"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
    r":(?P<port>\d{2,5})"
)

URI_SCHEMES = (
    "ss://",
    "ssr://",
    "vmess://",
    "vless://",
    "trojan://",
    "hysteria2://",
    "hy2://",
    "tuic://",
    "wireguard://",
)


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    out: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        out.append(s)
    return out


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def is_public_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(x) for x in parts]
    except ValueError:
        return False
    if any(n < 0 or n > 255 for n in nums):
        return False
    a, b = nums[0], nums[1]
    if a == 10 or a == 127 or a == 0:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False
    if a >= 224:
        return False
    return True


def parse_ip_ports(text: str) -> list[tuple[str, int, str]]:
    found: list[tuple[str, int, str]] = []
    for m in IP_PORT_RE.finditer(text):
        ip = m.group("ip")
        port = int(m.group("port"))
        proto = (m.group("proto") or "").lower()
        if not is_public_ip(ip):
            continue
        if port < 1 or port > 65535:
            continue
        found.append((ip, port, proto))
    return found


def extract_node_uris(text: str) -> list[str]:
    uris: list[str] = []
    for raw in text.splitlines():
        line = raw.strip().strip("`\"'")
        low = line.lower()
        if any(low.startswith(s) for s in URI_SCHEMES):
            uris.append(line.split()[0])
    for scheme in URI_SCHEMES:
        for m in re.finditer(re.escape(scheme) + r"[^\s<>\"']+", text, re.I):
            u = m.group(0).rstrip(").,;]'\"")
            uris.append(u)
    seen: set[str] = set()
    out: list[str] = []
    for u in uris:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out
