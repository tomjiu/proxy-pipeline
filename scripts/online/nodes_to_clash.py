#!/usr/bin/env python3
"""Convert share-link URIs → minimal Clash Meta YAML (select group + MATCH)."""
from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DIST_ONLINE, read_lines, write_text  # noqa: E402

MAX_PROXIES = 800


def b64decode(data: str) -> bytes:
    s = data.strip().replace("-", "+").replace("_", "/")
    pad = "=" * (-len(s) % 4)
    return base64.b64decode(s + pad, validate=False)


def safe_name(s: str, idx: int) -> str:
    s = unquote(s or "")
    s = re.sub(r"[\r\n#:{}\[\]]+", " ", s).strip() or f"node-{idx}"
    return (s[:48] + f"-{idx}") if s else f"node-{idx}"


def parse_ss(uri: str, idx: int) -> dict | None:
    # ss://base64@host:port or ss://base64(#name) or ss://method:pass@host:port
    try:
        raw = uri[5:]
        name = ""
        if "#" in raw:
            raw, name = raw.split("#", 1)
        if "@" in raw:
            user, hostpart = raw.rsplit("@", 1)
            try:
                dec = b64decode(user).decode("utf-8", errors="ignore")
                if ":" in dec:
                    method, password = dec.split(":", 1)
                else:
                    method, password = "aes-256-gcm", dec
            except Exception:
                if ":" in user:
                    method, password = user.split(":", 1)
                else:
                    return None
            hostpart = hostpart.split("?")[0]
            if ":" not in hostpart:
                return None
            host, port_s = hostpart.rsplit(":", 1)
            port = int(port_s)
        else:
            dec = b64decode(raw).decode("utf-8", errors="ignore")
            # method:pass@host:port
            if "@" not in dec or ":" not in dec:
                return None
            user, hostpart = dec.rsplit("@", 1)
            method, password = user.split(":", 1)
            host, port_s = hostpart.rsplit(":", 1)
            port = int(port_s)
        host = host.strip("[]")
        if not host or port < 1:
            return None
        return {
            "name": safe_name(name or f"ss-{host}", idx),
            "type": "ss",
            "server": host,
            "port": port,
            "cipher": method,
            "password": password,
            "udp": True,
        }
    except Exception:
        return None


def parse_vmess(uri: str, idx: int) -> dict | None:
    try:
        raw = uri[8:]
        if "#" in raw:
            raw = raw.split("#", 1)[0]
        obj = json.loads(b64decode(raw).decode("utf-8", errors="ignore"))
        host = obj.get("add") or obj.get("host") or ""
        port = int(obj.get("port") or 0)
        if not host or not port:
            return None
        net = (obj.get("net") or "tcp").lower()
        tls = (obj.get("tls") or "").lower()
        node = {
            "name": safe_name(obj.get("ps") or f"vmess-{host}", idx),
            "type": "vmess",
            "server": host,
            "port": port,
            "uuid": obj.get("id") or "",
            "alterId": int(obj.get("aid") or 0),
            "cipher": obj.get("scy") or "auto",
            "udp": True,
        }
        if net and net != "tcp":
            node["network"] = net
        if tls in ("tls", "1", "true"):
            node["tls"] = True
            if obj.get("sni"):
                node["servername"] = obj["sni"]
        if net == "ws":
            node["ws-opts"] = {
                "path": obj.get("path") or "/",
                "headers": {"Host": obj.get("host") or host},
            }
        return node if node["uuid"] else None
    except Exception:
        return None


def parse_vless_trojan_hy2(uri: str, idx: int) -> dict | None:
    try:
        u = urlparse(uri)
        scheme = (u.scheme or "").lower()
        if scheme == "hy2":
            scheme = "hysteria2"
        host = u.hostname
        port = u.port
        password = unquote(u.username or "")
        if not host or not port or not password:
            return None
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        name = safe_name(u.fragment or f"{scheme}-{host}", idx)
        if scheme == "vless":
            node: dict = {
                "name": name,
                "type": "vless",
                "server": host,
                "port": port,
                "uuid": password,
                "udp": True,
                "tls": q.get("security", "") in ("tls", "reality"),
                "flow": q.get("flow") or "",
                "client-fingerprint": q.get("fp") or "chrome",
            }
            if q.get("security") == "reality":
                node["reality-opts"] = {
                    "public-key": q.get("pbk") or "",
                    "short-id": q.get("sid") or "",
                }
                node["servername"] = q.get("sni") or ""
            elif q.get("sni"):
                node["servername"] = q["sni"]
            net = q.get("type") or "tcp"
            if net == "ws":
                node["network"] = "ws"
                node["ws-opts"] = {
                    "path": q.get("path") or "/",
                    "headers": {"Host": q.get("host") or host},
                }
            elif net == "grpc":
                node["network"] = "grpc"
                node["grpc-opts"] = {"grpc-service-name": q.get("serviceName") or ""}
            if not node.get("flow"):
                node.pop("flow", None)
            return node
        if scheme == "trojan":
            node = {
                "name": name,
                "type": "trojan",
                "server": host,
                "port": port,
                "password": password,
                "udp": True,
                "sni": q.get("sni") or host,
                "skip-cert-verify": q.get("allowInsecure") in ("1", "true")
                or q.get("insecure") in ("1", "true"),
            }
            return node
        if scheme == "hysteria2":
            node = {
                "name": name,
                "type": "hysteria2",
                "server": host,
                "port": port,
                "password": password,
                "sni": q.get("sni") or host,
                "skip-cert-verify": q.get("insecure") in ("1", "true"),
            }
            if q.get("pinSHA256"):
                # mihomo may use different key; keep password auth path
                pass
            return node
        return None
    except Exception:
        return None


def uri_to_proxy(uri: str, idx: int) -> dict | None:
    low = uri.lower().strip()
    if "t.me/" in low or low.count("://") > 1:
        return None
    if low.startswith("ss://"):
        return parse_ss(uri, idx)
    if low.startswith("vmess://"):
        return parse_vmess(uri, idx)
    if low.startswith(("vless://", "trojan://", "hysteria2://", "hy2://")):
        return parse_vless_trojan_hy2(uri, idx)
    return None


def to_yaml(proxies: list[dict]) -> str:
    # minimal hand-rolled yaml to avoid PyYAML dependency
    def dump_val(v, indent: int) -> str:
        sp = "  " * indent
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return str(v)
        if isinstance(v, dict):
            if not v:
                return "{}"
            lines = [""]
            for k, val in v.items():
                if isinstance(val, (dict, list)):
                    lines.append(f"{sp}  {k}: {dump_val(val, indent + 1)}")
                else:
                    lines.append(f"{sp}  {k}: {dump_val(val, indent + 1)}")
            return "\n".join(lines)
        if isinstance(v, list):
            if not v:
                return "[]"
            lines = [""]
            for item in v:
                lines.append(f"{sp}  - {dump_val(item, indent + 1)}")
            return "\n".join(lines)
        s = str(v).replace("\\", "\\\\").replace('"', '\\"')
        if re.search(r'[:#{}[\],&*?|>!%@`]', s) or s != s.strip() or s == "":
            return f'"{s}"'
        return s

    lines = [
        "# Generated by proxy-pipeline — Clash Meta / mihomo",
        "# Free public nodes: unstable; for test only",
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: info",
        "external-controller: 127.0.0.1:9090",
        "proxies:",
    ]
    names: list[str] = []
    for p in proxies:
        names.append(p["name"])
        lines.append("  - name: " + dump_val(p["name"], 1))
        for k, v in p.items():
            if k == "name":
                continue
            if isinstance(v, dict):
                lines.append(f"    {k}:")
                for kk, vv in v.items():
                    lines.append(f"      {kk}: {dump_val(vv, 3)}")
            else:
                lines.append(f"    {k}: {dump_val(v, 2)}")
    lines.append("proxy-groups:")
    lines.append('  - name: "PROXY"')
    lines.append("    type: select")
    lines.append("    proxies:")
    for n in names[:MAX_PROXIES]:
        lines.append(f"      - {dump_val(n, 3)}")
    lines.append('  - name: "AUTO"')
    lines.append("    type: url-test")
    lines.append("    url: http://www.gstatic.com/generate_204")
    lines.append("    interval: 300")
    lines.append("    proxies:")
    for n in names[: min(200, len(names))]:
        lines.append(f"      - {dump_val(n, 3)}")
    lines.append("rules:")
    lines.append("  - GEOIP,CN,DIRECT")
    lines.append("  - MATCH,PROXY")
    return "\n".join(lines) + "\n"


def _uniq_name(base: str, seen: set[str]) -> str:
    n = base
    c = 1
    while n in seen:
        c += 1
        n = f"{base}-{c}"
    seen.add(n)
    return n


def main() -> int:
    uris = read_lines(DIST_ONLINE / "nodes.txt")
    parsed: list[dict] = []
    by = {"ss": 0, "vmess": 0, "vless": 0, "trojan": 0, "hysteria2": 0, "fail": 0}
    seen_endpoint: set[str] = set()
    for i, uri in enumerate(uris):
        p = uri_to_proxy(uri, i)
        if not p:
            by["fail"] += 1
            continue
        ep = f"{p['type']}|{p.get('server')}|{p.get('port')}|{p.get('uuid') or p.get('password') or ''}"
        if ep in seen_endpoint:
            continue
        seen_endpoint.add(ep)
        parsed.append(p)
        by[p["type"]] = by.get(p["type"], 0) + 1

    per_type: dict[str, list[dict]] = {}
    for p in parsed:
        per_type.setdefault(p["type"], []).append(p)

    order = ["vless", "vmess", "trojan", "hysteria2", "ss"]
    quotas = {"vless": 280, "vmess": 180, "trojan": 120, "hysteria2": 80, "ss": 140}
    proxies: list[dict] = []
    seen_names: set[str] = set()
    used_ep: set[str] = set()
    for t in order:
        for p in per_type.get(t, [])[: quotas.get(t, 50)]:
            if len(proxies) >= MAX_PROXIES:
                break
            ep = f"{p['type']}|{p.get('server')}|{p.get('port')}"
            if ep in used_ep:
                continue
            used_ep.add(ep)
            pp = dict(p)
            pp["name"] = _uniq_name(p["name"], seen_names)
            proxies.append(pp)
    for p in parsed:
        if len(proxies) >= MAX_PROXIES:
            break
        ep = f"{p['type']}|{p.get('server')}|{p.get('port')}"
        if ep in used_ep:
            continue
        used_ep.add(ep)
        pp = dict(p)
        pp["name"] = _uniq_name(p["name"], seen_names)
        proxies.append(pp)

    write_text(DIST_ONLINE / "clash.yaml", to_yaml(proxies) if proxies else "proxies: []\n")
    # also a provider-only file (proxies list) for advanced users
    if proxies:
        # reuse full config is enough for clients
        pass
    print(json.dumps({"clash_proxies": len(proxies), "by_type": by}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
