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


def clean_str(s: object) -> str:
    """Strip NULs/controls that break YAML parsers (Clash Verge: invalid yaml)."""
    t = str(s if s is not None else "")
    # drop C0 controls + DEL; keep tab/lf only if ever needed (we flatten later)
    t = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", t)
    return t


def safe_name(s: str, idx: int) -> str:
    s = unquote(clean_str(s or ""))
    s = re.sub(r"[\r\n#:{}\[\]]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip() or f"node-{idx}"
    # ASCII-ish short name for max client compatibility
    s = s[:40]
    return f"{s}-{idx}" if s else f"node-{idx}"


def looks_like_uuid(s: str) -> bool:
    s = clean_str(s).strip()
    if not s or s.startswith("@") or " " in s:
        return False
    if re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        s,
    ):
        return True
    # some free lists use non-standard ids; allow hex-ish 8+ chars without junk
    if re.fullmatch(r"[0-9a-zA-Z_-]{8,64}", s) and not s.startswith("-"):
        return True
    return False


def parse_ss(uri: str, idx: int) -> dict | None:
    # ss://base64@host:port or ss://base64(#name) or ss://method:pass@host:port
    try:
        raw = uri[5:]
        name = ""
        if "#" in raw:
            raw, name = raw.split("#", 1)
        # reject non-ss share junk
        if "://" in raw.split("@")[0] if "@" in raw else raw:
            return None
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
            if "@" not in dec or ":" not in dec:
                return None
            user, hostpart = dec.rsplit("@", 1)
            method, password = user.split(":", 1)
            host, port_s = hostpart.rsplit(":", 1)
            port = int(port_s)
        host = clean_str(host.strip("[]"))
        method = clean_str(method)
        password = clean_str(password)
        if not host or port < 1 or not method or not password:
            return None
        # ss that was mis-tagged vless-style uuid-only is invalid as classic ss
        if method.startswith("http") or " " in method:
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
        host = clean_str(obj.get("add") or obj.get("host") or "")
        port = int(obj.get("port") or 0)
        uid = clean_str(obj.get("id") or "")
        if not host or not port or not looks_like_uuid(uid):
            return None
        net = clean_str(obj.get("net") or "tcp").lower()
        tls = clean_str(obj.get("tls") or "").lower()
        node = {
            "name": safe_name(obj.get("ps") or f"vmess-{host}", idx),
            "type": "vmess",
            "server": host,
            "port": port,
            "uuid": uid,
            "alterId": int(obj.get("aid") or 0),
            "cipher": clean_str(obj.get("scy") or "auto") or "auto",
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
                "path": clean_str(obj.get("path") or "/") or "/",
                "headers": {"Host": clean_str(obj.get("host") or host)},
            }
        return node
    except Exception:
        return None


def parse_vless_trojan_hy2(uri: str, idx: int) -> dict | None:
    try:
        u = urlparse(uri)
        scheme = (u.scheme or "").lower()
        if scheme == "hy2":
            scheme = "hysteria2"
        host = clean_str(u.hostname or "")
        port = u.port
        password = clean_str(unquote(u.username or ""))
        if not host or not port or not password:
            return None
        q = {k: clean_str(v[0]) for k, v in parse_qs(u.query).items()}
        name = safe_name(u.fragment or f"{scheme}-{host}", idx)
        if scheme == "vless":
            if not looks_like_uuid(password):
                return None
            node: dict = {
                "name": name,
                "type": "vless",
                "server": host,
                "port": port,
                "uuid": password,
                "udp": True,
                "tls": q.get("security", "") in ("tls", "reality"),
                "client-fingerprint": q.get("fp") or "chrome",
            }
            flow = q.get("flow") or ""
            if flow:
                node["flow"] = flow
            if q.get("security") == "reality":
                pbk = q.get("pbk") or ""
                if not pbk:
                    return None
                node["reality-opts"] = {
                    "public-key": pbk,
                    "short-id": q.get("sid") or "",
                }
                node["servername"] = q.get("sni") or host
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
            return node
        if scheme == "trojan":
            return {
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
        if scheme == "hysteria2":
            return {
                "name": name,
                "type": "hysteria2",
                "server": host,
                "port": port,
                "password": password,
                "sni": q.get("sni") or host,
                "skip-cert-verify": q.get("insecure") in ("1", "true"),
            }
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
    def dump_val(v) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return str(v)
        s = clean_str(v)
        # always double-quote strings for Clash client safety
        s = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ").replace("\r", "")
        return f'"{s}"'

    lines = [
        "# Generated by proxy-pipeline - Clash Meta / mihomo",
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
        # deep clean strings
        p = {k: (clean_str(v) if isinstance(v, str) else v) for k, v in p.items()}
        if isinstance(p.get("reality-opts"), dict):
            p["reality-opts"] = {
                kk: clean_str(vv) if isinstance(vv, str) else vv
                for kk, vv in p["reality-opts"].items()
            }
        if isinstance(p.get("ws-opts"), dict):
            wo = dict(p["ws-opts"])
            if isinstance(wo.get("headers"), dict):
                wo["headers"] = {
                    kk: clean_str(vv) if isinstance(vv, str) else vv
                    for kk, vv in wo["headers"].items()
                }
            if "path" in wo:
                wo["path"] = clean_str(wo["path"])
            p["ws-opts"] = wo
        names.append(p["name"])
        lines.append(f"  - name: {dump_val(p['name'])}")
        for k, v in p.items():
            if k == "name":
                continue
            if isinstance(v, dict):
                lines.append(f"    {k}:")
                for kk, vv in v.items():
                    if isinstance(vv, dict):
                        lines.append(f"      {kk}:")
                        for k3, v3 in vv.items():
                            lines.append(f"        {k3}: {dump_val(v3)}")
                    else:
                        lines.append(f"      {kk}: {dump_val(vv)}")
            else:
                lines.append(f"    {k}: {dump_val(v)}")
    lines.append("proxy-groups:")
    lines.append('  - name: "PROXY"')
    lines.append("    type: select")
    lines.append("    proxies:")
    for n in names[:MAX_PROXIES]:
        lines.append(f"      - {dump_val(n)}")
    lines.append('  - name: "AUTO"')
    lines.append("    type: url-test")
    lines.append('    url: "http://www.gstatic.com/generate_204"')
    lines.append("    interval: 300")
    lines.append("    proxies:")
    for n in names[: min(200, len(names))]:
        lines.append(f"      - {dump_val(n)}")
    lines.append("rules:")
    lines.append("  - GEOIP,CN,DIRECT")
    lines.append("  - MATCH,PROXY")
    out = "\n".join(lines) + "\n"
    # final safety: no NUL
    return out.replace("\x00", "")


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
