#!/usr/bin/env python3
"""用 mihomo 核心实测节点的「真实代理可用性」（跨平台）

═══════════════════════════════════════════════════════════════════════
为什么需要这一步
═══════════════════════════════════════════════════════════════════════

  ip112.cn 测的是「TCP 端口可达」，但端口通 ≠ 代理能用：
    · 服务端进程挂了，但 nginx/TCP 还在监听 → 端口通、代理不通
    · 协议参数错误（UUID/密码/SNI 不对）      → 端口通、代理不通
    · 节点被限速到不可用                      → 端口通、代理不通

  实测数据（2026-10-15，用户 5 个源的 85 个节点）：
    ip112 端口测活通过:  84 个
    mihomo 真实代理可用: 37 个   ← 43%
    ───────────────────────────
    假阳性率: 56%

  这 56% 就是「订阅能用但成功率低」的根因。

═══════════════════════════════════════════════════════════════════════
原理
═══════════════════════════════════════════════════════════════════════

  1. 启动 mihomo（禁用 TUN，只开 HTTP/SOCKS 端口）
  2. 通过 external-controller API 逐个测延迟
     GET /proxies/{name}/delay?timeout=N&url=<test-url>
  3. 统计可用率，输出可用节点列表

  测试标准与 Clash 客户端一致（握手成功 = 可用）。

═══════════════════════════════════════════════════════════════════════
用法
═══════════════════════════════════════════════════════════════════════

  python verify_proxy.py <订阅.yaml> [超时ms] [--out 结果.json]
  MIHOMO_BIN=/path/to/mihomo python verify_proxy.py sub.yaml 8000
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

IS_WIN = platform.system() == "Windows"

API_PORT = int(os.environ.get("MIHOMO_API_PORT", "29123"))
PROXY_PORT = int(os.environ.get("MIHOMO_PROXY_PORT", "29124"))
SOCKS_PORT = int(os.environ.get("MIHOMO_SOCKS_PORT", "29125"))
TEST_URL = os.environ.get(
    "MIHOMO_TEST_URL", "http://www.gstatic.com/generate_204")

# mihomo 内置类型 + 策略组（不是真实节点）
NON_NODE_TYPES = {
    "Selector", "URLTest", "Fallback", "LoadBalance", "Relay",
    "Direct", "Reject", "RejectDrop", "Compatible", "Pass", "Dns", "Smart",
}

# mihomo 内置代理名（不是订阅里的节点）
BUILTIN_PROXY_NAMES = {
    "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE",
    "GLOBAL", "PASS-RULE", "REJECT-RULE", "DIRECT-RULE",
    "REJECT-DROP-RULE", "COMPATIBLE-RULE", "MATCH", "FINAL",
}

# ── 已知 mihomo 下载地址（Actions 用）──
MIHOMO_RELEASES = [
    "v1.19.12", "v1.19.11", "v1.19.9", "v1.19.2",
]


def find_core() -> str:
    """找 mihomo 核心"""
    # 环境变量优先（CI 里用 MIHOMO_BIN 指向下载的核心）
    for var in ("MIHOMO_BIN", "MIHOMO"):
        env = os.environ.get(var)
        if env and Path(env).exists():
            return env

    if IS_WIN:
        cands = [
            r"C:\Program Files\Clash Verge\verge-mihomo.exe",
            r"C:\Program Files\Clash Verge\verge-mihomo-alpha.exe",
        ]
    else:
        cands = [
            "/usr/local/bin/mihomo", "/usr/bin/mihomo",
            "./mihomo", "./bin/mihomo",
            str(Path.cwd() / "mihomo"),
            str(Path.cwd() / "bin" / "mihomo"),
        ]

    for c in cands:
        if Path(c).exists():
            return c

    for name in ("mihomo", "clash-meta", "verge-mihomo"):
        p = shutil.which(name)
        if p:
            return p

    raise SystemExit(
        f"找不到 mihomo 核心。设置 MIHOMO_BIN 环境变量。\n试过: {cands}")


def install_mihomo(dest: Path) -> str:
    """下载 mihomo 到指定路径（Linux/macOS）"""
    import gzip
    import tarfile
    machine = platform.machine().lower()
    arch = "amd64" if machine in ("x86_64", "amd64") else \
           "arm64" if machine in ("aarch64", "arm64") else "amd64"

    for tag in MIHOMO_RELEASES:
        url = (f"https://github.com/MetaCubeX/mihomo/releases/download/"
               f"{tag}/mihomo-linux-{arch}-{tag}.gz")
        try:
            print(f"  尝试 {tag} ...", end=" ", flush=True)
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
            with urllib.request.urlopen(req, timeout=120) as r:
                data = r.read()
            raw = gzip.decompress(data)
            dest.write_bytes(raw)
            dest.chmod(0o755)
            print(f"OK ({len(raw)//1024//1024} MB)")
            return str(dest)
        except Exception as e:
            print(f"失败 ({type(e).__name__})")
            continue

    raise SystemExit("下载 mihomo 失败（所有版本都试过了）")


def find_geodata() -> Path | None:
    """找 GeoIP 数据目录（可选）"""
    if IS_WIN:
        p = Path(os.environ.get("APPDATA", "")) / \
            "io.github.clash-verge-rev.clash-verge-rev"
        if p.exists():
            return p
    for p in [Path("/usr/share/mihomo"), Path.home() / ".config/mihomo",
              Path.cwd()]:
        if (p / "geoip.dat").exists():
            return p
    return None


def prepare(src_yaml: Path, work: Path, geodata: Path | None) -> Path:
    """准备测试配置：去 TUN/系统代理，加 external-controller"""
    text = src_yaml.read_text(encoding="utf-8", errors="ignore")

    # 移除会冲突的顶层键（否则 mihomo 报 duplicate key）
    for pat in [
        r"(?m)^tun:\n(?:[ \t]+.*\n)*",
        r"(?m)^external-controller:.*\n",
        r"(?m)^secret:.*\n",
        r"(?m)^mixed-port:.*\n",
        r"(?m)^port:.*\n",
        r"(?m)^socks-port:.*\n",
        r"(?m)^redir-port:.*\n",
        r"(?m)^tproxy-port:.*\n",
        r"(?m)^allow-lan:.*\n",
        r"(?m)^log-level:.*\n",
        r"(?m)^mode:.*\n",
        r"(?m)^ipv6:.*\n",
        r"(?m)^bind-address:.*\n",
        r"(?m)^profile:\n(?:[ \t]+.*\n)*",
        r"(?m)^geodata-mode:.*\n",
        r"(?m)^geodata-loader:.*\n",
        r"(?m)^geo-auto-update:.*\n",
        r"(?m)^geo-update-interval:.*\n",
        r"(?m)^geox-url:\n(?:[ \t]+.*\n)*",
        r"(?m)^sniffer:\n(?:[ \t]+.*\n)*",
        r"(?m)^find-process-mode:.*\n",
        r"(?m)^unified-delay:.*\n",
        r"(?m)^tcp-concurrent:.*\n",
    ]:
        text = re.sub(pat, "", text)

    header = (
        f"mixed-port: {PROXY_PORT}\n"
        f"socks-port: {SOCKS_PORT}\n"
        f"allow-lan: false\n"
        f"mode: rule\n"
        f"log-level: warning\n"
        f"ipv6: false\n"
        f"external-controller: 127.0.0.1:{API_PORT}\n"
        f"unified-delay: true\n"
    )
    text = header + text

    # 简化 rules：出站用第一个节点（避免依赖组名）
    m = re.search(r'(?m)^\s+- name:\s*"?(.+?)"?\s*$', text)
    if m:
        text = re.sub(r"(?ms)^rules:\n(?:[ \t]*-.*\n)*",
                      f"rules:\n  - MATCH,{m.group(1)}\n", text)
    else:
        text = re.sub(r"(?ms)^rules:\n(?:[ \t]*-.*\n)*",
                      "rules:\n  - MATCH,DIRECT\n", text)

    # GeoIP：有就拷，没有则去掉依赖它的规则
    if geodata:
        for f in ["geoip.dat", "geosite.dat", "Country.mmdb", "geoip.metadb"]:
            s = geodata / f
            if s.exists():
                shutil.copy(s, work / f)
    else:
        text = re.sub(r"(?m)^\s*-\s*GEOIP,.*\n", "", text)
        text = re.sub(r"(?m)^\s*-\s*GEOSITE,.*\n", "", text)
        text = re.sub(r"(?ms)^rule-providers:\n(?:[ \t]+.*\n)*", "", text)
        text = re.sub(r"(?m)^\s*-\s*RULE-SET,.*\n", "", text)

    cfg = work / "config.yaml"
    cfg.write_text(text, encoding="utf-8")
    return cfg


def api(path: str, timeout: float = 10, method: str = "GET"):
    req = urllib.request.Request(
        f"http://127.0.0.1:{API_PORT}{path}", method=method,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read().decode()
    return json.loads(body) if body.strip() else {}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sub", help="订阅 YAML 路径")
    ap.add_argument("timeout_ms", nargs="?", type=int, default=5000)
    ap.add_argument("--out", default="dist/clean/proxy-verified.json")
    ap.add_argument("--out-clash", default="",
                    help="只输出可用节点到此 Clash YAML")
    ap.add_argument("--retries", type=int, default=2,
                    help="每个节点的重试次数（默认 2）")
    ap.add_argument("--install", action="store_true",
                    help="允许自动下载 mihomo")
    args = ap.parse_args()

    sub = Path(args.sub)
    if not sub.exists():
        print(f"❌ 找不到 {sub}")
        return 1

    # 找核心
    try:
        core = find_core()
    except SystemExit:
        if args.install:
            print("mihomo 未安装，尝试下载...")
            core = install_mihomo(Path("/tmp/mihomo"))
        else:
            raise

    print(f"核心:     {core}")
    print(f"订阅:     {sub}")
    print(f"超时:     {args.timeout_ms}ms × {args.retries} 次")

    work = Path(tempfile.mkdtemp(prefix="mihomo-verify-"))
    geodata = find_geodata()
    print(f"GeoIP:    {geodata or '无'}")
    cfg = prepare(sub, work, geodata)

    log = open(work / "mihomo.log", "w", encoding="utf-8")
    kwargs = {}
    if IS_WIN:
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

    proc = subprocess.Popen([core, "-d", str(work), "-f", str(cfg)],
                            stdout=log, stderr=subprocess.STDOUT, **kwargs)

    ready = False
    for _ in range(60):
        time.sleep(0.5)
        try:
            api("/version", timeout=3)
            ready = True
            break
        except Exception:
            if proc.poll() is not None:
                break

    if not ready:
        print("❌ 核心启动失败")
        log.close()
        print((work / "mihomo.log").read_text(
            encoding="utf-8", errors="ignore")[-2500:])
        try:
            proc.kill()
        except Exception:
            pass
        return 1

    print("✅ 核心已启动\n")

    proxies = api("/proxies")["proxies"]
    names = [
        n for n, v in proxies.items()
        if v.get("type") not in NON_NODE_TYPES
        and n.upper() not in BUILTIN_PROXY_NAMES      # 过滤内置代理名
        and not n.upper().endswith("-RULE")           # PASS-RULE 等
    ]
    skipped = len(proxies) - len(names)
    if skipped:
        print(f"（跳过 {skipped} 个内置/策略组条目）")
    print(f"待测节点: {len(names)}\n")

    ok: list[dict] = []
    fail: list[str] = []
    t0 = time.time()

    for i, name in enumerate(names, 1):
        q = urllib.parse.quote(name, safe="")
        u = urllib.parse.quote(TEST_URL, safe="")
        best = None
        for _ in range(max(1, args.retries)):
            try:
                r = api(f"/proxies/{q}/delay"
                        f"?timeout={args.timeout_ms}&url={u}",
                        timeout=args.timeout_ms / 1000 + 8)
                d = int(r.get("delay", 0) or 0)
                if d > 0:
                    best = d
                    break
            except Exception:
                pass
            time.sleep(0.2)

        if best:
            ok.append({"name": name, "delay": best})
        else:
            fail.append(name)

        if i % 10 == 0 or i == len(names):
            el = time.time() - t0
            eta = (el / i) * (len(names) - i)
            print(f"  {i}/{len(names)}  可用 {len(ok)}  失败 {len(fail)}  "
                  f"{el:.0f}s (ETA {eta:.0f}s)", flush=True)

    el = time.time() - t0
    total = len(names)
    rate = len(ok) * 100 // max(1, total)

    print(f"\n{'=' * 62}")
    print(f"结果: {len(ok)}/{total} 真可用 ({rate}%)   耗时 {el:.0f}s")
    print(f"{'=' * 62}\n")

    if ok:
        ok.sort(key=lambda x: x["delay"])
        print("最快 15 个:")
        for n in ok[:15]:
            print(f"  {n['delay']:>6}ms  {n['name'][:50]}")
        ds = [n["delay"] for n in ok]
        print(f"\n延迟: 最快 {min(ds)}ms / 中位 {sorted(ds)[len(ds)//2]}ms "
              f"/ 最慢 {max(ds)}ms")

    if fail:
        print(f"\n失败 {len(fail)} 个（前 10）:")
        for n in fail[:10]:
            print(f"  {n[:60]}")

    # 结果 JSON
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "total": total, "ok": len(ok), "fail": len(fail),
        "alive_rate": rate, "elapsed_s": round(el, 1),
        "timeout_ms": args.timeout_ms, "retries": args.retries,
        "ok_nodes": ok,
        "fail_nodes": fail,
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n结果: {out}")

    # 可用节点的 Clash YAML（保留原始配置，只留可用的）
    if args.out_clash and ok:
        ok_names = {n["name"] for n in ok}
        src_text = sub.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r"(?m)^proxies:\s*$", src_text)
        if m:
            rest = src_text[m.end():]
            end = re.search(r"(?m)^[A-Za-z][\w-]*:", rest)
            body = rest[: end.start()] if end else rest
            kept = []
            for ch in re.split(r"(?m)^  - ", body)[1:]:
                nm = re.search(r'(?m)^\s*name:\s*"?(.+?)"?\s*$',
                               ch.split("\n", 1)[0])
                if nm and nm.group(1).strip() in ok_names:
                    kept.append("  - " + ch.rstrip())
            oc = Path(args.out_clash)
            oc.parent.mkdir(parents=True, exist_ok=True)
            oc.write_text(
                f"# Proxy-Verified — {len(kept)} 个真实可用（mihomo 实测）\n"
                f"# at: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
                f"# rate: {rate}%\n"
                "proxies:\n" + "\n".join(kept) + "\n", encoding="utf-8")
            print(f"可用节点 YAML: {oc} ({len(kept)} 个)")

    try:
        proc.kill()
    except Exception:
        pass
    log.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
