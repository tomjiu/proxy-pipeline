#!/usr/bin/env python3
"""用 Cloudflare REST API 部署 Worker

⚠️ 为什么不用 `wrangler deploy`：
   本机网络对 Node 的 TLS 握手有干扰（curl 正常、Node fetch 报
   "socket disconnected before TLS connection established"），
   wrangler 会以 `TypeError: fetch failed` 失败。
   改用 curl 直接调 REST API，稳定可用。

设计原则：
  · 不硬编码 account id / KV id / D1 id —— 全部从配置读取或动态查询
  · 不做绝对路径假设 —— 从脚本位置推导仓库根

用法：
  python scripts/deploy/deploy_worker.py
  python scripts/deploy/deploy_worker.py --dry-run   # 只打包不上传
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
from pathlib import Path

IS_WIN = platform.system() == "Windows"
CURL = "curl.exe" if IS_WIN else "curl"

ROOT = Path(__file__).resolve().parents[2]      # 仓库根
WORKER_DIR = ROOT / "worker"
LOCAL_TOML = WORKER_DIR / "wrangler.local.toml"
TEMPLATE_TOML = WORKER_DIR / "wrangler.toml"


def wrangler_cfg() -> Path:
    if IS_WIN:
        return Path(os.environ["APPDATA"]) / "xdg.config/.wrangler/config/default.toml"
    return Path.home() / ".config/.wrangler/config/default.toml"


def get_token() -> str:
    cfg = wrangler_cfg()
    if not cfg.exists():
        raise SystemExit(f"找不到 wrangler 配置: {cfg}\n先运行 `wrangler login`")
    m = re.search(r'oauth_token\s*=\s*"([^"]+)"',
                  cfg.read_text(encoding="utf-8"))
    if not m:
        raise SystemExit("配置里没有 oauth_token")
    return m.group(1)


def curl(*args: str, timeout: int = 60) -> str:
    r = subprocess.run([CURL, "-s", "--noproxy", "*", "-m", str(timeout), *args],
                       capture_output=True, text=True,
                       encoding="utf-8", errors="ignore")
    return r.stdout


def get_account_id(token: str) -> str:
    """动态查询 account id（不硬编码）"""
    # ① 优先从本地配置读
    if LOCAL_TOML.exists():
        m = re.search(r'^\s*account_id\s*=\s*"([^"]+)"',
                      LOCAL_TOML.read_text(encoding="utf-8"), re.M)
        if m:
            return m.group(1)

    # ② 调 API 查
    body = curl("-H", f"Authorization: Bearer {token}",
                "https://api.cloudflare.com/client/v4/accounts")
    try:
        j = json.loads(body)
        accts = j.get("result") or []
        if len(accts) == 1:
            return accts[0]["id"]
        if accts:
            print("  多个账号，请用 --account 指定：")
            for a in accts:
                print(f"    {a['id']}  {a.get('name')}")
            raise SystemExit(1)
    except SystemExit:
        raise
    except Exception:
        pass
    raise SystemExit("拿不到 account id（在 wrangler.local.toml 里加 account_id）")


def parse_bindings() -> tuple[str, list[dict]]:
    """从 wrangler.local.toml 读 worker 名 + 绑定"""
    if not LOCAL_TOML.exists():
        raise SystemExit(f"找不到 {LOCAL_TOML}\n"
                         "从 wrangler.toml 复制一份并填入真实 id")

    text = LOCAL_TOML.read_text(encoding="utf-8")
    name = (re.search(r'^\s*name\s*=\s*"([^"]+)"', text, re.M) or [None, "worker"])[1]

    bindings: list[dict] = []
    for m in re.finditer(r'^\s*RAW_BASE\s*=\s*"([^"]+)"', text, re.M):
        bindings.append({"type": "plain_text", "name": "RAW_BASE", "text": m.group(1)})
    for m in re.finditer(
            r'\[\[kv_namespaces\]\](.*?)(?=\n\[|\Z)', text, re.S):
        blk = m.group(1)
        b = (re.search(r'binding\s*=\s*"([^"]+)"', blk) or [None, None])[1]
        i = (re.search(r'^\s*id\s*=\s*"([^"]+)"', blk, re.M) or [None, None])[1]
        if b and i:
            bindings.append({"type": "kv_namespace", "name": b, "namespace_id": i})
    for m in re.finditer(
            r'\[\[d1_databases\]\](.*?)(?=\n\[|\Z)', text, re.S):
        blk = m.group(1)
        b = (re.search(r'binding\s*=\s*"([^"]+)"', blk) or [None, None])[1]
        i = (re.search(r'database_id\s*=\s*"([^"]+)"', blk) or [None, None])[1]
        if b and i:
            bindings.append({"type": "d1", "name": b, "id": i})

    return name, bindings


def bundle() -> Path:
    out = WORKER_DIR / "dist-bundle" / "worker.js"
    out.parent.mkdir(parents=True, exist_ok=True)

    npx = "npx.cmd" if IS_WIN else "npx"
    r = subprocess.run(
        [npx, "esbuild", "src/index.ts", "--bundle", "--format=esm",
         "--platform=neutral", "--target=es2022", "--outfile=" + str(out)],
        cwd=WORKER_DIR, capture_output=True, text=True, shell=IS_WIN,
        encoding="utf-8", errors="ignore")

    if r.returncode != 0:
        print(r.stdout[-1500:])
        print(r.stderr[-1500:])
        raise SystemExit("esbuild 打包失败")

    print(f"  打包: {out.name}  {out.stat().st_size} 字节")
    return out


def deploy(js: Path, token: str, account: str, name: str,
           bindings: list[dict], compat: str) -> bool:
    metadata = {
        "main_module": "worker.js",
        "compatibility_date": compat,
        "bindings": bindings,
    }
    tmp = Path(tempfile.gettempdir()) / "cf-worker-metadata.json"
    tmp.write_text(json.dumps(metadata), encoding="utf-8")

    url = (f"https://api.cloudflare.com/client/v4/accounts/{account}"
           f"/workers/scripts/{name}")

    body = curl(
        "-X", "PUT", url,
        "-H", f"Authorization: Bearer {token}",
        "-F", f"metadata=@{tmp};type=application/json",
        "-F", f"worker.js=@{js};type=application/javascript+module",
        timeout=120,
    )

    try:
        j = json.loads(body)
    except Exception:
        print(f"  ❌ 响应不是 JSON: {body[:300]}")
        return False

    if j.get("success"):
        print(f"  ✅ 部署成功: {name}")
        print(f"     account: {account[:8]}…  bindings: {len(bindings)}")
        return True

    print(f"  ❌ 失败: {json.dumps(j.get('errors', j), ensure_ascii=False)[:400]}")
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="只打包不上传")
    ap.add_argument("--account", default="", help="指定 account id")
    args = ap.parse_args()

    name, bindings = parse_bindings()
    print(f"  worker:   {name}")
    print(f"  bindings: {len(bindings)}")
    for b in bindings:
        key = b.get("namespace_id") or b.get("id") or ""
        print(f"    {b['type']:<14} {b['name']:<10} {str(key)[:12]}…")

    js = bundle()

    if args.dry_run:
        print("  --dry-run：跳过上传")
        return 0

    token = get_token()
    account = args.account or get_account_id(token)

    compat = "2024-11-01"
    if LOCAL_TOML.exists():
        m = re.search(r'compatibility_date\s*=\s*"([^"]+)"',
                      LOCAL_TOML.read_text(encoding="utf-8"))
        if m:
            compat = m.group(1)

    return 0 if deploy(js, token, account, name, bindings, compat) else 1


if __name__ == "__main__":
    sys.exit(main())
