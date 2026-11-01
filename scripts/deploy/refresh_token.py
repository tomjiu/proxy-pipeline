"""手动刷新 wrangler 的 OAuth token（绕过 Node fetch 的 TLS 问题）

背景：本机网络对 Node 的 TLS 握手有干扰，`wrangler whoami` 会卡住，
      导致 token 过期后无法自动刷新。改用 curl 走 OAuth2 refresh_token 流程。

用法：
  python scripts/deploy/refresh_token.py
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

CFG = Path.home() / "AppData" / "Roaming" / "xdg.config" / ".wrangler" / "config" / "default.toml"
# Linux/macOS 回退
if not CFG.exists():
    CFG = Path.home() / ".config" / ".wrangler" / "config" / "default.toml"

# wrangler 内置 OAuth client id（公开值）
CLIENT_ID = "54d11594-84e4-41aa-b438-e81b8fa78ee7"
TOKEN_URL = "https://dash.cloudflare.com/oauth2/token"


def read_field(text: str, name: str) -> str:
    m = re.search(rf'^{name}\s*=\s*"([^"]+)"', text, re.M)
    return m.group(1) if m else ""


def write_field(text: str, name: str, value: str) -> str:
    if re.search(rf'^{name}\s*=', text, re.M):
        return re.sub(rf'^{name}\s*=\s*"[^"]*"', f'{name} = "{value}"',
                      text, count=1, flags=re.M)
    return text + f'\n{name} = "{value}"\n'


def main() -> int:
    if not CFG.exists():
        print(f"❌ 找不到 wrangler 配置: {CFG}")
        return 1

    text = CFG.read_text(encoding="utf-8")
    rt = read_field(text, "refresh_token")
    if not rt:
        print("❌ 配置里没有 refresh_token（需要重新 `wrangler login`）")
        return 1

    print(f"  配置: {CFG}")
    print(f"  refresh_token: {rt[:10]}…   （长度 {len(rt)}）")

    # 用 curl 发 refresh 请求
    r = subprocess.run([
        "curl", "-s", "-X", "POST", TOKEN_URL,
        "-H", "Content-Type: application/x-www-form-urlencoded",
        "--noproxy", "*", "-m", "30",
        "-d", f"grant_type=refresh_token",
        "-d", f"refresh_token={rt}",
        "-d", f"client_id={CLIENT_ID}",
    ], capture_output=True, text=True, encoding="utf-8", errors="ignore")

    if r.returncode != 0:
        print(f"❌ curl 失败: {r.stderr[:200]}")
        return 1

    try:
        j = json.loads(r.stdout)
    except Exception:
        print(f"❌ 响应不是 JSON: {r.stdout[:300]}")
        return 1

    if "access_token" not in j:
        print(f"❌ 刷新失败: {json.dumps(j, ensure_ascii=False)[:400]}")
        return 1

    at = j["access_token"]
    nrt = j.get("refresh_token", rt)
    expires_in = int(j.get("expires_in", 3600))
    exp = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

    text = write_field(text, "oauth_token", at)
    text = write_field(text, "refresh_token", nrt)
    text = write_field(text, "expiration_time", exp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z")
    CFG.write_text(text, encoding="utf-8")

    print(f"  ✅ 刷新成功")
    print(f"     access_token: {at[:12]}…")
    print(f"     有效期至:     {exp.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
