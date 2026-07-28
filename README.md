# proxy-pipeline

免费云上采集（GitHub Actions）+ 关注向公开 TG 频道预览页 + CF Worker 只读 API。  
**节点/代理洁净度筛选**放在本地或 VPS（不要用家宽硬扫）。

## 分工

| 位置 | 做什么 |
|------|--------|
| **GitHub Actions** `online-scan` | **只 mirror** 多家仓库/API 的 raw（含 ProxyGather 产物），**按 ip:port 去重**，可选 TG/`sub-urls`；抽样 light check → `dist/online/` |
| **CF Worker** | 读 raw `dist/**`，提供 `/pool/*` `/sub/*` `/meta` |
| **本地 / VPS** `scripts/local/clean_filter.py` | 严格测活、去劫持页 → `dist/clean/` 再 push |

### 池源（广 + 去重）

编辑 `sources/pool-urls.txt`，格式：

```text
http|https://raw.githubusercontent.com/.../http.txt
socks5|https://...
```

已内置：ProxyGather working-*、ProxyScrape、Proxifly、openproxylist、SpeedX、monosans、jetkai、MuRongPIG 等。  
同一 `ip:port` 出现在多个源时只保留一条；协议冲突时优先 **socks5 > socks4 > http**。

## 快速开始

### 1. 推到 GitHub

```bash
cd proxy-pipeline
git init
git add .
git commit -m "init proxy-pipeline"
# 创建空仓库后
git remote add origin https://github.com/<USER>/<REPO>.git
git branch -M main
git push -u origin main
```

在仓库 **Settings → Actions → General** 允许 workflow 写 contents（默认 token 可 push）。

### 2. 编辑源

- `sources/pool-urls.txt` — 公开 HTTP/SOCKS 列表 raw  
- `sources/tg-channels.txt` — **公开**频道用户名（无需 TG API，只抓 `t.me/s/...`）  
- `sources/sub-urls.txt` — 已知订阅 URL（可先空着）

### 3. 手动跑一次 Actions

Actions → **online-scan** → Run workflow。

产物：

- `dist/online/http.txt` `socks5.txt` `socks4.txt`
- `dist/online/http.live.txt`（抽样存活）
- `dist/online/nodes.txt` / `nodes.base64.txt`（URI 节点）
- `dist/online/meta.json`

### 4. 部署 Worker

```bash
cd worker
npm i
# 编辑 wrangler.toml 中 RAW_BASE
npx wrangler deploy
```

`RAW_BASE` 示例：

`https://raw.githubusercontent.com/<USER>/<REPO>/main/dist`

可选 `API_TOKEN`：请求带 `?token=` 或头 `X-Api-Token`。

### 5. Clash 节点测活（免费 GitHub Actions）

**不要用 CF / Vercel 测活**（超时短、做不了 vless/hy2 握手）。

本仓 workflow **`check-nodes`**：

| 模式 | 何时 | 行为 |
|------|------|------|
| `incremental` | 约每 6 小时 | 只测**新节点** + 上次**死掉**的；上次活着的直接保留 |
| `full` | 每天 UTC 03:27 一次 | 对 `clash.yaml` 里全部节点做 mihomo delay 测试 |

产出：`dist/clean/clash.yaml`、`alive.json`、`check_report.json`  

客户端订阅（测活后）：

```text
https://proxy-pipeline-api.d05j86dzd.workers.dev/sub/clash-live
```

额度：GitHub 免费 Actions 对**公开仓**一般够用；几百节点全量大约数分钟～十几分钟，一天 1 次全量 + 几次增量通常远低于限额。

### 6. HTTP 池洁净（可选，VPS）

```bash
python scripts/local/clean_filter.py --input dist/online/http.txt --out dist/clean/http.txt
```

## API

| 路径 | 说明 |
|------|------|
| `GET /health` | 存活 |
| `GET /meta` | online meta 或 clean report |
| `GET /pool/http?src=online\|clean&live=1` | 代理列表 |
| `GET /pool/socks5` | SOCKS5 |
| `GET /pool/random?proto=http` | 随机一条 |
| `GET /sub/nodes` | 节点 URI 文本 |
| `GET /sub/base64` | base64 订阅雏形 |
| `GET /sub/clash` | 暂为 nodes 明文（完整 YAML 可后续本地生成） |

## 设计说明

- **线上不做**：全量深测、Google 搜索爬、私有 TG、浏览器自动化。  
- **TG**：仅公开频道网页预览，把常用频道写进 `tg-channels.txt` 即可，无需 bot。  
- **家宽**：只 git / 开发；clean 与重扫走 VPS 或代理出口。  
- **多 CF 号叠额度**：不推荐；先缓存与 token。

## 本地试刮（不 push）

```bash
python scripts/online/scrape.py
python scripts/online/light_check.py --sample 50
```

## License

仅供学习与自用网络调试；遵守当地法律与源站条款；勿用于攻击或违法用途。
