# scripts

本目录的脚本分两类：**自动化链路用**（被 Actions 调用）和**手动工具**（排查/运维用）。

## 自动化链路（被 `.github/workflows/*` 调用）

```
online-scan ──► scrape.py ──► nodes_to_clash.py / build_clash_from_feeds.py
                    │
                    ▼
check-nodes ──► check_clash_nodes.py
                    │
                    ▼
ai-probe ─────► ai_probe.py
                    │
                    ▼
cn-check ─────► cn_check.py ──► cn_report.py
                    │
                    ▼
verify-proxy ─► verify_proxy.py
```

| 脚本 | 作用 |
|---|---|
| `online/scrape.py` | 抓取订阅源 → `dist/online/nodes.txt` |
| `online/nodes_to_clash.py` | URI → Clash YAML（全量转换） |
| `online/build_clash_from_feeds.py` | 精选 feeds → Clash YAML |
| `online/check_clash_nodes.py` | mihomo delay-test 测连通性 |
| `online/ai_probe.py` | AI 服务可达性画像（tier S/A/B/X） |
| `online/cn_check.py` | ip112 双端 CN 端口测活 |
| `online/cn_report.py` | CN 结果汇总 |
| `online/verify_proxy.py` | **真实代理握手验证**（mihomo 实测） |
| `online/geo_lookup.py` | 节点地理信息查询 |
| `online/rename_nodes.py` | 节点按地区重命名 |
| `online/light_check.py` | 代理池轻量测活（SCOPE=all 时用） |
| `online/show_report.py` / `show_stats.py` | 报告输出 |
| `local/clean_filter.py` | 本地清理过滤 |

## 手动工具（排查 / 运维）

| 脚本 | 用途 | 用法 |
|---|---|---|
| `deploy/deploy_worker.py` | **部署 Worker**（绕过 wrangler 的 Node TLS 问题） | `python scripts/deploy/deploy_worker.py [--dry-run]` |
| `deploy/refresh_token.py` | **刷新 wrangler OAuth token**（`wrangler whoami` 在本机会卡住） | `python scripts/deploy/refresh_token.py` |
| `online/sync_template.py` | **模板 yaml → ts 同步**（改完 yaml 必须跑，否则 Worker 不生效） | `python scripts/online/sync_template.py [--check]` |
| `online/render_template_check.py` | 渲染模板供 `mihomo -t` 校验 | `python scripts/online/render_template_check.py out.yaml` |
| `online/extract_template.py` | 从本地 Clash 配置提取模板（生成 `default-template.yaml`） | 一次性使用 |

## 常见坑

### 1. 改了 `default-template.yaml` 但 Worker 没生效

Worker 运行时用的是 **`default-template.ts` 里内嵌的字符串**（打包时读不到 .yaml）。
改完 yaml 必须同步：

```bash
python scripts/online/sync_template.py          # 同步
python scripts/online/sync_template.py --check  # 确认一致
```

`sync_template.py` 还会自检 CN 规则是否误写成走代理。

### 2. `wrangler deploy` 报 `fetch failed`

本机对 Node 的 TLS 握手有干扰（curl 正常、Node fetch 失败）。用：

```bash
python scripts/deploy/refresh_token.py    # token 过期时先刷新
python scripts/deploy/deploy_worker.py    # 走 CF REST API 部署
```

### 3. 校验模板时脚本卡死

早期用正则 `(?ms)^proxy-groups:\n(?:.*\n)*?(?=^rules:)` 会触发**灾难性回溯**。
`render_template_check.py` 已改为行处理，不要退回正则写法。

### 4. 本地跑 mihomo 校验

工作目录需要 `geoip.dat` / `geosite.dat` / `Country.mmdb`，
否则 GeoIP 规则加载失败（那是环境问题，不是配置问题）：

```bash
# 从 Clash Verge 拷一份
cp "$APPDATA/io.github.clash-verge-rev.clash-verge-rev"/{geoip.dat,geosite.dat,Country.mmdb} <工作目录>/
```
