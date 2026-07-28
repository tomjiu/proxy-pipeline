# 可 mirror 资源目录（公开 raw / API）

只收录 **无需登录、可 curl** 的源。面板站（北极光等）不进此表。

## 池子（`pool-urls.txt`）

| 类别 | 代表 |
|------|------|
| 已测活 working | Skillter/ProxyGather, ClearProxy, Thordata, databay-labs |
| 商业镜像免费档 | ProxyScrape (jsd + API v2/v4), Proxifly |
| 公开站 | openproxylist.xyz, api.openproxylist.xyz, spys.me |
| 经典 GitHub | SpeedX, monosans, clarketm, ShiftyTR, jetkai, rdavydov |
| 大聚合 | MuRongPIG/Proxy-Master, BreakingTechFr/Proxy_Free, ErcinDedeoglu |
| 其它 | hideip.me raw, hookzof, vakhov, sunny9577, TuanMinPay, B4RC0DE-TM… |

可选超大：`gfpcom/free-proxy-list` wiki raw（默认注释，体积 10MB+）。

## 节点 URI（`tg-channels.txt` / `sub-urls.txt`）

- TG：公开频道网页预览，不保证有货。
- sub：自行填 raw 订阅；勿提交带个人 token 的链接到公开仓。

## 不收录

- 需登录面板、验证码、切换次数
- 无稳定 URL 的 HTML 列表页（应用 VPS + 浏览器另做）

## 维护

```bash
python scripts/online/scrape.py
# 看 dist/online/sources_report.json 里 ok:false 的，注释掉或换 URL
```
