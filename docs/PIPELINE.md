# 节点筛选流程（最终版）

## 你的设计（明确记录）

```
① 抓取            GitHub 源 + 你的订阅源
       ↓
② Actions 连通性   mihomo delay-test（真实协议握手）
       ↓
③ AI 质量筛选      tier S/A（过 Grok/ChatGPT/Gemini 等）
       ↓
④ CN 连通性        从中国大陆测端口可达
       ↓
⑤ 合并             只有过了 ②③④ 的节点才进订阅
```

## 实际实现的问题（2026-10-15 发现）

| 步骤 | 问题 | 后果 |
|---|---|---|
| ② | `check-nodes` 默认 `--mode incremental`，只测增量 | 3449 → 只有 180 个被测过 |
| ③ | `ai-probe` 产出了 `clash-tier-s.yaml`，但**下游没人读** | AI 筛选完全没生效 |
| ④ | `cn-check` 读的是 `clash.yaml`（未过 AI），不是 `tier-s.yaml` | CN 测活对象错误 |
| ④ | `cn-alive.yaml` 只有 4 个节点 | 白名单形同虚设 |
| ⑤ | Worker 的 `probeCN` catch 分支 `return true` | **所有失败都被放行** |
| ⑤ | Worker 超时设 6s，ip112 需要 10-40s | 大量超时 → 全部误判为「可达」 |

## 为什么输出 251 个

```
cn-alive.yaml 白名单命中  = 2 个
Worker 实时验证           = 其余 249 个
  → probeCN 超时（6s < 实际 10-40s）
  → catch 分支 return true
  → 全部放行 ❌

最终 = 251 个，其中仅 ~50% 真的 CN 可达
```

## 正确实现

### 关键修正

1. **`check-nodes` 用 full 模式**（不是 incremental）
2. **`ai-probe` 的输出接到 `cn-check`**
3. **`cn-check` 读 `clash-tier-s.yaml`**（AI 筛过的）
4. **Worker 的 `probeCN` 超时提到 45s**，且 catch 分支改为「**不判定**」（标记未知，保留但不计入白名单）
5. **CN 验证必须在 Actions 做**（Workers 有 CPU/时间限制，跑不完）

### 用户订阅源的 CN 验证

**矛盾**：用户源节点不能进公开仓库，但 Worker 又跑不完验证。

**解法**：`sub-refresh` 定时调用 Worker 的 `/admin/warm-cn`，**分批**完成验证：
- 每 15 分钟验证 100 个
- 累积到 KV（哈希 key）
- 用户请求只读 KV

## 待办

- [ ] `cn-check` 改成读 `clash-tier-s.yaml`
- [ ] `ai-probe` 触发链接到 `cn-check`
- [ ] `check-nodes` 默认改 full
- [ ] Worker `probeCN` 超时 6s → 45s
- [ ] Worker `probeCN` catch 改为「未知」而非「可达」
- [ ] KV 存三种状态：1=可达 0=被墙 unknown=未验证
