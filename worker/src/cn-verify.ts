/**
 * CN 连通性验证（Worker 内部）—— 用于用户订阅源
 *
 * ⚠️ 安全设计（关键）：
 *   用户的私有节点【绝不能】离开 Worker：
 *     · 不写文件（Worker 无文件系统）
 *     · 不上传仓库
 *     · 不进日志（只记数量，不记 server/port）
 *     · 只把「server:port 的判定结果」缓存到 KV
 *
 * 流程：
 *   1. 聚合时对每个节点调 ip112 国内端 API（纯 HTTP，Worker 可发）
 *   2. 通 → 保留；不通 → 剔除
 *   3. 结果按 server:port 缓存到 KV（避免每次请求都测）
 *
 * 限制：
 *   · 免费版 CPU 10ms/请求 —— 所以**必须靠缓存**
 *   · 由定时预热（sub-refresh）提前填充缓存，用户请求只读缓存
 */

/** ip112.cn 的国内端 API（从中国大陆测目标端口） */
const CN_API = "https://api.ycwxgzs.com/ipcheck/index.php";

/** 缓存前缀 */
const CN_CACHE_PREFIX = "cnv:";     // cn verify

/** 缓存 TTL（秒）—— 6 小时 */
const CN_CACHE_TTL = 6 * 3600;

/** 单次请求最多验证多少个节点（保护 CPU） */
const CN_MAX_PER_REQUEST = 8;

/** 单次验证的超时（毫秒）
 *  ⚠️ ip112 实际需要 10-40s，原来设 6s 导致大量超时误判 */
const CN_TIMEOUT_MS = 45000;

export interface CNVerifyResult {
  /** server:port → 是否 CN 可达 */
  alive: Set<string>;
  /** 实测数量 */
  probed: number;
  /** 命中缓存数量 */
  cached: number;
  /** 确认被墙数量 */
  blocked: number;
  /** 未知数量（探测失败，保留但不算确认可达） */
  unknown: number;
}

/**
 * 生成缓存 key
 *
 * ⚠️ 安全：用 SHA-256 哈希，KV 里**看不到明文 server/port**
 *    即使 KV 被导出，也无法直接读出节点地址（需暴力枚举才能反推）
 */
async function key(server: string, port: string): Promise<string> {
  const raw = `${server.toLowerCase()}:${port}`;
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
  const hex = Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
  return CN_CACHE_PREFIX + hex.slice(0, 32);
}

/** 同步版本的标识（仅用于内存内 Set，不落盘） */
function memKey(server: string, port: string): string {
  return `${server}:${port}`;
}

/** 探测结果：true=可达 / false=被墙 / null=未知（探测失败，不判定） */
export type ProbeVerdict = boolean | null;

/**
 * 调用 ip112 国内端，判断端口是否可达
 *
 * ⚠️ 关键修正（2026-10-15）：
 *   原来 catch 分支 `return true`（把探测失败当「可达」）+
 *   超时只有 6s（ip112 实际需要 10-40s）
 *   → 大量超时被误判为「可达」→ 订阅里混入 50% 不可用节点
 *
 *   现在：
 *     · 超时提到 45s（匹配 ip112 的真实耗时）
 *     · 探测失败返回 null（未知），不再当「可达」
 *     · 只有拿到明确响应才判定 true/false
 */
async function probeCN(server: string, port: string): Promise<ProbeVerdict> {
  try {
    const body = new URLSearchParams({ ip: server, port }).toString();
    const res = await fetch(CN_API, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (compatible; proxy-pipeline/1.0)",
        "Origin": "https://ip112.cn",
        "Referer": "https://ip112.cn/",
      },
      body,
      signal: AbortSignal.timeout(CN_TIMEOUT_MS),
    });
    // 非 200 → 未知（不判定）
    if (!res.ok) return null;

    const data = await res.json() as { tcp?: string };
    const tcp = String(data.tcp || "").replace(/<[^>]+>/g, "").trim();
    if (!tcp) return null;                       // 空响应 → 未知

    // "端口可用" = 通；"端口不可用" = 被墙
    if (tcp.includes("不可用")) return false;
    if (tcp.includes("可用")) return true;
    return null;                                 // 无法识别 → 未知
  } catch {
    // 超时/网络错误 → 未知（**不再**当可达）
    return null;
  }
}

/**
 * 验证一批节点的 CN 连通性
 *
 * @param nodes  待验证节点（含 server/port）
 * @param env    Worker 环境（用 KV 做缓存）
 * @param opts   maxProbe 限制实际探测数量
 */
export async function verifyCN(
  nodes: Array<{ server: string; port: string }>,
  env: { KV?: KVNamespace },
  opts: { maxProbe?: number; refresh?: boolean } = {},
): Promise<CNVerifyResult> {
  const alive = new Set<string>();
  const maxProbe = opts.maxProbe ?? CN_MAX_PER_REQUEST;

  // 去重
  const uniq = new Map<string, { server: string; port: string }>();
  for (const n of nodes) {
    const k = `${n.server}:${n.port}`;
    if (!uniq.has(k)) uniq.set(k, n);
  }

  let cached = 0;
  let probed = 0;
  let blocked = 0;
  let unknown = 0;
  const toProbe: Array<{ k: string; server: string; port: string }> = [];

  // 1. 先查缓存
  for (const [k, n] of uniq) {
    let hit: string | null = null;
    if (env.KV && !opts.refresh) {
      try {
        const ck = await key(n.server, n.port);
        hit = await env.KV.get(ck, "text");
      } catch { /* ignore */ }
    }
    if (hit === "1") {
      alive.add(k);
      cached++;
    } else if (hit === "0") {
      cached++;
      blocked++;
    } else if (hit === "?") {
      // 已知未知 → 保留（不因探测失败误删）
      cached++;
      unknown++;
      alive.add(k);
    } else if (toProbe.length < maxProbe) {
      toProbe.push({ k, ...n });
    } else {
      // 超过本次限额 → 保留（下次预热再验证）
      unknown++;
      alive.add(k);
    }
  }

  // 2. 并发探测（最多 maxProbe 个）
  const results = await Promise.all(
    toProbe.map(async item => {
      const verdict = await probeCN(item.server, item.port);
      return { ...item, verdict };
    }),
  );

  // 3. 写缓存 + 统计
  const writes: Promise<unknown>[] = [];
  for (const r of results) {
    probed++;
    if (r.verdict === true) {
      alive.add(r.k);
    } else if (r.verdict === false) {
      blocked++;
    } else {
      // 未知 → 保留（不误删），但缓存为 "?" 以便下次重试
      unknown++;
      alive.add(r.k);
    }
    if (env.KV) {
      const v = r.verdict === true ? "1" : r.verdict === false ? "0" : "?";
      // 未知的只缓存 5 分钟（快速重试）；明确的缓存 6 小时
      const ttl = r.verdict === null ? 300 : CN_CACHE_TTL;
      writes.push(
        (async () => {
          const ck = await key(r.server, r.port);
          await env.KV!.put(ck, v, { expirationTtl: ttl });
        })().catch(() => {}),
      );
    }
  }
  await Promise.all(writes);

  return { alive, probed, cached, blocked, unknown };
}

/**
 * 预热：批量验证并写缓存（供定时任务调用）
 *
 * ⚠️ 日志只输出数量，不输出 server/port —— 避免私有节点进日志
 */
export async function warmCNCache(
  nodes: Array<{ server: string; port: string }>,
  env: { KV?: KVNamespace },
  opts: { limit?: number; concurrency?: number } = {},
): Promise<{ probed: number; alive: number; blocked: number; cached: number; unknown: number }> {
  const limit = opts.limit ?? 200;
  const concurrency = opts.concurrency ?? 4;

  // 去重
  const uniq = new Map<string, { server: string; port: string }>();
  for (const n of nodes) {
    const k = `${n.server}:${n.port}`;
    if (!uniq.has(k)) uniq.set(k, n);
  }

  // ⚠️ 关键：先筛出【未缓存】的，再取 limit 个
  //    否则每次调用都从第 0 个开始，重复验证同一批，后面的永远测不到
  const pending: Array<[string, { server: string; port: string }]> = [];
  let cachedHits = 0;
  let alive = 0, blocked = 0, unknown = 0;

  for (const entry of uniq.entries()) {
    const [k, n] = entry;
    if (env.KV) {
      try {
        const ck = await key(n.server, n.port);
        const hit = await env.KV.get(ck, "text");
        if (hit === "1") { cachedHits++; alive++; continue; }
        if (hit === "0") { cachedHits++; blocked++; continue; }
        // hit === "?" → 未知，重新探测（不 continue）
      } catch { /* ignore */ }
    }
    pending.push(entry);
  }

  const items = pending.slice(0, limit);
  let probed = 0;

  // 分批并发
  for (let i = 0; i < items.length; i += concurrency) {
    const batch = items.slice(i, i + concurrency);
    const rs = await Promise.all(batch.map(async ([k, n]) => {
      const verdict = await probeCN(n.server, n.port);
      return { k, verdict };
    }));

    for (const r of rs) {
      probed++;
      const v = r.verdict === true ? "1" : r.verdict === false ? "0" : "?";
      if (r.verdict === true) alive++;
      else if (r.verdict === false) blocked++;
      else unknown++;

      if (env.KV) {
        const [rServer, ...rPortParts] = r.k.split(":");
        const rPort = rPortParts.join(":");
        const ck = await key(rServer, rPort);
        // 未知只缓存 5 分钟（快速重试）
        const ttl = r.verdict === null ? 300 : CN_CACHE_TTL;
        await env.KV.put(ck, v, { expirationTtl: ttl }).catch(() => {});
      }
    }
  }

  return { probed, alive, blocked, cached: cachedHits, unknown };
}
