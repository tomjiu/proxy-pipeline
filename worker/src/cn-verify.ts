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

/** 单次验证的超时（毫秒） */
const CN_TIMEOUT_MS = 6000;

export interface CNVerifyResult {
  /** server:port → 是否 CN 可达 */
  alive: Set<string>;
  /** 实测数量 */
  probed: number;
  /** 命中缓存数量 */
  cached: number;
  /** 不可达数量 */
  blocked: number;
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

/** 调用 ip112 国内端，判断端口是否可达 */
async function probeCN(server: string, port: string): Promise<boolean> {
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
    if (!res.ok) return false;
    const data = await res.json() as { tcp?: string };
    const tcp = String(data.tcp || "").replace(/<[^>]+>/g, "").trim();
    // "端口可用" = 通；"端口不可用" = 被墙
    return tcp.includes("可用") && !tcp.includes("不可用");
  } catch {
    // 探测服务异常 → 保守起见当「可达」（不因服务故障误删节点）
    return true;
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
    } else if (toProbe.length < maxProbe) {
      toProbe.push({ k, ...n });
    } else {
      // 超过本次限额 → 先当可达（避免误删），下次预热再验证
      alive.add(k);
    }
  }

  // 2. 并发探测（最多 maxProbe 个）
  const results = await Promise.all(
    toProbe.map(async item => {
      const ok = await probeCN(item.server, item.port);
      return { ...item, ok };
    }),
  );

  // 3. 写缓存 + 统计
  const writes: Promise<unknown>[] = [];
  for (const r of results) {
    probed++;
    if (r.ok) {
      alive.add(r.k);
    } else {
      blocked++;
    }
    if (env.KV) {
      writes.push(
        (async () => {
          const ck = await key(r.server, r.port);
          await env.KV!.put(ck, r.ok ? "1" : "0", { expirationTtl: CN_CACHE_TTL });
        })().catch(() => {}),
      );
    }
  }
  await Promise.all(writes);

  return { alive, probed, cached, blocked };
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
): Promise<{ probed: number; alive: number; blocked: number; cached: number }> {
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
  let alive = 0, blocked = 0;

  for (const entry of uniq.entries()) {
    const [k, n] = entry;
    if (env.KV) {
      try {
        const ck = await key(n.server, n.port);
        const hit = await env.KV.get(ck, "text");
        if (hit !== null) {
          cachedHits++;
          if (hit === "1") alive++; else blocked++;
          continue;
        }
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
      const ok = await probeCN(n.server, n.port);
      return { k, ok, skipped: false };
    }));

    for (const r of rs) {
      probed++;
      if (r.ok) alive++; else blocked++;
      if (env.KV) {
        const [rServer, ...rPortParts] = r.k.split(":");
        const rPort = rPortParts.join(":");
        const ck = await key(rServer, rPort);
        await env.KV.put(ck, r.ok ? "1" : "0", { expirationTtl: CN_CACHE_TTL })
          .catch(() => {});
      }
    }
  }

  return { probed, alive, blocked, cached: cachedHits };
}
