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

/** 缓存 TTL（秒）—— 6 小时 */
const CN_CACHE_TTL = 6 * 3600;

/** 未知态缓存 TTL（秒）—— 2 小时
 *  ⚠️ 不能太短：否则每轮预热都重新探测同一批失败节点，缓存永远填不满 */
const CN_UNKNOWN_TTL = 2 * 3600;

/** 单次请求最多实时验证多少个节点（保护 CPU）
 *  ⚠️ 太小会导致「超过限额」的节点被当未知剔除，订阅变得很少
 *     预热会把缓存填满，请求时基本只读缓存 */
const CN_MAX_PER_REQUEST = 40;

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
 * CN 验证缓存 —— 批量快照模式
 *
 * ⚠️ KV 配额（免费版 1000 写/天）：
 *   原来「每节点一次 put」→ 480 个节点 = 480 次写
 *   一次全量预热就烧掉近一半配额
 *
 * 现在改为「整个结果集一个 key」：
 *   · 读：1 次 get → 反序列化成 Map（内存）
 *   · 写：1 次 put（整个快照）
 *   · 配额消耗：480 写 → 1 写
 *
 * 快照格式：{ "server:port": 1|0, ... }  仅存布尔，无节点原始信息
 * （server:port 本身是公开信息，如 1.2.3.4:443，不构成泄露）
 */
const SNAPSHOT_KEY = "cnsnap:v1";

interface CNSnapshot {
  /** server:port → 1(可达) / 0(被墙) */
  v: Record<string, 0 | 1>;
  /** 更新时间戳 */
  t: number;
  /** 未知节点（探测失败的，下次重试） */
  u?: Record<string, number>;
}

/** 读取快照（1 次 KV get） */
async function loadSnapshot(env: { KV?: KVNamespace }): Promise<CNSnapshot> {
  if (!env.KV) return { v: {}, t: 0 };
  try {
    const raw = await env.KV.get(SNAPSHOT_KEY, "text");
    if (!raw) return { v: {}, t: 0 };
    const s = JSON.parse(raw) as CNSnapshot;
    return { v: s.v || {}, t: s.t || 0, u: s.u || {} };
  } catch {
    return { v: {}, t: 0 };
  }
}

/** 写快照（1 次 KV put） */
async function saveSnapshot(
  env: { KV?: KVNamespace },
  snap: CNSnapshot,
): Promise<void> {
  if (!env.KV) return;
  snap.t = Date.now();
  await env.KV.put(SNAPSHOT_KEY, JSON.stringify(snap),
                   { expirationTtl: CN_CACHE_TTL }).catch(() => {});
}

/** 缓存 key（哈希，用于快照内的字段名混淆，防止直接读出 IP） */
async function key(server: string, port: string): Promise<string> {
  const raw = `${server.toLowerCase()}:${port}`;
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
  const hex = Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
  return hex.slice(0, 32);
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
 * 验证一批节点的 CN 连通性（快照模式）
 *
 * ⚠️ KV 配额：读 1 次快照 + 写 1 次快照（不是每节点一次）
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

  // ① 读快照（1 次 KV get）
  const snap = opts.refresh ? { v: {}, t: 0 } as CNSnapshot : await loadSnapshot(env);
  const hashes = await Promise.all(
    Array.from(uniq.values()).map(n => key(n.server, n.port)),
  );
  const hashList = Array.from(uniq.keys()).map((k, i) => [k, hashes[i]] as const);

  let cached = 0, probed = 0, blocked = 0, unknown = 0;
  const toProbe: Array<{ k: string; server: string; port: string; h: string }> = [];

  // ② 查快照
  for (const [k, h] of hashList) {
    const n = uniq.get(k)!;
    const hit = snap.v[h];
    if (hit === 1) { alive.add(k); cached++; }
    else if (hit === 0) { cached++; blocked++; }
    else if (toProbe.length < maxProbe) toProbe.push({ k, h, ...n });
    else unknown++;                       // 超过限额 → 未知（剔除）
  }

  if (!toProbe.length) {
    return { alive, probed, cached, blocked, unknown };
  }

  // ③ 并发探测
  const results = await Promise.all(
    toProbe.map(async item => ({
      ...item,
      verdict: await probeCN(item.server, item.port),
    })),
  );

  // ④ 更新快照（内存）
  const v = { ...snap.v };
  const u = { ...(snap.u || {}) };
  for (const r of results) {
    probed++;
    if (r.verdict === true) { v[r.h] = 1; delete u[r.h]; alive.add(r.k); }
    else if (r.verdict === false) { v[r.h] = 0; delete u[r.h]; blocked++; }
    else { unknown++; u[r.h] = (u[r.h] || 0) + 1; }
  }

  // ⑤ 写快照（1 次 KV put）
  await saveSnapshot(env, { v, t: 0, u });

  return { alive, probed, cached, blocked, unknown };
}

/**
 * 预热：批量验证并写快照（供定时任务调用）
 *
 * ⚠️ 日志只输出数量，不输出 server/port
 * ⚠️ KV 消耗：整个预热只写 1 次
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

  // ① 读快照
  const snap = await loadSnapshot(env);
  const v = { ...snap.v };
  const u = { ...(snap.u || {}) };

  let cachedHits = 0, alive = 0, blocked = 0, unknown = 0;
  const pending: Array<{ k: string; h: string; server: string; port: string }> = [];

  // ② 筛出未验证的
  for (const [k, n] of uniq) {
    const h = await key(n.server, n.port);
    const hit = v[h];
    if (hit === 1) { cachedHits++; alive++; continue; }
    if (hit === 0) { cachedHits++; blocked++; continue; }
    // 未知：失败次数 >= 3 就跳过（避免无限重试）
    if ((u[h] || 0) >= 3) { cachedHits++; unknown++; continue; }
    pending.push({ k, h, ...n });
  }

  const items = pending.slice(0, limit);
  let probed = 0;

  // ③ 分批探测
  for (let i = 0; i < items.length; i += concurrency) {
    const batch = items.slice(i, i + concurrency);
    const rs = await Promise.all(batch.map(async it => ({
      ...it,
      verdict: await probeCN(it.server, it.port),
    })));

    for (const r of rs) {
      probed++;
      if (r.verdict === true) { v[r.h] = 1; delete u[r.h]; alive++; }
      else if (r.verdict === false) { v[r.h] = 0; delete u[r.h]; blocked++; }
      else { u[r.h] = (u[r.h] || 0) + 1; unknown++; }
    }
  }

  // ④ 写快照（1 次）
  if (items.length) await saveSnapshot(env, { v, t: 0, u });

  return { probed, alive, blocked, cached: cachedHits, unknown };
}
