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
 * CN 验证结果存储 —— 用 D1（不是 KV）
 *
 * ⚠️ 为什么换 D1：
 *   KV 免费版写配额只有 1,000/天，而预热需要频繁写入。
 *   即使改成「整快照 1 次写」，仍受限于 KV 的配额池。
 *   D1 免费版写 **100,000 行/天**（宽 100 倍），且支持 SQL 查询。
 *
 * 表结构（单表，一行一条记录）：
 *   CREATE TABLE cn_verify (
 *     hash    TEXT PRIMARY KEY,   -- sha256(server:port) 前 32 位
 *     ok      INTEGER NOT NULL,   -- 1=可达 / 0=被墙
 *     ts      INTEGER NOT NULL,   -- 验证时间戳
 *     fails   INTEGER DEFAULT 0   -- 连续探测失败次数
 *   );
 *
 * ⚠️ 安全：只存哈希，不存 server/port 明文
 */

/** 环境（含 D1 绑定） */
export interface CNEnv {
  DB?: D1Database;
  KV?: KVNamespace;
}

/** 确保表存在（幂等，每次调用代价很低） */
let tableEnsured = false;
async function ensureTable(env: CNEnv): Promise<boolean> {
  if (!env.DB) return false;
  if (tableEnsured) return true;
  try {
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS cn_verify (
         hash  TEXT PRIMARY KEY,
         ok    INTEGER NOT NULL,
         ts    INTEGER NOT NULL,
         fails INTEGER DEFAULT 0
       )`,
    ).run();
    tableEnsured = true;
    return true;
  } catch (e) {
    console.error("[cn] ensureTable failed:", e instanceof Error ? e.message : String(e));
    return false;
  }
}

/** 批量查询验证结果（1 次 SQL） */
async function loadResults(
  env: CNEnv,
  hashes: string[],
): Promise<Map<string, { ok: boolean; fails: number }>> {
  const out = new Map<string, { ok: boolean; fails: number }>();
  if (!env.DB || !hashes.length) return out;
  if (!(await ensureTable(env))) return out;

  try {
    // 分批 IN 查询（D1 参数上限约 100）
    const CHUNK = 90;
    for (let i = 0; i < hashes.length; i += CHUNK) {
      const batch = hashes.slice(i, i + CHUNK);
      const ph = batch.map(() => "?").join(",");
      const rs = await env.DB.prepare(
        `SELECT hash, ok, fails FROM cn_verify WHERE hash IN (${ph})`,
      ).bind(...batch).all();
      for (const r of (rs.results || []) as Array<{ hash: string; ok: number; fails: number }>) {
        out.set(r.hash, { ok: r.ok === 1, fails: r.fails || 0 });
      }
    }
  } catch (e) {
    console.error("[cn] loadResults failed:", e instanceof Error ? e.message : String(e));
  }
  return out;
}

/** 批量写入验证结果（D1 batch，1 次往返） */
async function saveResults(
  env: CNEnv,
  rows: Array<{ hash: string; ok: boolean; fails: number }>,
): Promise<void> {
  if (!env.DB || !rows.length) return;
  if (!(await ensureTable(env))) return;

  try {
    const now = Date.now();
    const stmt = env.DB.prepare(
      `INSERT INTO cn_verify (hash, ok, ts, fails) VALUES (?, ?, ?, ?)
       ON CONFLICT(hash) DO UPDATE SET ok=excluded.ok, ts=excluded.ts, fails=excluded.fails`,
    );
    // batch 上限 100 条
    const CHUNK = 90;
    for (let i = 0; i < rows.length; i += CHUNK) {
      const batch = rows.slice(i, i + CHUNK).map(r =>
        stmt.bind(r.hash, r.ok ? 1 : 0, now, r.fails),
      );
      await env.DB.batch(batch);
    }
  } catch (e) {
    console.error("[cn] saveResults failed:", e instanceof Error ? e.message : String(e));
  }
}

/** 清理过期记录（>7 天） */
async function pruneOld(env: CNEnv): Promise<void> {
  if (!env.DB) return;
  try {
    const cutoff = Date.now() - 7 * 24 * 3600 * 1000;
    await env.DB.prepare(`DELETE FROM cn_verify WHERE ts < ?`).bind(cutoff).run();
  } catch { /* ignore */ }
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
 * 验证一批节点的 CN 连通性（D1 存储）
 *
 * 流程：
 *   ① 批量查 D1（1 次 SQL）
 *   ② 缓存命中的直接用
 *   ③ 未命中的实时探测（受 maxProbe 限制）
 *   ④ 批量写 D1（1 次 batch）
 */
export async function verifyCN(
  nodes: Array<{ server: string; port: string }>,
  env: CNEnv,
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
  if (!uniq.size) {
    return { alive, probed: 0, cached: 0, blocked: 0, unknown: 0 };
  }

  // 算哈希
  const entries = await Promise.all(
    Array.from(uniq.entries()).map(async ([k, n]) => ({ k, n, h: await key(n.server, n.port) })),
  );

  // ① 批量查（1 次 SQL）
  const known = opts.refresh
    ? new Map<string, { ok: boolean; fails: number }>()
    : await loadResults(env, entries.map(e => e.h));

  let cached = 0, blocked = 0, unknown = 0;
  const toProbe: typeof entries = [];

  for (const e of entries) {
    const hit = known.get(e.h);
    if (hit) {
      cached++;
      if (hit.ok) alive.add(e.k);
      else blocked++;
    } else if (toProbe.length < maxProbe) {
      toProbe.push(e);
    } else {
      unknown++;                    // 超过限额 → 未知（剔除）
    }
  }

  if (!toProbe.length) {
    return { alive, probed: 0, cached, blocked, unknown };
  }

  // ③ 实时探测
  const probed: Array<{ hash: string; ok: boolean; fails: number }> = [];
  const results = await Promise.all(
    toProbe.map(async e => ({ ...e, verdict: await probeCN(e.n.server, e.n.port) })),
  );

  for (const r of results) {
    const prevFails = known.get(r.h)?.fails ?? 0;
    if (r.verdict === true) {
      alive.add(r.k);
      probed.push({ hash: r.h, ok: true, fails: 0 });
    } else if (r.verdict === false) {
      blocked++;
      probed.push({ hash: r.h, ok: false, fails: 0 });
    } else {
      unknown++;
      probed.push({ hash: r.h, ok: false, fails: Math.min(prevFails + 1, 99) });
    }
  }

  // ④ 批量写（1 次 batch）
  await saveResults(env, probed);

  return { alive, probed: probed.length, cached, blocked, unknown };
}

/**
 * 预热：批量验证并写 D1
 *
 * ⚠️ 日志只输出数量，不输出 server/port
 */
export async function warmCNCache(
  nodes: Array<{ server: string; port: string }>,
  env: CNEnv,
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
  if (!uniq.size) {
    return { probed: 0, alive: 0, blocked: 0, cached: 0, unknown: 0 };
  }

  // 算哈希
  const entries = await Promise.all(
    Array.from(uniq.entries()).map(async ([k, n]) => ({ k, n, h: await key(n.server, n.port) })),
  );

  // ① 批量查
  const known = await loadResults(env, entries.map(e => e.h));

  let cachedHits = 0, alive = 0, blocked = 0, unknown = 0;
  const pending: typeof entries = [];

  for (const e of entries) {
    const hit = known.get(e.h);
    if (hit) {
      cachedHits++;
      if (hit.ok) alive++; else blocked++;
      continue;
    }
    pending.push(e);
  }

  const items = pending.slice(0, limit);
  const rows: Array<{ hash: string; ok: boolean; fails: number }> = [];

  // ② 分批探测
  for (let i = 0; i < items.length; i += concurrency) {
    const batch = items.slice(i, i + concurrency);
    const rs = await Promise.all(batch.map(async e => ({
      ...e,
      verdict: await probeCN(e.n.server, e.n.port),
    })));

    for (const r of rs) {
      const prevFails = known.get(r.h)?.fails ?? 0;
      if (r.verdict === true) {
        alive++;
        rows.push({ hash: r.h, ok: true, fails: 0 });
      } else if (r.verdict === false) {
        blocked++;
        rows.push({ hash: r.h, ok: false, fails: 0 });
      } else {
        unknown++;
        rows.push({ hash: r.h, ok: false, fails: Math.min(prevFails + 1, 99) });
      }
    }
  }

  // ③ 批量写
  if (rows.length) {
    await saveResults(env, rows);
    // 偶尔清理过期记录
    if (Math.random() < 0.05) await pruneOld(env);
  }

  return { probed: rows.length, alive, blocked, cached: cachedHits, unknown };
}
