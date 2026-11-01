/**
 * 类型定义与 KV 存储层
 */

export interface Env {
  RAW_BASE: string;
  API_TOKEN?: string;
  ADMIN_PASSWORD?: string;
  SESSION_SECRET?: string;
  /** 流量统计接口（服务端 /api/traffic） */
  TRAFFIC_API?: string;
  /** 流量接口密钥 */
  TRAFFIC_SECRET?: string;
  /** 总量上限（字节），默认 2.5TB */
  QUOTA_TOTAL?: string;
  /** 每人上限（字节），默认 1TB */
  QUOTA_PER_USER?: string;
  KV?: KVNamespace;
  /** D1 数据库（CN 验证结果存储，写额度比 KV 宽 100 倍） */
  DB?: D1Database;
  BUCKET?: R2Bucket;
}

/** 一个订阅源 */
export interface SubSource {
  id: string;           // 内部 id
  url: string;          // 订阅 URL
  label?: string;       // 备注名
  enabled: boolean;
  added_at: string;
}

/** 订阅配置（存在 KV） */
export interface SubConfig {
  token: string;              // URL 里的 token
  name: string;               // 订阅名称
  sources: SubSource[];       // 聚合源
  rename: boolean;            // 是否重命名节点
  min_tier: "all" | "A" | "S"; // 质量过滤
  probe: boolean;             // 是否测活（剔除失效节点）
  /** 是否只保留 CN（中国）实测可达的节点 */
  cn_only: boolean;
  /** 同 server:port 只保留评分最高的一个（默认 true，避免同一服务器重复出现） */
  dedup_server: boolean;
  /** 是否启用评分筛选（剔除 http/socks/anytls + 控制总量） */
  filter: boolean;
  /** 目标节点数上限（默认 300） */
  target_nodes: number;
  rules_mode: "builtin" | "custom"; // 规则来源
  rules?: string;             // 自定义规则 YAML
  updated_at: string;
  hits: number;               // 访问次数
}

/** 全局设置 */
export interface GlobalConfig {
  default_rules: string;      // 默认规则 YAML
  updated_at: string;
}

const KV_PREFIX = {
  sub: "sub:",          // sub:<token> → SubConfig
  global: "global:",    // global:<key> → value
  cache: "cache:",      // cache:<token> → 生成的订阅（带 TTL）
  session: "session:",  // session:<id> → 过期时间
};

// ── KV 操作封装 ──

export async function kvGetJSON<T>(env: Env, key: string): Promise<T | null> {
  if (!env.KV) return null;
  try {
    const raw = await env.KV.get(key, "text");
    if (!raw) return null;
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export async function kvPutJSON(env: Env, key: string, value: unknown,
                                 ttl?: number): Promise<void> {
  if (!env.KV) throw new Error("KV not bound");
  const opts = ttl ? { expirationTtl: ttl } : undefined;
  await env.KV.put(key, JSON.stringify(value), opts);
}

export async function kvDelete(env: Env, key: string): Promise<void> {
  if (!env.KV) return;
  await env.KV.delete(key);
}

export async function kvList(env: Env, prefix: string): Promise<string[]> {
  if (!env.KV) return [];
  const out: string[] = [];
  let cursor: string | undefined;
  do {
    const res = await env.KV.list({ prefix, cursor });
    for (const k of res.keys) out.push(k.name);
    cursor = res.list_complete ? undefined : res.cursor;
  } while (cursor);
  return out;
}

// ── 业务操作 ──

export function subKey(token: string): string {
  return KV_PREFIX.sub + token;
}

export async function getSub(env: Env, token: string): Promise<SubConfig | null> {
  return kvGetJSON<SubConfig>(env, subKey(token));
}

export async function putSub(env: Env, cfg: SubConfig): Promise<void> {
  cfg.updated_at = new Date().toISOString();
  await kvPutJSON(env, subKey(cfg.token), cfg);
}

export async function deleteSub(env: Env, token: string): Promise<void> {
  await kvDelete(env, subKey(token));
  await kvDelete(env, KV_PREFIX.cache + token);
}

export async function listSubs(env: Env): Promise<SubConfig[]> {
  const keys = await kvList(env, KV_PREFIX.sub);
  const out: SubConfig[] = [];
  for (const k of keys) {
    const v = await kvGetJSON<SubConfig>(env, k);
    if (v) out.push(v);
  }
  return out.sort((a, b) => (b.updated_at || "").localeCompare(a.updated_at || ""));
}

export async function getGlobal(env: Env): Promise<GlobalConfig> {
  const g = await kvGetJSON<GlobalConfig>(env, KV_PREFIX.global + "config");
  if (g) return g;
  // 默认使用用户预设模板（DNS + 分流规则 + 39 个 rule-providers）
  return { default_rules: "", updated_at: new Date().toISOString() };
}

export async function putGlobal(env: Env, g: GlobalConfig): Promise<void> {
  g.updated_at = new Date().toISOString();
  await kvPutJSON(env, KV_PREFIX.global + "config", g);
}

/**
 * 订阅结果缓存
 *
 * 设计要点（KV 免费版仅 1000 写/天）：
 *   1. **只用一个 key**：`cache:sub:<token>`，不按格式/参数分裂（避免写放大 + 命中率稀释）
 *   2. 缓存的是**渲染后的 YAML**，txt/json 由同一份内容派生，不单独写
 *   3. 清除时必须用同一个 key（此前的 bug：cacheClear 删的 key 与实际写入的不一致）
 *   4. 内容变更（改源/改规则）→ 立即清除
 */
function subCacheKey(token: string): string {
  return KV_PREFIX.cache + "sub:" + token;
}

/**
 * 订阅缓存 —— D1 优先，KV 兜底
 *
 * ⚠️ 为什么改 D1：
 *   KV 免费版写配额只有 1,000/天，订阅缓存每次生成都要写 → 很快耗尽。
 *   配额耗尽后缓存永远 miss → 每个请求都重新聚合 5 个源（6-13 秒）
 *   → 客户端「更新订阅」超时失败。
 *
 *   D1 免费版写 100,000 行/天（宽 100 倍），实测稳定。
 *
 * 表结构：
 *   CREATE TABLE sub_cache (token TEXT PRIMARY KEY, body TEXT, ts INTEGER);
 */
let subTableEnsured = false;

async function ensureSubTable(env: Env): Promise<boolean> {
  if (!env.DB) return false;
  if (subTableEnsured) return true;
  try {
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS sub_cache (
         token TEXT PRIMARY KEY,
         body  TEXT NOT NULL,
         ts    INTEGER NOT NULL
       )`,
    ).run();
    subTableEnsured = true;
    return true;
  } catch (e) {
    console.error("[cache] ensureSubTable failed:",
                  e instanceof Error ? e.message : String(e));
    return false;
  }
}

export async function cacheGet(env: Env, token: string): Promise<string | null> {
  // ① D1 优先
  if (env.DB && (await ensureSubTable(env))) {
    try {
      const row = await env.DB.prepare(
        `SELECT body, ts FROM sub_cache WHERE token = ?`,
      ).bind(token).first() as { body?: string; ts?: number } | null;
      if (row?.body) {
        // 检查 TTL（30 分钟 —— sub-refresh 每 15 分钟重新预热）
        const age = (Date.now() - (row.ts || 0)) / 1000;
        if (age < 1800) return row.body;
      }
    } catch { /* 落到 KV */ }
  }
  // ② KV 兜底
  if (env.KV) {
    try {
      return await env.KV.get(subCacheKey(token), "text");
    } catch { /* ignore */ }
  }
  return null;
}

export async function cachePut(env: Env, token: string, content: string,
                               ttl = 600): Promise<void> {
  // ① D1（主）
  if (env.DB && (await ensureSubTable(env))) {
    try {
      await env.DB.prepare(
        `INSERT INTO sub_cache (token, body, ts) VALUES (?, ?, ?)
         ON CONFLICT(token) DO UPDATE SET body=excluded.body, ts=excluded.ts`,
      ).bind(token, content, Date.now()).run();
      // 顺便清理过期记录（>1 天）
      if (Math.random() < 0.1) {
        env.DB.prepare(`DELETE FROM sub_cache WHERE ts < ?`)
          .bind(Date.now() - 86400000).run().catch(() => {});
      }
    } catch (e) {
      console.error("[cache] D1 put failed:",
                    e instanceof Error ? e.message : String(e));
    }
  }
  // ② KV（备份，失败不影响）
  if (env.KV) {
    try {
      await env.KV.put(subCacheKey(token), content, { expirationTtl: ttl });
    } catch { /* 配额耗尽是常态，忽略 */ }
  }
}

export async function cacheClear(env: Env, token: string): Promise<void> {
  // D1
  if (env.DB) {
    try {
      await env.DB.prepare(`DELETE FROM sub_cache WHERE token = ?`)
        .bind(token).run();
    } catch { /* ignore */ }
  }
  // KV（含历史遗留 key）
  if (!env.KV) return;
  const keys = [
    subCacheKey(token),
    subCacheKey(token) + ":stats",
    KV_PREFIX.cache + token,
    KV_PREFIX.cache + token + ".yaml",
    KV_PREFIX.cache + token + ".yml",
    KV_PREFIX.cache + token + ".yaml.p",
    KV_PREFIX.cache + token + ".txt",
    KV_PREFIX.cache + token + ".txt.p",
  ];
  await Promise.all(keys.map(k => env.KV!.delete(k).catch(() => {})));
}

// ── 默认规则 ──

export const DEFAULT_RULES = `# ── 默认分流规则 ──
# 可按需修改；语法同 Clash/Mihomo

rules:
  # 局域网直连
  - GEOIP,LAN,DIRECT,no-resolve
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve

  # 广告拦截
  - DOMAIN-SUFFIX,doubleclick.net,REJECT
  - DOMAIN-SUFFIX,googleadservices.com,REJECT
  - DOMAIN-KEYWORD,analytics,REJECT

  # 国内直连
  - GEOIP,CN,DIRECT
  - DOMAIN-SUFFIX,cn,DIRECT

  # 其余走代理
  - MATCH,PROXY
`;

/** 生成随机 token */
export function randomToken(len = 16): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => chars[b % chars.length]).join("");
}

/** 生成随机 id */
export function randomId(len = 8): string {
  return randomToken(len);
}
