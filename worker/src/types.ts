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

export async function cacheGet(env: Env, token: string): Promise<string | null> {
  if (!env.KV) return null;
  return env.KV.get(subCacheKey(token), "text");
}

export async function cachePut(env: Env, token: string, content: string,
                               ttl = 600): Promise<void> {
  if (!env.KV) return;
  await env.KV.put(subCacheKey(token), content, { expirationTtl: ttl });
}

export async function cacheClear(env: Env, token: string): Promise<void> {
  if (!env.KV) return;
  // 同时清理历史遗留 key（旧版本用过多种命名）
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
