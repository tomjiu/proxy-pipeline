/**
 * Cloudflare Worker — 订阅聚合管理面板
 *
 * 功能：
 *   1. 登录（固定密码 + 签名 Cookie）
 *   2. 订阅管理（多源聚合，存 KV）
 *   3. 规则编辑
 *   4. 生成可导入的订阅链接
 *   5. 保留原有只读 API（/pool/* /sub/nodes /meta）
 *
 * 路由：
 *   GET  /                       仪表盘（未登录跳登录页）
 *   GET  /login                  登录页
 *   POST /login                  登录提交
 *   POST /logout                 退出
 *   GET  /api/subs               列出订阅
 *   POST /api/subs               新建订阅
 *   PATCH/DELETE /api/subs/:tok  修改/删除
 *   POST /api/subs/:tok/sources  添加源
 *   PATCH/DELETE /api/subs/:tok/sources/:i
 *   GET  /api/subs/:tok/test     测试所有源
 *   GET/PUT /api/rules           规则
 *   GET  /sub/:tok.yaml          Clash 订阅（公开，token 即凭据）
 *   GET  /sub/:tok.txt           Base64 订阅（公开）
 *   ── 原有只读 API ──
 *   GET  /meta /pool/* /sub/nodes /sub/base64 /sub/clash
 */

import type { Env, SubConfig, SubSource } from "./types";
import {
  getSub, putSub, deleteSub, listSubs, getGlobal, putGlobal,
  cacheGet, cachePut, cacheClear, randomToken, randomId,
} from "./types";
import {
  isAuthed, checkPassword, createSession, sessionCookie, clearCookie,
  authRequired,
} from "./auth";
import {
  aggregate, buildClash, buildBase64, renameSimple, fetchSource,
  type ParsedNode,
} from "./subscription";
import { loginPage, dashboardPage } from "./ui";
import { DEFAULT_TEMPLATE } from "./default-template";
import { probeCFNodes, filterCFAlive, isCFNode, type CFProbeResult } from "./cf-probe";

const CACHE_TTL = 120;
const GEN_CACHE_TTL = 300;   // 生成的订阅缓存 5 分钟

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const method = req.method;

    if (method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET, POST, PATCH, DELETE, PUT, OPTIONS",
          "access-control-allow-headers": "Content-Type, X-Api-Token",
        },
      });
    }

    try {
      // ── 认证路由 ──
      if (path === "/login" && method === "GET") {
        return html(loginPage(undefined, url.searchParams.get("next") || "/"));
      }
      if (path === "/login" && method === "POST") {
        return await handleLogin(req, env);
      }
      if (path === "/logout") {
        return new Response(null, {
          status: 302,
          headers: { location: "/login", "set-cookie": clearCookie() },
        });
      }

      // ── 公开订阅（token 即凭据，无需登录）──
      const subMatch = path.match(/^\/sub\/([a-z0-9]{6,64})\.(yaml|yml|txt|json)$/);
      if (subMatch) {
        return await serveSubscription(env, subMatch[1], subMatch[2], req);
      }

      // ── 公开只读 API（数据来自公开仓库，无需登录）──
      // 注意：必须在认证检查之前处理
      const pub = await handlePublicApi(req, env, path);
      if (pub) return pub;

      // ── 以下需要登录（若配置了密码）──
      const needsAuth = authRequired(env) && !isApiTokenRequest(req, env);
      if (needsAuth && !(await isAuthed(req, env))) {
        if (path.startsWith("/api/")) {
          return json({ error: "unauthorized" }, 401);
        }
        return new Response(null, {
          status: 302,
          headers: { location: "/login?next=" + encodeURIComponent(path) },
        });
      }

      // ── 仪表盘 ──
      if (path === "/" && wantsHtml(req)) {
        const subs = await listSubs(env);
        const g = await getGlobal(env);
        return html(dashboardPage({
          subs: subs.map(s => ({
            token: s.token, name: s.name, sources: s.sources,
            rename: s.rename, min_tier: s.min_tier, rules_mode: s.rules_mode,
            updated_at: s.updated_at, hits: s.hits || 0,
          })),
          defaultRules: g.default_rules,
          origin: url.origin,
        }));
      }

      // ── API：订阅管理 ──
      if (path === "/api/subs") {
        if (method === "GET") {
          const subs = await listSubs(env);
          return json({ subs });
        }
        if (method === "POST") return await createSub(req, env);
      }

      const subApi = path.match(/^\/api\/subs\/([a-z0-9]{6,64})(\/.*)?$/);
      if (subApi) {
        return await handleSubApi(req, env, subApi[1], subApi[2] || "");
      }

      // ── API：流量 ──
      if (path === "/api/traffic" && method === "GET") {
        return json(await trafficSummary(env));
      }

      // ── API：规则 ──
      if (path === "/api/rules") {
        const g = await getGlobal(env);
        if (method === "GET") return json({ rules: g.default_rules });
        if (method === "PUT") {
          const body = await readJson(req);
          if (typeof body.rules !== "string") return json({ error: "rules required" }, 400);
          await putGlobal(env, { default_rules: body.rules, updated_at: g.updated_at });
          return json({ ok: true });
        }
      }

      return json({ error: "not found", path }, 404);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return json({ error: "internal", message: msg }, 500);
    }
  },
};

// ══════════ 登录 ══════════

async function handleLogin(req: Request, env: Env): Promise<Response> {
  let password = "";
  let next = "/";
  const ct = req.headers.get("content-type") || "";

  if (ct.includes("application/json")) {
    const b = await readJson(req);
    password = String(b.password || "");
    next = String(b.next || "/");
  } else {
    const form = await req.formData();
    password = String(form.get("password") || "");
    next = String(form.get("next") || "/");
  }

  if (!env.ADMIN_PASSWORD) {
    return html(loginPage("服务端未配置 ADMIN_PASSWORD，无法登录", next), 500);
  }
  if (!checkPassword(env, password)) {
    return html(loginPage("密码错误", next), 401);
  }

  const token = await createSession(env);
  // 安全检查：next 必须是站内路径
  const safeNext = next.startsWith("/") && !next.startsWith("//") ? next : "/";
  return new Response(null, {
    status: 302,
    headers: { location: safeNext, "set-cookie": sessionCookie(token) },
  });
}

// ══════════ 订阅管理 API ══════════

async function createSub(req: Request, env: Env): Promise<Response> {
  if (!env.KV) return json({ error: "KV not bound — 请先配置 KV 命名空间" }, 503);
  const body = await readJson(req);

  const sources: SubSource[] = Array.isArray(body.sources)
    ? body.sources
        .filter((s: any) => s && typeof s.url === "string" && /^https?:\/\//.test(s.url))
        .map((s: any) => ({
          id: randomId(),
          url: String(s.url).trim(),
          label: String(s.label || "").slice(0, 60),
          enabled: s.enabled !== false,
          added_at: new Date().toISOString(),
        }))
    : [];

  if (!sources.length) return json({ error: "至少需要一个有效的 http(s) 订阅源" }, 400);

  const cfg: SubConfig = {
    token: randomToken(16),
    name: String(body.name || "我的订阅").slice(0, 60),
    sources,
    rename: body.rename !== false,
    min_tier: ["all", "A", "S"].includes(body.min_tier) ? body.min_tier : "all",
    probe: body.probe !== false,
    rules_mode: body.rules_mode === "custom" ? "custom" : "builtin",
    updated_at: new Date().toISOString(),
    hits: 0,
  };
  await putSub(env, cfg);
  return json({ ok: true, sub: cfg });
}

async function handleSubApi(req: Request, env: Env, token: string,
                            rest: string): Promise<Response> {
  const cfg = await getSub(env, token);
  if (!cfg) return json({ error: "not found" }, 404);
  const method = req.method;

  // /api/subs/:tok
  if (rest === "") {
    if (method === "GET") return json({ sub: cfg });
    if (method === "DELETE") {
      await deleteSub(env, token);
      return json({ ok: true });
    }
    if (method === "PATCH") {
      const b = await readJson(req);
      if (typeof b.name === "string") cfg.name = b.name.slice(0, 60);
      if (typeof b.rename === "boolean") cfg.rename = b.rename;
      if (typeof b.probe === "boolean") cfg.probe = b.probe;
      if (["all", "A", "S"].includes(b.min_tier)) cfg.min_tier = b.min_tier;
      if (["builtin", "custom"].includes(b.rules_mode)) cfg.rules_mode = b.rules_mode;
      if (typeof b.rules === "string") cfg.rules = b.rules.slice(0, 20000);
      await putSub(env, cfg);
      await cacheClear(env, token);
      return json({ ok: true, sub: cfg });
    }
  }

  // /api/subs/:tok/sources
  if (rest === "/sources" && method === "POST") {
    const b = await readJson(req);
    if (typeof b.url !== "string" || !/^https?:\/\//.test(b.url)) {
      return json({ error: "invalid url" }, 400);
    }
    cfg.sources.push({
      id: randomId(),
      url: b.url.trim(),
      label: String(b.label || "").slice(0, 60),
      enabled: b.enabled !== false,
      added_at: new Date().toISOString(),
    });
    await putSub(env, cfg);
    await cacheClear(env, token);
    return json({ ok: true, sub: cfg });
  }

  // /api/subs/:tok/sources/:idx
  const srcM = rest.match(/^\/sources\/(\d+)$/);
  if (srcM) {
    const idx = parseInt(srcM[1], 10);
    if (idx < 0 || idx >= cfg.sources.length) return json({ error: "index out of range" }, 404);

    if (method === "DELETE") {
      cfg.sources.splice(idx, 1);
      await putSub(env, cfg);
      await cacheClear(env, token);
      return json({ ok: true, sub: cfg });
    }
    if (method === "PATCH") {
      const b = await readJson(req);
      if (typeof b.url === "string" && /^https?:\/\//.test(b.url)) {
        cfg.sources[idx].url = b.url.trim();
      }
      if (typeof b.label === "string") cfg.sources[idx].label = b.label.slice(0, 60);
      if (typeof b.enabled === "boolean") cfg.sources[idx].enabled = b.enabled;
      await putSub(env, cfg);
      await cacheClear(env, token);
      return json({ ok: true, sub: cfg });
    }
  }

  // /api/subs/:tok/test
  if (rest === "/test" && method === "GET") {
    const results = await Promise.all(cfg.sources.map(async s => {
      const r = await fetchSource(s, 12000);
      return {
        url: s.url, label: s.label, ok: r.ok, format: r.format,
        nodes: r.nodes.length, error: r.error, status: r.status,
      };
    }));
    const total = results.reduce((a, r) => a + r.nodes, 0);
    return json({ results, nodes: total });
  }

  return json({ error: "not found" }, 404);
}

// ══════════ 生成并返回订阅 ══════════

async function serveSubscription(env: Env, token: string, ext: string,
                                 req: Request): Promise<Response> {
  const cfg = await getSub(env, token);
  if (!cfg) {
    return new Response("subscription not found\n", {
      status: 404,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  const isJson = ext === "json";
  const cb = new URL(req.url).searchParams.get("cb");
  // 测活开关：?probe=0 跳过，?probe=1 强制
  const probeParam = new URL(req.url).searchParams.get("probe");
  const doProbe = probeParam === "1" || (probeParam !== "0" && cfg.probe !== false);

  // 缓存 key 带 probe 标记（不同结果分开缓存）
  const cacheKey = `${token}.${ext}${doProbe ? ".p" : ""}`;

  // 缓存命中（仍要带流量头，所以先取流量）
  if (!isJson && !cb) {
    const cached = await cacheGet(env, cacheKey);
    if (cached) {
      const t = await getTraffic(env);
      return subResponse(cached, ext, true, null, t);
    }
  }

  // ── 1. 聚合 ──
  const agg = await aggregate(cfg.sources);
  let nodes: ParsedNode[] = agg.nodes;

  // ── 2. 测活（默认关闭）──
  // 实测结论（2026-10）：
  //   ❌ CF Worker 无 TCP socket API → 无法探测 hy2/vless 直连节点
  //   ⚠️ 指向域名的 ws 节点可 fetch（101），但指向 CF 任播 IP 的会被自己边缘拦（403）
  //   ⚠️ 大规模测活会耗尽免费版 10ms CPU 配额（Error 1102）
  //
  // 策略：**不测活，改为勤更新**；客户端用 url-test 组自动选优。
  // 如需临时开启：?probe=1
  let probeStats: { total: number; probeable: number; alive: number; dead: number; skipped: number } | null = null;
  let probeDetail: CFProbeResult[] = [];
  if (doProbe && nodes.length) {
    try {
      const r = await probeCFNodes(nodes, { concurrency: 6, maxProbe: 40, timeoutMs: 5000 });
      probeStats = r.stats;
      probeDetail = r.results;
      const before = nodes.length;
      nodes = filterCFAlive(nodes, r.results);
      console.log(`[probe] ${before} -> ${nodes.length} (probeable=${r.stats.probeable} alive=${r.stats.alive} dead=${r.stats.dead})`);
    } catch (e) {
      console.error("[probe] failed:", e);
      probeStats = null;
    }
  }

  // ── 3. 重命名 ──
  if (cfg.rename) nodes = renameSimple(nodes);

  // ── 4. tier 过滤 ──
  if (cfg.min_tier !== "all") {
    try {
      const tierRes = await fetchDist(env, "clean/quality_tiers.json");
      if (tierRes.ok) {
        const t = await tierRes.json() as any;
        const want = cfg.min_tier === "S" ? new Set(t.tier_S || [])
                                          : new Set([...(t.tier_S || []), ...(t.tier_A || [])]);
        const before = nodes.length;
        nodes = nodes.filter(n => want.has(n.name));
        // 重命名后名字变了 → 无匹配则回退到不过滤（避免空订阅）
        if (nodes.length === 0 && before > 0) {
          nodes = cfg.rename ? renameSimple(agg.nodes) : agg.nodes;
        }
      }
    } catch { /* 过滤失败则不过滤 */ }
  }

  // ── 5. 输出 ──
  const traffic = await getTraffic(env);

  if (isJson) {
    return json({
      token, name: cfg.name, nodes: nodes.length,
      probe: probeStats,
      probe_method: "CF-node WebSocket/HTTP (only network:ws + CF IP)",
      probe_samples: probeDetail.slice(0, 40).map(r => ({
        name: r.name, server: r.server, port: r.port, type: r.type,
        network: r.network, method: r.method, alive: r.alive,
        ms: r.ms, status: r.status, error: r.error,
      })),
      traffic: await trafficSummary(env),
      sources: agg.results.map(r => ({
        url: r.url, ok: r.ok, format: r.format, nodes: r.nodes.length,
        bytes: r.bytes, error: r.error,
      })),
      duplicates: agg.duplicates, total_fetched: agg.total_fetched,
    });
  }

  let content: string;
  if (ext === "txt") {
    content = buildBase64(nodes);
  } else {
    const g = await getGlobal(env);
    // 规则来源：自定义 > 全局 > 内置模板
    const template = cfg.rules_mode === "custom" && cfg.rules
      ? undefined                       // 自定义规则 → 不用模板，走精简生成
      : (g.default_rules && g.default_rules.length > 100 ? undefined : DEFAULT_TEMPLATE);
    const rules = cfg.rules_mode === "custom" && cfg.rules ? cfg.rules : g.default_rules;
    content = buildClash(nodes, {
      rename: cfg.rename,
      rules,
      title: cfg.name,
      template,
    });
  }

  await cachePut(env, cacheKey, content, GEN_CACHE_TTL);

  cfg.hits = (cfg.hits || 0) + 1;
  putSub(env, cfg).catch(() => {});

  return subResponse(content, ext, false, probeStats, traffic);
}


// ══════════ 流量统计 ══════════

/**
 * 查询流量用量。
 *
 * 环境变量（可选）：
 *   TRAFFIC_API     服务端流量接口，如 https://san.example.com/traffic
 *   TRAFFIC_SECRET  接口密钥（Authorization 头）
 *   QUOTA_TOTAL     总量上限（字节），默认 2.5 TB
 *   QUOTA_PER_USER  每人上限（字节），默认 1 TB
 *
 * 未配置 TRAFFIC_API 时返回 0/默认上限（不影响订阅可用）。
 */
const DEFAULT_TOTAL_BYTES = 2560 * 1024 ** 3;      // 2.5 TB
const DEFAULT_PER_USER_BYTES = 1024 * 1024 ** 3;   // 1 TB

interface TrafficInfo {
  used: number;
  total: number;
  source: string;
  perUser: Record<string, { used: number; total: number }>;
}

let trafficCache: { at: number; data: TrafficInfo } | null = null;
const TRAFFIC_CACHE_TTL = 60_000;

async function getTraffic(env: Env): Promise<TrafficInfo> {
  const total = parseInt((env as any).QUOTA_TOTAL || "", 10) || DEFAULT_TOTAL_BYTES;
  const perUserLimit = parseInt((env as any).QUOTA_PER_USER || "", 10) || DEFAULT_PER_USER_BYTES;

  if (trafficCache && Date.now() - trafficCache.at < TRAFFIC_CACHE_TTL) {
    return trafficCache.data;
  }

  const empty: TrafficInfo = { used: 0, total, source: "none", perUser: {} };
  const api = (env as any).TRAFFIC_API;
  const secret = (env as any).TRAFFIC_SECRET;
  if (!api) {
    trafficCache = { at: Date.now(), data: empty };
    return empty;
  }

  try {
    const res = await fetch(api, {
      headers: secret ? { Authorization: secret } : {},
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json() as Record<string, any>;

    let sum = 0;
    const perUser: Record<string, { used: number; total: number }> = {};
    for (const [k, v] of Object.entries(data)) {
      if (k === "acme" || !v || typeof v !== "object") continue;
      const bytes = (Number(v.tx) || 0) + (Number(v.rx) || 0);
      sum += bytes;
      perUser[k] = { used: bytes, total: perUserLimit };
    }
    if (sum === 0 && typeof data.total === "number") sum = data.total;

    const info: TrafficInfo = { used: sum, total, source: "trafficStats", perUser };
    trafficCache = { at: Date.now(), data: info };
    return info;
  } catch {
    trafficCache = { at: Date.now(), data: empty };
    return empty;
  }
}

/** 供 UI 显示：总量 + 剩余 */
async function trafficSummary(env: Env): Promise<{
  used: number; total: number; remain: number; pct: number;
  used_gb: number; total_gb: number; remain_gb: number; source: string;
  per_user: Record<string, { used_gb: number; total_gb: number; remain_gb: number; pct: number }>;
}> {
  const t = await getTraffic(env);
  const GB = 1024 ** 3;
  const perUser: Record<string, any> = {};
  for (const [k, v] of Object.entries(t.perUser)) {
    perUser[k] = {
      used_gb: +(v.used / GB).toFixed(2),
      total_gb: +(v.total / GB).toFixed(2),
      remain_gb: +((v.total - v.used) / GB).toFixed(2),
      pct: +(v.used * 100 / v.total).toFixed(2),
    };
  }
  return {
    used: t.used, total: t.total,
    remain: Math.max(0, t.total - t.used),
    pct: +(t.used * 100 / t.total).toFixed(2),
    used_gb: +(t.used / GB).toFixed(2),
    total_gb: +(t.total / GB).toFixed(2),
    remain_gb: +((t.total - t.used) / GB).toFixed(2),
    source: t.source,
    per_user: perUser,
  };
}


function subResponse(content: string, ext: string, cached: boolean,
                     probe: { total: number; probeable: number; alive: number; dead: number; skipped: number } | null,
                     traffic: TrafficInfo | null): Response {
  const ct = ext === "txt" ? "text/plain; charset=utf-8"
           : ext === "json" ? "application/json; charset=utf-8"
           : "text/yaml; charset=utf-8";
  const headers: Record<string, string> = {
    "content-type": ct,
    "cache-control": "public, max-age=60",
    "access-control-allow-origin": "*",
    "x-cached": cached ? "hit" : "miss",
    "profile-update-interval": "6",
  };
  if (traffic) {
    headers["subscription-userinfo"] =
      `upload=0; download=${traffic.used}; total=${traffic.total}; expire=0`;
    headers["x-traffic"] =
      `used=${traffic.used};total=${traffic.total};remain=${Math.max(0, traffic.total - traffic.used)};src=${traffic.source}`;
  }
  if (probe) {
    headers["x-probe"] = `total=${probe.total};probeable=${probe.probeable};alive=${probe.alive};dead=${probe.dead};skip=${probe.skipped}`;
  }
  return new Response(content, { headers });
}

// ══════════ 公开只读 API ══════════
// 数据源是公开 GitHub 仓库，本身不敏感；开放访问便于客户端直接使用。

async function handlePublicApi(req: Request, env: Env,
                               path: string): Promise<Response | null> {
  if (path === "/health") {
    return json({ ok: true, service: "proxy-pipeline-worker",
                  kv: !!env.KV, auth: authRequired(env) });
  }
  if (path === "/meta") return withCors(await fetchDist(env, "online/meta.json"));
  if (path === "/pool/http") return withCors(await fetchDist(env, "online/http.txt"));
  if (path === "/pool/socks5") return withCors(await fetchDist(env, "online/socks5.txt"));
  if (path === "/pool/socks4") return withCors(await fetchDist(env, "online/socks4.txt"));
  if (path === "/pool/all") return withCors(await fetchDist(env, "online/all.txt"));
  if (path === "/sub/nodes") return withCors(await fetchDist(env, "online/nodes.txt"));
  if (path === "/sub/base64") return withCors(await fetchDist(env, "online/nodes.base64.txt"));

  // 现成的 Clash 订阅（来自 Actions 产物）
  if (path === "/sub/clash" || path === "/clash.yaml" || path === "/sub/clash-live") {
    const r = await fetchDist(env, "clean/clash.yaml");
    if (r.ok) return withCors(r);
    return withCors(await fetchDist(env, "online/clash.yaml"));
  }
  if (path === "/sub/clash-renamed" || path === "/clash-renamed.yaml") {
    return withCors(await fetchDist(env, "clean/clash-renamed.yaml"));
  }
  if (path === "/sub/tier-s" || path === "/tier-s.yaml") {
    return withCors(await fetchDist(env, "clean/clash-tier-s.yaml"));
  }
  if (path === "/sub/geo") return withCors(await fetchDist(env, "clean/geo.json"));
  return null;
}

// ══════════ 工具 ══════════

async function fetchDist(env: Env, rel: string): Promise<Response> {
  const base = (env.RAW_BASE || "").replace(/\/+$/, "");
  if (!base) return new Response("RAW_BASE not configured", { status: 500 });

  // 多 CDN 回退
  const urls: string[] = [`${base}/${rel}`];
  const ghMatch = base.match(/raw\.githubusercontent\.com\/([^/]+)\/([^/]+)\/([^/]+)/);
  if (ghMatch) {
    const [, user, repo, branch] = ghMatch;
    urls.push(`https://cdn.jsdelivr.net/gh/${user}/${repo}@${branch}/${rel}`);
    urls.push(`https://fastly.jsdelivr.net/gh/${user}/${repo}@${branch}/${rel}`);
  }

  let lastErr = "";
  for (const u of urls) {
    try {
      const r = await fetch(u, { cf: { cacheTtl: CACHE_TTL } });
      if (r.ok) {
        const text = await r.text();
        return new Response(text, {
          status: 200,
          headers: {
            "content-type": r.headers.get("content-type") || "text/plain; charset=utf-8",
            "access-control-allow-origin": "*",
            "cache-control": `public, max-age=${CACHE_TTL}`,
            "x-source": u.includes("jsdelivr") ? "cdn" : "raw",
          },
        });
      }
      lastErr = `HTTP ${r.status}`;
    } catch (e) {
      lastErr = e instanceof Error ? e.message : String(e);
    }
  }
  return new Response(`fetch failed: ${lastErr}`, { status: 502 });
}

function isApiTokenRequest(req: Request, env: Env): boolean {
  if (!env.API_TOKEN) return false;
  const t = req.headers.get("X-Api-Token");
  return t === env.API_TOKEN;
}

function wantsHtml(req: Request): boolean {
  const a = req.headers.get("accept") || "";
  return a.includes("text/html");
}

async function readJson(req: Request): Promise<any> {
  try {
    return await req.json();
  } catch {
    return {};
  }
}

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj, null, 2) + "\n", {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
    },
  });
}

function html(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function withCors(res: Response): Response {
  const h = new Headers(res.headers);
  h.set("access-control-allow-origin", "*");
  return new Response(res.body, { status: res.status, headers: h });
}
