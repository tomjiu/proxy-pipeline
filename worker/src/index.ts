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

  // 缓存命中
  if (!isJson) {
    const cached = await cacheGet(env, token + "." + ext);
    if (cached) return subResponse(cached, ext, true);
  }

  // 聚合
  const agg = await aggregate(cfg.sources);
  let nodes: ParsedNode[] = agg.nodes;

  if (cfg.rename) nodes = renameSimple(nodes);

  // tier 过滤（用节点名匹配 quality_tiers.json）
  if (cfg.min_tier !== "all") {
    try {
      const tierRes = await fetchDist(env, "clean/quality_tiers.json");
      if (tierRes.ok) {
        const t = await tierRes.json() as any;
        const want = cfg.min_tier === "S" ? new Set(t.tier_S || [])
                                          : new Set([...(t.tier_S || []), ...(t.tier_A || [])]);
        const before = nodes.length;
        nodes = nodes.filter(n => want.has(n.name) || want.has(n.origin ? n.name : n.name));
        // 名字已被重命名时无法匹配 → 保留全部并提示
        if (nodes.length === 0 && before > 0) nodes = agg.nodes;
        if (cfg.rename) nodes = renameSimple(nodes);
      }
    } catch { /* 过滤失败则不过滤 */ }
  }

  if (isJson) {
    return json({
      token, name: cfg.name, nodes: nodes.length,
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
    const rules = cfg.rules_mode === "custom" && cfg.rules ? cfg.rules : g.default_rules;
    content = buildClash(nodes, {
      rename: cfg.rename,
      rules,
      title: cfg.name,
    });
  }

  await cachePut(env, token + "." + ext, content, GEN_CACHE_TTL);

  // 计数（异步，不阻塞响应）
  cfg.hits = (cfg.hits || 0) + 1;
  putSub(env, cfg).catch(() => {});

  return subResponse(content, ext, false);
}

function subResponse(content: string, ext: string, cached: boolean): Response {
  const ct = ext === "txt" ? "text/plain; charset=utf-8"
           : ext === "json" ? "application/json; charset=utf-8"
           : "text/yaml; charset=utf-8";
  return new Response(content, {
    headers: {
      "content-type": ct,
      "cache-control": "public, max-age=60",
      "access-control-allow-origin": "*",
      "x-cached": cached ? "hit" : "miss",
      "profile-update-interval": "6",
      // Clash 会解析这个头显示流量
      "subscription-userinfo": "upload=0; download=0; total=0; expire=0",
    },
  });
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
