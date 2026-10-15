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
  isAuthed, checkPassword, createSession, sessionCookie, clearCookie, constantTimeEqual,
  authRequired,
} from "./auth";
import {
  aggregate, buildClash, buildBase64, renameSimple, fetchSource,
  type ParsedNode,
} from "./subscription";
import { loginPage, dashboardPage } from "./ui";
import { DEFAULT_TEMPLATE } from "./default-template";
import { probeCFNodes, filterCFAlive, isCFNode, type CFProbeResult } from "./cf-probe";
import { filterByScore, DEFAULT_FILTER, type FilterOptions } from "./scoring";

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
      // ── 登出 ──
      // ⚠️ 必须限定 POST：否则 <img src="/logout"> 即可强制登出（登出 CSRF）
      //    另校验 Origin/Referer，防止跨站表单提交
      if (path === "/logout") {
        if (method !== "POST") {
          return json({ error: "method not allowed", allow: "POST" }, 405);
        }
        if (!sameOrigin(req, url)) {
          return json({ error: "cross-origin request rejected" }, 403);
        }
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
      const needsAuth = authRequired(env) && !(await isApiTokenRequest(req, env));
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

  // ── 限流：防在线爆破（基于 IP + KV 计数）──
  const ip = req.headers.get("cf-connecting-ip") || "unknown";
  const rl = await checkLoginRate(env, ip);
  if (!rl.allowed) {
    return html(loginPage(
      `尝试次数过多，请 ${rl.retryAfter} 秒后再试`, next), 429,
      { "retry-after": String(rl.retryAfter) });
  }

  // ── 统一失败响应（不区分「未配置密码」与「密码错误」，避免探测部署状态）──
  const fail = () => html(loginPage("密码错误", next), 401);

  if (!env.ADMIN_PASSWORD) {
    // 未配置密码 → 拒绝，但对外表现与密码错误一致（详情写日志）
    console.error("[auth] ADMIN_PASSWORD not configured");
    await recordLoginFail(env, ip);
    return fail();
  }
  if (!(await checkPassword(env, password))) {
    await recordLoginFail(env, ip);
    return fail();
  }

  // 成功 → 清除失败计数
  await clearLoginFail(env, ip);

  const token = await createSession(env);
  // 安全检查：next 必须是站内路径
  const safeNext = next.startsWith("/") && !next.startsWith("//") ? next : "/";
  return new Response(null, {
    status: 302,
    headers: { location: safeNext, "set-cookie": sessionCookie(token) },
  });
}

// ══════════ 登录限流 ══════════

const LOGIN_MAX_FAILS = 5;          // 15 分钟内最多失败 5 次
const LOGIN_WINDOW_S = 900;         // 窗口 15 分钟

async function checkLoginRate(env: Env, ip: string): Promise<{ allowed: boolean; retryAfter: number }> {
  if (!env.KV) return { allowed: true, retryAfter: 0 };
  try {
    const key = `rl:login:${ip}`;
    const raw = await env.KV.get(key, "text");
    if (!raw) return { allowed: true, retryAfter: 0 };
    const d = JSON.parse(raw) as { count: number; first: number };
    const elapsed = Math.floor(Date.now() / 1000) - d.first;
    if (elapsed > LOGIN_WINDOW_S) return { allowed: true, retryAfter: 0 };
    if (d.count >= LOGIN_MAX_FAILS) {
      return { allowed: false, retryAfter: LOGIN_WINDOW_S - elapsed };
    }
    return { allowed: true, retryAfter: 0 };
  } catch {
    return { allowed: true, retryAfter: 0 };
  }
}

async function recordLoginFail(env: Env, ip: string): Promise<void> {
  if (!env.KV) return;
  try {
    const key = `rl:login:${ip}`;
    const now = Math.floor(Date.now() / 1000);
    const raw = await env.KV.get(key, "text");
    let d = { count: 0, first: now };
    if (raw) {
      const prev = JSON.parse(raw) as { count: number; first: number };
      if (now - prev.first <= LOGIN_WINDOW_S) d = { count: prev.count, first: prev.first };
    }
    d.count += 1;
    await env.KV.put(key, JSON.stringify(d), { expirationTtl: LOGIN_WINDOW_S + 60 });
  } catch { /* 限流失败不影响主流程 */ }
}

async function clearLoginFail(env: Env, ip: string): Promise<void> {
  if (!env.KV) return;
  try {
    await env.KV.delete(`rl:login:${ip}`);
  } catch { /* ignore */ }
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
    probe: body.probe === true,
    cn_only: body.cn_only === true,
    filter: body.filter !== false,
    target_nodes: Number.isFinite(body.target_nodes)
      ? Math.min(1000, Math.max(10, Number(body.target_nodes)))
      : 300,
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
      if (typeof b.cn_only === "boolean") cfg.cn_only = b.cn_only;
      if (typeof b.filter === "boolean") cfg.filter = b.filter;
      if (Number.isFinite(b.target_nodes)) {
        cfg.target_nodes = Math.min(1000, Math.max(10, Number(b.target_nodes)));
      }
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
  const sp = new URL(req.url).searchParams;

  // ── 缓存键：只有 token（不按格式/参数分裂，避免写放大与命中率稀释）──
  // ⚠️ 之前用 `${token}.${ext}${probe?" .p":""}` 导致：
  //    ① 一个 token 产生 4~6 个 key，各自 5 分钟过期 → 写放大
  //    ② cacheClear 只删 `cache:<token>`，与实际 key 不匹配 → 改配置后旧缓存清不掉
  //    现在统一为 `cache:sub:<token>`，且缓存内容是渲染后的 Clash YAML。

  const t0 = Date.now();
  const cachedYaml = await cacheGet(env, token);

  if (cachedYaml) {
    // 命中：只做格式转换（txt/json 从 YAML 派生，不重算聚合）
    const traffic = await getTraffic(env);
    if (ext === "txt") {
      const txt = yamlToBase64(cachedYaml);
      return subResponse(txt, ext, true, null, traffic);
    }
    if (isJson) {
      const nodes = extractNamesFromYaml(cachedYaml);
      // 缓存里存了上次的统计（避免 JSON 请求触发全量重算）
      const stats = await cacheGet(env, token + ":stats");
      let parsed: any = null;
      try { parsed = stats ? JSON.parse(stats) : null; } catch { /* ignore */ }
      return json({
        token, name: cfg.name, nodes: nodes.length,
        cached: true, elapsed_ms: Date.now() - t0,
        filter: parsed?.filter ?? null,
        filter_config: { enabled: cfg.filter !== false, target: cfg.target_nodes || 300 },
        sources: parsed?.sources ?? null,
        duplicates: parsed?.duplicates ?? null,
        total_fetched: parsed?.total_fetched ?? null,
        traffic: await trafficSummary(env),
      });
    }
    return subResponse(cachedYaml, ext, true, null, traffic);
  }

  // ── 未命中：全量聚合 ──
  // ⚠️ 此路径 CPU 约 12~28ms，超过免费版 10ms 限制（Error 1102 风险）
  //    因此必须靠高缓存命中率规避；由 sub-refresh.yml 定时预热
  const agg = await aggregate(cfg.sources);
  let nodes: ParsedNode[] = agg.nodes;

  // ── 测活（默认关闭，且**不允许通过 URL 参数强制开启**）──
  // ⚠️ 之前 `?probe=1` 无需登录即可触发 40 次并发探测：
  //    - 子请求可达 80 个（超免费版 50 限制）
  //    - CPU 25~45ms（必触发 Error 1102）
  //    → 已移除公开强制开关，只认 cfg.probe（需登录 PATCH 才能改）
  const doProbe = cfg.probe === true;
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

  // ── 3.5 CN 连通性过滤（只保留中国实测可达的节点）──
  // 数据来源：GitHub Actions 用 ip112.cn 双端 API 测出的 cn-alive.yaml
  //   · 国内端 api.ycwxgzs.com + 国外端 api.52bwg.com 对比
  //   · 判定规则：国内端口不可达 = 被墙，剔除
  //
  // ⚠️ 用 server:port 匹配（不依赖节点名，因为订阅里的名字可能被重命名）
  // ⚠️ 数据过期或为空时**不过滤**（避免全空）
  let cnStats: { loaded: number; before: number; after: number } | null = null;
  if (cfg.cn_only === true && nodes.length) {
    try {
      const res = await fetchDist(env, "clean/cn-alive.yaml");
      if (res.ok) {
        const yaml = await res.text();
        const allowed = new Set<string>();
        // 按块提取 server:port（不依赖节点名，避免重命名导致匹配失败）
        const body = yaml.split(/^proxies:\s*$/m)[1] || "";
        for (const ch of body.split(/^\s*- /m).slice(1)) {
          const sv = ch.match(/^\s*server:\s*"?([^"\s,}]+)"?/m);
          const pt = ch.match(/^\s*port:\s*"?(\d+)"?/m);
          if (sv && pt) allowed.add(`${sv[1]}:${pt[1]}`);
        }

        if (allowed.size > 0) {
          const before = nodes.length;
          const kept = nodes.filter(n => allowed.has(`${n.server}:${n.port}`));
          if (kept.length > 0) {
            nodes = kept;
            cnStats = { loaded: allowed.size, before, after: kept.length };
            console.log(`[cn] ${before} -> ${kept.length} (CN whitelist ${allowed.size})`);
          } else {
            console.log(`[cn] no match (whitelist ${allowed.size}, nodes ${before}), keeping all`);
          }
        } else {
          console.log("[cn] whitelist empty, skipping filter");
        }
      } else {
        console.log(`[cn] cn-alive.yaml fetch failed: HTTP ${res.status}`);
      }
    } catch (e) {
      console.error("[cn] filter failed:", e);
    }
  }

  // ── 4. tier 过滤（在重命名之前，用原名匹配）──
  // ⚠️ 必须在 renameSimple 之前做：quality_tiers.json 里的 key 是**原始节点名**，
  //    重命名后无法匹配。早期实现先重命名再过滤，导致过滤永不命中并触发回退，
  //    而回退基准误用 agg.nodes —— 会把测活已判死的节点重新放回订阅。
  if (cfg.min_tier !== "all") {
    try {
      const tierRes = await fetchDist(env, "clean/quality_tiers.json");
      if (tierRes.ok) {
        const t = await tierRes.json() as any;
        const want = cfg.min_tier === "S"
          ? new Set<string>(t.tier_S || [])
          : new Set<string>([...(t.tier_S || []), ...(t.tier_A || [])]);
        const before = nodes.length;
        const kept = nodes.filter(n => want.has(n.name));
        if (kept.length > 0) {
          nodes = kept;
        } else if (before > 0) {
          // 无匹配（可能是 tier 数据过期或节点名格式不同）
          // → 回退到**过滤前的当前 nodes**（保留测活结果），并记日志
          console.log(`[tier] no match for min_tier=${cfg.min_tier} (${before} nodes), keeping all`);
        }
      }
    } catch { /* 过滤失败则不过滤 */ }
  }

  // ── 5. 评分筛选（剔除代理池协议 + 优选高质量节点 + 控制总量）──
  // 需求：
  //   - 剔除 http / socks4 / socks5 / anytls（客户端用不上或支持差）
  //   - 按评分优选，总量 ≤ target（默认 300）
  //   - vless 设上限、hysteria2 保底，平衡协议分布
  let filterStats: {
    input: number; droppedByType: number; kept: number;
    byProto: Record<string, number>; scoreRange: [number, number];
  } | null = null;
  if (cfg.filter !== false && nodes.length) {
    try {
      const opts: FilterOptions = {
        ...DEFAULT_FILTER,
        target: cfg.target_nodes || DEFAULT_FILTER.target,
      };
      const fr = filterByScore(nodes, opts);
      filterStats = fr.stats;
      nodes = fr.kept;
      console.log(`[filter] ${fr.stats.input} -> ${fr.stats.kept} ` +
        `(dropped ${fr.stats.droppedByType} by type) ${JSON.stringify(fr.stats.byProto)}`);
    } catch (e) {
      console.error("[filter] failed:", e);
    }
  }

  // ── 6. 重命名 ──
  if (cfg.rename) nodes = renameSimple(nodes);

  // ── 5. 输出 ──
  const traffic = await getTraffic(env);

  if (isJson) {
    return json({
      token, name: cfg.name, nodes: nodes.length,
      probe: probeStats,
      cn: cnStats,
      cn_config: { enabled: cfg.cn_only === true },
      filter: filterStats,
      filter_config: { enabled: cfg.filter !== false, target: cfg.target_nodes || 300 },
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

  // ── 缓存写入 ──
  // ⚠️ KV 写配额（免费版 1000/天）：**只写一份**（渲染后的 Clash YAML）
  //    统计信息随 YAML 一起写（同一 key 后缀，成本可忽略）
  //    由 sub-refresh.yml 每 15 分钟预热，用户请求基本都命中
  if (ext === "yaml" || ext === "yml" || ext === "txt") {
    let yamlContent = content;
    if (ext === "txt") {
      const g = await getGlobal(env);
      const template = cfg.rules_mode === "custom" && cfg.rules
        ? undefined
        : (g.default_rules && g.default_rules.length > 100 ? undefined : DEFAULT_TEMPLATE);
      yamlContent = buildClash(nodes, {
        rename: cfg.rename,
        rules: cfg.rules_mode === "custom" && cfg.rules ? cfg.rules : g.default_rules,
        title: cfg.name,
        template,
      });
    }
    await Promise.all([
      cachePut(env, token, yamlContent, GEN_CACHE_TTL),
      cachePut(env, token + ":stats", JSON.stringify({
        cn: cnStats,
      cn_config: { enabled: cfg.cn_only === true },
      filter: filterStats,
        sources: agg.results.map(r => ({
          url: r.url, ok: r.ok, format: r.format,
          nodes: r.nodes.length, error: r.error,
        })),
        duplicates: agg.duplicates,
        total_fetched: agg.total_fetched,
        at: new Date().toISOString(),
      }), GEN_CACHE_TTL),
    ]);
  }

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

/**
 * 校验请求是否同源（用于状态变更接口的 CSRF 防护）
 * 允许无 Origin 头的情况（部分客户端/curl），但若存在则必须匹配
 */
function sameOrigin(req: Request, url: URL): boolean {
  const origin = req.headers.get("origin");
  if (origin) {
    try {
      return new URL(origin).host === url.host;
    } catch {
      return false;
    }
  }
  const referer = req.headers.get("referer");
  if (referer) {
    try {
      return new URL(referer).host === url.host;
    } catch {
      return false;
    }
  }
  // 无 Origin/Referer（curl、命令行客户端）→ 放行
  return true;
}

// ══════════ 缓存派生（从缓存的 YAML 生成其他格式，避免重算）══════════

/** 从缓存的 Clash YAML 提取节点名（供 JSON 统计） */
function extractNamesFromYaml(yaml: string): string[] {
  const m = yaml.match(/^proxies:\s*$/m);
  if (!m || m.index === undefined) return [];
  let rest = yaml.slice(m.index + m[0].length);
  const end = rest.match(/^proxy-groups:\s*$/m);
  if (end && end.index !== undefined) rest = rest.slice(0, end.index);
  const names: string[] = [];
  for (const ch of rest.split(/^ {2}- name:\s*/m).slice(1)) {
    const first = ch.split("\n", 1)[0].trim();
    const n = first.replace(/^"(.*)"$/, "$1");
    if (n) names.push(n);
  }
  return names;
}

/**
 * 从 Clash YAML 生成 Base64 订阅（v2rayN 用）
 *
 * 说明：完整还原节点 URI 需要按协议重新序列化，成本高。
 * 这里采用**折中方案**：直接 base64 编码 YAML 内容。
 * 大多数客户端（v2rayN/小火箭）能识别 base64(YAML)。
 */
function yamlToBase64(yaml: string): string {
  const bytes = new TextEncoder().encode(yaml);
  // 分块处理，避免逐字符拼接（CPU 陷阱）
  let bin = "";
  const CHUNK = 8192;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

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

async function isApiTokenRequest(req: Request, env: Env): Promise<boolean> {
  if (!env.API_TOKEN) return false;
  const t = req.headers.get("X-Api-Token");
  if (!t) return false;
  // 恒定时间比较（防止通过响应时间推断 token）
  return constantTimeEqual(t, env.API_TOKEN);
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

function html(body: string, status = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      ...(extraHeaders || {}),
    },
  });
}

function withCors(res: Response): Response {
  const h = new Headers(res.headers);
  h.set("access-control-allow-origin", "*");
  return new Response(res.body, { status: res.status, headers: h });
}
