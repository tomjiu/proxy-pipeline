/**
 * Cloudflare Worker — read-only API + simple HTML UI over GitHub raw dist/.
 */

export interface Env {
  RAW_BASE: string;
  API_TOKEN?: string;
}

const CACHE_TTL = 120;

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (req.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET, OPTIONS",
          "access-control-allow-headers": "X-Api-Token, Content-Type",
        },
      });
    }

    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    // Public homepage (no API token required for UI shell)
    if (path === "/" && wantsHtml(req)) {
      return htmlPage(url.origin);
    }
    if (path === "/") {
      return json({
        ok: true,
        service: "proxy-pipeline-worker",
        ui: "open in browser for dashboard",
        health: "/health",
      });
    }

    if (!checkAuth(req, env)) {
      return json({ error: "unauthorized" }, 401);
    }

    const track = normalizeTrack(url.searchParams.get("src"));

    if (path === "/health") {
      return json({ ok: true, service: "proxy-pipeline-worker" });
    }

    if (path === "/meta") {
      if (track === "clean") {
        const r = await fetchDist(env, "clean/report.json");
        if (r.ok) return withCors(r);
      }
      return withCors(await fetchDist(env, "online/meta.json"));
    }

    if (path === "/pool/http" || path === "/pool/http.txt") {
      if (url.searchParams.get("live") === "1") {
        return withCors(await fetchDist(env, "online/http.live.txt"));
      }
      const res =
        track === "clean"
          ? await fetchPreferred(env, "clean/http.txt", "online/http.txt")
          : await fetchDist(env, "online/http.txt");
      return withCors(res);
    }

    if (path === "/pool/socks5") {
      return withCors(await fetchDist(env, "online/socks5.txt"));
    }

    if (path === "/pool/socks4") {
      return withCors(await fetchDist(env, "online/socks4.txt"));
    }

    if (path === "/pool/all") {
      return withCors(await fetchDist(env, "online/all.txt"));
    }

    if (path === "/pool/random") {
      const proto = url.searchParams.get("proto") || "http";
      let res: Response;
      if (track === "clean") {
        if (proto === "socks5" || proto === "socks4") {
          res = await fetchDist(env, `online/${proto}.txt`);
        } else {
          res = await fetchPreferred(env, "clean/http.txt", "online/http.txt");
        }
      } else {
        const rel =
          proto === "socks5"
            ? "online/socks5.txt"
            : proto === "socks4"
              ? "online/socks4.txt"
              : "online/http.txt";
        res = await fetchDist(env, rel);
      }
      if (!res.ok) return withCors(res);
      const text = await res.text();
      const line = pickRandom(text.split("\n"));
      if (!line) return json({ error: "empty" }, 404);
      return new Response(line + "\n", {
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "access-control-allow-origin": "*",
          "cache-control": "no-store",
        },
      });
    }

    if (path === "/sub/nodes") {
      const res =
        track === "clean"
          ? await fetchPreferred(env, "clean/nodes.txt", "online/nodes.txt")
          : await fetchDist(env, "online/nodes.txt");
      return withCors(res);
    }

    if (path === "/sub/base64") {
      return withCors(await fetchDist(env, "online/nodes.base64.txt"));
    }

    if (path === "/sub/clash" || path === "/clash.yaml") {
      if (track === "clean") {
        const clean = await fetchDist(env, "clean/clash.yaml");
        if (clean.ok) return asYaml(clean);
        // fall back so clients never 404
        return asYaml(await fetchDist(env, "online/clash.yaml"));
      }
      return asYaml(await fetchDist(env, "online/clash.yaml"));
    }

    if (path === "/sub/clash-live" || path === "/sub/clash/live") {
      const clean = await fetchDist(env, "clean/clash.yaml");
      if (clean.ok) return asYaml(clean);
      return asYaml(await fetchDist(env, "online/clash.yaml"));
    }

    return json(
      {
        error: "not_found",
        routes: [
          "/",
          "/health",
          "/meta",
          "/pool/http",
          "/pool/socks5",
          "/pool/socks4",
          "/pool/all",
          "/pool/random",
          "/sub/nodes",
          "/sub/base64",
        ],
      },
      404,
    );
  },
};

function wantsHtml(req: Request): boolean {
  const accept = req.headers.get("accept") || "";
  if (accept.includes("text/html")) return true;
  // curl without Accept still gets JSON at / via path===/ non-html branch;
  // browsers always send text/html
  return false;
}

function htmlPage(origin: string): Response {
  const o = origin.replace(/\/$/, "");
  const body = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>proxy-pipeline</title>
<style>
:root{--bg:#0f1419;--card:#1a2332;--text:#e7ecf3;--muted:#8b9bb4;--acc:#3d9cf0;--ok:#3ecf8e;--line:#2a3548}
*{box-sizing:border-box}
body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}
.wrap{max-width:880px;margin:0 auto;padding:28px 18px 48px}
h1{font-size:1.45rem;margin:0 0 6px;font-weight:650}
.sub{color:var(--muted);font-size:.92rem;margin-bottom:22px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-bottom:22px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}
.stat b{display:block;font-size:1.35rem;font-variant-numeric:tabular-nums}
.stat span{color:var(--muted);font-size:.78rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:14px}
.card h2{font-size:.95rem;margin:0 0 12px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.row{display:flex;gap:8px;align-items:center;margin:8px 0;flex-wrap:wrap}
.row code{flex:1;min-width:0;background:#0c1017;border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-size:.8rem;overflow:auto;word-break:break-all}
button,.btn{appearance:none;border:0;background:var(--acc);color:#fff;border-radius:8px;padding:9px 12px;font-size:.82rem;cursor:pointer;text-decoration:none;display:inline-block;white-space:nowrap}
button.sec,.btn.sec{background:#2a3548}
button:hover,.btn:hover{filter:brightness(1.08)}
.note{color:var(--muted);font-size:.85rem;margin-top:18px}
.err{color:#ff7b7b}
.ok{color:var(--ok)}
a{color:var(--acc)}
</style>
</head>
<body>
<div class="wrap">
  <h1>proxy-pipeline</h1>
  <p class="sub">多源公开代理 raw 镜像 · 去重 · 只读 API。免费列表不稳定，仅供学习/测试。</p>
  <div class="stats" id="stats">
    <div class="stat"><b id="c-http">—</b><span>HTTP</span></div>
    <div class="stat"><b id="c-s4">—</b><span>SOCKS4</span></div>
    <div class="stat"><b id="c-s5">—</b><span>SOCKS5</span></div>
    <div class="stat"><b id="c-all">—</b><span>合计</span></div>
    <div class="stat"><b id="c-src">—</b><span>源 OK</span></div>
  </div>
  <p class="sub" id="updated">加载 meta…</p>

  <div class="card">
    <h2>代理池链接（复制到软件 / 脚本）</h2>
    ${linkRow("HTTP", o + "/pool/http")}
    ${linkRow("SOCKS5", o + "/pool/socks5")}
    ${linkRow("SOCKS4", o + "/pool/socks4")}
    ${linkRow("全部 all", o + "/pool/all")}
    ${linkRow("随机一条", o + "/pool/random")}
    ${linkRow("抽样 live HTTP", o + "/pool/http?live=1")}
  </div>

  <div class="card">
    <h2>节点 / 订阅</h2>
    ${linkRow("Clash 订阅 (可用)", o + "/sub/clash")}
    ${linkRow("Clash 测活优先", o + "/sub/clash-live")}
    ${linkRow("节点 URI 列表", o + "/sub/nodes")}
    ${linkRow("Base64 (v2rayN)", o + "/sub/base64")}
  </div>

  <div class="card">
    <h2>其它</h2>
    ${linkRow("Meta JSON", o + "/meta")}
    ${linkRow("Health", o + "/health")}
    <div class="row">
      <a class="btn sec" href="https://github.com/tomjiu/proxy-pipeline" target="_blank" rel="noopener">GitHub 仓库</a>
      <a class="btn sec" href="https://raw.githubusercontent.com/tomjiu/proxy-pipeline/main/dist/online/http.txt" target="_blank" rel="noopener">直连 raw http</a>
    </div>
  </div>

  <p class="note">两套数据：<b>池子</b> <code>/pool/*</code>=HTTP/SOCKS；<b>Clash</b> <code>/sub/clash</code> 现改为<strong>少而精</strong>（优先已筛选/测活类公开源，约百来条）。公开免费节点仍易挂，请用组 <code>AUTO</code> 测速；日常请自建/机场。</p>
</div>
<script>
const origin = ${JSON.stringify(o)};
function copy(t){
  navigator.clipboard.writeText(t).then(()=>toast('已复制')).catch(()=>{
    prompt('复制:', t);
  });
}
function toast(m){
  const n=document.getElementById('updated');
  const old=n.textContent;
  n.innerHTML='<span class="ok">'+m+'</span>';
  setTimeout(()=>{n.textContent=old},1200);
}
function fmt(n){return typeof n==='number'?n.toLocaleString():'—'}
const t=new URLSearchParams(location.search).get('token');
const metaUrl=origin+'/meta'+(t?'?token='+encodeURIComponent(t):'');
fetch(metaUrl).then(r=>r.json()).then(m=>{
  const c=m.counts||{};
  document.getElementById('c-http').textContent=fmt(c.http);
  document.getElementById('c-s4').textContent=fmt(c.socks4);
  document.getElementById('c-s5').textContent=fmt(c.socks5);
  document.getElementById('c-all').textContent=fmt(c.all_pool);
  document.getElementById('c-src').textContent=(c.sources_ok??'—')+'/'+(c.sources_total??'—');
  document.getElementById('updated').textContent='更新: '+(m.finished_at||m.generated_at||'—')+' · mode '+(m.mode||'');
}).catch(e=>{
  document.getElementById('updated').innerHTML='<span class="err">meta 加载失败</span>';
});
</script>
</body>
</html>`;

  return new Response(body, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "public, max-age=60",
    },
  });
}

function linkRow(label: string, href: string): string {
  const safe = href.replace(/"/g, "&quot;");
  return `<div class="row">
  <code title="${label}">${safe}</code>
  <button type="button" onclick="copy(${JSON.stringify(href)})">复制</button>
  <a class="btn sec" href="${safe}" target="_blank" rel="noopener">打开</a>
</div>`;
}

function normalizeTrack(src: string | null): "online" | "clean" | "local" {
  if (src === "clean" || src === "local") return src;
  return "online";
}

function checkAuth(req: Request, env: Env): boolean {
  const token = env.API_TOKEN;
  if (!token) return true;
  const url = new URL(req.url);
  return url.searchParams.get("token") === token || req.headers.get("X-Api-Token") === token;
}

async function fetchDist(env: Env, rel: string): Promise<Response> {
  const base = (env.RAW_BASE || "").replace(/\/$/, "");
  if (!base || base.includes("REPLACE_")) {
    return json({ error: "RAW_BASE not configured" }, 500);
  }
  const target = `${base}/${rel.replace(/^\//, "")}`;
  const cache = caches.default;
  const cacheKey = new Request(target, { method: "GET" });
  const hit = await cache.match(cacheKey);
  if (hit) return hit;

  const upstream = await fetch(target, {
    headers: { "user-agent": "proxy-pipeline-worker/1.0" },
  });

  const headers = new Headers();
  const ct = upstream.headers.get("content-type") || guessContentType(rel);
  headers.set("content-type", ct);
  headers.set("access-control-allow-origin", "*");
  headers.set("cache-control", `public, max-age=${CACHE_TTL}`);

  const out = new Response(upstream.body, { status: upstream.status, headers });
  if (upstream.ok) {
    try {
      await cache.put(cacheKey, out.clone());
    } catch {
      /* ignore */
    }
  }
  return out;
}

/** Fetch primary; if missing, fall back so clients never 404. */
async function fetchPreferred(env: Env, primary: string, fallback: string): Promise<Response> {
  const res = await fetchDist(env, primary);
  if (res.ok) return res;
  return fetchDist(env, fallback);
}

function guessContentType(rel: string): string {
  if (rel.endsWith(".json")) return "application/json; charset=utf-8";
  if (rel.endsWith(".yaml") || rel.endsWith(".yml")) return "text/yaml; charset=utf-8";
  return "text/plain; charset=utf-8";
}

function pickRandom(lines: string[]): string | null {
  const items = lines.map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  if (!items.length) return null;
  return items[Math.floor(Math.random() * items.length)]!;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
    },
  });
}

function withCors(res: Response): Response {
  const headers = new Headers(res.headers);
  headers.set("access-control-allow-origin", "*");
  return new Response(res.body, { status: res.status, headers });
}

/** Clash clients expect yaml content-type, not octet-stream from GitHub raw. */
function asYaml(res: Response): Response {
  const headers = new Headers(res.headers);
  headers.set("access-control-allow-origin", "*");
  if (res.ok) {
    headers.set("content-type", "text/yaml; charset=utf-8");
    headers.set("content-disposition", "inline; filename=\"clash.yaml\"");
  }
  return new Response(res.body, { status: res.status, headers });
}
