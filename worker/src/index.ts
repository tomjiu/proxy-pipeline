/**
 * Cloudflare Worker — read-only API over GitHub raw dist/.
 *
 * wrangler vars:
 *   RAW_BASE   e.g. https://raw.githubusercontent.com/USER/REPO/main/dist
 *   API_TOKEN  optional; require ?token= or header X-Api-Token
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

    if (!checkAuth(req, env)) {
      return json({ error: "unauthorized" }, 401);
    }

    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const track = normalizeTrack(url.searchParams.get("src"));

    if (path === "/" || path === "/health") {
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
      const rel = track === "clean" ? "clean/http.txt" : "online/http.txt";
      return withCors(await fetchDist(env, rel));
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
      let rel = "online/http.txt";
      if (track === "clean") rel = "clean/http.txt";
      else if (proto === "socks5") rel = "online/socks5.txt";
      else if (proto === "socks4") rel = "online/socks4.txt";
      const res = await fetchDist(env, rel);
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
      const rel = track === "clean" ? "clean/nodes.txt" : "online/nodes.txt";
      return withCors(await fetchDist(env, rel));
    }

    if (path === "/sub/base64") {
      return withCors(await fetchDist(env, "online/nodes.base64.txt"));
    }

    if (path === "/sub/clash") {
      return withCors(await fetchDist(env, "online/nodes.txt"));
    }

    return json(
      {
        error: "not_found",
        routes: [
          "/health",
          "/meta?src=online|clean",
          "/pool/http?src=online|clean&live=1",
          "/pool/socks5",
          "/pool/socks4",
          "/pool/all",
          "/pool/random?proto=http|socks5",
          "/sub/nodes",
          "/sub/base64",
          "/sub/clash",
        ],
      },
      404,
    );
  },
};

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
