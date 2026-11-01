/**
 * CF 节点测活 —— 用 fetch/WebSocket 探测（唯一可行的方式）
 *
 * 原理：
 *   url.v1.mk 这类源的节点是 **CF Workers/Pages 中转**：
 *     - server = Cloudflare 任播 IP（104.x / 172.6x）
 *     - network = ws（WebSocket）
 *     - port = 80/443（标准 HTTP 端口）
 *
 *   所以可以用 fetch/WebSocket 探测：
 *     - 直接 fetch 目标 Host，看是否返回 200/101
 *     - WS 节点发起 WebSocket 握手（101 Switching Protocols = 活着）
 *
 * 能力边界：
 *   ✅ CF 中转节点（vless+ws / trojan+ws / vmess+ws）
 *   ❌ 普通 vless/hy2（非 CF 中转，无 TCP API 测不了）
 */

export interface CFProbeResult {
  name: string;
  server: string;
  port: string;
  type: string;
  network: string;
  alive: boolean;
  /** 探测方式 */
  method: "ws" | "http" | "dns" | "skipped";
  ms: number;
  status?: string;
  error?: string;
}

/**
 * 判断节点是否**可被 Worker 探测**
 *
 * 实测结论：
 *   ✅ 指向域名的 ws 节点（如 xxx.pages.dev）→ fetch 返回 101，可测
 *   ❌ 指向 CF 任播 IP 的节点（104.x / 172.66.x）→ Worker fetch 自己的边缘
 *      会被拦截返回 403（2ms），无法判断真实存活
 *   ❌ 非 ws 节点（hy2/vless 直连）→ 无 TCP API
 */
export function isProbeable(server: string, raw: string): boolean {
  // 必须是 websocket（走 HTTP，fetch 可达）
  if (!/network:\s*"?ws"?/i.test(raw)) return false;
  // 必须是域名（IP 会被自己的边缘拦截）
  if (/^\d+\.\d+\.\d+\.\d+$/.test(server)) return false;
  if (/^[0-9a-f:]+$/i.test(server)) return false;   // IPv6
  return true;
}

/** 判断是否是 CF 中转节点（用于统计，不代表可探测） */
export function isCFNode(server: string, raw: string): boolean {
  if (!/network:\s*"?ws"?/i.test(raw)) return false;
  const CF_IP = /^(104\.(1[6-9]|2[0-7])\.|172\.(6[4-9]|7[0-1])\.|162\.15[89]\.|188\.114\.|190\.93\.|19[0-8]\.41\.|141\.101\.|108\.162\.|173\.245\.|103\.2[12]\.|103\.31\.|131\.0\.7[2-5]\.)/;
  if (CF_IP.test(server)) return true;
  if (/\.(workers\.dev|pages\.dev|cloudflare\.com|wpd-bot)/i.test(server)) return true;
  return false;
}

/** 从节点块提取 ws-opts 里的 Host 头 */
function extractWSHost(raw: string): string {
  // ws-opts: {path: "...", headers: {Host: xxx}}
  const m1 = raw.match(/headers:\s*\{[^}]*Host:\s*"?([^",}\s]+)"?/i);
  if (m1) return m1[1];
  // Host: xxx（独立行）
  const m2 = raw.match(/^\s+Host:\s*"?([^"\s]+)"?/im);
  if (m2) return m2[1];
  // servername / sni
  const m3 = raw.match(/^\s+(?:servername|sni):\s*"?([^"\s]+)"?/im);
  if (m3) return m3[1];
  return "";
}

/** 从节点块提取 ws path */
function extractWSPath(raw: string): string {
  const m = raw.match(/path:\s*"?([^",}\s]+)"?/i);
  return m ? m[1] : "/";
}

/**
 * 探测单个 CF 节点
 *
 * 方法：向 server:port 发起 WebSocket 握手并带上正确的 Host 头
 *   - 101 → 节点活着（WS 升级成功）
 *   - 其他 → 尝试普通 HTTP 请求
 */
export async function probeCFNode(
  node: { name: string; type: string; server: string; port: string; raw: string },
  timeoutMs = 6000,
): Promise<CFProbeResult> {
  const t0 = Date.now();
  const base: CFProbeResult = {
    name: node.name, server: node.server, port: node.port,
    type: node.type,
    network: (node.raw.match(/network:\s*"?(\w+)"?/i) || [])[1] || "tcp",
    alive: false, method: "skipped", ms: 0,
  };

  const host = extractWSHost(node.raw) || node.server;
  const path = extractWSPath(node.raw);
  const port = node.port;
  const scheme = port === "443" ? "https" : "http";

  // ── 方式 1：WebSocket 握手（最准确）──
  try {
    const wsUrl = `${scheme === "https" ? "wss" : "ws"}://${node.server}:${port}${path}`;
    // Cloudflare Workers 支持 WebSocket 客户端（用 fetch + Upgrade 头）
    const res = await fetch(`https://${node.server}${path}`, {
      headers: {
        "Host": host,
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": btoa(String(Math.random())).slice(0, 22) + "==",
        "User-Agent": "Mozilla/5.0",
      },
      signal: AbortSignal.timeout(timeoutMs),
    });

    const ms = Date.now() - t0;
    // 101 = WS 升级成功；200/404 也说明 CF 边缘活着
    if (res.status === 101 || res.ok || res.status === 404 || res.status === 400) {
      return { ...base, alive: true, method: "ws", ms,
               status: `HTTP ${res.status}` };
    }
    return { ...base, alive: false, method: "ws", ms,
             status: `HTTP ${res.status}`, error: `unexpected ${res.status}` };
  } catch (e) {
    // WS 失败 → 尝试普通 HTTP
    const wsErr = e instanceof Error ? e.message : String(e);
    const ms1 = Date.now() - t0;

    // ── 方式 2：普通 HTTP 请求（验证 CF 边缘可达）──
    try {
      const res = await fetch(`https://${host}${path}`, {
        headers: { "User-Agent": "Mozilla/5.0" },
        redirect: "manual",
        signal: AbortSignal.timeout(timeoutMs),
      });
      const ms = Date.now() - t0;
      // CF 返回任何响应都说明边缘活着
      return { ...base, alive: res.status < 500, method: "http", ms,
               status: `HTTP ${res.status}` };
    } catch (e2) {
      return { ...base, alive: false, method: "http", ms: Date.now() - t0,
               error: `ws:${wsErr.slice(0, 30)} http:${(e2 instanceof Error ? e2.message : String(e2)).slice(0, 30)}` };
    }
  }
}

/**
 * 批量探测（只测「可探测」的节点：ws + 域名）
 */
export async function probeCFNodes(
  nodes: Array<{ name: string; type: string; server: string; port: string; raw: string }>,
  opts: { concurrency?: number; maxProbe?: number; timeoutMs?: number } = {},
): Promise<{
  results: CFProbeResult[];
  stats: { total: number; probeable: number; alive: number; dead: number; skipped: number };
}> {
  const concurrency = opts.concurrency ?? 6;
  const maxProbe = opts.maxProbe ?? 40;
  const timeoutMs = opts.timeoutMs ?? 5000;

  const results: CFProbeResult[] = [];
  const probeable: typeof nodes = [];
  const skipped: CFProbeResult[] = [];

  for (const n of nodes) {
    if (isProbeable(n.server, n.raw)) {
      probeable.push(n);
    } else {
      // 不可探测 → 保留（标记 skipped）
      skipped.push({
        name: n.name, server: n.server, port: n.port, type: n.type,
        network: (n.raw.match(/network:\s*"?(\w+)"?/i) || [])[1] || "tcp",
        alive: true, method: "skipped", ms: 0,
        status: isCFNode(n.server, n.raw) ? "CF-IP (self-request blocked)" : "not probeable in Worker",
      });
    }
  }

  const toProbe = probeable.slice(0, maxProbe);
  const overflow: CFProbeResult[] = probeable.slice(maxProbe).map(n => ({
    name: n.name, server: n.server, port: n.port, type: n.type,
    network: "ws", alive: true, method: "skipped" as const, ms: 0,
    status: "over probe limit (kept)",
  }));

  let cursor = 0;
  const out: CFProbeResult[] = new Array(toProbe.length);
  async function worker() {
    while (true) {
      const i = cursor++;
      if (i >= toProbe.length) return;
      out[i] = await probeCFNode(toProbe[i], timeoutMs);
    }
  }
  if (toProbe.length) {
    await Promise.all(Array.from({ length: Math.min(concurrency, toProbe.length) }, worker));
  }

  results.push(...out, ...skipped, ...overflow);

  const probed = out.filter(Boolean);
  return {
    results,
    stats: {
      total: nodes.length,
      probeable: probeable.length,
      alive: probed.filter(r => r.alive).length,
      dead: probed.filter(r => !r.alive).length,
      skipped: skipped.length + overflow.length,
    },
  };
}

/** 按测活结果过滤（保留 skipped / 不可探测的） */
export function filterCFAlive<T extends { server: string; raw: string; name: string }>(
  nodes: T[],
  results: CFProbeResult[],
): T[] {
  // 只移除「探测过且失败」的
  const deadSet = new Set(
    results.filter(r => r.method !== "skipped" && !r.alive)
           .map(r => r.name + "|" + r.server)
  );
  return nodes.filter(n => !deadSet.has(n.name + "|" + n.server));
}
