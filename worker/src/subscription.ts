/**
 * 订阅解析与聚合
 *
 * 支持格式：
 *   1. Clash / Mihomo YAML（proxies 段）
 *   2. Base64 编码的节点 URI 列表（v2rayN / 小火箭）
 *   3. 纯文本节点 URI 列表
 *
 * 聚合逻辑：
 *   - 从多个源拉取
 *   - 解析出节点（保留原始 YAML 块）
 *   - 按 type|server|port|(uuid|password) 去重
 *   - 输出合并后的 Clash YAML
 */

import type { SubSource } from "./types";

export interface ParsedNode {
  name: string;
  type: string;
  server: string;
  port: string;
  raw: string;        // 原始 YAML 块（缩进已规范）
  origin: string;     // 来源 URL（用于调试）
}

export interface FetchResult {
  url: string;
  ok: boolean;
  status?: number;
  error?: string;
  format: "clash" | "base64" | "uris" | "empty";
  nodes: ParsedNode[];
  bytes: number;
}

const UA = "Mozilla/5.0 (compatible; proxy-pipeline-worker/1.0)";

// ── 解析 Clash YAML 的 proxies 段 ──

export function parseClashNodes(text: string, origin = ""): ParsedNode[] {
  const m = text.match(/^proxies:\s*$/m);
  if (!m || m.index === undefined) return [];

  let rest = text.slice(m.index + m[0].length);
  const endM = rest.match(/^proxy-groups:\s*$/m);
  if (endM && endM.index !== undefined) rest = rest.slice(0, endM.index);

  // 自动检测缩进：找到第一个 "- name:" 前的空格数
  const firstItem = rest.match(/^([ \t]*)-[ \t]*name:/m);
  if (!firstItem) return [];
  const itemIndent = firstItem[1];              // 列表项的缩进
  const fieldIndent = itemIndent + "  ";        // 字段缩进（比列表项多 2）

  const out: ParsedNode[] = [];

  // 用动态缩进切分节点块
  const splitRe = new RegExp(`^${escapeRe(itemIndent)}-[ \\t]*name:[ \\t]*`, "m");
  const chunks = rest.split(splitRe);

  for (let i = 1; i < chunks.length; i++) {
    const ch = chunks[i];
    const firstLine = ch.split("\n", 1)[0].trim();
    const name = firstLine.replace(/^"(.*)"$/, "$1");

    // 字段用动态缩进匹配（也兼容固定 4 空格）
    const field = (key: string): string => {
      const res = [
        new RegExp(`^${escapeRe(fieldIndent)}${key}:\\s*(.+?)\\s*$`, "m"),
        new RegExp(`^ {2}${key}:\\s*(.+?)\\s*$`, "m"),   // 兜底
        new RegExp(`^ {4}${key}:\\s*(.+?)\\s*$`, "m"),   // 兜底
      ];
      for (const re of res) {
        const mm = ch.match(re);
        if (mm) {
          let v = mm[1].trim();
          if (v.length >= 2 && v[0] === '"' && v[v.length - 1] === '"') v = v.slice(1, -1);
          return v;
        }
      }
      return "";
    };

    const type = field("type");
    const server = field("server");
    const port = field("port");

    if (name && type && server) {
      // 重建规范化的 YAML 块（统一 2/4 缩进）
      const raw = normalizeBlock(ch, name, fieldIndent);
      out.push({ name, type, server, port, raw, origin });
    }
  }
  return out;
}

/** 把节点块规范化为标准的 2/4 缩进格式 */
function normalizeBlock(ch: string, name: string, fieldIndent: string): string {
  const lines = ch.replace(/\s+$/, "").split("\n");
  const out: string[] = [`  - name: ${yamlQuote(name)}`];

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    // 去掉原有的 fieldIndent 前缀，统一改为 4 空格
    let body = line;
    if (body.startsWith(fieldIndent)) {
      body = body.slice(fieldIndent.length);
    } else {
      body = body.replace(/^\s{1,6}/, "");
    }
    out.push("    " + body);
  }
  return out.join("\n") + "\n";
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ── 解析节点 URI 列表 ──

interface URINode { name: string; type: string; server: string; port: string; raw: string; }

function parseShareURI(uri: string, idx: number): URINode | null {
  const scheme = uri.split("://")[0]?.toLowerCase();
  if (!scheme) return null;

  let name = "";
  let body = uri;

  const hashIdx = uri.indexOf("#");
  if (hashIdx >= 0) {
    body = uri.slice(0, hashIdx);
    try {
      name = decodeURIComponent(uri.slice(hashIdx + 1));
    } catch {
      name = uri.slice(hashIdx + 1);
    }
  }

  try {
    if (scheme === "vmess") {
      const b64 = body.slice("vmess://".length);
      const json = JSON.parse(b64Decode(b64));
      const server = String(json.add || "");
      const port = String(json.port || "");
      const type = "vmess";
      if (!server) return null;
      name = name || String(json.ps || `vmess-${server}`);
      // 转成 Clash 块
      const lines = [
        `  - name: ${yamlQuote(name)}`,
        `    type: vmess`,
        `    server: ${yamlQuote(server)}`,
        `    port: ${port}`,
        `    uuid: ${yamlQuote(String(json.id || ""))}`,
        `    alterId: ${json.aid ?? 0}`,
        `    cipher: ${json.scy || "auto"}`,
        `    udp: true`,
      ];
      if (json.tls === "tls") {
        lines.push(`    tls: true`);
        if (json.sni) lines.push(`    servername: ${yamlQuote(String(json.sni))}`);
        if (json.host) lines.push(`    ws-opts: {path: ${yamlQuote(String(json.path || "/"))}, headers: {Host: ${yamlQuote(String(json.host))}}}`);
      } else if (json.net === "ws") {
        lines.push(`    network: ws`);
        lines.push(`    ws-opts: {path: ${yamlQuote(String(json.path || "/"))}}`);
      }
      return { name, type, server, port, raw: lines.join("\n") + "\n" };
    }

    if (scheme === "vless") {
      // vless://uuid@host:port?params#name
      const rest = body.slice("vless://".length);
      const atIdx = rest.lastIndexOf("@");
      if (atIdx < 0) return null;
      const uuid = rest.slice(0, atIdx);
      const hp = rest.slice(atIdx + 1).split("?")[0];
      const [server, port] = splitHostPort(hp);
      const params = parseQuery(body);
      if (!server) return null;

      const lines = [
        `  - name: ${yamlQuote(name || `vless-${server}`)}`,
        `    type: vless`,
        `    server: ${yamlQuote(server)}`,
        `    port: ${port}`,
        `    uuid: ${yamlQuote(uuid)}`,
        `    udp: true`,
      ];
      const sec = params.get("security");
      if (sec === "tls" || sec === "reality") {
        lines.push(`    tls: true`);
        if (params.get("sni")) lines.push(`    servername: ${yamlQuote(params.get("sni")!)}`);
        if (sec === "reality") {
          lines.push(`    reality-opts:`);
          lines.push(`      public-key: ${yamlQuote(params.get("pbk") || "")}`);
          if (params.get("sid")) lines.push(`      short-id: ${yamlQuote(params.get("sid")!)}`);
        }
      }
      if (params.get("fp")) lines.push(`    client-fingerprint: ${params.get("fp")}`);
      if (params.get("flow")) lines.push(`    flow: ${params.get("flow")}`);
      if (params.get("type") === "ws") {
        lines.push(`    network: ws`);
        lines.push(`    ws-opts: {path: ${yamlQuote(params.get("path") || "/")}}`);
      } else if (params.get("type") === "grpc") {
        lines.push(`    network: grpc`);
        lines.push(`    grpc-opts: {grpc-service-name: ${yamlQuote(params.get("serviceName") || "")}}`);
      }
      return { name, type: "vless", server, port, raw: lines.join("\n") + "\n" };
    }

    if (scheme === "trojan") {
      const rest = body.slice("trojan://".length);
      const atIdx = rest.lastIndexOf("@");
      if (atIdx < 0) return null;
      const password = rest.slice(0, atIdx);
      const hp = rest.slice(atIdx + 1).split("?")[0];
      const [server, port] = splitHostPort(hp);
      const params = parseQuery(body);
      if (!server) return null;
      const lines = [
        `  - name: ${yamlQuote(name || `trojan-${server}`)}`,
        `    type: trojan`,
        `    server: ${yamlQuote(server)}`,
        `    port: ${port}`,
        `    password: ${yamlQuote(password)}`,
        `    udp: true`,
        `    skip-cert-verify: true`,
      ];
      if (params.get("sni")) lines.push(`    sni: ${yamlQuote(params.get("sni")!)}`);
      return { name, type: "trojan", server, port, raw: lines.join("\n") + "\n" };
    }

    if (scheme === "hysteria2" || scheme === "hy2") {
      const rest = body.slice(scheme.length + 3);
      const atIdx = rest.lastIndexOf("@");
      if (atIdx < 0) return null;
      const auth = rest.slice(0, atIdx);
      const hp = rest.slice(atIdx + 1).split("?")[0];
      const [server, port] = splitHostPort(hp);
      const params = parseQuery(body);
      if (!server) return null;
      const lines = [
        `  - name: ${yamlQuote(name || `hysteria2-${server}`)}`,
        `    type: hysteria2`,
        `    server: ${yamlQuote(server)}`,
        `    port: ${port}`,
        `    password: ${yamlQuote(decodeURIComponent(auth))}`,
        `    skip-cert-verify: true`,
      ];
      if (params.get("sni")) lines.push(`    sni: ${yamlQuote(params.get("sni")!)}`);
      if (params.get("insecure") === "1") lines.push(`    skip-cert-verify: true`);
      return { name, type: "hysteria2", server, port, raw: lines.join("\n") + "\n" };
    }

    if (scheme === "ss") {
      const rest = body.slice("ss://".length);
      let method = "", password = "", server = "", port = "";
      const atIdx = rest.lastIndexOf("@");
      if (atIdx >= 0) {
        // ss://base64(method:pass)@host:port
        const userinfo = rest.slice(0, atIdx);
        const hp = rest.slice(atIdx + 1).split("?")[0];
        [server, port] = splitHostPort(hp);
        let decoded = "";
        try { decoded = b64Decode(userinfo); } catch { decoded = userinfo; }
        const ci = decoded.indexOf(":");
        if (ci > 0) { method = decoded.slice(0, ci); password = decoded.slice(ci + 1); }
      } else {
        // 全 base64 形式
        try {
          const decoded = b64Decode(rest);
          const ci = decoded.indexOf(":");
          const ai = decoded.lastIndexOf("@");
          if (ci > 0 && ai > ci) {
            method = decoded.slice(0, ci);
            password = decoded.slice(ci + 1, ai);
            [server, port] = splitHostPort(decoded.slice(ai + 1));
          }
        } catch { return null; }
      }
      if (!server || !method) return null;
      const lines = [
        `  - name: ${yamlQuote(name || `ss-${server}`)}`,
        `    type: ss`,
        `    server: ${yamlQuote(server)}`,
        `    port: ${port}`,
        `    cipher: ${method}`,
        `    password: ${yamlQuote(password)}`,
        `    udp: true`,
      ];
      return { name, type: "ss", server, port, raw: lines.join("\n") + "\n" };
    }
  } catch {
    return null;
  }
  return null;
}

function splitHostPort(hp: string): [string, string] {
  hp = hp.trim();
  if (hp.startsWith("[")) {
    // IPv6
    const end = hp.indexOf("]");
    const host = hp.slice(1, end);
    const port = hp.slice(end + 2);
    return [host, port];
  }
  const idx = hp.lastIndexOf(":");
  if (idx < 0) return [hp, "443"];
  return [hp.slice(0, idx), hp.slice(idx + 1)];
}

function parseQuery(uri: string): Map<string, string> {
  const out = new Map<string, string>();
  const qi = uri.indexOf("?");
  if (qi < 0) return out;
  let q = uri.slice(qi + 1);
  const hi = q.indexOf("#");
  if (hi >= 0) q = q.slice(0, hi);
  for (const pair of q.split("&")) {
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    try {
      out.set(pair.slice(0, eq), decodeURIComponent(pair.slice(eq + 1)));
    } catch {
      out.set(pair.slice(0, eq), pair.slice(eq + 1));
    }
  }
  return out;
}

function yamlQuote(s: string): string {
  if (s === "") return '""';
  if (/[:#{}[\],&*?|>!%@"`\n]/.test(s) || /^\s|\s$/.test(s)) {
    return '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  }
  return s;
}

function b64Decode(s: string): string {
  let t = s.trim().replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  const bin = atob(t);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder("utf-8", { fatal: false, ignoreBOM: false }).decode(bytes);
}

// ── 从 URI 列表文本解析 ──

export function parseURIs(text: string, origin = ""): ParsedNode[] {
  const out: ParsedNode[] = [];
  const re = /(?:ss|ssr|vmess|vless|trojan|hysteria2|hy2|tuic):\/\/[^\s"'<>]+/g;
  const found = text.match(re) || [];
  found.forEach((uri, i) => {
    const n = parseShareURI(uri, i);
    if (n) out.push({ ...n, origin });
  });
  return out;
}

// ── 智能解析（自动识别格式）──

export function parseAny(text: string, origin = ""): { format: FetchResult["format"]; nodes: ParsedNode[] } {
  const trimmed = text.trim();
  if (!trimmed) return { format: "empty", nodes: [] };

  // 1. Clash YAML
  if (/^proxies:\s*$/m.test(text) || /^\s*proxies:\s*$/m.test(text)) {
    const nodes = parseClashNodes(text, origin);
    if (nodes.length) return { format: "clash", nodes };
  }

  // 2. 直接是 URI 列表
  if (/(?:ss|vmess|vless|trojan|hysteria2|hy2):\/\//.test(text)) {
    const nodes = parseURIs(text, origin);
    if (nodes.length) return { format: "uris", nodes };
  }

  // 3. Base64 编码
  if (/^[A-Za-z0-9+/=\s_-]+$/.test(trimmed.slice(0, 200)) && trimmed.length > 40) {
    try {
      const decoded = b64Decode(trimmed.replace(/\s+/g, ""));
      if (/(?:ss|vmess|vless|trojan|hysteria2|hy2):\/\//.test(decoded)) {
        const nodes = parseURIs(decoded, origin);
        if (nodes.length) return { format: "base64", nodes };
      }
      if (/^proxies:\s*$/m.test(decoded)) {
        const nodes = parseClashNodes(decoded, origin);
        if (nodes.length) return { format: "base64", nodes };
      }
    } catch { /* ignore */ }
  }

  return { format: "empty", nodes: [] };
}

// ── 拉取一个源 ──

export async function fetchSource(src: SubSource, timeoutMs = 15000): Promise<FetchResult> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(src.url, {
      headers: { "User-Agent": UA, "Accept": "*/*" },
      signal: ctrl.signal,
      redirect: "follow",
      cf: { cacheTtl: 60 },
    });
    if (!res.ok) {
      return { url: src.url, ok: false, status: res.status,
               error: `HTTP ${res.status}`, format: "empty", nodes: [], bytes: 0 };
    }
    const text = await res.text();
    const { format, nodes } = parseAny(text, src.url);
    return { url: src.url, ok: true, status: res.status, format,
             nodes: nodes.map(n => ({ ...n, name: n.name })), bytes: text.length };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { url: src.url, ok: false, error: msg, format: "empty", nodes: [], bytes: 0 };
  } finally {
    clearTimeout(timer);
  }
}

// ── 聚合多个源 ──

export interface AggregateResult {
  nodes: ParsedNode[];
  results: FetchResult[];
  duplicates: number;
  total_fetched: number;
}

export function fingerprint(n: ParsedNode): string {
  // 提取凭据做指纹
  const cred = n.raw.match(/^ {4}(uuid|password):\s*(.+?)\s*$/m);
  const credVal = cred ? cred[2].replace(/"/g, "") : "";
  return `${n.type}|${n.server}|${n.port}|${credVal}`;
}

export async function aggregate(sources: SubSource[]): Promise<AggregateResult> {
  const enabled = sources.filter(s => s.enabled);
  const results = await Promise.all(enabled.map(s => fetchSource(s)));

  const seen = new Set<string>();
  const nodes: ParsedNode[] = [];
  let totalFetched = 0;
  let dup = 0;

  for (const r of results) {
    totalFetched += r.nodes.length;
    for (const n of r.nodes) {
      const fp = fingerprint(n);
      if (seen.has(fp)) { dup++; continue; }
      seen.add(fp);
      nodes.push(n);
    }
  }

  return { nodes, results, duplicates: dup, total_fetched: totalFetched };
}

// ── 生成 Clash YAML ──

export interface BuildOptions {
  rename: boolean;
  rules: string;
  title?: string;
  /** 模板内容（含 {{PROXY}} 占位符）；提供时用它生成，否则用内置精简版 */
  template?: string;
}

/**
 * 用模板合成订阅：把节点注入模板，替换 {{PROXY}} 占位符
 *
 * 模板结构：[DNS / 嗅探 / rule-providers / rules] + 运行时注入 [proxies / proxy-groups]
 */
export function buildFromTemplate(
  nodes: ParsedNode[],
  template: string,
  groupName = "🚀 节点选择",
  autoGroup = "⚡ 自动选择",
): string {
  const now = new Date().toISOString();
  const names = nodes.map(n => n.name);
  const q = (s: string) => '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';

  // 要注入的两个段
  const inject: string[] = [];

  inject.push("proxies:");
  for (const n of nodes) inject.push(n.raw.replace(/\s+$/, ""));

  inject.push("");
  inject.push("proxy-groups:");

  // 入口组（规则里的 {{PROXY}} 指向它）
  inject.push(`  - name: ${q(groupName)}`);
  inject.push(`    type: select`);
  inject.push(`    proxies:`);
  inject.push(`      - ${q(autoGroup)}`);
  inject.push(`      - DIRECT`);
  inject.push(`      - REJECT`);
  for (const nm of names) inject.push(`      - ${q(nm)}`);

  // 自动测速组
  inject.push(`  - name: ${q(autoGroup)}`);
  inject.push(`    type: url-test`);
  inject.push(`    url: "http://www.gstatic.com/generate_204"`);
  inject.push(`    interval: 300`);
  inject.push(`    tolerance: 50`);
  inject.push(`    proxies:`);
  for (const nm of names) inject.push(`      - ${q(nm)}`);

  // 在 rule-providers / rules 之前插入
  const lines = template.split("\n");
  const out: string[] = [];
  let inserted = false;

  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (!inserted && i > 0 && (/^rule-providers:\s*$/.test(l) || /^rules:\s*$/.test(l))) {
      out.push("");
      out.push(...inject);
      out.push("");
      inserted = true;
    }
    // 替换占位符
    // ⚠️ 规则里是 CSV 格式，组名**不能加引号**（否则引号会成为组名的一部分）
    //    这与 proxy-groups 里的 YAML 引号不同
    const line = l.replace(/\{\{PROXY\}\}/g, groupName);
    out.push(line);
  }

  if (!inserted) {
    out.push("");
    out.push(...inject);
  }

  const header = [
    "# Proxy Pipeline — 合成订阅（模板 + 节点）",
    `# generated: ${now}`,
    `# nodes: ${nodes.length}`,
    "",
  ].join("\n");

  return header + out.join("\n").replace(/^\n+/, "") + "\n";
}

/** 简单的地理重命名（从节点名解析国家/城市） */
export function renameSimple(nodes: ParsedNode[]): ParsedNode[] {
  const counter = new Map<string, number>();
  return nodes.map(n => {
    const parsed = parseRegionFromName(n.name);
    const code = parsed.code;
    const city = parsed.city;

    const key = city ? `${code}-${city}` : code;
    const idx = (counter.get(key) || 0) + 1;
    counter.set(key, idx);

    const flag = code === "XX" ? "🏴" :
      String.fromCodePoint(...Array.from(code).map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
    const cityPart = city ? ` ${city}` : "";
    const newName = `${flag} ${code}${cityPart} ${String(idx).padStart(2, "0")}`;

    const raw = n.raw.replace(/^ {2}- name:\s*.+$/m, `  - name: ${yamlQuote(newName)}`);
    return { ...n, name: newName, raw };
  });
}

/** 国家名映射（英→标准码） */
const COUNTRY_ALIAS: Record<string, string> = {
  "united states": "US", "usa": "US", "america": "US",
  "japan": "JP", "korea": "KR", "south korea": "KR",
  "singapore": "SG", "hongkong": "HK", "hong kong": "HK",
  "taiwan": "TW", "germany": "DE", "netherlands": "NL",
  "holland": "NL", "britain": "GB", "uk": "GB", "england": "GB",
  "france": "FR", "canada": "CA", "australia": "AU",
  "russia": "RU", "italy": "IT", "sweden": "SE", "finland": "FI",
  "poland": "PL", "switzerland": "CH", "turkey": "TR",
  "india": "IN", "indonesia": "ID", "malaysia": "MY",
  "thailand": "TH", "vietnam": "VN", "philippines": "PH",
  "brazil": "BR", "argentina": "AR", "mexico": "MX",
  "south africa": "ZA", "emirates": "AE", "uae": "AE",
  "israel": "IL", "ukraine": "UA", "czech": "CZ",
  "romania": "RO", "hungary": "HU", "bulgaria": "BG",
  "lithuania": "LT", "latvia": "LV", "moldova": "MD",
  "serbia": "RS", "china": "CN", "macau": "MO",
  "new zealand": "NZ", "iceland": "IS", "austria": "AT",
  "belgium": "BE", "denmark": "DK", "norway": "NO",
  "ireland": "IE", "spain": "ES", "portugal": "PT",
};

/** 协议/技术关键词 —— 不是国家码，必须排除 */
const TECH_WORDS = new Set([
  "WS", "GRPC", "TLS", "TCP", "UDP", "CDN", "CF", "IP", "VPS", "SS", "SSR",
  "VM", "VL", "HY", "H2", "HTTP", "HTTPS", "SNI", "DNS", "ISP", "IDC",
  "API", "URL", "CDN", "BGP", "NAT", "GIA", "IEPL", "IPLC", "BGP",
  "XTLS", "REALITY", "VLESS", "TROJAN", "HYSTERIA", "SHADOWSOCKS",
  "PRO", "MAX", "PLUS", "VIP", "SVIP", "FREE", "FAST", "AUTO",
  "MB", "GB", "TB", "MS", "IO", "CN2", "GCP", "AWS", "AZ", "OVH",
]);

/** 合法国家码白名单（ISO 3166-1 alpha-2 常用子集 + 常见代理地区） */
const VALID_CC = new Set([
  "US", "JP", "KR", "SG", "HK", "TW", "DE", "NL", "GB", "FR", "CA", "AU",
  "RU", "IT", "SE", "FI", "PL", "EE", "CH", "TR", "IN", "ID", "MY", "TH",
  "VN", "PH", "BR", "AR", "MX", "ZA", "AE", "IL", "UA", "CZ", "RO", "HU",
  "BG", "LT", "LV", "MD", "RS", "CN", "MO", "NZ", "IS", "AT", "BE", "DK",
  "NO", "IE", "ES", "PT", "BA", "HR", "SI", "SK", "GR", "EG", "NG", "KE",
  "SA", "QA", "KW", "OM", "BH", "JO", "LB", "PK", "BD", "LK", "NP", "MM",
  "KH", "LA", "MN", "KZ", "UZ", "GE", "AM", "AZ", "BY", "PR", "DO", "GT",
  "CR", "PA", "PE", "CO", "VE", "EC", "UY", "PY", "BO", "CU", "TT", "JM",
  "MT", "CY", "LU", "MC", "LI", "SM", "AD", "GI", "IM", "JE", "GG",
  "AL", "MK", "ME", "BY", "AX", "FO", "GL", "NC", "PF", "FJ", "PG",
  "BN", "TL", "MV", "AF", "IQ", "IR", "SY", "YE", "SD", "ET", "TZ",
  "UG", "GH", "CI", "SN", "CM", "AO", "MZ", "ZM", "ZW", "BW", "NA",
  "MU", "MG", "TN", "MA", "DZ", "LY", "CV", "SN",
]);

function isValidCC(code: string): boolean {
  return VALID_CC.has(code.toUpperCase()) && !isTechWord(code);
}

function isTechWord(s: string): boolean {
  return TECH_WORDS.has(s.toUpperCase());
}

/** IATA 机场码 → (国家码, 城市) —— 节点名常用三字码 */
const IATA_CODE: Record<string, [string, string]> = {
  SEA: ["US", "Seattle"], LAX: ["US", "Los Angeles"], SJC: ["US", "San Jose"],
  SFO: ["US", "San Francisco"], JFK: ["US", "New York"], EWR: ["US", "Newark"],
  ORD: ["US", "Chicago"], DFW: ["US", "Dallas"], IAD: ["US", "Washington"],
  ATL: ["US", "Atlanta"], MIA: ["US", "Miami"], PHX: ["US", "Phoenix"],
  DEN: ["US", "Denver"], BOS: ["US", "Boston"], LAS: ["US", "Las Vegas"],
  HKG: ["HK", "Hong Kong"], TPE: ["TW", "Taipei"], NRT: ["JP", "Tokyo"],
  HND: ["JP", "Tokyo"], KIX: ["JP", "Osaka"], ICN: ["KR", "Seoul"],
  SIN: ["SG", "Singapore"], BKK: ["TH", "Bangkok"], KUL: ["MY", "Kuala Lumpur"],
  CGK: ["ID", "Jakarta"], MNL: ["PH", "Manila"], SGN: ["VN", "Ho Chi Minh"],
  HAN: ["VN", "Hanoi"], DEL: ["IN", "Delhi"], BOM: ["IN", "Mumbai"],
  DXB: ["AE", "Dubai"], LHR: ["GB", "London"], CDG: ["FR", "Paris"],
  FRA: ["DE", "Frankfurt"], AMS: ["NL", "Amsterdam"], MAD: ["ES", "Madrid"],
  FCO: ["IT", "Rome"], MXP: ["IT", "Milan"], ZRH: ["CH", "Zurich"],
  VIE: ["AT", "Vienna"], ARN: ["SE", "Stockholm"], HEL: ["FI", "Helsinki"],
  OSL: ["NO", "Oslo"], CPH: ["DK", "Copenhagen"], WAW: ["PL", "Warsaw"],
  PRG: ["CZ", "Prague"], BUD: ["HU", "Budapest"], IST: ["TR", "Istanbul"],
  SVO: ["RU", "Moscow"], LED: ["RU", "St Petersburg"], KBP: ["UA", "Kyiv"],
  YYZ: ["CA", "Toronto"], YVR: ["CA", "Vancouver"], YUL: ["CA", "Montreal"],
  SYD: ["AU", "Sydney"], MEL: ["AU", "Melbourne"], AKL: ["NZ", "Auckland"],
  GRU: ["BR", "Sao Paulo"], EZE: ["AR", "Buenos Aires"], MEX: ["MX", "Mexico City"],
  JNB: ["ZA", "Johannesburg"], CPT: ["ZA", "Cape Town"], CAI: ["EG", "Cairo"],
};

/** 中文地区名 → 国家码 (+可选城市) */
const CN_REGION: Record<string, [string, string?]> = {
  "美国": ["US"], "日本": ["JP"], "韩国": ["KR"], "新加坡": ["SG"],
  "香港": ["HK"], "台湾": ["TW"], "德国": ["DE"], "荷兰": ["NL"],
  "英国": ["GB"], "法国": ["FR"], "加拿大": ["CA"], "澳大利亚": ["AU"],
  "澳洲": ["AU"], "俄罗斯": ["RU"], "意大利": ["IT"], "瑞典": ["SE"],
  "芬兰": ["FI"], "波兰": ["PL"], "瑞士": ["CH"], "土耳其": ["TR"],
  "印度": ["IN"], "印尼": ["ID"], "马来西亚": ["MY"], "泰国": ["TH"],
  "越南": ["VN"], "菲律宾": ["PH"], "巴西": ["BR"], "阿根廷": ["AR"],
  "墨西哥": ["MX"], "南非": ["ZA"], "阿联酋": ["AE"], "以色列": ["IL"],
  "乌克兰": ["UA"], "捷克": ["CZ"], "罗马尼亚": ["RO"], "保加利亚": ["BG"],
  "立陶宛": ["LT"], "拉脱维亚": ["LV"], "塞尔维亚": ["RS"], "澳门": ["MO"],
  "新西兰": ["NZ"], "奥地利": ["AT"], "比利时": ["BE"], "丹麦": ["DK"],
  "挪威": ["NO"], "爱尔兰": ["IE"], "西班牙": ["ES"], "葡萄牙": ["PT"],
  // 城市 → 国家
  "洛杉矶": ["US", "Los Angeles"], "圣何塞": ["US", "San Jose"],
  "西雅图": ["US", "Seattle"], "纽约": ["US", "New York"],
  "达拉斯": ["US", "Dallas"], "芝加哥": ["US", "Chicago"],
  "东京": ["JP", "Tokyo"], "大阪": ["JP", "Osaka"],
  "首尔": ["KR", "Seoul"], "伦敦": ["GB", "London"],
  "法兰克福": ["DE", "Frankfurt"], "阿姆斯特丹": ["NL", "Amsterdam"],
  "巴黎": ["FR", "Paris"], "莫斯科": ["RU", "Moscow"],
  "悉尼": ["AU", "Sydney"], "圣保罗": ["BR", "Sao Paulo"],
  "孟买": ["IN", "Mumbai"], "迪拜": ["AE", "Dubai"],
};

/** 从节点名解析 (国家码, 城市) */
export function parseRegionFromName(name: string): { code: string; city: string } {
  // 清理：去掉引号、多余空格
  const clean = name.replace(/^["'\s]+|["'\s]+$/g, "");
  if (!clean) return { code: "XX", city: "" };

  // ── 0. IATA 机场码（节点名常用，如 "移动-SEA-443-WS"）──
  const iataMatches = clean.match(/\b(SEA|LAX|SJC|SFO|JFK|EWR|ORD|DFW|IAD|ATL|MIA|PHX|DEN|BOS|LAS|HKG|TPE|NRT|HND|KIX|ICN|SIN|BKK|KUL|CGK|MNL|SGN|HAN|DEL|BOM|DXB|LHR|CDG|FRA|AMS|MAD|FCO|MXP|ZRH|VIE|ARN|HEL|OSL|CPH|WAW|PRG|BUD|IST|SVO|LED|KBP|YYZ|YVR|YUL|SYD|MEL|AKL|GRU|EZE|MEX|JNB|CPT|CAI)\b/g);
  if (iataMatches && iataMatches.length) {
    const hit = IATA_CODE[iataMatches[0]];
    if (hit) return { code: hit[0], city: hit[1] };
  }

  // ── 1. 国旗 emoji（最强信号）──
  const flagMatch = clean.match(/[\u{1F1E6}-\u{1F1FF}]{2}/u);
  if (flagMatch) {
    const code = Array.from(flagMatch[0])
      .map(c => String.fromCharCode(c.codePointAt(0)! - 0x1F1E6 + 65)).join("");
    if (/^[A-Z]{2}$/.test(code) && isValidCC(code)) {
      const after = clean.slice(clean.indexOf(flagMatch[0]) + flagMatch[0].length);
      return { code, city: extractCity(after) };
    }
  }

  // ── 2. "NL-Alkmaar-7311" / "US-West Wendover-49684" / "SG-auto ──
  const m1 = clean.match(/(?:^|[\s|])?([A-Z]{2})[-_]+([A-Za-z][A-Za-z\s]{1,20}?)(?:[-_]|\s*\d|$)/);
  if (m1 && isValidCC(m1[1])) {
    const city = cleanCity(m1[2]);
    const junk = /^(auto|fiber|test|cellular|allowlist|only|node|proxy|vip|free|fast|tls|ws|grpc|tcp|h2|http|cdn|relay|direct)$/i;
    return { code: m1[1], city: junk.test(city) ? "" : city };
  }

  // ── 3. 中文地区名（含城市）──
  for (const [cn, [code, city]] of Object.entries(CN_REGION)) {
    if (clean.includes(cn)) {
      return { code, city: city || "" };
    }
  }

  // ── 4. 英文国家名 ──
  const lower = clean.toLowerCase();
  for (const [alias, code] of Object.entries(COUNTRY_ALIAS)) {
    if (alias.length >= 3 && lower.includes(alias)) {
      return { code, city: "" };
    }
  }

  // ── 5. 独立国家码（必须是合法国家码）──
  const m2 = clean.match(/\b([A-Z]{2})\b/g);
  if (m2) {
    for (const cand of m2) {
      if (isValidCC(cand)) {
        return { code: cand, city: "" };
      }
    }
  }

  return { code: "XX", city: "" };
}

function isCountryName(s: string): boolean {
  return ["美国", "日本", "韩国", "新加坡", "香港", "台湾", "德国", "荷兰",
          "英国", "法国", "加拿大", "澳大利亚", "俄罗斯", "意大利", "瑞典",
          "芬兰", "波兰", "瑞士", "土耳其", "印度", "印尼", "马来西亚",
          "泰国", "越南", "菲律宾", "巴西", "阿根廷", "墨西哥", "南非"].includes(s);
}

function extractCity(s: string): string {
  // 形如 "-Alkmaar-7311-ezrr" 或 " Amsterdam 01"
  const m = s.match(/^[-_\s]*([A-Za-z][A-Za-z\s]{1,20}?)(?:[-_]|\s*\d|$)/);
  return m ? cleanCity(m[1]) : "";
}

function cleanCity(s: string): string {
  const t = s.trim().replace(/[-_]+/g, " ").replace(/\s+/g, " ").trim();
  // 标题化
  return t.split(" ").map(w => w ? w[0].toUpperCase() + w.slice(1).toLowerCase() : "").join(" ").slice(0, 18);
}

export function buildClash(nodes: ParsedNode[], opts: BuildOptions): string {
  // 有模板 → 用模板合成（保留用户的 DNS/规则/规则集）
  if (opts.template && opts.template.trim().length > 100) {
    return buildFromTemplate(nodes, opts.template);
  }

  const now = new Date().toISOString();
  const names = nodes.map(n => n.name);

  const lines: string[] = [
    `# ${opts.title || "Proxy Pipeline Subscription"}`,
    `# generated: ${now}`,
    `# nodes: ${nodes.length}`,
    `mixed-port: 7890`,
    `allow-lan: false`,
    `mode: rule`,
    `log-level: warning`,
    `external-controller: 127.0.0.1:9090`,
    ``,
    `proxies:`,
  ];
  for (const n of nodes) lines.push(n.raw.replace(/\s+$/, ""));

  const q = (s: string) => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

  lines.push(``, `proxy-groups:`);
  lines.push(`  - name: "PROXY"`);
  lines.push(`    type: select`);
  lines.push(`    proxies:`);
  lines.push(`      - "AUTO"`);
  lines.push(`      - "DIRECT"`);
  for (const nm of names) lines.push(`      - ${q(nm)}`);

  lines.push(`  - name: "AUTO"`);
  lines.push(`    type: url-test`);
  lines.push(`    url: "http://www.gstatic.com/generate_204"`);
  lines.push(`    interval: 300`);
  lines.push(`    tolerance: 50`);
  lines.push(`    proxies:`);
  for (const nm of names) lines.push(`      - ${q(nm)}`);

  lines.push(``);
  // 规则：用户提供的 YAML 片段（含 rules: 头）
  const rulesText = opts.rules.trim();
  if (/^rules:/m.test(rulesText)) {
    lines.push(rulesText);
  } else {
    lines.push(`rules:`);
    for (const l of rulesText.split("\n")) {
      if (!l.trim()) continue;
      lines.push(l.startsWith("  ") ? l : `  - ${l.replace(/^-\s*/, "")}`);
    }
  }

  return lines.join("\n") + "\n";
}

/** 生成 base64 订阅（节点 URI 列表） */
export function buildBase64(nodes: ParsedNode[]): string {
  // 只输出支持的协议，且需要能转回 URI；这里用简化做法：
  // 把节点信息拼成 v2rayN 能识别的 URI
  const uris: string[] = [];
  for (const n of nodes) {
    const field = (k: string) => {
      const m = n.raw.match(new RegExp(`^ {4}${k}:\\s*(.+?)\\s*$`, "m"));
      return m ? m[1].replace(/^"|"$/g, "") : "";
    };
    const server = field("server");
    const port = field("port");
    const name = encodeURIComponent(n.name).replace(/%20/g, "%20");
    if (n.type === "vmess") {
      const obj = {
        v: "2", ps: n.name, add: server, port,
        id: field("uuid"), aid: field("alterId") || "0",
        scy: field("cipher") || "auto", net: "tcp", type: "none",
        host: "", path: "", tls: field("tls") === "true" ? "tls" : "",
      };
      const b64 = btoa(unescape(encodeURIComponent(JSON.stringify(obj))));
      uris.push(`vmess://${b64}`);
    } else if (n.type === "vless") {
      const params = new URLSearchParams();
      params.set("encryption", "none");
      if (field("tls") === "true") params.set("security", "tls");
      const sni = field("servername");
      if (sni) params.set("sni", sni);
      uris.push(`vless://${field("uuid")}@${server}:${port}?${params.toString()}#${name}`);
    } else if (n.type === "trojan") {
      uris.push(`trojan://${field("password")}@${server}:${port}?sni=${field("sni")}#${name}`);
    } else if (n.type === "hysteria2") {
      uris.push(`hysteria2://${field("password")}@${server}:${port}?sni=${field("sni")}#${name}`);
    } else if (n.type === "ss") {
      const userinfo = btoa(`${field("cipher")}:${field("password")}`);
      uris.push(`ss://${userinfo}@${server}:${port}#${name}`);
    }
  }
  const joined = uris.join("\n");
  // UTF-8 安全的 base64
  const bytes = new TextEncoder().encode(joined);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
