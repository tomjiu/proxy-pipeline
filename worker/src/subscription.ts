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

  const out: ParsedNode[] = [];
  // 按 "  - name:" 切分（2 空格缩进）
  const chunks = rest.split(/^ {2}- name:\s*/m);
  for (let i = 1; i < chunks.length; i++) {
    const ch = chunks[i];
    const raw = "  - name: " + ch.replace(/\s+$/, "") + "\n";

    const firstLine = ch.split("\n", 1)[0].trim();
    const name = firstLine.replace(/^"(.*)"$/, "$1");

    const field = (key: string): string => {
      const re = new RegExp(`^ {4}${key}:\\s*(.+?)\\s*$`, "m");
      const mm = ch.match(re);
      if (!mm) return "";
      let v = mm[1];
      if (v.length >= 2 && v[0] === '"' && v[v.length - 1] === '"') v = v.slice(1, -1);
      return v;
    };

    const type = field("type");
    const server = field("server");
    const port = field("port");

    if (name && type && server) {
      out.push({ name, type, server, port, raw, origin });
    }
  }
  return out;
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
}

/** 简单的地理重命名（基于节点名里的国旗/国家码） */
export function renameSimple(nodes: ParsedNode[]): ParsedNode[] {
  const counter = new Map<string, number>();
  return nodes.map(n => {
    // 尝试从名字提取国旗
    const flagMatch = n.name.match(/[\u{1F1E6}-\u{1F1FF}]{2}/u);
    let code = "XX";
    if (flagMatch) {
      code = Array.from(flagMatch[0]).map(c =>
        String.fromCharCode(c.codePointAt(0)! - 0x1F1E6 + 65)).join("");
    } else {
      const ccMatch = n.name.match(/\b(US|JP|KR|SG|HK|TW|DE|NL|GB|FR|CA|AU|RU|IT|SE|FI|PL|EE|CH|TR|IN|ID|MY|TH|VN|PH|BR|AR|MX|ZA|AE|IL)\b/);
      if (ccMatch) code = ccMatch[1];
    }
    const key = code;
    const idx = (counter.get(key) || 0) + 1;
    counter.set(key, idx);
    const flag = code === "XX" ? "🏴" :
      String.fromCodePoint(...Array.from(code).map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
    const newName = `${flag} ${code} ${String(idx).padStart(2, "0")}`;
    const raw = n.raw.replace(/^ {2}- name:\s*.+$/m, `  - name: ${yamlQuote(newName)}`);
    return { ...n, name: newName, raw };
  });
}

export function buildClash(nodes: ParsedNode[], opts: BuildOptions): string {
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
