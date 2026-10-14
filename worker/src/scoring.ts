/**
 * 节点评分与筛选 —— 从公开源里挑出更好的节点
 *
 * 设计目标（用户需求）：
 *   1. 剔除 http / socks4 / socks5（代理池协议，客户端用不上）
 *   2. 剔除 anytls 等支持差的协议
 *   3. 按评分优选，总量控制在 300 以内
 *   4. 尽量平衡 vless / hysteria2（受源限制，hy2 尽量保满）
 *
 * 评分维度（均来自节点自身特征，不需要联网探测）：
 *   + 协议偏好：hysteria2 > trojan > vless > ss > vmess
 *   + 传输方式：有 TLS > 无 TLS；grpc/ws 优先于裸 tcp（更抗封锁）
 *   + 端口：443 最佳，8443/2053/2083 等 CDN 友好端口次之，非常规端口降分
 *   + 服务端：域名 > IP（域名通常有 CDN 加速）；非 CF 任播 IP 加分
 *   + 名称含地区标识（说明源做了整理）
 *   - 惩罚：无 TLS 明传、非常用端口、CF 任播 IP（大量共享，质量差）
 */

export interface ScoredNode {
  name: string;
  type: string;
  server: string;
  port: string;
  raw: string;
  score: number;
  reasons: string[];
}

/** 协议权重（越大越优） */
const PROTO_WEIGHT: Record<string, number> = {
  hysteria2: 50,   // QUIC，抗封锁最好，用户最重视
  hysteria: 50,
  trojan: 35,      // TLS 伪装好
  vless: 30,       // 主流，但量大需控制
  ss: 20,
  vmess: 15,       // 老旧
  tuic: 45,
};

/** 完全剔除的协议（代理池协议，客户端不支持或不需要） */
const DROP_TYPES = new Set([
  "http", "https", "socks4", "socks5", "socks", "anytls",
]);

/** 优质端口 */
const GOOD_PORTS = new Set(["443", "8443", "2053", "2083", "2087", "2096", "8443"]);
/** CDN 友好端口（次优） */
const CDN_PORTS = new Set(["80", "8080", "8880", "2052", "2082", "2086", "2095"]);

const CF_IP_RE = /^(104\.(1[6-9]|2[0-7])\.|172\.(6[4-9]|7[0-1])\.|162\.15[89]\.|188\.114\.|190\.93\.|19[0-8]\.41\.|141\.101\.|108\.162\.|173\.245\.|103\.2[12]\.|103\.31\.)/;

/** 给单个节点打分 */
export function scoreNode(node: {
  name: string; type: string; server: string; port: string; raw: string;
}): ScoredNode {
  const reasons: string[] = [];
  let score = 0;

  const t = node.type.toLowerCase();
  const raw = node.raw;
  const port = String(node.port);

  // ── 1. 协议 ──
  const pw = PROTO_WEIGHT[t] ?? 10;
  score += pw;
  reasons.push(`proto:${t}+${pw}`);

  // ── 2. TLS ──
  const hasTLS = /^\s+tls:\s*true/m.test(raw)
    || /^\s+(?:servername|sni):/m.test(raw)
    || t === "trojan" || t === "hysteria2";
  if (hasTLS) {
    score += 15;
    reasons.push("tls+15");
  } else {
    score -= 20;
    reasons.push("no-tls-20");
  }

  // ── 3. 传输方式 ──
  const netMatch = raw.match(/^\s+network:\s*"?(\w+)"?/m);
  const net = netMatch ? netMatch[1].toLowerCase() : "tcp";
  if (net === "grpc") { score += 8; reasons.push("grpc+8"); }
  else if (net === "ws") { score += 6; reasons.push("ws+6"); }
  else if (net === "h2" || net === "http") { score += 4; reasons.push("h2+4"); }
  else if (net === "tcp" || net === "raw") {
    // 裸 TCP 加 TLS 也是好的（如 reality）
    if (/reality-opts/i.test(raw)) { score += 12; reasons.push("reality+12"); }
    else { score += 2; reasons.push("tcp+2"); }
  }

  // ── 4. 端口 ──
  if (GOOD_PORTS.has(port)) { score += 10; reasons.push(`port443+10`); }
  else if (CDN_PORTS.has(port)) { score += 3; reasons.push(`port-cdn+3`); }
  else if (/^\d+$/.test(port) && parseInt(port, 10) > 1024) {
    score -= 5; reasons.push("port-high-5");
  }

  // ── 5. 服务端 ──
  const isDomain = !/^\d+\.\d+\.\d+\.\d+$/.test(node.server) && !/^[0-9a-f:]+$/i.test(node.server);
  if (isDomain) {
    score += 8;
    reasons.push("domain+8");
  } else if (CF_IP_RE.test(node.server)) {
    score -= 25;
    reasons.push("cf-ip-25");
  }

  // ── 6. 名称含地区标识 ──
  if (/[\u{1F1E6}-\u{1F1FF}]{2}/u.test(node.name)
      || /\b(US|JP|KR|SG|HK|TW|DE|NL|GB|FR|CA|AU|RU|IT|SE|FI|PL|CH|TR|IN|ID|MY|TH|VN|PH|BR|AR|MX|ZA|AE|IL)\b/.test(node.name)
      || /(美国|日本|韩国|新加坡|香港|台湾|德国|荷兰|英国|法国|加拿大|澳大利亚)/.test(node.name)) {
    score += 4;
    reasons.push("named+4");
  }

  return { ...node, score, reasons };
}

/** 是否应剔除（协议不支持） */
export function shouldDrop(node: { type: string }): boolean {
  return DROP_TYPES.has(node.type.toLowerCase());
}

export interface FilterOptions {
  /** 目标节点总数 */
  target?: number;
  /** 各协议上限（0 = 不限） */
  maxPerProto?: Record<string, number>;
  /** 各协议保底数量（尽量满足，源不足时按实际） */
  minPerProto?: Record<string, number>;
}

export interface FilterResult<T> {
  kept: T[];
  dropped: T[];
  stats: {
    input: number;
    droppedByType: number;
    kept: number;
    byProto: Record<string, number>;
    scoreRange: [number, number];
  };
}

/**
 * 筛选节点
 *
 * 策略：
 *   1. 先按协议剔除（http/socks/anytls）
 *   2. 全部打分
 *   3. 按「分协议配额」分配：
 *      - 每个协议先保底（minPerProto）
 *      - 剩余名额按分数从高到低填
 *      - 受 maxPerProto 限制
 *   4. 总数不超过 target
 */
export function filterByScore<T extends {
  name: string; type: string; server: string; port: string; raw: string;
}>(nodes: T[], opts: FilterOptions = {}): FilterResult<T> {
  const target = opts.target ?? 300;
  const maxPerProto = opts.maxPerProto ?? {};
  const minPerProto = opts.minPerProto ?? {};

  const input = nodes.length;

  // 1. 剔除不支持的协议
  const usable: T[] = [];
  let droppedByType = 0;
  for (const n of nodes) {
    if (shouldDrop(n)) { droppedByType++; continue; }
    usable.push(n);
  }

  // 2. 打分 + 排序
  const scored = usable.map(n => scoreNode(n));
  scored.sort((a, b) => b.score - a.score);

  // 3. 分协议配额
  const byProto = new Map<string, ScoredNode[]>();
  for (const s of scored) {
    const key = normalizeProto(s.type);
    if (!byProto.has(key)) byProto.set(key, []);
    byProto.get(key)!.push(s);
  }

  const kept: ScoredNode[] = [];
  const takenByProto = new Map<string, number>();

  // 3a. 保底：每协议先取前 N 个
  for (const [proto, items] of byProto) {
    const want = minPerProto[proto] ?? 0;
    const take = Math.min(want, items.length);
    for (let i = 0; i < take; i++) {
      kept.push(items[i]);
    }
    takenByProto.set(proto, take);
  }

  // 3b. 剩余名额：全局按分数填充
  const remaining = Math.max(0, target - kept.length);
  let added = 0;
  for (const s of scored) {
    if (added >= remaining) break;
    const key = normalizeProto(s.type);
    const already = takenByProto.get(key) ?? 0;
    const cap = maxPerProto[key];
    // 已在保底阶段取过的不重复取
    const items = byProto.get(key)!;
    const idx = items.indexOf(s);
    if (idx < already) continue;          // 保底已取
    if (cap !== undefined && already >= cap) continue;   // 超过上限

    kept.push(s);
    takenByProto.set(key, already + 1);
    added++;
  }

  // 4. 结果
  const keptNames = new Set(kept.map(k => k.name + "|" + k.server + "|" + k.port));
  const keptOriginal = usable.filter(n =>
    keptNames.has(n.name + "|" + n.server + "|" + n.port));
  const droppedOriginal = usable.filter(n =>
    !keptNames.has(n.name + "|" + n.server + "|" + n.port));

  const finalByProto: Record<string, number> = {};
  for (const k of kept) {
    const key = normalizeProto(k.type);
    finalByProto[key] = (finalByProto[key] ?? 0) + 1;
  }

  const scores = kept.map(k => k.score);

  return {
    kept: keptOriginal,
    dropped: droppedOriginal,
    stats: {
      input,
      droppedByType,
      kept: keptOriginal.length,
      byProto: finalByProto,
      scoreRange: scores.length
        ? [Math.min(...scores), Math.max(...scores)]
        : [0, 0],
    },
  };
}

function normalizeProto(t: string): string {
  const x = t.toLowerCase();
  if (x === "hy2") return "hysteria2";
  return x;
}

/** 默认配额（供 Worker 调用） */
export const DEFAULT_FILTER: FilterOptions = {
  target: 300,
  maxPerProto: {
    vless: 120,      // 主流但量大，设上限
    vmess: 60,
    trojan: 60,
    ss: 40,
    hysteria2: 40,   // 源里少，尽量保满
    tuic: 20,
  },
  minPerProto: {
    hysteria2: 10,   // 源里就这么点，保底
    vless: 40,
    trojan: 20,
    ss: 10,
  },
};
