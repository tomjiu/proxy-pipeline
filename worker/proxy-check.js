/**
 * CF Worker 代理测活能力验证
 *
 * 目标：验证 Worker 能否判断「代理是否活着」
 *
 * 三个测试：
 *   1. HTTP 代理测活   —— 用 fetch 带 proxy？(CF 不支持 fetch 代理，需手工隧道)
 *   2. SOCKS5 测活     —— 用 connect() 做 SOCKS5 握手 + CONNECT
 *   3. 纯 TCP 端口探测 —— 只判断端口是否 open（最弱但最快）
 *   4. UDP 探测        —— 预期失败
 *
 * 用法：
 *   /?test=tcp&host=1.2.3.4&port=8080
 *   /?test=socks5&host=1.2.3.4&port=1080
 *   /?test=batch&list=<url>      批量测（读一个 ip:port 列表）
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const test = url.searchParams.get('test') || 'info';

    if (test === 'info') {
      return json({
        runtime_note: 'workerd (Cloudflare Workers)',
        capabilities: {
          fetch: true,
          tcp_connect: typeof connect === 'function',
          udp: false,
          'socks5_via_connect': 'possible (TCP handshake)',
          'http_proxy_via_fetch': 'NOT possible - fetch() has no proxy option',
          'http_proxy_via_connect': 'possible (manual HTTP CONNECT tunneling)',
          'vless_reality': 'NOT possible - needs REALITY-specific TLS params',
          'hysteria2_quic': 'NOT possible - requires UDP',
        },
        verdict: {
          'HTTP/SOCKS proxy check': '✅ 可行',
          'TCP port open check': '✅ 可行（但弱）',
          'vless/hy2 node check': '❌ 不可行',
        },
      });
    }

    // ── 测试1: 纯 TCP 端口探测 ──
    if (test === 'tcp') {
      const host = url.searchParams.get('host');
      const port = parseInt(url.searchParams.get('port') || '80');
      if (!host) return json({ error: 'need host' }, 400);

      const t0 = Date.now();
      try {
        const socket = connect({ hostname: host, port }, { secureTransport: 'off' });
        // 只测能否建立连接
        const writer = socket.writable.getWriter();
        await writer.close();
        socket.close();
        return json({ ok: true, host, port, elapsed_ms: Date.now() - t0,
          verdict: '端口开放' });
      } catch (e) {
        return json({ ok: false, host, port, elapsed_ms: Date.now() - t0,
          error: e.message, verdict: '端口关闭或不可达' });
      }
    }

    // ── 测试2: SOCKS5 完整握手 + CONNECT + 真实请求 ──
    if (test === 'socks5') {
      const host = url.searchParams.get('host');
      const port = parseInt(url.searchParams.get('port') || '1080');
      const target = url.searchParams.get('target') || 'example.com';
      const targetPort = parseInt(url.searchParams.get('target_port') || '80');
      if (!host) return json({ error: 'need host' }, 400);

      const t0 = Date.now();
      let socket = null;
      try {
        socket = connect({ hostname: host, port }, { secureTransport: 'off' });
        const writer = socket.writable.getWriter();
        const reader = socket.readable.getReader();

        // ① 协商：无认证
        await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
        const neg = await reader.read();
        if (!neg.value || neg.value[0] !== 0x05 || neg.value[1] !== 0x00) {
          throw new Error('negotiation failed: ' + (neg.value ? Array.from(neg.value) : 'empty'));
        }

        // ② CONNECT
        const tb = new TextEncoder().encode(target);
        await writer.write(new Uint8Array([
          0x05, 0x01, 0x00, 0x03, tb.length, ...tb,
          (targetPort >> 8) & 0xff, targetPort & 0xff
        ]));
        const conn = await reader.read();
        if (!conn.value || conn.value[1] !== 0x00) {
          throw new Error('connect failed: reply=' + (conn.value ? conn.value[1] : 'empty'));
        }

        // ③ 通过代理发真实 HTTP 请求
        await writer.write(new TextEncoder().encode(
          `GET /generate_204 HTTP/1.1\r\nHost: ${target}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`));

        let body = '';
        for (let i = 0; i < 5; i++) {
          const { value, done } = await reader.read();
          if (done || !value) break;
          body += new TextDecoder().decode(value);
          if (body.includes('\r\n\r\n')) break;
        }
        reader.cancel().catch(() => {});
        socket.close();

        const firstLine = body.split('\r\n')[0] || '';
        return json({
          ok: true, host, port, target, elapsed_ms: Date.now() - t0,
          negotiation: 'ok', connect: 'ok',
          response_first_line: firstLine,
          is_genuine: /204|200/.test(firstLine),
          verdict: /204|200/.test(firstLine) ? '✅ 真代理可用' : '⚠️ 有响应但不是预期内容',
        });
      } catch (e) {
        try { if (socket) socket.close(); } catch (_) {}
        return json({ ok: false, host, port, elapsed_ms: Date.now() - t0,
          error: e.message, verdict: '❌ 不可用' });
      }
    }

    // ── 测试3: HTTP 代理（CONNECT 隧道法）──
    if (test === 'http') {
      const host = url.searchParams.get('host');
      const port = parseInt(url.searchParams.get('port') || '8080');
      if (!host) return json({ error: 'need host' }, 400);

      const t0 = Date.now();
      let socket = null;
      try {
        socket = connect({ hostname: host, port }, { secureTransport: 'off' });
        const writer = socket.writable.getWriter();
        const reader = socket.readable.getReader();

        // 直接发完整 URL 的 HTTP 请求（HTTP 代理标准用法）
        const req = `GET http://example.com/generate_204 HTTP/1.1\r\n`
                  + `Host: example.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`;
        await writer.write(new TextEncoder().encode(req));

        let body = '';
        for (let i = 0; i < 5; i++) {
          const { value, done } = await reader.read();
          if (done || !value) break;
          body += new TextDecoder().decode(value);
          if (body.includes('\r\n\r\n')) break;
        }
        reader.cancel().catch(() => {});
        socket.close();

        const firstLine = body.split('\r\n')[0] || '';
        return json({
          ok: true, host, port, elapsed_ms: Date.now() - t0,
          response_first_line: firstLine,
          is_genuine: /204|200/.test(firstLine),
          verdict: /204|200/.test(firstLine) ? '✅ 真代理可用' : '⚠️ 异常响应',
        });
      } catch (e) {
        try { if (socket) socket.close(); } catch (_) {}
        return json({ ok: false, host, port, elapsed_ms: Date.now() - t0,
          error: e.message, verdict: '❌ 不可用' });
      }
    }

    // ── 测试4: 批量测活（并发）──
    if (test === 'batch') {
      const listUrl = url.searchParams.get('list');
      if (!listUrl) return json({ error: 'need list=<url of ip:port lines>' }, 400);

      try {
        const res = await fetch(listUrl, { cf: { cacheTtl: 60 } });
        const text = await res.text();
        const lines = text.split('\n').map(s => s.trim())
          .filter(s => /^\d+\.\d+\.\d+\.\d+:\d+$/.test(s)).slice(0, 50);

        const results = await Promise.all(lines.map(async (addr) => {
          const [h, p] = addr.split(':');
          const t0 = Date.now();
          try {
            const s = connect({ hostname: h, port: parseInt(p) }, { secureTransport: 'off' });
            const w = s.writable.getWriter();
            await w.close();
            s.close();
            return { addr, alive: true, ms: Date.now() - t0 };
          } catch (e) {
            return { addr, alive: false, ms: Date.now() - t0, err: e.message };
          }
        }));

        const alive = results.filter(r => r.alive).length;
        // 注意：返回全部会很大，只返回统计 + 存活列表
        return json({
          total: results.length,
          alive,
          alive_rate: (alive / results.length * 100).toFixed(1) + '%',
          note: '这是 TCP 端口探测，不是真代理验证。端口开放 ≠ 代理可用',
          alive_list: results.filter(r => r.alive).map(r => r.addr),
        });
      } catch (e) {
        return json({ error: 'fetch list failed: ' + e.message }, 500);
      }
    }

    return json({ error: 'unknown test',
      available: ['info', 'tcp', 'socks5', 'http', 'batch'] }, 400);
  }
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}
