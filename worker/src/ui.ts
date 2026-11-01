/**
 * Web UI —— 登录页 + 管理面板
 * 纯 HTML/CSS/JS 内联，无外部依赖
 */

export function loginPage(error?: string, next?: string): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录 · Proxy Pipeline</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
    background: #0f1115; color: #e6e8eb;
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    padding: 20px;
  }
  .card {
    background: #171a21; border: 1px solid #262b36; border-radius: 12px;
    padding: 32px; width: 100%; max-width: 380px;
  }
  h1 { font-size: 20px; margin-bottom: 8px; }
  .sub { color: #8b94a3; font-size: 13px; margin-bottom: 24px; }
  label { display: block; font-size: 13px; color: #a8b0bd; margin-bottom: 6px; }
  input[type=password] {
    width: 100%; padding: 11px 13px; background: #0f1115;
    border: 1px solid #2c3341; border-radius: 8px; color: #e6e8eb;
    font-size: 14px; outline: none; transition: border-color .15s;
  }
  input[type=password]:focus { border-color: #4b7bec; }
  button {
    width: 100%; margin-top: 16px; padding: 12px;
    background: #4b7bec; color: #fff; border: none; border-radius: 8px;
    font-size: 14px; font-weight: 500; cursor: pointer; transition: background .15s;
  }
  button:hover { background: #3d6ad4; }
  .err {
    background: #2d1a1e; border: 1px solid #5c2a33; color: #ff8a9b;
    padding: 10px 13px; border-radius: 8px; font-size: 13px; margin-bottom: 16px;
  }
</style>
</head>
<body>
<div class="card">
  <h1>🔐 Proxy Pipeline</h1>
  <p class="sub">订阅聚合管理面板</p>
  ${error ? `<div class="err">${escapeHtml(error)}</div>` : ""}
  <form method="POST" action="/login">
    <input type="hidden" name="next" value="${escapeHtml(next || "/")}">
    <label for="pw">访问密码</label>
    <input type="password" id="pw" name="password" autocomplete="current-password" autofocus required>
    <button type="submit">登录</button>
  </form>
</div>
</body>
</html>`;
}

export function dashboardPage(opts: {
  subs: Array<{
    token: string; name: string; sources: Array<{ url: string; label?: string; enabled: boolean; id: string }>;
    rename: boolean; min_tier: string; rules_mode: string;
    updated_at: string; hits: number;
  }>;
  defaultRules: string;
  origin: string;
}): string {
  const subsJson = JSON.stringify(opts.subs).replace(/</g, "\\u003c");
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Proxy Pipeline · 管理面板</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
    background: #0f1115; color: #e6e8eb; line-height: 1.55;
  }
  header {
    background: #171a21; border-bottom: 1px solid #262b36;
    padding: 16px 24px; display: flex; align-items: center; justify-content: space-between;
    position: sticky; top: 0; z-index: 10;
  }
  header h1 { font-size: 17px; font-weight: 600; }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 24px; }
  .card {
    background: #171a21; border: 1px solid #262b36; border-radius: 12px;
    padding: 20px; margin-bottom: 20px;
  }
  .card h2 { font-size: 15px; margin-bottom: 14px; display: flex; align-items: center; gap: 8px; }
  .btn {
    display: inline-flex; align-items: center; gap: 5px;
    padding: 7px 13px; border-radius: 7px; border: 1px solid #2c3341;
    background: #1e2229; color: #cfd5de; font-size: 13px; cursor: pointer;
    transition: all .15s; text-decoration: none;
  }
  .btn:hover { background: #262b36; border-color: #3a4250; }
  .btn.primary { background: #4b7bec; border-color: #4b7bec; color: #fff; }
  .btn.primary:hover { background: #3d6ad4; }
  .btn.danger { color: #ff8a9b; border-color: #4a2630; }
  .btn.danger:hover { background: #2d1a1e; }
  .btn.sm { padding: 4px 9px; font-size: 12px; }
  input[type=text], input[type=url], textarea, select {
    width: 100%; padding: 9px 11px; background: #0f1115;
    border: 1px solid #2c3341; border-radius: 7px; color: #e6e8eb;
    font-size: 13px; outline: none; font-family: inherit; transition: border-color .15s;
  }
  input:focus, textarea:focus, select:focus { border-color: #4b7bec; }
  textarea { resize: vertical; min-height: 90px; font-family: ui-monospace, "SF Mono", Consolas, monospace; font-size: 12px; }
  label { display: block; font-size: 12px; color: #a8b0bd; margin: 12px 0 5px; }
  label:first-child { margin-top: 0; }
  .row { display: flex; gap: 10px; align-items: flex-start; }
  .row > * { flex: 1; }
  .row > .fixed { flex: 0 0 auto; }
  .sub-item {
    border: 1px solid #262b36; border-radius: 10px; padding: 15px;
    margin-bottom: 14px; background: #14171d;
  }
  .sub-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
  .sub-title { font-weight: 600; font-size: 14px; }
  .src {
    display: flex; gap: 8px; align-items: center; padding: 7px 0;
    border-bottom: 1px solid #1e2229; font-size: 12px;
  }
  .src:last-child { border-bottom: none; }
  .src input[type=text] { flex: 1; padding: 6px 9px; font-size: 12px; }
  .src input[type=url] { flex: 2; padding: 6px 9px; font-size: 12px; }
  .link-box {
    display: flex; gap: 8px; align-items: center; margin-top: 10px;
    background: #0f1115; border: 1px solid #2c3341; border-radius: 8px; padding: 4px 4px 4px 12px;
  }
  .link-box input {
    border: none; background: transparent; padding: 6px 0;
    font-family: ui-monospace, monospace; font-size: 12px; color: #8fd3a0;
  }
  .muted { color: #6b7480; font-size: 12px; }
  .tag {
    display: inline-block; padding: 2px 7px; border-radius: 5px;
    font-size: 11px; background: #1e2229; color: #8b94a3; margin-left: 6px;
  }
  .tag.s { background: #1a2e1f; color: #6fcf8a; }
  .toast {
    position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%) translateY(80px);
    background: #1e2229; border: 1px solid #2c3341; padding: 11px 20px;
    border-radius: 9px; font-size: 13px; opacity: 0; transition: all .25s;
    pointer-events: none; z-index: 100;
  }
  .toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
  .toast.ok { border-color: #2d5c3a; color: #8fd3a0; }
  .toast.err { border-color: #5c2a33; color: #ff8a9b; }
  details summary { cursor: pointer; font-size: 13px; color: #a8b0bd; padding: 6px 0; }
  details[open] summary { margin-bottom: 10px; }
  @media (max-width: 640px) {
    .row { flex-direction: column; }
    .src { flex-wrap: wrap; }
    .wrap { padding: 14px; }
  }
</style>
</head>
<body>
<header>
  <h1>🚀 Proxy Pipeline</h1>
  <div>
    <button class="btn sm" onclick="showRules()">📝 规则</button>
    <button class="btn sm" onclick="logout()">退出</button>
  </div>
</header>

<div class="wrap">
  <div class="card">
    <h2>➕ 新建订阅</h2>
    <label>订阅名称</label>
    <input type="text" id="newName" placeholder="例如：我的订阅" value="">
    <label>订阅源（每行一个 URL，支持 Clash YAML / Base64 / 节点链接）</label>
    <textarea id="newSources" placeholder="https://example.com/sub1&#10;https://example.com/sub2"></textarea>
    <div class="row" style="margin-top:12px">
      <div>
        <label style="margin-top:0">节点重命名</label>
        <select id="newRename">
          <option value="1">启用（🇺🇸 US 01）</option>
          <option value="0">保持原名</option>
        </select>
      </div>
      <div>
        <label style="margin-top:0">质量过滤</label>
        <select id="newTier">
          <option value="all">全部</option>
          <option value="A">tier A 及以上</option>
          <option value="S">仅 tier S（优质）</option>
        </select>
      </div>
    </div>
    <button class="btn primary" style="margin-top:16px" onclick="createSub()">创建</button>
  </div>

  <div id="subs"></div>
</div>

<div class="toast" id="toast"></div>

<script>
const ORIGIN = ${JSON.stringify(opts.origin)};
let SUBS = ${subsJson};
const DEFAULT_RULES = ${JSON.stringify(opts.defaultRules)};

function toast(msg, ok = true) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show ' + (ok ? 'ok' : 'err');
  setTimeout(() => { t.className = 'toast'; }, 2200);
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
  });
  if (res.status === 401) { location.href = '/login'; throw new Error('unauthorized'); }
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
  return data;
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function render() {
  const box = document.getElementById('subs');
  if (!SUBS.length) {
    box.innerHTML = '<div class="card"><p class="muted">还没有订阅，用上面的表单创建一个。</p></div>';
    return;
  }
  box.innerHTML = SUBS.map(s => {
    const clashUrl = ORIGIN + '/sub/' + s.token + '.yaml';
    const b64Url = ORIGIN + '/sub/' + s.token + '.txt';
    return \`
    <div class="card sub-item">
      <div class="sub-head">
        <div>
          <span class="sub-title">\${esc(s.name || '未命名')}</span>
          \${s.min_tier === 'S' ? '<span class="tag s">仅优质</span>' : ''}
          <span class="tag">\${s.sources.filter(x => x.enabled).length} 个源</span>
          <span class="tag">\${s.hits || 0} 次访问</span>
        </div>
        <div style="display:flex;gap:6px">
          <button class="btn sm" onclick="testSub('\${s.token}')">测活</button>
          <button class="btn sm danger" onclick="delSub('\${s.token}')">删除</button>
        </div>
      </div>

      <label>Clash 订阅链接（可直接导入）</label>
      <div class="link-box">
        <input type="text" readonly value="\${esc(clashUrl)}" onclick="this.select()">
        <button class="btn sm primary" onclick="copyText('\${esc(clashUrl)}')">复制</button>
      </div>

      <label>Base64 订阅链接（v2rayN / 小火箭）</label>
      <div class="link-box">
        <input type="text" readonly value="\${esc(b64Url)}" onclick="this.select()">
        <button class="btn sm" onclick="copyText('\${esc(b64Url)}')">复制</button>
      </div>

      <details>
        <summary>编辑订阅源（\${s.sources.length}）</summary>
        <div id="srcs-\${s.token}">
          \${s.sources.map((src, i) => \`
            <div class="src">
              <input type="text" value="\${esc(src.label || '')}" placeholder="备注"
                     onchange="editSource('\${s.token}', \${i}, 'label', this.value)">
              <input type="url" value="\${esc(src.url)}" placeholder="https://..."
                     onchange="editSource('\${s.token}', \${i}, 'url', this.value)">
              <label style="margin:0;display:flex;align-items:center;gap:4px;white-space:nowrap">
                <input type="checkbox" \${src.enabled ? 'checked' : ''}
                       onchange="editSource('\${s.token}', \${i}, 'enabled', this.checked)"> 启用
              </label>
              <button class="btn sm danger" onclick="delSource('\${s.token}', \${i})">×</button>
            </div>\`).join('')}
        </div>
        <div style="margin-top:10px">
          <button class="btn sm" onclick="addSource('\${s.token}')">+ 添加源</button>
          <button class="btn sm" onclick="toggleRename('\${s.token}', \${s.rename ? 0 : 1})">
            \${s.rename ? '关闭重命名' : '启用重命名'}
          </button>
        </div>
      </details>
    </div>\`;
  }).join('');
}

async function reload() {
  const d = await api('/api/subs');
  SUBS = d.subs || [];
  render();
}

async function createSub() {
  const name = document.getElementById('newName').value.trim() || '我的订阅';
  const urls = document.getElementById('newSources').value
    .split('\\n').map(s => s.trim()).filter(Boolean);
  if (!urls.length) return toast('请至少填一个订阅源', false);
  try {
    const d = await api('/api/subs', {
      method: 'POST',
      body: JSON.stringify({
        name,
        sources: urls.map((u, i) => ({ url: u, label: '源' + (i + 1), enabled: true })),
        rename: document.getElementById('newRename').value === '1',
        min_tier: document.getElementById('newTier').value,
      }),
    });
    toast('创建成功');
    document.getElementById('newSources').value = '';
    document.getElementById('newName').value = '';
    await reload();
  } catch (e) { toast(e.message, false); }
}

async function delSub(token) {
  if (!confirm('确认删除这个订阅？')) return;
  try {
    await api('/api/subs/' + token, { method: 'DELETE' });
    toast('已删除'); await reload();
  } catch (e) { toast(e.message, false); }
}

async function addSource(token) {
  const url = prompt('订阅 URL：');
  if (!url) return;
  try {
    await api('/api/subs/' + token + '/sources', {
      method: 'POST',
      body: JSON.stringify({ url, label: '', enabled: true }),
    });
    toast('已添加'); await reload();
  } catch (e) { toast(e.message, false); }
}

async function delSource(token, idx) {
  try {
    await api('/api/subs/' + token + '/sources/' + idx, { method: 'DELETE' });
    toast('已删除'); await reload();
  } catch (e) { toast(e.message, false); }
}

async function editSource(token, idx, key, value) {
  try {
    await api('/api/subs/' + token + '/sources/' + idx, {
      method: 'PATCH',
      body: JSON.stringify({ [key]: value }),
    });
    toast('已保存');
  } catch (e) { toast(e.message, false); }
}

async function toggleRename(token, val) {
  try {
    await api('/api/subs/' + token, {
      method: 'PATCH',
      body: JSON.stringify({ rename: !!val }),
    });
    toast('已更新'); await reload();
  } catch (e) { toast(e.message, false); }
}

async function testSub(token) {
  toast('测试中…');
  try {
    const d = await api('/api/subs/' + token + '/test');
    const ok = (d.results || []).filter(r => r.ok).length;
    const total = (d.results || []).length;
    toast(\`\${ok}/\${total} 个源可用，共 \${d.nodes || 0} 个节点\`, ok > 0);
  } catch (e) { toast(e.message, false); }
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast('已复制到剪贴板');
  } catch {
    // 降级
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); document.body.removeChild(ta);
    toast('已复制');
  }
}

async function showRules() {
  try {
    const d = await api('/api/rules');
    const rules = prompt('编辑规则（YAML 片段，含 rules: 头）：', d.rules);
    if (rules === null) return;
    await api('/api/rules', { method: 'PUT', body: JSON.stringify({ rules }) });
    toast('规则已保存');
  } catch (e) { toast(e.message, false); }
}

async function logout() {
  await fetch('/logout', { method: 'POST' });
  location.href = '/login';
}

render();
</script>
</body>
</html>`;
}

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string));
}
