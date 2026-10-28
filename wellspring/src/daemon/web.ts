/// Wellspring Web UI + HTTP API, served by wellspringd on 127.0.0.1.
/// Pages: 凭据库 (vault), 审计流水 (audit), 用量统计 (stats).
/// API under /api/* uses the same ops as the unix socket. UI requires the admin
/// token (entered once, kept in sessionStorage, sent as Bearer).
import { createServer as httpCreate, IncomingMessage, ServerResponse } from "node:http";
import { handle } from "./main.ts";

export const HTTP_PORT = Number(process.env.WELLSPRING_HTTP_PORT ?? 7777);

const MAX_BODY_BYTES = 1024 * 1024;
const READ_OPS = new Set(["ping", "list", "describe", "view", "policy_get", "audit", "auth_check", "request_list"]);
const WRITE_OPS = new Set(["put", "put_source", "adopt", "delete", "policy_put", "resolve", "draw_env", "draw", "auth_issue_oneshot",
  // Derived operations need the admin token too: a signature oracle is still an oracle.
  "derive_totp", "derive_hmac", "derive_encrypt", "derive_decrypt", "request_fulfill", "request_cancel", "access_put"]);

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;
    const fail = (status: number, message: string) => {
      if (settled) return;
      settled = true;
      chunks.length = 0;
      reject(Object.assign(new Error(message), { status }));
    };
    req.on("error", () => fail(400, "request read failed"));
    req.on("aborted", () => fail(400, "request aborted"));
    req.on("close", () => { if (!req.complete) fail(400, "request closed before completion"); });
    req.on("data", (chunk) => {
      if (settled) return;
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += bytes.length;
      if (size > MAX_BODY_BYTES) { fail(413, "request body exceeds 1 MiB"); return; }
      chunks.push(bytes);
    });
    req.on("end", () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    const length = Number(req.headers["content-length"]);
    if (Number.isFinite(length) && length > MAX_BODY_BYTES) fail(413, "request body exceeds 1 MiB");
  });
}

function json(res: ServerResponse, code: number, data: any) {
  res.writeHead(code, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  res.end(JSON.stringify(data));
}

// A busy port must never take the daemon down: the UI is optional, the socket is not.
export function startHttp(preferred = HTTP_PORT) {
  const server = httpCreate(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;

    // ---- API ----
    if (path.startsWith("/api/")) {
      const op = path.slice("/api/".length);
      if (!READ_OPS.has(op) && !WRITE_OPS.has(op)) return json(res, 404, { error: "not found" });
      if (req.method !== "POST" && !(req.method === "GET" && READ_OPS.has(op))) {
        res.setHeader("allow", READ_OPS.has(op) ? "GET, POST" : "POST");
        return json(res, 405, { error: "method not allowed" });
      }
      // Credentials belong only in Authorization, never URLs or JSON payloads.
      const auth = (req.headers.authorization ?? "").replace(/^Bearer\s+/i, "");
      if (op !== "ping" && !handle({ op: "auth_check", token: auth }).ok) {
        return json(res, 401, { error: "unauthorized" });
      }
      let body: any = Object.create(null);
      if (req.method === "POST") {
        try {
          body = JSON.parse((await readBody(req)) || "{}");
          if (!body || typeof body !== "object" || Array.isArray(body)) return json(res, 400, { error: "expected JSON object" });
        } catch (e: any) {
          return json(res, e?.status ?? 400, { error: e?.status ? e.message : "bad json" });
        }
      } else {
        for (const [k, v] of url.searchParams) if (k !== "token") body[k] = v;
      }
      const msg: any = { ...body, op, token: auth };
      try {
        const result = handle(msg);
        return json(res, 200, result);
      } catch (e: any) {
        return json(res, 500, { error: String(e?.message ?? e) });
      }
    }

    // ---- favicon ----
    // Inlined so the console keeps its mark when served from a single daemon file.
    if (path === "/favicon.svg" || path === "/favicon.ico") {
      res.writeHead(200, { "content-type": "image/svg+xml; charset=utf-8", "cache-control": "public, max-age=86400" });
      return res.end(FAVICON);
    }

    // ---- UI ----
    if (path === "/" || path === "/index.html") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      return res.end(HTML);
    }
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("not found");
  });
  const announce = () => console.log(`wellspring web UI: http://127.0.0.1:${(server.address() as { port?: number })?.port}`);
  server.on("error", (err: NodeJS.ErrnoException) => {
    // Fall back to an ephemeral port only for the default: an explicitly requested
    // port must not silently move, because a human may have bookmarked it.
    if (err.code === "EADDRINUSE" && preferred === HTTP_PORT) return server.listen(0, "127.0.0.1", announce);
    console.error("web ui failed:", err.message);
  });
  server.listen(preferred, "127.0.0.1", announce);
  return server;
}

// Favicon: broken ring (the well mouth) + falling droplet. Colours match the UI accent.
const FAVICON = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="Wellspring">
<rect width="64" height="64" rx="14" fill="#0f1419"/>
<circle cx="32" cy="32" r="19" fill="none" stroke="#4fc3f7" stroke-width="5" stroke-linecap="round" stroke-dasharray="84 36" transform="rotate(-58 32 32)"/>
<path d="M32 16c5.5 7.4 9 12.4 9 16.6A9 9 0 0 1 23 32.6C23 28.4 26.5 23.4 32 16z" fill="#4fc3f7"/>
<circle cx="32" cy="33" r="3" fill="#0f1419"/>
</svg>
`;

const HTML = `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<title>Wellspring · 凭证井</title>
<style>
  :root { --bg:#0f1419; --card:#1a222c; --line:#2a3644; --fg:#e8eef4; --dim:#8fa3b3; --accent:#4fc3f7; --red:#ef5350; --orange:#ffa726; --green:#66bb6a; --violet:#b388ff; }
  * { box-sizing:border-box; margin:0; }
  body { background:var(--bg); color:var(--fg); font:14px/1.6 ui-sans-serif,system-ui,"PingFang SC","Microsoft YaHei",sans-serif; }
  header { display:flex; align-items:center; gap:14px; padding:14px 24px; border-bottom:1px solid var(--line); position:sticky; top:0; background:var(--bg); z-index:5; }
  header h1 { font-size:18px; font-weight:600; }
  header h1 span { color:var(--accent); }
  nav { display:flex; gap:6px; margin-left:auto; }
  nav button { background:none; border:1px solid var(--line); color:var(--dim); padding:6px 14px; border-radius:8px; cursor:pointer; font-size:13px; }
  nav button.active { color:var(--fg); border-color:var(--accent); }
  main { max-width:1100px; margin:0 auto; padding:24px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:18px; margin-bottom:16px; }
  .card h2 { font-size:15px; margin-bottom:12px; color:var(--accent); }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th { text-align:left; color:var(--dim); font-weight:500; padding:6px 10px; border-bottom:1px solid var(--line); }
  td { padding:6px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
  tr:hover td { background:rgba(79,195,247,.05); }
  .badge { display:inline-block; padding:1px 8px; border-radius:10px; font-size:11px; }
  .b-ok { background:rgba(102,187,106,.15); color:var(--green); }
  .b-denied { background:rgba(239,83,80,.15); color:var(--red); }
  .b-warn { background:rgba(255,167,38,.15); color:var(--orange); }
  .b-expired { background:rgba(179,136,255,.16); color:var(--violet); }
  .b-cred { background:rgba(79,195,247,.12); color:var(--accent); }
  .b-pii { background:rgba(255,167,38,.12); color:var(--orange); }
  .mono { font-family:ui-monospace,Menlo,monospace; font-size:12px; color:var(--dim); }
  button { background:var(--card); color:var(--fg); border:1px solid var(--line); padding:7px 12px; border-radius:8px; cursor:pointer; }
  button:hover { border-color:var(--accent); }
  button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
  .danger { color:var(--red); }
  .notice { padding:10px; color:var(--green); min-height:40px; }
  .table-wrap { overflow-x:auto; }
  @media(max-width:640px) { header { flex-wrap:wrap; padding:12px; } nav { flex-wrap:wrap; margin:0; } main { padding:12px; } .kv { grid-template-columns:1fr; } }
  input,select,textarea { background:var(--bg); border:1px solid var(--line); color:var(--fg); padding:6px 10px; border-radius:8px; font-size:13px; }
  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-bottom:12px; }
  #login { max-width:420px; margin:80px auto; text-align:center; }
  #login .hint { color:var(--dim); font-size:12px; margin-top:10px; }
  .card .hint { color:var(--dim); font-size:12px; margin:2px 0 12px; }
  .bar { height:8px; border-radius:4px; background:var(--line); overflow:hidden; margin-top:4px; }
  .bar > div { height:100%; background:var(--accent); }
  .kv { display:grid; grid-template-columns:auto 1fr; gap:4px 16px; font-size:13px; }
  .kv b { color:var(--dim); font-weight:500; }
  .empty { color:var(--dim); text-align:center; padding:30px; }
  .stats-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:12px; }
  .stat { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px; }
  .stat .num { font-size:26px; font-weight:600; }
  .stat .lbl { color:var(--dim); font-size:12px; }
  .usage-panel pre { white-space:pre-wrap; overflow-wrap:anywhere; margin:8px 0; padding:10px; background:var(--bg); }
  .usage-panel p { color:var(--dim); }
  .usage-panel button { margin-bottom:12px; }
  textarea { width:100%; resize:vertical; }
  .request-choice { display:block; margin:10px 0; }
  .request-actions { margin-top:16px; }
  button:disabled { opacity:.5; cursor:default; }
</style>
</head>
<body>
<div id="login" class="card" style="display:none">
  <h2>💧 Wellspring 管理台</h2>
  <p style="color:var(--dim);font-size:13px">需要 admin token 才能进入</p>
  <div class="row" style="justify-content:center;margin-top:16px">
    <input id="tok-in" type="password" placeholder="粘贴 admin token" style="width:240px" />
    <button onclick="login()" style="padding:6px 18px;border-radius:8px;border:1px solid var(--accent);background:var(--accent);color:#08121a;cursor:pointer">进入</button>
  </div>
  <p class="hint">token 在 ~/.wellspring/admin.token（仅本用户可读）。可执行 cat 查看后粘贴。</p>
</div>
<header id="appbar" style="display:none">
  <h1><img src="/favicon.svg" alt="" width="22" height="22" style="vertical-align:-4px;margin-right:8px">Wellspring <span>· 凭证井</span></h1>
  <nav>
    <button id="tab-vault" onclick="show('vault')">凭据库</button>
    <button id="tab-requests" onclick="show('requests')">待填写</button>
    <button id="tab-audit" onclick="show('audit')">使用记录</button>
    <button id="tab-stats" onclick="show('stats')">概览</button>
    <button id="tab-policy" onclick="show('policy')">设置</button>
    <button onclick="logout()">退出</button>
  </nav>
</header>
<main id="app" style="display:none"></main>
<script>
const requestedId = new URLSearchParams(location.search).get('request');
const S = { token: sessionStorage.wst ?? "", authenticated:false, tab: requestedId ? "requests" : "vault", entries: [], events: [], policy: {}, requests:[], requestId:requestedId, requestBusy:false, requestLoading:false };
let requestTimer;

async function api(op, body = {}) {
  const r = await fetch("/api/" + op, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer " + S.token },
    body: JSON.stringify(body),
  });
  const result = await r.json();
  if (r.status === 401) {
    S.authenticated = false; clearInterval(requestTimer); S.token = ''; sessionStorage.removeItem('wst');
    document.getElementById('app').innerHTML = ''; document.getElementById('app').style.display = 'none';
    document.getElementById('appbar').style.display = 'none'; document.getElementById('login').style.display = 'block';
    throw new Error('登录已失效，请重新登录');
  }
  if (!r.ok || result.error) throw new Error(result.error || '请求失败');
  return result;
}
function notify(message, failed = false) {
  let el = document.getElementById('notice');
  if (!el) { el = document.createElement('div'); el.id='notice'; el.className='notice'; el.setAttribute('role','status'); document.body.appendChild(el); }
  el.textContent = message; el.style.color = failed ? 'var(--red)' : 'var(--green)';
}
window.addEventListener('unhandledrejection', e => { e.preventDefault(); notify(e.reason?.message ?? '没有完成，原因未知', true); });

function login() {
  S.token = document.getElementById("tok-in").value.trim();
  api("auth_check").then((r) => {
    if (r.ok) { sessionStorage.wst = S.token; enter(); }
    else notify("token 不对", true);
  }).catch(() => notify('连不上本地服务，确认 wellspringd 还在运行', true));
}
function logout() { sessionStorage.removeItem("wst"); location.reload(); }
function enter() {
  S.authenticated = true; document.getElementById('tok-in').value = '';
  clearInterval(requestTimer);
  requestTimer = setInterval(() => { if (S.authenticated) refreshRequests().catch(() => {}); }, 5000);
  refreshRequests().catch(() => {});
  document.getElementById("login").style.display = "none";
  document.getElementById("appbar").style.display = "flex";
  document.getElementById("app").style.display = "block";
  show(S.tab);
}

function show(tab) {
  S.tab = tab;
  for (const t of ["vault", "requests", "audit", "stats", "policy"]) document.getElementById("tab-" + t).classList.toggle("active", t === tab);
  if (tab === "vault") renderVault();
  if (tab === "requests") renderRequests();
  if (tab === "audit") renderAudit();
  if (tab === "stats") renderStats();
  if (tab === "policy") renderPolicy();
}

function esc(s) { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }
function fmtTs(ts) { return new Date(ts).toLocaleString("zh-CN", { hour12: false }); }
function verdictBadge(v) {
  if (v === "ok") return '<span class="badge b-ok">成功</span>';
  if (v === "denied_auth") return '<span class="badge b-denied">没带 token</span>';
  if (v === "denied_reason") return '<span class="badge b-warn">原因不允许</span>';
  if (v === "denied_rate") return '<span class="badge b-warn">太快了</span>';
  if (v === "expired") return '<span class="badge b-expired">已过期</span>';
  return '<span class="badge b-denied">' + esc(v) + "</span>";
}
function fmtDuration(ms) {
  if (ms <= 0) return "已过期";
  const s = Math.floor(ms / 1000);
  if (s < 60) return s + " 秒后过期";
  const m = Math.floor(s / 60), h = Math.floor(m / 60), d = Math.floor(h / 24);
  if (d > 0) return d + " 天后过期";
  if (h > 0) return h + " 小时后过期";
  return m + " 分钟后过期";
}
// Remaining lifetime badge; empty when the credential never expires. No plaintext involved.
function expiryBadge(f) {
  if (typeof f?.expiresAt !== "number") return "";
  const left = f.expiresAt - Date.now();
  // Right-aligned inside the cell so the countdown line doesn't jump as digits change.
  return '<span class="badge ' + (left <= 0 ? "b-expired" : "b-warn") + '" title="' + esc(fmtTs(f.expiresAt)) + '">' +
    esc(fmtDuration(left)) + "</span>";
}

// ---------- independent human input requests ----------
function requestStatus(r) {
  return r.status === 'pending' && new Date(r.expiresAt).getTime() <= Date.now() ? 'expired' : r.status;
}
function requestStatusLabel(status) {
  return ({pending:'待填写', fulfilled:'已填写', cancelled:'已取消', expired:'已过期'})[status] || '状态未知';
}
async function refreshRequests() {
  if (!S.authenticated || S.requestLoading) return;
  S.requestLoading = true;
  try {
    const r = await api('request_list');
    if (!S.authenticated) return;
    S.requests = r.requests ?? [];
    const count = S.requests.filter(r => requestStatus(r) === 'pending').length;
    document.getElementById('tab-requests').textContent = '待填写' + (count ? ' (' + count + ')' : '');
    if (S.tab === 'requests') drawRequests();
  } finally { S.requestLoading = false; }
}
function renderRequests() {
  document.getElementById('app').innerHTML = '<div class="card"><h2>待填写</h2><p class="hint">在此页面直接向本地凭据服务填写，内容不会进入模型对话。默认仅供本次任务使用。</p><div id="request-list"></div></div><div id="request-detail"></div>';
  drawRequests();
  refreshRequests().catch(() => notify('刷新请求失败，请稍后重试', true));
}
function drawRequests() {
  const list = document.getElementById('request-list');
  const detail = document.getElementById('request-detail');
  if (!list || !detail) return;
  list.replaceChildren();
  const ordered = [...S.requests].sort((a,b) => Number(requestStatus(b) === 'pending') - Number(requestStatus(a) === 'pending'));
  for (const r of ordered) {
    const button = document.createElement('button');
    button.textContent = (r.label || r.requestId) + ' · ' + requestStatusLabel(requestStatus(r));
    button.style.margin = '4px'; button.disabled = S.requestBusy;
    button.onclick = () => {
      if (S.requestId !== r.requestId) { S.requestId = r.requestId; detail.replaceChildren(); delete detail.dataset.requestId; delete detail.dataset.status; }
      const url = new URL(location.href); url.searchParams.set('request', r.requestId); history.replaceState(null, '', url);
      drawRequests();
    };
    list.appendChild(button);
  }
  if (!ordered.length) list.textContent = '暂无填写请求。';
  const r = S.requests.find(r => r.requestId === S.requestId);
  if (!r) {
    detail.textContent = S.requestId ? '未找到此请求，可能已清理。请检查链接或选择其他请求。' : '选择一个请求查看详情并填写。';
    return;
  }
  const status = requestStatus(r);
  // Leave the live form intact during polling. Never keep secret drafts in state/storage.
  if (detail.dataset.requestId === r.requestId && detail.dataset.status === status) return;
  detail.dataset.requestId = r.requestId; detail.dataset.status = status;
  detail.innerHTML = '<div class="card"><h2>' + esc(r.label || '填写凭据') + '</h2><div class="kv">' +
    '<b>用途</b><span>' + esc(r.purpose) + '</span><b>目标</b><span>' + esc(r.target || '未声明') + '</span>' +
    '<b>调用方</b><span>' + esc(r.caller) + '</span><b>通道</b><span>' + esc(r.channel) + '</span>' +
    '<b>到期时间</b><span>' + esc(fmtTs(r.expiresAt)) + '</span><b>状态</b><span>' + esc(requestStatusLabel(status)) + '</span></div>' +
    '<p class="hint">用途和目标由调用方声明，并不代表已验证实际使用目的或网络目的地。</p>' +
    (status === 'pending' ? '<form id="request-form"><label for="request-value">请填写 ' + esc(r.label || '凭据值') + '</label>' +
      '<input id="request-value" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" style="display:block;width:100%" required>' +
      '<p class="hint">提交后，正在等这个请求的 agent 会立刻拿到引用，不用再问一遍。</p>' +
      '<label class="request-choice"><input id="request-visible" type="checkbox"> 显示输入内容（支持多行）</label>' +
      '<label class="request-choice"><input type="radio" name="request-save" value="once" checked> 仅本次任务</label>' +
      '<label class="request-choice"><input type="radio" name="request-save" value="save"> 保存供以后使用</label>' +
      '<div id="request-save-options" hidden><label for="request-name">保存名称（可选）</label><input id="request-name" placeholder="例如 github_token"><label for="request-field">字段名（可选）</label><input id="request-field" placeholder="默认 value"></div>' +
      '<div class="row request-actions"><button type="submit">提交凭据</button><button type="button" id="request-cancel" class="danger">取消请求</button></div></form>' :
      '<p>' + esc(status === 'expired' ? '请求已过期，请调用方重新发起。' : status === 'cancelled' ? '请求已取消。' : '已完成填写，输入内容已清空。') + '</p>' +
      (r.ref ? '<p class="mono">' + esc(r.ref) + '</p>' : '')) + '</div>';
  if (status !== 'pending') return;
  const form = document.getElementById('request-form');
  form.onsubmit = e => { e.preventDefault(); fulfillRequest(r.requestId); };
  document.getElementById('request-visible').onchange = e => {
    const input = document.getElementById('request-value');
    // A native password control protects the default value from accessibility
    // snapshots as well as screen display. Multiline entry requires explicit reveal.
    const next = document.createElement(e.target.checked ? 'textarea' : 'input');
    if (!e.target.checked) next.type = 'password'; else next.rows = 4;
    if (!e.target.checked && /[\\r\\n]/.test(input.value)) {
      notify('多行内容保持显示直至提交，以免隐藏时丢失换行'); e.target.checked = true; return;
    }
    next.id = input.id; next.value = input.value; next.required = true; next.autocomplete = 'off'; next.spellcheck = false;
    next.style.cssText = 'display:block;width:100%'; input.value = ''; input.replaceWith(next); next.focus();
  };
  form.querySelectorAll('[name="request-save"]').forEach(input => input.onchange = () => {
    document.getElementById('request-save-options').hidden = form.querySelector('[name="request-save"]:checked').value !== 'save';
  });
  document.getElementById('request-cancel').onclick = () => cancelRequest(r.requestId);
}
function requestBusy(busy) {
  S.requestBusy = busy;
  document.querySelectorAll('#request-form button,#request-list button').forEach(b => b.disabled = busy);
}
async function fulfillRequest(requestId) {
  if (S.requestBusy) return;
  const input = document.getElementById('request-value');
  if (!input || !input.value) { notify('请填写凭据值', true); return; }
  const save = document.querySelector('[name="request-save"]:checked').value === 'save';
  const body = {requestId, value:input.value, save};
  if (save) {
    const name = document.getElementById('request-name').value.trim();
    const field = document.getElementById('request-field').value.trim();
    body.id = name ? normalizeId(name, 'credential') : 'cred:request_' + requestId;
    if (field) body.field = field;
  }
  requestBusy(true);
  try {
    const result = await api('request_fulfill', body);
    if (result.status !== 'fulfilled') throw new Error('request not fulfilled');
    input.value = ''; body.value = '';
    const r = S.requests.find(r => r.requestId === requestId);
    if (r) { r.status = 'fulfilled'; r.ref = result.ref; }
    notify(save ? '已提交并保存供以后使用' : '已提交，仅本次任务可用');
    drawRequests(); await refreshRequests();
  } catch {
    // Do not surface server diagnostics that could accidentally include input values.
    notify('提交未完成，请检查请求状态后重试', true); await refreshRequests().catch(() => {});
  } finally { body.value = ''; requestBusy(false); }
}
async function cancelRequest(requestId) {
  if (S.requestBusy) return;
  requestBusy(true);
  try {
    const result = await api('request_cancel', {requestId});
    if (result.status !== 'cancelled') throw new Error('request not cancelled');
    const input = document.getElementById('request-value'); if (input) input.value = '';
    const r = S.requests.find(r => r.requestId === requestId); if (r) r.status = 'cancelled';
    notify('已取消请求'); drawRequests(); await refreshRequests();
  } catch { notify('取消未完成，请刷新请求状态后重试', true); }
  finally { requestBusy(false); }
}

// ---------- field use constraints ----------
function showAccess(index, fieldIndex) {
  document.getElementById('access-form')?.remove();
  const entry = S.entries[index], field = entry.fields[fieldIndex];
  const box = document.createElement('form'); box.id = 'access-form'; box.className = 'card';
  box.innerHTML = '<h2>使用范围 · ' + esc(entry.id + '/' + field.name) + '</h2><p class="hint">每行一项，填写准确名称；留空表示该项不限制。多个项目按列表匹配，不同范围同时生效。用途和目标是调用方声明的意图，不代表已经验证实际用途或网络目的地。</p>' +
    '<div class="kv">' + [['callers','允许的调用方'],['channels','允许的通道'],['purposes','允许的用途'],['targets','允许的目标']].map(([key,label]) => '<label for="access-' + key + '">' + label + '</label><textarea id="access-' + key + '" rows="3" spellcheck="false"></textarea>').join('') +
    '</div><div class="row request-actions"><button type="submit">保存使用范围</button><button type="button" id="access-close">取消</button></div>';
  document.getElementById('app').prepend(box);
  for (const key of ['callers','channels','purposes','targets']) document.getElementById('access-' + key).value = (field.usePolicy?.[key] ?? []).join('\\n');
  document.getElementById('access-close').onclick = () => box.remove();
  box.onsubmit = async e => {
    e.preventDefault();
    const usePolicy = {};
    for (const key of ['callers','channels','purposes','targets']) {
      const values = [...new Set(document.getElementById('access-' + key).value.split('\\n').map(s => s.trim()).filter(Boolean))];
      if (values.length) usePolicy[key] = values;
    }
    const submit = box.querySelector('[type="submit"]'); submit.disabled = true;
    try {
      await api('access_put', {id:entry.id, field:field.name, usePolicy});
      field.usePolicy = usePolicy; box.remove(); notify('已保存字段使用范围');
    } catch { notify('保存未完成，请检查范围内容后重试', true); }
    finally { submit.disabled = false; }
  };
  box.scrollIntoView({behavior:'smooth',block:'start'});
}

// ---------- vault ----------
async function renderVault() {
  const app = document.getElementById("app");
  app.innerHTML = '<div class="card"><div class="row"><input id="q" placeholder="按名称或字段过滤" style="flex:1" oninput="drawVault()"><button onclick="showAdd()">＋ 新增凭据</button></div><div id="vault-tbl"></div></div>';
  const r = await api("list");
  S.entries = (r.descriptors ?? []).map(e => ({ ...e, id: e.ref.slice('secret://'.length) }));
  drawVault();
}
function drawVault() {
  const q = (document.getElementById("q")?.value ?? "").toLowerCase();
  const rows = S.entries.filter((e) => !q || e.id.toLowerCase().includes(q) || e.fields.some((f) => f.name.includes(q)));
  const el = document.getElementById("vault-tbl");
  if (!rows.length) { el.innerHTML = '<div class="empty">这里还是空的。点「＋ 新增凭据」，填名称和值就行。</div>'; return; }
  el.innerHTML = "<table><tr><th>条目</th><th>字段</th><th>类型</th><th>指纹</th><th>保护状态</th><th>有效期</th><th>标签</th><th>操作</th></tr>" +
    rows.map((e) => {
      const cls = e.id.startsWith("person:") ? "b-pii" : "b-cred";
      return e.fields.map((f, i) =>
        "<tr>" +
        (i === 0 ? '<td rowspan="' + e.fields.length + '"><span class="badge ' + cls + '">' + esc(e.id) + "</span></td>" : "") +
        "<td>" + esc(f.name) + "</td><td>" + esc(f.class ?? "credential") + "</td>" +
        '<td class="mono">' + esc(f.fingerprint ?? "") + "</td>" +
        '<td class="mono">' + (f.source
          ? '<span class="badge" title="每次取用时从宿主机现读，本工具不保存它的值">' + esc(f.source) + "</span>"
          : esc(e.maskedPreview?.[f.name] ?? "****")) + "</td>" +
        "<td>" + expiryBadge(f) + "</td>" +
        (i === 0 ? '<td rowspan="' + e.fields.length + '">' + (e.tags ?? []).map(esc).join(", ") + "</td>" : "") +
        '<td><button class="usage-field" data-entry="' + S.entries.indexOf(e) + '" data-field="' + i + '" aria-expanded="false">使用</button> <button class="access-field" data-entry="' + S.entries.indexOf(e) + '" data-field="' + i + '">使用范围</button> <button class="edit-field" data-entry="' + S.entries.indexOf(e) + '" data-field="' + i + '">轮换</button> <button class="danger delete-field" data-entry="' + S.entries.indexOf(e) + '" data-field="' + i + '">删除字段</button>' + (i === 0 ? ' <button class="danger delete-entry" data-entry="' + S.entries.indexOf(e) + '">删除条目</button>' : '') + '</td></tr>'
      ).join("");
    }).join("") + "</table>";
  el.className = 'table-wrap';
  el.querySelectorAll('.usage-field').forEach(b => b.onclick = () => showUsage(b));
  el.querySelectorAll('.access-field').forEach(b => b.onclick = () => showAccess(Number(b.dataset.entry), Number(b.dataset.field)));
  el.querySelectorAll('.edit-field').forEach(b => b.onclick = () => showAdd(Number(b.dataset.entry), Number(b.dataset.field)));
  el.querySelectorAll('.delete-field,.delete-entry').forEach(b => b.onclick = () => deleteEntry(Number(b.dataset.entry), b.classList.contains('delete-field') ? Number(b.dataset.field) : undefined));
}
function showUsage(button) {
  const previous = document.getElementById('usage-panel');
  const close = button.getAttribute('aria-expanded') === 'true';
  document.querySelectorAll('.usage-field').forEach(b => b.setAttribute('aria-expanded', 'false'));
  previous?.remove();
  if (close) return;
  const entry = S.entries[Number(button.dataset.entry)];
  const field = entry.fields[Number(button.dataset.field)];
  const ref = 'secret://' + entry.id + '/' + field.name;
  // POSIX quoting keeps even punctuation in user-supplied refs literal.
  const quote = value => "'" + value.split("'").join("'" + String.fromCharCode(92) + "''") + "'";
  const examples = [
    ['引用地址', ref],
    ['命令行 · 放进环境变量', 'wellspring exec --secret ' + quote('APP_SECRET=' + ref) + " -- '<program>' '<arg>'"],
    ['命令行 · 从文件描述符读', 'wellspring exec --secret-fd ' + quote('APP_SECRET=' + ref) + " -- '<program>' '<arg>'"],
    ['命令行 · 写进临时文件', 'wellspring exec --secret-file ' + quote('APP_SECRET_FILE=' + ref) + " -- '<program>' '<arg>'"],
    ['命令行 · git 凭据', 'wellspring exec --git-cred ' + quote(ref) + " -- git ls-remote 'https://<host>/<repo>.git'"],
    ['配置文件模板', '{"secret": {{' + ref + ' | json}}}'],
    ['命令行 · 用模板渲染配置文件', "wellspring exec --template-file 'APP_CONFIG=<template-path>' -- '<program>' '<arg>'"],
    ['MCP · 模板渲染配置', JSON.stringify({name:'wellspring_exec',arguments:{templates:{APP_CONFIG:'{"secret": {{' + ref + ' | json}}}'},command:['<program>','<arg>'],output:'none'}},null,2)],
    ['MCP · 注入环境变量', JSON.stringify({name:'wellspring_exec',arguments:{env:{APP_SECRET:ref},command:['<program>','<arg>'],output:'none'}}, null, 2)],
    ['MCP · 验证码（字段填 base32 种子）', JSON.stringify({name:'wellspring_derive',arguments:{op:'totp',ref}}, null, 2)],
    ['MCP · 签名（字段填 HMAC 密钥）', JSON.stringify({name:'wellspring_derive',arguments:{op:'hmac',ref,data:'<待签名内容>',alg:'sha256'}}, null, 2)],
    ['MCP · 加密（字段填 base64 的 32 字节密钥）', JSON.stringify({name:'wellspring_derive',arguments:{op:'encrypt',ref,plaintext:'<明文>'}}, null, 2)],
    ['MCP · 等用户填写（最多 55 秒）', JSON.stringify({name:'wellspring_request_status',arguments:{requestId:'req_xxx',waitMs:55000}}, null, 2)],
  ];
  const row = document.createElement('tr'); row.id = 'usage-panel';
  const cell = document.createElement('td'); cell.colSpan = 8; cell.className = 'usage-panel';
  const heading = document.createElement('h3'); heading.textContent = '怎么用 ' + entry.id + '/' + field.name; cell.appendChild(heading);
  const note = document.createElement('p');
  note.textContent = '上面都只是引用地址，不会读出明文。把 <program> 换成你自己的程序，注意别让它把密钥打印出来。文件描述符用 WELLSPRING_FD_APP_SECRET 取号；APP_SECRET_FILE 指向一个退出时自动删除的临时文件。MCP 示例默认不返回程序输出。等填写用 waitMs，最长 55 秒，超时会返回待处理。备份导出导入在命令行做：wellspring export / import，需要先停掉守护进程。';
  cell.appendChild(note);
  for (const [label, text] of examples) {
    const title = document.createElement('h4'); title.textContent = label;
    const pre = document.createElement('pre'); pre.textContent = text;
    const copy = document.createElement('button'); copy.textContent = '复制';
    copy.onclick = async () => {
      try { await navigator.clipboard.writeText(text); notify('已复制'); }
      catch { const selection = window.getSelection(); const range = document.createRange(); range.selectNodeContents(pre); selection.removeAllRanges(); selection.addRange(range); notify('浏览器不让直接复制，已帮你选中，按 Cmd+C', true); }
    };
    cell.append(title, pre, copy);
  }
  row.appendChild(cell); button.closest('tr').after(row); button.setAttribute('aria-expanded', 'true');
}
async function deleteEntry(index, fieldIndex) {
  const entry = S.entries[index]; const field = fieldIndex === undefined ? undefined : entry.fields[fieldIndex].name;
  if (!confirm('删除 ' + entry.id + (field ? '/' + field : ' 的全部字段') + '？删了就找不回来了。')) return;
  await api('delete', {id:entry.id, field});
  notify('已删除'); await renderVault();}
// Sensible defaults per common secret kind: one click instead of six fields.
// mask "none" is right for machine credentials (a mask there would be noise) and
// "phone"/"keep1" is right for personal data.
const QUICK_KINDS = [
  { label: "API Key", id: "cred:api_key" },
  { label: "数据库密码", id: "cred:db_prod", field: "password" },
  { label: "GitHub Token", id: "cred:github_pat" },
  { label: "SSH 私钥", id: "cred:ssh_key", mask: "none" },
  { label: "签名密钥", id: "cred:sign_key", field: "key" },
  { label: "手机号", id: "person:contact", field: "phone", cls: "pii", mask: "phone" },
];
// Rotation has to know which entry and field it is rewriting; creation does not.
function showAdd(index, fieldIndex) {
  document.getElementById('add-form')?.remove();
  const entry = index === undefined ? undefined : S.entries[index];
  const field = entry?.fields[fieldIndex];
  const app = document.getElementById("app");
  // Two steps only when creating: name + value. Everything else is a default that
  // can be changed under 高级选项. Rotation keeps the stricter checked fields.
  app.insertAdjacentHTML("afterbegin",
    entry
      ? '<div class="card" id="add-form"><h2>轮换字段</h2><p class="hint">旧值不会被读取，直接用新值覆盖。</p>' +
        '<div class="kv"><b>条目</b><span class="mono">' + esc(entry.id) + '</span>' +
        '<b>字段名</b><span class="mono">' + esc(field.name) + '</span>' +
        '<b>新值</b><input id="f-val" type="password" placeholder="新的值" autocomplete="new-password">' +
        '<b>类型</b><select id="f-cls"><option value="credential">凭据</option><option value="pii">个人信息</option><option value="pii_high">高敏感个人信息</option></select>' +
        '<b>脱敏</b><select id="f-mask"><option value="keep1">keep1 (****)</option><option value="phone">phone</option><option value="region">region</option><option value="none">none</option></select>' +
        '<b></b><span id="f-mask-note"></span>' +
        '<b>有效期</b><select id="f-ttl"><option value="">保持当前</option><option value="3600000">1 小时</option><option value="86400000">1 天</option><option value="604800000">7 天</option><option value="2592000000">30 天</option></select>' +
        '<b></b><span id="f-ttl-note"></span></div>' +
        '<div class="row" style="margin-top:12px"><button onclick="addPut()">存新值</button><button onclick="document.getElementById(\\'add-form\\').remove()">取消</button></div></div>'
      : '<div class="card" id="add-form"><h2>新增凭据</h2><p class="hint">填个名字、粘贴值，保存。</p>' +
        '<div class="row" id="quick-kinds"></div>' +
        '<div class="kv"><b>名称</b><input id="f-id" placeholder="例如 github_token" autocapitalize="off" autocorrect="off">' +
        '<b>值</b><input id="f-val" type="password" placeholder="密钥、密码或私钥" autocomplete="new-password">' +
        '<b>或来源</b><input id="f-src" placeholder="env:NAME 或 dotenv:/绝对路径#KEY" autocapitalize="off" autocorrect="off" spellcheck="false">' +
        '<b></b><span class="hint" style="margin:0">填了来源就不存值，每次取用时现读。可选 env:NAME、dotenv:/路径#KEY、file:/路径、keychain:服务名、command:命令。</span></div>' +
        '<div id="f-adv-wrap"><button id="f-adv-toggle" type="button" style="margin-top:12px">高级选项</button>' +
        '<div id="f-adv" class="kv" style="display:none;margin-top:12px">' +
        '<b>字段名</b><input id="f-field" placeholder="默认 value">' +
        '<b>类型</b><select id="f-cls"><option value="credential">凭据</option><option value="pii">个人信息</option><option value="pii_high">高敏感个人信息</option></select>' +
        '<b>脱敏</b><select id="f-mask"><option value="keep1">keep1 (****)</option><option value="phone">phone</option><option value="region">region</option><option value="none">none</option></select>' +
        '<b>有效期</b><select id="f-ttl"><option value="">不过期</option><option value="3600000">1 小时</option><option value="86400000">1 天</option><option value="604800000">7 天</option><option value="2592000000">30 天</option></select>' +
        '<b>标签</b><input id="f-tags" placeholder="逗号分隔，例如 production,github">' +
        '</div></div>' +
        '<div class="row" style="margin-top:12px"><button onclick="addPut()">保存</button><button onclick="document.getElementById(\\'add-form\\').remove()">取消</button></div></div>');
  if (!entry) document.getElementById('quick-kinds').innerHTML = QUICK_KINDS.map((k, i) =>
    '<button type="button" class="quick" data-i="' + i + '">' + esc(k.label) + '</button>').join("");
  if (!entry) document.querySelectorAll('#add-form .quick').forEach(b => b.onclick = () => applyQuick(Number(b.dataset.i)));
  if (!entry) document.getElementById('f-adv-toggle').onclick = () => {
    const box = document.getElementById('f-adv');
    const open = box.style.display !== 'none';
    box.style.display = open ? 'none' : 'grid';
    document.getElementById('f-adv-toggle').textContent = open ? '高级选项' : '收起高级选项';
  };
  if (entry) {
    const form = document.getElementById('add-form');
    form.dataset.edit = '1';
    form.dataset.entry = String(index);
    form.dataset.field = field.name;
    // Tags are entry-wide and never edited during a field rotation.
    form.dataset.tags = JSON.stringify(entry.tags ?? []);
    document.getElementById('f-cls').value = field.class;
    const select = document.getElementById('f-mask');
    if (typeof field.mask === 'string') {
      if (!Array.from(select.options).some(o => o.value === field.mask)) select.add(new Option(field.mask, field.mask));
      select.value = field.mask;
      document.getElementById('f-mask-note').textContent = '已保留原脱敏方式。';
    } else {
      select.add(new Option('请选择脱敏方式', ''), 0); select.value = '';
      document.getElementById('f-mask-note').textContent = '请明确选择轮换后的脱敏方式。';
    }
    // Rotation must not silently wipe an existing expiry: keep the current window
    // unless the operator picks a new duration.
    const ttlNote = document.getElementById('f-ttl-note');
    const ttlSelect = document.getElementById('f-ttl');
    if (typeof field.expiresAt === 'number') {
      const current = field.expiresAt > Date.now() ? 'keep' : 'choose';
      ttlSelect.add(new Option(current === 'keep' ? '保持当前（' + fmtDuration(field.expiresAt - Date.now()) + '）' : '已过期，请选择新的有效期', current), 0);
      ttlSelect.value = current;
      ttlSelect.dataset.expiresAt = String(field.expiresAt);
      ttlNote.textContent = '当前到期时间：' + fmtTs(field.expiresAt) + '。选择具体时长则从现在重新计时。';
    } else {
      ttlNote.textContent = '该字段当前无有效期。不选择则轮换后仍为永久有效。';
    }
  }
  document.getElementById('f-val').focus();
}
function normalizeId(raw, cls) {
  const name = String(raw ?? "").trim();
  if (!name) return "";
  const prefix = cls === "pii" || cls === "pii_high" ? "person:" : "cred:";
  const typed = /^(cred|person):/i.test(name) ? name : prefix + name;
  // Separators a human would type are not allowed in refs; normalize instead of rejecting.
  return typed.replace(/\./g, "_").replace(/\s+/g, "_");
}
// Pre-fills the form from a quick kind: name, field, class, mask, and its own tags.
function applyQuick(i) {
  const k = QUICK_KINDS[i];
  document.getElementById('f-id').value = k.id;
  document.getElementById('f-field').value = k.field ?? 'value';
  document.getElementById('f-cls').value = k.cls ?? 'credential';
  document.getElementById('f-mask').value = k.mask ?? 'keep1';
  document.getElementById('f-val').focus();
}
async function addPut() {
  const form = document.getElementById('add-form');
  const editing = form.dataset.edit === '1';
  const entry = editing ? S.entries[Number(form.dataset.entry)] : undefined;
  const value = document.getElementById("f-val").value;
  const source = (document.getElementById("f-src").value || '').trim();
  if (!value && !source) { notify('填一个值，或者填一个来源', true); return; }
  if (value && source) { notify('值和来源只能选一个', true); return; }
  const body = {
    // A bare name is prefixed so nobody has to learn the ref syntax up front.
    id: editing ? entry.id : normalizeId(document.getElementById("f-id").value, document.getElementById('f-cls').value),
    field: editing ? form.dataset.field : (document.getElementById("f-field").value || "value"),
    value, cls: document.getElementById("f-cls").value || undefined,
    mask: document.getElementById("f-mask").value,
    tags: form.dataset.tags !== undefined
      ? JSON.parse(form.dataset.tags)
      : document.getElementById('f-tags').value.split(',').map(s => s.trim()).filter(Boolean),
  };
  if (!body.id) { notify('请填写名称', true); return; }
  const ttlSelect = document.getElementById('f-ttl');
  const ttl = ttlSelect.value;
  if (ttl === 'choose') { notify('请选择轮换后的有效期', true); return; }
  if (ttl === 'keep') body.expiresAt = Number(ttlSelect.dataset.expiresAt);
  else if (ttl) body.ttlMs = Number(ttl);
  if (!body.mask) { notify('请明确选择脱敏方式后保存', true); return; }
  // A source-backed field stores no ciphertext, so it takes the other write path:
  // put() would demand a value, and there is none to give.
  const r = source && !editing
    ? await api("put_source", { ...body, source, value: undefined })
    : await api("put", body);
  if (r.ok) {
    if (editing) notify('已轮换并加密保存');
    else if (source) notify('已绑定来源 ' + source + '，不存值');
    else notify('已保存 ' + body.id + (body.ttlMs ? '（' + fmtDuration(body.ttlMs) + '）' : ''));
    form.remove(); renderVault();
  }
}

async function renderPolicy() {
  const r = await api('policy_get'); S.policy=r.policy;
  if (!S.policy.exec) S.policy.exec={enabled:false,allow:[],deny:[]};
  document.getElementById('app').innerHTML='<div class="card"><h2>解析明文的条件</h2><p>只有写了业务原因、且在下面白名单里，才允许取个人信息明文。同一个字段每分钟的次数也有限制。</p><div class="kv"><label for="p-reasons">允许填的原因（逗号分隔）</label><input id="p-reasons"><label for="p-rate">每个字段每分钟最多取几次</label><input id="p-rate" type="number" min="1" max="10000"></div></div><div class="card"><h2>能跑哪些命令</h2><p>一行一条规则，带空格的参数用引号。* 匹配一个参数，末尾的 ** 匹配任意多个；拒绝规则优先。</p><label><input id="p-exec-enabled" type="checkbox"> 启用命令白名单</label><div class="kv"><label for="p-exec-allow">放行</label><textarea id="p-exec-allow" rows="6" placeholder="node app.js"></textarea><label for="p-exec-deny">拦下</label><textarea id="p-exec-deny" rows="6"></textarea></div><div class="row"><button onclick="savePolicy()">保存</button></div></div>';
  document.getElementById('p-reasons').value=r.policy.resolveReasons.join(', ');
  document.getElementById('p-rate').value=r.policy.resolveRatePerMin;
  document.getElementById('p-exec-enabled').checked=S.policy.exec.enabled ?? true;
  document.getElementById('p-exec-allow').value=(S.policy.exec.allow ?? []).join('\\n');
  document.getElementById('p-exec-deny').value=(S.policy.exec.deny ?? []).join('\\n');
}
async function savePolicy() {
  const lines=id=>document.getElementById(id).value.split('\\n').map(s=>s.trim()).filter(Boolean);
  const policy={...S.policy,resolveReasons:document.getElementById('p-reasons').value.split(',').map(s=>s.trim()).filter(Boolean),resolveRatePerMin:Number(document.getElementById('p-rate').value),exec:{enabled:document.getElementById('p-exec-enabled').checked,allow:lines('p-exec-allow'),deny:lines('p-exec-deny')}};
  await api('policy_put',{policy}); notify('已保存');
}

// ---------- audit ----------
function parseAudit(lines) {
  return (Array.isArray(lines) ? lines : []).flatMap(line => {
    try {
      const e = JSON.parse(line);
      return e && typeof e === 'object' && !Array.isArray(e) &&
        ['op','entry','field','channel','verdict'].every(k => typeof e[k] === 'string') &&
        typeof e.ts === 'number' && Number.isFinite(e.ts) ? [e] : [];
    } catch { return []; }
  }).reverse();
}
async function renderAudit() {
  const app = document.getElementById("app");
  app.innerHTML = '<div class="card"><div class="row"><input id="aq" placeholder="搜操作、条目或结果" style="flex:1" oninput="drawAudit()"></div><div id="audit-tbl"></div></div>';
  const r = await api("audit");
  S.events = parseAudit(r.events);
  drawAudit();
}
function drawAudit() {
  const q = (document.getElementById("aq")?.value ?? "").toLowerCase();
  const evs = S.events.filter((e) => !q || JSON.stringify(e).toLowerCase().includes(q)).slice(0, 300);
  const el = document.getElementById("audit-tbl");
  if (!evs.length) { el.innerHTML = '<div class="empty">还没有记录。用一次凭据，这里就会出现。</div>'; return; }
  el.innerHTML = "<table><tr><th>时间</th><th>操作</th><th>条目</th><th>字段</th><th>通道</th><th>原因</th><th>结果</th></tr>" +
    evs.map((e) => "<tr><td class='mono'>" + fmtTs(e.ts) + "</td><td>" + esc(e.op) + "</td><td>" + esc(e.entry) + "</td><td>" + esc(e.field) + "</td><td class='mono'>" + esc(e.channel) + "</td><td>" + esc(e.reason ?? "—") + "</td><td>" + verdictBadge(e.verdict) + "</td></tr>").join("") + "</table>";
}

// ---------- stats ----------
async function renderStats() {
  const app = document.getElementById("app");
  const [audit, vault] = await Promise.all([api('audit'), api('list')]);
  S.entries = vault.descriptors ?? [];
  const evs = parseAudit(audit.events);
  S.events = evs;
  const draws = evs.filter(e => ['draw', 'draw_env', 'resolve'].includes(e.op));
  const ok = draws.filter((e) => e.verdict === "ok");
  const admin = evs.filter(e => !['draw', 'draw_env', 'resolve'].includes(e.op) && e.verdict === 'ok');
  const denied = evs.filter((e) => e.verdict.startsWith('denied_'));
  const errors = evs.filter(e => e.verdict === 'error');
  const expired = evs.filter(e => e.verdict === 'expired');
  const byOp = Object.create(null), byEntry = Object.create(null), byChannel = Object.create(null);
  for (const e of evs) { byOp[e.op] = (byOp[e.op] ?? 0) + 1; byChannel[e.channel] = (byChannel[e.channel] ?? 0) + 1; }
  for (const e of ok) byEntry[e.entry] = (byEntry[e.entry] ?? 0) + 1;
  const top = (o, n = 8) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, n);
  const max = Math.max(1, ...Object.values(byEntry));
  const p = await api("policy_get");
  app.innerHTML =
    '<div class="stats-grid">' +
    '<div class="stat"><div class="num">' + evs.length + '</div><div class="lbl">总记录</div></div>' +
    '<div class="stat"><div class="num" style="color:var(--green)">' + ok.length + '</div><div class="lbl">成功取用</div></div>' +
    '<div class="stat"><div class="num">' + admin.length + '</div><div class="lbl">管理操作</div></div>' +
    '<div class="stat"><div class="num" style="color:var(--red)">' + denied.length + '</div><div class="lbl">被拒绝</div></div>' +
    '<div class="stat"><div class="num" style="color:var(--orange)">' + errors.length + '</div><div class="lbl">出错</div></div>' +
    '<div class="stat"><div class="num" style="color:var(--violet)">' + expired.length + '</div><div class="lbl">已过期</div></div>' +
    '<div class="stat"><div class="num">' + S.entries.length + '</div><div class="lbl">条目数</div></div>' +
    '</div>' +
    '<div class="card"><h2>各条目被取用次数</h2>' + top(byEntry).map(([k, v]) =>
      '<div style="margin:6px 0"><div class="row" style="margin:0"><span class="mono" style="width:200px">' + esc(k) + '</span><span class="mono">' + v + '</span></div><div class="bar"><div style="width:' + (v / max * 100) + '%"></div></div></div>').join("") + '</div>' +
    '<div class="card"><h2>各操作次数</h2><div class="kv">' + Object.entries(byOp).map(([k, v]) => "<b>" + esc(k) + "</b><span>" + v + "</span>").join("") + '</div></div>' +
    '<div class="card"><h2>各取用方式次数</h2><div class="kv">' + Object.entries(byChannel).map(([k, v]) => "<b>" + esc(k) + "</b><span>" + v + "</span>").join("") + '</div></div>' +
    '<div class="card"><h2>当前设置</h2><div class="kv"><b>允许的解析原因</b><span>' + (p.policy?.resolveReasons ?? []).map(esc).join(", ") + '</span><b>限速</b><span>' + esc(p.policy?.resolveRatePerMin ?? "-") + ' 次/分钟（每个字段）</span></div></div>';
}

// boot: token present -> try ping; else show login
if (S.token) api("auth_check").then(() => enter()).catch(() => { sessionStorage.removeItem('wst'); document.getElementById('login').style.display='block'; });
else document.getElementById("login").style.display = "block";
</script>
</body>
</html>`;
