/* Simple-WireGuard – single page app (vanilla JS, no build step, CSP friendly). */
'use strict';

const S = { me: null, csrf: null, route: 'dashboard', timer: null, peers: [], settings: null };
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/* ---------- icons ---------- */
const ICON = {
  dash: '<path d="M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 3v6h8V3z"/>',
  peers: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>',
  users: '<circle cx="12" cy="8" r="4"/><path d="M4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 0 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 0 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 0 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 0 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
  backup: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
  audit: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/>',
  account: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  plus: '<path d="M12 5v14M5 12h14"/>', qr: '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h3v3h-3zM20 14v.01M14 20h.01M17 20h4v-3"/>',
  dl: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>', edit: '<path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
  trash: '<path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/>', power: '<path d="M18.4 6.6a9 9 0 1 1-12.8 0M12 2v10"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>', x: '<path d="M18 6 6 18M6 6l12 12"/>',
  key: '<path d="M21 2l-2 2m-7.6 7.6a5.5 5.5 0 1 1-7.8 7.8 5.5 5.5 0 0 1 7.8-7.8zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/>',
  copy: '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
};
const icon = n => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON[n]}</svg>`;
const tip = text => `<span class="tip" tabindex="0" role="button" aria-label="Hilfe" data-tip="${esc(text)}">?</span>`;

/* ---------- formatting ---------- */
const fmtBytes = b => { if (!b) return '0 B'; const u = ['B', 'KB', 'MB', 'GB', 'TB']; const i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), 4); return (b / 1024 ** i).toFixed(i ? 1 : 0) + ' ' + u[i]; };
const fmtDate = ts => ts ? new Date(ts * 1000).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' }) : '–';
const ago = ts => { if (!ts) return 'nie'; const s = Math.floor(Date.now() / 1000 - ts); if (s < 60) return `vor ${s}s`; if (s < 3600) return `vor ${Math.floor(s / 60)} min`; if (s < 86400) return `vor ${Math.floor(s / 3600)} h`; return `vor ${Math.floor(s / 86400)} d`; };
const toLocalInput = ts => { if (!ts) return ''; const d = new Date(ts * 1000); d.setMinutes(d.getMinutes() - d.getTimezoneOffset()); return d.toISOString().slice(0, 16); };
const fromLocalInput = v => v ? Math.floor(new Date(v).getTime() / 1000) : null;

/* ---------- API ---------- */
async function api(path, { method = 'GET', body, raw = false } = {}) {
  const headers = { 'Accept': 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (S.csrf && method !== 'GET') headers['X-CSRF-Token'] = S.csrf;
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin' });
  if (res.status === 401 && !path.startsWith('/api/auth/')) { toast('Sitzung abgelaufen – bitte neu anmelden', 'warn'); await boot(); throw new Error('unauthorized'); }
  if (!res.ok) {
    let msg = res.statusText;
    try { const j = await res.json(); msg = typeof j.detail === 'string' ? j.detail : (j.detail?.[0]?.msg || msg); } catch (_) { /* ignore */ }
    throw new Error(msg);
  }
  if (raw) return res;
  return res.json();
}

function toast(msg, kind = 'info', ms = 4500) {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), ms);
}
const handleResult = (r, okMsg) => { if (r && r.warning) toast(r.warning, 'warn', 8000); else if (okMsg) toast(okMsg, 'ok'); };

/* ---------- tooltips (hover, focus, tap) ---------- */
function initTooltips() {
  const tt = $('#tooltip');
  let current = null, shownAt = 0;
  const show = el => {
    current = el; shownAt = Date.now(); tt.textContent = el.dataset.tip; tt.hidden = false;
    const r = el.getBoundingClientRect(); const t = tt.getBoundingClientRect();
    let left = Math.min(Math.max(8, r.left + r.width / 2 - t.width / 2), window.innerWidth - t.width - 8);
    let top = r.top - t.height - 8; if (top < 8) top = r.bottom + 8;
    tt.style.left = left + 'px'; tt.style.top = top + 'px';
  };
  const hide = () => { current = null; tt.hidden = true; };
  // Hover only for real mice; touch devices use tap (click) + focus instead.
  document.addEventListener('pointerover', e => { if (e.pointerType !== 'mouse') return; const el = e.target.closest('[data-tip]'); if (el) show(el); });
  document.addEventListener('pointerout', e => { if (e.pointerType === 'mouse' && e.target.closest('[data-tip]')) hide(); });
  document.addEventListener('focusin', e => { const el = e.target.closest('[data-tip]'); if (el) show(el); });
  document.addEventListener('focusout', e => { if (e.target.closest('[data-tip]') && Date.now() - shownAt > 400) hide(); });
  document.addEventListener('click', e => { const el = e.target.closest('.tip'); if (el) { e.preventDefault(); if (current === el && !tt.hidden && Date.now() - shownAt > 400) hide(); else show(el); } else hide(); }, true);
  window.addEventListener('scroll', hide, { passive: true });
}

/* ---------- modal ---------- */
function modal({ title, body, footer = '', onMount }) {
  const root = $('#modal-root');
  root.innerHTML = `<div class="modal-backdrop"><div class="modal" role="dialog" aria-modal="true" aria-label="${esc(title)}">
    <header><h3>${esc(title)}</h3><button class="btn icon" data-close aria-label="Schließen">${icon('x')}</button></header>
    <div class="body">${body}</div>${footer ? `<footer>${footer}</footer>` : ''}</div></div>`;
  const close = () => { root.innerHTML = ''; document.removeEventListener('keydown', onKey); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  $$('[data-close]', root).forEach(b => b.addEventListener('click', close));
  $('.modal-backdrop', root).addEventListener('mousedown', e => { if (e.target.classList.contains('modal-backdrop')) close(); });
  const first = $('input, select, textarea', root); if (first) setTimeout(() => first.focus(), 30);
  if (onMount) onMount(root, close);
  return close;
}

function confirmDialog(title, text, okLabel = 'Bestätigen', danger = true) {
  return new Promise(resolve => {
    let done = false;
    const close = modal({
      title, body: `<p>${esc(text)}</p>`,
      footer: `<button class="btn" data-close>Abbrechen</button><button class="btn ${danger ? 'danger solid' : 'primary'}" data-ok>${esc(okLabel)}</button>`,
      onMount: root => $('[data-ok]', root).addEventListener('click', () => { done = true; close(); resolve(true); }),
    });
    const obs = new MutationObserver(() => { if (!$('#modal-root').children.length) { obs.disconnect(); if (!done) resolve(false); } });
    obs.observe($('#modal-root'), { childList: true });
  });
}

function formData(form) {
  const out = {};
  $$('[name]', form).forEach(el => { out[el.name] = el.type === 'checkbox' ? el.checked : (el.type === 'number' ? Number(el.value) : el.value); });
  return out;
}

async function download(path, fallbackName, opts) {
  const res = await api(path, { ...opts, raw: true });
  const cd = res.headers.get('content-disposition') || '';
  const name = (cd.match(/filename="([^"]+)"/) || [])[1] || fallbackName;
  const blob = await res.blob();
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name;
  document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
const copy = async text => { try { await navigator.clipboard.writeText(text); toast('In Zwischenablage kopiert', 'ok'); } catch (_) { toast('Kopieren nicht möglich', 'error'); } };

/* ---------- auth screens ---------- */
const brand = () => `<div class="brand"><img src="/icons/icon.svg" alt=""><div>Simple-WireGuard<small>${esc(S.me?.version || '')}</small></div></div>`;

function renderLogin(err = '') {
  $('#app').className = '';
  $('#app').innerHTML = `<div class="auth"><form class="card" id="login" autocomplete="on">
    ${brand()}<h1>Anmeldung</h1>${err ? `<div class="alert danger">${esc(err)}</div>` : ''}
    <div class="field"><label for="u">Benutzername ${tip('Ihr Benutzername für die Verwaltungsoberfläche. Konten werden von einem Administrator angelegt.')}</label>
      <input id="u" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required maxlength="32"></div>
    <div class="field"><label for="p">Passwort ${tip('Nach 5 Fehlversuchen wird das Konto für 15 Minuten gesperrt. Im Notfall: sudo swg-admin reset-password <user>')}</label>
      <input id="p" name="password" type="password" autocomplete="current-password" required></div>
    <button class="btn primary" type="submit">Weiter</button></form></div>`;
  $('#login').addEventListener('submit', async e => {
    e.preventDefault();
    const btn = $('button', e.target); btn.disabled = true;
    try {
      const r = await api('/api/auth/login', { method: 'POST', body: formData(e.target) });
      S.csrf = r.csrf;
      r.stage === 'totp' ? renderTotp() : renderEnroll();
    } catch (ex) { renderLogin(ex.message); }
  });
}

function otpField(id) {
  return `<div class="field"><label for="${id}">6-stelliger Code ${tip('Code aus Ihrer Authenticator-App (z. B. Aegis, 2FAS, Google/Microsoft Authenticator). Er wechselt alle 30 Sekunden. Jeder Code ist nur einmal gültig.')}</label>
    <input id="${id}" name="code" class="otp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required></div>`;
}

function renderTotp(err = '') {
  $('#app').innerHTML = `<div class="auth"><form class="card" id="totp">${brand()}<h1>Zwei-Faktor-Bestätigung</h1>
    ${err ? `<div class="alert danger">${esc(err)}</div>` : ''}${otpField('c')}
    <button class="btn primary" type="submit">Anmelden</button>
    <p class="muted">Kein Zugriff auf die App? Ein Admin kann TOTP per <code>sudo swg-admin reset-totp &lt;user&gt;</code> zurücksetzen.</p></form></div>`;
  $('#totp').addEventListener('submit', async e => {
    e.preventDefault();
    try { const r = await api('/api/auth/totp', { method: 'POST', body: formData(e.target) }); S.csrf = r.csrf; await boot(); }
    catch (ex) { ex.message.includes('anmelden') ? renderLogin(ex.message) : renderTotp(ex.message); }
  });
}

async function renderEnroll(err = '') {
  let d;
  try { d = await api('/api/auth/enroll'); } catch (ex) { return renderLogin(ex.message); }
  $('#app').innerHTML = `<div class="auth"><form class="card" id="enroll">${brand()}<h1>TOTP einrichten (Pflicht)</h1>
    ${err ? `<div class="alert danger">${esc(err)}</div>` : ''}
    <div class="alert info">Scannen Sie den QR-Code mit Ihrer Authenticator-App und bestätigen Sie mit dem angezeigten Code.</div>
    <img class="qr" src="${esc(d.qr)}" alt="TOTP QR-Code">
    <div class="field"><span class="lbl">Manueller Schlüssel ${tip('Falls Scannen nicht möglich ist: diesen Schlüssel manuell in der App eintragen (zeitbasiert, 6 Stellen, 30 s).')}</span>
      <div class="secret-box"><code>${esc(d.secret)}</code><button type="button" class="btn sm" data-copy="${esc(d.secret)}">${icon('copy')}</button></div></div>
    ${otpField('c')}<button class="btn primary" type="submit">Bestätigen & anmelden</button></form></div>`;
  $('[data-copy]').addEventListener('click', e => copy(e.currentTarget.dataset.copy));
  $('#enroll').addEventListener('submit', async e => {
    e.preventDefault();
    try { const r = await api('/api/auth/enroll', { method: 'POST', body: formData(e.target) }); S.csrf = r.csrf; await boot(); }
    catch (ex) { renderEnroll(ex.message); }
  });
}

/* ---------- shell ---------- */
const NAV = [
  { id: 'dashboard', label: 'Dashboard', icon: 'dash' },
  { id: 'peers', label: 'Peers', icon: 'peers' },
  { id: 'users', label: 'Benutzer', icon: 'users', admin: true },
  { id: 'settings', label: 'Einstellungen', icon: 'settings', admin: true },
  { id: 'backup', label: 'Backup', icon: 'backup', admin: true },
  { id: 'audit', label: 'Audit-Log', icon: 'audit', admin: true },
  { id: 'account', label: 'Konto', icon: 'account' },
];
const MOBILE_NAV = ['dashboard', 'peers', 'settings', 'account'];
const isAdmin = () => S.me?.role === 'admin';

function renderShell() {
  const items = NAV.filter(n => !n.admin || isAdmin());
  $('#app').className = '';
  $('#app').innerHTML = `<div class="layout">
    <aside class="sidebar">${brand()}<nav class="nav">${items.map(n => `<a href="#/${n.id}" data-nav="${n.id}">${icon(n.icon)}${n.label}</a>`).join('')}</nav>
      <div class="spacer"></div><div class="userbox">Angemeldet als <strong>${esc(S.me.username)}</strong> (${esc(S.me.role)})<br>
      <button class="btn sm" data-logout>${icon('logout')} Abmelden</button></div></aside>
    <main id="view"></main>
    <nav class="bottom-nav">${items.filter(n => MOBILE_NAV.includes(n.id)).map(n => `<a href="#/${n.id}" data-nav="${n.id}">${icon(n.icon)}${n.label}</a>`).join('')}</nav></div>`;
  $('[data-logout]').addEventListener('click', logout);
}

async function logout() {
  try { await api('/api/auth/logout', { method: 'POST' }); } catch (_) { /* ignore */ }
  S.me = null; S.csrf = null; renderLogin();
}

const VIEWS = {};
async function route() {
  if (!S.me?.authenticated) return;
  clearInterval(S.timer);
  let r = (location.hash.replace(/^#\/?/, '') || 'dashboard').split('?')[0];
  if (!VIEWS[r] || (NAV.find(n => n.id === r)?.admin && !isAdmin())) r = 'dashboard';
  if (S.me.must_change_password) r = 'account';
  S.route = r;
  $$('[data-nav]').forEach(a => a.classList.toggle('active', a.dataset.nav === r));
  try { await VIEWS[r]($('#view')); } catch (ex) { if (ex.message !== 'unauthorized') $('#view').innerHTML = `<div class="alert danger">${esc(ex.message)}</div>`; }
}
const head = (title, sub = '', actions = '') => `<div class="page-head"><div><h1>${esc(title)}</h1>${sub ? `<p>${sub}</p>` : ''}</div><div class="actions">${actions}</div></div>`;

/* ---------- dashboard ---------- */
VIEWS.dashboard = async view => {
  const draw = async () => {
    const d = await api('/api/dashboard');
    if (S.route !== 'dashboard') return;
    const i = d.interface; const maxT = Math.max(1, ...d.top_peers.map(p => p.rx + p.tx));
    view.innerHTML = head('Dashboard', `Server <code>${esc(i.endpoint)}:${esc(i.listen_port)}</code> · aktualisiert sich alle 10 s`,
      isAdmin() ? `<a class="btn primary" href="#/peers?new=1">${icon('plus')} Neuer Peer</a>` : '') +
      (i.error ? `<div class="alert danger">Agent-Fehler: ${esc(i.error)}</div>` : '') +
      `<div class="grid stats">
        ${stat('Interface', i.up ? '<span class="badge ok">aktiv</span>' : '<span class="badge danger">inaktiv</span>', esc(i.name), 'Status des WireGuard-Interfaces auf dem Server.')}
        ${stat('Online', d.counts.online, `von ${d.counts.enabled} aktiven Peers`, 'Peers mit einem Handshake in den letzten 3 Minuten.')}
        ${stat('Peers gesamt', d.counts.total, `${d.counts.expired} abgelaufen`, 'Alle angelegten Peers inkl. deaktivierter.')}
        ${stat('Empfangen', fmtBytes(d.traffic.rx), 'seit Interface-Start', 'Vom Server empfangene Daten aller Peers (rx) seit dem letzten Interface-Start.')}
        ${stat('Gesendet', fmtBytes(d.traffic.tx), 'seit Interface-Start', 'An alle Peers gesendete Daten (tx) seit dem letzten Interface-Start.')}
        ${stat('Läuft bald ab', d.counts.expiring_soon, 'innerhalb 7 Tagen', 'Peers, deren Ablaufdatum in den nächsten 7 Tagen erreicht wird. Abgelaufene Peers werden automatisch deaktiviert.')}
      </div>
      <div class="grid two" style-x>
        <div class="card"><h2>Online-Peers ${tip('Aktuell verbundene Peers mit öffentlicher Absender-Adresse und letztem Handshake.')}</h2>
          ${d.online_peers.length ? d.online_peers.map(p => `<div class="list-row"><div><strong>${esc(p.name)}</strong><div class="muted mono">${esc(p.endpoint || '')}</div></div><div class="muted">${ago(p.latest_handshake)}</div></div>`).join('') : '<div class="empty">Kein Peer online</div>'}</div>
        <div class="card"><h2>Top-Traffic ${tip('Die 5 Peers mit dem meisten Datenvolumen seit Interface-Start.')}</h2>
          ${d.top_peers.filter(p => p.rx + p.tx).length ? d.top_peers.filter(p => p.rx + p.tx).map(p => `<div class="list-row"><div class="grow"><strong>${esc(p.name)}</strong><div class="bar"><span data-w="${Math.round((p.rx + p.tx) / maxT * 100)}"></span></div></div><div class="muted">${fmtBytes(p.rx + p.tx)}</div></div>`).join('') : '<div class="empty">Noch kein Traffic</div>'}</div>
        <div class="card"><h2>Server ${tip('Eckdaten der WireGuard-Serverkonfiguration. Änderungen erfolgen über erneutes Ausführen von install.sh.')}</h2>
          <dl class="kv"><dt>Endpoint</dt><dd><code>${esc(i.endpoint)}:${esc(i.listen_port)}</code></dd><dt>VPN-Subnetz</dt><dd><code>${esc(i.subnet)}</code></dd>
          <dt>Server-IP</dt><dd><code>${esc(i.server_address)}</code></dd><dt>Public Key</dt><dd><code>${esc(i.public_key)}</code></dd><dt>Version</dt><dd>${esc(d.version)}</dd></dl></div>
        ${isAdmin() ? `<div class="card"><h2>Letzte Aktivitäten ${tip('Die jüngsten Einträge aus dem Audit-Log. Vollständige Liste unter „Audit-Log“.')}</h2>
          ${d.recent_audit.map(a => `<div class="list-row"><div><strong>${esc(a.action)}</strong> <span class="muted">${esc(a.detail || '')}</span><div class="muted">${esc(a.username || '–')} · ${esc(a.ip || '')}</div></div><div class="muted">${ago(a.ts)}</div></div>`).join('') || '<div class="empty">Keine Einträge</div>'}</div>` : ''}
      </div>`;
    $$('.bar > span[data-w]', view).forEach(s => { s.style.width = s.dataset.w + '%'; });
    $$('[style-x]', view).forEach(el => { el.style.marginTop = '16px'; });
  };
  await draw();
  S.timer = setInterval(() => draw().catch(() => {}), 10000);
};
const stat = (label, value, sub, help) => `<div class="card stat"><div class="label">${esc(label)} ${tip(help)}</div><div class="value">${value}</div><div class="sub">${sub}</div></div>`;

/* ---------- peers ---------- */
function peerStatus(p) {
  if (!p.enabled) return '<span class="badge muted">deaktiviert</span>';
  if (p.expired) return '<span class="badge danger">abgelaufen</span>';
  if (p.online) return '<span class="badge ok">online</span>';
  return '<span class="badge warn">offline</span>';
}

VIEWS.peers = async view => {
  const filter = { q: '', status: 'all' };
  const draw = async () => {
    S.peers = await api('/api/peers');
    if (S.route !== 'peers') return;
    const q = filter.q.toLowerCase();
    const rows = S.peers.filter(p => (!q || [p.name, p.description, p.address, p.public_key].join(' ').toLowerCase().includes(q)) &&
      (filter.status === 'all' || (filter.status === 'online' && p.online) || (filter.status === 'offline' && p.enabled && !p.online) || (filter.status === 'disabled' && !p.enabled)));
    $('#peer-table').innerHTML = rows.length ? `<table class="responsive"><thead><tr><th>Name</th><th>Status</th><th>Adresse</th><th>Letzter Handshake</th><th>Traffic ↓/↑</th><th>Ablauf</th><th></th></tr></thead><tbody>
      ${rows.map(p => `<tr><td class="primary-cell"><div class="name">${esc(p.name)}</div><div class="desc">${esc(p.description)}</div></td>
        <td data-label="Status">${peerStatus(p)}</td><td data-label="Adresse"><code>${esc(p.address)}</code></td>
        <td data-label="Handshake">${ago(p.latest_handshake)}</td><td data-label="Traffic">${fmtBytes(p.rx)} / ${fmtBytes(p.tx)}</td>
        <td data-label="Ablauf">${p.expires_at ? fmtDate(p.expires_at) : '–'}</td>
        <td class="row-actions"><div class="actions">${isAdmin() ? `
          <button class="btn sm icon" data-act="qr" data-id="${p.id}" data-tip="QR-Code & Konfiguration anzeigen" aria-label="QR">${icon('qr')}</button>
          <button class="btn sm icon" data-act="dl" data-id="${p.id}" data-tip="Client-Konfiguration (.conf) herunterladen" aria-label="Download">${icon('dl')}</button>
          <button class="btn sm icon" data-act="edit" data-id="${p.id}" data-tip="Peer bearbeiten" aria-label="Bearbeiten">${icon('edit')}</button>
          <button class="btn sm icon" data-act="toggle" data-id="${p.id}" data-tip="${p.enabled ? 'Deaktivieren (Verbindung sofort trennen)' : 'Aktivieren'}" aria-label="An/Aus">${icon('power')}</button>
          <button class="btn sm icon danger" data-act="del" data-id="${p.id}" data-tip="Peer endgültig löschen" aria-label="Löschen">${icon('trash')}</button>` : ''}</div></td></tr>`).join('')}
      </tbody></table>` : `<div class="empty">${S.peers.length ? 'Keine Treffer' : 'Noch keine Peers angelegt'}</div>`;
  };
  view.innerHTML = head('Peers', 'WireGuard-Clients, die sich mit diesem Server verbinden dürfen.',
    isAdmin() ? `<button class="btn primary" data-new>${icon('plus')} Neuer Peer</button>` : '') +
    `<div class="toolbar"><input type="search" id="pq" placeholder="Suchen: Name, IP, Schlüssel…" aria-label="Suche" data-tip="Filtert nach Name, Beschreibung, VPN-IP oder Public Key.">
     <select id="ps" aria-label="Status" data-tip="Nach Verbindungsstatus filtern."><option value="all">Alle</option><option value="online">Online</option><option value="offline">Offline</option><option value="disabled">Deaktiviert</option></select></div>
     <div class="card table-wrap" id="peer-table"><div class="spinner"></div></div>`;
  $('#pq').addEventListener('input', e => { filter.q = e.target.value; draw(); });
  $('#ps').addEventListener('change', e => { filter.status = e.target.value; draw(); });
  $('[data-new]', view)?.addEventListener('click', () => peerForm(null, draw));
  $('#peer-table').addEventListener('click', async e => {
    const b = e.target.closest('[data-act]'); if (!b) return;
    const p = S.peers.find(x => x.id === Number(b.dataset.id));
    try {
      if (b.dataset.act === 'edit') peerForm(p, draw);
      if (b.dataset.act === 'qr') showQr(p);
      if (b.dataset.act === 'dl') await download(`/api/peers/${p.id}/config`, 'peer.conf');
      if (b.dataset.act === 'toggle') { handleResult(await api(`/api/peers/${p.id}/toggle`, { method: 'POST' }), p.enabled ? 'Deaktiviert' : 'Aktiviert'); draw(); }
      if (b.dataset.act === 'del' && await confirmDialog('Peer löschen', `„${p.name}“ wird gelöscht und sofort getrennt. Fortfahren?`, 'Löschen')) {
        handleResult(await api(`/api/peers/${p.id}`, { method: 'DELETE' }), 'Gelöscht'); draw();
      }
    } catch (ex) { toast(ex.message, 'error'); }
  });
  await draw();
  if (location.hash.includes('new=1') && isAdmin()) { history.replaceState(null, '', '#/peers'); peerForm(null, draw); }
  S.timer = setInterval(() => { if (!$('#modal-root').children.length) draw().catch(() => {}); }, 15000);
};

async function peerForm(p, done) {
  const d = p ? null : await api('/api/peers/defaults');
  const v = p || { name: '', description: '', address: d.address, client_allowed_ips: d.client_allowed_ips, dns: d.dns, keepalive: d.keepalive, enabled: true, has_psk: true, expires_at: null };
  modal({
    title: p ? `Peer bearbeiten: ${p.name}` : 'Neuer Peer',
    body: `<form id="pf"><div class="form-grid">
      <div class="field"><label for="f-name">Name ${tip('Eindeutiger Anzeigename, z. B. „laptop-max“ oder „iphone-anna“. Wird auch als Dateiname der Konfiguration verwendet.')}</label><input id="f-name" name="name" required maxlength="64" value="${esc(v.name)}"></div>
      <div class="field"><label for="f-addr">VPN-IP-Adresse ${tip('Feste IP des Clients im VPN-Subnetz. Wird automatisch mit der nächsten freien Adresse vorbelegt.')}</label><input id="f-addr" name="address" required value="${esc(v.address)}" inputmode="decimal"></div>
      </div>
      <div class="field"><label for="f-desc">Beschreibung ${tip('Optionale Notiz, z. B. Besitzer, Gerät oder Zweck.')}</label><input id="f-desc" name="description" maxlength="500" value="${esc(v.description)}"></div>
      <div class="field"><label for="f-aips">Client AllowedIPs ${tip('Welche Ziele der Client durch den Tunnel routet. 0.0.0.0/0, ::/0 = gesamter Traffic (Full Tunnel). Für Split-Tunnel nur interne Netze eintragen, z. B. 10.8.0.0/24, 192.168.10.0/24.')}</label><input id="f-aips" name="client_allowed_ips" required value="${esc(v.client_allowed_ips)}"></div>
      <div class="form-grid">
      <div class="field"><label for="f-dns">DNS-Server ${tip('DNS-Server, die der Client bei aktivem Tunnel nutzt (kommagetrennt). Leer = DNS des Clients bleibt unverändert.')}</label><input id="f-dns" name="dns" value="${esc(v.dns)}"></div>
      <div class="field"><label for="f-ka">Keepalive (Sekunden) ${tip('PersistentKeepalive: hält NAT-Verbindungen offen. 25 ist ein guter Wert für mobile Geräte hinter NAT; 0 = aus.')}</label><input id="f-ka" name="keepalive" type="number" min="0" max="3600" value="${esc(v.keepalive)}"></div>
      <div class="field"><label for="f-exp">Ablaufdatum ${tip('Optional. Nach Ablauf wird der Peer automatisch deaktiviert (z. B. für Gast- oder Dienstleisterzugänge). Leer = unbegrenzt.')}</label><input id="f-exp" name="expires_at" type="datetime-local" value="${toLocalInput(v.expires_at)}"></div>
      </div>
      <label class="check"><input type="checkbox" name="use_psk" ${v.has_psk ? 'checked' : ''}> Preshared Key verwenden ${tip('Zusätzlicher symmetrischer Schlüssel pro Peer. Erhöht die Sicherheit (u. a. gegen zukünftige Quantenangriffe). Empfohlen.')}</label>
      <label class="check"><input type="checkbox" name="enabled" ${v.enabled ? 'checked' : ''}> Aktiv ${tip('Deaktivierte Peers bleiben gespeichert, können sich aber nicht verbinden.')}</label>
      ${p ? '' : `<details><summary class="muted">Erweitert: eigenen Public Key verwenden</summary>
        <div class="field"><label for="f-pub">Public Key des Clients ${tip('Nur ausfüllen, wenn der Client sein Schlüsselpaar selbst erzeugt hat. Dann speichert der Server keinen privaten Schlüssel und es kann keine fertige Config/QR erzeugt werden.')}</label><input id="f-pub" name="public_key" maxlength="64" class="mono"></div></details>`}
      ${p ? `<div class="actions"><button type="button" class="btn sm" data-rotate data-tip="Erzeugt ein neues Schlüsselpaar. Der Client benötigt danach eine neue Konfiguration.">${icon('key')} Schlüssel rotieren</button></div>` : ''}
    </form>`,
    footer: `<button class="btn" data-close>Abbrechen</button><button class="btn primary" form="pf" type="submit">${p ? 'Speichern' : 'Anlegen'}</button>`,
    onMount: (root, close) => {
      $('[data-rotate]', root)?.addEventListener('click', async () => {
        if (!await confirmDialog('Schlüssel rotieren', 'Der aktuelle Client verliert die Verbindung, bis er die neue Konfiguration importiert. Fortfahren?', 'Rotieren')) return;
        try { handleResult(await api(`/api/peers/${p.id}/rotate`, { method: 'POST' }), 'Neue Schlüssel erzeugt'); done(); showQr(p); } catch (ex) { toast(ex.message, 'error'); }
      });
      $('#pf', root).addEventListener('submit', async e => {
        e.preventDefault();
        const f = formData(e.target);
        f.expires_at = fromLocalInput(f.expires_at);
        if (!f.public_key) delete f.public_key;
        try {
          const r = await api(p ? `/api/peers/${p.id}` : '/api/peers', { method: p ? 'PUT' : 'POST', body: f });
          close(); handleResult(r, p ? 'Gespeichert' : 'Peer angelegt'); await done();
          if (!p && !f.public_key) showQr({ id: r.id, name: f.name });
        } catch (ex) { toast(ex.message, 'error'); }
      });
    },
  });
}

async function showQr(p) {
  try {
    const r = await api(`/api/peers/${p.id}/qr`);
    modal({
      title: `Konfiguration: ${p.name}`,
      body: `<div class="alert warn">Enthält den privaten Schlüssel – nur an den Gerätebesitzer weitergeben.</div>
        <img class="qr" src="${esc(r.qr)}" alt="QR-Code"><p class="muted">In der WireGuard-App: „Tunnel hinzufügen“ → „QR-Code scannen“.</p>
        <pre class="conf">${esc(r.config)}</pre>`,
      footer: `<button class="btn" data-copyconf>${icon('copy')} Kopieren</button><button class="btn primary" data-dlconf>${icon('dl')} Herunterladen</button>`,
      onMount: root => {
        $('[data-copyconf]', root).addEventListener('click', () => copy(r.config));
        $('[data-dlconf]', root).addEventListener('click', () => download(`/api/peers/${p.id}/config`, 'peer.conf').catch(ex => toast(ex.message, 'error')));
      },
    });
  } catch (ex) { toast(ex.message, 'error'); }
}

/* ---------- users ---------- */
VIEWS.users = async view => {
  const draw = async () => {
    const users = await api('/api/users');
    view.innerHTML = head('Benutzer', 'Zugänge zur Verwaltungsoberfläche. TOTP ist für alle Konten Pflicht.', `<button class="btn primary" data-new>${icon('plus')} Neuer Benutzer</button>`) +
      `<div class="card table-wrap"><table class="responsive"><thead><tr><th>Benutzer</th><th>Rolle</th><th>TOTP</th><th>Status</th><th>Letzter Login</th><th></th></tr></thead><tbody>
      ${users.map(u => `<tr><td class="primary-cell"><div class="name">${esc(u.username)}${u.username === S.me.username ? ' <span class="muted">(Sie)</span>' : ''}</div></td>
        <td data-label="Rolle"><select data-role="${u.id}" aria-label="Rolle" data-tip="Admin: volle Rechte. Viewer: nur Dashboard und Peer-Liste lesen.">
          <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>Admin</option><option value="viewer" ${u.role === 'viewer' ? 'selected' : ''}>Viewer</option></select></td>
        <td data-label="TOTP">${u.totp_enabled ? '<span class="badge ok">aktiv</span>' : '<span class="badge warn">ausstehend</span>'}</td>
        <td data-label="Status">${u.locked ? '<span class="badge danger">gesperrt</span>' : '<span class="badge ok">ok</span>'}${u.must_change_password ? ' <span class="badge muted">PW-Wechsel</span>' : ''}</td>
        <td data-label="Letzter Login">${fmtDate(u.last_login)}</td>
        <td class="row-actions"><div class="actions">
          ${u.locked ? `<button class="btn sm" data-act="unlock" data-id="${u.id}" data-tip="Sperre nach Fehlversuchen aufheben">Entsperren</button>` : ''}
          <button class="btn sm" data-act="totp" data-id="${u.id}" data-name="${esc(u.username)}" data-tip="TOTP zurücksetzen: Benutzer muss beim nächsten Login neu einrichten. Alle Sitzungen werden beendet.">TOTP reset</button>
          ${u.username !== S.me.username ? `<button class="btn sm icon danger" data-act="del" data-id="${u.id}" data-name="${esc(u.username)}" data-tip="Benutzer löschen" aria-label="Löschen">${icon('trash')}</button>` : ''}
        </div></td></tr>`).join('')}</tbody></table></div>
      <div class="card" style-x><h2>Notfallzugang ${tip('Diese Befehle funktionieren nur direkt auf dem Server mit Root-Rechten und sind der „Notfall-Schlüssel“, falls Passwort oder Authenticator verloren gehen.')}</h2>
      <pre class="conf">sudo swg-admin reset-password &lt;user&gt; [--generate]\nsudo swg-admin reset-totp &lt;user&gt;\nsudo swg-admin unlock &lt;user&gt;\nsudo swg-admin list-users</pre></div>`;
    $$('[style-x]', view).forEach(el => { el.style.marginTop = '16px'; });
    $('[data-new]', view).addEventListener('click', () => userForm(draw));
    $$('[data-role]', view).forEach(sel => sel.addEventListener('change', async e => {
      try { await api(`/api/users/${e.target.dataset.role}`, { method: 'PUT', body: { role: e.target.value } }); toast('Rolle geändert', 'ok'); } catch (ex) { toast(ex.message, 'error'); draw(); }
    }));
    $$('[data-act]', view).forEach(b => b.addEventListener('click', async () => {
      const id = b.dataset.id;
      try {
        if (b.dataset.act === 'unlock') { await api(`/api/users/${id}/unlock`, { method: 'POST' }); toast('Entsperrt', 'ok'); }
        if (b.dataset.act === 'totp' && await confirmDialog('TOTP zurücksetzen', `TOTP für „${b.dataset.name}“ zurücksetzen?`, 'Zurücksetzen')) { await api(`/api/users/${id}/reset-totp`, { method: 'POST' }); toast('TOTP zurückgesetzt', 'ok'); if (b.dataset.name === S.me.username) return boot(); }
        if (b.dataset.act === 'del' && await confirmDialog('Benutzer löschen', `„${b.dataset.name}“ endgültig löschen?`, 'Löschen')) { await api(`/api/users/${id}`, { method: 'DELETE' }); toast('Gelöscht', 'ok'); }
        draw();
      } catch (ex) { toast(ex.message, 'error'); }
    }));
  };
  await draw();
};

function userForm(done) {
  modal({
    title: 'Neuer Benutzer',
    body: `<form id="uf">
      <div class="field"><label for="nu">Benutzername ${tip('3–32 Zeichen: Buchstaben, Ziffern, Punkt, Unterstrich, Bindestrich.')}</label><input id="nu" name="username" required pattern="[a-zA-Z0-9._-]{3,32}" autocapitalize="none"></div>
      <div class="field"><label for="nr">Rolle ${tip('Admin: darf alles. Viewer: sieht Dashboard und Peers, kann aber nichts ändern und keine Konfigurationen abrufen.')}</label><select id="nr" name="role"><option value="admin">Admin</option><option value="viewer">Viewer</option></select></div>
      <div class="field"><label for="np">Initiales Passwort ${tip('Leer lassen, um ein sicheres Passwort zu generieren. Der Benutzer muss es beim ersten Login ändern und TOTP einrichten.')}</label><input id="np" name="password" type="password" autocomplete="new-password" placeholder="leer = generieren"></div>
    </form>`,
    footer: `<button class="btn" data-close>Abbrechen</button><button class="btn primary" form="uf" type="submit">Anlegen</button>`,
    onMount: (root, close) => $('#uf', root).addEventListener('submit', async e => {
      e.preventDefault();
      const f = formData(e.target); if (!f.password) delete f.password;
      try {
        const r = await api('/api/users', { method: 'POST', body: f });
        close(); await done();
        if (r.initial_password) modal({ title: 'Initiales Passwort', body: `<div class="alert warn">Wird nur jetzt angezeigt. Sicher übermitteln!</div><div class="secret-box"><code>${esc(r.initial_password)}</code><button class="btn sm" data-c>${icon('copy')}</button></div>`, onMount: rr => $('[data-c]', rr).addEventListener('click', () => copy(r.initial_password)) });
        else toast('Benutzer angelegt', 'ok');
      } catch (ex) { toast(ex.message, 'error'); }
    }),
  });
}

/* ---------- settings ---------- */
VIEWS.settings = async view => {
  if (!isAdmin()) { location.hash = '#/account'; return; }
  const s = await api('/api/settings');
  const po = s.pushover;
  view.innerHTML = head('Einstellungen', 'Standardwerte für neue Peers, Benachrichtigungen und Systemfunktionen.') + `<div class="grid two">
    <form class="card" id="sf"><h2>Standardwerte für neue Peers ${tip('Diese Werte werden beim Anlegen eines Peers vorbelegt und können pro Peer überschrieben werden.')}</h2>
      <div class="field"><label for="s-dns">DNS-Server ${tip('Kommagetrennte DNS-Server für Clients, z. B. 1.1.1.1, 9.9.9.9 oder ein interner DNS.')}</label><input id="s-dns" name="default_dns" value="${esc(s.default_dns)}"></div>
      <div class="field"><label for="s-aips">AllowedIPs ${tip('Standard-Routing der Clients. 0.0.0.0/0, ::/0 leitet allen Traffic durch das VPN.')}</label><input id="s-aips" name="default_allowed_ips" value="${esc(s.default_allowed_ips)}"></div>
      <div class="field"><label for="s-ka">Keepalive (Sekunden) ${tip('Standard-PersistentKeepalive. 25 empfohlen für Geräte hinter NAT.')}</label><input id="s-ka" name="default_keepalive" type="number" min="0" max="3600" value="${esc(s.default_keepalive)}"></div>
      <h2>Benachrichtigungen ${tip('Welche Ereignisse per Pushover gemeldet werden. Erfordert hinterlegte Pushover-Zugangsdaten.')}</h2>
      ${Object.entries(s.notification_labels).map(([k, l]) => `<label class="check"><input type="checkbox" data-notify="${esc(k)}" ${s.notifications[k] ? 'checked' : ''}> ${esc(l)}</label>`).join('')}
      <div class="actions"><button class="btn primary" type="submit">Speichern</button></div></form>
    <div><form class="card" id="pf2"><h2>Pushover ${tip('Push-Benachrichtigungen aufs Smartphone über pushover.net. Die Schlüssel werden verschlüsselt (Fernet/AES) gespeichert und nie wieder im Klartext angezeigt.')}</h2>
      <p>${po.configured ? `<span class="badge ok">konfiguriert</span> <span class="muted">Token ${esc(po.token_hint)} · User ${esc(po.user_hint)}</span>` : '<span class="badge warn">nicht konfiguriert</span>'}</p>
      <div class="field"><label for="po-t">API Token (Application Key) ${tip('Unter pushover.net → „Create an Application/API Token“. 30 Zeichen. Leer lassen, um den gespeicherten Wert zu behalten.')}</label><input id="po-t" name="token" autocomplete="off" spellcheck="false" placeholder="${po.configured ? 'unverändert' : 'azGDORePK8gMaC0QOYAMyEEuzJnyUi'}"></div>
      <div class="field"><label for="po-u">User Key ${tip('Ihr persönlicher User- oder Gruppen-Key von der Pushover-Startseite. 30 Zeichen.')}</label><input id="po-u" name="user" autocomplete="off" spellcheck="false" placeholder="${po.configured ? 'unverändert' : 'uQiRzpo4DXghDmr9QzzfQu27cmVRsG'}"></div>
      <div class="actions"><button class="btn primary" type="submit">Speichern</button><button class="btn" type="button" data-test>Test senden</button>${po.configured ? '<button class="btn danger" type="button" data-clear>Entfernen</button>' : ''}</div></form>
    <div class="card" style-x><h2>System ${tip('Server-Eckdaten. Port, Subnetz und Endpoint werden über install.sh geändert (z. B. sudo bash install.sh --endpoint vpn.example.com).')}</h2>
      <dl class="kv"><dt>Interface</dt><dd>${esc(s.server.iface)}</dd><dt>Endpoint</dt><dd><code>${esc(s.server.endpoint)}:${esc(s.server.listen_port)}</code></dd><dt>Subnetz</dt><dd><code>${esc(s.server.subnet)}</code></dd><dt>MTU</dt><dd>${esc(s.server.mtu || 'auto')}</dd></dl>
      <div class="actions" style-x><button class="btn danger" data-restart data-tip="Startet das WireGuard-Interface neu. Alle Clients verbinden sich danach automatisch wieder (kurze Unterbrechung).">${icon('power')} Interface neu starten</button>
      <button class="btn" data-theme-toggle data-tip="Zwischen hellem, dunklem und System-Design wechseln (wird lokal gespeichert).">Design wechseln</button></div></div></div></div>`;
  $$('[style-x]', view).forEach(el => { el.style.marginTop = '16px'; });
  $('#sf').addEventListener('submit', async e => {
    e.preventDefault();
    const f = formData(e.target); const n = {};
    $$('[data-notify]', e.target).forEach(c => { n[c.dataset.notify] = c.checked; delete f[c.name]; });
    try { await api('/api/settings', { method: 'PUT', body: { default_dns: f.default_dns, default_allowed_ips: f.default_allowed_ips, default_keepalive: f.default_keepalive, notifications: n } }); toast('Gespeichert', 'ok'); } catch (ex) { toast(ex.message, 'error'); }
  });
  $('#pf2').addEventListener('submit', async e => {
    e.preventDefault();
    try { await api('/api/settings/pushover', { method: 'PUT', body: formData(e.target) }); toast('Pushover gespeichert', 'ok'); VIEWS.settings(view); } catch (ex) { toast(ex.message, 'error'); }
  });
  $('[data-test]').addEventListener('click', async () => { try { await api('/api/settings/pushover/test', { method: 'POST' }); toast('Testnachricht gesendet', 'ok'); } catch (ex) { toast(ex.message, 'error'); } });
  $('[data-clear]')?.addEventListener('click', async () => { if (await confirmDialog('Pushover entfernen', 'Gespeicherte Pushover-Schlüssel löschen?', 'Entfernen')) { await api('/api/settings/pushover', { method: 'PUT', body: { clear: true } }); VIEWS.settings(view); } });
  $('[data-restart]').addEventListener('click', async () => { if (await confirmDialog('Interface neu starten', 'Alle VPN-Verbindungen werden kurz unterbrochen.', 'Neu starten')) { try { await api('/api/system/restart', { method: 'POST' }); toast('Interface neu gestartet', 'ok'); } catch (ex) { toast(ex.message, 'error'); } } });
  $('[data-theme-toggle]').addEventListener('click', cycleTheme);
};

function applyTheme() { let t = null; try { t = localStorage.getItem('swg-theme'); } catch (_) { /* ignore */ } if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme; }
function cycleTheme() { let t = null; try { t = localStorage.getItem('swg-theme'); } catch (_) { /* ignore */ } const next = t === 'dark' ? 'light' : t === 'light' ? null : 'dark'; try { next ? localStorage.setItem('swg-theme', next) : localStorage.removeItem('swg-theme'); } catch (_) { /* ignore */ } applyTheme(); toast('Design: ' + (next || 'System'), 'info', 1500); }

/* ---------- backup ---------- */
VIEWS.backup = async view => {
  view.innerHTML = head('Backup & Restore', 'Verschlüsselte Sicherung aller Peers (inkl. Schlüssel) und Einstellungen.') + `<div class="grid two">
    <form class="card" id="bx"><h2>Backup erstellen ${tip('Erzeugt eine mit Ihrer Passphrase verschlüsselte Datei (scrypt + AES-256-GCM). Ohne Passphrase ist die Datei wertlos – gut aufbewahren!')}</h2>
      <div class="field"><label for="bp">Passphrase ${tip('Mindestens 12 Zeichen. Wird nicht gespeichert und kann nicht wiederhergestellt werden.')}</label><input id="bp" name="passphrase" type="password" minlength="12" required autocomplete="new-password"></div>
      <div class="field"><label for="bp2">Passphrase wiederholen ${tip('Zur Vermeidung von Tippfehlern.')}</label><input id="bp2" name="passphrase2" type="password" minlength="12" required autocomplete="new-password"></div>
      <label class="check"><input type="checkbox" name="include_users"> Benutzer inkl. Passwort-Hashes & TOTP sichern ${tip('Für eine vollständige Migration auf einen neuen Server. Ohne diese Option werden nur Peers und Einstellungen gesichert.')}</label>
      <div class="actions"><button class="btn primary" type="submit">${icon('dl')} Backup herunterladen</button></div></form>
    <form class="card" id="br"><h2>Wiederherstellen ${tip('Ersetzt ALLE aktuellen Peers durch den Stand der Sicherung. Einstellungen werden überschrieben.')}</h2>
      <div class="alert warn">Aktuelle Peers werden ersetzt. Vorher ein Backup erstellen!</div>
      <div class="field"><label for="bf">Backup-Datei (.swgbak) ${tip('Eine zuvor mit Simple-WireGuard erstellte Sicherungsdatei.')}</label><input id="bf" name="file" type="file" accept=".swgbak,.json,application/json" required></div>
      <div class="field"><label for="brp">Passphrase ${tip('Die beim Erstellen der Sicherung gewählte Passphrase.')}</label><input id="brp" name="passphrase" type="password" required autocomplete="off"></div>
      <label class="check"><input type="checkbox" name="include_users"> Auch Benutzer wiederherstellen ${tip('Ersetzt alle Benutzer und beendet alle Sitzungen – auch Ihre. Nur wenn die Sicherung Benutzer enthält.')}</label>
      <div class="actions"><button class="btn danger solid" type="submit">Wiederherstellen</button></div></form></div>
    <div class="card" style-x><h2>Hinweis zur Server-Identität ${tip('Der private Server-Schlüssel liegt aus Sicherheitsgründen nur root-lesbar auf dem Server und ist nicht Teil des GUI-Backups.')}</h2>
      <p class="muted">Für einen Umzug ohne neue Client-Konfigurationen zusätzlich als root sichern: <code>/etc/simple-wireguard/</code> (enthält Server-Schlüssel und den Schlüssel zur Entschlüsselung gespeicherter Geheimnisse).</p></div>`;
  $$('[style-x]', view).forEach(el => { el.style.marginTop = '16px'; });
  $('#bx').addEventListener('submit', async e => {
    e.preventDefault(); const f = formData(e.target);
    if (f.passphrase !== f.passphrase2) return toast('Passphrasen stimmen nicht überein', 'error');
    try { await download('/api/backup/export', 'simple-wireguard.swgbak', { method: 'POST', body: { passphrase: f.passphrase, include_users: f.include_users } }); toast('Backup erstellt', 'ok'); e.target.reset(); } catch (ex) { toast(ex.message, 'error'); }
  });
  $('#br').addEventListener('submit', async e => {
    e.preventDefault(); const f = formData(e.target); const file = $('#bf').files[0];
    if (!file) return;
    if (!await confirmDialog('Wiederherstellen', 'Alle aktuellen Peers werden ersetzt. Fortfahren?', 'Wiederherstellen')) return;
    try {
      const blob = JSON.parse(await file.text());
      const r = await api('/api/backup/restore', { method: 'POST', body: { backup: blob, passphrase: f.passphrase, include_users: f.include_users } });
      r.warnings.forEach(w => toast(w, 'warn', 10000)); handleResult(r, `${r.peers} Peers wiederhergestellt`);
      if (f.include_users) boot(); else e.target.reset();
    } catch (ex) { toast(ex instanceof SyntaxError ? 'Datei ist kein gültiges Backup' : ex.message, 'error'); }
  });
};

/* ---------- audit ---------- */
VIEWS.audit = async view => {
  let q = '';
  view.innerHTML = head('Audit-Log', 'Sicherheitsrelevante Aktionen (12 Monate Aufbewahrung). Zusätzlich in /var/log/simple-wireguard/audit.log.') +
    `<div class="toolbar"><input type="search" id="aq" placeholder="Filtern: Aktion, Benutzer, IP…" data-tip="Volltextfilter über Aktion, Benutzer, Details und IP-Adresse." aria-label="Filter"></div><div class="card table-wrap" id="at"></div>`;
  const draw = async () => {
    const rows = await api('/api/audit?limit=300&q=' + encodeURIComponent(q));
    $('#at').innerHTML = rows.length ? `<table class="responsive"><thead><tr><th>Zeit</th><th>Aktion</th><th>Benutzer</th><th>IP</th><th>Details</th></tr></thead><tbody>
      ${rows.map(r => `<tr><td class="primary-cell"><strong>${esc(r.action)}</strong> <span class="muted">${fmtDate(r.ts)}</span></td><td data-label="Aktion">${esc(r.action)}</td><td data-label="Benutzer">${esc(r.username || '–')}</td><td data-label="IP"><code>${esc(r.ip || '–')}</code></td><td data-label="Details">${esc(r.detail || '')}</td></tr>`).join('')}</tbody></table>` : '<div class="empty">Keine Einträge</div>';
  };
  let t; $('#aq').addEventListener('input', e => { q = e.target.value; clearTimeout(t); t = setTimeout(draw, 250); });
  await draw();
};

/* ---------- account ---------- */
VIEWS.account = async view => {
  const sessions = await api('/api/account/sessions');
  view.innerHTML = head('Mein Konto', `Angemeldet als <strong>${esc(S.me.username)}</strong> (${esc(S.me.role)})`, `<button class="btn" data-logout2>${icon('logout')} Abmelden</button>`) +
    (S.me.must_change_password ? '<div class="alert warn">Bitte ändern Sie Ihr initiales Passwort, bevor Sie fortfahren.</div>' : '') + `<div class="grid two">
    <form class="card" id="cp"><h2>Passwort ändern ${tip('Andere Sitzungen werden nach der Änderung automatisch abgemeldet.')}</h2>
      <div class="field"><label for="pc">Aktuelles Passwort ${tip('Zur Bestätigung Ihrer Identität.')}</label><input id="pc" name="current" type="password" required autocomplete="current-password"></div>
      <div class="field"><label for="pn">Neues Passwort ${tip('Mindestens 12 Zeichen und 3 von 4 Zeichenklassen (klein, groß, Ziffer, Sonderzeichen). Ein Passwortmanager wird empfohlen.')}</label><input id="pn" name="new" type="password" minlength="12" required autocomplete="new-password"></div>
      <div class="field"><label for="pn2">Neues Passwort wiederholen ${tip('Zur Vermeidung von Tippfehlern.')}</label><input id="pn2" name="new2" type="password" minlength="12" required autocomplete="new-password"></div>
      <div class="actions"><button class="btn primary" type="submit">Passwort ändern</button></div></form>
    <div class="card"><h2>Aktive Sitzungen ${tip('Geräte, auf denen Sie aktuell angemeldet sind. Unbekannte Sitzungen sofort beenden und Passwort ändern.')}</h2>
      ${sessions.map(x => `<div class="list-row"><div><strong>${esc(x.ip)}</strong>${x.current ? ' <span class="badge ok">diese Sitzung</span>' : ''}<div class="muted">${esc(x.user_agent).slice(0, 80)}</div><div class="muted">aktiv ${ago(x.last_seen)}</div></div>
        ${x.current ? '' : `<button class="btn sm danger" data-revoke="${esc(x.id)}">Beenden</button>`}</div>`).join('')}
      <p class="muted">Design: <button class="btn sm" data-theme-toggle>wechseln</button></p></div></div>`;
  $('[data-logout2]').addEventListener('click', logout);
  $('[data-theme-toggle]', view).addEventListener('click', cycleTheme);
  $$('[data-revoke]', view).forEach(b => b.addEventListener('click', async () => { await api(`/api/account/sessions/${b.dataset.revoke}`, { method: 'DELETE' }); toast('Sitzung beendet', 'ok'); VIEWS.account(view); }));
  $('#cp').addEventListener('submit', async e => {
    e.preventDefault(); const f = formData(e.target);
    if (f.new !== f.new2) return toast('Passwörter stimmen nicht überein', 'error');
    try { await api('/api/account/password', { method: 'POST', body: { current: f.current, new: f.new } }); toast('Passwort geändert', 'ok'); S.me.must_change_password = false; e.target.reset(); route(); } catch (ex) { toast(ex.message, 'error'); }
  });
};

/* ---------- boot ---------- */
async function boot() {
  try { S.me = await api('/api/auth/me'); } catch (ex) { S.me = null; }
  if (!S.me) { $('#app').innerHTML = '<div class="auth"><div class="card"><div class="alert danger">Server nicht erreichbar.</div></div></div>'; return; }
  S.csrf = S.me.csrf || null;
  if (S.me.stage === 'totp') return renderTotp();
  if (S.me.stage === 'enroll') return renderEnroll();
  if (!S.me.authenticated) return renderLogin();
  renderShell();
  route();
}

applyTheme();
initTooltips();
window.addEventListener('hashchange', route);
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
boot();
