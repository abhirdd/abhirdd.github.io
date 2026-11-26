function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const pad2 = n => String(n).padStart(2, '0');

function statusClass(s) {
  const x = (s || '').toLowerCase();
  if (x === 'fixed') return 'badge fixed';
  if (x === 'verified') return 'badge verified';
  if (x === 'new' || x === 'untriaged' || x === 'assigned' || x === 'accepted') return 'badge new';
  return 'badge other';
}

function toast(msg, kind) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show ' + (kind || 'ok');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.className = 'toast'; }, 2600);
}

function issueUrl(id) { return 'https://issues.chromium.org/issues/' + encodeURIComponent(id); }

let lastData = null;
let currentView = 'overview';   // 'overview' | 'custom' | 'cat:<id>'
let currentEmail = '';
let configList = [];
let favs = new Set(JSON.parse(localStorage.getItem('favs') || '[]'));

function persistFavs() { localStorage.setItem('favs', JSON.stringify([...favs])); }
function sortDefs(defs) {
  return [...defs].sort((a, b) => {
    const fa = favs.has(String(a.id)) ? 0 : 1;
    const fb = favs.has(String(b.id)) ? 0 : 1;
    if (fa !== fb) return fa - fb;
    return Number(a.id) - Number(b.id);
  });
}

function countLabel(c) {
  if (c.error) return 'err';
  if (c.total == null) return '50+';
  return String(c.total);
}

function renderCard(c, isCustom) {
  const issues = c.issues || [];
  const emailTag = c.email ? '<span class="email-tag">' + esc(c.email) + '</span>' : '';
  const badge = isCustom ? '<span class="card-num custom-num">&#9733;</span>' : '<span class="card-num">' + pad2(c.id) + '</span>';

  let body = '';
  if (c.error) {
    body = '<div class="err">Gagal memuat: ' + esc(c.error) + '</div>';
  } else if (!issues.length) {
    body = '<div class="empty">Belum ada data / tidak ada hasil.</div>';
  } else {
    const rows = issues.map(it => {
      const link = issueUrl(it.id);
      const prio = esc(it.priority);
      const st = esc(it.status);
      const rep = it.reporter || '';
      const rwd = it.reward;
      const rwdTxt = (rwd === undefined || rwd === '') ? '<span class="muted">…</span>'
        : (rwd === '—' ? '<span class="muted">—</span>' : '<span class="reward">' + esc(rwd) + '</span>');
      return '<tr>' +
        '<td class="id"><a href="' + link + '" target="_blank" rel="noopener" title="' + esc(it.id) + '">' + esc(it.id) + '</a></td>' +
        '<td class="ttl"><div class="issue-title" title="' + esc(it.title) + '"><a href="' + link + '" target="_blank" rel="noopener">' + esc(it.title) + '</a></div></td>' +
        '<td><span class="' + statusClass(st) + '">' + esc(it.status || '-') + '</span></td>' +
        '<td><span class="prio ' + prio + '">' + (prio || '-') + '</span></td>' +
        '<td class="rep" title="' + esc(rep) + '">' + (rep ? esc(rep) : '<span class="muted">-</span>') + '</td>' +
        '<td class="rwd">' + rwdTxt + '</td>' +
        '<td class="mod">' + esc(it.modified || '') + '</td>' +
        '<td class="act"><button class="act-btn" data-action="save-issue" data-id="' + esc(it.id) + '" title="Simpan temuan ini">&#128190;</button></td>' +
        '</tr>';
    }).join('');
    body = '<div class="table-wrap"><table>' +
      '<thead><tr><th class="id">ID</th><th>Judul</th><th>Status</th><th>Pri</th><th>Reporter</th><th>Bounty</th><th class="mod">Modified</th><th class="act"></th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div>';
  }

  const foot = c.error ? '' :
    ('<div class="card-foot">Menampilkan ' + issues.length + ' terbaru' + (c.total != null ? ' dari ' + c.total : '') + ' · diperbarui ' + esc(c.fetched_at || '') + '</div>');

  return '<article class="card' + (isCustom ? ' card-custom' : '') + '">' +
    '<div class="card-top">' +
      badge +
      '<div class="card-head">' +
        '<h2 class="card-title">' + (favs.has(String(c.id)) ? '<span class="fav-star">&#9733;</span> ' : '') + esc(c.title) + ' ' + emailTag + '</h2>' +
        '<div class="card-desc">' + esc(c.description) + '</div>' +
      '</div>' +
      '<span class="count-badge">' + countLabel(c) + '</span>' +
    '</div>' +
    '<div class="query-line">' + esc(c.query) + '</div>' +
    '<div class="card-actions">' +
      '<a class="open" href="' + esc(c.url) + '" target="_blank" rel="noopener">Lihat di Issue Tracker &#8599;</a>' +
      '<button class="act-btn' + (favs.has(String(c.id)) ? ' fav-on' : '') + '" data-action="fav" data-id="' + esc(c.id) + '" title="Favorit (pin ke atas)">' + (favs.has(String(c.id)) ? '&#9733;' : '&#9734;') + '</button>' +
    '</div>' +
    body +
    foot +
    '</article>';
}

function menuCount(d) {
  const c = (lastData && lastData.categories) ? lastData.categories[String(d.id)] : null;
  return c ? countLabel(c) : '…';
}

function renderMenu(data) {
  const base = configList.length
    ? configList
    : Object.values(data.categories || {}).map(c => ({ id: c.id, title: c.title, query: c.query, description: c.description }));
  const defs = sortDefs(base);
  const q = (document.getElementById('menu-filter').value || '').trim().toLowerCase();
  const filtered = defs.filter(d => !q || ((d.title || '') + ' ' + (d.query || '')).toLowerCase().includes(q));

  let html = '<div class="menu-group">' +
    '<a class="menu-item' + (currentView === 'overview' ? ' active' : '') + '" data-action="menu" data-view="overview">' +
      '<span class="mi-icon">&#9776;</span><span>Ringkasan</span></a>' +
    '<a class="menu-item' + (currentView === 'custom' ? ' active' : '') + '" data-action="menu" data-view="custom">' +
      '<span class="mi-icon">&#9733;</span><span>Pencarian Kustom</span></a>' +
    '<a class="menu-item" href="saved/">' +
      '<span class="mi-icon">&#128190;</span><span>Saved</span></a>' +
    '</div>';

  html += '<div class="menu-group-label">Kategori (' + filtered.length + ')</div>';
  html += filtered.map(d => {
    const active = currentView === 'cat:' + d.id;
    return '<a class="menu-item' + (active ? ' active' : '') + '" data-action="opencat" data-id="' + d.id + '">' +
      '<span class="mi-num">' + pad2(d.id) + '</span>' +
      '<span class="mi-title">' + esc(d.title) + '</span>' +
      '<span class="mi-count">' + menuCount(d) + '</span></a>';
  }).join('');

  document.getElementById('menu').innerHTML = html;
}

function renderOverview(data) {
  const cats = data.categories || {};
  const base = configList.length ? configList : Object.values(cats).map(c => ({ id: c.id, title: c.title, description: c.description }));
  const defs = sortDefs(base);
  let totalIssues = 0;
  Object.values(cats).forEach(c => { if (typeof c.total === 'number') totalIssues += c.total; });

  const stats = '<div class="stats">' +
    '<div class="stat"><div class="num">' + (data.progress || 0) + '/' + (data.total || defs.length) + '</div><div class="lbl">Kategori dimuat</div></div>' +
    '<div class="stat"><div class="num">' + defs.length + '</div><div class="lbl">Total kategori</div></div>' +
    '<div class="stat"><div class="num">' + totalIssues + '</div><div class="lbl">Total isu (terhitung)</div></div>' +
    '</div>';

  const emailPanel = '<div class="panel">' +
    '<div class="panel-head"><strong>Email reporter pribadi</strong>' +
    '<small>Dipakai untuk kategori "Laporan By Mail". Masukkan emailmu untuk memantau laporan yang kamu kirim.</small></div>' +
    '<form id="email-form" class="inline-form" autocomplete="off">' +
    '<input id="email-input" type="email" placeholder="kamu@email.com" spellcheck="false">' +
    '<button type="submit">Terapkan</button>' +
    '<span id="email-status" class="form-status" role="status"></span>' +
    '</form></div>';

  const rows = defs.map(d => {
    const c = cats[String(d.id)];
    return '<a class="cat-row" data-action="opencat" data-id="' + d.id + '">' +
      '<span class="cat-num">' + pad2(d.id) + '</span>' +
      '<span class="cat-title">' + esc(d.title) + '<small>' + esc(d.description || '') + '</small></span>' +
      '<span class="cat-count">' + (c ? countLabel(c) : '…') + '</span>' +
      '<span class="cat-arrow">&#8250;</span></a>';
  }).join('');

  return stats + emailPanel + '<div class="cat-list">' + rows + '</div>';
}

function renderCustomView(data) {
  const cd = data.custom || null;
  const form = '<div class="panel">' +
    '<div class="panel-head"><strong>Pencarian kustom</strong>' +
    '<small>Ketik query issue tracker sendiri, mis. <code style="font-family:var(--mono);font-size:11px">type:vulnerability status:open v8</code></small></div>' +
    '<form id="custom-form" class="inline-form" autocomplete="off">' +
    '<input id="custom-input" type="text" class="mono" placeholder="contoh: status:open component:Blink" spellcheck="false">' +
    '<button type="submit">Cari</button>' +
    '<span id="custom-status" class="form-status" role="status"></span>' +
    '</form></div>';

  let result = '';
  if (cd) {
    if (cd.status === 'fetching') {
      result = '<div class="card card-custom"><div class="card-top"><span class="card-num custom-num">&#9733;</span>' +
        '<div class="card-head"><h2 class="card-title">Pencarian Kustom</h2><div class="card-desc">Mencari: ' + esc(cd.query) + '</div></div></div>' +
        '<div class="empty">Mengambil data dari Issue Tracker…</div></div>';
    } else if (cd.status === 'error') {
      result = '<div class="card card-custom"><div class="card-top"><span class="card-num custom-num">&#9733;</span>' +
        '<div class="card-head"><h2 class="card-title">Pencarian Kustom</h2><div class="card-desc">Query: ' + esc(cd.query) + '</div></div></div>' +
        '<div class="err">Gagal: ' + esc(cd.error) + '</div></div>';
    } else if (cd.status === 'done' && cd.result) {
      result = renderCard(cd.result, true);
    }
  }
  return form + result;
}

function updateTitle(data) {
  const t = document.getElementById('view-title');
  const sub = document.getElementById('view-subtitle');
  if (currentView === 'overview') { t.textContent = 'Ringkasan'; sub.textContent = 'Tampilan umum semua kategori'; }
  else if (currentView === 'custom') { t.textContent = 'Pencarian Kustom'; sub.textContent = 'Cari query isu sendiri'; }
  else {
    const id = currentView.slice(4);
    const c = (data.categories || {})[id];
    if (c) { t.textContent = c.title; sub.textContent = c.description; }
    else {
      const def = configList.find(d => String(d.id) === String(id));
      t.textContent = def ? def.title : 'Kategori';
      sub.textContent = def ? def.description : '';
    }
  }
}

function renderContent(data) {
  const el = document.getElementById('content');
  if (currentView === 'overview') el.innerHTML = renderOverview(data);
  else if (currentView === 'custom') el.innerHTML = renderCustomView(data);
  else {
    const id = currentView.slice(4);
    const c = (data.categories || {})[id];
    if (c) {
      el.innerHTML = renderCard(c);
      triggerRewards(id);
    } else {
      const def = configList.find(d => String(d.id) === String(id));
      el.innerHTML = '<div class="empty">' + (def ? esc(def.title) + '<br>Memuat data dari Issue Tracker…' : 'Kategori tidak ditemukan.') + '</div>';
    }
  }
  const em = document.getElementById('email-input');
  if (em && document.activeElement !== em) em.value = currentEmail;
}

function render(data) {
  lastData = data;
  const st = document.getElementById('status');
  const map = { idle: 'memuat…', fetching: 'memuat…', done: 'selesai', error: 'error' };
  let statusTxt = map[data.status] || data.status;
  if (data.status === 'fetching' && data.total) {
    const pct = Math.round((data.progress || 0) / data.total * 100);
    statusTxt = 'memuat ' + (data.progress || 0) + '/' + data.total + ' (' + pct + '%)';
  }
  st.innerHTML = '<span class="dot"></span>' + statusTxt;
  st.className = 'pill ' + data.status;
  document.getElementById('lastupdate').textContent = data.last_update ? ('Update: ' + data.last_update) : '';

  renderMenu(data);
  // jangan timpa saat user sedang mengetik di input dalam konten
  const active = document.activeElement;
  if (active && active.closest && active.closest('#content') && (active.tagName === 'INPUT')) {
    updateTitle(data);
    return;
  }
  renderContent(data);
  updateTitle(data);
  document.getElementById('refresh').disabled = (data.status === 'fetching');
}

async function load() {
  let data;
  try {
    const r = await fetch('data/summary.json', { cache: 'no-store' });
    data = await r.json();
  } catch (e) {
    const st = document.getElementById('status');
    st.innerHTML = '<span class="dot"></span>server offline';
    st.className = 'pill error';
    return;
  }
  render(data);
}

async function loadSettings() {
  currentEmail = '';
}

async function loadConfig() {
  try {
    const r = await fetch('data/config.json', { cache: 'no-store' });
    configList = await r.json();
  } catch (e) {}
}

async function applyEmail() {
  toast('Mode statis: ubah email tidak tersedia.', 'err');
  return;
  const email = document.getElementById('email-input').value.trim();
  const status = document.getElementById('email-status');
  if (!email) { status.textContent = 'Email kosong.'; status.className = 'form-status err'; return; }
  status.textContent = 'Menyimpan…'; status.className = 'form-status';
  try {
    const r = await fetch('/api/settings', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    const d = await r.json();
    if (r.ok && d.ok) {
      currentEmail = d.email;
      status.textContent = 'Tersimpan · mengambil data…'; status.className = 'form-status ok';
      toast('Email disimpan: ' + d.email);
      setTimeout(() => { status.textContent = ''; status.className = 'form-status'; }, 5000);
      setTimeout(load, 800);
      setTimeout(load, 5000);
    } else {
      status.textContent = d.error || 'Gagal menyimpan.'; status.className = 'form-status err';
      toast(d.error || 'Gagal menyimpan email.', 'err');
    }
  } catch (e) {
    status.textContent = 'Jaringan error.'; status.className = 'form-status err';
  }
}

async function runCustomSearch() {
  toast('Mode statis: pencarian kustom tidak tersedia.', 'err');
  return;
  const q = document.getElementById('custom-input').value.trim();
  const status = document.getElementById('custom-status');
  if (!q) { status.textContent = 'Query kosong.'; status.className = 'form-status err'; return; }
  status.textContent = 'Mencari…'; status.className = 'form-status';
  try {
    const r = await fetch('/api/search', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: q })
    });
    const d = await r.json();
    if (r.ok && d.ok) {
      toast('Mencari: ' + q);
      setTimeout(() => { status.textContent = ''; status.className = 'form-status'; }, 9000);
      setTimeout(load, 500);
      setTimeout(load, 3000);
      setTimeout(load, 8000);
    } else {
      status.textContent = d.error || 'Gagal.'; status.className = 'form-status err';
      toast(d.error || 'Gagal mencari.', 'err');
    }
  } catch (e) {
    status.textContent = 'Jaringan error.'; status.className = 'form-status err';
  }
}

function toggleFav(id) {
  const key = String(id);
  if (favs.has(key)) favs.delete(key); else favs.add(key);
  persistFavs();
  if (lastData) render(lastData);
}

const GH_OWNER = 'abhirdd';
const GH_REPO = 'abhirdd.github.io';
const GH_SAVE_DIR = 'chromium-monitor/saved';

function saveToken() {
  let t = localStorage.getItem('gh_save_token');
  if (!t) {
    t = prompt('Masukkan GitHub Fine-grained PAT (hanya repo abhirdd.github.io, izin Contents: Read/Write):');
    if (!t) return null;
    t = t.trim();
    localStorage.setItem('gh_save_token', t);
  }
  return t;
}

function b64(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function tsStr() {
  const d = new Date();
  const p = n => String(n).padStart(2, '0');
  return '' + d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '_' + p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds());
}

function findIssue(issueId) {
  const cats = (lastData && lastData.categories) || {};
  for (const c of Object.values(cats)) {
    const found = (c.issues || []).find(it => String(it.id) === String(issueId));
    if (found) return { issue: found, category: c };
  }
  return null;
}

async function saveIssue(issueId) {
  const token = saveToken();
  if (!token) { toast('Dibatalkan: token tidak diisi.', 'err'); return; }
  const res = findIssue(issueId);
  if (!res) { toast('Temuan tidak ditemukan.', 'err'); return; }
  const fname = issueId + '.json';
  const path = GH_SAVE_DIR + '/' + fname;
  const apiBase = 'https://api.github.com/repos/' + GH_OWNER + '/' + GH_REPO;
  const payload = {
    saved_at: new Date().toISOString(),
    issue_url: issueUrl(issueId),
    category: res.category.title || '',
    issue: res.issue
  };
  const headers = {
    'Authorization': 'Bearer ' + token,
    'Content-Type': 'application/json',
    'Accept': 'application/vnd.github+json'
  };
  try {
    let sha = null;
    try {
      const g = await fetch(apiBase + '/contents/' + path, { headers: headers });
      if (g.status === 401) { localStorage.removeItem('gh_save_token'); toast('Token salah/kedaluwarsa. Coba lagi.', 'err'); return; }
      if (g.ok) { const gd = await g.json(); sha = gd && gd.sha; }
    } catch (e) {}
    const body = { message: 'Simpan temuan ' + issueId, content: b64(JSON.stringify(payload, null, 2)) };
    if (sha) body.sha = sha;
    const r = await fetch(apiBase + '/contents/' + path, { method: 'PUT', headers: headers, body: JSON.stringify(body) });
    const d = await r.json();
    if (r.status === 401) { localStorage.removeItem('gh_save_token'); toast('Token salah/kedaluwarsa. Coba lagi.', 'err'); return; }
    if (r.ok) { toast('Tersimpan: saved/' + fname); }
    else { toast((d && d.message) || 'Gagal menyimpan.', 'err'); }
  } catch (e) {
    toast('Gagal terhubung ke GitHub.', 'err');
  }
}

function triggerRewards(catId) {
  // mode statis: bounty sudah tertanam di data snapshot
}

document.addEventListener('click', (ev) => {
  const el = ev.target.closest('[data-action]');
  if (!el) return;
  const action = el.getAttribute('data-action');
  if (action === 'menu') {
    currentView = el.getAttribute('data-view');
    if (lastData) render(lastData);
  } else if (action === 'opencat') {
    currentView = 'cat:' + el.getAttribute('data-id');
    if (lastData) render(lastData);
  } else if (action === 'fav') {
    toggleFav(el.getAttribute('data-id'));
  } else if (action === 'save-issue') {
    saveIssue(el.getAttribute('data-id'));
  }
});

document.addEventListener('submit', (ev) => {
  if (ev.target && ev.target.id === 'email-form') { ev.preventDefault(); applyEmail(); }
  else if (ev.target && ev.target.id === 'custom-form') { ev.preventDefault(); runCustomSearch(); }
});

document.getElementById('menu-filter').addEventListener('input', () => { if (lastData) renderMenu(lastData); });

document.getElementById('refresh').addEventListener('click', async () => {
  toast('Mode statis: data snapshot, tidak ada refresh live.', 'err');
  return;
  toast('Mengambil ulang semua data…');
  setTimeout(load, 800);
});

(async function init() {
  await loadSettings();
  await loadConfig();
  await load();
  setInterval(load, 8000);
})();