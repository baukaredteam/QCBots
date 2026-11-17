// Cases list page (Stage F2). Safe text rendering via textContent/createElement.
let state = { limit: 20, offset: 0, total: 0, cases: [] };
let currentIdempotencyKey = '';

function genIdempotencyKey() {
  if (window.crypto && window.crypto.randomUUID) return window.crypto.randomUUID();
  return 'idem-' + Date.now() + '-' + Math.random().toString(16).slice(2);
}

function statusBadgeClass(s) {
  switch (s) {
    case 'OPEN': return 'badge badge-open';
    case 'IN_PROGRESS': return 'badge badge-inprogress';
    case 'REVIEW': return 'badge badge-review';
    case 'ARCHIVED': return 'badge badge-archived';
    default: return 'badge badge-closed';
  }
}
function priorityBadgeClass(p) {
  if (p === 'P1') return 'badge badge-p1';
  if (p === 'P2') return 'badge badge-p2';
  if (p === 'P3') return 'badge badge-p3';
  return 'badge badge-p4';
}

function setState(name) {
  const ids = ['state-loading','state-error','state-forbidden','state-empty','list-view'];
  ids.forEach(id => {
    const e = document.getElementById(id);
    if (e) e.classList.add('hidden');
  });
  if (name === 'loading') document.getElementById('state-loading').classList.remove('hidden');
  if (name === 'error') document.getElementById('state-error').classList.remove('hidden');
  if (name === 'forbidden') document.getElementById('state-forbidden').classList.remove('hidden');
  if (name === 'empty') { document.getElementById('state-empty').classList.remove('hidden'); document.getElementById('list-view').classList.remove('hidden'); }
  if (name === 'ready') document.getElementById('list-view').classList.remove('hidden');
}

async function loadMe() {
  try {
    const me = await api('/api/v1/auth/me');
    document.getElementById('user-name').textContent = me.user.id + ' (' + me.user.role + ')';
    document.getElementById('avatar').textContent = (me.user.id || '?').slice(0,2).toUpperCase();
    document.getElementById('role-info').textContent = 'Role: ' + me.user.role;
    document.getElementById('client-info').textContent = 'Clients: ' + (me.authorized_clients || []).join(', ');
    const clients = me.authorized_clients || [];
    const fc = document.getElementById('f-client');
    const cc = document.getElementById('c-client');
    fc.innerHTML = ''; cc.innerHTML = '';
    const all = document.createElement('option'); all.value = ''; all.textContent = 'All';
    fc.appendChild(all);
    clients.forEach(c => {
      const o1 = document.createElement('option'); o1.value = c; o1.textContent = c; fc.appendChild(o1);
      const o2 = document.createElement('option'); o2.value = c; o2.textContent = c; cc.appendChild(o2);
    });
    return me;
  } catch (e) { /* api.js redirects on 401 */ }
}

async function loadCases() {
  setState('loading');
  const q = new URLSearchParams();
  q.set('limit', String(state.limit)); q.set('offset', String(state.offset));
  const status = document.getElementById('f-status').value;
  const prio = document.getElementById('f-priority').value;
  const client = document.getElementById('f-client').value;
  const search = (document.getElementById('f-search').value || document.getElementById('search').value || '').trim().toLowerCase();
  if (status) q.set('status', status);
  if (prio) q.set('priority', prio);
  if (client) q.set('client_id', client);
  try {
    const data = await api('/api/v1/cases?' + q.toString());
    let cases = data.cases || [];
    if (search) cases = cases.filter(c => (c.title||'').toLowerCase().includes(search) || (c.case_id||'').toLowerCase().includes(search));
    state.cases = cases; state.total = data.total;
    renderCases(cases, data.total);
  } catch (e) {
    if (e && e.status === 403) { setState('forbidden'); return; }
    if (e && e.status === 503) { document.getElementById('error-msg').textContent = 'M6 schema not applied (503).'; setState('error'); return; }
    document.getElementById('error-msg').textContent = (e && e.data && e.data.error && e.data.error.message) || 'Failed to load cases';
    setState('error');
  }
}

function renderCases(cases, total) {
  if (cases.length === 0) { setState('empty'); document.getElementById('cases-tbody').innerHTML = ''; document.getElementById('count-badge').textContent = '0 cases'; document.getElementById('pagination-info').textContent = 'Showing 0 of ' + total; return; }
  setState('ready');
  const tbody = document.getElementById('cases-tbody');
  tbody.innerHTML = '';
  document.getElementById('count-badge').textContent = cases.length + ' of ' + total + ' cases (page)';
  cases.forEach((c, idx) => {
    const tr = document.createElement('tr');
    tr.className = 'clickable fade-in';
    tr.setAttribute('tabindex','0');
    const add = (text) => { const td = document.createElement('td'); td.textContent = text; tr.appendChild(td); return td; };
    add(String(state.offset + idx + 1));
    const idTd = add(c.case_id);
    idTd.firstChild;
    const titleTd = add(c.title || '');
    const statusTd = document.createElement('td');
    const b1 = document.createElement('span'); b1.className = statusBadgeClass(c.status); b1.textContent = c.status; statusTd.appendChild(b1); tr.appendChild(statusTd);
    const priTd = document.createElement('td');
    const b2 = document.createElement('span'); b2.className = priorityBadgeClass(c.priority); b2.textContent = c.priority || '—'; priTd.appendChild(b2); tr.appendChild(priTd);
    add(c.updated_at || '');
    const actTd = document.createElement('td');
    const btn = document.createElement('button'); btn.className = 'btn-icon'; btn.textContent = '👁'; btn.title = 'View case';
    btn.addEventListener('click', (ev) => { ev.stopPropagation(); window.location.href = 'case-detail.html?case_id=' + encodeURIComponent(c.case_id); });
    actTd.appendChild(btn); tr.appendChild(actTd);
    tr.addEventListener('click', () => { window.location.href = 'case-detail.html?case_id=' + encodeURIComponent(c.case_id); });
    tbody.appendChild(tr);
  });
  const shownFrom = total === 0 ? 0 : state.offset + 1;
  const shownTo = state.offset + cases.length;
  document.getElementById('pagination-info').textContent = 'Showing ' + shownFrom + '–' + shownTo + ' of ' + total + ' cases';
  document.getElementById('prev-btn').disabled = state.offset === 0;
  document.getElementById('next-btn').disabled = (state.offset + cases.length) >= total;
}

function openCreateModal() {
  currentIdempotencyKey = genIdempotencyKey();
  document.getElementById('c-idem').value = currentIdempotencyKey;
  document.getElementById('create-modal').classList.add('open');
}
function closeCreateModal() { document.getElementById('create-modal').classList.remove('open'); }

document.addEventListener('DOMContentLoaded', async () => {
  await loadMe();
  await loadCases();
  document.getElementById('retry-btn').addEventListener('click', loadCases);
  document.getElementById('prev-btn').addEventListener('click', () => { if (state.offset >= state.limit) { state.offset -= state.limit; loadCases(); } });
  document.getElementById('next-btn').addEventListener('click', () => { state.offset += state.limit; loadCases(); });
  ['f-status','f-priority','f-client'].forEach(id => document.getElementById(id).addEventListener('change', () => { state.offset = 0; loadCases(); }));
  document.getElementById('f-search').addEventListener('input', () => { state.offset = 0; loadCases(); });
  document.getElementById('search').addEventListener('input', () => { document.getElementById('f-search').value = document.getElementById('search').value; state.offset = 0; loadCases(); });
  document.getElementById('clear-filters').addEventListener('click', (e) => { e.preventDefault(); document.getElementById('f-search').value=''; document.getElementById('f-status').value=''; document.getElementById('f-priority').value=''; document.getElementById('f-client').value=''; state.offset=0; loadCases(); });
  document.getElementById('new-case-btn').addEventListener('click', openCreateModal);
  document.getElementById('close-modal-btn').addEventListener('click', closeCreateModal);
  document.getElementById('cancel-create').addEventListener('click', closeCreateModal);
  document.getElementById('create-modal').addEventListener('click', (e) => { if (e.target.id === 'create-modal') closeCreateModal(); });
  document.getElementById('create-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errBox = document.getElementById('create-error'); errBox.textContent = '';
    const payload = {
      title: document.getElementById('c-title').value.trim(),
      description: document.getElementById('c-desc').value.trim(),
      initial_client_id: document.getElementById('c-client').value,
      priority: document.getElementById('c-priority').value,
      severity: document.getElementById('c-severity').value,
      idempotency_key: currentIdempotencyKey // stable across retries
    };
    if (!payload.title) { errBox.textContent = 'Title required'; return; }
    try {
      const created = await api('/api/v1/cases', { method: 'POST', body: payload });
      closeCreateModal();
      // Navigate to detail using safe href
      window.location.href = 'case-detail.html?case_id=' + encodeURIComponent(created.case_id);
    } catch (err) {
      if (err && err.status === 409) {
        errBox.textContent = 'Conflict: idempotency key reused with different payload. Reload cases.';
        // Keep same idempotency key on retry (do not regenerate)
        return;
      }
      errBox.textContent = (err && err.data && err.data.error && err.data.error.message) || ('Create failed: ' + (err && err.status || 'network'));
    }
  });
  document.getElementById('logout-btn').addEventListener('click', async () => {
    try { await api('/api/v1/auth/logout', { method: 'POST', body: {} }); } catch (_) {}
    window.location.href = 'login.html';
  });
});
