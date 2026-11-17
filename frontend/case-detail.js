// Case detail (Stage F3/F4). All untrusted content via textContent.
const params = new URLSearchParams(window.location.search);
const caseID = params.get('case_id') || '';
let selectedArtifactId = '';
let me = null;

function setState(name) {
  ['state-loading','state-forbidden','state-error','detail-view'].forEach(id => document.getElementById(id).classList.add('hidden'));
  if (name === 'loading') document.getElementById('state-loading').classList.remove('hidden');
  if (name === 'forbidden') document.getElementById('state-forbidden').classList.remove('hidden');
  if (name === 'error') document.getElementById('state-error').classList.remove('hidden');
  if (name === 'ready') document.getElementById('detail-view').classList.remove('hidden');
}
function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
  const panel = document.getElementById('tab-' + name);
  if (panel) panel.classList.remove('hidden');
  if (name === 'participants') loadParticipants();
  if (name === 'artifacts') loadArtifacts();
  if (name === 'notes') loadNotes();
  if (name === 'activity') loadActivity();
  if (name === 'hypotheses') { loadHypotheses(); loadInvestigations(); }
}

async function loadMe() {
  try {
    me = await api('/api/v1/auth/me');
    document.getElementById('user-name').textContent = me.user.id + ' (' + me.user.role + ')';
    document.getElementById('avatar').textContent = (me.user.id || '?').slice(0,2).toUpperCase();
    document.getElementById('role-info').textContent = 'Role: ' + me.user.role;
    document.getElementById('client-info').textContent = 'Clients: ' + (me.authorized_clients || []).join(', ');
  } catch (_) {}
}

async function loadCase() {
  setState('loading');
  if (!caseID) { document.getElementById('error-msg').textContent = 'Missing case_id'; setState('error'); return; }
  try {
    const c = await api('/api/v1/cases/' + encodeURIComponent(caseID));
    document.getElementById('case-title').textContent = c.title || 'Case';
    document.getElementById('case-sub').textContent = 'Case ' + c.case_id + ' • Owner ' + c.owner_id;
    const badges = document.getElementById('case-badges');
    badges.innerHTML = '';
    const s = document.createElement('span');
    s.className = 'badge ' + (c.status === 'OPEN' ? 'badge-open' : c.status === 'IN_PROGRESS' ? 'badge-inprogress' : c.status === 'REVIEW' ? 'badge-review' : 'badge-closed');
    s.textContent = c.status;
    badges.appendChild(s);
    // Overview (V1.1): title/description/owner/timestamps/status/priority + summaries
    document.getElementById('ov-title').textContent = c.title || '—';
    document.getElementById('ov-desc').textContent = c.description || 'No description provided.';
    document.getElementById('ov-owner').textContent = c.owner_id || '—';
    document.getElementById('ov-times').textContent = 'Created: ' + (c.created_at || '—') + ' • Updated: ' + (c.updated_at || '—');
    const ovBadges = document.getElementById('ov-badges'); ovBadges.innerHTML = '';
    ovBadges.appendChild(s.cloneNode(true));
    // Participants / hypotheses / artifacts / activity summaries (real data only)
    try {
      const parts = await api('/api/v1/cases/' + encodeURIComponent(caseID) + '/participants');
      document.getElementById('ov-participants').textContent = (parts.participants||[]).length ? (parts.participants||[]).map(p=>p.user_id+' ('+p.role_in_case+')').join(', ') : 'No participants';
    } catch (_) { document.getElementById('ov-participants').textContent = 'Not available'; }
    try {
      const hyps = await api('/api/v1/cases/' + encodeURIComponent(caseID) + '/hypotheses?limit=5&offset=0');
      document.getElementById('ov-hypotheses').textContent = (hyps.hypotheses||[]).length ? (hyps.hypotheses||[]).map(h=>h.hypothesis_id+' • '+h.client_id+(h.latest_decision? ' • latest '+h.latest_decision : '')).join('; ') : 'No linked hypotheses visible';
    } catch (_) { document.getElementById('ov-hypotheses').textContent = 'Not available'; }
    try {
      const ctx = await api('/api/v1/cases/' + encodeURIComponent(caseID));
      const arts = ctx.artifacts || [];
      document.getElementById('ov-artifacts').textContent = arts.length ? arts.length + ' visible artifacts (' + arts.map(a=>a.artifact_id).join(', ') + ')' : 'No visible artifacts';
    } catch (_) { document.getElementById('ov-artifacts').textContent = 'Not available'; }
    try {
      const act = await api('/api/v1/cases/' + encodeURIComponent(caseID) + '/activity?limit=5&offset=0');
      document.getElementById('ov-activity').textContent = (act.activity||[]).length ? (act.activity||[]).map(a=>a.action+' '+a.created_at).join('; ') : 'No recent activity';
    } catch (_) { document.getElementById('ov-activity').textContent = 'Not available'; }
    setState('ready');
    await populateHypSelects();
  } catch (e) {
    if (e && (e.status === 403 || e.status === 401)) { setState('forbidden'); return; }
    document.getElementById('error-msg').textContent = (e && e.data && e.data.error && e.data.error.message) || 'Failed to load case';
    setState('error');
  }
}

async function populateHypSelects() {
  // Available hypotheses for the user (grant-filtered) + client selects from authorized clients.
  const linked = await api('/api/v1/cases/' + encodeURIComponent(caseID) + '/hypotheses?limit=100&offset=0').catch(() => ({hypotheses:[]}));
  const avail = await api('/api/v1/hypotheses?limit=100&offset=0').catch(() => ({hypotheses:[]}));
  const fill = (id, list, linkedOnly) => {
    const sel = document.getElementById(id); if (!sel) return;
    sel.innerHTML = '';
    const ph = document.createElement('option'); ph.value = ''; ph.textContent = linkedOnly ? 'Select linked hypothesis…' : 'Select hypothesis…'; sel.appendChild(ph);
    (list || []).forEach(h => { const o = document.createElement('option'); o.value = h.hypothesis_id; o.textContent = h.hypothesis_id + ' • ' + h.title + ' • ' + h.client_id; sel.appendChild(o); });
  };
  fill('hyp-select', avail.hypotheses || [], false);
  fill('hr-hyp', linked.hypotheses || [], true);
  fill('inv-hyp', linked.hypotheses || [], true);
  // Client selects from authorized clients.
  const clients = (me && me.authorized_clients) || [];
  ['hyp-client-select','hr-client','inv-client'].forEach(id => {
    const sel = document.getElementById(id); if (!sel) return;
    sel.innerHTML = '';
    const ph = document.createElement('option'); ph.value = ''; ph.textContent = 'Select client…'; sel.appendChild(ph);
    clients.forEach(c => { const o = document.createElement('option'); o.value = c; o.textContent = c; sel.appendChild(o); });
  });
  // Keep inv-client plausible: default to the first authorized client.
  const invClient = document.getElementById('inv-client');
  if (invClient && clients.length) invClient.value = clients[0];
}

async function loadParticipants() {
  const box = document.getElementById('participants-list'); box.innerHTML = '';
  try {
    const data = await api('/api/v1/cases/' + encodeURIComponent(caseID) + '/participants');
    (data.participants || []).forEach(p => {
      const d = document.createElement('div'); d.className = 'list-item';
      d.textContent = p.user_id + ' • ' + p.role_in_case + ' • granted ' + p.granted_at;
      d.dataset.userId = p.user_id;
      d.addEventListener('click', () => { document.getElementById('part-user').value = p.user_id; });
      box.appendChild(d);
    });
    if ((data.participants||[]).length === 0) box.textContent = 'No participants';
  } catch (e) { box.textContent = (e && e.data && e.data.error && e.data.error.message) || 'Failed to load participants'; }
}

async function loadArtifacts() {
  const box = document.getElementById('artifacts-list'); box.innerHTML = '';
  try {
    const ctx = await api('/api/v1/cases/' + encodeURIComponent(caseID));
    (ctx.artifacts || []).forEach(a => {
      const d = document.createElement('div'); d.className = 'list-item';
      const title = document.createElement('div'); title.textContent = 'Artifact ' + a.artifact_id + ' • ' + a.visibility_scope + ' • ' + (a.client_id || 'GLOBAL') + ' • ' + a.data_classification;
      const body = document.createElement('div'); body.textContent = a.sanitized_representation || '(no content / summary only)';
      const status = document.createElement('div'); status.textContent = 'Access: ' + a.access_status + ' • Detail: ' + a.detail_level;
      const btn = document.createElement('button'); btn.className = 'btn btn-secondary btn-sm'; btn.textContent = 'Review';
      btn.addEventListener('click', () => { selectedArtifactId = a.artifact_id; document.getElementById('review-form').classList.remove('hidden'); });
      d.appendChild(title); d.appendChild(body); d.appendChild(status); d.appendChild(btn);
      box.appendChild(d);
    });
    if ((ctx.artifacts||[]).length === 0) box.textContent = 'No artifacts visible';
  } catch (e) { box.textContent = (e && e.data && e.data.error && e.data.error.message) || 'Failed to load artifacts'; }
}

async function loadNotes() {
  const box = document.getElementById('notes-list'); box.innerHTML = '';
  try {
    const data = await api('/api/v1/cases/' + encodeURIComponent(caseID) + '/notes?limit=100&offset=0');
    (data.notes || []).forEach(n => {
      const d = document.createElement('div'); d.className = 'note';
      const head = document.createElement('div'); head.textContent = n.note_type + ' • ' + n.visibility_scope + ' • ' + (n.client_id || 'GLOBAL') + ' • by ' + n.user_id + ' • ' + n.created_at;
      const body = document.createElement('p'); body.textContent = n.note_text;
      d.appendChild(head); d.appendChild(body);
      (n.revisions || []).forEach(r => {
        const rev = document.createElement('div'); rev.className = 'rev';
        rev.textContent = 'Rev ' + r.created_at + ' by ' + r.created_by + ': ' + r.note_text;
        d.appendChild(rev);
      });
      box.appendChild(d);
    });
    if ((data.notes||[]).length === 0) box.textContent = 'No notes visible';
  } catch (e) { box.textContent = (e && e.data && e.data.error && e.data.error.message) || 'Failed to load notes'; }
}

async function loadActivity() {
  const box = document.getElementById('activity-list'); box.innerHTML = '';
  try {
    const data = await api('/api/v1/cases/' + encodeURIComponent(caseID) + '/activity?limit=100&offset=0');
    document.getElementById('activity-total').textContent = 'Total (visible): ' + data.total;
    (data.activity || []).forEach(a => {
      const d = document.createElement('div'); d.className = 'act-row';
      const t = document.createElement('span'); t.textContent = a.created_at;
      const act = document.createElement('span'); act.textContent = a.action + ' • ' + a.visibility_scope + ' • ' + (a.client_id || 'GLOBAL');
      const det = document.createElement('span'); det.textContent = a.details || '';
      d.appendChild(t); d.appendChild(act); d.appendChild(det);
      box.appendChild(d);
    });
    if ((data.activity||[]).length === 0) box.textContent = 'No activity visible';
  } catch (e) { box.textContent = (e && e.data && e.data.error && e.data.error.message) || 'Failed to load activity'; }
}

async function loadHypotheses() {
  const box = document.getElementById('hyp-list'); box.innerHTML = '';
  try {
    const data = await api('/api/v1/cases/' + encodeURIComponent(caseID) + '/hypotheses?limit=100&offset=0');
    (data.hypotheses || []).forEach(h => {
      const d = document.createElement('div'); d.className = 'list-item';
      const t = document.createElement('div'); t.textContent = h.hypothesis_id + ' • ' + h.title + ' • ' + h.client_id + ' • ' + h.status;
      const latest = document.createElement('div'); latest.textContent = h.latest_decision ? ('Latest: ' + h.latest_decision + ' (' + h.latest_review_id + ')') : 'Latest: none';
      d.appendChild(t); d.appendChild(latest);
      box.appendChild(d);
    });
    if ((data.hypotheses||[]).length === 0) box.textContent = 'No linked hypotheses visible';
  } catch (e) { box.textContent = (e && e.data && e.data.error && e.data.error.message) || 'Failed to load hypotheses'; }
}

async function loadInvestigations() {
  const box = document.createElement('div'); box.id = 'inv-list';
  const host = document.getElementById('hyp-list');
  if (!host) return;
  // Append investigations block below hypotheses list.
  let section = document.getElementById('inv-section');
  if (!section) {
    section = document.createElement('div'); section.id = 'inv-section';
    section.style.marginTop = '1rem';
    const h = document.createElement('div'); h.className = 'filter-label'; h.textContent = 'Investigations (visible only)';
    const list = document.createElement('div'); list.id = 'inv-rows';
    section.appendChild(h); section.appendChild(list);
    host.parentNode.appendChild(section);
  }
  const list = document.getElementById('inv-rows'); list.innerHTML = '';
  try {
    const data = await api('/api/v1/cases/' + encodeURIComponent(caseID) + '/investigations?limit=100&offset=0');
    (data.investigations || []).forEach(inv => {
      const d = document.createElement('div'); d.className = 'list-item';
      const t = document.createElement('div'); t.textContent = inv.investigation_id + ' • ' + inv.hypothesis_id + ' • ' + inv.client_id + ' • ' + (inv.final_verdict || 'no verdict');
      const s = document.createElement('div'); s.textContent = 'Analyst ' + inv.analyst_id + ' • ' + inv.created_at;
      d.appendChild(t); d.appendChild(s);
      list.appendChild(d);
    });
    if ((data.investigations||[]).length === 0) list.textContent = 'No investigations visible';
  } catch (e) { list.textContent = (e && e.data && e.data.error && e.data.error.message) || 'Failed to load investigations'; }
}

document.addEventListener('DOMContentLoaded', async () => {
  await loadMe();
  await loadCase();
  document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => switchTab(t.dataset.tab)));
  document.getElementById('transition-btn').addEventListener('click', async () => {
    const errBox = document.getElementById('transition-error'); errBox.textContent = '';
    try {
      await api('/api/v1/cases/' + encodeURIComponent(caseID) + '/status', { method: 'PUT', body: { status: document.getElementById('new-status').value, closed_reason: document.getElementById('close-reason').value } });
      await loadCase();
    } catch (e) { errBox.textContent = (e && e.data && e.data.error && e.data.error.message) || 'Transition failed'; }
  });
  document.getElementById('reload-parts').addEventListener('click', loadParticipants);
  document.getElementById('add-part-btn').addEventListener('click', async () => {
    const errBox = document.getElementById('part-error'); errBox.textContent = '';
    try {
      await api('/api/v1/cases/' + encodeURIComponent(caseID) + '/participants', { method: 'POST', body: { user_id: document.getElementById('part-user').value.trim(), role_in_case: document.getElementById('part-role').value } });
      loadParticipants();
    } catch (e) { errBox.textContent = (e && e.data && e.data.error && e.data.error.message) || 'Add failed'; }
  });
  document.getElementById('remove-part-btn').addEventListener('click', async () => {
    const errBox = document.getElementById('part-error'); errBox.textContent = '';
    const uid = document.getElementById('part-user').value.trim();
    if (!uid) { errBox.textContent = 'Enter user_id to revoke'; return; }
    try {
      await api('/api/v1/cases/' + encodeURIComponent(caseID) + '/participants/' + encodeURIComponent(uid), { method: 'DELETE' });
      loadParticipants();
    } catch (e) { errBox.textContent = (e && e.data && e.data.error && e.data.error.message) || 'Revoke failed'; }
  });
  document.getElementById('submit-review').addEventListener('click', async () => {
    const errBox = document.getElementById('review-error'); const okBox = document.getElementById('review-ok');
    errBox.textContent = ''; okBox.textContent = '';
    if (!selectedArtifactId) { errBox.textContent = 'Select an artifact first'; return; }
    try {
      const res = await api('/api/v1/cases/' + encodeURIComponent(caseID) + '/artifacts/' + encodeURIComponent(selectedArtifactId) + '/review', { method: 'PUT', body: { decision: document.getElementById('review-decision').value, reason: document.getElementById('review-reason').value } });
      okBox.textContent = 'Reviewed: ' + res.decision;
      loadArtifacts(); loadActivity();
    } catch (e) { errBox.textContent = (e && e.data && e.data.error && e.data.error.message) || 'Review failed'; }
  });
  document.getElementById('note-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errBox = document.getElementById('note-error'); errBox.textContent = '';
    try {
      await api('/api/v1/cases/' + encodeURIComponent(caseID) + '/notes', { method: 'POST', body: { note_text: document.getElementById('note-text').value, note_type: document.getElementById('note-type').value, visibility_scope: document.getElementById('note-scope').value, client_id: document.getElementById('note-client').value.trim() } });
      document.getElementById('note-text').value = '';
      loadNotes(); loadActivity();
    } catch (err) { errBox.textContent = (err && err.data && err.data.error && err.data.error.message) || 'Add note failed'; }
  });
  document.getElementById('link-hyp-btn').addEventListener('click', async () => {
    const errBox = document.getElementById('hyp-error'); errBox.textContent = '';
    const hid = document.getElementById('hyp-select').value;
    if (!hid) { errBox.textContent = 'Select a hypothesis'; return; }
    try { await api('/api/v1/cases/' + encodeURIComponent(caseID) + '/hypotheses/' + encodeURIComponent(hid), { method: 'POST', body: {} }); loadHypotheses(); populateHypSelects(); }
    catch (e) { errBox.textContent = (e && e.data && e.data.error && e.data.error.message) || 'Link failed'; }
  });
  document.getElementById('unlink-hyp-btn').addEventListener('click', async () => {
    const errBox = document.getElementById('hyp-error'); errBox.textContent = '';
    const hid = document.getElementById('hr-hyp').value || document.getElementById('hyp-select').value;
    if (!hid) { errBox.textContent = 'Select a linked hypothesis'; return; }
    try { await api('/api/v1/cases/' + encodeURIComponent(caseID) + '/hypotheses/' + encodeURIComponent(hid), { method: 'DELETE' }); loadHypotheses(); populateHypSelects(); }
    catch (e) { errBox.textContent = (e && e.data && e.data.error && e.data.error.message) || 'Unlink failed'; }
  });
  document.getElementById('hyp-review-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errBox = document.getElementById('hr-error'); errBox.textContent = '';
    try {
      await api('/api/v1/cases/' + encodeURIComponent(caseID) + '/hypotheses/' + encodeURIComponent(document.getElementById('hr-hyp').value) + '/review', { method: 'POST', body: { client_id: document.getElementById('hr-client').value, decision: document.getElementById('hr-decision').value, reason: '' } });
      loadHypotheses(); populateHypSelects();
    } catch (err) { errBox.textContent = (err && err.data && err.data.error && err.data.error.message) || 'Review failed'; }
  });
  document.getElementById('inv-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errBox = document.getElementById('inv-error'); const okBox = document.getElementById('inv-ok');
    errBox.textContent = ''; okBox.textContent = '';
    try {
      const inv = await api('/api/v1/cases/' + encodeURIComponent(caseID) + '/investigations', { method: 'POST', body: { hypothesis_id: document.getElementById('inv-hyp').value, client_id: document.getElementById('inv-client').value, time_range: document.getElementById('inv-range').value.trim(), evidence: '', analyst_findings: '' } });
      okBox.textContent = 'Investigation created: ' + inv.investigation_id;
      loadActivity(); loadInvestigations();
    } catch (err) { errBox.textContent = (err && err.data && err.data.error && err.data.error.message) || 'Create investigation failed'; }
  });
  document.getElementById('logout-btn').addEventListener('click', async () => {
    try { await api('/api/v1/auth/logout', { method: 'POST', body: {} }); } catch (_) {}
    window.location.href = 'login.html';
  });
});
