"use strict";
/* V3 shell.js — routing, cases explorer, case workspace (V3-F3 renders '#case' here). */
const ROUTES = [
  ['HOME',[['home','⌂','Analyst Home','M6'],['mywork','◷','My Work','FRONTEND-ONLY'],['reviews','✓','Review Queue','GAP']]],
  ['INTELLIGENCE',[['feed','≋','Intelligence Feed','GAP'],['reports','▤','Report Explorer','EXISTS'],['entities','◇','Threat Entities','GAP'],['cases','▣','Research Cases','M6'],['case','⊞','Case Workspace','M6']]],
  ['THREAT HUNTING',[['hypotheses','⚑','Hypothesis Lab','M6'],['hunt','⌕','Hunt Workspace','2B-4B']]],
  ['DETECTION ENGINEERING',[['detection','▥','Detection Coverage','PARTIAL'],['qradar','⌘','QRadar Inventory','EXISTS'],['fields','⊞','Field Intelligence','EXISTS'],['inventory','I','Inventory Workspace','M7-F']]],
  ['SOC OPERATIONS',[['clients','◫','Client Intelligence','PARTIAL'],['investigations','◉','Investigations','M6']]],
  ['KNOWLEDGE',[['graph','⬡','Evidence Graph','GAP']]],
  ['ADMINISTRATION',[['settings','⚙','Settings & Access','GAP']]]
];
let current = 'home';
let me = null;
let casesState = { limit: 20, offset: 0, total: 0, search: '', status: '', priority: '', client: '' };
let currentCaseId = '';
let currentIdempotencyKey = '';
let caseData = null; // refreshed per case/context; invalidated on scope changes.

function escEl(tag, text, cls) { const n = document.createElement(tag); if (text != null) n.textContent = text; if (cls) n.className = cls; return n; }
// Bounded fetch: hangs become honest Error states instead of eternal Loading…
function withTimeout(promise, ms, label) {
  return Promise.race([promise, new Promise((_, rej) => setTimeout(() => rej({ status: 0, data: { error: { message: (label || 'Request') + ' timed out after ' + ms + 'ms' } } }), ms))]);
}
function statusBadgeClass(s) {
  s = (s||'').toLowerCase();
  if (s.includes('progress')||s.includes('open')) return 'badge mint';
  if (s.includes('review')||s.includes('high')||s.includes('pending')||s.includes('needs')) return 'badge amber';
  if (s.includes('closed')||s.includes('approved')) return 'badge mint';
  return 'badge muted';
}

function renderNav(){
  const nav = document.getElementById('nav');
  nav.innerHTML = '';
  ROUTES.forEach(([group, rows]) => {
    const g = document.createElement('div'); g.className = 'navgroup'; g.textContent = group; nav.appendChild(g);
    rows.forEach(([id, icon, label, tag]) => {
      const b = document.createElement('button');
      b.className = 'navitem' + (id === current ? ' active' : '');
      b.setAttribute('data-go', id);
      if (id === current) b.setAttribute('aria-current', 'page');
      const ic = document.createElement('span'); ic.className = 'navicon'; ic.textContent = icon;
      const lb = document.createElement('span'); lb.className = 'navlabel'; lb.textContent = label;
      b.appendChild(ic); b.appendChild(lb);
      if (tag) { const t = document.createElement('span'); t.className = 'navtag'; t.textContent = tag; b.appendChild(t); }
      nav.appendChild(b);
    });
  });
}

/* ---------- V3-F4: Analyst Home ---------- */
let homeCtl = { seq: 0 };
let feedCtl = { seq: 0, selectSeq: 0, clientId: '', reportId: '', idemKey: '', idemPayloadHash: '' };
async function renderHome() {
  const seq = ++homeCtl.seq;
  const c = document.getElementById('content');
  c.textContent = '';
  const grantList = (me.authorized_clients || []).join(', ') || 'No CLIENT grants (metadata only)';
  const heading = document.createElement('div'); heading.className = 'heading';
  const left = document.createElement('div');
  left.appendChild(escEl('div', 'YOUR INTELLIGENCE DESK', 'eyebrow'));
  left.appendChild(escEl('h1', 'Good afternoon, Analyst'));
  const sub = escEl('p', 'Your research, review work, and threat intelligence in one place. Authorized contexts: ' + grantList + '.');
  left.appendChild(sub);
  const actions = document.createElement('div');
  const openBtn = escEl('button', 'Open research cases', 'btn primary');
  openBtn.addEventListener('click', () => navigate('cases'));
  actions.appendChild(openBtn);
  heading.append(left, actions);
  c.appendChild(heading);

  const banner = document.createElement('div'); banner.className = 'demo-banner';
  banner.appendChild(escEl('span', 'HYBRID · CTI + SOC — Real APIs via cookie-session; environment not verified in UI.', null));
  banner.appendChild(escEl('span', 'M6', 'badge mint'));
  c.appendChild(banner);

  const grid = document.createElement('div'); grid.className = 'grid2';
  const mkPanel = (title) => {
    const panel = document.createElement('article'); panel.className = 'panel';
    const h = document.createElement('div'); h.className = 'panelhead';
    h.appendChild(escEl('div', title, 'paneltitle'));
    const b = document.createElement('div'); b.className = 'panelbody'; b.textContent = 'Loading…';
    b.id = 'home-' + title.replace(/[^a-z]+/gi, '-').toLowerCase();
    panel.append(h, b);
    grid.appendChild(panel);
    return b;
  };
  const casesBox = mkPanel('My Research Cases');
  const actionsBox = mkPanel('My Work / Actions');
  const reviewsBox = mkPanel('Pending Human Reviews (per-case sample)');
  const ctiBox = mkPanel('Intelligence Updates');
  const actBox = mkPanel('Recent Activity');
  c.appendChild(grid);

  // 1) My Research Cases — GET /api/v1/cases (bounded)
  try {
    const data = await api('/api/v1/cases?limit=5&offset=0');
    if (seq !== homeCtl.seq) return;
    casesBox.innerHTML = '';
    (data.cases || []).forEach(cs => {
      const row = document.createElement('div'); row.className = 'home-case';
      const main = document.createElement('div'); main.className = 'home-case-main';
      main.appendChild(escEl('strong', cs.title || 'Untitled', 'home-case-title'));
      const badges = document.createElement('div'); badges.className = 'home-case-badges';
      badges.appendChild(escEl('span', cs.status || '—', statusBadgeClass(cs.status)));
      badges.appendChild(escEl('span', cs.priority || '—', statusBadgeClass(cs.priority)));
      main.appendChild(badges);
      const meta = escEl('div', (cs.case_id ? cs.case_id.slice(0, 8) + '…' : '') + (cs.updated_at ? ' • ' + cs.updated_at : ''), 'text-muted home-case-meta');
      main.appendChild(meta);
      row.appendChild(main);
      const btn = escEl('button', 'Open', 'btn small home-case-open');
      btn.addEventListener('click', () => { currentCaseId = cs.case_id; navigate('case', { case_id: cs.case_id }); });
      row.appendChild(btn);
      casesBox.appendChild(row);
    });
    if (!(data.cases || []).length) casesBox.textContent = 'No cases visible.';
  } catch (e) {
    if (seq !== homeCtl.seq) return;
    casesBox.textContent = (e && e.status === 503) ? 'M6 schema not applied (503).' : ((e && e.data && e.data.error && e.data.error.message) || 'Failed to load cases');
  }

  // 2) My Work — derived from role + grants (no fabricated assignments)
  {
    const role = me.user.role;
    const grants = me.authorized_clients || [];
    actionsBox.innerHTML = '';
    const lines = [
      'Role: ' + role,
      'Authorized clients: ' + (grants.length ? grants.join(', ') : 'none — metadata only'),
      'Case CREATE: ' + (role === 'CTI_ANALYST' || role === 'ADMINISTRATOR' ? 'allowed (grant still required)' : 'denied'),
      'Hypothesis LINK: ' + (['CTI_ANALYST','HYPOTHESIS_WRITER','ADMINISTRATOR'].includes(role) ? 'allowed' : 'denied'),
      'Review (artifact/hypothesis): ' + (role === 'ADMINISTRATOR' || role === 'REVIEWER' ? 'allowed' : 'denied')
    ];
    lines.forEach(l => actionsBox.appendChild(escEl('div', l, 'text-muted')));
    const nav = escEl('button', 'Open Research Cases', 'btn primary'); nav.style.marginTop = '12px';
    nav.addEventListener('click', () => navigate('cases'));
    actionsBox.appendChild(nav);
  }

  // 3) Pending reviews — no reliable pending signal in CaseContext (review_decision
  // is not exposed via GET /cases/{id}); show honest limitation, never invented tasks.
  // Visible artifacts below are navigation hints ONLY — not a pending queue.
  {
    reviewsBox.innerHTML = '';
    const role = me.user.role;
    const canReview = (role === 'ADMINISTRATOR' || role === 'REVIEWER');
    const hint = escEl('div', 'Review Queue requires backend aggregation: GET /cases/{id} does not expose review_decision/review_status, so pending reviews cannot be determined reliably. ' + (canReview ? 'Your role (' + role + ') has REVIEW permission, but the queue itself is not computed.' : 'Your role (' + role + ') has no REVIEW permission.'), 'text-muted');
    reviewsBox.appendChild(hint);
    try {
      const list = await api('/api/v1/cases?limit=5&offset=0');
      if (seq !== homeCtl.seq) return;
      let shown = 0;
      for (const cs of (list.cases || [])) {
        if (shown >= 5) break;
        if (seq !== homeCtl.seq) return;
        const ctx = await api('/api/v1/cases/' + encodeURIComponent(cs.case_id));
        if (seq !== homeCtl.seq) return;
        (ctx.artifacts || []).forEach(a => {
          if (a.access_status === 'VISIBLE' && a.detail_level !== 'NONE') {
            const row = escEl('div', 'Visible artifact ' + a.artifact_id + ' • ' + (a.client_id || 'GLOBAL') + ' • ' + a.data_classification + ' • Case ' + (cs.title || cs.case_id.slice(0,12)) + ' (not a pending queue)', 'row');
            reviewsBox.appendChild(row);
            shown++;
          }
        });
      }
      if (!shown) reviewsBox.appendChild(escEl('div', 'No visible artifacts in the sampled cases.', 'text-muted'));
    } catch (_) {
      if (seq !== homeCtl.seq) return;
      reviewsBox.appendChild(escEl('div', 'Review preview unavailable.', 'text-muted'));
    }
  }

  // 4) Intelligence Updates — honors the selected client context.
  // Global Research skips ONLY this per-client fetch; other panels continue.
  {
    ctiBox.innerHTML = '';
    const ctx = document.getElementById('tenant') ? document.getElementById('tenant').value : 'global';
    if (ctx === 'global') {
      const hint = escEl('div', 'Global Research = metadata only. Select an authorized client above to load CTI reports (per-client list; no global feed). Recent Activity and other panels below are unaffected.', 'text-muted');
      ctiBox.appendChild(hint);
    } else if (!me.authorized_clients.includes(ctx)) {
      ctiBox.textContent = 'No grant for selected client — CTI updates unavailable.';
    } else {
      try {
        const data = await api('/api/v1/tenants/' + encodeURIComponent(ctx) + '/cti/reports');
        if (seq !== homeCtl.seq) return;
        const reports = (data.reports || []).slice(0, 5);
        if (!reports.length) { ctiBox.textContent = 'No authorized reports for ' + ctx + '.'; }
        else {
          const label = escEl('div', 'Authorized reports for ' + ctx + ' (per-client list; no global feed)', 'text-muted');
          ctiBox.appendChild(label);
          reports.forEach(r => ctiBox.appendChild(escEl('div', '• ' + (r.title || r.report_id), 'row')));
        }
      } catch (_) {
        if (seq !== homeCtl.seq) return;
        ctiBox.textContent = 'CTI updates unavailable.';
      }
    }
  }

  // 5) Recent Activity — bounded (first 3 cases, capped)
  {
    actBox.innerHTML = '';
    const hint = escEl('div', 'Visible events from up to 3 accessible cases.', 'text-muted');
    actBox.appendChild(hint);
    try {
      const list = await api('/api/v1/cases?limit=3&offset=0');
      if (seq !== homeCtl.seq) return;
      let shown = 0;
      for (const cs of (list.cases || [])) {
        if (shown >= 10) break;
        if (seq !== homeCtl.seq) return;
        const act = await api('/api/v1/cases/' + encodeURIComponent(cs.case_id) + '/activity?limit=5&offset=0');
        if (seq !== homeCtl.seq) return;
        (act.activity || []).forEach(a => {
          if (shown < 10) {
            actBox.appendChild(escEl('div', '• ' + (cs.title || cs.case_id.slice(0,12)) + ' — ' + a.action + ' ' + a.created_at, 'row'));
            shown++;
          }
        });
      }
      if (!shown) actBox.appendChild(escEl('div', 'No recent visible activity.', 'text-muted'));
    } catch (_) {
      if (seq !== homeCtl.seq) return;
      actBox.appendChild(escEl('div', 'Activity unavailable.', 'text-muted'));
    }
  }
}

/* ---------- V3-F5: Intelligence Hub ---------- */
async function renderFeed() {
  const seq = ++feedCtl.seq;
  const grantList = (me.authorized_clients || []);
  const topCtx = document.getElementById('tenant') ? document.getElementById('tenant').value : 'global';
  const startClient = (topCtx !== 'global' && grantList.includes(topCtx)) ? topCtx : '';
  feedCtl.clientId = startClient; feedCtl.reportId = '';
  const c = document.getElementById('content');
  c.innerHTML = '';
  const heading = document.createElement('div'); heading.className = 'heading';
  const left = document.createElement('div');
  left.appendChild(escEl('div', 'INTELLIGENCE / REPORTS', 'eyebrow'));
  left.appendChild(escEl('h1', 'Intelligence Hub'));
  left.appendChild(escEl('p', 'Per-client CTI reports from confirmed endpoints. Global Research is metadata-only — reports load only for an explicitly selected authorized client. No global feed, no invented IOCs, scores, or attribution.'));
  heading.appendChild(left);
  c.appendChild(heading);
  const banner = document.createElement('div'); banner.className = 'demo-banner';
  banner.appendChild(escEl('span', 'HYBRID · CTI + SOC — per-client reports only; no cross-client aggregation', null));
  banner.appendChild(escEl('span', 'EXISTS (per-client)', 'badge mint'));
  c.appendChild(banner);
  const toolbar = document.createElement('div'); toolbar.className = 'filterbar';
  const lab = document.createElement('label'); lab.style.display = 'flex'; lab.style.alignItems = 'center'; lab.style.gap = '8px';
  const ctxLabel = (topCtx === 'global') ? 'Source Client (topbar: Global Research)' : ('Client (topbar context = ' + topCtx + ')');
  lab.appendChild(escEl('span', ctxLabel, 'eyebrow'));
  const sel = document.createElement('select'); sel.setAttribute('aria-label', 'Client');
  const ph = document.createElement('option'); ph.value = ''; ph.textContent = 'Select authorized client…'; sel.appendChild(ph);
  grantList.forEach(cid => { const o = document.createElement('option'); o.value = cid; o.textContent = cid; sel.appendChild(o); });
  lab.appendChild(sel);
  toolbar.appendChild(lab);
  const ctxNote = escEl('span', '', 'text-muted'); ctxNote.id = 'feed-ctx-note';
  const updateCtxNote = (selected) => {
    ctxNote.textContent = grantList.length ? ('Topbar context: ' + (topCtx === 'global' ? 'Global Research (metadata only)' : topCtx) + '. Source client: ' + (selected || 'not selected') + '. Reports load only for the selected source client; this is not a global context.') : 'No authorized CLIENT grants — metadata only.';
  };
  updateCtxNote(startClient);
  toolbar.appendChild(ctxNote);
  c.appendChild(toolbar);
  const layout = document.createElement('div'); layout.className = 'v3layout';
  const listHost = document.createElement('div'); listHost.id = 'feed-list';
  const inspector = document.createElement('aside'); inspector.className = 'panel v3inspector';
  const ih = document.createElement('div'); ih.className = 'panelhead'; ih.appendChild(escEl('div', 'CONTEXT INSPECTOR', 'paneltitle'));
  const inspBody = document.createElement('div'); inspBody.className = 'panelbody'; inspBody.id = 'feed-inspector';
  inspBody.setAttribute('role', 'status'); inspBody.setAttribute('aria-live', 'polite');
  inspBody.textContent = 'Select a report to inspect provenance and entities.';
  inspector.append(ih, inspBody);
  layout.append(listHost, inspector);
  c.appendChild(layout);
  const loadForClient = async (cid) => {
    const mySeq = feedCtl.seq;
    updateCtxNote(cid);
    // Client switch: clear previous CLIENT data, selection, Inspector.
    feedCtl.selectSeq++;
    feedCtl.reportId = ''; feedCtl.idemKey = ''; feedCtl.idemPayloadHash = '';
    inspBody.textContent = 'Select a report to inspect provenance and entities.';
    if (!cid) {
      listHost.innerHTML = '';
      listHost.appendChild(escEl('div', 'Select an authorized client to load reports. Global Research does not imply cross-client access.', 'statebox'));
      return;
    }
    if (!grantList.includes(cid)) {
      listHost.innerHTML = '';
      listHost.appendChild(escEl('div', 'No grant for selected client (403 path). Client data was not fetched.', 'statebox'));
      return;
    }
    feedCtl.clientId = cid;
    listHost.innerHTML = '';
    listHost.appendChild(escEl('div', 'Loading…', 'statebox'));
    try {
      const data = await api('/api/v1/tenants/' + encodeURIComponent(cid) + '/cti/reports');
      if (mySeq !== feedCtl.seq) return;
      listHost.innerHTML = '';
      const reports = data.reports || [];
      const shown = reports.slice(0, 50);
      const t = escEl('div', 'Authorized reports for ' + cid + ' — showing ' + shown.length + ' of ' + (data.count != null ? data.count : reports.length) + ' (backend returns full list; no pagination parameter)', 'paneltitle');
      t.style.marginBottom = '10px'; listHost.appendChild(t);
      if (!shown.length) { listHost.appendChild(escEl('div', 'No authorized reports for ' + cid + '.', 'statebox')); return; }
      shown.forEach(rep => {
        if (rep.client_id && rep.client_id !== cid) return;
        const btn = escEl('button', null, 'sel-row');
        btn.setAttribute('role', 'option');
        const title = escEl('strong', rep.title || rep.report_id);
        const meta = escEl('div', [rep.author, rep.publication_date, rep.collection_date].filter(Boolean).join(' • ') || 'Dates not available', 'text-muted');
        const sub = escEl('div', 'Report ' + rep.report_id + ' • status ' + (rep.status || 'Not available / not verified'), 'text-muted');
        btn.append(title, meta, sub);
        btn.addEventListener('click', () => selectReport(rep.report_id, cid, mySeq));
        listHost.appendChild(btn);
      });
    } catch (e) {
      if (mySeq !== feedCtl.seq) return;
      listHost.innerHTML = '';
      const msg = (e && e.status === 401) ? 'Session expired (401). Please sign in.' : (e && e.status === 403) ? 'Access denied (403). Client grant required.' : (e && e.status === 404) ? 'Client not found (404).' : 'Failed to load reports';
      listHost.appendChild(escEl('div', msg, 'statebox'));
    }
  };
  sel.addEventListener('change', () => { feedCtl.seq++; loadForClient(sel.value); });
  if (startClient) { sel.value = startClient; loadForClient(startClient); }
  else { loadForClient(''); }
}

/* ---------- V3-F10: Field Intelligence (M7-D Phase 2A) ---------- */
let fieldCtl = {
  seq: 0, selectSeq: 0, clientId: '', instanceId: '', domainId: '', typeId: '', sourceId: '', qid: '',
  tab: 'events', inv: null, loadError: null, search: '',
  tok: { inst: 0, dom: 0, type: 0, src: 0, qid: 0, data: 0 },
  dataTok: 0
};
async function renderFieldIntelligence() {
  const grantList = (me.authorized_clients || []);
  const topCtx = document.getElementById('tenant') ? document.getElementById('tenant').value : 'global';
  const startClient = (topCtx !== 'global' && grantList.includes(topCtx)) ? topCtx : '';
  const { listHost, inspBody } = pageShell('DETECTION ENGINEERING / FIELD INTELLIGENCE', 'Field Intelligence',
    'Per-client QRadar telemetry inventory: instances → domains → log source types → log sources → QIDs, field definitions, raw-to-CEP candidate mappings and staged imports. Every request is client-scoped and grant-filtered server-side. A mapping is a candidate until an authorized reviewer approves it, and no field is AQL-verified without recorded evidence.',
    'M7-D Phase 2A — read-only registry, redacted staging, no live QRadar access', 'EXISTS');

  const toolbar = document.createElement('div'); toolbar.className = 'filterbar';
  const mkSelect = (label, aria) => {
    const lab = document.createElement('label'); lab.style.display = 'flex'; lab.style.alignItems = 'center'; lab.style.gap = '6px';
    lab.appendChild(escEl('span', label, 'eyebrow'));
    const sel = document.createElement('select'); sel.setAttribute('aria-label', aria);
    lab.appendChild(sel); toolbar.appendChild(lab); return sel;
  };
  const selClient = mkSelect('Client', 'Client');
  const selInstance = mkSelect('Instance', 'QRadar instance');
  const selDomain = mkSelect('Domain', 'QRadar domain');
  const selType = mkSelect('DSM', 'Log source type');
  const selSource = mkSelect('Log source', 'Log source');
  const selEvent = mkSelect('Event', 'Event');
  const fill = (sel, placeholder, items, valueOf, labelOf) => {
    sel.innerHTML = '';
    const ph = document.createElement('option'); ph.value = ''; ph.textContent = placeholder; sel.appendChild(ph);
    items.forEach(it => { const o = document.createElement('option'); o.value = valueOf(it); o.textContent = labelOf(it); sel.appendChild(o); });
    sel.disabled = items.length === 0;
  };
  fill(selClient, 'Select authorized client…', grantList.map(c => ({ c: c })), x => x.c, x => x.c);
  fill(selInstance, 'Instance…', [], x => x, x => x);
  fill(selDomain, 'Domain…', [], x => x, x => x);
  fill(selType, 'Log source type…', [], x => x, x => x);
  fill(selSource, 'Log source…', [], x => x, x => x);
  fill(selEvent, 'Event / QID…', [], x => x, x => x);

  const searchLab = document.createElement('label'); searchLab.style.display = 'flex'; searchLab.style.alignItems = 'center'; searchLab.style.gap = '8px';
  searchLab.appendChild(escEl('span', 'Search', 'eyebrow'));
  const searchInp = document.createElement('input'); searchInp.placeholder = 'Filter loaded rows…'; searchInp.setAttribute('aria-label', 'Search');
  searchLab.appendChild(searchInp); toolbar.appendChild(searchLab);

  const tabs = document.createElement('div'); tabs.className = 'tabs';
  const isAdmin = me && me.user && me.user.role === 'ADMINISTRATOR';
  const tabDefs = [['events', 'Event Catalog'], ['fields', 'Field Registry'], ['imports', 'Auto Import'], ['mappings', 'Mapping Inspector'], ['readiness', 'Hunt Readiness']];
  if (isAdmin) tabDefs.push(['bindings', 'Domain Bindings']);
  const tabBtns = {};
  tabDefs.forEach(([id, label]) => {
    const b = escEl('button', label, 'tab' + (fieldCtl.tab === id ? ' active' : ''));
    b.addEventListener('click', () => {
      fieldCtl.tab = id;
      Object.values(tabBtns).forEach(x => x.classList.remove('active')); b.classList.add('active');
      paint();
    });
    tabBtns[id] = b; tabs.appendChild(b);
  });
  toolbar.appendChild(tabs);
  document.getElementById('content').insertBefore(toolbar, document.querySelector('.v3layout'));

  // Every load reports failure instead of pretending an empty catalogue.
  const get = async (path) => {
    try { return { data: await api(path) }; } catch (e) { return { err: e }; }
  };
  const statusText = (e, what) => {
    const s = e && e.status;
    if (s === 403) return 'Access denied (403): no client grant for ' + what + '.';
    if (s === 404) return 'Not found (404) for ' + what + '.';
    if (s === 400) return 'Rejected (400): ' + ((e.data && e.data.error && e.data.error.message) || 'invalid request') + ' for ' + what + '.';
    if (s === 503) return 'Field registry unavailable (503): schema not applied.';
    return 'Failed to load ' + what + (s ? ' (' + s + ')' : ' (network)') + '.';
  };

  const paint = () => {
    const inv = fieldCtl.inv;
    listHost.innerHTML = '';
    if (fieldCtl.loadError) {
      listHost.appendChild(escEl('div', fieldCtl.loadError, 'statebox'));
      return;
    }
    if (!fieldCtl.clientId) {
      listHost.appendChild(escEl('div', 'Select an authorized client to load the QRadar hierarchy.', 'statebox'));
      return;
    }
    if (!inv) { listHost.appendChild(escEl('div', 'Loading…', 'statebox')); return; }
    const q = (fieldCtl.search || '').toLowerCase();
    const rows = tabRows(inv).filter(r => !q || JSON.stringify(r).toLowerCase().includes(q));
    listHost.appendChild(escEl('div', 'Showing ' + Math.min(rows.length, 300) + ' of ' + rows.length + ' — the filter applies to the loaded rows; the API has no full-text search', 'paneltitle'));
    if (!rows.length) {
      listHost.appendChild(escEl('div', 'No rows for this selection. An absent row means "not recorded", not "does not exist in QRadar".', 'statebox'));
      return;
    }
    rows.slice(0, 300).forEach(r => {
      const btn = escEl('button', null, 'sel-row'); btn.setAttribute('role', 'option');
      btn.append(escEl('strong', r.title), escEl('div', r.meta || '', 'text-muted'));
      if (r.badge) btn.appendChild(escEl('span', r.badge.text, 'badge ' + r.badge.cls));
      btn.addEventListener('click', () => inspect(r));
      listHost.appendChild(btn);
    });
  };

  const tabRows = (inv) => {
    if (fieldCtl.tab === 'events') {
      return (inv.qids || []).map(x => ({
        kind: 'qid', ref: x,
        title: (x.event_name || x.qid) + (x.native_event_id ? ' • native ' + x.native_event_id : ''),
        meta: 'QID ' + x.qid + ' • log source ' + (x.log_source_id || '—')
      }));
    }
    if (fieldCtl.tab === 'fields') {
      return (inv.fields || []).map(f => {
        const obs = (inv.observations || []).filter(o => o.field_id === f.field_id);
        const verified = obs.some(o => o.aql_verification_status === 'VERIFIED');
        return {
          kind: 'field', ref: f, title: f.field_name + ' • ' + f.field_origin,
          meta: 'CEP ' + (f.cep_identifier || '—') + ' • observations ' + obs.length + (verified ? '' : ' • AQL not verified'),
          badge: { text: verified ? 'AQL VERIFIED (manual)' : 'UNVERIFIED', cls: verified ? 'mint' : 'amber' }
        };
      });
    }
    if (fieldCtl.tab === 'imports') {
      const items = (inv.batches || []).map(b => ({
        kind: 'batch', ref: b, title: b.batch_name + ' • ' + b.processing_status,
        meta: b.source_type + ' • rows ' + (b.parsed_rows || 0) + ' / rejected ' + (b.rejected_rows || 0) + ' • redactions ' + (b.redacted_values || 0),
        badge: { text: b.processing_status, cls: b.processing_status === 'PUBLISHED' ? 'mint' : (b.processing_status === 'FAILED' || b.processing_status === 'REJECTED') ? 'muted' : 'amber' }
      }));
      items.push({ kind: 'upload', title: 'Upload telemetry export…', meta: 'Local parse → redact → candidate mapping. Raw values are never stored.' });
      return items;
    }
    if (fieldCtl.tab === 'mappings') {
      return (inv.mappings || []).map(m => ({
        kind: 'mapping', ref: m,
        title: (m.raw_source_field || '—') + ' → ' + (m.target_cep_field || '—'),
        meta: 'origin ' + m.origin + ' • version ' + m.mapping_version + ' • DSM ' + (m.applicable_dsm || '—'),
        badge: { text: m.origin === 'auto' ? 'CANDIDATE' : 'APPROVED', cls: m.origin === 'auto' ? 'amber' : 'mint' }
      }));
    }
    if (fieldCtl.tab === 'bindings') {
      return (inv.bindings || []).map(b => {
        const confirmed = b.binding_kind === 'CLIENT' && b.verification_status === 'VERIFIED';
        return {
          kind: 'binding', ref: b,
          title: (b.domain_name || b.domain_id) + ' • native ' + (b.native_qradar_domain_id || 'unverified'),
          meta: 'kind ' + b.binding_kind + ' • client ' + (b.client_id || b.inferred_client_id || 'none') +
                (b.inferred_client_id && !b.client_id ? ' (inferred, not authoritative)' : '') +
                ' • revision ' + b.revision,
          badge: { text: confirmed ? 'VERIFIED' : (b.binding_kind === 'SHARED' ? 'SHARED' : 'UNASSIGNED'), cls: confirmed ? 'mint' : 'amber' }
        };
      });
    }
    const inv2 = inv;
    const statuses = {}; (inv2.sources || []).forEach(s => { const k = s.status || 'UNKNOWN'; statuses[k] = (statuses[k] || 0) + 1; });
    const origins = {}; (inv2.fields || []).forEach(f => { const k = f.field_origin || 'unknown'; origins[k] = (origins[k] || 0) + 1; });
    const aql = {}; (inv2.observations || []).forEach(o => { const k = o.aql_verification_status || 'UNKNOWN'; aql[k] = (aql[k] || 0) + 1; });
    return [
      { kind: 'summary', title: 'Instances ' + (inv2.instances || []).length + ' • domains ' + (inv2.domains || []).length + ' • log source types ' + (inv2.types || []).length, meta: 'Declared inventory only — no live QRadar read.' },
      { kind: 'summary', title: 'Log sources: ' + (inv2.sources || []).length + ' — ' + (Object.keys(statuses).map(k => k + ' ' + statuses[k]).join(', ') || 'none'), meta: 'UNKNOWN means the status was never recorded, not that telemetry is absent.' },
      { kind: 'summary', title: 'QIDs / events: ' + (inv2.qids || []).length, meta: 'Catalogue entries are declared; none is AQL-verified by presence alone.' },
      { kind: 'summary', title: 'Field definitions: ' + (inv2.fields || []).length + ' — ' + (Object.keys(origins).map(k => k + ' ' + origins[k]).join(', ') || 'none'), meta: 'raw_only fields are never treated as normalized CEP properties.' },
      { kind: 'summary', title: 'Mappings: ' + (inv2.mappings || []).length + ' (auto candidates ' + (inv2.mappings || []).filter(m => m.origin === 'auto').length + ')', meta: 'A candidate mapping is not an approved mapping.' },
      { kind: 'summary', title: 'Observations by AQL status: ' + (Object.keys(aql).map(k => k + ' ' + aql[k]).join(', ') || 'none'), meta: 'Only a recorded reviewer attestation may say VERIFIED; absence is not proof.' },
      { kind: 'summary', title: 'Import batches: ' + (inv2.batches || []).length, meta: 'UPLOAD → PARSE → REDACT → MAP → REVIEW → PUBLISH; only a reviewer may approve.' }
    ];
  };

  const inspect = async (r) => {
    const seq = ++fieldCtl.selectSeq;
    inspBody.innerHTML = '';
    const ref = r.ref || {};
    const head = (t) => inspBody.appendChild(escEl('div', t, 'kv-k'));
    if (r.kind === 'qid') {
      head('QID ' + ref.qid);
      kvAdd(inspBody, 'Event name', ref.event_name);
      kvAdd(inspBody, 'Native event ID', ref.native_event_id);
      kvAdd(inspBody, 'Log source', ref.log_source_id);
      kvAdd(inspBody, 'Created', ref.created_at);
      inspBody.appendChild(escEl('div', 'The native event ID is a per-DSM identifier: it is not the QRadar QID and not an AQL field.', 'text-muted'));
      return;
    }
    if (r.kind === 'field') {
      head('Field ' + ref.field_name);
      kvAdd(inspBody, 'Field ID', ref.field_id); kvAdd(inspBody, 'Origin', ref.field_origin);
      kvAdd(inspBody, 'Data type', ref.data_type); kvAdd(inspBody, 'CEP identifier', ref.cep_identifier);
      kvAdd(inspBody, 'AQL expression', ref.aql_field_expression); kvAdd(inspBody, 'Event scope', ref.supported_event_scope);
      secAdd(inspBody, 'Observations');
      const obs = ((fieldCtl.inv && fieldCtl.inv.observations) || []).filter(o => o.field_id === ref.field_id);
      if (!obs.length) inspBody.appendChild(escEl('div', 'No observation recorded — verification unknown, not "field absent".', 'text-muted'));
      obs.forEach(o => inspBody.appendChild(escEl('div', '• AQL ' + o.aql_verification_status + ' • raw ' + (o.field_present_in_raw ? 'yes' : 'no') + ' • CEP displayed ' + (o.qradar_property_displayed ? 'yes' : 'no') + ' • value extracted ' + (o.extracted_value_present ? 'yes' : 'no') + ' • ' + (o.verification_timestamp || 'no timestamp') + ' • ' + (o.evidence_reference || 'no evidence reference'), 'text-muted')));
      return;
    }
    if (r.kind === 'mapping') {
      head('Mapping ' + ref.raw_source_field + ' → ' + ref.target_cep_field);
      kvAdd(inspBody, 'Origin', ref.origin === 'auto' ? 'auto (candidate)' : ref.origin);
      kvAdd(inspBody, 'Semantic alias', ref.semantic_alias); kvAdd(inspBody, 'Applicable DSM', ref.applicable_dsm);
      kvAdd(inspBody, 'Applicable event', ref.applicable_event); kvAdd(inspBody, 'Version', ref.mapping_version);
      if (ref.origin === 'auto') {
        const ev = document.createElement('input');
        ev.placeholder = 'Approval evidence (ticket, AQL result, sample reference)';
        ev.setAttribute('aria-label', 'Approval evidence');
        ev.style.marginTop = '10px'; ev.style.width = '100%';
        const btn = escEl('button', 'Approve mapping (reviewer)', 'btn primary btn-sm'); btn.style.marginTop = '8px';
        btn.addEventListener('click', async () => {
          if (ev.value.trim().length < 12) { alert('Enter a real evidence reference (at least 12 characters).'); return; }
          try {
            await api('/api/v1/qradar/field-mappings/' + encodeURIComponent(ref.mapping_id) + '/approve', { method: 'POST', body: { evidence: ev.value.trim() } });
            alert('Mapping approved.');
            loadDomain();
          } catch (e) { alert((e && e.data && e.data.error && e.data.error.message) || ('Approve failed (' + (e && e.status) + ')')); }
        });
        inspBody.append(ev, btn);
      }
      inspBody.appendChild(escEl('div', 'A raw field seen in one event does not make it a normalized CEP property for that DSM.', 'text-muted'));
      return;
    }
    if (r.kind === 'upload') { renderUploadForm(inspBody); return; }
    if (r.kind === 'binding') { renderBindingForm(ref, inspBody); return; }
    if (r.kind === 'batch') { renderBatch(ref, inspBody, seq); return; }
    head('Hunt readiness (read-only)');
    kvAdd(inspBody, 'Statement', r.title); kvAdd(inspBody, 'Limitation', r.meta);
    inspBody.appendChild(escEl('div', 'This is a declared-inventory summary, not a detection coverage verdict.', 'text-muted'));
  };

  const renderBindingForm = (b, host) => {
    host.appendChild(escEl('div', 'Domain binding ' + (b.domain_name || b.domain_id), 'kv-k'));
    kvAdd(host, 'Internal domain id', b.domain_id);
    kvAdd(host, 'Native QRadar domain id', b.native_qradar_domain_id || 'not verified — must come from QRadar, never from the label');
    kvAdd(host, 'Binding kind', b.binding_kind);
    kvAdd(host, 'Bound client', b.client_id || 'none');
    kvAdd(host, 'Inferred (legacy) client', b.inferred_client_id || 'none');
    kvAdd(host, 'Verified by', b.verified_by || '—');
    kvAdd(host, 'Evidence', b.evidence_reference || '—');
    kvAdd(host, 'Revision', b.revision);
    if (!isAdmin) return;

    host.appendChild(escEl('div', 'Confirm or change this binding', 'paneltitle'));
    host.appendChild(escEl('div', 'Native IDs come from QRadar metadata or an administrator decision. A domain label is never used as an ID.', 'text-muted'));
    const native = document.createElement('input');
    native.placeholder = 'Native QRadar Domain ID (digits)';
    native.setAttribute('aria-label', 'Native QRadar domain id');
    native.value = b.native_qradar_domain_id || '';
    const kind = document.createElement('select'); kind.setAttribute('aria-label', 'Binding kind');
    [['CLIENT', 'CLIENT'], ['SHARED', 'SHARED'], ['UNASSIGNED', 'UNASSIGNED']].forEach(([v, l]) => {
      const o = document.createElement('option'); o.value = v; o.textContent = l; kind.appendChild(o);
    });
    kind.value = b.binding_kind || 'UNASSIGNED';
    const client = document.createElement('select'); client.setAttribute('aria-label', 'Bound client');
    const none = document.createElement('option'); none.value = ''; none.textContent = '— no client —'; client.appendChild(none);
    (me.authorized_clients || []).forEach(c => { const o = document.createElement('option'); o.value = c; o.textContent = c; client.appendChild(o); });
    client.value = b.client_id || '';
    const ev = document.createElement('input');
    ev.placeholder = 'Evidence (QRadar export reference, ticket)';
    ev.setAttribute('aria-label', 'Binding evidence');
    const btn = escEl('button', 'Confirm binding', 'btn primary btn-sm');
    const out = escEl('div', null, 'text-muted');
    btn.addEventListener('click', async () => {
      if (ev.value.trim().length < 12) { alert('Enter real evidence (at least 12 characters).'); return; }
      if (kind.value === 'CLIENT' && !client.value) { alert('Select the client that owns this domain.'); return; }
      btn.disabled = true;
      try {
        await api('/api/v1/qradar/domains/' + encodeURIComponent(b.domain_id) + '/binding', {
          method: 'PUT',
          body: {
            native_qradar_domain_id: native.value.trim(),
            client_id: kind.value === 'CLIENT' ? client.value : '',
            binding_kind: kind.value,
            evidence: ev.value.trim(),
            expected_revision: b.revision
          }
        });
        out.textContent = 'Binding updated.';
        await loadDomains();
      } catch (e) {
        const msg = (e && e.data && e.data.error && e.data.error.message) || ('Binding update failed (' + (e && e.status) + ')');
        out.textContent = msg;
      } finally { btn.disabled = false; }
    });
    [native, kind, client, ev, btn, out].forEach(n => { n.style.display = 'block'; n.style.marginTop = '8px'; host.appendChild(n); });
    const hist = escEl('button', 'Show binding history', 'btn btn-sm'); hist.style.marginTop = '8px';
    const histHost = escEl('div', null, 'text-muted');
    hist.addEventListener('click', async () => {
      try {
        const d = await api('/api/v1/qradar/domains/' + encodeURIComponent(b.domain_id) + '/binding-history');
        histHost.innerHTML = '';
        (d.history || []).forEach(h => histHost.appendChild(escEl('div', '• rev ' + h.revision + ': ' + h.previous_kind + ' → ' + h.new_kind + ' • client ' + (h.previous_client_id || '—') + ' → ' + (h.new_client_id || '—') + ' • ' + h.actor_id + ' • ' + h.evidence_reference, 'text-muted')));
      } catch (e) { histHost.textContent = 'History unavailable (' + ((e && e.status) || 'network') + ').'; }
    });
    host.append(hist, histHost);
  };

  const renderUploadForm = (host) => {
    host.appendChild(escEl('div', 'Import a telemetry export', 'kv-k'));
    host.appendChild(escEl('div', 'The browser uploads the file to this on-premise Atlas backend, which parses and redacts it before any database write. Redaction happens server-side, not in the browser. Unparseable or ambiguous input is rejected, not guessed.', 'text-muted'));
    const src = document.createElement('select'); src.setAttribute('aria-label', 'Source type');
    ['windows_kev', 'iis', 'csv', 'json', 'jsonl', 'txt'].forEach(t => { const o = document.createElement('option'); o.value = t; o.textContent = t; src.appendChild(o); });
    const name = document.createElement('input'); name.placeholder = 'Batch name'; name.setAttribute('aria-label', 'Batch name');
    const file = document.createElement('input'); file.type = 'file'; file.setAttribute('aria-label', 'File');
    const btn = escEl('button', 'Upload and parse', 'btn primary btn-sm');
    const out = escEl('div', null, 'text-muted');
    btn.addEventListener('click', async () => {
      if (!fieldCtl.domainId) { alert('Select a domain first.'); return; }
      if (!file.files || !file.files[0]) { alert('Choose a file.'); return; }
      const fd = new FormData();
      fd.append('client_id', fieldCtl.clientId);
      fd.append('domain_id', fieldCtl.domainId);
      fd.append('batch_name', name.value || file.files[0].name);
      fd.append('source_type', src.value);
      fd.append('file', file.files[0]);
      btn.disabled = true; out.textContent = 'Uploading…';
      try {
        const res = await apiForm('/api/v1/qradar/import-file', fd);
        out.textContent = 'Batch ' + res.batch.batch_id + ': ' + res.batch.processing_status + ' • ' + (res.batch.parsed_rows || 0) + ' parsed, ' + (res.batch.redacted_values || 0) + ' values redacted. Review it in Auto Import.';
        await loadDomain();
      } catch (e) {
        out.textContent = (e && e.data && e.data.error && e.data.error.message) || ('Upload failed (' + (e && e.status) + ')');
      } finally { btn.disabled = false; }
    });
    [src, name, file, btn, out].forEach(n => { n.style.display = 'block'; n.style.marginTop = '8px'; host.appendChild(n); });
  };

  const renderBatch = async (b, host, seq) => {
    host.appendChild(escEl('div', 'Import batch ' + (b.batch_name || b.batch_id), 'kv-k'));
    kvAdd(host, 'Status', b.processing_status);
    kvAdd(host, 'Source type', b.source_type);
    kvAdd(host, 'Parser', b.parser_version);
    kvAdd(host, 'Redaction', b.redaction_version);
    kvAdd(host, 'Parsed / rejected rows', (b.parsed_rows || 0) + ' / ' + (b.rejected_rows || 0));
    kvAdd(host, 'Redacted values', b.redacted_values || 0);
    kvAdd(host, 'Warnings', b.parse_warnings);
    kvAdd(host, 'Errors', b.import_errors);
    kvAdd(host, 'Reviewed by', b.reviewed_by);
    secAdd(host, 'Redacted preview');
    const rowsHost = escEl('div', 'Loading…', 'text-muted'); host.appendChild(rowsHost);
    const mapsHost = escEl('div', null); host.appendChild(mapsHost);
    try {
      const rows = (await api('/api/v1/qradar/import-rows?batch_id=' + encodeURIComponent(b.batch_id))).import_rows || [];
      if (seq !== fieldCtl.selectSeq) return;
      rowsHost.innerHTML = '';
      if (!rows.length) rowsHost.textContent = 'No stored rows.';
      rows.slice(0, 10).forEach(rw => rowsHost.appendChild(escEl('div', '#' + rw.row_number + ' ' + (rw.parse_error ? 'ERROR: ' + rw.parse_error : (rw.raw_line || '')), 'text-muted')));
      const maps = (await api('/api/v1/qradar/import-field-maps?batch_id=' + encodeURIComponent(b.batch_id))).import_field_maps || [];
      if (seq !== fieldCtl.selectSeq) return;
      secAdd(mapsHost, 'Candidate mappings');
      if (!maps.length) mapsHost.appendChild(escEl('div', 'No candidate mappings derived.', 'text-muted'));
      maps.forEach(m => {
        const row = escEl('div', '• ' + m.raw_field_name + ' → ' + (m.suggested_cep_field || 'unmapped') + ' (' + (m.mapping_confidence || 'n/a') + ')' + (m.ambiguous ? ' — AMBIGUOUS, needs review' : ''), m.ambiguous ? 'text-muted' : 'text-muted');
        mapsHost.appendChild(row);
        if (m.evidence) mapsHost.appendChild(escEl('div', '   ' + m.evidence, 'text-muted'));
      });
    } catch (e) {
      rowsHost.textContent = 'Batch detail unavailable (' + ((e && e.status) || 'network') + ').';
    }
    if (b.processing_status === 'MAPPED' || b.processing_status === 'REVIEWED') {
      const ev = document.createElement('input');
      ev.placeholder = 'Review evidence (what you checked, where)';
      ev.setAttribute('aria-label', 'Review evidence');
      ev.style.marginTop = '10px'; ev.style.width = '100%';
      const row = document.createElement('div'); row.style.display = 'flex'; row.style.gap = '6px'; row.style.marginTop = '8px';
      const ok = escEl('button', 'Approve', 'btn primary btn-sm');
      const no = escEl('button', 'Reject', 'btn btn-sm');
      ok.addEventListener('click', () => decide('APPROVED'));
      no.addEventListener('click', () => decide('REJECTED'));
      const decide = async (decision) => {
        if (ev.value.trim().length < 12) { alert('Enter real review evidence (at least 12 characters).'); return; }
        try {
          await api('/api/v1/qradar/import-batches/' + encodeURIComponent(b.batch_id) + '/review', { method: 'POST', body: { decision: decision, evidence: ev.value.trim() } });
          await loadDomain();
        } catch (e) { alert((e && e.data && e.data.error && e.data.error.message) || ('Review failed (' + (e && e.status) + ')')); }
      };
      row.append(ok, no); host.append(ev, row);
    }
    if (b.processing_status === 'REVIEWED') {
      const pub = escEl('button', 'Publish to registry', 'btn primary'); pub.style.marginTop = '8px';
      pub.addEventListener('click', async () => {
        try {
          await api('/api/v1/qradar/import-batches/' + encodeURIComponent(b.batch_id) + '/publish', { method: 'POST', body: {} });
          await loadDomain();
        } catch (e) { alert((e && e.data && e.data.error && e.data.error.message) || ('Publish failed (' + (e && e.status) + ')')); }
      });
      host.appendChild(pub);
    }
  };

  // ---- hierarchical loading, always with real parent IDs ----
  let inv = { instances: [], domains: [], types: [], sources: [], qids: [], fields: [], mappings: [], observations: [], batches: [] };

  const loadDomain = async () => {
    fieldCtl.loadError = null;
    if (!fieldCtl.domainId) { inv = { instances: inv.instances, domains: inv.domains, types: [], sources: [], qids: [], fields: [], mappings: [], observations: [], batches: [] }; fieldCtl.inv = inv; paint(); return; }
    const seq = ++fieldCtl.tok.data;
    fieldCtl.inv = null; paint();
    const enc = encodeURIComponent;
    const [f, m, o, b] = await Promise.all([
      get('/api/v1/qradar/field-definitions?client_id=' + enc(fieldCtl.clientId) + '&domain_id=' + enc(fieldCtl.domainId)),
      get('/api/v1/qradar/field-mappings?client_id=' + enc(fieldCtl.clientId) + '&domain_id=' + enc(fieldCtl.domainId)),
      get('/api/v1/qradar/field-observations?client_id=' + enc(fieldCtl.clientId) + '&domain_id=' + enc(fieldCtl.domainId)),
      get('/api/v1/qradar/import-batches?client_id=' + enc(fieldCtl.clientId))
    ]);
    if (seq !== fieldCtl.tok.data) return;
    const failed = [f, m, o, b].find(x => x.err);
    if (failed) { fieldCtl.loadError = statusText(failed.err, 'field registry data'); paint(); return; }
    inv.fields = f.data.field_definitions || [];
    inv.mappings = m.data.field_mappings || [];
    inv.observations = o.data.field_observations || [];
    inv.batches = b.data.import_batches || [];
    fieldCtl.inv = inv; paint();
  };

  const loadQIDs = async () => {
    const seq = ++fieldCtl.tok.qid;
    if (!fieldCtl.sourceId) { inv.qids = []; fieldCtl.inv = inv; paint(); return; }
    const r = await get('/api/v1/qradar/qids?log_source_id=' + encodeURIComponent(fieldCtl.sourceId));
    if (seq !== fieldCtl.tok.qid) return;
    if (r.err) { fieldCtl.loadError = statusText(r.err, 'QIDs'); paint(); return; }
    inv.qids = r.data.qradar_qids || [];
    fieldCtl.inv = inv; paint();
  };

  const loadSources = async () => {
    const seq = ++fieldCtl.tok.src;
    if (!fieldCtl.typeId) { inv.sources = []; inv.qids = []; fieldCtl.inv = inv; paint(); return; }
    const r = await get('/api/v1/qradar/log-sources?log_source_type_id=' + encodeURIComponent(fieldCtl.typeId));
    if (seq !== fieldCtl.tok.src) return;
    if (r.err) { fieldCtl.loadError = statusText(r.err, 'log sources'); paint(); return; }
    inv.sources = r.data.log_sources || [];
    fill(selSource, 'Log source…', inv.sources, x => x.log_source_id, x => (x.status || 'UNKNOWN') + ' • ' + x.log_source_id);
    fieldCtl.inv = inv; paint();
  };

  const loadTypes = async () => {
    const seq = ++fieldCtl.tok.type;
    if (!fieldCtl.domainId) { inv.types = []; inv.sources = []; inv.qids = []; paint(); return; }
    const r = await get('/api/v1/qradar/log-source-types?domain_id=' + encodeURIComponent(fieldCtl.domainId));
    if (seq !== fieldCtl.tok.type) return;
    if (r.err) { fieldCtl.loadError = statusText(r.err, 'log source types'); paint(); return; }
    inv.types = r.data.log_source_types || [];
    fill(selType, 'Log source type…', inv.types, x => x.log_source_type_id, x => x.type_name);
  };

  const loadDomains = async () => {
    const seq = ++fieldCtl.tok.dom;
    if (!fieldCtl.instanceId) { inv.domains = []; fieldCtl.inv = inv; paint(); return; }
    const r = await get('/api/v1/qradar/domains?instance_id=' + encodeURIComponent(fieldCtl.instanceId));
    if (seq !== fieldCtl.tok.dom) return;
    if (r.err) { fieldCtl.loadError = statusText(r.err, 'domains'); paint(); return; }
    inv.domains = r.data.domains || [];
    fill(selDomain, 'Domain…', inv.domains, x => x.domain_id, x => x.domain_name + (x.domain_type ? ' (' + x.domain_type + ')' : ''));
    // Binding metadata is instance-scoped; administrators reconcile it here.
    if (isAdmin) {
      const b = await get('/api/v1/qradar/domain-bindings?instance_id=' + encodeURIComponent(fieldCtl.instanceId));
      if (seq !== fieldCtl.tok.dom) return;
      if (b.err) { fieldCtl.loadError = statusText(b.err, 'domain bindings'); paint(); return; }
      inv.bindings = b.data.domain_bindings || [];
    }
    fieldCtl.inv = inv;
    if (fieldCtl.tab === 'bindings') paint();
    if (!inv.domains.length) listHost.appendChild(escEl('div', 'This instance exposes no domains to you.', 'statebox'));
  };

  const loadInstances = async () => {
    fieldCtl.loadError = null;
    if (!fieldCtl.clientId) { fieldCtl.inv = null; paint(); return; }
    const seq = ++fieldCtl.tok.inst;
    fieldCtl.inv = null; paint();
    const r = await get('/api/v1/qradar/instances?client_id=' + encodeURIComponent(fieldCtl.clientId));
    if (seq !== fieldCtl.tok.inst) return;
    if (r.err) { fieldCtl.loadError = statusText(r.err, 'QRadar instances'); paint(); return; }
    inv.instances = r.data.instances || [];
    fill(selInstance, 'Instance…', inv.instances, x => x.instance_id, x => x.instance_name + (x.host ? ' (' + x.host + ')' : ''));
    fieldCtl.inv = inv; paint();
  };

  selClient.addEventListener('change', () => {
    fieldCtl.clientId = selClient.value; fieldCtl.instanceId = ''; fieldCtl.domainId = ''; fieldCtl.typeId = ''; fieldCtl.sourceId = ''; fieldCtl.qid = '';
    fill(selInstance, 'Instance…', [], x => x, x => x); fill(selDomain, 'Domain…', [], x => x, x => x);
    fill(selType, 'Log source type…', [], x => x, x => x); fill(selSource, 'Log source…', [], x => x, x => x); fill(selEvent, 'Event / QID…', [], x => x, x => x);
    loadInstances();
  });
  selInstance.addEventListener('change', () => {
    fieldCtl.instanceId = selInstance.value; fieldCtl.domainId = ''; fieldCtl.typeId = ''; fieldCtl.sourceId = '';
    fill(selDomain, 'Domain…', [], x => x, x => x); fill(selType, 'Log source type…', [], x => x, x => x);
    fill(selSource, 'Log source…', [], x => x, x => x); fill(selEvent, 'Event / QID…', [], x => x, x => x);
    loadDomains();
  });
  selDomain.addEventListener('change', () => {
    fieldCtl.domainId = selDomain.value; fieldCtl.typeId = ''; fieldCtl.sourceId = '';
    fill(selType, 'Log source type…', [], x => x, x => x); fill(selSource, 'Log source…', [], x => x, x => x);
    fill(selEvent, 'Event / QID…', [], x => x, x => x);
    loadTypes(); loadDomain();
  });
  selType.addEventListener('change', () => {
    fieldCtl.typeId = selType.value; fieldCtl.sourceId = '';
    fill(selSource, 'Log source…', [], x => x, x => x); fill(selEvent, 'Event / QID…', [], x => x, x => x);
    loadSources();
  });
  selSource.addEventListener('change', () => {
    fieldCtl.sourceId = selSource.value; fieldCtl.qid = '';
    fill(selEvent, 'Event / QID…', [], x => x, x => x);
    loadQIDs().then(() => {
      fill(selEvent, 'Event / QID…', inv.qids, x => x.qid, x => (x.event_name || x.qid) + ' • ' + x.qid);
    });
  });
  selEvent.addEventListener('change', () => { fieldCtl.qid = selEvent.value; paint(); });
  searchInp.addEventListener('input', () => { fieldCtl.search = searchInp.value; paint(); });

  if (startClient) { selClient.value = startClient; fieldCtl.clientId = startClient; loadInstances(); }
  else paint();
}

const selectReport = async (reportId, cid, seq) => {
  const mySelect = ++feedCtl.selectSeq;
  feedCtl.reportId = reportId;
  feedCtl.idemKey = ''; feedCtl.idemPayloadHash = '';
  const insp = document.getElementById('feed-inspector');
  if (!insp) return;
  insp.innerHTML = 'Loading…';
  const load = async (path, opts) => { try { return await api(path, opts); } catch (e) { return { __err: (e && e.status) || 0 }; } };
  const detail = await load('/api/v1/cti/reports/' + encodeURIComponent(reportId));
  if (mySelect !== feedCtl.selectSeq || seq !== feedCtl.seq) return;
  if (detail && detail.__err) { insp.textContent = 'Report unavailable (' + detail.__err + ').'; return; }
  if (detail && detail.client_id && detail.client_id !== cid) { insp.textContent = 'Client isolation: report client does not match selected context. Not displayed.'; return; }
  const [iocs, ttps, cves, evid] = await Promise.all([
    load('/api/v1/cti/reports/' + encodeURIComponent(reportId) + '/iocs'),
    load('/api/v1/cti/reports/' + encodeURIComponent(reportId) + '/ttps'),
    load('/api/v1/cti/reports/' + encodeURIComponent(reportId) + '/cves'),
    load('/api/v1/cti/reports/' + encodeURIComponent(reportId) + '/evidence')
  ]);
  if (mySelect !== feedCtl.selectSeq || seq !== feedCtl.seq) return;
  insp.innerHTML = '';
  const add = (k, v) => { const d = escEl('div', null, 'kv'); d.appendChild(escEl('div', k, 'kv-k')); d.appendChild(escEl('div', v ? String(v) : 'Not available / not verified', 'kv-v')); insp.appendChild(d); };
  const sec = (t) => { const s = escEl('div', t, 'paneltitle'); s.style.margin = '14px 0 8px'; insp.appendChild(s); };
  insp.appendChild(escEl('div', 'Report ' + reportId + ' • ' + cid, 'kv-k'));
  add('Title', detail && detail.title);
  add('Author', detail && detail.author);
  add('Publication date', detail && detail.publication_date);
  add('Collection date', detail && detail.collection_date);
  add('Status', detail && detail.status);
  add('Source ID', detail && detail.source_id);
  add('Original content ref', detail && detail.original_content_ref);
  add('Checksum', detail && detail.checksum);
  sec('IOCs');
  if (iocs && iocs.__err) insp.appendChild(escEl('div', 'IOCs unavailable (' + iocs.__err + ').', 'text-muted'));
  else { const arr = iocs && iocs.iocs || []; if (!arr.length) insp.appendChild(escEl('div', 'No IOCs extracted — Not available / not verified.', 'text-muted')); arr.forEach(i => insp.appendChild(escEl('div', '• ' + (i.indicator_type || '') + ': ' + (i.indicator_value || '') + (i.confidence ? ' (confidence: ' + i.confidence + ')' : ''), 'row'))); }
  sec('TTPs');
  if (ttps && ttps.__err) insp.appendChild(escEl('div', 'TTPs unavailable (' + ttps.__err + ').', 'text-muted'));
  else { const arr = ttps && ttps.ttps || []; if (!arr.length) insp.appendChild(escEl('div', 'No TTPs extracted — Not available / not verified.', 'text-muted')); arr.forEach(t => insp.appendChild(escEl('div', '• ' + [t.mitre_technique_id, t.mitre_tactic, t.technique_name].filter(Boolean).join(' / ') || t.technique_id, 'row'))); }
  sec('CVEs');
  if (cves && cves.__err) insp.appendChild(escEl('div', 'CVEs unavailable (' + cves.__err + ').', 'text-muted'));
  else { const arr = cves && cves.cves || []; if (!arr.length) insp.appendChild(escEl('div', 'No CVEs linked — Not available / not verified.', 'text-muted')); arr.forEach(cv => insp.appendChild(escEl('div', '• ' + (cv.cve_id_text || cv.cve_id) + (cv.severity ? ' (' + cv.severity + ')' : '') + (cv.description ? ' — ' + cv.description : ''), 'row'))); }
  sec('Evidence / provenance');
  if (evid && evid.__err) insp.appendChild(escEl('div', 'Evidence unavailable (' + evid.__err + ').', 'text-muted'));
  else { const counts = evid && evid.counts || {}; insp.appendChild(escEl('div', 'Claims ' + (counts.claims || 0) + ' • actors ' + (counts.threat_actors || 0) + ' • campaigns ' + (counts.campaigns || 0) + ' • malware ' + (counts.malware || 0), 'text-muted')); (evid.claims || []).forEach(cl => insp.appendChild(escEl('div', 'Claim: ' + (cl.claim_text || ''), 'row'))); (evid.threat_actors || []).forEach(a => insp.appendChild(escEl('div', 'Actor: ' + (a.actor_name || ''), 'row'))); (evid.campaigns || []).forEach(a => insp.appendChild(escEl('div', 'Campaign: ' + (a.campaign_name || ''), 'row'))); (evid.malware || []).forEach(a => insp.appendChild(escEl('div', 'Malware: ' + (a.malware_name || ''), 'row'))); }
  // M7-C: Client Relevance (per-dimension verdicts + evidence; no numeric scores).
  sec('Client Relevance (M7-C)');
  assessRelevanceInto(insp, reportId, cid, me.user.role);
  const role = me.user.role;
  const canViewCTI = role !== 'READ_ONLY';
  const analyzeBtn = escEl('button', 'Run analysis (POST /analyze)', 'btn');
  analyzeBtn.style.marginTop = '12px';
  analyzeBtn.disabled = !canViewCTI;
  if (!canViewCTI) analyzeBtn.textContent = 'Run analysis — denied (role READ_ONLY)';
  analyzeBtn.addEventListener('click', async () => {
    if (!canViewCTI) return;
    const ok = window.confirm('Run analysis on report ' + reportId + '?\n\nThis is a MUTATING operation (POST /api/v1/cti/reports/{report_id}/analyze): status becomes ANALYZED and IOC/TTP extraction runs. It does NOT run on simple report open.\n\nRole: ' + role + ' (CanViewCTI required).');
    if (!ok) return;
    analyzeBtn.disabled = true;
    const r = await load('/api/v1/cti/reports/' + encodeURIComponent(reportId) + '/analyze', { method: 'POST', body: {} });
    if (mySelect !== feedCtl.selectSeq) return;
    analyzeBtn.disabled = false;
    if (r && r.__err) { alert('Analysis unavailable (' + r.__err + ').'); return; }
    alert('Analysis completed — status ' + (r && r.status || 'ANALYZED') + '. Re-open the report to re-read IOC/TTP entities.');
  });
  insp.appendChild(analyzeBtn);
  // M7-B: linked cases + Link to Case + Create Case from Report.
  const linkedSec = escEl('div', 'Linked Research Cases', 'paneltitle');
  linkedSec.style.margin = '14px 0 8px';
  insp.appendChild(linkedSec);
  const linkedList = escEl('div', 'Loading…', 'text-muted');
  insp.appendChild(linkedList);
  const loadLinkedCases = async () => {
    try {
      const d = await api('/api/v1/cti/reports/' + encodeURIComponent(reportId) + '/cases?limit=20&offset=0');
      linkedList.innerHTML = '';
      const rows = d.cases || [];
      if (!rows.length) { linkedList.textContent = 'No linked cases.'; return; }
      rows.forEach(c => {
        const btn = escEl('button', (c.title || c.case_id) + ' • ' + (c.status || '—'), 'btn small');
        btn.style.margin = '2px';
        btn.addEventListener('click', () => { currentCaseId = c.case_id; navigate('case', { case_id: c.case_id }); });
        linkedList.appendChild(btn);
      });
    } catch (e) {
      linkedList.textContent = (e && e.status === 403) ? 'Access denied (403).' : (e && e.status === 503) ? 'Links unavailable (M7-B schema not applied).' : 'Failed to load linked cases.';
    }
  };
  loadLinkedCases();
  const linkRow = document.createElement('div'); linkRow.style.display = 'flex'; linkRow.style.gap = '6px'; linkRow.style.marginTop = '8px';
  const caseSel = document.createElement('select'); caseSel.setAttribute('aria-label', 'Case to link');
  const casePh = document.createElement('option'); casePh.value = ''; casePh.textContent = 'Select case…'; caseSel.appendChild(casePh);
  api('/api/v1/cases?limit=50&offset=0').then(d => { (d.cases || []).forEach(c => { const o = document.createElement('option'); o.value = c.case_id; o.textContent = (c.title || c.case_id); caseSel.appendChild(o); }); }).catch(() => {});
  const linkBtn = escEl('button', 'Link to Case', 'btn primary btn-sm');
  linkBtn.addEventListener('click', async () => {
    if (!caseSel.value) return;
    try { await api('/api/v1/cases/' + encodeURIComponent(caseSel.value) + '/cti-reports', { method: 'POST', body: { report_id: reportId } }); alert('Linked to case ' + caseSel.value); loadLinkedCases(); }
    catch (e) { alert((e && e.data && e.data.error && e.data.error.message) || 'Link failed'); }
  });
  linkRow.append(caseSel, linkBtn);
  insp.appendChild(linkRow);
  const createFromReportBtn = escEl('button', 'Create Case from Report', 'btn btn-sm');
  createFromReportBtn.style.marginTop = '8px';
  createFromReportBtn.addEventListener('click', async () => {
    const payload = { title: (detail && detail.title) || ('CTI Case ' + reportId), description: 'From CTI report ' + reportId, priority: 'P2', severity: 'HIGH', idempotency_key: genIdempotencyKey() };
    try {
      const created = await api('/api/v1/cti/reports/' + encodeURIComponent(reportId) + '/create-case', { method: 'POST', body: payload });
      alert('Case created and linked: ' + created.case_id);
      loadLinkedCases();
    } catch (e) {
      if (e && e.status === 409) alert('Conflict (409): idempotency key reused with different payload.');
      else alert((e && e.data && e.data.error && e.data.error.message) || 'Create failed');
    }
  });
  insp.appendChild(createFromReportBtn);
  const createBtn = escEl('button', 'Create Research Case (not linked)', 'btn primary');
  createBtn.style.marginTop = '8px';
  createBtn.addEventListener('click', async () => {
    if (createBtn.disabled) return;
    const payload = { title: (detail && detail.title) || ('CTI Case ' + reportId), description: 'From CTI report ' + reportId, initial_client_id: cid };
    const canonical = JSON.stringify([payload.title, payload.description, payload.initial_client_id]);
    if (!feedCtl.idemKey || feedCtl.idemPayloadHash !== canonical) {
      if (feedCtl.idemKey && feedCtl.idemPayloadHash && feedCtl.idemPayloadHash !== canonical) {
        alert('Idempotency conflict: payload changed after the key was issued. Generating a new key for the changed payload.');
      }
      feedCtl.idemKey = genIdempotencyKey();
      feedCtl.idemPayloadHash = canonical;
    }
    payload.idempotency_key = feedCtl.idemKey;
    createBtn.disabled = true;
    try {
      const created = await api('/api/v1/cases', { method: 'POST', body: payload });
      feedCtl.idemKey = ''; feedCtl.idemPayloadHash = '';
      alert('Research Case created: ' + created.case_id + '. Report is NOT marked as linked — no Case↔Report junction API exists. Retrying this action would create a NEW case (key reset on success).');
    }
    catch (e) {
      if (e && e.status === 409) alert('Conflict (409): same idempotency key, changed payload — key kept for retry. Do not change the payload and retry.');
      else alert('Create failed (retry reuses the same idempotency key): ' + ((e && e.data && e.data.error && e.data.error.message) || ('status ' + (e && e.status))));
    } finally { if (feedCtl.idemKey) createBtn.disabled = false; }
  });
  insp.appendChild(createBtn);
}
/* ---------- V3-F6: QRadar Inventory / Detection / Clients / Hypotheses ---------- */
let qrCtl = { seq: 0, selectSeq: 0, tab: 'rules' };
let detCtl = { seq: 0, selectSeq: 0 };
let cliCtl = { seq: 0, selectSeq: 0 };
let hypCtl = { seq: 0, selectSeq: 0 };
function pageShell(eyebrow, title, intro, bannerText, badgeText) {
  const c = document.getElementById('content'); c.innerHTML = '';
  const heading = document.createElement('div'); heading.className = 'heading';
  const left = document.createElement('div');
  left.appendChild(escEl('div', eyebrow, 'eyebrow'));
  left.appendChild(escEl('h1', title));
  left.appendChild(escEl('p', intro));
  heading.appendChild(left); c.appendChild(heading);
  const banner = document.createElement('div'); banner.className = 'demo-banner';
  banner.appendChild(escEl('span', bannerText, null));
  banner.appendChild(escEl('span', badgeText, 'badge mint'));
  c.appendChild(banner);
  const layout = document.createElement('div'); layout.className = 'v3layout';
  const listHost = document.createElement('div');
  const inspector = document.createElement('aside'); inspector.className = 'panel v3inspector';
  const ih = document.createElement('div'); ih.className = 'panelhead'; ih.appendChild(escEl('div', 'CONTEXT INSPECTOR', 'paneltitle'));
  const inspBody = document.createElement('div'); inspBody.className = 'panelbody';
  inspBody.setAttribute('role', 'status'); inspBody.setAttribute('aria-live', 'polite');
  inspBody.textContent = 'Select an item to inspect.';
  inspector.append(ih, inspBody);
  layout.append(listHost, inspector);
  c.appendChild(layout);
  return { c, listHost, inspBody };
}
function kvAdd(host, k, v) { const d = escEl('div', null, 'kv'); d.appendChild(escEl('div', k, 'kv-k')); d.appendChild(escEl('div', v ? String(v) : 'Not available / not verified', 'kv-v')); host.appendChild(d); }
function secAdd(host, t) { const s = escEl('div', t, 'paneltitle'); s.style.margin = '14px 0 8px'; host.appendChild(s); }
/* ---------- M7-C: Client Relevance (read-only badges + assess + review) ---------- */
function relBadge(v) { const b = escEl('span', v || 'UNKNOWN', v === 'MATCH' ? 'badge mint' : (v === 'NO_MATCH' ? 'badge muted' : 'badge amber')); b.style.marginRight = '4px'; return b; }
async function loadRelevanceInto(host, reportId, cid) {
  host.innerHTML = '';
  const state = escEl('div', 'Loading…', 'statebox'); host.appendChild(state);
  try {
    const d = await api('/api/v1/cti/reports/' + encodeURIComponent(reportId) + '/relevance/' + encodeURIComponent(cid));
    if (host.isConnected === false) return;
    state.remove();
    if (!d || !d.findings) { host.appendChild(escEl('div', 'No assessment yet.', 'text-muted')); return; }
    if (d.status === 'FAILED') { host.appendChild(escEl('div', 'Last assessment FAILED (' + (d.error_code || 'compute_error') + '). Retry allowed.', 'text-muted')); return; }
    host.appendChild(escEl('div', 'Assessment ' + d.assessment_id + ' • rules ' + (d.matching_rule_version || '—') + ' • inventory ' + String(d.inventory_snapshot || '').slice(0, 16) + '…', 'text-muted'));
    d.findings.forEach(f => {
      const row = escEl('div', null, 'row'); row.style.display = 'flex'; row.style.flexWrap = 'wrap'; row.style.gap = '4px'; row.style.alignItems = 'center';
      row.append(relBadge(f.verdict), escEl('strong', f.dimension), escEl('span', f.explanation || '', 'text-muted'));
      host.appendChild(row);
      (f.unknowns || []).forEach(u => host.appendChild(escEl('div', '• unknown: ' + u, 'text-muted')));
      (f.limitations || []).forEach(u => host.appendChild(escEl('div', '• limitation: ' + u, 'text-muted')));
      (f.evidence || []).forEach(e => host.appendChild(escEl('div', '• evidence ' + e.matched_entity_type + ' ' + e.matched_entity_id + ' via ' + e.matching_rule_id + ' v' + e.matching_rule_version + (e.inventory_evidence ? ' ' + e.inventory_evidence : ''), 'text-muted')));
    });
    (d.reviews || []).forEach(r => host.appendChild(escEl('div', 'Review ' + r.dimension + ': ' + r.original_verdict + ' → ' + r.override_verdict + ' (' + r.reason + ')', 'text-muted')));
    // Reviewer override (append-only; never mutates findings). Original verdict must equal computed.
    const role = me && me.user && me.user.role;
    if (role === 'ADMINISTRATOR' || role === 'REVIEWER') {
      const fr = document.createElement('div'); fr.style.display = 'flex'; fr.style.gap = '4px'; fr.style.flexWrap = 'wrap'; fr.style.marginTop = '6px';
      const dim = document.createElement('select'); dim.setAttribute('aria-label', 'Review dimension');
      ['SECTOR', 'TECHNOLOGY', 'TELEMETRY'].forEach(x => { const o = document.createElement('option'); o.value = x; o.textContent = x; dim.appendChild(o); });
      const ovr = document.createElement('select'); ovr.setAttribute('aria-label', 'Override verdict');
      ['MATCH', 'NO_MATCH', 'UNKNOWN'].forEach(x => { const o = document.createElement('option'); o.value = x; o.textContent = x; ovr.appendChild(o); });
      const reason = document.createElement('input'); reason.placeholder = 'Reason (required)'; reason.setAttribute('aria-label', 'Review reason');
      const btn = escEl('button', 'Submit review', 'btn primary btn-sm');
      btn.addEventListener('click', async () => {
        if (!reason.value.trim()) { alert('Reason is required.'); return; }
        const orig = (d.findings.find(f => f.dimension === dim.value) || {}).verdict;
        if (!orig) { alert('No computed finding for this dimension.'); return; }
        try {
          await api('/api/v1/cti/reports/' + encodeURIComponent(d.report_id) + '/relevance/' + encodeURIComponent(d.client_id) + '/review', { method: 'POST', body: { assessment_id: d.assessment_id, dimension: dim.value, original_verdict: orig, override_verdict: ovr.value, reason: reason.value.trim() } });
          alert('Review recorded (append-only).');
          loadRelevanceInto(host, d.report_id, d.client_id);
        } catch (e) { alert((e && e.data && e.data.error && e.data.error.message) || 'Review failed'); }
      });
      fr.append(dim, ovr, reason, btn);
      host.appendChild(fr);
    }
  } catch (e) {
    state.remove();
    if (e && e.status === 404) host.appendChild(escEl('div', 'No assessment yet.', 'text-muted'));
    else if (e && e.status === 403) host.appendChild(escEl('div', 'Access denied (403).', 'text-muted'));
    else if (e && e.status === 503) host.appendChild(escEl('div', 'Relevance unavailable (schema not applied).', 'text-muted'));
    else host.appendChild(escEl('div', 'Relevance unavailable (' + ((e && e.status) || 'network') + ').', 'text-muted'));
  }
}
function assessRelevanceInto(host, reportId, cid, role) {
  const can = role === 'CTI_ANALYST' || role === 'ADMINISTRATOR';
  const btn = escEl('button', 'Assess relevance (POST)', 'btn primary btn-sm'); btn.style.marginTop = '8px'; btn.disabled = !can;
  if (!can) btn.textContent = 'Assess relevance — denied (role ' + role + ')';
  let key = '';
  const relHost = document.createElement('div'); relHost.id = 'rel-host';
  const reload = () => loadRelevanceInto(relHost, reportId, cid);
  btn.addEventListener('click', async () => {
    if (!can) return;
    if (!key) key = genIdempotencyKey();
    btn.disabled = true;
    try {
      const r = await api('/api/v1/cti/reports/' + encodeURIComponent(reportId) + '/relevance/' + encodeURIComponent(cid) + '/assess', { method: 'POST', body: { idempotency_key: key } });
      if (r && r.created) key = '';
      await reload();
    } catch (e) {
      if (e && e.status === 409) { alert('Conflict (409): idempotency key reused with different payload.'); key = ''; }
      else alert((e && e.data && e.data.error && e.data.error.message) || 'Assess failed');
      btn.disabled = false;
    }
  });
  host.append(btn, relHost);
  reload();
}
async function renderQRadar() {
  const seq = ++qrCtl.seq;
  const { listHost, inspBody } = pageShell('DETECTION / INVENTORY', 'QRadar Inventory', 'Global QRadar inventory from confirmed endpoints (Rules, Building Blocks, Custom Fields). Global rules/fields are shared; no per-client filtering is applied here — client telemetry is per-client (see Detection / Client Intelligence).', 'Global inventory (shared) — no QRadar backend changes', 'EXISTS');
  const toolbar = document.createElement('div'); toolbar.className = 'filterbar';
  const tabs = document.createElement('div'); tabs.className = 'tabs';
  const tabDefs = [['rules', 'Rules'], ['bbs', 'Building Blocks'], ['fields', 'Custom Fields']];
  const buttons = {};
  tabDefs.forEach(([id, label]) => {
    const b = escEl('button', label, 'tab' + (qrCtl.tab === id ? ' active' : ''));
    b.addEventListener('click', () => { qrCtl.tab = id; qrCtl.seq++; buttons[Object.keys(buttons)[0]] && null; Object.values(buttons).forEach(x => x.classList.remove('active')); b.classList.add('active'); loadTab(id); });
    buttons[id] = b; tabs.appendChild(b);
  });
  toolbar.appendChild(tabs);
  const searchLab = document.createElement('label'); searchLab.style.display = 'flex'; searchLab.style.alignItems = 'center'; searchLab.style.gap = '8px';
  searchLab.appendChild(escEl('span', 'Filter', 'eyebrow'));
  const searchInp = document.createElement('input'); searchInp.placeholder = 'Filter loaded list…'; searchInp.setAttribute('aria-label', 'Filter');
  searchLab.appendChild(searchInp);
  toolbar.appendChild(searchLab);
  document.getElementById('content').insertBefore(toolbar, document.querySelector('.v3layout'));
  let cache = [];
  const paint = () => {
    listHost.innerHTML = '';
    const q = (searchInp.value || '').toLowerCase();
    const rows = cache.filter(r => !q || JSON.stringify(r).toLowerCase().includes(q)).slice(0, 200);
    const t = escEl('div', 'Showing ' + rows.length + ' of ' + cache.length + ' (filter applies to loaded list; backend has no full-text search)', 'paneltitle');
    t.style.marginBottom = '10px'; listHost.appendChild(t);
    if (!rows.length) { listHost.appendChild(escEl('div', 'No items. Empty inventory or filter excludes all.', 'statebox')); return; }
    rows.forEach(r => {
      const btn = escEl('button', null, 'sel-row'); btn.setAttribute('role', 'option');
      const title = escEl('strong', r.title || r.id);
      const meta = escEl('div', r.meta || '', 'text-muted');
      btn.append(title, meta);
      btn.addEventListener('click', () => selectQrItem(r));
      listHost.appendChild(btn);
    });
  };
  searchInp.addEventListener('input', paint);
  const loadTab = async (tab) => {
    const mySeq = qrCtl.seq;
    listHost.innerHTML = ''; listHost.appendChild(escEl('div', 'Loading…', 'statebox'));
    inspBody.textContent = 'Select an item to inspect.';
    try {
      const TIMEOUT = 8000;
      if (tab === 'rules') {
        const d = await withTimeout(api('/api/v1/qradar/rules'), TIMEOUT, 'QRadar rules');
        if (mySeq !== qrCtl.seq) return;
        cache = (d.rules || []).map(r => ({ id: r.rule_id, title: r.rule_name || r.rule_id, meta: 'Rule ' + r.rule_id + ' • ' + (r.criticality || 'Not available') + ' • ' + (r.log_source || 'Not available') + ' • enabled ' + (r.enabled ? 'yes' : 'no'), ref: r }));
      } else if (tab === 'bbs') {
        const d = await withTimeout(api('/api/v1/qradar/building-blocks'), TIMEOUT, 'Building blocks');
        if (mySeq !== qrCtl.seq) return;
        cache = (d.building_blocks || []).map(b => ({ id: b.bb_id, title: b.bb_name || b.bb_id, meta: 'BB ' + b.bb_id + ' • ' + (b.category || 'Not available') + ' • ' + (b.availability || 'Not available'), ref: b, kind: 'bb' }));
      } else {
        const d = await withTimeout(api('/api/v1/qradar/fields'), TIMEOUT, 'QRadar fields');
        if (mySeq !== qrCtl.seq) return;
        cache = (d.fields || []).map(f => ({ id: f.field_id, title: f.field_name || f.field_id, meta: 'Field ' + f.field_id + ' • ' + (f.field_type || 'Not available') + ' • ' + (f.availability || 'Not available') + ' • ' + (f.display_name || ''), ref: f, kind: 'field' }));
      }
      paint();
    } catch (e) {
      if (mySeq !== qrCtl.seq) return;
      listHost.innerHTML = '';
      const msg = (e && e.status === 0) ? 'Request failed (timeout). The endpoint did not respond in 8s — see server diagnostic report.' : (e && e.status === 401) ? 'Session expired (401).' : (e && e.status === 403) ? 'Access denied (403).' : 'Failed to load';
      listHost.appendChild(escEl('div', msg, 'statebox'));
    }
  };
  const selectQrItem = async (r) => {
    const mySelect = ++qrCtl.selectSeq;
    inspBody.innerHTML = 'Loading…';
    if (r.kind === 'field') {
      const f = r.ref;
      inspBody.innerHTML = '';
      inspBody.appendChild(escEl('div', 'Custom Field ' + f.field_id, 'kv-k'));
      kvAdd(inspBody, 'Name', f.field_name); kvAdd(inspBody, 'Display name', f.display_name); kvAdd(inspBody, 'Type', f.field_type);
      kvAdd(inspBody, 'Availability', f.availability); kvAdd(inspBody, 'Log sources', f.log_sources); kvAdd(inspBody, 'Adversary control', f.adversary_control);
      kvAdd(inspBody, 'Normalized name', f.normalized_name); kvAdd(inspBody, 'Aliases', f.aliases); kvAdd(inspBody, 'Used in events', f.used_in_events);
      kvAdd(inspBody, 'Source type', f.source_type); kvAdd(inspBody, 'Active', f.is_active ? 'yes' : 'no');
      return;
    }
    try {
      const detail = r.kind === 'bb'
        ? await api('/api/v1/qradar/building-blocks/' + encodeURIComponent(r.id))
        : await api('/api/v1/qradar/rules/' + encodeURIComponent(r.id));
      if (mySelect !== qrCtl.selectSeq) return;
      inspBody.innerHTML = '';
      if (r.kind === 'bb') {
        inspBody.appendChild(escEl('div', 'Building Block ' + detail.bb_id, 'kv-k'));
        kvAdd(inspBody, 'Name', detail.bb_name); kvAdd(inspBody, 'Level', detail.level); kvAdd(inspBody, 'Category', detail.category);
        kvAdd(inspBody, 'Depends on', detail.depends_on_bb); kvAdd(inspBody, 'Availability', detail.availability); kvAdd(inspBody, 'Adversary control', detail.adversary_control);
        kvAdd(inspBody, 'Sysmon required', detail.sysmon_required ? 'yes' : 'no'); kvAdd(inspBody, 'Own conditions', detail.own_conditions); kvAdd(inspBody, 'Logic', detail.full_bb_logic); kvAdd(inspBody, 'Notes', detail.notes);
      } else {
        inspBody.appendChild(escEl('div', 'QRadar Rule ' + detail.rule_id, 'kv-k'));
        kvAdd(inspBody, 'Name', detail.rule_name); kvAdd(inspBody, 'Enabled', detail.enabled ? 'yes' : 'no');
        kvAdd(inspBody, 'Criticality', detail.criticality); kvAdd(inspBody, 'Log source', detail.log_source);
        kvAdd(inspBody, 'MITRE techniques', (detail.mitre_techniques || []).join(', ') || 'Not available / not verified');
        kvAdd(inspBody, 'Sysmon required', detail.sysmon_required ? 'yes' : 'no');
        kvAdd(inspBody, 'Events 30d', detail.event_count_30d); kvAdd(inspBody, 'Offenses 30d', detail.offense_count_30d);
        kvAdd(inspBody, 'Created', detail.created_date); kvAdd(inspBody, 'Modified', detail.modified_date);
        kvAdd(inspBody, 'Full logic', detail.full_rule_logic); kvAdd(inspBody, 'Effective logic', detail.effective_detection_logic);
        kvAdd(inspBody, 'BB chain', detail.bb_chain_summary); kvAdd(inspBody, 'Reference sets', (detail.reference_sets_used || []).join(', ') || 'Not available / not verified');
        kvAdd(inspBody, 'Custom fields', (detail.custom_fields || []).length + ' entries'); kvAdd(inspBody, 'Building blocks', (detail.building_blocks || []).length + ' entries');
      }
    } catch (e) {
      if (mySelect !== qrCtl.selectSeq) return;
      inspBody.textContent = 'Detail unavailable (' + ((e && e.status) || 0) + ').';
    }
  };
  loadTab(qrCtl.tab);
}
async function renderDetection() {
  const seq = ++detCtl.seq;
  const grantList = (me.authorized_clients || []);
  const topCtx = document.getElementById('tenant') ? document.getElementById('tenant').value : 'global';
  const startClient = (topCtx !== 'global' && grantList.includes(topCtx)) ? topCtx : '';
  const { listHost, inspBody } = pageShell('DETECTION / COVERAGE', 'Detection Coverage', 'Coverage is shown only from confirmed fields. A rule existing does not mean COVERED: rule exists, data source available, required fields verified, and detection validated are separate questions.', 'Rule exists ≠ covered — unverified states are honest', 'INVENTORY');
  const toolbar = document.createElement('div'); toolbar.className = 'filterbar';
  const lab = document.createElement('label'); lab.style.display = 'flex'; lab.style.alignItems = 'center'; lab.style.gap = '8px';
  lab.appendChild(escEl('span', (topCtx === 'global' ? 'Telemetry Client (topbar: Global Research)' : 'Telemetry Client (topbar context = ' + topCtx + ')'), 'eyebrow'));
  const sel = document.createElement('select'); sel.setAttribute('aria-label', 'Telemetry client');
  const ph = document.createElement('option'); ph.value = ''; ph.textContent = 'Select authorized client…'; sel.appendChild(ph);
  grantList.forEach(cid => { const o = document.createElement('option'); o.value = cid; o.textContent = cid; sel.appendChild(o); });
  lab.appendChild(sel);
  toolbar.appendChild(lab);
  const note = escEl('span', '', 'text-muted'); note.id = 'det-ctx-note'; toolbar.appendChild(note);
  document.getElementById('content').insertBefore(toolbar, document.querySelector('.v3layout'));
  const updateNote = (cid) => { note.textContent = grantList.length ? ('Telemetry client: ' + (cid || 'not selected') + '. Telemetry is per-client; global rules/fields are shared.') : 'No authorized CLIENT grants — metadata only.'; };
  updateNote(startClient);
  listHost.innerHTML = ''; listHost.appendChild(escEl('div', 'Loading…', 'statebox'));
  let rules = [], detRules = [], telemetry = [];
  const paint = () => {
    listHost.innerHTML = '';
    const t = escEl('div', 'Rules: ' + rules.length + ' QRadar + ' + detRules.length + ' inventory; telemetry rows: ' + telemetry.length + ' (client: ' + (detCtl.client || 'not selected') + ')', 'paneltitle');
    t.style.marginBottom = '10px'; listHost.appendChild(t);
    secAdd(listHost, 'MITRE ATT&CK mapping (from rule fields)');
    const all = [...rules.map(r => ({ name: r.rule_name || r.rule_id, id: r.rule_id, tech: (r.mitre_techniques || []).join(', ') || 'Not available / not verified', ls: r.log_source })), ...detRules.map(r => ({ name: r.rule_name || r.rule_id, id: r.rule_id, tech: r.mitre_techniques || 'Not available / not verified', ls: r.log_source }))].slice(0, 50);
    if (!all.length) listHost.appendChild(escEl('div', 'No mapping rules returned. Empty inventory — not a coverage claim.', 'text-muted'));
    all.forEach(r => listHost.appendChild(escEl('div', '• ' + r.name + ' (' + r.id + ') — MITRE ' + r.tech + ' • log source ' + (r.ls || 'Not available / not verified'), 'row')));
    secAdd(listHost, 'Coverage questions per rule (capped 25)');
    all.slice(0, 25).forEach(r => {
      const hasTelem = telemetry.some(t => t.log_source_type_id && r.ls && t.log_source_type_id.toLowerCase().includes(String(r.ls).toLowerCase().slice(0, 6)));
      listHost.appendChild(escEl('div', '• ' + r.name + ' — rule exists: yes; data source available: ' + (telemetry.length ? (hasTelem ? 'likely (telemetry present)' : 'Unknown') : 'Not verified') + '; required fields verified: Not verified; detection validated: Not verified', 'row'));
    });
    secAdd(listHost, 'Telemetry (confirmed fields only)');
    if (!telemetry.length) listHost.appendChild(escEl('div', 'No telemetry rows for the selected client (or none selected). Not verified.', 'text-muted'));
    telemetry.slice(0, 50).forEach(t => listHost.appendChild(escEl('div', '• ' + (t.log_source_type_id || t.status_id) + ' • ' + (t.connection_status || 'Not available') + ' • ' + (t.event_volume_status || '') + ' • ' + (t.last_event_timestamp || ''), 'row')));
  };
  const loadAll = async (cid) => {
    const mySeq = detCtl.seq;
    detCtl.selectSeq++; detCtl.client = cid || '';
    updateNote(cid);
    inspBody.textContent = 'Select a rule or telemetry row summary is shown at left. No invented coverage.';
    if (!cid) {
      listHost.innerHTML = ''; listHost.appendChild(escEl('div', 'Select an authorized client for telemetry. Global rules above remain visible.', 'statebox'));
      try {
        const [qr, inv] = await Promise.all([withTimeout(api('/api/v1/qradar/rules'), 8000, 'QRadar rules'), withTimeout(api('/api/v1/inventory/rules'), 8000, 'Detection rules')]);
        if (mySeq !== detCtl.seq) return;
        rules = qr.rules || []; detRules = inv.rules || []; telemetry = [];
        paint();
      } catch (e) {
        if (mySeq !== detCtl.seq) return;
        listHost.innerHTML = ''; listHost.appendChild(escEl('div', (e && e.status === 0) ? 'Request failed (timeout). The endpoint did not respond in 8s — see server diagnostic report.' : 'Failed to load rules', 'statebox'));
      }
      return;
    }
    if (!grantList.includes(cid)) { listHost.innerHTML = ''; listHost.appendChild(escEl('div', 'No grant for selected client — telemetry denied.', 'statebox')); return; }
    listHost.innerHTML = ''; listHost.appendChild(escEl('div', 'Loading…', 'statebox'));
    try {
      const TIMEOUT = 8000;
      const [qr, inv, tm] = await Promise.all([
        withTimeout(api('/api/v1/qradar/rules'), TIMEOUT, 'QRadar rules'),
        withTimeout(api('/api/v1/inventory/rules'), TIMEOUT, 'Detection rules'),
        withTimeout(api('/api/v1/inventory/telemetry', { headers: { 'X-Client-ID': cid } }), TIMEOUT, 'Telemetry')
      ]);
      if (mySeq !== detCtl.seq) return;
      rules = qr.rules || []; detRules = inv.rules || []; telemetry = tm.telemetry || [];
      paint();
    } catch (e) {
      if (mySeq !== detCtl.seq) return;
      listHost.innerHTML = '';
      listHost.appendChild(escEl('div', (e && e.status === 403) ? 'Access denied (403).' : (e && e.status === 0) ? 'Request failed (timeout). The endpoint did not respond in 8s — see server diagnostic report.' : 'Failed to load', 'statebox'));
    }
  };
  sel.addEventListener('change', () => { detCtl.seq++; loadAll(sel.value); });
  if (startClient) { sel.value = startClient; loadAll(startClient); } else { loadAll(''); }
}
async function renderClients() {
  const seq = ++cliCtl.seq;
  const grantList = (me.authorized_clients || []);
  const topCtx = document.getElementById('tenant') ? document.getElementById('tenant').value : 'global';
  const startClient = (topCtx !== 'global' && grantList.includes(topCtx)) ? topCtx : '';
  const { listHost, inspBody } = pageShell('SOC / CLIENTS', 'Client Intelligence', 'Only authorized client context is shown (backend grant-filtered). Sector, technology, telemetry, and relevance appear only when the backend returns confirmed values.', 'Authorized clients only — Global Research grants no private access', 'PER-CLIENT');
  const toolbar = document.createElement('div'); toolbar.className = 'filterbar';
  const lab = document.createElement('label'); lab.style.display = 'flex'; lab.style.alignItems = 'center'; lab.style.gap = '8px';
  lab.appendChild(escEl('span', (topCtx === 'global' ? 'Source Client (topbar: Global Research)' : 'Client (topbar context = ' + topCtx + ')'), 'eyebrow'));
  const sel = document.createElement('select'); sel.setAttribute('aria-label', 'Client');
  const ph = document.createElement('option'); ph.value = ''; ph.textContent = 'Select authorized client…'; sel.appendChild(ph);
  grantList.forEach(cid => { const o = document.createElement('option'); o.value = cid; o.textContent = cid; sel.appendChild(o); });
  lab.appendChild(sel);
  toolbar.appendChild(lab);
  const note = escEl('span', '', 'text-muted'); note.id = 'cli-ctx-note'; toolbar.appendChild(note);
  document.getElementById('content').insertBefore(toolbar, document.querySelector('.v3layout'));
  const updateNote = (cid, total) => { note.textContent = 'Source client: ' + (cid || 'not selected') + ' • authorized clients visible: ' + (total != null ? total : '…') + '. Sector/technology/relevance: Not available / not verified (no endpoint).'; };
  updateNote(startClient);
  listHost.innerHTML = ''; listHost.appendChild(escEl('div', 'Loading…', 'statebox'));
  let clients = [];
  const load = async (cid) => {
    const mySeq = cliCtl.seq;
    cliCtl.selectSeq++;
    inspBody.textContent = 'Select a client.';
    if (!cid) { listHost.innerHTML = ''; listHost.appendChild(escEl('div', 'Select an authorized client.', 'statebox')); updateNote(''); return; }
    if (!grantList.includes(cid)) { listHost.innerHTML = ''; listHost.appendChild(escEl('div', 'No grant — denied.', 'statebox')); return; }
    updateNote(cid, clients.length);
    listHost.innerHTML = ''; listHost.appendChild(escEl('div', 'Loading…', 'statebox'));
    try {
      const d = await api('/api/v1/clients');
      if (mySeq !== cliCtl.seq) return;
      clients = d.clients || [];
      updateNote(cid, clients.length);
      listHost.innerHTML = '';
      const me_ = clients.find(x => x.client_id === cid);
      if (!me_) { listHost.appendChild(escEl('div', 'Client not in authorized list — not displayed (no private metadata).', 'statebox')); inspBody.textContent = 'No data.'; return; }
      const row = escEl('button', null, 'sel-row');
      row.append(escEl('strong', me_.client_name || me_.client_id), escEl('div', 'Client ' + me_.client_id + ' • status ' + (me_.status || 'Not available'), 'text-muted'));
      row.addEventListener('click', () => selectCli(me_.client_id, mySeq));
      listHost.appendChild(row);
      selectCli(me_.client_id, mySeq);
    } catch (e) {
      if (mySeq !== cliCtl.seq) return;
      listHost.innerHTML = ''; listHost.appendChild(escEl('div', 'Failed to load clients', 'statebox'));
    }
  };
  const selectCli = async (cid, seq2) => {
    const mySelect = ++cliCtl.selectSeq;
    inspBody.innerHTML = 'Loading…';
    try {
      const d = await api('/api/v1/clients');
      if (mySelect !== cliCtl.selectSeq || seq2 !== cliCtl.seq) return;
      const me_ = (d.clients || []).find(x => x.client_id === cid);
      if (!me_) { inspBody.textContent = 'Not authorized.'; return; }
      let tm = null;
      try { tm = await api('/api/v1/inventory/telemetry', { headers: { 'X-Client-ID': cid } }); } catch (_) {}
      if (mySelect !== cliCtl.selectSeq) return;
      inspBody.innerHTML = '';
      inspBody.appendChild(escEl('div', 'Client ' + cid, 'kv-k'));
      kvAdd(inspBody, 'Name', me_.client_name); kvAdd(inspBody, 'Status', me_.status);
      kvAdd(inspBody, 'Created', me_.created_at); kvAdd(inspBody, 'Updated', me_.updated_at);
      kvAdd(inspBody, 'Sector', 'Not available / not verified'); kvAdd(inspBody, 'Technology', 'Not available / not verified');
      kvAdd(inspBody, 'Relevance score', 'Not available / not verified');
      secAdd(inspBody, 'Telemetry');
      const arr = (tm && tm.telemetry) || [];
      if (!arr.length) inspBody.appendChild(escEl('div', 'No telemetry rows — Not verified.', 'text-muted'));
      arr.slice(0, 20).forEach(t => inspBody.appendChild(escEl('div', '• ' + (t.log_source_type_id || t.status_id) + ' • ' + (t.connection_status || 'Not available'), 'row')));
      // M7-C: Relevant reports (MATCH in ≥1 dimension, latest assessment per report).
      secAdd(inspBody, 'Relevant reports (M7-C)');
      const relHost = escEl('div', 'Loading…', 'text-muted'); inspBody.appendChild(relHost);
      try {
        const rd = await api('/api/v1/clients/' + encodeURIComponent(cid) + '/relevant-reports?limit=20&offset=0');
        if (mySelect !== cliCtl.selectSeq) return;
        relHost.innerHTML = '';
        const rows = (rd && rd.reports) || [];
        if (!rows.length) relHost.textContent = 'No MATCH reports for this client.';
        rows.forEach(r => relHost.appendChild(escEl('div', '• ' + (r.report_id || '') + ' • ' + (r.assessment_id || ''), 'row')));
      } catch (ex) {
        if (mySelect !== cliCtl.selectSeq) return;
        relHost.textContent = (ex && ex.status === 403) ? 'Access denied (403).' : (ex && ex.status === 503) ? 'Relevance unavailable (schema not applied).' : 'Relevant reports unavailable.';
      }
    } catch (e) {
      if (mySelect !== cliCtl.selectSeq) return;
      inspBody.textContent = 'Detail unavailable (' + ((e && e.status) || 0) + ').';
    }
  };
  sel.addEventListener('change', () => { cliCtl.seq++; load(sel.value); });
  if (startClient) { sel.value = startClient; load(startClient); } else { load(''); }
}
async function renderHypotheses() {
  const seq = ++hypCtl.seq;
  const grantList = (me.authorized_clients || []);
  const topCtx = document.getElementById('tenant') ? document.getElementById('tenant').value : 'global';
  const startClient = (topCtx !== 'global' && grantList.includes(topCtx)) ? topCtx : '';
  const { listHost, inspBody } = pageShell('THREAT HUNTING / LAB', 'Hypothesis Lab', 'Authorized hunt hypotheses from GET /api/v1/hypotheses (grant-filtered). No Hypothesis Authoring API is claimed here.', 'Grant-filtered hypotheses only', 'EXISTS');
  const toolbar = document.createElement('div'); toolbar.className = 'filterbar';
  const lab = document.createElement('label'); lab.style.display = 'flex'; lab.style.alignItems = 'center'; lab.style.gap = '8px';
  lab.appendChild(escEl('span', 'Client filter', 'eyebrow'));
  const sel = document.createElement('select'); sel.setAttribute('aria-label', 'Client filter');
  const all = document.createElement('option'); all.value = ''; all.textContent = 'All authorized clients'; sel.appendChild(all);
  grantList.forEach(cid => { const o = document.createElement('option'); o.value = cid; o.textContent = cid; if (startClient === cid) o.selected = true; sel.appendChild(o); });
  lab.appendChild(sel);
  toolbar.appendChild(lab);
  const note = escEl('span', '', 'text-muted'); note.id = 'hyp-ctx-note'; toolbar.appendChild(note);
  document.getElementById('content').insertBefore(toolbar, document.querySelector('.v3layout'));
  const updateNote = (cid, total) => { note.textContent = 'Filter client: ' + (cid || 'all authorized') + ' • total (server): ' + (total != null ? total : '…') + '. Linked-case search is bounded to first 20 visible cases.'; };
  updateNote(startClient);
  listHost.innerHTML = ''; listHost.appendChild(escEl('div', 'Loading…', 'statebox'));
  const load = async (cid) => {
    const mySeq = hypCtl.seq;
    hypCtl.selectSeq++;
    inspBody.textContent = 'Select a hypothesis.';
    updateNote(cid);
    listHost.innerHTML = ''; listHost.appendChild(escEl('div', 'Loading…', 'statebox'));
    try {
      const q = cid ? ('?client_id=' + encodeURIComponent(cid) + '&limit=100&offset=0') : '?limit=100&offset=0';
      const d = await api('/api/v1/hypotheses' + q);
      if (mySeq !== hypCtl.seq) return;
      updateNote(cid, d.total);
      listHost.innerHTML = '';
      const rows = d.hypotheses || [];
      if (!rows.length) { listHost.appendChild(escEl('div', 'No hypotheses for current filter.', 'statebox')); return; }
      const t = escEl('div', 'Showing ' + rows.length + ' of ' + d.total + ' (server total, limit 100)', 'paneltitle');
      t.style.marginBottom = '10px'; listHost.appendChild(t);
      rows.forEach(h => {
        if (cid && h.client_id && h.client_id !== cid) return;
        if (!cid && h.client_id && !grantList.includes(h.client_id)) return;
        const btn = escEl('button', null, 'sel-row'); btn.setAttribute('role', 'option');
        btn.append(escEl('strong', h.title || h.hypothesis_id), escEl('div', 'Client ' + (h.client_id || 'Not available') + ' • ' + (h.status || 'Not available') + ' • ' + (h.hypothesis_id || ''), 'text-muted'));
        btn.addEventListener('click', () => selectHyp(h, mySeq));
        listHost.appendChild(btn);
      });
    } catch (e) {
      if (mySeq !== hypCtl.seq) return;
      listHost.innerHTML = ''; listHost.appendChild(escEl('div', 'Failed to load hypotheses', 'statebox'));
    }
  };
  const selectHyp = async (h, seq2) => {
    const mySelect = ++hypCtl.selectSeq;
    inspBody.innerHTML = 'Loading…';
    inspBody.appendChild(escEl('div', 'Hypothesis ' + (h.hypothesis_id || ''), 'kv-k'));
    kvAdd(inspBody, 'Title', h.title); kvAdd(inspBody, 'Client', h.client_id); kvAdd(inspBody, 'Status', h.status);
    kvAdd(inspBody, 'Description', h.description);
    secAdd(inspBody, 'Linked Research Case (bounded search)');
    inspBody.appendChild(escEl('div', 'Searching first 20 visible cases…', 'text-muted'));
    try {
      const cases = await api('/api/v1/cases?limit=20&offset=0');
      if (mySelect !== hypCtl.selectSeq) return;
      let linked = null;
      for (const cs of (cases.cases || [])) {
        if (mySelect !== hypCtl.selectSeq) return;
        try {
          const lh = await api('/api/v1/cases/' + encodeURIComponent(cs.case_id) + '/hypotheses?limit=100&offset=0');
          if ((lh.hypotheses || []).some(x => x.hypothesis_id === h.hypothesis_id)) { linked = cs; break; }
        } catch (_) {}
      }
      if (mySelect !== hypCtl.selectSeq) return;
      // drop the "searching" line (last child)
      if (inspBody.lastChild) inspBody.removeChild(inspBody.lastChild);
      if (!linked) { inspBody.appendChild(escEl('div', 'Not linked in the bounded search (first 20 visible cases). No link is claimed.', 'text-muted')); return; }
      const row = escEl('div', 'Linked case: ' + (linked.title || linked.case_id), 'row');
      inspBody.appendChild(row);
      const btn = escEl('button', 'Open linked case', 'btn primary'); btn.style.marginTop = '8px';
      btn.addEventListener('click', () => { currentCaseId = linked.case_id; navigate('case', { case_id: linked.case_id }); });
      inspBody.appendChild(btn);
    } catch (e) {
      if (mySelect !== hypCtl.selectSeq) return;
      if (inspBody.lastChild) inspBody.removeChild(inspBody.lastChild);
      inspBody.appendChild(escEl('div', 'Linked-case search unavailable (' + ((e && e.status) || 0) + ').', 'text-muted'));
    }
  };
  sel.addEventListener('change', () => { hypCtl.seq++; load(sel.value); });
  load(sel.value);
}
function renderPlaceholder(key, body) {
  const c = document.getElementById('content');
  c.innerHTML = '';
  const name = ROUTES.flatMap(g => g[1]).find(r => r[0] === key)?.[2] || key;
  const h = document.createElement('div'); h.className = 'heading';
  const left = document.createElement('div');
  left.appendChild(escEl('div', 'WORKSPACE', 'eyebrow'));
  left.appendChild(escEl('h1', name));
  const p = escEl('p', body); left.appendChild(p);
  h.appendChild(left);
  c.appendChild(h);
  const box = document.createElement('div'); box.className = 'statebox';
  box.textContent = 'This route is a V3 shell placeholder. Content lands in later stages; backend contracts are unchanged.';
  c.appendChild(box);
}

async function loadMe() {
  try {
    me = await api('/api/v1/auth/me');
    document.getElementById('user-name').textContent = me.user.id;
    document.getElementById('user-role').textContent = me.user.role;
    document.getElementById('avatar').textContent = (me.user.id || '?').slice(0,2).toUpperCase();
    const sel = document.getElementById('tenant');
    sel.innerHTML = '';
    const glob = document.createElement('option'); glob.value = 'global'; glob.textContent = '◈ Global Research (metadata only)'; sel.appendChild(glob);
    (me.authorized_clients || []).forEach(c => {
      const o = document.createElement('option'); o.value = c; o.textContent = c; sel.appendChild(o);
    });
    if (casesState.client && !me.authorized_clients.includes(casesState.client)) casesState.client = '';
  } catch (_) {
    showStateEssence('denied', 'Session expired or forbidden (401/403). Please sign in.');
    throw new Error('no session');
  }
}

/* ---------- Router ---------- */
function parseHash() {
  const h = location.hash.slice(1);
  const qi = h.indexOf('?');
  const route = qi >= 0 ? h.slice(0, qi) : h;
  const q = new URLSearchParams(qi >= 0 ? h.slice(qi+1) : '');
  return { route, q };
}
function navigate(route, params) {
  let valid = ROUTES.some(g => g[1].some(r => r[0] === route));
  if (!valid) route = 'home';
  current = route;
  const name = ROUTES.flatMap(g => g[1]).find(r => r[0] === route)?.[2] || 'Analyst Home';
  document.getElementById('crumb').textContent = name;
  renderNav();
  const qs = params ? ('?' + new URLSearchParams(params).toString()) : '';
  history.pushState(null, '', '#' + route + qs);
  renderRoute(route);
}
function renderRoute(route) {
  // Any navigation away from the workspace invalidates its in-flight requests.
  if (route !== 'hunt' && typeof hwCtl !== 'undefined') hwCtl.seq++;
  if (route === 'home') { renderHome(); }
  else if (route === 'feed' || route === 'reports') { renderFeed(); }
  else if (route === 'cases') { syncCasesFromURL(); renderCases(); }
  else if (route === 'case') { renderCase(); }
  else if (route === 'qradar') { renderQRadar(); }
  else if (route === 'detection') { renderDetection(); }
  else if (route === 'clients') { renderClients(); }
  else if (route === 'fields') { renderFieldIntelligence(); }
  else if (route === 'inventory') { renderInventoryWorkspace(); }
  else if (route === 'hypotheses') { renderHypotheses(); }
  else if (route === 'hunt') { renderHuntWorkspace(); }
  else { renderPlaceholder(route, 'Shell page — see matrix for readiness.'); }
}

/* ---------- Cases explorer (V3-F2) ---------- */
function casesQuery() {
  const q = new URLSearchParams();
  q.set('limit', String(casesState.limit)); q.set('offset', String(casesState.offset));
  if (casesState.status) q.set('status', casesState.status);
  if (casesState.priority) q.set('priority', casesState.priority);
  if (casesState.client) q.set('client_id', casesState.client);
  return q.toString();
}
function casesURL(params) {
  const p = params instanceof URLSearchParams ? params : new URLSearchParams(params);
  return '#cases' + (p.toString() ? '?' + p.toString() : '');
}
function showStateEssence(kind, msg, retry) {
  const c = document.getElementById('content');
  c.innerHTML = '';
  const d = document.createElement('div'); d.className = 'statebox'; d.setAttribute('role', kind==='error' ? 'alert' : 'status');
  d.textContent = msg;
  if (retry) { const b = escEl('button', 'Retry', 'btn primary'); b.style.marginTop = '12px'; b.addEventListener('click', retry); d.appendChild(document.createElement('br')); d.appendChild(b); }
  if (kind === 'denied') { const a = escEl('a', 'Go to Login', 'btn primary'); a.href = '../login.html'; a.style.display='inline-block'; a.style.marginTop='12px'; d.appendChild(document.createElement('br')); d.appendChild(a); }
  c.appendChild(d);
}
function syncCasesFromURL() {
  const { q } = parseHash();
  casesState = {
    limit: 20, offset: parseInt(q.get('offset')||'0', 10) || 0,
    total: 0, search: q.get('search')||'', status: q.get('status')||'', priority: q.get('priority')||'', client: q.get('client')||''
  };
}
function pushCasesRoute() {
  const p = new URLSearchParams();
  if (casesState.search) p.set('search', casesState.search);
  if (casesState.status) p.set('status', casesState.status);
  if (casesState.priority) p.set('priority', casesState.priority);
  if (casesState.client) p.set('client', casesState.client);
  if (casesState.offset) p.set('offset', String(casesState.offset));
  history.pushState(null, '', casesURL(p));
}
async function renderCases() {
  const c = document.getElementById('content');
  c.innerHTML = '';
  const heading = document.createElement('div'); heading.className = 'heading';
  const left = document.createElement('div');
  left.appendChild(escEl('div', 'INTELLIGENCE / RESEARCH', 'eyebrow'));
  left.appendChild(escEl('h1', 'Research Cases'));
  const p = escEl('p', 'Structured threat investigations with explicit per-client access boundaries. Global case metadata does not imply access to all linked client evidence.'); left.appendChild(p);
  const actions = document.createElement('div');
  const openBtn = escEl('button', 'Open Case Workspace', 'btn primary');
  openBtn.addEventListener('click', () => navigate('case', currentCaseId ? { case_id: currentCaseId } : {}));
  actions.appendChild(openBtn);
  heading.appendChild(left); heading.appendChild(actions);
  c.appendChild(heading);

  const toolbar = document.createElement('div'); toolbar.className = 'filterbar';
  const mkInput = (label, ph, val) => {
    const lab = document.createElement('label'); lab.style.display = 'flex'; lab.style.alignItems = 'center'; lab.style.gap = '8px';
    lab.appendChild(escEl('span', label, 'eyebrow'));
    const inp = document.createElement('input'); inp.type = 'text'; inp.placeholder = ph; inp.value = val || '';
    inp.setAttribute('aria-label', label);
    lab.appendChild(inp); return [lab, inp];
  };
  const [searchLab, searchInp] = mkInput('Search', 'Filter this page by title or reference…', casesState.search);
  const [statusLab, statusSel] = (() => {
    const lab = document.createElement('label'); lab.style.display='flex'; lab.appendChild(escEl('span','Status','eyebrow'));
    const s = document.createElement('select'); s.setAttribute('aria-label','Status');
    [['','All statuses'],['OPEN','Open'],['IN_PROGRESS','In progress'],['REVIEW','Review'],['CLOSED','Closed'],['ARCHIVED','Archived']].forEach(([v,t]) => { const o=document.createElement('option'); o.value=v; o.textContent=t; if (casesState.status===v) o.selected=true; s.appendChild(o); });
    lab.appendChild(s); return [lab, s];
  })();
  const [prioLab, prioSel] = (() => {
    const lab = document.createElement('label'); lab.style.display='flex'; lab.appendChild(escEl('span','Priority','eyebrow'));
    const s = document.createElement('select'); s.setAttribute('aria-label','Priority');
    [['','All priorities'],['P1','P1'],['P2','P2'],['P3','P3'],['P4','P4']].forEach(([v,t]) => { const o=document.createElement('option'); o.value=v; o.textContent=t; if (casesState.priority===v) o.selected=true; s.appendChild(o); });
    lab.appendChild(s); return [lab, s];
  })();
  const [clientLab, clientSel] = (() => {
    const lab = document.createElement('label'); lab.style.display='flex'; lab.appendChild(escEl('span','Client','eyebrow'));
    const s = document.createElement('select'); s.setAttribute('aria-label','Client');
    const all = document.createElement('option'); all.value=''; all.textContent='All clients'; s.appendChild(all);
    (me.authorized_clients || []).forEach(cid => { const o=document.createElement('option'); o.value=cid; o.textContent=cid; if (casesState.client===cid) o.selected=true; s.appendChild(o); });
    lab.appendChild(s); return [lab, s];
  })();
  const newBtn = escEl('button', '+ New Case', 'btn primary');
  toolbar.append(searchLab, statusLab, prioLab, clientLab, newBtn);
  c.appendChild(toolbar);

  const note = escEl('div', 'Search filters the current page (backend does not support full-text search). Total is permission-aware from the server.', 'text-muted');
  note.style.margin = '0 0 12px'; note.style.fontSize = '12px';
  c.appendChild(note);

  const panel = document.createElement('div'); panel.className = 'panel';
  const ph = document.createElement('div'); ph.className = 'panelhead';
  ph.appendChild(escEl('div', 'Authorized research', 'paneltitle'));
  const count = document.createElement('span'); count.className = 'badge mint'; count.id = 'cases-count'; count.textContent = 'Loading…';
  ph.appendChild(count);
  panel.appendChild(ph);
  const body = document.createElement('div'); body.className = 'panelbody'; body.id = 'cases-body';
  panel.appendChild(body);
  c.appendChild(panel);
  const pager = document.createElement('div'); pager.className = 'pager';
  pager.id = 'cases-pager';
  c.appendChild(pager);

  newBtn.addEventListener('click', openCreateDrawer);
  let debounce;
  const apply = () => { casesState.offset = 0; pushCasesRoute(); loadCases(); };
  searchInp.addEventListener('input', () => { clearTimeout(debounce); debounce = setTimeout(() => { casesState.search = searchInp.value.trim(); apply(); }, 300); });
  statusSel.addEventListener('change', () => { casesState.status = statusSel.value; apply(); });
  prioSel.addEventListener('change', () => { casesState.priority = prioSel.value; apply(); });
  clientSel.addEventListener('change', () => { casesState.client = clientSel.value; apply(); });
  await loadCases();
}
async function loadCases() {
  const body = document.getElementById('cases-body');
  const count = document.getElementById('cases-count');
  const pager = document.getElementById('cases-pager');
  if (!body) return;
  body.innerHTML = '';
  body.appendChild(escEl('div', 'Loading…', 'statebox'));
  try {
    const data = await api('/api/v1/cases?' + casesQuery());
    let cases = data.cases || [];
    if (casesState.search) {
      const s = casesState.search.toLowerCase();
      cases = cases.filter(c => (c.title||'').toLowerCase().includes(s) || (c.case_id||'').toLowerCase().includes(s));
    }
    body.innerHTML = '';
    count.textContent = cases.length + ' of ' + data.total + ' cases (page)';
    if (!cases.length) {
      body.appendChild(escEl('div', 'No research cases match current filters. Adjust filters or create a case.', 'statebox'));
      pager.innerHTML = '';
      return;
    }
    const wrap = document.createElement('div'); wrap.className = 'tablewrap';
    const table = document.createElement('table');
    const thead = document.createElement('thead');
    const heads = ['#', 'Case ID', 'Title', 'Status', 'Priority', 'Updated', 'Actions'];
    const hr = document.createElement('tr');
    heads.forEach(h => hr.appendChild(escEl('th', h)));
    thead.appendChild(hr);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    cases.forEach((c, idx) => {
      const tr = document.createElement('tr');
      tr.append(
        escEl('td', String(casesState.offset + idx + 1)),
        (() => { const td = escEl('td', c.case_id); td.style.fontFamily = 'ui-monospace,monospace'; return td; })(),
        escEl('td', c.title || ''),
        (() => { const td = document.createElement('td'); td.appendChild(escEl('span', c.status || '—', statusBadgeClass(c.status))); return td; })(),
        (() => { const td = document.createElement('td'); td.appendChild(escEl('span', c.priority || '—', statusBadgeClass(c.priority))); return td; })(),
        escEl('td', c.updated_at || '—'),
        (() => { const td = document.createElement('td'); const btn = escEl('button', 'Open', 'btn small'); btn.addEventListener('click', () => { currentCaseId = c.case_id; navigate('case', { case_id: c.case_id }); }); td.appendChild(btn); return td; })()
      );
      tr.addEventListener('click', () => { currentCaseId = c.case_id; navigate('case', { case_id: c.case_id }); });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    body.appendChild(wrap);
    pager.innerHTML = '';
    const info = escEl('span', 'Showing ' + (casesState.offset+1) + '–' + (casesState.offset + cases.length) + ' of ' + data.total + ' cases');
    const btns = document.createElement('span');
    const prev = escEl('button', '‹ Prev', 'btn small'); prev.disabled = casesState.offset === 0;
    const next = escEl('button', 'Next ›', 'btn small'); next.disabled = (casesState.offset + cases.length) >= data.total;
    prev.addEventListener('click', () => { casesState.offset = Math.max(0, casesState.offset - casesState.limit); pushCasesRoute(); loadCases(); });
    next.addEventListener('click', () => { casesState.offset += casesState.limit; pushCasesRoute(); loadCases(); });
    btns.append(prev, next);
    pager.append(info, btns);
  } catch (e) {
    if (e && e.status === 401) { showStateEssence('denied', 'Session expired (401). Please sign in.'); return; }
    if (e && e.status === 403) { showStateEssence('denied', 'Access denied (403). Client grant required.'); return; }
    if (e && e.status === 503) { showStateEssence('error', 'M6 schema not applied (503).', loadCases); return; }
    showStateEssence('error', (e && e.data && e.data.error && e.data.error.message) || 'Failed to load cases', loadCases);
  }
}
function genIdempotencyKey() {
  if (window.crypto && window.crypto.randomUUID) return window.crypto.randomUUID();
  return 'idem-' + Date.now() + '-' + Math.random().toString(16).slice(2);
}
function openCreateDrawer() {
  const root = document.getElementById('drawer-root');
  root.innerHTML = '';
  if (!currentIdempotencyKey) currentIdempotencyKey = genIdempotencyKey();
  const overlay = document.createElement('div'); overlay.className = 'overlay open'; overlay.id = 'create-overlay';
  const drawer = document.createElement('div'); drawer.className = 'drawer open'; drawer.id = 'create-drawer'; drawer.setAttribute('role','dialog'); drawer.setAttribute('aria-modal','true'); drawer.setAttribute('aria-labelledby','create-title');
  const head = document.createElement('div'); head.style.cssText = 'display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem';
  const t = escEl('h3', 'Create Research Case'); t.style.margin = '0'; t.id = 'create-title';
  const close = escEl('button', 'Close', 'btn'); close.addEventListener('click', closeCreateDrawer);
  head.append(t, close);
  const form = document.createElement('form'); form.id = 'create-form';
  const mkField = (labelText, id, type, opts) => {
    const wrap = document.createElement('div');
    const lab = document.createElement('label'); lab.className = 'kv-k'; lab.htmlFor = id; lab.textContent = labelText;
    let inp;
    if (opts) {
      inp = document.createElement('select'); inp.id = id;
      opts.forEach(([v,t]) => { const o=document.createElement('option'); o.value=v; o.textContent=t; inp.appendChild(o); });
    } else {
      inp = document.createElement(type || 'input'); inp.id = id; if (type!=='textarea') inp.type = type || 'text'; else inp.rows = 3;
    }
    inp.style.cssText = 'width:100%;margin:.35rem 0 .75rem;padding:9px 11px;background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text)';
    wrap.append(lab, inp);
    return [wrap, inp];
  };
  const [titleW, titleInp] = mkField('Title *', 'c-title', 'text');
  const [descW, descInp] = mkField('Description', 'c-desc', 'textarea');
  const [clientW, clientSel] = mkField('Initial Client', 'c-client', null, [['', 'Select client…'], ...(me.authorized_clients||[]).map(c=>[c,c])]);
  titleInp.required = true;
  const [prioW, prioSel] = mkField('Priority', 'c-priority', null, [['P2','P2'],['P1','P1'],['P3','P3'],['P4','P4']]);
  const [sevW, sevSel] = mkField('Severity', 'c-severity', null, [['HIGH','HIGH'],['CRITICAL','CRITICAL'],['MEDIUM','MEDIUM'],['LOW','LOW']]);
  const err = escEl('div', '', 'err'); err.id = 'create-error'; err.setAttribute('role','alert'); err.style.color = 'var(--red)'; err.style.minHeight = '1.2em';
  const submit = escEl('button', 'Create Case', 'btn primary'); submit.type = 'submit'; submit.style.width = '100%'; submit.style.marginTop = '.75rem';
  form.append(titleW, descW, clientW, prioW, sevW, err, submit);
  drawer.append(head, form);
  root.append(overlay, drawer);
  overlay.addEventListener('click', closeCreateDrawer);
  document.addEventListener('keydown', function esc(e){ if (e.key==='Escape') { closeCreateDrawer(); document.removeEventListener('keydown', esc); } });
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err.textContent = '';
    const payload = { title: titleInp.value.trim(), description: descInp.value.trim(), initial_client_id: clientSel.value, priority: prioSel.value, severity: sevSel.value, idempotency_key: currentIdempotencyKey };
    if (!payload.title) { err.textContent = 'Title required'; return; }
    try {
      const created = await api('/api/v1/cases', { method: 'POST', body: payload });
      currentIdempotencyKey = '';
      closeCreateDrawer();
      currentCaseId = created.case_id;
      navigate('case', { case_id: created.case_id });
    } catch (e2) {
      if (e2 && e2.status === 409) { err.textContent = 'Conflict: idempotency key reused with different payload. Kept the same key for retry.'; return; }
      err.textContent = (e2 && e2.data && e2.data.error && e2.data.error.message) || ('Create failed: ' + (e2 && e2.status || 'network'));
    }
  });
  titleInp.focus();
}
function closeCreateDrawer() {
  document.getElementById('drawer-root').innerHTML = '';
}

/* ---------- V3-F3: Case Workspace ---------- */
let ws = { tab: 'overview', hypotheses: [], artifacts: [], notes: [], activity: [], investigations: [], parts: [], selectedHyp: '', selectedArtifact: '', loadSeq: 0 };
function wsResetSelections() { ws.selectedHyp = ''; ws.selectedArtifact = ''; }
function renderCase() {
  const c = document.getElementById('content');
  c.innerHTML = '';
  if (!currentCaseId) {
    const d = document.createElement('div'); d.className = 'statebox'; d.setAttribute('role','status');
    d.textContent = 'Select a case from Research Cases. Deep link requires #case?case_id=<uuid>.';
    const a = document.createElement('a'); a.href = '#cases'; a.textContent = 'Back to Cases'; a.className = 'btn primary'; a.style.display='inline-block'; a.style.marginTop='12px';
    d.appendChild(document.createElement('br')); d.appendChild(a);
    c.appendChild(d);
    return;
  }
  const seq = ++ws.loadSeq;
  wsResetSelections();
  // Header
  const header = document.createElement('div'); header.className = 'heading';
  const left = document.createElement('div');
  left.appendChild(escEl('div', 'INTELLIGENCE / RESEARCH CASE', 'eyebrow'));
  left.appendChild(escEl('h1', 'Case …'));
  const sub = document.createElement('p'); sub.textContent = 'Access is enforced server-side. Tab content below is fetched with your grants.';
  left.appendChild(sub);
  const acts = document.createElement('div'); acts.style.display='flex'; acts.style.gap='.5rem'; acts.style.flexWrap='wrap';
  const lifecycleBtn = escEl('button', 'Change status', 'btn');
  const partsBtn = escEl('button', 'Participants', 'btn');
  lifecycleBtn.addEventListener('click', () => openLifecycleDrawer());
  partsBtn.addEventListener('click', () => openLifecycleDrawer('participants'));
  acts.append(lifecycleBtn, partsBtn);
  header.append(left, acts);
  c.appendChild(header);

  // Lifecycle rail (v3 5-step visual)
  const flow = document.createElement('div'); flow.className = 'flow';
  ['SOURCE CTI','ANALYSIS Hypotheses','EVIDENCE Artifacts','EXECUTION Investigations','JUDGMENT Review'].forEach((t,i) => {
    const step = document.createElement('div');
    step.appendChild(escEl('b', String(i+1).padStart(2,'0') + ' · ' + t.split(' ')[0]));
    step.appendChild(document.createElement('br'));
    step.appendChild(escEl('span', t.split(' ').slice(1).join(' ') || ''));
    flow.appendChild(step);
  });
  c.appendChild(flow);

  // Main + Inspector
  const layout = document.createElement('div'); layout.className = 'v3layout';
  const mainCol = document.createElement('div'); mainCol.style.minWidth = '0';
  const insp = document.createElement('aside'); insp.className = 'v3inspector panel';
  insp.id = 'inspector';
  const ih = document.createElement('div'); ih.className = 'panelhead';
  ih.appendChild(escEl('div', 'CONTEXT INSPECTOR', 'paneltitle'));
  insp.appendChild(ih);
  const ib = document.createElement('div'); ib.className = 'panelbody'; ib.id = 'inspector-body';
  ib.textContent = 'Select a hypothesis, artifact, note or investigation to inspect provenance, scope and allowed actions.';
  insp.appendChild(ib);
  layout.append(mainCol, insp);
  c.appendChild(layout);

  // Tabs
  const tabs = document.createElement('div'); tabs.className = 'tabs'; tabs.setAttribute('role','tablist');
  const tabDefs = [['overview','Research Summary'],['cti','CTI Context'],['hypotheses','Hypotheses'],['evidence','Evidence'],['investigations','Investigations'],['notes','Notes'],['timeline','Timeline']];
  tabDefs.forEach(([k, label]) => {
    const b = escEl('button', label, 'tab' + (ws.tab === k ? ' active' : ''));
    b.dataset.tab = k; b.setAttribute('role','tab');
    b.addEventListener('click', () => { ws.tab = k; renderCaseTabs(mainCol); });
    tabs.appendChild(b);
  });
  mainCol.appendChild(tabs);
  const tabHost = document.createElement('div'); tabHost.id = 'tab-host'; mainCol.appendChild(tabHost);
  renderCaseTabs(mainCol);
  // Load everything (sequential to avoid stale DOM overwrites).
  loadWorkspace(seq);
}
function renderCaseTabs(host) {
  const tabHost = document.getElementById('tab-host');
  if (!tabHost) return;
  tabHost.innerHTML = '';
  const tabs = host ? host.querySelector('.tabs') : null;
  if (tabs) tabs.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === ws.tab));
  const panel = document.createElement('div');
  panel.id = 'tab-panel';
  tabHost.appendChild(panel);
  const renderer = ({ overview: renderOverviewTab, cti: renderCtiTab, hypotheses: renderHypTab, evidence: renderEvTab, investigations: renderInvTab, notes: renderNotesTab, timeline: renderTimelineTab }[ws.tab] || (() => {}));
  // Renderer must be invoked synchronously so fillWorkspace can populate it.
  renderer(panel);
  if (ws.tab === 'cti') renderLinkedReports(document.getElementById('cti-list'));
}
function renderOverviewTab(panel) {
  const box = document.createElement('div');
  box.appendChild(escEl('h3', 'Research Summary'));
  const meta = document.createElement('div'); meta.style.display = 'grid'; meta.style.gridTemplateColumns = 'repeat(auto-fit,minmax(180px,1fr))'; meta.style.gap = '1rem';
  meta.id = 'ov-meta';
  meta.appendChild(escEl('div', 'Loading…', 'text-muted'));
  box.appendChild(meta);
  panel.appendChild(box);
}
function renderCtiTab(panel) {
  const box = document.createElement('div');
  box.appendChild(escEl('h3', 'CTI Context'));
  const list = document.createElement('div'); list.id = 'cti-list'; list.setAttribute('role','listbox');
  list.textContent = 'Loading…';
  box.appendChild(list);
  const row = document.createElement('div'); row.style.display = 'flex'; row.style.gap = '.5rem'; row.style.flexWrap = 'wrap'; row.style.marginTop = '1rem';
  const inp = document.createElement('input'); inp.id = 'cti-report-input'; inp.placeholder = 'Report ID to link…'; inp.setAttribute('aria-label','Report ID to link');
  const linkBtn = escEl('button', 'Link report', 'btn primary btn-sm');
  linkBtn.addEventListener('click', async () => {
    const rid = inp.value.trim(); if (!rid) return;
    try { await api('/api/v1/cases/' + encodeURIComponent(currentCaseId) + '/cti-reports', { method: 'POST', body: { report_id: rid } }); await refreshWorkspace(); }
    catch (e) { alert((e && e.data && e.data.error && e.data.error.message) || 'Link failed'); }
  });
  row.append(inp, linkBtn);
  box.appendChild(row);
  panel.appendChild(box);
}
function renderLinkedReports(listEl) {
  if (!listEl) return;
  listEl.innerHTML = '';
  api('/api/v1/cases/' + encodeURIComponent(currentCaseId) + '/cti-reports?limit=50&offset=0').then(d => {
    const rows = d.reports || [];
    if (!rows.length) { listEl.textContent = 'No linked CTI reports.'; return; }
    rows.forEach(r => {
      const row = escEl('div', null, 'sel-row');
      row.append(escEl('strong', (r.title || r.report_id) + ' • ' + (r.client_id || '—') + ' • ' + (r.status || '—')));
      const unlink = escEl('button', 'Unlink', 'btn small');
      unlink.addEventListener('click', async () => {
        try { await api('/api/v1/cases/' + encodeURIComponent(currentCaseId) + '/cti-reports/' + encodeURIComponent(r.report_id), { method: 'DELETE' }); await refreshWorkspace(); }
        catch (e) { alert((e && e.data && e.data.error && e.data.error.message) || 'Unlink failed'); }
      });
      row.appendChild(unlink);
      listEl.appendChild(row);
      // M7-C: read-only relevance badges for this linked report.
      if (r.client_id) {
        api('/api/v1/cti/reports/' + encodeURIComponent(r.report_id) + '/relevance/' + encodeURIComponent(r.client_id)).then(d => {
          if (!row.isConnected || !d || !d.findings) return;
          const br = escEl('div', null, 'row'); br.style.display = 'flex'; br.style.flexWrap = 'wrap'; br.style.gap = '4px';
          br.appendChild(escEl('span', 'Relevance:', 'text-muted'));
          d.findings.forEach(f => { br.appendChild(relBadge(f.verdict)); br.appendChild(escEl('span', f.dimension, 'text-muted')); });
          row.parentElement && row.parentElement.insertBefore(br, row.nextSibling);
        }).catch(() => {});
      }
    });
  }).catch(e => {
    if (e && e.status === 503) listEl.textContent = 'CTI links not available (M7-B schema not applied).';
    else if (e && e.status === 403) listEl.textContent = 'Access denied (403).';
    else listEl.textContent = 'Failed to load linked reports.';
  });
}
function renderHypTab(panel) {
  const box = document.createElement('div');
  box.appendChild(escEl('h3', 'Linked Hypotheses'));
  const list = document.createElement('div'); list.id = 'hyp-list'; list.setAttribute('role','listbox');
  box.appendChild(list);
  const row = document.createElement('div'); row.style.display = 'flex'; row.style.gap = '.5rem'; row.style.flexWrap = 'wrap'; row.style.marginTop = '1rem';
  const sel = document.createElement('select'); sel.id = 'link-select'; sel.setAttribute('aria-label','Available hypothesis to link');
  const linkBtn = escEl('button', 'Link', 'btn primary btn-sm');
  linkBtn.addEventListener('click', async () => {
    const hid = sel.value; if (!hid) return;
    try { await api('/api/v1/cases/' + encodeURIComponent(currentCaseId) + '/hypotheses/' + encodeURIComponent(hid), { method: 'POST', body: {} }); await refreshWorkspace(); }
    catch (e) { alert((e && e.data && e.data.error && e.data.error.message) || 'Link failed'); }
  });
  row.append(sel, linkBtn);
  box.appendChild(row);
  panel.appendChild(box);
}
function renderEvTab(panel) {
  const box = document.createElement('div');
  box.appendChild(escEl('h3', 'Evidence'));
  const list = document.createElement('div'); list.id = 'ev-list'; list.setAttribute('role','listbox');
  box.appendChild(list);
  panel.appendChild(box);
}
function renderInvTab(panel) {
  const box = document.createElement('div');
  box.appendChild(escEl('h3', 'Investigations'));
  const list = document.createElement('div'); list.id = 'inv-list';
  box.appendChild(list);
  const row = document.createElement('div'); row.style.display = 'flex'; row.style.gap = '.5rem'; row.style.marginTop = '1rem'; row.style.flexWrap = 'wrap';
  const hypSel = document.createElement('select'); hypSel.id = 'inv-hyp'; hypSel.setAttribute('aria-label','Linked hypothesis');
  const clientSel = document.createElement('select'); clientSel.id = 'inv-client'; clientSel.setAttribute('aria-label','Client');
  const rangeInp = document.createElement('input'); rangeInp.id = 'inv-range'; rangeInp.placeholder = 'time_range';
  const createBtn = escEl('button', 'Create Investigation', 'btn primary btn-sm');
  createBtn.addEventListener('click', async () => {
    try {
      const inv = await api('/api/v1/cases/' + encodeURIComponent(currentCaseId) + '/investigations', { method: 'POST', body: { hypothesis_id: hypSel.value, client_id: clientSel.value, time_range: rangeInp.value.trim(), evidence: '', analyst_findings: '' } });
      alert('Investigation created: ' + inv.investigation_id);
      renderInvTabRefresh();
    } catch (e) { alert((e && e.data && e.data.error && e.data.error.message) || 'Create failed'); }
  });
  row.append(hypSel, clientSel, rangeInp, createBtn);
  box.appendChild(row);
  panel.appendChild(box);
  (async () => {
    const data = await api('/api/v1/cases/' + encodeURIComponent(currentCaseId) + '/hypotheses?limit=100&offset=0').catch(() => ({ hypotheses: [] }));
    hypSel.innerHTML = '';
    const ph = document.createElement('option'); ph.value = ''; ph.textContent = 'Select linked hypothesis…'; hypSel.appendChild(ph);
    (data.hypotheses || []).forEach(h => { const o = document.createElement('option'); o.value = h.hypothesis_id; o.textContent = h.hypothesis_id + ' • ' + h.title + ' • ' + h.client_id; hypSel.appendChild(o); });
    clientSel.innerHTML = '';
    (me.authorized_clients || []).forEach(c => { const o = document.createElement('option'); o.value = c; o.textContent = c; clientSel.appendChild(o); });
  })();
}
function renderInvTabRefresh() { renderCaseTabs(document.querySelector('.v3layout') ? document.getElementById('content') : null); }
function renderNotesTab(panel) {
  const box = document.createElement('div');
  box.appendChild(escEl('h3', 'Analyst Notes'));
  const list = document.createElement('div'); list.id = 'notes-list';
  box.appendChild(list);
  const form = document.createElement('form'); form.style.marginTop = '1rem';
  const ta = document.createElement('textarea'); ta.id = 'note-text'; ta.rows = 3; ta.style.width = '100%'; ta.placeholder = 'Note body (textContent only)';
  const scope = document.createElement('select'); scope.id = 'note-scope';
  ['GLOBAL','CLIENT'].forEach(s => { const o = document.createElement('option'); o.value = s; o.textContent = s; scope.appendChild(o); });
  const clientSel = document.createElement('select'); clientSel.id = 'note-client';
  (me.authorized_clients || []).forEach(c => { const o = document.createElement('option'); o.value = c; o.textContent = c; clientSel.appendChild(o); });
  const typeSel = document.createElement('select'); typeSel.id = 'note-type';
  ['observation','finding','question','escalation'].forEach(s => { const o = document.createElement('option'); o.value = s; o.textContent = s; typeSel.appendChild(o); });
  const addBtn = escEl('button', 'Add note', 'btn primary btn-sm'); addBtn.type = 'submit';
  form.append(ta, scope, typeSel, clientSel, addBtn);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api('/api/v1/cases/' + encodeURIComponent(currentCaseId) + '/notes', { method: 'POST', body: { note_text: ta.value, note_type: typeSel.value, visibility_scope: scope.value, client_id: clientSel.value } });
      ta.value = ''; renderNotesTabRefresh();
    } catch (err) { alert((err && err.data && err.data.error && err.data.error.message) || 'Add note failed'); }
  });
  box.appendChild(form);
  panel.appendChild(box);
}
function renderNotesTabRefresh() { renderCaseTabs(document.getElementById('content')); }
function renderTimelineTab(panel) {
  const box = document.createElement('div');
  box.appendChild(escEl('h3', 'Timeline'));
  const list = document.createElement('div'); list.id = 'activity-list';
  box.appendChild(list);
  panel.appendChild(box);
}

let wsCtl = null;
async function loadWorkspace(seq) {
  // Every promise checks seq: if case/context changed mid-fetch, results are discarded.
  try {
    const [caseObj, parts, ctx] = await Promise.all([
      api('/api/v1/cases/' + encodeURIComponent(currentCaseId)),
      (async () => { try { return await api('/api/v1/cases/' + encodeURIComponent(currentCaseId) + '/participants'); } catch (_) { return { participants: [] }; } })(),
      (async () => { try { return await api('/api/v1/cases/' + encodeURIComponent(currentCaseId) + '/activity?limit=100&offset=0'); } catch (_) { return { activity: [], total: 0 }; } })()
    ]);
    if (seq !== ws.loadSeq) return;
    caseData = caseObj;
    const hyps = await api('/api/v1/cases/' + encodeURIComponent(currentCaseId) + '/hypotheses?limit=100&offset=0');
    if (seq !== ws.loadSeq) return;
    ws.hypotheses = hyps.hypotheses || [];
    const notes = await api('/api/v1/cases/' + encodeURIComponent(currentCaseId) + '/notes?limit=100&offset=0');
    if (seq !== ws.loadSeq) return;
    ws.notes = notes.notes || [];
    const invs = await api('/api/v1/cases/' + encodeURIComponent(currentCaseId) + '/investigations?limit=100&offset=0');
    if (seq !== ws.loadSeq) return;
    ws.investigations = invs.investigations || [];
    ws.activity = ctx.activity || [];
    ws.parts = parts.participants || [];
    fillWorkspace(caseObj, seq);
    renderCaseTabs(document.getElementById('content'));
  } catch (e) {
    if (seq !== ws.loadSeq) return;
    if (e && e.status === 401) { showStateEssence('denied', 'Session expired (401). Please sign in.'); return; }
    if (e && e.status === 403) { showStateEssence('denied', 'Access denied (403). Client grant required.'); return; }
    if (e && e.status === 404) { showStateEssence('error', 'Case not found (404).', () => navigate('cases')); return; }
    if (e && e.status === 503) { showStateEssence('error', 'M6 schema not applied (503).', () => navigate('case', { case_id: currentCaseId })); return; }
    showStateEssence('error', (e && e.data && e.data.error && e.data.error.message) || 'Failed to load case workspace', () => navigate('case', { case_id: currentCaseId }));
  }
}
function fillWorkspace(caseObj, seq) {
  wsCtl = { seq };
  const title = document.querySelector('.heading h1');
  if (title) title.textContent = caseObj.title || 'Case Workspace';
  const meta = document.getElementById('ov-meta');
  if (meta) {
    meta.innerHTML = '';
    const add = (k, v) => { const d = escEl('div', null, 'kv'); d.appendChild(escEl('div', k, 'kv-k')); d.appendChild(escEl('div', v || '—', 'kv-v')); meta.appendChild(d); };
    add('Case ID', caseObj.case_id);
    add('Description', caseObj.description || 'No description.');
    add('Owner', caseObj.owner_id || '—');
    add('Timestamps', 'Created ' + (caseObj.created_at||'—') + ' • Updated ' + (caseObj.updated_at||'—'));
    add('Linked hypotheses', String(ws.hypotheses.length) + ' visible');
    add('Evidence (artifacts)', String((caseObj.artifacts||[]).length) + ' visible');
    add('Recent activity', String(ws.activity.length) + ' visible events');
  }
  // Hypotheses list (visible only)
  const hypList = document.getElementById('hyp-list');
  if (hypList) {
    hypList.innerHTML = '';
    (ws.hypotheses || []).forEach(h => {
      const btn = escEl('button', null, 'sel-row' + (h.hypothesis_id === ws.selectedHyp ? ' sel' : ''));
      btn.setAttribute('role','option');
      const t = escEl('div', h.hypothesis_id + ' • ' + h.title + ' • ' + h.client_id + ' • ' + h.status);
      const l = escEl('div', h.latest_decision ? ('Latest review: ' + h.latest_decision) : 'Latest review: none', 'text-muted');
      btn.append(t, l);
      btn.addEventListener('click', () => { ws.selectedHyp = h.hypothesis_id; inspectHypothesis(h); renderCaseTabs(document.getElementById('content')); });
      hypList.appendChild(btn);
    });
    const sel = document.getElementById('link-select');
    if (sel) {
      sel.innerHTML = '';
      const ph = document.createElement('option'); ph.value = ''; ph.textContent = 'Select hypothesis…'; sel.appendChild(ph);
      api('/api/v1/hypotheses?limit=100&offset=0').then(d => {
        if (seq !== ws.loadSeq) return;
        (d.hypotheses || []).forEach(h => { const o = document.createElement('option'); o.value = h.hypothesis_id; o.textContent = h.hypothesis_id + ' • ' + h.title + ' • ' + h.client_id; sel.appendChild(o); });
      }).catch(() => {});
    }
  }
  // Evidence list
  const evList = document.getElementById('ev-list');
  if (evList) {    evList.innerHTML = '';
    (caseObj.artifacts || []).forEach(a => {
      const btn = escEl('button', null, 'sel-row' + (a.artifact_id === ws.selectedArtifact ? ' sel' : ''));
      btn.setAttribute('role','option');
      btn.appendChild(escEl('div', a.artifact_id + ' • ' + (a.sanitized_representation || '(summary only)') + ' • ' + a.data_classification + ' • ' + (a.client_id || 'GLOBAL')));
      btn.appendChild(escEl('div', 'Access: ' + a.access_status + ' • Detail: ' + a.detail_level, 'text-muted'));
      btn.addEventListener('click', () => { ws.selectedArtifact = a.artifact_id; inspectArtifact(a); renderCaseTabs(document.getElementById('content')); });
      evList.appendChild(btn);
    });
  }
  // Notes + timeline lists are rendered by their tab functions after refresh
  renderLinkedReports(document.getElementById('cti-list'));
  renderInvTabRefreshContent();
  renderNotesList();
  renderActivityList();
}
function renderInvTabRefreshContent() {
  const box = document.getElementById('inv-list');
  if (!box) return;
  box.innerHTML = '';
  (ws.investigations || []).forEach(inv => {
    box.appendChild(escEl('div', inv.investigation_id + ' • ' + inv.hypothesis_id + ' • ' + inv.client_id + ' • ' + (inv.final_verdict || 'no verdict'), 'sel-row'));
  });
  if (!(ws.investigations || []).length) box.textContent = 'No investigations visible.';
}
function renderNotesList() {
  const box = document.getElementById('notes-list');
  if (!box) return;
  box.innerHTML = '';
  (ws.notes || []).forEach(n => {
    const d = escEl('div', null, 'note');
    d.appendChild(escEl('div', n.note_type + ' • ' + n.visibility_scope + ' • ' + (n.client_id || 'GLOBAL') + ' • by ' + n.user_id, 'kv-k'));
    d.appendChild(escEl('p', n.note_text));
    (n.revisions || []).forEach(r => d.appendChild(escEl('div', 'Rev ' + r.created_at + ' by ' + r.created_by + ': ' + r.note_text, 'text-muted')));
    box.appendChild(d);
  });
  if (!(ws.notes || []).length) box.textContent = 'No notes visible.';
}
function renderActivityList() {
  const box = document.getElementById('activity-list');
  if (!box) return;
  box.innerHTML = '';
  (ws.activity || []).forEach(a => {
    const d = escEl('div', null, 'tl-i');
    d.appendChild(escEl('span', '●', 'tl-d'));
    d.appendChild(escEl('span', a.created_at + '  ' + a.action + '  ' + a.visibility_scope + '  ' + (a.client_id || '') + '  ' + (a.details || '')));
    box.appendChild(d);
  });
  if (!(ws.activity || []).length) box.textContent = 'No activity visible.';
}
function inspectHypothesis(h) {
  const body = document.getElementById('inspector-body');
  body.innerHTML = '';
  body.appendChild(escEl('div', 'Hypothesis ' + h.hypothesis_id, 'kv-k'));
  const add = (k,v) => { const d=escEl('div',null,'kv'); d.appendChild(escEl('div',k,'kv-k')); d.appendChild(escEl('div',v||'—','kv-v')); body.appendChild(d); };
  add('Title', h.title);
  add('Client', h.client_id);
  add('Latest decision', h.latest_decision || 'none');
  const reviewBtn = escEl('button', 'Open review (drawer)', 'btn primary btn-sm'); reviewBtn.style.marginTop = '12px';
  reviewBtn.addEventListener('click', () => openReviewDrawer('hypothesis', h));
  body.appendChild(reviewBtn);
}
function inspectArtifact(a) {
  const body = document.getElementById('inspector-body');
  body.innerHTML = '';
  body.appendChild(escEl('div', 'Artifact ' + a.artifact_id, 'kv-k'));
  const add = (k,v) => { const d=escEl('div',null,'kv'); d.appendChild(escEl('div',k,'kv-k')); d.appendChild(escEl('div',v||'—','kv-v')); body.appendChild(d); };
  add('Client scope', a.client_id || 'GLOBAL');
  add('Classification', a.data_classification);
  add('Access', a.access_status + ' / ' + a.detail_level);
  add('Provenance', a.provenance_source || '—');
  const reviewBtn = escEl('button', 'Review artifact', 'btn primary btn-sm'); reviewBtn.style.marginTop = '12px';
  reviewBtn.addEventListener('click', () => openReviewDrawer('artifact', a));
  body.appendChild(reviewBtn);
}
function openLifecycleDrawer(kind) {
  const root = document.getElementById('drawer-root');
  root.innerHTML = '';
  const overlay = document.createElement('div'); overlay.className = 'overlay open';
  const drawer = document.createElement('div'); drawer.className = 'drawer open'; drawer.setAttribute('role','dialog'); drawer.setAttribute('aria-modal','true');
  drawer.appendChild(escEl('h3', kind === 'participants' ? 'Participants' : 'Lifecycle transition'));
  const err = escEl('div', '', 'err'); err.id = 'drawer-err'; err.setAttribute('role','alert'); err.style.color = 'var(--red)'; err.style.minHeight = '1.2em';
  if (kind === 'participants') {
    const inp = document.createElement('input'); inp.id = 'part-user'; inp.placeholder = 'user_id'; inp.style.cssText = 'width:100%;margin:.5rem 0;padding:9px 11px;background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text)';
    const roleSel = document.createElement('select'); roleSel.id = 'part-role'; roleSel.style.cssText = 'width:100%;margin:.5rem 0;padding:9px 11px;background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text)';
    ['VIEWER','EDITOR'].forEach(r => { const o=document.createElement('option'); o.value=r; o.textContent=r; roleSel.appendChild(o); });
    const addBtn = escEl('button', 'Add participant', 'btn primary'); addBtn.style.width = '100%';
    addBtn.addEventListener('click', async () => {
      err.textContent = '';
      try { await api('/api/v1/cases/' + encodeURIComponent(currentCaseId) + '/participants', { method: 'POST', body: { user_id: inp.value.trim(), role_in_case: roleSel.value } }); closeCreateDrawer(); refreshWorkspace(); }
      catch (e) { err.textContent = (e && e.data && e.data.error && e.data.error.message) || 'Add failed'; }
    });
    drawer.append(inp, roleSel, addBtn, err);
  } else {
    const sel = document.createElement('select'); sel.id = 'new-status'; sel.style.cssText = 'width:100%;margin:.5rem 0;padding:9px 11px;background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text)';
    ['IN_PROGRESS','REVIEW','CLOSED','ARCHIVED'].forEach(s => { const o=document.createElement('option'); o.value=s; o.textContent=s; sel.appendChild(o); });
    const reason = document.createElement('input'); reason.id = 'close-reason'; reason.placeholder = 'Closed reason (for CLOSED/ARCHIVED)'; reason.style.cssText = 'width:100%;margin:.5rem 0;padding:9px 11px;background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text)';
    const go = escEl('button', 'Transition', 'btn primary'); go.style.width = '100%';
    go.addEventListener('click', async () => {
      err.textContent = '';
      try { await api('/api/v1/cases/' + encodeURIComponent(currentCaseId) + '/status', { method: 'PUT', body: { status: sel.value, closed_reason: reason.value } }); closeCreateDrawer(); refreshWorkspace(); }
      catch (e) { err.textContent = (e && e.data && e.data.error && e.data.error.message) || 'Transition failed'; }
    });
    drawer.append(sel, reason, go, err);
  }
  const closeBtn = escEl('button', 'Close (Esc)', 'btn'); closeBtn.style.marginTop = '.75rem'; closeBtn.addEventListener('click', closeCreateDrawer);
  drawer.appendChild(closeBtn);
  root.append(overlay, drawer);
  overlay.addEventListener('click', closeCreateDrawer);
  document.addEventListener('keydown', function esc(e){ if (e.key==='Escape') { closeCreateDrawer(); document.removeEventListener('keydown', esc); } });
}
function openReviewDrawer(kind, obj) {
  const root = document.getElementById('drawer-root');
  root.innerHTML = '';
  const overlay = document.createElement('div'); overlay.className = 'overlay open';
  const drawer = document.createElement('div'); drawer.className = 'drawer open'; drawer.setAttribute('role','dialog'); drawer.setAttribute('aria-modal','true');
  drawer.appendChild(escEl('h3', kind === 'artifact' ? 'Review artifact ' + obj.artifact_id : 'Review hypothesis ' + obj.hypothesis_id));
  const err = escEl('div', '', 'err'); err.setAttribute('role','alert'); err.style.color = 'var(--red)'; err.style.minHeight = '1.2em';
  const decSel = document.createElement('select'); decSel.style.cssText = 'width:100%;margin:.5rem 0;padding:9px 11px;background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text)';
  ['APPROVED','REJECTED','NEEDS_MORE_DATA'].forEach(d => { const o=document.createElement('option'); o.value=d; o.textContent=d; decSel.appendChild(o); });
  const reasonInp = document.createElement('input'); reasonInp.placeholder = 'Reason'; reasonInp.style.cssText = 'width:100%;margin:.5rem 0;padding:9px 11px;background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text)';
  let clientSel = null, hypSel = null;
  if (kind === 'hypothesis') {
    clientSel = document.createElement('select'); clientSel.style.cssText = decSel.style.cssText;
    (me.authorized_clients || []).forEach(c => { const o=document.createElement('option'); o.value=c; o.textContent=c; clientSel.appendChild(o); });
    drawer.append(decSel, clientSel, reasonInp, err);
  } else {
    drawer.append(decSel, reasonInp, err);
  }
  const submit = escEl('button', 'Submit review', 'btn primary'); submit.style.width = '100%';
  submit.addEventListener('click', async () => {
    err.textContent = '';
    try {
      if (kind === 'artifact') {
        await api('/api/v1/cases/' + encodeURIComponent(currentCaseId) + '/artifacts/' + encodeURIComponent(obj.artifact_id) + '/review', { method: 'PUT', body: { decision: decSel.value, reason: reasonInp.value } });
      } else {
        await api('/api/v1/cases/' + encodeURIComponent(currentCaseId) + '/hypotheses/' + encodeURIComponent(obj.hypothesis_id) + '/review', { method: 'POST', body: { client_id: clientSel.value, decision: decSel.value, reason: reasonInp.value } });
      }
      closeCreateDrawer(); refreshWorkspace();
    } catch (e) { err.textContent = (e && e.data && e.data.error && e.data.error.message) || 'Review failed'; }
  });
  drawer.appendChild(submit);
  const closeBtn = escEl('button', 'Close (Esc)', 'btn'); closeBtn.style.marginTop = '.75rem'; closeBtn.addEventListener('click', closeCreateDrawer);
  drawer.appendChild(closeBtn);
  root.append(overlay, drawer);
  overlay.addEventListener('click', closeCreateDrawer);
  document.addEventListener('keydown', function esc(e){ if (e.key==='Escape') { closeCreateDrawer(); document.removeEventListener('keydown', esc); } });
}
async function refreshWorkspace() {
  const seq = ++ws.loadSeq;
  // Clear selections so stale client content never lingers in DOM.
  wsResetSelections();
  document.getElementById('inspector-body').innerHTML = '';
  document.getElementById('inspector-body').textContent = 'Select an item to inspect.';
  await loadWorkspace(seq);
}

/* ---------- Pages ---------- */

document.addEventListener('click', e => {
  const go = e.target.closest('[data-go]');
  if (go) { navigate(go.dataset.go); return; }
});
document.getElementById('tenant').addEventListener('change', e => {
  // Switching client context clears per-client selection and refetches.
  wsResetSelections();
  homeCtl.seq++;
  feedCtl.seq++;
  feedCtl.selectSeq++;
  feedCtl.reportId = ''; feedCtl.idemKey = ''; feedCtl.idemPayloadHash = '';
  if (current === 'cases') {
    casesState.client = e.target.value === 'global' ? '' : e.target.value;
    casesState.offset = 0;
    pushCasesRoute();
    renderCases();
  } else if (current === 'case') {
    refreshWorkspace();
  } else if (current === 'home') {
    renderHome();
  } else if (current === 'feed' || current === 'reports') {
    renderFeed();
  } else if (current === 'qradar') {
    qrCtl.seq++; qrCtl.selectSeq++; renderQRadar();
  } else if (current === 'detection') {
    detCtl.seq++; detCtl.selectSeq++; renderDetection();
  } else if (current === 'clients') {
    cliCtl.seq++; cliCtl.selectSeq++; renderClients();
  } else if (current === 'hypotheses') {
    hypCtl.seq++; hypCtl.selectSeq++; renderHypotheses();
  } else {
    renderPlaceholder('Context changed', 'Client context switched to ' + e.target.value + '. Pages will refetch authorized data.');
  }
});
window.addEventListener('hashchange', () => {
  const { route, q } = parseHash();
  if (route && route !== current) navigate(route, (route === 'case' || route === 'hunt' || route === 'inventory') ? Object.fromEntries(q.entries()) : undefined);
  else if (route === 'cases') {
    const prev = JSON.stringify(casesState);
    syncCasesFromURL();
    if (current === 'cases' && JSON.stringify(casesState) !== prev) renderCases();
  } else if (route === 'case') {
    currentCaseId = q.get('case_id') || '';
    refreshWorkspace();
  } else if (route === 'hunt') {
    hwCtl.seq++;
    renderHuntWorkspace();
  }
});
(async () => {
  await loadMe();
  const { route, q } = parseHash();
  if (route === 'case') {
    currentCaseId = q.get('case_id') || '';
    navigate('case', { case_id: currentCaseId });
  } else if (route === 'cases') {
    navigate('cases');
  } else {
    const r0 = location.hash.slice(1).split('?')[0] || 'home';
    navigate(r0, ((r0 === 'hunt' || r0 === 'inventory') && [...q.keys()].length) ? Object.fromEntries(q.entries()) : undefined);
  }
})();
