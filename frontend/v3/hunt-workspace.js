"use strict";
/* M7-D Phase 2B-4B — Hunt Workspace.
   Real API data only. Every value is rendered with textContent; YAML and AQL are
   never interpreted as HTML. No execution, no deployment, no QRadar calls. */

let hwCtl = { seq: 0, section: 'plans', client: '', ruleId: '', domainId: '', translationId: '', planId: '', busy: false };

function hwRole() { return (me && me.user && me.user.role) || ''; }
function hwCanCreate() { return hwRole() === 'ADMINISTRATOR' || hwRole() === 'HYPOTHESIS_WRITER'; }
function hwCanReview() { return hwRole() === 'ADMINISTRATOR' || hwRole() === 'REVIEWER'; }
function hwCanGenerate() { return hwRole() === 'ADMINISTRATOR'; }

function hwConflictLabel(code) {
  switch (code) {
    case 'STALE_SCOPE': return 'evidence changed since the draft was produced (stale scope).';
    case 'EVIDENCE_UNAVAILABLE': return 'evidence a decision depends on is no longer readable.';
    case 'HUNT_PLAN_CONFLICT': return 'plan state or attached evidence changed. Refresh and retry.';
    case 'HUNT_PLAN_INVALID': return 'the request was incomplete or invalid.';
    default: return 'the plan changed. Refresh and retry.';
  }
}
function hwErrText(e) {
  if (!e) return 'Request failed.';
  if (e.status === 401) return 'Session expired (401). Sign in again.';
  if (e.status === 403) return 'Access denied (403). Your role or client grant does not permit this action.';
  if (e.status === 409) {
    const code = (e.data && e.data.error && e.data.error.code) || 'CONFLICT';
    return 'Conflict (409): ' + hwConflictLabel(code);
  }
  if (e.status >= 500) return 'Server error (' + e.status + '). Nothing was changed.';
  const msg = e.data && e.data.error && e.data.error.message;
  return msg || ('Request failed (' + (e.status || 'network') + ').');
}
function hwStateBox(host, text) { host.innerHTML = ''; host.appendChild(escEl('div', text, 'statebox')); }
function hwNotify(msg, tone) {
  let host = document.getElementById('hw-flash');
  if (!host) { host = document.createElement('div'); host.id = 'hw-flash'; host.className = 'note'; host.style.margin = '0 0 12px'; const content = document.getElementById('content'); content.insertBefore(host, document.querySelector('.v3layout')); }
  host.innerHTML = '';
  host.appendChild(hwBadge(tone === 'error' ? 'ACTION FAILED' : 'INFO', tone === 'error' ? 'muted' : 'mint'));
  host.appendChild(document.createElement('br'));
  host.appendChild(escEl('div', msg, tone === 'error' ? 'text-muted' : ''));
}
function hwMuted(host, text) { host.appendChild(escEl('div', text, 'text-muted')); }
function hwBadge(text, tone) { return escEl('span', text || 'UNKNOWN', 'badge ' + (tone || 'muted')); }
function hwEvidenceTone(s) {
  if (s === 'OK') return 'mint';
  if (s === 'STALE_EVIDENCE') return 'amber';
  return 'muted';
}
function hwStatusTone(s) {
  if (s === 'READY_FOR_REVIEW' || s === 'APPROVED' || s === 'OK') return 'mint';
  if (s === 'NEEDS_FIELD_VERIFICATION' || s === 'IN_REVIEW' || s === 'DRAFT') return 'amber';
  if (s === 'UNSUPPORTED' || s === 'BLOCKED' || s === 'REJECTED' || s === 'STALE_EVIDENCE' || s === 'EVIDENCE_UNAVAILABLE') return 'muted';
  return 'muted';
}
function hwPre(text, maxHeight) {
  const pre = document.createElement('pre');
  pre.textContent = text || '';
  pre.style.whiteSpace = 'pre-wrap';
  pre.style.wordBreak = 'break-word';
  pre.style.fontSize = '11px';
  pre.style.lineHeight = '1.45';
  pre.style.background = '#0c1624';
  pre.style.border = '1px solid var(--line)';
  pre.style.borderRadius = '8px';
  pre.style.padding = '10px';
  pre.style.maxHeight = maxHeight || '260px';
  pre.style.overflow = 'auto';
  pre.style.margin = '0 0 10px';
  return pre;
}
function hwTable(headers, rows) {
  const wrap = document.createElement('div'); wrap.className = 'tablewrap';
  const table = document.createElement('table');
  const thead = document.createElement('thead');
  const hr = document.createElement('tr');
  headers.forEach(h => hr.appendChild(escEl('th', h)));
  thead.appendChild(hr); table.appendChild(thead);
  const tbody = document.createElement('tbody');
  rows.forEach(cells => {
    const tr = document.createElement('tr');
    cells.forEach(cell => {
      const td = document.createElement('td');
      if (cell instanceof Node) td.appendChild(cell);
      else td.textContent = cell == null ? '' : String(cell);
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody); wrap.appendChild(table);
  return wrap;
}
function hwButton(label, cls, onClick, disabled, title) {
  const b = escEl('button', label, 'btn ' + (cls || ''));
  b.disabled = !!disabled;
  if (title) b.title = title;
  b.addEventListener('click', onClick);
  return b;
}
function hwCopyButton(text) {
  const b = hwButton('Copy AQL', 'small', async () => {
    try {
      await navigator.clipboard.writeText(text || '');
      b.textContent = 'Copied';
      setTimeout(() => { b.textContent = 'Copy AQL'; }, 1500);
    } catch (_) { b.textContent = 'Copy unavailable'; }
  }, !text);
  return b;
}

/* ---------- shell ---------- */

function hwCurrentQuery() {
  const h = location.hash.slice(1);
  const i = h.indexOf('?');
  return new URLSearchParams(i >= 0 ? h.slice(i + 1) : '');
}
function hwPush(query) {
  const qs = query.toString();
  history.replaceState(null, '', '#hunt' + (qs ? '?' + qs : ''));
}
async function renderHuntWorkspace() {
  const seq = ++hwCtl.seq;
  const grants = (me.authorized_clients || []);
  const topCtx = document.getElementById('tenant') ? document.getElementById('tenant').value : 'global';
  const q = hwCurrentQuery();
  const wanted = q.get('client') || '';
  const startClient = grants.includes(wanted) ? wanted : ((topCtx !== 'global' && grants.includes(topCtx)) ? topCtx : (grants[0] || ''));
  const section = q.get('section') || hwCtl.section || 'plans';
  hwCtl.client = startClient;
  hwCtl.section = ['plans', 'translation', 'coverage', 'review'].includes(section) ? section : 'plans';
  hwCtl.ruleId = q.get('rule') || hwCtl.ruleId || '';
  hwCtl.domainId = q.get('domain') || hwCtl.domainId || '';
  hwCtl.translationId = q.get('translation') || hwCtl.translationId || '';
  hwCtl.planId = q.get('plan') || hwCtl.planId || '';

  const shell = pageShell(
    'THREAT HUNTING / WORKSPACE',
    'Hunt Workspace',
    'CTI report → Sigma detection → verified telemetry → AQL draft → reviewed hunt plan. A draft is reviewed, never executed; approval is a human decision on evidence, not QRadar validation.',
    'Reviewed drafts only — nothing is executed or deployed',
    'PHASE 2B-4B'
  );
  const c = document.getElementById('content');

  const bar = document.createElement('div'); bar.className = 'filterbar';
  const lab = document.createElement('label'); lab.style.display = 'flex'; lab.style.alignItems = 'center'; lab.style.gap = '8px';
  lab.appendChild(escEl('span', 'Authorized client', 'eyebrow'));
  const sel = document.createElement('select'); sel.setAttribute('aria-label', 'Authorized client');
  if (!grants.length) { const o = document.createElement('option'); o.value = ''; o.textContent = 'No client grants'; sel.appendChild(o); }
  grants.forEach(cid => { const o = document.createElement('option'); o.value = cid; o.textContent = cid; sel.appendChild(o); });
  sel.value = startClient;
  lab.appendChild(sel); bar.appendChild(lab);
  bar.appendChild(escEl('span', grants.length ? ('Grant-scoped: ' + startClient + '. Other clients are not listed or fetched.') : 'No authorized clients: metadata-only view.', 'text-muted'));
  const refresh = hwButton('Refresh', 'small', () => { hwCtl.seq++; renderHuntWorkspace(); });
  bar.appendChild(refresh);
  c.insertBefore(bar, document.querySelector('.v3layout'));

  const tabs = document.createElement('div'); tabs.className = 'tabs';
  [['plans', 'Hunt Plans'], ['translation', 'Detection Translation'], ['coverage', 'Coverage & Gaps'], ['review', 'Review Queue']].forEach(([key, label]) => {
    const b = escEl('button', label, 'tab' + (hwCtl.section === key ? ' active' : ''));
    b.setAttribute('role', 'tab');
    b.setAttribute('aria-selected', hwCtl.section === key ? 'true' : 'false');
    b.addEventListener('click', () => {
      hwCtl.section = key; hwCtl.planId = ''; hwCtl.translationId = '';
      const nq = hwCurrentQuery(); nq.set('section', key); if (hwCtl.client) nq.set('client', hwCtl.client); hwPush(nq);
      hwCtl.seq++; renderHuntWorkspace();
    });
    tabs.appendChild(b);
  });
  c.insertBefore(tabs, document.querySelector('.v3layout'));

  sel.addEventListener('change', () => {
    hwCtl.client = sel.value; hwCtl.planId = ''; hwCtl.ruleId = ''; hwCtl.domainId = ''; hwCtl.translationId = '';
    const nq = hwCurrentQuery(); nq.set('client', sel.value); nq.set('section', hwCtl.section);
    ['plan', 'rule', 'domain', 'translation'].forEach(k => nq.delete(k));
    hwPush(nq);
    hwCtl.seq++; renderHuntWorkspace();
  });

  if (!startClient) {
    hwStateBox(shell.listHost, 'No authorized client. The Hunt Workspace shows only grant-scoped data.');
    shell.inspBody.textContent = 'No client selected.';
    return;
  }
  // The workbench and gap report use the full width; the plan/review tabs keep
  // the context inspector.
  if (hwCtl.section === 'translation' || hwCtl.section === 'coverage') {
    const layout = document.querySelector('.v3layout');
    if (layout) layout.style.gridTemplateColumns = '1fr';
    const insp = document.querySelector('.v3inspector');
    if (insp) insp.style.display = 'none';
  }
  if (hwCtl.section === 'plans') return hwPlans(shell, seq);
  if (hwCtl.section === 'translation') return hwTranslation(shell, seq);
  if (hwCtl.section === 'coverage') return hwCoverage(shell, seq);
  return hwReview(shell, seq);
}

/* ---------- hunt plans ---------- */

function hwPlanEvidence(plan) {
  const items = plan.items || [];
  if (!items.length) return { state: 'NO ITEMS', detail: 'No reviewed draft is attached.' };
  if (items.some(i => i.evidence_state === 'EVIDENCE_UNAVAILABLE')) return { state: 'EVIDENCE_UNAVAILABLE', detail: 'Attached evidence is no longer readable.' };
  if (items.some(i => i.evidence_state === 'STALE_EVIDENCE' || i.stale)) return { state: 'STALE_EVIDENCE', detail: 'Attached evidence is stale.' };
  return { state: 'OK', detail: 'Attached drafts are current.' };
}
function hwPlanSearchLink(plan) {
  return '#hunt?section=plans&client=' + encodeURIComponent(plan.client_id || '') + '&plan=' + encodeURIComponent(plan.plan_id);
}

async function hwPlans(shell, seq) {
  const { listHost, inspBody } = shell;
  const cid = hwCtl.client;
  hwStateBox(listHost, 'Loading hunt plans…');
  inspBody.textContent = 'Select a plan to inspect.';
  let plans = [], hyps = [];
  try {
    const d = await api('/api/v1/hunt-plans?client_id=' + encodeURIComponent(cid));
    if (seq !== hwCtl.seq) return;
    plans = d.plans || [];
  } catch (e) {
    if (seq !== hwCtl.seq) return;
    hwStateBox(listHost, hwErrText(e));
    return;
  }
  try {
    const h = await api('/api/v1/hypotheses?client_id=' + encodeURIComponent(cid) + '&limit=100&offset=0');
    if (seq !== hwCtl.seq) return;
    hyps = h.hypotheses || [];
  } catch (_) { hyps = []; }
  const hypVersions = {};
  hyps.forEach(h => { hypVersions[h.hypothesis_id] = Number(h.current_version_no || 0); });

  listHost.innerHTML = '';
  if (hwCanCreate()) {
    const form = document.createElement('div'); form.className = 'note';
    form.appendChild(escEl('div', 'Create a hunt plan from an authorized hypothesis', 'paneltitle'));
    const title = document.createElement('input'); title.placeholder = 'Plan title'; title.setAttribute('aria-label', 'Plan title');
    title.style.background = '#0c1624'; title.style.border = '1px solid var(--line)'; title.style.borderRadius = '8px';
    title.style.color = 'var(--text)'; title.style.padding = '8px 10px'; title.style.width = '100%'; title.style.margin = '8px 0';
    const hyp = document.createElement('select'); hyp.setAttribute('aria-label', 'Hypothesis');
    hyp.style.background = '#0c1624'; hyp.style.border = '1px solid var(--line)'; hyp.style.borderRadius = '8px';
    hyp.style.color = 'var(--text)'; hyp.style.padding = '8px 10px'; hyp.style.width = '100%'; hyp.style.margin = '0 0 8px';
    if (!hyps.length) { const o = document.createElement('option'); o.value = ''; o.textContent = 'No hypothesis for this client'; hyp.appendChild(o); }
    hyps.forEach(h => { const o = document.createElement('option'); o.value = h.hypothesis_id; o.textContent = (h.title || h.hypothesis_id) + ' · v' + (h.current_version_no || 'unavailable') + ' [' + h.hypothesis_id + ']'; hyp.appendChild(o); });
    const create = hwButton('Create draft plan', 'primary small', async () => {
      if (!title.value.trim() || !hyp.value) { hwNotify('A title and a hypothesis are required.', 'error'); return; }
      // The version comes from the API. A missing version is an error, never a
      // silent guess of "1".
      const version = Number(hypVersions[hyp.value] || 0);
      if (!version) {
        hwNotify('The API did not return a current version for this hypothesis. Refusing to create a plan with a guessed version.', 'error');
        return;
      }
      create.disabled = true;
      try {
        const p = await api('/api/v1/hunt-plans', { method: 'POST', body: { client_id: cid, hypothesis_id: hyp.value, hypothesis_version: version, title: title.value.trim() } });
        hwCtl.planId = p.plan_id;
        const nq = hwCurrentQuery(); nq.set('plan', p.plan_id); hwPush(nq);
        renderHuntWorkspace();
      } catch (e) { hwNotify(hwErrText(e)); create.disabled = false; }
    }, !hyps.length, hyps.length ? '' : 'No hypothesis is available for this client.');
    form.append(title, hyp, create);
    listHost.appendChild(form);
  } else {
    hwMuted(listHost, 'Creating plans requires the hypothesis-writer capability (ADMINISTRATOR or HYPOTHESIS_WRITER).');
  }

  listHost.appendChild(escEl('div', plans.length + ' plan version(s) for ' + cid + '. Approved versions are immutable; changes create a new version.', 'paneltitle')).style.margin = '14px 0 8px';
  if (!plans.length) {
    hwStateBox(listHost, 'No hunt plans for this client yet.');
    return;
  }
  const rows = plans.map(p => {
    const ev = hwPlanEvidence(p);
    const open = hwButton('Open', 'small', () => {
      hwCtl.planId = p.plan_id;
      const nq = hwCurrentQuery(); nq.set('plan', p.plan_id); hwPush(nq);
      renderHuntWorkspace();
    });
    return [
      p.title, p.client_id, p.hypothesis_id + ' v' + p.hypothesis_version,
      'v' + p.version, p.status, String((p.items || []).length), ev.state,
      p.reviewed_by || '—', p.created_at || '—', p.reviewed_at || '—', open
    ];
  });
  listHost.appendChild(hwTable(['Title', 'Client', 'Hypothesis', 'Plan ver', 'Status', 'Drafts', 'Evidence', 'Reviewer', 'Created', 'Reviewed', ''], rows));

  const chosen = hwCtl.planId || (plans[0] && plans[0].plan_id);
  if (chosen) hwPlanInspector(inspBody, chosen, seq);
}

async function hwPlanInspector(host, planId, seq) {
  host.innerHTML = '';
  host.appendChild(escEl('div', 'Loading plan…', 'text-muted'));
  let plan;
  try {
    plan = await api('/api/v1/hunt-plans/' + encodeURIComponent(planId));
  } catch (e) {
    host.innerHTML = '';
    hwMuted(host, hwErrText(e));
    return;
  }
  if (seq !== hwCtl.seq) return;
  host.innerHTML = '';
  host.appendChild(escEl('div', 'Hunt plan', 'kv-k'));
  kvAdd(host, 'Title', plan.title);
  kvAdd(host, 'Client', plan.client_id);
  kvAdd(host, 'Hypothesis', plan.hypothesis_id + ' v' + plan.hypothesis_version);
  kvAdd(host, 'Plan version', 'v' + plan.version + (plan.supersedes_plan_id ? ' (supersedes ' + plan.supersedes_plan_id + ')' : ''));
  kvAdd(host, 'Status', plan.status);
  kvAdd(host, 'Created', (plan.created_by || '—') + ' · ' + (plan.created_at || '—'));
  kvAdd(host, 'Submitted', (plan.submitted_by || '—') + ' · ' + (plan.submitted_at || '—'));
  kvAdd(host, 'Reviewed', (plan.reviewed_by || '—') + ' · ' + (plan.reviewed_at || '—'));
  kvAdd(host, 'Review evidence', plan.review_evidence || '—');
  const ev = hwPlanEvidence(plan);
  kvAdd(host, 'Evidence state', ev.state + ' — ' + ev.detail);

  secAdd(host, 'Attached drafts');
  if (!(plan.items || []).length) hwMuted(host, 'No draft attached.');
  (plan.items || []).forEach(it => {
    const row = document.createElement('div'); row.className = 'note';
    row.appendChild(hwBadge(it.evidence_state || (it.stale ? 'STALE_EVIDENCE' : 'OK'), hwEvidenceTone(it.evidence_state)));
    row.appendChild(escEl('div', it.translation_id, 'kv-v'));
    row.appendChild(escEl('div', it.translation_status + ' · domain ' + it.native_qradar_domain_id + ' (' + it.domain_id + ')', 'text-muted'));
    row.appendChild(escEl('div', 'Added by ' + (it.added_by || '—') + ' · ' + (it.added_at || '—'), 'text-muted'));
    if (it.stale_reasons && it.stale_reasons.length) row.appendChild(escEl('div', 'Why: ' + it.stale_reasons.join(' | '), 'text-muted'));
    row.appendChild(hwButton('Open draft', 'small', () => {
      hwCtl.section = 'translation'; hwCtl.translationId = it.translation_id; hwCtl.ruleId = '';
      const nq = hwCurrentQuery(); nq.set('section', 'translation'); nq.set('translation', it.translation_id); nq.set('client', plan.client_id); hwPush(nq);
      hwCtl.seq++; renderHuntWorkspace();
    }));
    host.appendChild(row);
  });

  secAdd(host, 'Actions');
  if (plan.status === 'DRAFT') {
    const attachHost = document.createElement('div');
    attachHost.appendChild(escEl('div', 'Attach a READY_FOR_REVIEW draft', 'kv-k'));
    const sel = document.createElement('select'); sel.setAttribute('aria-label', 'Ready draft to attach');
    sel.style.cssText = 'width:100%;background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text);padding:8px;margin:6px 0';
    const o0 = document.createElement('option'); o0.value = ''; o0.textContent = 'Loading drafts…'; sel.appendChild(o0);
    attachHost.appendChild(sel);
    const attach = hwButton('Attach to plan', 'small', async () => {
      if (!sel.value) { hwNotify('Select a draft first.'); return; }
      attach.disabled = true;
      try { await api('/api/v1/hunt-plans/' + encodeURIComponent(planId) + '/items', { method: 'POST', body: { translation_id: sel.value } }); renderHuntWorkspace(); }
      catch (e) { hwNotify(hwErrText(e)); attach.disabled = false; }
    }, true, 'Select a draft');
    attachHost.appendChild(attach);
    host.appendChild(attachHost);
    (async () => {
      try {
        const rules = (await api('/api/v1/detections/sigma?client_id=' + encodeURIComponent(plan.client_id))).rules || [];
        let candidates = [];
        for (const r of rules.slice(0, 20)) {
          if (seq !== hwCtl.seq) return;
          try {
            const t = await api('/api/v1/sigma-rules/' + encodeURIComponent(r.rule_id) + '/translations');
            (t.translations || []).forEach(tr => { if (tr.status === 'READY_FOR_REVIEW' && !tr.stale) candidates.push(tr); });
          } catch (_) {}
        }
        if (seq !== hwCtl.seq || !sel.isConnected) return;
        sel.innerHTML = '';
        if (!candidates.length) { const o = document.createElement('option'); o.value = ''; o.textContent = 'No READY_FOR_REVIEW draft for this client'; sel.appendChild(o); return; }
        candidates.forEach(tr => { const o = document.createElement('option'); o.value = tr.translation_id; o.textContent = tr.translation_id + ' · domain ' + tr.native_qradar_domain_id + ' · ' + tr.rule_id; sel.appendChild(o); });
        attach.disabled = false; attach.title = '';
      } catch (e) {
        sel.innerHTML = ''; const o = document.createElement('option'); o.value = ''; o.textContent = hwErrText(e); sel.appendChild(o);
      }
    })();
    const submit = hwButton('Submit for review', 'primary small', async () => {
      submit.disabled = true;
      try { await api('/api/v1/hunt-plans/' + encodeURIComponent(planId) + '/submit', { method: 'POST', body: {} }); renderHuntWorkspace(); }
      catch (e) { hwNotify(hwErrText(e)); submit.disabled = false; }
    }, !hwCanCreate() || !(plan.items || []).length, !hwCanCreate() ? 'Requires plan-writer capability' : 'Attach at least one draft first');
    host.appendChild(submit);
  } else if (plan.status === 'IN_REVIEW') {
    if (hwCanReview()) {
      const evIn = document.createElement('textarea');
      evIn.placeholder = 'Review evidence (required, at least 12 characters)';
      evIn.setAttribute('aria-label', 'Review evidence');
      evIn.rows = 3;
      evIn.style.cssText = 'width:100%;background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text);padding:8px;margin:6px 0';
      const note = document.createElement('input'); note.placeholder = 'Note (optional)';
      note.setAttribute('aria-label', 'Review note');
      note.style.cssText = 'width:100%;background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text);padding:8px;margin:0 0 8px';
      const decide = async (decision) => {
        if (!evIn.value.trim()) { hwNotify('Review evidence is required.'); return; }
        if (hwCtl.busy) return;
        hwCtl.busy = true;
        try {
          await api('/api/v1/hunt-plans/' + encodeURIComponent(planId) + '/review', { method: 'POST', body: { decision, evidence: evIn.value.trim(), note: note.value.trim() } });
          hwCtl.busy = false;
          renderHuntWorkspace();
        } catch (e) {
          hwCtl.busy = false;
          hwNotify(hwErrText(e), 'error');
        }
      };
      const row = document.createElement('div'); row.style.display = 'flex'; row.style.gap = '6px';
      row.append(
        hwButton('Approve (reviewed draft)', 'primary small', () => decide('APPROVED')),
        hwButton('Reject', 'small', () => decide('REJECTED'))
      );
      host.append(evIn, note, row);
      hwMuted(host, 'Approval means a human-reviewed draft. It is not executed, not deployed, and not validated against QRadar.');
    } else {
      hwMuted(host, 'Review requires ADMINISTRATOR or REVIEWER. The server enforces this.');
    }
  } else {
    const ver = hwButton('Create new plan version', 'primary small', async () => {
      ver.disabled = true;
      try { const p = await api('/api/v1/hunt-plans/' + encodeURIComponent(planId) + '/versions', { method: 'POST', body: {} }); hwCtl.planId = p.plan_id; const nq = hwCurrentQuery(); nq.set('plan', p.plan_id); hwPush(nq); hwCtl.seq++; renderHuntWorkspace(); }
      catch (e) { hwNotify(hwErrText(e)); ver.disabled = false; }
    }, !hwCanCreate(), 'Requires plan-writer capability');
    host.appendChild(ver);
    hwMuted(host, plan.status === 'APPROVED' ? 'Approved content is immutable. A new version preserves this version.' : 'A new version starts as DRAFT.');
  }

  secAdd(host, 'Version history');
  try {
    const all = (await api('/api/v1/hunt-plans?client_id=' + encodeURIComponent(plan.client_id))).plans || [];
    if (seq !== hwCtl.seq || !host.isConnected) return;
    const hist = all.filter(p => p.logical_id === plan.logical_id).sort((a, b) => a.version - b.version);
    hist.forEach(p => {
      const row = document.createElement('div'); row.className = 'hist';
      row.appendChild(escEl('span', 'v' + p.version + ' · ' + p.status + ' · ' + (p.reviewed_by || p.created_by || '')));
      const open = hwButton('Open', 'small', () => { hwCtl.planId = p.plan_id; renderHuntWorkspace(); });
      row.appendChild(open);
      host.appendChild(row);
    });
  } catch (_) { hwMuted(host, 'Version history unavailable.'); }
}

/* ---------- detection translation workbench ---------- */

async function hwTranslation(shell, seq) {
  const { listHost, inspBody } = shell;
  const cid = hwCtl.client;
  hwStateBox(listHost, 'Loading Sigma detections…');
  inspBody.textContent = 'Select a rule to inspect its source, readiness and drafts.';
  let rules = [];
  try {
    const d = await api('/api/v1/detections/sigma?client_id=' + encodeURIComponent(cid));
    if (seq !== hwCtl.seq) return;
    rules = d.rules || [];
  } catch (e) {
    if (seq !== hwCtl.seq) return;
    hwStateBox(listHost, hwErrText(e)); return;
  }
  listHost.innerHTML = '';
  if (!rules.length) { hwStateBox(listHost, 'No Sigma detection is registered for this client. Ingest one in the Sigma Registry first.'); return; }

  const cols = document.createElement('div'); cols.className = 'hwcols';
  const left = document.createElement('div');
  const center = document.createElement('div');
  const right = document.createElement('div');
  cols.append(left, center, right);
  listHost.appendChild(cols);

  left.appendChild(escEl('div', '1 · SIGMA SOURCE', 'paneltitle'));
  rules.forEach(r => {
    const row = document.createElement('div'); row.className = 'note';
    const head = document.createElement('div'); head.style.display = 'flex'; head.style.gap = '6px'; head.style.alignItems = 'center';
    head.append(escEl('strong', r.title || r.rule_id), escEl('span', 'v' + r.version, 'badge muted'));
    row.appendChild(head);
    row.appendChild(escEl('div', (r.logsource_product || r.logsource_service || 'logsource not stated') + ' · ' + r.rule_id, 'text-muted'));
    row.appendChild(hwButton('Inspect source', 'small', () => {
      hwCtl.ruleId = r.rule_id; hwCtl.domainId = ''; hwCtl.translationId = '';
      const nq = hwCurrentQuery(); nq.set('rule', r.rule_id); nq.set('section', 'translation'); hwPush(nq);
      hwCtl.seq++; renderHuntWorkspace();
    }));
    left.appendChild(row);
  });

  const ruleId = hwCtl.ruleId || rules[0].rule_id;
  if (!hwCtl.ruleId) hwCtl.ruleId = ruleId;
  let rule = null, scope = null, translations = [];
  try {
    rule = await api('/api/v1/detections/sigma/' + encodeURIComponent(ruleId));
    if (seq !== hwCtl.seq) return;
    const td = await api('/api/v1/sigma-rules/' + encodeURIComponent(ruleId) + '/translations');
    if (seq !== hwCtl.seq) return;
    translations = td.translations || [];
    try { scope = await api('/api/v1/detections/sigma/' + encodeURIComponent(ruleId) + '/scope?client_id=' + encodeURIComponent(cid)); } catch (e) { scope = { error: hwErrText(e), domains: [], notes: [] }; }
  } catch (e) {
    hwMuted(left, hwErrText(e)); return;
  }
  if (seq !== hwCtl.seq) return;

  secAdd(left, 'Selected source');
  kvAdd(left, 'Title', rule.title);
  kvAdd(left, 'Sigma id', rule.sigma_rule_id);
  kvAdd(left, 'Version', 'v' + rule.version);
  kvAdd(left, 'Filename', rule.filename);
  kvAdd(left, 'CTI report', rule.report_id || 'Not linked to a report');
  kvAdd(left, 'Logsource', [rule.logsource_product, rule.logsource_category, rule.logsource_service].filter(Boolean).join(' / ') || '—');
  kvAdd(left, 'Condition', rule.condition);
  kvAdd(left, 'Modifiers', (rule.modifiers || []).join(', ') || 'none');
  kvAdd(left, 'MITRE tags', (rule.tags || []).filter(t => String(t).startsWith('attack.')).join(', ') || 'none');
  secAdd(left, 'Original Sigma YAML (never rendered as HTML)');
  left.appendChild(hwPre(rule.yaml, '300px'));

  center.appendChild(escEl('div', '2 · CLIENT TELEMETRY', 'paneltitle'));
  if (scope && scope.error) { hwMuted(center, scope.error); }
  else if (!scope || !(scope.domains || []).length) {
    hwMuted(center, 'No verified client domain binding for ' + cid + '. Generation is blocked until a verified native domain exists.');
    (scope && scope.notes || []).forEach(n => hwMuted(center, '• ' + n));
  } else {
    const dsel = document.createElement('select'); dsel.setAttribute('aria-label', 'Verified domain');
    dsel.style.cssText = 'width:100%;background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text);padding:8px;margin-bottom:10px';
    scope.domains.forEach(d => { const o = document.createElement('option'); o.value = d.domain_id; o.textContent = d.domain_name + ' · native ' + d.native_qradar_domain_id + ' · ' + d.status; dsel.appendChild(o); });
    const chosen = scope.domains.some(d => d.domain_id === hwCtl.domainId) ? hwCtl.domainId : scope.domains[0].domain_id;
    dsel.value = chosen; hwCtl.domainId = chosen;
    center.appendChild(dsel);
    const dom = scope.domains.find(d => d.domain_id === chosen);
    kvAdd(center, 'Instance', dom.instance_id);
    kvAdd(center, 'Native QRadar Domain ID', dom.native_qradar_domain_id);
    kvAdd(center, 'Binding revision', dom.binding_revision);
    kvAdd(center, 'Readiness', dom.status);
    kvAdd(center, 'DSM', dom.dsm_verified ? (dom.primary_dsm || 'verified') : 'Not verified / unknown DSM');
    kvAdd(center, 'Event scope', 'Sigma event value, not a QRadar QID');
    secAdd(center, 'Field readiness (mapping + attestation)');
    (dom.fields || []).forEach(f => {
      const box = document.createElement('div'); box.className = 'note';
      box.append(hwBadge(f.state, hwStatusTone(f.state)), escEl('strong', ' ' + f.field));
      box.appendChild(escEl('div', 'CEP: ' + (f.cep_field || '—') + ' · mapping ' + (f.mapping_id || '—') + (f.mapping_version ? ' v' + f.mapping_version : ''), 'text-muted'));
      box.appendChild(escEl('div', 'Approved by: ' + (f.approved_by || 'not approved') + ' · AQL observation: ' + (f.observation || 'not attested'), 'text-muted'));
      if (f.detail) box.appendChild(escEl('div', f.detail, 'text-muted'));
      center.appendChild(box);
    });
    secAdd(center, 'Log source candidates');
    if (!(dom.log_sources || []).length) hwMuted(center, 'No log source candidate — DSM not established.');
    (dom.log_sources || []).forEach(ls => hwMuted(center, '• ' + (ls.type_name || ls.log_source_type_id || '') + ' · ' + (ls.match || '') + ' · ' + (ls.status || 'unknown')));
    (scope.notes || []).forEach(n => hwMuted(center, '• ' + n));
    dsel.addEventListener('change', () => {
      hwCtl.domainId = dsel.value;
      const nq = hwCurrentQuery(); nq.set('domain', dsel.value); hwPush(nq);
      hwCtl.seq++; renderHuntWorkspace();
    });
  }

  right.appendChild(escEl('div', '3 · AQL DRAFT', 'paneltitle'));
  const tm = translations.length ? translations[0] : null;
  const chosenTr = translations.find(t => t.translation_id === hwCtl.translationId) || tm;
  if (!translations.length) {
    hwMuted(right, 'No draft exists for this rule.');
  } else {
    const tsel = document.createElement('select'); tsel.setAttribute('aria-label', 'Draft');
    tsel.style.cssText = 'width:100%;background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text);padding:8px;margin-bottom:10px';
    translations.forEach(t => { const o = document.createElement('option'); o.value = t.translation_id; o.textContent = t.translation_id + ' · ' + t.status + (t.stale ? ' · STALE' : ''); tsel.appendChild(o); });
    tsel.value = chosenTr.translation_id; hwCtl.translationId = chosenTr.translation_id;
    right.appendChild(tsel);
    let full = chosenTr;
    try { full = await api('/api/v1/detection-translations/' + encodeURIComponent(chosenTr.translation_id)); } catch (_) {}
    if (seq !== hwCtl.seq) return;
    kvAdd(right, 'Status', full.status);
    kvAdd(right, 'Conversion mode', full.conversion_mode);
    kvAdd(right, 'Domain', (full.native_qradar_domain_id || '—') + ' · binding rev ' + full.binding_revision);
    kvAdd(right, 'Staleness', full.stale ? ('STALE_EVIDENCE: ' + (full.stale_reasons || []).join(' | ')) : 'OK');
    kvAdd(right, 'Worker / backend', (full.worker_version || '—') + ' / ' + (full.backend_version || '—') + ' / pySigma ' + (full.pysigma_version || '—'));
    kvAdd(right, 'Execution', 'NOT EXECUTED — draft only');
    if (full.status === 'UNSUPPORTED' || full.status === 'BLOCKED' || full.status === 'NEEDS_FIELD_VERIFICATION') {
      const warn = document.createElement('div'); warn.className = 'note';
      warn.appendChild(hwBadge(full.status, hwStatusTone(full.status)));
      warn.appendChild(escEl('div', 'No AQL is produced. The original Sigma detection is preserved unchanged.', 'text-muted'));
      right.appendChild(warn);
    }
    secAdd(right, 'AQL draft');
    if (full.aql_draft) {
      const aqlPre = hwPre(full.aql_draft, '220px');
      aqlPre.classList.add('hw-aql');
      right.appendChild(aqlPre);
      right.appendChild(hwCopyButton(full.aql_draft));
    } else {
      hwMuted(right, 'No AQL draft exists for this status.');
    }
    secAdd(right, 'Diagnostics');
    const dg = full.diagnostics || {};
    kvAdd(right, 'Converted fields', (dg.converted_fields || []).join(', ') || 'none');
    kvAdd(right, 'Unmapped fields', (dg.unmapped_fields || []).join(', ') || 'none');
    kvAdd(right, 'Unsupported conditions', (dg.unsupported_conditions || []).join(' | ') || 'none reported');
    kvAdd(right, 'Worker error', dg.worker_error || 'none');
    kvAdd(right, 'Worker isolation', 'network sandbox: ' + (dg.isolation && dg.isolation.network_sandbox ? 'yes' : 'NOT implemented') + ' · filesystem sandbox: ' + (dg.isolation && dg.isolation.filesystem_sandbox ? 'yes' : 'NOT implemented'));
    (dg.notes || []).forEach(n => hwMuted(right, '• ' + n));
    secAdd(right, 'Mapping snapshot');
    if (!(full.mappings || []).length) hwMuted(right, 'No mapping in the snapshot.');
    (full.mappings || []).forEach(m => hwMuted(right, '• ' + m.field + ' → ' + (m.cep_field || '—') + ' · ' + (m.state || '') + ' · mapping ' + (m.mapping_id || '—') + ' v' + (m.mapping_version || '—') + ' · approved by ' + (m.approved_by || '—')));
    tsel.addEventListener('change', () => {
      hwCtl.translationId = tsel.value;
      const nq = hwCurrentQuery(); nq.set('translation', tsel.value); hwPush(nq);
      hwCtl.seq++; renderHuntWorkspace();
    });
  }

  secAdd(right, 'Actions');
  const gen = hwButton('Generate AQL draft', 'primary small', async () => {
    if (!hwCtl.domainId) { hwNotify('Select a verified domain first.'); return; }
    gen.disabled = true;
    try {
      const t = await api('/api/v1/sigma-rules/' + encodeURIComponent(ruleId) + '/translations', {
        method: 'POST', body: { client_id: cid, domain_id: hwCtl.domainId, conversion_mode: 'VERIFIED_FIELDS_ONLY', time_window_days: 7 }
      });
      hwCtl.translationId = t.translation_id;
      hwCtl.seq++; renderHuntWorkspace();
    } catch (e) { hwNotify(hwErrText(e)); gen.disabled = false; }
  }, !hwCanGenerate() || !scope || !(scope.domains || []).length,
    !hwCanGenerate() ? 'Requires the AQL-generation capability' : (!(scope && (scope.domains || []).length) ? 'No verified domain' : ''));
  right.appendChild(gen);
  if (!hwCanGenerate()) hwMuted(right, 'Generation requires ADMINISTRATOR. Existing drafts remain readable.');

  if (chosenTr) {
    const attachHost = document.createElement('div'); attachHost.style.marginTop = '10px';
    attachHost.appendChild(escEl('div', 'Attach to a DRAFT hunt plan', 'kv-k'));
    const psel = document.createElement('select'); psel.setAttribute('aria-label', 'Draft hunt plan');
    psel.style.cssText = 'width:100%;background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text);padding:8px;margin:6px 0';
    const ob = document.createElement('option'); ob.value = ''; ob.textContent = 'Loading plans…'; psel.appendChild(ob);
    const attach = hwButton('Attach to plan', 'small', async () => {
      if (!psel.value) { hwNotify('Select a DRAFT plan.'); return; }
      attach.disabled = true;
      try { await api('/api/v1/hunt-plans/' + encodeURIComponent(psel.value) + '/items', { method: 'POST', body: { translation_id: chosenTr.translation_id } }); hwNotify('Draft attached to plan ' + psel.value + '.'); renderHuntWorkspace(); }
      catch (e) { hwNotify(hwErrText(e)); attach.disabled = false; }
    }, true);
    attachHost.append(psel, attach);
    right.appendChild(attachHost);
    (async () => {
      try {
        const plans = (await api('/api/v1/hunt-plans?client_id=' + encodeURIComponent(cid))).plans || [];
        const drafts = plans.filter(p => p.status === 'DRAFT');
        if (seq !== hwCtl.seq || !psel.isConnected) return;
        psel.innerHTML = '';
        if (!drafts.length) { const o = document.createElement('option'); o.value = ''; o.textContent = 'No DRAFT plan for this client'; psel.appendChild(o); return; }
        drafts.forEach(p => { const o = document.createElement('option'); o.value = p.plan_id; o.textContent = (p.title || p.plan_id) + ' · v' + p.version; psel.appendChild(o); });
        attach.disabled = false;
      } catch (_) { psel.innerHTML = ''; const o = document.createElement('option'); o.value = ''; o.textContent = 'Plans unavailable'; psel.appendChild(o); }
    })();
  }
}

/* ---------- coverage & gaps ---------- */

async function hwCoverage(shell, seq) {
  const { listHost, inspBody } = shell;
  const cid = hwCtl.client;
  hwStateBox(listHost, 'Loading readiness diagnostics…');
  inspBody.textContent = 'Gaps are grouped from Detection Scope diagnostics. No readiness percentage is invented.';
  let rules = [];
  try { rules = (await api('/api/v1/detections/sigma?client_id=' + encodeURIComponent(cid))).rules || []; }
  catch (e) { if (seq === hwCtl.seq) hwStateBox(listHost, hwErrText(e)); return; }
  if (seq !== hwCtl.seq) return;
  listHost.innerHTML = '';
  if (!rules.length) { hwStateBox(listHost, 'No Sigma detections for this client. Nothing to assess.'); return; }

  const groups = {
    'No verified domain / missing telemetry': [], 'Unknown DSM': [], 'Missing CEP target': [],
    'Unapproved mapping': [], 'Missing AQL attestation': [], 'Unsupported Sigma condition': [],
    'Stale binding or mapping': [], 'Not ready but explained': []
  };
  const perRule = [];
  for (const r of rules.slice(0, 12)) {
    let scope = null;
    try { scope = await api('/api/v1/detections/sigma/' + encodeURIComponent(r.rule_id) + '/scope?client_id=' + encodeURIComponent(cid)); } catch (e) { groups['No verified domain / missing telemetry'].push(r.title + ' — scope unavailable (' + hwErrText(e) + ')'); continue; }
    if (seq !== hwCtl.seq) return;
    let trs = [];
    try { trs = (await api('/api/v1/sigma-rules/' + encodeURIComponent(r.rule_id) + '/translations')).translations || []; } catch (_) {}
    const stale = trs.filter(t => t.stale);
    if (stale.length) groups['Stale binding or mapping'].push(r.title + ' — ' + stale.map(t => (t.stale_reasons || []).join('; ')).join(' | '));
    const unsupported = trs.filter(t => t.status === 'UNSUPPORTED' || t.status === 'BLOCKED');
    unsupported.forEach(t => groups['Unsupported Sigma condition'].push(r.title + ' — ' + t.status + ((t.diagnostics && t.diagnostics.worker_error) ? (': ' + t.diagnostics.worker_error) : '')));
    perRule.push(r.title + ' · ' + r.rule_id + ' · ' + (scope.status || 'UNKNOWN') + ' · drafts ' + trs.length);
    if (!(scope.domains || []).length) { groups['No verified domain / missing telemetry'].push(r.title + ' — no verified client domain binding'); }
    (scope.domains || []).forEach(d => {
      if (!d.dsm_verified) groups['Unknown DSM'].push(r.title + ' @ ' + d.domain_name + ' — DSM not verified');
      (d.fields || []).forEach(f => {
        if (f.state === 'SCOPE_MISMATCH' || f.state === 'CONFLICTING_MAPPINGS') groups['Unapproved mapping'].push(r.title + ' @ ' + d.domain_name + ' — ' + f.field + ': ' + f.state);
        else if (f.state === 'MISSING' || f.state === 'UNVERIFIED') groups['Missing CEP target'].push(r.title + ' @ ' + d.domain_name + ' — ' + f.field + ': ' + f.state);
        else if (f.state === 'MAPPING_APPROVED' || f.state === 'CEP_DISPLAYED') groups['Missing AQL attestation'].push(r.title + ' @ ' + d.domain_name + ' — ' + f.field + ': ' + f.state);
        else if (f.state === 'AQL_MANUALLY_ATTESTED' && !f.mapping_id) groups['Unapproved mapping'].push(r.title + ' @ ' + d.domain_name + ' — ' + f.field + ': attested but no approved mapping');
      });
      if (d.status !== 'READY_FOR_REVIEW' && d.status !== 'NEEDS_FIELD_VERIFICATION') groups['Not ready but explained'].push(r.title + ' @ ' + d.domain_name + ' — ' + d.status);
    });
  }
  if (seq !== hwCtl.seq) return;

  let total = 0;
  Object.keys(groups).forEach(k => { total += groups[k].length; });
  listHost.appendChild(escEl('div', 'Rules assessed: ' + Math.min(rules.length, 12) + ' of ' + rules.length + ' · gap findings: ' + total + ' · no percentage is computed', 'paneltitle'));
  Object.keys(groups).forEach(k => {
    secAdd(listHost, k + ' (' + groups[k].length + ')');
    if (!groups[k].length) { hwMuted(listHost, 'None observed in this sample.'); return; }
    groups[k].slice(0, 20).forEach(g => listHost.appendChild(escEl('div', '• ' + g, 'row')));
  });
  secAdd(listHost, 'Per-rule status');
  perRule.forEach(p => listHost.appendChild(escEl('div', '• ' + p, 'row')));
  const nav = hwButton('Open Field Intelligence', 'small', () => navigate('fields'));
  listHost.appendChild(nav);
  hwMuted(listHost, 'Mappings are never approved automatically. Field Intelligence is where approval happens.');
}

/* ---------- review queue ---------- */

async function hwReview(shell, seq) {
  const { listHost, inspBody } = shell;
  const cid = hwCtl.client;
  hwStateBox(listHost, 'Loading review queue…');
  inspBody.textContent = 'Select an IN_REVIEW plan. Refresh happens before every decision.';
  let plans = [];
  try { plans = (await api('/api/v1/hunt-plans?client_id=' + encodeURIComponent(cid))).plans || []; }
  catch (e) { if (seq === hwCtl.seq) hwStateBox(listHost, hwErrText(e)); return; }
  if (seq !== hwCtl.seq) return;
  const queue = plans.filter(p => p.status === 'IN_REVIEW');
  listHost.innerHTML = '';
  listHost.appendChild(escEl('div', queue.length + ' plan(s) awaiting review for ' + cid + '.', 'paneltitle')).style.margin = '0 0 10px';
  if (!hwCanReview()) hwMuted(listHost, 'You cannot decide these plans (requires ADMINISTRATOR or REVIEWER). The queue is read-only and the server enforces it.');
  if (!queue.length) { hwStateBox(listHost, 'Review queue is empty for this client.'); return; }
  const rows = queue.map(p => {
    const ev = hwPlanEvidence(p);
    return [p.title, p.hypothesis_id, 'v' + p.version, p.submitted_by || '—', p.submitted_at || '—', ev.state, hwButton('Review', 'small', () => {
      hwCtl.planId = p.plan_id;
      const nq = hwCurrentQuery(); nq.set('plan', p.plan_id); hwPush(nq);
      hwCtl.seq++; renderHuntWorkspace();
    })];
  });
  listHost.appendChild(hwTable(['Title', 'Hypothesis', 'Plan ver', 'Submitted by', 'Submitted at', 'Evidence', ''], rows));
  const chosen = (queue.find(p => p.plan_id === hwCtl.planId) || queue[0]).plan_id;
  await hwReviewInspector(inspBody, chosen, seq);
}

async function hwReviewInspector(host, planId, seq) {
  host.innerHTML = '';
  host.appendChild(escEl('div', 'Loading plan…', 'text-muted'));
  let plan;
  try { plan = await api('/api/v1/hunt-plans/' + encodeURIComponent(planId)); }
  catch (e) { host.innerHTML = ''; hwMuted(host, hwErrText(e)); return; }
  if (seq !== hwCtl.seq) return;
  host.innerHTML = '';
  host.appendChild(escEl('div', 'Review', 'kv-k'));
  kvAdd(host, 'Plan', plan.title + ' · v' + plan.version);
  kvAdd(host, 'Client', plan.client_id);
  kvAdd(host, 'Hypothesis', plan.hypothesis_id + ' v' + plan.hypothesis_version);
  kvAdd(host, 'Submitted', (plan.submitted_by || '—') + ' · ' + (plan.submitted_at || '—'));
  const ev = hwPlanEvidence(plan);
  kvAdd(host, 'Evidence state', ev.state + ' — ' + ev.detail);

  secAdd(host, 'Drafts and drafts context');
  for (const it of (plan.items || [])) {
    const box = document.createElement('div'); box.className = 'note';
    box.appendChild(hwBadge(it.evidence_state || 'UNKNOWN', hwEvidenceTone(it.evidence_state)));
    box.appendChild(escEl('div', it.translation_id + ' · ' + it.translation_status, 'kv-v'));
    box.appendChild(escEl('div', 'Native domain ' + it.native_qradar_domain_id + ' · mapping snapshot in draft', 'text-muted'));
    if (it.stale_reasons && it.stale_reasons.length) box.appendChild(escEl('div', 'Stale: ' + it.stale_reasons.join(' | '), 'text-muted'));
    try {
      const tr = await api('/api/v1/detection-translations/' + encodeURIComponent(it.translation_id));
      if (seq !== hwCtl.seq) return;
      kvAdd(box, 'Conversion mode', tr.conversion_mode);
      kvAdd(box, 'Unsupported', ((tr.diagnostics && tr.diagnostics.unsupported_conditions) || []).join(' | ') || 'none reported');
      kvAdd(box, 'Worker error', (tr.diagnostics && tr.diagnostics.worker_error) || 'none');
      if (tr.aql_draft) box.appendChild(hwPre(tr.aql_draft, '160px'));
      else box.appendChild(escEl('div', 'No AQL draft for this status — the original detection is preserved.', 'text-muted'));
      try {
        const rule = await api('/api/v1/detections/sigma/' + encodeURIComponent(tr.rule_id));
        if (seq !== hwCtl.seq) return;
        kvAdd(box, 'Sigma source', rule.title + ' v' + rule.version);
        box.appendChild(hwPre(rule.yaml, '120px'));
      } catch (_) {}
    } catch (e) { hwMuted(box, 'Draft detail unavailable: ' + hwErrText(e)); }
    host.appendChild(box);
  }
  if (seq !== hwCtl.seq || !host.isConnected) return;

  secAdd(host, 'Decision');
  if (!hwCanReview()) {
    hwMuted(host, 'Approval and rejection require ADMINISTRATOR or REVIEWER.');
    return;
  }
  const evIn = document.createElement('textarea');
  evIn.placeholder = 'Review evidence (required, at least 12 characters)';
  evIn.setAttribute('aria-label', 'Review evidence');
  evIn.rows = 3;
  evIn.style.cssText = 'width:100%;background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text);padding:8px;margin:6px 0';
  const note = document.createElement('input'); note.placeholder = 'Note (optional)';
  note.setAttribute('aria-label', 'Review note');
  note.style.cssText = 'width:100%;background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text);padding:8px;margin:0 0 8px';
  const status = escEl('div', '', 'text-muted');
  const decide = async (decision) => {
    if (!evIn.value.trim()) { hwNotify('Review evidence is required.'); return; }
    if (hwCtl.busy) return;
    hwCtl.busy = true;
    status.textContent = 'Refreshing the plan before the decision…';
    try {
      await api('/api/v1/hunt-plans/' + encodeURIComponent(planId));
      status.textContent = 'Submitting ' + decision.toLowerCase() + '…';
      await api('/api/v1/hunt-plans/' + encodeURIComponent(planId) + '/review', { method: 'POST', body: { decision, evidence: evIn.value.trim(), note: note.value.trim() } });
      hwCtl.busy = false;
      hwCtl.seq++; renderHuntWorkspace();
    } catch (e) {
      hwCtl.busy = false;
      status.textContent = hwErrText(e);
    }
  };
  const row = document.createElement('div'); row.style.display = 'flex'; row.style.gap = '6px';
  row.append(hwButton('Approve (reviewed draft)', 'primary small', () => decide('APPROVED')), hwButton('Reject', 'small', () => decide('REJECTED')));
  host.append(evIn, note, row, status);
  const callout = document.createElement('div'); callout.className = 'note';
  callout.appendChild(escEl('div', 'APPROVED = human-reviewed draft', 'paneltitle'));
  callout.appendChild(escEl('div', 'Not executed. Not deployed. Not validated against QRadar. The backend revalidates binding, mapping and attestation inside the decision transaction.', 'text-muted'));
  host.appendChild(callout);
}
