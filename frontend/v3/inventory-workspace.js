"use strict";
/* M7-F Phase 1 — Manual Inventory Workspace.
   Real API data only. Existing QRadar inventory tables, no second registry.
   No QRadar API, no binding auto-confirmation, no mapping auto-approval. */

let invCtl = { seq: 0, section: 'gaps', client: '', instanceId: '', domainId: '', kind: 'log_source_types', preview: null };

function invRole() { return (me && me.user && me.user.role) || ''; }
function invCanEdit() { return invRole() === 'ADMINISTRATOR'; }
function invCanReview() { return invRole() === 'ADMINISTRATOR' || invRole() === 'REVIEWER'; }
function invStatusTone(s) {
  if (['APPROVED_MAPPING', 'AQL_MANUALLY_ATTESTED', 'MANUALLY_ENTERED'].includes(s)) return 'mint';
  if (['IMPORTED_UNVERIFIED', 'STALE'].includes(s)) return 'amber';
  if (['CONFLICTING', 'MISSING'].includes(s)) return 'muted';
  return 'muted';
}
function invQuery() {
  const h = location.hash.slice(1); const i = h.indexOf('?');
  return new URLSearchParams(i >= 0 ? h.slice(i + 1) : '');
}
function invPush(q) { const s = q.toString(); history.replaceState(null, '', '#inventory' + (s ? '?' + s : '')); }
function invField(label, value, onInput, type) {
  const lab = document.createElement('label'); lab.style.cssText = 'display:flex;flex-direction:column;gap:4px;font-size:11px;color:var(--muted)';
  lab.appendChild(escEl('span', label));
  const inp = document.createElement('input'); inp.value = value || ''; inp.type = type || 'text';
  inp.style.cssText = 'background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text);padding:7px 9px';
  inp.addEventListener('input', () => onInput(inp.value));
  lab.appendChild(inp); return lab;
}
function invSelect(label, values, value, onChange) {
  const lab = document.createElement('label'); lab.style.cssText = 'display:flex;flex-direction:column;gap:4px;font-size:11px;color:var(--muted)';
  lab.appendChild(escEl('span', label));
  const sel = document.createElement('select');
  sel.style.cssText = 'background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text);padding:7px 9px';
  values.forEach(v => { const o = document.createElement('option'); o.value = v.value; o.textContent = v.label; sel.appendChild(o); });
  sel.value = value || '';
  sel.addEventListener('change', () => onChange(sel.value));
  lab.appendChild(sel); return lab;
}

async function renderInventoryWorkspace() {
  const seq = ++invCtl.seq;
  const grants = me.authorized_clients || [];
  const q = invQuery();
  const wanted = q.get('client') || '';
  const topCtx = document.getElementById('tenant') ? document.getElementById('tenant').value : 'global';
  invCtl.client = grants.includes(wanted) ? wanted : ((topCtx !== 'global' && grants.includes(topCtx)) ? topCtx : (grants[0] || ''));
  invCtl.section = q.get('section') || invCtl.section || 'gaps';

  const shell = pageShell('DETECTION ENGINEERING / INVENTORY', 'Manual Inventory Workspace',
    'QRadar metadata entered or imported by operators. Nothing here proves live connectivity, approves a mapping automatically or changes a client binding.',
    'Manual evidence only — not live QRadar telemetry', 'M7-F');
  const c = document.getElementById('content');

  const bar = document.createElement('div'); bar.className = 'filterbar';
  const sel = document.createElement('select'); sel.setAttribute('aria-label', 'Authorized client');
  sel.style.cssText = 'background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text);padding:7px 9px';
  grants.forEach(g => { const o = document.createElement('option'); o.value = g; o.textContent = g; sel.appendChild(o); });
  sel.value = invCtl.client;
  sel.addEventListener('change', () => {
    invCtl.client = sel.value; invCtl.instanceId = ''; invCtl.domainId = ''; invCtl.preview = null;
    const nq = invQuery(); nq.set('client', sel.value); invPush(nq); invCtl.seq++; renderInventoryWorkspace();
  });
  bar.appendChild(escEl('span', 'Client', 'eyebrow')); bar.appendChild(sel);
  bar.appendChild(escEl('span', grants.length ? 'Grant-scoped: only this client is listed.' : 'No client grants.', 'text-muted'));
  c.insertBefore(bar, document.querySelector('.v3layout'));

  const tabs = document.createElement('div'); tabs.className = 'tabs';
  [['instances', 'Instances'], ['bindings', 'Domain Bindings'], ['logSources', 'Log Sources'],
   ['dsmEvents', 'DSM & Event IDs'], ['customProps', 'Custom Properties'], ['mappings', 'Field Mappings'],
   ['import', 'Import & Preview'], ['gaps', 'Inventory Gaps']].forEach(([key, label]) => {
    const b = escEl('button', label, 'tab' + (invCtl.section === key ? ' active' : ''));
    b.setAttribute('role', 'tab'); b.setAttribute('aria-selected', invCtl.section === key ? 'true' : 'false');
    b.addEventListener('click', () => {
      invCtl.section = key;
      const nq = invQuery(); nq.set('section', key); if (invCtl.client) nq.set('client', invCtl.client); invPush(nq);
      invCtl.seq++; renderInventoryWorkspace();
    });
    tabs.appendChild(b);
  });
  c.insertBefore(tabs, document.querySelector('.v3layout'));

  if (!invCtl.client) { hwStateBox(shell.listHost, 'No authorized client.'); return; }
  const fn = { instances: invInstances, bindings: invBindings, logSources: invLogSources, dsmEvents: invDsmEvents,
    customProps: invCustomProps, mappings: invMappings, import: invImport, gaps: invGaps }[invCtl.section] || invGaps;
  return fn(shell, seq);
}

async function invInstances(shell, seq) {
  const host = shell.listHost; host.innerHTML = ''; host.appendChild(escEl('div', 'Loading instances…', 'statebox'));
  let instances = [];
  try { instances = (await api('/api/v1/qradar/instances?client_id=' + encodeURIComponent(invCtl.client))).instances || []; }
  catch (e) { if (seq === invCtl.seq) hwStateBox(host, hwErrText(e)); return; }
  if (seq !== invCtl.seq) return;
  host.innerHTML = '';
  if (!instances.length) hwMuted(host, 'No QRadar instance is registered for this client yet.');
  else host.appendChild(hwTable(['Instance', 'Host', 'Created', ''], instances.map(i => [i.instance_name, i.host || '—', i.created_at,
    hwButton('Open domains', 'small', () => { invCtl.instanceId = i.instance_id; invCtl.section = 'bindings'; renderInventoryWorkspace(); })])));
  if (invCanEdit()) {
    const form = document.createElement('div'); form.className = 'note';
    form.appendChild(escEl('div', 'Register a QRadar console (manual metadata)', 'paneltitle'));
    let name = '', h = '';
    const row = document.createElement('div'); row.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;margin-top:8px';
    row.append(invField('Instance name', '', v => name = v), invField('Host', '', v => h = v));
    form.appendChild(row);
    form.appendChild(hwButton('Create instance', 'primary small', async () => {
      try { await api('/api/v1/qradar/instances', { method: 'POST', body: { client_id: invCtl.client, instance_name: name.trim(), host: h.trim() } }); invCtl.seq++; renderInventoryWorkspace(); }
      catch (e) { hwNotify(hwErrText(e), 'error'); }
    }));
    host.appendChild(form);
  }
}

async function invBindings(shell, seq) {
  const host = shell.listHost; host.innerHTML = '';
  let instances = [];
  try { instances = (await api('/api/v1/qradar/instances?client_id=' + encodeURIComponent(invCtl.client))).instances || []; }
  catch (e) { hwStateBox(host, hwErrText(e)); return; }
  if (seq !== invCtl.seq) return;
  host.innerHTML = '';
  if (!instances.length) { hwStateBox(host, 'No instance. Create one under Instances first.'); return; }
  if (!instances.some(i => i.instance_id === invCtl.instanceId)) invCtl.instanceId = instances[0].instance_id;
  host.appendChild(invSelect('Instance', instances.map(i => ({ value: i.instance_id, label: i.instance_name + ' · ' + (i.host || '') })), invCtl.instanceId,
    v => { invCtl.instanceId = v; invCtl.seq++; renderInventoryWorkspace(); }));
  let domains = [], bindings = [];
  try {
    domains = (await api('/api/v1/qradar/domains?instance_id=' + encodeURIComponent(invCtl.instanceId))).domains || [];
    bindings = (await api('/api/v1/qradar/domain-bindings?instance_id=' + encodeURIComponent(invCtl.instanceId))).domain_bindings || [];
  } catch (e) { hwMuted(host, hwErrText(e)); return; }
  if (seq !== invCtl.seq) return;
  const byDomain = {}; bindings.forEach(b => byDomain[b.domain_id] = b);
  host.appendChild(escEl('div', 'Domains and verified ownership', 'paneltitle')).style.margin = '14px 0 8px';
  if (!domains.length) hwMuted(host, 'No domain on this console yet.');
  else host.appendChild(hwTable(['Domain', 'Native ID', 'Binding', 'Verification', 'Revision'], domains.map(d => {
    const b = byDomain[d.domain_id] || {};
    return [d.domain_name, d.native_qradar_domain_id || '—', b.binding_kind || 'UNASSIGNED', b.verification_status || 'UNVERIFIED', b.revision == null ? '—' : String(b.revision)];
  })));
  if (invCanEdit()) {
    const form = document.createElement('div'); form.className = 'note';
    form.appendChild(escEl('div', 'Confirm a native Domain ID (administrator only; requires evidence)', 'paneltitle'));
    let dname = '', dtype = 'production';
    const row = document.createElement('div'); row.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;margin-top:8px';
    row.append(invField('Domain name', '', v => dname = v), invField('Domain type', dtype, v => dtype = v));
    form.appendChild(row);
    form.appendChild(hwButton('Create domain (UNASSIGNED)', 'small', async () => {
      try { await api('/api/v1/qradar/domains', { method: 'POST', body: { instance_id: invCtl.instanceId, domain_name: dname.trim(), domain_type: dtype.trim() } }); invCtl.seq++; renderInventoryWorkspace(); }
      catch (e) { hwNotify(hwErrText(e), 'error'); }
    }));
    const sel = document.createElement('select'); sel.setAttribute('aria-label', 'Domain to bind');
    sel.style.cssText = 'width:100%;background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text);padding:7px;margin:8px 0';
    domains.forEach(d => { const o = document.createElement('option'); o.value = d.domain_id; o.textContent = d.domain_name; sel.appendChild(o); });
    let native = '', evidence = '';
    const brow = document.createElement('div'); brow.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap';
    brow.append(invField('Native QRadar Domain ID', '', v => native = v), invField('Evidence reference', '', v => evidence = v));
    form.append(sel, brow);
    form.appendChild(hwButton('Bind domain to ' + invCtl.client, 'primary small', async () => {
      const d = domains.find(x => x.domain_id === sel.value); if (!d) return;
      const b = byDomain[d.domain_id] || {};
      try {
        await api('/api/v1/qradar/domains/' + encodeURIComponent(d.domain_id) + '/binding', { method: 'PUT',
          body: { native_qradar_domain_id: native.trim(), client_id: invCtl.client, binding_kind: 'CLIENT', evidence: evidence.trim(), expected_revision: b.revision || 0 } });
        invCtl.seq++; renderInventoryWorkspace();
      } catch (e) { hwNotify(hwErrText(e), 'error'); }
    }));
    host.appendChild(form);
  } else hwMuted(host, 'Binding changes require ADMINISTRATOR with the QRadar binding capability.');
}

async function invDomainPicker(host, seq) {
  let instances = [];
  try { instances = (await api('/api/v1/qradar/instances?client_id=' + encodeURIComponent(invCtl.client))).instances || []; }
  catch (_) { return []; }
  if (!instances.length) { hwMuted(host, 'No instance registered.'); return []; }
  if (!instances.some(i => i.instance_id === invCtl.instanceId)) invCtl.instanceId = instances[0].instance_id;
  let domains = [];
  try { domains = (await api('/api/v1/qradar/domains?instance_id=' + encodeURIComponent(invCtl.instanceId))).domains || []; }
  catch (_) { return []; }
  if (!domains.length) { hwMuted(host, 'No domain on this instance.'); return []; }
  if (!domains.some(d => d.domain_id === invCtl.domainId)) invCtl.domainId = domains[0].domain_id;
  host.appendChild(invSelect('Domain', domains.map(d => ({ value: d.domain_id, label: d.domain_name })), invCtl.domainId,
    v => { invCtl.domainId = v; invCtl.seq++; renderInventoryWorkspace(); }));
  return domains;
}

async function invLogSources(shell, seq) {
  const host = shell.listHost; host.innerHTML = '';
  await invDomainPicker(host, seq);
  if (seq !== invCtl.seq || !invCtl.domainId) return;
  let types = [], sources = [];
  try {
    types = (await api('/api/v1/qradar/log-source-types?domain_id=' + encodeURIComponent(invCtl.domainId))).log_source_types || [];
    if (types.length) sources = (await api('/api/v1/qradar/log-sources?log_source_type_id=' + encodeURIComponent(types[0].log_source_type_id))).log_sources || [];
  } catch (e) { hwMuted(host, hwErrText(e)); return; }
  if (seq !== invCtl.seq) return;
  host.appendChild(escEl('div', 'Log source types (DSM) and manually declared log sources', 'paneltitle')).style.margin = '14px 0 8px';
  host.appendChild(hwTable(['Type', 'Created'], types.map(t => [t.type_name, t.created_at])));
  if (invCanEdit()) {
    let name = '';
    host.appendChild(invField('New log source type (DSM)', '', v => name = v));
    host.appendChild(hwButton('Add type', 'small', async () => {
      try { await api('/api/v1/qradar/log-source-types', { method: 'POST', body: { domain_id: invCtl.domainId, type_name: name.trim() } }); invCtl.seq++; renderInventoryWorkspace(); }
      catch (e) { hwNotify(hwErrText(e), 'error'); }
    }));
  }
  if (sources.length) {
    host.appendChild(escEl('div', 'Log sources of the first type', 'paneltitle')).style.margin = '14px 0 8px';
    host.appendChild(hwTable(['Status', 'Provenance', 'First seen', 'Last seen'], sources.map(s => [s.status, s.data_provenance || '—', s.first_seen || '—', s.last_seen || '—'])));
  } else hwMuted(host, 'No log source declared for the first type.');
  hwMuted(host, 'Status is operator-declared metadata. It does not prove a log source is online.');
}

async function invDsmEvents(shell, seq) {
  const host = shell.listHost; host.innerHTML = '';
  await invDomainPicker(host, seq);
  if (seq !== invCtl.seq || !invCtl.domainId) return;
  let types = [];
  try { types = (await api('/api/v1/qradar/log-source-types?domain_id=' + encodeURIComponent(invCtl.domainId))).log_source_types || []; }
  catch (e) { hwMuted(host, hwErrText(e)); return; }
  if (seq !== invCtl.seq) return;
  host.appendChild(escEl('div', 'DSMs and QIDs / native event identifiers', 'paneltitle')).style.margin = '14px 0 8px';
  if (!types.length) hwMuted(host, 'No DSM type. Add one under Log Sources.');
  let sources = [];
  if (types.length) { try { sources = (await api('/api/v1/qradar/log-sources?log_source_type_id=' + encodeURIComponent(types[0].log_source_type_id))).log_sources || []; } catch (_) {} }
  if (seq !== invCtl.seq) return;
  if (sources.length) {
    let qids = [];
    try { qids = (await api('/api/v1/qradar/qids?log_source_id=' + encodeURIComponent(sources[0].log_source_id))).qradar_qids || []; } catch (_) {}
    if (qids.length) host.appendChild(hwTable(['Event', 'Native event id'], qids.map(q => [q.event_name, q.native_event_id || '—'])));
    else hwMuted(host, 'No QID recorded for this log source.');
    if (invCanEdit()) {
      let ev = '', nid = '';
      const row = document.createElement('div'); row.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;margin-top:8px';
      row.append(invField('Event name', '', v => ev = v), invField('Native event identifier', '', v => nid = v));
      host.appendChild(row);
      host.appendChild(hwButton('Add QID', 'small', async () => {
        try { await api('/api/v1/qradar/qids', { method: 'POST', body: { log_source_id: sources[0].log_source_id, event_name: ev.trim(), native_event_id: nid.trim() } }); invCtl.seq++; renderInventoryWorkspace(); }
        catch (e) { hwNotify(hwErrText(e), 'error'); }
      }));
    }
  } else hwMuted(host, 'A QID needs a declared log source; none exists for the first DSM type.');
}

async function invCustomProps(shell, seq) {
  const host = shell.listHost; host.innerHTML = '';
  await invDomainPicker(host, seq);
  if (seq !== invCtl.seq || !invCtl.domainId) return;
  let defs = [];
  try { defs = (await api('/api/v1/qradar/field-definitions?client_id=' + encodeURIComponent(invCtl.client) + '&domain_id=' + encodeURIComponent(invCtl.domainId))).field_definitions || []; }
  catch (e) { hwMuted(host, hwErrText(e)); return; }
  if (seq !== invCtl.seq) return;
  host.appendChild(escEl('div', 'Raw field definitions and custom properties', 'paneltitle')).style.margin = '14px 0 8px';
  if (!defs.length) hwMuted(host, 'No field definition.');
  else host.appendChild(hwTable(['Field', 'Origin', 'Type', 'CEP', 'AQL expression'], defs.map(d => [d.field_name, d.field_origin, d.data_type || '—', d.cep_identifier || '—', d.aql_field_expression || '—'])));
  if (invCanEdit()) {
    let name = '', origin = 'custom', dtype = '', cep = '';
    const row = document.createElement('div'); row.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;margin-top:8px';
    row.append(invField('Field name', '', v => name = v), invField('Origin (custom/system/normalized/raw_only)', origin, v => origin = v),
      invField('Data type', '', v => dtype = v), invField('CEP identifier', '', v => cep = v));
    host.appendChild(row);
    host.appendChild(hwButton('Add definition', 'small', async () => {
      try { await api('/api/v1/qradar/field-definitions', { method: 'POST', body: { client_id: invCtl.client, domain_id: invCtl.domainId, field_name: name.trim(), field_origin: origin.trim(), data_type: dtype.trim(), cep_identifier: cep.trim(), supported_event_scope: '', aql_field_expression: cep.trim() } }); invCtl.seq++; renderInventoryWorkspace(); }
      catch (e) { hwNotify(hwErrText(e), 'error'); }
    }));
  }
}

async function invMappings(shell, seq) {
  const host = shell.listHost; host.innerHTML = '';
  await invDomainPicker(host, seq);
  if (seq !== invCtl.seq || !invCtl.domainId) return;
  let maps = [];
  try { maps = (await api('/api/v1/qradar/field-mappings?client_id=' + encodeURIComponent(invCtl.client) + '&domain_id=' + encodeURIComponent(invCtl.domainId))).field_mappings || []; }
  catch (e) { hwMuted(host, hwErrText(e)); return; }
  if (seq !== invCtl.seq) return;
  host.appendChild(escEl('div', 'Candidate and approved mappings', 'paneltitle')).style.margin = '14px 0 8px';
  if (!maps.length) hwMuted(host, 'No mapping.');
  else host.appendChild(hwTable(['Raw field', 'CEP', 'DSM', 'Event', 'Ver', 'Source', 'Approved by', ''], maps.map(m => [
    m.raw_source_field, m.target_cep_field, m.applicable_dsm || '—', m.applicable_event || '—', m.mapping_version,
    m.source_category || m.origin || '—', m.approved_by || '—',
    m.approved_by ? '—' : (invCanReview() ? hwButton('Review', 'small', () => invApproveMapping(m.mapping_id, host)) : 'needs reviewer')
  ])));
  if (invCanEdit()) {
    let raw = '', cep = '', dsm = '', ver = '1';
    const row = document.createElement('div'); row.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;margin-top:8px';
    row.append(invField('Raw source field', '', v => raw = v), invField('Target CEP field', '', v => cep = v),
      invField('Applicable DSM', '', v => dsm = v), invField('Version', ver, v => ver = v));
    host.appendChild(row);
    host.appendChild(hwButton('Add candidate mapping', 'small', async () => {
      try { await api('/api/v1/qradar/field-mappings', { method: 'POST', body: { client_id: invCtl.client, domain_id: invCtl.domainId, raw_source_field: raw.trim(), target_cep_field: cep.trim(), semantic_alias: '', applicable_dsm: dsm.trim(), applicable_event: '', mapping_version: ver.trim(), origin: 'manual' } }); invCtl.seq++; renderInventoryWorkspace(); }
      catch (e) { hwNotify(hwErrText(e), 'error'); }
    }));
  }
}

async function invApproveMapping(mappingId, host) {
  const evidence = prompt('Reviewer evidence (at least 12 characters). Approval is manual and never implies a QRadar query ran.');
  if (!evidence) return;
  try { await api('/api/v1/qradar/field-mappings/' + encodeURIComponent(mappingId) + '/approve', { method: 'POST', body: { evidence } }); invCtl.seq++; renderInventoryWorkspace(); }
  catch (e) { hwNotify(hwErrText(e), 'error'); }
}

async function invImport(shell, seq) {
  const host = shell.listHost; host.innerHTML = '';
  await invDomainPicker(host, seq);
  if (seq !== invCtl.seq || !invCtl.domainId) return;
  const kinds = [['log_source_types', 'Log source types (DSM)'], ['log_sources', 'Log sources'],
    ['qids', 'QIDs / event identifiers'], ['field_definitions', 'Field definitions'], ['field_mappings', 'Field mappings']];
  host.appendChild(invSelect('Category', kinds.map(([v, l]) => ({ value: v, label: l })), invCtl.kind, v => { invCtl.kind = v; invCtl.preview = null; invCtl.seq++; renderInventoryWorkspace(); }));
  const t = document.createElement('div'); t.style.margin = '8px 0';
  t.appendChild(escEl('span', 'Template: ', 'text-muted'));
  const a = document.createElement('a'); a.href = '/api/v1/qradar/inventory/import-templates/' + encodeURIComponent(invCtl.kind); a.textContent = invCtl.kind + '.csv'; a.setAttribute('download', '');
  a.style.color = 'var(--mint)'; t.appendChild(a);
  host.appendChild(t);

  let format = 'csv', source = '', content = '';
  const srow = document.createElement('div'); srow.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap';
  srow.append(invField('Format (csv or json)', 'csv', v => format = v), invField('Declared source (export name/ticket)', '', v => source = v));
  host.appendChild(srow);
  const ta = document.createElement('textarea'); ta.rows = 8; ta.placeholder = 'Paste CSV or JSON here';
  ta.setAttribute('aria-label', 'Import content');
  ta.style.cssText = 'width:100%;background:#0c1624;border:1px solid var(--line);border-radius:8px;color:var(--text);padding:9px;font-family:monospace;margin:8px 0';
  ta.addEventListener('input', () => content = ta.value);
  host.appendChild(ta);
  host.appendChild(hwButton('Preview (dry run)', 'primary small', async () => {
    try {
      invCtl.preview = await api('/api/v1/qradar/inventory/import/preview', { method: 'POST',
        body: { client_id: invCtl.client, domain_id: invCtl.domainId, kind: invCtl.kind, format: format.trim(), content, declared_source: source.trim() } });
      invCtl.seq++; renderInventoryWorkspace();
    } catch (e) { hwNotify(hwErrText(e), 'error'); }
  }));
  if (invCtl.preview) host.appendChild(invPreviewPanel(invCtl.preview));
}

function invPreviewPanel(p) {
  const box = document.createElement('div'); box.className = 'note'; box.style.marginTop = '12px';
  box.appendChild(escEl('div', 'Preview · ' + p.kind + ' · ' + p.format, 'paneltitle'));
  const s = p.summary || {};
  box.appendChild(escEl('div', 'rows ' + (s.rows || 0) + ' · create ' + (s.create || 0) + ' · duplicate ' + (s.duplicate || 0) +
    ' · conflict ' + (s.conflict || 0) + ' · error ' + (s.error || 0), 'text-muted'));
  if (p.conflicts && p.conflicts.length) p.conflicts.forEach(c => box.appendChild(escEl('div', '⚠ ' + c, 'text-muted')));
  box.appendChild(hwTable(['Line', 'Status', 'Detail'], (p.rows || []).slice(0, 200).map(r => [r.line, r.status, r.message || ''])));
  (p.notes || []).forEach(n => box.appendChild(escEl('div', n, 'text-muted')));
  if ((s.conflict || 0) === 0 && (s.error || 0) === 0 && (s.create || 0) > 0 && invCanEdit()) {
    box.appendChild(hwButton('Commit ' + s.create + ' new row(s)', 'primary small', async () => {
      try {
        await api('/api/v1/qradar/inventory/import/commit', { method: 'POST',
          body: { client_id: p.client_id, domain_id: p.domain_id, kind: p.kind, format: p.format,
            content: document.querySelector('textarea[aria-label="Import content"]').value,
            declared_source: p.declared_source, dry_run: false, confirm: true } });
        invCtl.preview = null; hwNotify('Import committed. Values are IMPORTED_UNVERIFIED and require review.'); invCtl.seq++; renderInventoryWorkspace();
      } catch (e) { hwNotify(hwErrText(e), 'error'); }
    }));
  } else if ((s.conflict || 0) > 0) hwMuted(box, 'Conflicts block the whole import; nothing will be written.');
  return box;
}

async function invGaps(shell, seq) {
  const host = shell.listHost; host.innerHTML = '';
  host.appendChild(escEl('div', 'Loading completeness…', 'statebox'));
  let report;
  try { report = await api('/api/v1/qradar/inventory/completeness?client_id=' + encodeURIComponent(invCtl.client)); }
  catch (e) { if (seq === invCtl.seq) hwStateBox(host, hwErrText(e)); return; }
  if (seq !== invCtl.seq) return;
  host.innerHTML = '';
  if (!(report.domains || []).length) { hwStateBox(host, 'No client-bound domain. Confirm a native Domain ID first.'); return; }
  report.domains.forEach(d => {
    const box = document.createElement('div'); box.className = 'note';
    box.appendChild(escEl('div', d.domain_name + ' · native ' + (d.native_qradar_domain_id || '—') + ' · binding ' + d.binding_status + ' · rev ' + d.binding_revision, 'paneltitle'));
    box.appendChild(hwTable(['Area', 'Status', 'Count', 'Detail'], (d.areas || []).map(a => {
      const row = [a.entity, '', String(a.count || 0), a.detail || ''];
      const td = hwBadge(a.status, invStatusTone(a.status));
      return [a.entity, td, String(a.count || 0), a.detail || ''];
    })));
    host.appendChild(box);
  });
  (report.notes || []).forEach(n => hwMuted(host, n));
}
