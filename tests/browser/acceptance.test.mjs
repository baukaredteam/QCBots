// Reproducible Hunt Workspace acceptance.
//
// Starts a disposable Go server (seeded synthetic SQLite inside an authorized
// temp directory), drives the real v3 UI with system Chrome through
// playwright-core, and asserts the security behaviours of Phase 2B-4B.
//
// Run:  cd tests/browser && npm install && npm test
// Env:  CHROME_PATH (optional), GO_EXE (optional), ACCEPTANCE_KEEP=1 to keep temp.

import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, readdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { chromium } from 'playwright-core';

const repoRoot = path.resolve(import.meta.dirname, '..', '..');
const backendDir = path.join(repoRoot, 'backend');
const shotsDir = path.join(repoRoot, 'frontend', 'v3', 'shots');
const GO = process.env.GO_EXE || 'go';

let tmpDir, server, browser, context, page, base, serverLog = '';

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

async function waitHealthy(url, attempts = 120) {
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch (_) { /* not ready yet */ }
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error('server did not become healthy\n' + serverLog);
}

function findChrome() {
  if (process.env.CHROME_PATH && existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  const candidates = [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    path.join(process.env.LOCALAPPDATA || '', 'Google', 'Chrome', 'Application', 'chrome.exe'),
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
  ].filter(Boolean);
  for (const c of candidates) if (existsSync(c)) return c;
  // Playwright's own Chromium cache.
  const cache = path.join(process.env.LOCALAPPDATA || '', 'ms-playwright');
  if (existsSync(cache)) {
    for (const name of readdirSync(cache)) {
      if (!name.startsWith('chromium-')) continue;
      for (const rel of ['chrome-win\\chrome.exe', 'chrome-linux\\chrome', 'chrome-mac\\Chromium.app\\Contents\\MacOS\\Chromium']) {
        const p = path.join(cache, name, rel);
        if (existsSync(p)) return p;
      }
    }
  }
  throw new Error('no Chrome/Chromium found; set CHROME_PATH');
}

async function api(pathname, options = {}) {
  const headers = Object.assign({ Origin: base }, options.headers || {});
  if (options.data !== undefined) headers['Content-Type'] = 'application/json';
  return context.request.fetch(base + pathname, Object.assign({}, options, { headers }));
}

// One real login per user; later switches restore the captured cookie set. This
// keeps the server's login rate limit untouched and makes the suite fast.
const sessions = {};

async function asUser(key, username, password, clientId) {
  await context.clearCookies();
  if (!sessions[key]) {
    const res = await api('/api/v1/auth/login', { method: 'POST', data: { username, password, client_id: clientId } });
    assert.equal(res.status(), 200, `login failed for ${username}`);
    sessions[key] = await context.cookies();
  }
  await context.addCookies(sessions[key]);
}

async function openWorkspace(query) {
  await page.goto(`${base}/v3/index.html#hunt?${query}`);
  await page.reload();
  await page.waitForSelector('h1', { timeout: 15000 });
  await page.waitForFunction(() => document.querySelector('#content')?.innerText.includes('Hunt Workspace'));
  await page.waitForSelector('.v3layout', { timeout: 15000 });
}

async function planList() {
  return page.evaluate(async () => {
    const r = await fetch('/api/v1/hunt-plans?client_id=client-alpha');
    return (await r.json()).plans || [];
  });
}

async function waitPlan(title, predicate, label) {
  for (let i = 0; i < 60; i++) {
    const p = (await planList()).find(x => x.title === title);
    if (p && predicate(p)) return p;
    await new Promise(r => setTimeout(r, 250));
  }
  throw new Error('timed out waiting for plan state: ' + label);
}

async function shot(name) {
  await page.screenshot({ path: path.join(shotsDir, name), fullPage: false });
}

before(async () => {
  tmpDir = mkdtempSync(path.join(tmpdir(), 'sentinel-hw-'));
  const dbPath = path.join(tmpDir, 'acceptance.db');
  const seed = spawnSync(GO, ['run', '.', 'seed-hunt-acceptance', dbPath], {
    cwd: backendDir,
    env: Object.assign({}, process.env, { SENTINEL_ACCEPTANCE_DIR: tmpDir, SENTINEL_ENABLE_TEST_SEEDERS: '1', CGO_ENABLED: '1' }),
    encoding: 'utf8',
    timeout: 300000
  });
  if (seed.status !== 0) throw new Error(`seed failed (${seed.status})\n${seed.stdout}\n${seed.stderr}`);

  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  // The server env deliberately does not inherit test-seeding switches: the
  // opt-in belongs only to the disposable seeding subprocess above.
  const serverEnv = Object.assign({}, process.env, {
    WORKBENCH_DB_PATH: dbPath,
    WORKBENCH_PORT: String(port),
    WORKBENCH_ORIGIN: base,
    CGO_ENABLED: '1'
  });
  for (const key of ['SENTINEL_ENABLE_TEST_SEEDERS', 'SENTINEL_ACCEPTANCE_DIR', 'WORKBENCH_SEED_DATA']) delete serverEnv[key];
  server = spawn(GO, ['run', '.'], {
    cwd: backendDir,
    env: serverEnv,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  server.stdout.on('data', d => { serverLog += d; });
  server.stderr.on('data', d => { serverLog += d; });
  await waitHealthy(base + '/api/v1/health');

  browser = await chromium.launch({ executablePath: findChrome(), headless: true });
  context = await browser.newContext({ baseURL: base });
  page = await context.newPage();
  page.on('dialog', d => d.dismiss());
});

after(async () => {
  try { await browser?.close(); } catch (_) {}
  if (server?.pid) {
    if (process.platform === 'win32') spawnSync('taskkill', ['/PID', String(server.pid), '/T', '/F']);
    else server.kill('SIGTERM');
  }
  if (tmpDir && !process.env.ACCEPTANCE_KEEP) {
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
  }
});

test('client isolation: Alpha sees only Alpha, Beta only Beta', async () => {
  await asUser('writer', 'analyst-multi', 'multi-pass-2026', 'client-alpha');
  await openWorkspace('section=plans&client=client-alpha');
  await page.waitForSelector('.v3layout table', { timeout: 15000 });
  const alphaOptions = await page.locator('select[aria-label="Authorized client"] option').evaluateAll(os => os.map(o => o.value));
  assert.deepEqual(alphaOptions, ['client-alpha']);
  const alphaText = await page.locator('.v3layout').innerText();
  assert.match(alphaText, /Alpha – analyst draft/);
  assert.doesNotMatch(alphaText, /client-beta|Beta Finance/);
  await shot('2b4b-h1-plans.png');

  await asUser('beta', 'analyst-beta', 'beta-pass-2026', 'client-beta');
  await openWorkspace('section=plans&client=client-beta');
  await page.waitForFunction(() => !document.querySelector('#content')?.innerText.includes('Loading'), null, { timeout: 15000 });
  const betaOptions = await page.locator('select[aria-label="Authorized client"] option').evaluateAll(os => os.map(o => o.value));
  assert.deepEqual(betaOptions, ['client-beta']);
  const betaText = await page.locator('.v3layout').innerText();
  assert.doesNotMatch(betaText, /Alpha – analyst draft/);
});

test('Sigma YAML renders as text, never as markup', async () => {
  await asUser('writer', 'analyst-multi', 'multi-pass-2026', 'client-alpha');
  await openWorkspace('section=translation&client=client-alpha');
  const rules = await page.evaluate(async () => (await (await fetch('/api/v1/detections/sigma?client_id=client-alpha')).json()).rules);
  const htmlRule = rules.find(r => (r.title || '').includes('HTML Fixture'));
  assert.ok(htmlRule, 'HTML fixture rule missing');
  await page.goto(`${base}/v3/index.html#hunt?section=translation&client=client-alpha&rule=${encodeURIComponent(htmlRule.rule_id)}`);
  await page.reload();
  await page.waitForSelector('.hwcols pre', { timeout: 15000 });
  const yamlText = await page.locator('.hwcols pre').first().innerText();
  assert.match(yamlText, /<script>alert\(1\)<\/script>/);
  assert.match(await page.locator('.v3layout').innerText(), /HTML Fixture <img src=x/);
  assert.equal(await page.locator('.v3layout script, .v3layout img').count(), 0);
});

test('AQL draft is displayed and marked NOT EXECUTED', async () => {
  await asUser('writer', 'analyst-multi', 'multi-pass-2026', 'client-alpha');
  await openWorkspace('section=translation&client=client-alpha');
  const rules = await page.evaluate(async () => (await (await fetch('/api/v1/detections/sigma?client_id=client-alpha')).json()).rules);
  const ready = rules.find(r => r.title === 'Windows Logon Success');
  assert.ok(ready, 'ready rule missing');
  await page.goto(`${base}/v3/index.html#hunt?section=translation&client=client-alpha&rule=${encodeURIComponent(ready.rule_id)}`);
  await page.reload();
  await page.waitForSelector('.hw-aql', { timeout: 15000 });
  const aql = await page.locator('.hw-aql').innerText();
  assert.match(aql, /domainid=5/);
  assert.match(aql, /LAST 7 DAYS/);
  const text = await page.locator('.v3layout').innerText();
  assert.match(text, /NOT EXECUTED/);
  assert.equal(await page.getByRole('button', { name: 'Copy AQL' }).count(), 1);
  await shot('2b4b-h2-translation.png');
});

test('DRAFT -> IN_REVIEW -> APPROVED with evidence', async () => {
  await asUser('writer', 'analyst-multi', 'multi-pass-2026', 'client-alpha');
  await openWorkspace('section=translation&client=client-alpha');
  const rules = await page.evaluate(async () => (await (await fetch('/api/v1/detections/sigma?client_id=client-alpha')).json()).rules);
  const ready = rules.find(r => r.title === 'Windows Logon Success');
  await page.goto(`${base}/v3/index.html#hunt?section=translation&client=client-alpha&rule=${encodeURIComponent(ready.rule_id)}`);
  await page.reload();
  await page.getByRole('button', { name: 'Attach to plan' }).waitFor({ timeout: 15000 });
  await page.waitForFunction(() => {
    const sel = document.querySelector('select[aria-label="Draft hunt plan"]');
    return sel && [...sel.options].some(o => o.value && o.textContent.includes('Alpha – analyst draft'));
  });
  const attach = page.getByRole('button', { name: 'Attach to plan' });
  await attach.click();
  await page.waitForFunction(async () => {
    const r = await fetch('/api/v1/hunt-plans?client_id=client-alpha');
    const d = await r.json();
    return d.plans.some(p => p.title === 'Alpha – analyst draft' && (p.items || []).length === 1);
  }, null, { timeout: 15000 });

  await openWorkspace('section=plans&client=client-alpha');
  const draftRow = page.locator('tr', { hasText: 'Alpha – analyst draft' }).first();
  await draftRow.getByRole('button', { name: 'Open' }).click();
  await page.getByRole('button', { name: 'Submit for review' }).waitFor({ timeout: 15000 });
  await page.getByRole('button', { name: 'Submit for review' }).click();
  await waitPlan('Alpha – analyst draft', p => p.status === 'IN_REVIEW', 'submit');
  assert.equal(await page.getByRole('button', { name: 'Approve (reviewed draft)' }).count(), 0);

  await asUser('reviewer', 'reviewer', 'reviewer-pass-2026', 'client-alpha');
  await openWorkspace('section=review&client=client-alpha');
  const row = page.locator('tr', { hasText: 'Alpha – analyst draft' }).first();
  await row.getByRole('button', { name: 'Review' }).click();
  await page.locator('textarea[aria-label="Review evidence"]').fill('Reviewed binding revision, mapping snapshot and attestation, ticket BT-1');
  await page.getByRole('button', { name: 'Approve (reviewed draft)' }).click();
  await waitPlan('Alpha – analyst draft', p => p.status === 'APPROVED', 'approve');
  await shot('2b4b-h3-approved.png');
});

test('unauthorized review is rejected with 403', async () => {
  await asUser('writer', 'analyst-multi', 'multi-pass-2026', 'client-alpha');
  await openWorkspace('section=plans&client=client-alpha');
  const plan = (await planList()).find(p => p.title === 'Alpha – analyst draft');
  const status = await page.evaluate(async (planId) => {
    const r = await fetch('/api/v1/hunt-plans/' + planId + '/review', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision: 'APPROVED', evidence: 'self approval attempt, ticket X' })
    });
    return r.status;
  }, plan.plan_id);
  assert.equal(status, 403);
  assert.equal(await page.getByRole('button', { name: /Approve/ }).count(), 0);
});

test('stale evidence denies approval with 409 and keeps IN_REVIEW', async () => {
  await asUser('reviewer', 'reviewer', 'reviewer-pass-2026', 'client-alpha');
  await openWorkspace('section=review&client=client-alpha');
  const row = page.locator('tr', { hasText: 'stale evidence review' }).first();
  await row.getByRole('button', { name: 'Review' }).click();
  const ev = page.locator('textarea[aria-label="Review evidence"]');
  await ev.fill('Reviewed the stale fixture deliberately, ticket BT-2');
  await page.getByRole('button', { name: 'Approve (reviewed draft)' }).click();
  await page.waitForFunction(() => document.body.innerText.includes('Conflict (409)'), null, { timeout: 15000 });
  const stale = (await planList()).find(p => p.title === 'Alpha – stale evidence review');
  assert.equal(stale.status, 'IN_REVIEW');
  await shot('2b4b-h4-stale-409.png');
});

test('approved content is immutable and a new version preserves it', async () => {
  await asUser('writer', 'analyst-multi', 'multi-pass-2026', 'client-alpha');
  await openWorkspace('section=plans&client=client-alpha');
  const approved = (await planList()).find(p => p.title === 'Alpha – analyst draft' && p.status === 'APPROVED');
  assert.ok(approved, 'approved plan missing');
  await page.goto(`${base}/v3/index.html#hunt?section=plans&client=client-alpha&plan=${approved.plan_id}`);
  await page.reload();
  await page.getByRole('button', { name: 'Create new plan version' }).waitFor({ timeout: 15000 });
  assert.equal(await page.getByRole('button', { name: /edit|save|modify/i }).count(), 0);
  await page.getByRole('button', { name: 'Create new plan version' }).click();
  const forked = await waitPlan('Alpha – analyst draft', p => p.version === 2 && p.status === 'DRAFT', 'version fork');
  assert.equal(forked.supersedes_plan_id, approved.plan_id);
  const v1 = (await planList()).find(p => p.plan_id === approved.plan_id);
  assert.equal(v1.status, 'APPROVED');
  assert.equal(v1.reviewed_by, 'user-reviewer');
  await page.waitForFunction(() => {
    const rows = [...document.querySelectorAll('.v3inspector .hist')].map(h => h.textContent);
    return rows.some(h => h.includes('v1 · APPROVED')) && rows.some(h => h.includes('v2 · DRAFT'));
  }, null, { timeout: 15000 });
  const history = await page.locator('.v3inspector .hist').allInnerTexts();
  assert.ok(history.some(h => h.includes('v1 · APPROVED')), 'history must show approved v1');
  assert.ok(history.some(h => h.includes('v2 · DRAFT')), 'history must show draft v2');
  await shot('2b4b-h5-version.png');
});

test('no execution or deployment control exists', async () => {
  await asUser('writer', 'analyst-multi', 'multi-pass-2026', 'client-alpha');
  await openWorkspace('section=translation&client=client-alpha');
  const buttons = await page.locator('button').allInnerTexts();
  assert.equal(buttons.filter(b => /execute|deploy|run query|launch/i.test(b)).length, 0);
  assert.doesNotMatch(await page.locator('body').innerText(), /VALIDATED_BY_QRADAR/);
});

test('refresh and deep links keep the selected context', async () => {
  await asUser('writer', 'analyst-multi', 'multi-pass-2026', 'client-alpha');
  await openWorkspace('section=plans&client=client-alpha');
  await page.waitForSelector('.v3layout table', { timeout: 15000 });
  const approved = (await planList()).find(p => p.title === 'Alpha – analyst draft' && p.status === 'APPROVED');
  await page.goto(`${base}/v3/index.html#hunt?section=plans&client=client-alpha&plan=${approved.plan_id}`);
  await page.reload();
  await page.waitForSelector('.v3inspector .kv', { timeout: 15000 });
  assert.match(await page.locator('.v3inspector').innerText(), /Alpha – analyst draft/);
  assert.equal(await page.locator('.tab.active').innerText(), 'Hunt Plans');

  const rules = await page.evaluate(async () => (await (await fetch('/api/v1/detections/sigma?client_id=client-alpha')).json()).rules);
  const ready = rules.find(r => r.title === 'Windows Logon Success');
  await page.goto(`${base}/v3/index.html#hunt?section=translation&client=client-alpha&rule=${encodeURIComponent(ready.rule_id)}`);
  await page.reload();
  await page.waitForSelector('.hwcols pre', { timeout: 15000 });
  assert.equal(await page.locator('.tab.active').innerText(), 'Detection Translation');
  assert.match(await page.locator('.hwcols').innerText(), /Windows Logon Success/);
});

test('inventory workspace is grant-scoped and shows completeness', async () => {
  await asUser('writer', 'analyst-multi', 'multi-pass-2026', 'client-alpha');
  await page.goto(`${base}/v3/index.html#inventory?section=gaps&client=client-alpha`);
  await page.reload();
  await page.waitForFunction(() => document.body.innerText.includes('Inventory Gaps'), null, { timeout: 15000 });
  await page.waitForSelector('.v3layout .note', { timeout: 15000 });
  const alphaText = await page.locator('.v3layout').innerText();
  assert.match(alphaText, /Alpha Corporate/);
  assert.match(alphaText, /MANUALLY_ENTERED|APPROVED_MAPPING|AQL_MANUALLY_ATTESTED/);
  assert.doesNotMatch(alphaText, /Beta Finance/);
  await shot('2b7f-inventory-gaps.png');

  await asUser('beta', 'analyst-beta', 'beta-pass-2026', 'client-beta');
  await page.goto(`${base}/v3/index.html#inventory?section=gaps&client=client-beta`);
  await page.reload();
  await page.waitForFunction(() => document.body.innerText.includes('Inventory Gaps'), null, { timeout: 15000 });
  const betaText = await page.locator('.v3layout').innerText();
  assert.doesNotMatch(betaText, /Alpha Corporate/);
});

test('manual import preview and idempotent commit through the API', async () => {
  await asUser('admin', 'admin', 'admin-pass-2026', 'client-alpha');
  await page.goto(`${base}/v3/index.html#inventory?section=import&client=client-alpha`);
  await page.reload();
  await page.waitForFunction(() => document.body.innerText.includes('Import & Preview'), null, { timeout: 15000 });
  const ids = await page.evaluate(async () => {
    const instances = (await (await fetch('/api/v1/qradar/instances?client_id=client-alpha')).json()).instances || [];
    if (!instances.length) return null;
    const domains = (await (await fetch('/api/v1/qradar/domains?instance_id=' + encodeURIComponent(instances[0].instance_id))).json()).domains || [];
    const bound = domains.find(d => d.native_qradar_domain_id === '5');
    return bound ? { domain: bound.domain_id } : null;
  });
  assert.ok(ids, 'seeded domain 5 not found');
  const call = async (path, body) => page.evaluate(async ({ path, body }) => {
    const m = document.cookie.match(/(?:^|; )csrf_token=([^;]*)/);
    const csrf = m ? decodeURIComponent(m[1]) : '';
    const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: JSON.stringify(body) });
    return { status: r.status, body: await r.json().catch(() => null) };
  }, { path, body });
  const payload = {
    client_id: 'client-alpha', domain_id: ids.domain, kind: 'log_source_types', format: 'csv',
    content: 'type_name\nBrowser Import DSM\n', declared_source: 'browser acceptance M7F-1'
  };
  const preview = await call('/api/v1/qradar/inventory/import/preview', payload);
  assert.equal(preview.status, 200);
  assert.equal(preview.body.summary.create, 1);

  const commit = await call('/api/v1/qradar/inventory/import/commit', Object.assign({}, payload, { confirm: true }));
  assert.equal(commit.status, 201);
  assert.equal(commit.body.summary.created, 1);

  const again = await call('/api/v1/qradar/inventory/import/commit', Object.assign({}, payload, { confirm: true }));
  assert.equal(again.status, 201);
  assert.equal(again.body.summary.created, 0);
  assert.equal(again.body.summary.duplicate, 1);
});
