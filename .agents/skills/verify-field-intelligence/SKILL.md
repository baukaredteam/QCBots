---
name: verify-field-intelligence
description: "Project-local browser verification for the Sentinel Atlas Field Intelligence screen (v3 #fields): open the tab with an authorized client, check honest errors and empty states, verify the Threat Intel Links crosswalk and NOT VERIFIED labels, and confirm no Threadlinqs calls or fabricated metrics. Use when reviewing the Field Intelligence design or the v3 Field Intelligence view; verdicts follow docs/VERIFICATION_CONTRACT.md."
disable-model-invocation: true
---

# Verify Field Intelligence

Surface: the v3 web UI at `/v3/index.html#fields`, served by the Go backend from `frontend/`. Primary harness: the OpenMausBot mounted Browser using the installed agent-browser 0.41.2 snapshot/ref workflow; the repo also ships a Playwright acceptance harness in `tests/browser`.

Authored at `e70de881fe1e143ce115e0e216f632035b094a6c` (PR #1–#8 merged). Current code revision for the Threat Intel Links static proof: `e3cacbdaf807936d5e7eac95a1ede8fb7683e9f3` (PR #9 merged).

All three browser scenarios are NOT VERIFIED. No live authenticated backend session was available during the interview (`curl` probes returned HTTP 000 with curl exits 7 and 52 — see `evidence/2026-11-17-preflight/`). No browser exit codes or page results have been invented. The Threat Intel Links tab was absent at the authored baseline but exists in source at `e3cacbd`; a real `grep` proof is in `evidence/2026-11-17-threat-links-static/`, and the browser scenario is still NOT VERIFIED.

`docs/FIELD_INTELLIGENCE_DESIGN.md` and `config/imports/2026-07-11/field_intelligence_concept_v4.html` are DESIGN ONLY (synthetic). They are design references, not evidence of telemetry, QRadar connectivity, client data, or Threadlinqs calls.

## Interview (observed facts, not assumptions)

- Navigation: `frontend/v3/v3.js` line 7 defines the `fields` route with label `Field Intelligence`; `frontend/v3/hunt-workspace.js` line 698 has an `Open Field Intelligence` button that navigates to `fields`.
- Field view (`frontend/v3/v3.js` lines 328–489): selects with ARIA labels `Client`, `QRadar instance`, `QRadar domain`, `Log source type`, `Log source`, `Event`, plus a `Search` input. The global client context is `#tenant` (ARIA label `Client context`). Client options come from `me.authorized_clients`; the client select placeholder is `Select authorized client…`.
- Tabs: `Event Catalog`, `Field Registry`, `Auto Import`, `Mapping Inspector`, `Hunt Readiness`, plus `Domain Bindings` for `ADMINISTRATOR`. `Threat Intel Links` was absent at `e70de881`; at `e3cacbd` (PR #9) `frontend/v3/v3.js` line 376 declares `['threat-links', 'Threat Intel Links']` and line 407 renders the crosswalk (`DESIGN ONLY`, `Threadlinqs live PoC: NOT VERIFIED`). Verified statically with `grep -n "threat-links" frontend/v3/v3.js` (exit 0) — see `evidence/2026-11-17-threat-links-static/`. Static proof is not a browser run.
- Client-scoped requests: `/api/v1/qradar/field-definitions?client_id=…&domain_id=…`, `/api/v1/qradar/field-mappings?…`, `/api/v1/qradar/field-observations?…`, `/api/v1/qradar/import-batches?client_id=…`, and cascading instance/domain/type/source/QID endpoints.
- Honest empty/error states live in `.statebox`: `Select an authorized client to load the QRadar hierarchy.`, `No rows for this selection. An absent row means "not recorded", not "does not exist in QRadar".`, and status texts for 403/404/400/503/network failures. Field rows carry `UNVERIFIED` or `AQL VERIFIED (manual)` badges; presence alone never means AQL VERIFIED.
- No Threadlinqs request exists in `frontend/v3`; the only frontend mention is a prototype (`frontend/prototypes/v2/intelligence-hub.html`) labelled approval pending and unverified. Counts shown by the view are derived from loaded inventory arrays, not from a hardcoded demo metric.
- Backend launch: `cd backend`, `CGO_ENABLED=1`, `WORKBENCH_DB_PATH`, `WORKBENCH_PORT`, `WORKBENCH_ORIGIN` (`backend/config.go` lines 61–64); static files are served from `../frontend` (`backend/main.go` lines 983–1030). Disposable seeding: `go run . seed-hunt-acceptance <db>` with `SENTINEL_ACCEPTANCE_DIR` and `SENTINEL_ENABLE_TEST_SEEDERS=1` (`tests/browser/acceptance.test.mjs` lines 121–140).
- Repo harness: `cd tests/browser && npm ci && npm test` (`package.json` runs `node --test --test-concurrency=1 acceptance.test.mjs`) drives the Hunt Workspace, not this screen; record it separately, not as Field Intelligence proof.
- Browser tool: `agent-browser --version` → `agent-browser 0.41.2`; `agent-browser skills get core` returns the version-matched snapshot/ref guide; `agent-browser session id --scope worktree --prefix qa-sentinel` yields a worktree-scoped CLI session name. The mounted Browser surface cannot accept that name, so CLI session isolation is NOT VERIFIED and must be reported, not claimed.

## Launch

Create an isolated worktree; do not switch the shared checkout's HEAD:

```
git worktree add --detach <run-dir> e3cacbdaf807936d5e7eac95a1ede8fb7683e9f3
```

Use the current code revision so the Threat Intel Links tab is present. The preflight environment probes were taken at the authored baseline `e70de881`.

Seed a disposable SQLite database and serve the app from the run worktree:

```
cd <run-dir>/backend
SENTINEL_ENABLE_TEST_SEEDERS=1 SENTINEL_ACCEPTANCE_DIR=<tmp> CGO_ENABLED=1 go run . seed-hunt-acceptance <tmp>/field-intel.db
WORKBENCH_DB_PATH=<tmp>/field-intel.db WORKBENCH_PORT=<port> WORKBENCH_ORIGIN=http://127.0.0.1:<port> CGO_ENABLED=1 go run .
```

Ready means an authenticated session exists: `/api/v1/auth/me` returns 200 with `authorized_clients`, the `#tenant` select offers an authorized client, and the `Field Intelligence` nav link is present. A 401/403/404 from `/api/v1/auth/me` is an environment blocker (see `docs/BROWSER_SMOKE_TEST.md`), not a product FAIL; leave the scenarios NOT VERIFIED.

## Doctor

Before driving, record:

```
agent-browser --version
agent-browser skills get core
agent-browser session id --scope worktree --prefix qa-sentinel
cd <run-dir>/backend && go env CGO_ENABLED CC GOOS GOARCH
curl.exe -s -o NUL -w "%{http_code}" http://127.0.0.1:<port>/api/v1/auth/me
```

Doctor fails closed unless the auth probe is 200 and the browser tool is available. Recorded preflight values were `agent-browser 0.41.2`, probe HTTP 000 (curl exits 7 / 52 on ports 8080, 4174, 4173); therefore Doctor was not ready and no browser scenario was driven.

## Drive

Use the mounted Browser surface for all page actions. Follow the agent-browser core loop: `agent_browser_open` the authorized URL, use the returned refs (or a new `agent_browser_snapshot`), click/select/fill stable handles, snapshot again to observe changed content, save a screenshot, collect whatever console/page errors the surface reports, then `agent_browser_close`. If CLI actions are permitted, pass the worktree-scoped session name on every command; otherwise report that limitation.

Stable handles from this repo: nav link text `Field Intelligence`; `#tenant` (`aria-label="Client context"`); selects with ARIA labels `Client`, `QRadar instance`, `QRadar domain`, `Log source type`, `Log source`, `Event`; tab buttons `Event Catalog`, `Field Registry`, `Auto Import`, `Mapping Inspector`, `Hunt Readiness`, `Threat Intel Links` (present from `e3cacbd`), `Domain Bindings` (admin only); `.statebox` for honest error/empty states; `UNVERIFIED` / `AQL VERIFIED (manual)` badges. Do not drive the DESIGN ONLY concept HTML as if it were the app.

Capture, per action: the ref and action, resulting visible text, any request/response observation, screenshot, and console/page errors reported by the surface. Browser actions return structured results, not shell exit codes: record exit as N/A, never 0.

## Evidence

For each real run create `.agents/skills/verify-field-intelligence/evidence/<utc-run-id>/` with `command.txt`, `actions.md` (action/ref/observed state), screenshot PNG, reported console/page errors, probes and any process exit codes. Use REAL PASS / FAIL / NOT VERIFIED from docs/VERIFICATION_CONTRACT.md. A blocked environment is NOT VERIFIED; a broken assertion in a correctly provisioned environment is FAIL. `evidence/2026-11-17-preflight/` holds the real preflight commands and exit codes collected here; it establishes only that no live backend was available, not any product behavior. `evidence/2026-11-17-threat-links-static/` holds the real `grep -n "threat-links" frontend/v3/v3.js` proof (exit 0) at `e3cacbd`; it proves source presence only, not a rendered browser scenario.

## Cleanup

Close the task browser, stop only the server process started for this run, delete the disposable DB and worktree, and keep the evidence. Never kill by process name, never edit staged evidence or trusted inventory to make a scenario pass, and never use a mocked backend or fabricated credentials.

## Helpers

No helper script ships with this skill. Real commands available in this repo/toolchain: `git worktree add --detach`, `go run . seed-hunt-acceptance <db>`, `go run .` with `WORKBENCH_*` variables, `npm ci` and `npm test` in `tests/browser`, `curl.exe` auth probe, `agent-browser --version`, `agent-browser skills get core`, `agent-browser session id --scope worktree --prefix qa-sentinel`.

## Feature map

- `features/README.md` — index and current verdicts.
- `features/field-intelligence-client-errors.md` — open the tab, choose an authorized client, verify honest errors/empty states.
- `features/threat-intel-links-crosswalk.md` — Threat Intel Links crosswalk and NOT VERIFIED labels.
- `features/no-threadlinqs-no-fake-metrics.md` — no Threadlinqs calls and no fabricated metrics.
