# Sentinel Atlas — Frontend v3 Baseline + M7 Gap Analysis & Architecture

> Status: **DESIGN ONLY (READ-ONLY)** — no Go, frontend, SQLite, migration, MCP or Evidence Graph changes were made to produce this document. M7 implementation must not begin until explicitly approved.
> Date: 2026-11-08. Authoritative inputs: `frontend/v3/*`, `backend/*.go`, `migrations/0001–0005`, live read-only inspection of `storage/workbench.db` (mode=ro) and isolated `stagef.db`.

---

## STAGE 1 — BASELINE

### 1.1 Frozen state

| Layer | State |
|---|---|
| Backend | Go (single binary). M6 Research Case Workspace complete. QRadar deadlock fixed and tests green (`go build/vet/test` PASS, race PASS). |
| Frontend v3 | AppShell + 17 hash routes, frozen as approved UI baseline. Design source: `sentinel-atlas-final.html` (not in repo; tokens extracted to `frontend/v3/design-tokens.css`: midnight navy `#080e19/#101b2b`, mint `#53d5ba`, sidebar 244px / icon rail ≤1200px, topbar 70px). |
| Auth | Cookie-session + CSRF (double-submit + Origin via `frontend/api.js`), no tokens in storage. RBAC backend-authoritative. |
| Working DB `storage/workbench.db` | **Untouched.** Read-only check (see 1.4). |

### 1.2 Implemented / Partial / Design-only (17 routes)

**Implemented (real APIs, browser E2E verified):**
`#home` (Home: cases/actions/per-case review sample/CTI updates/activity), `#feed` + `#reports` (Intelligence Hub: per-client reports, inspector, analyze-POST, case create — *not linked*), `#cases` (list/create, idempotency, pagination), `#case` (workspace: tabs, lifecycle, participants, artifact/hypothesis review, notes, activity, investigations), `#qradar` (Rules/Building Blocks/Custom Fields + inspectors), `#hypotheses` (list/select/linked-case search), `#detection` (MITRE/log-source/telemetry with honest coverage model), `#clients` (grant-filtered list + telemetry).

**Partial:**
- `#reviews` Review Queue — no backend aggregation (queue cannot be reliably computed; `review_decision` not exposed via GET) — honest limitation only, no fabricated tasks.
- `#detection` / `#clients` — sector, technology, relevance score, field verification, detection validation: **Not available / not verified** (no endpoints).
- `#mywork` — derived from role/grants only; no assignment API.

**Design-only (honest placeholder + honest "BACKEND-GAP" statement):**
`#entities` (no Threat Entities API), `#hunt` (no SIEM execution API), `#fields` (no per-client Field Intelligence Lab API), `#investigations` (no global list; per-case investigations live inside `#case`), `#graph` (no Evidence Graph HTTP API wired), `#settings` (no Settings API).

### 1.3 Regression evidence (as of freeze)

- `go build ./...` PASS; `go vet ./...` PASS; `go test -timeout 600s -count=1 ./...` PASS (ok ~114s); targeted `go test -race` PASS.
- V3-F6/F7 browser E2E (CDP Chromium, isolated `stagef.db`): 16 terminal screenshots at 1280/1440/1600/1920 (all settled, no Loading…, no exceptions), security suite: beta→alpha 403 (reports/telemetry), hypothesis zero-leak, stale-token passes, no legacy tokens in v3 JS, cookie-session + CSRF live.
- Live QRadar endpoints (post-fix): `rules`, `building-blocks`, `fields` → 200 (all `count=0`).

### 1.4 Working SQLite (read-only inspection, no writes)

`storage/workbench.db` (569344 bytes) opened `mode=ro`, uri=True. Findings:

- `schema_migrations`: `0001_initial.sql`, `0002_qradar_inventory` (+ legacy duplicated 0001/0002 rows from earlier seeded runs — cosmetic, not touched).
- **M6 tables absent**: `case_activity`, `case_artifacts`, `case_hypotheses`, `user_authorized_clients` — **not present** (therefore `research_cases` etc. live in M6 only on isolated test DBs).
- Present with data: `cti_reports`=3, `users`=3. Present empty: `indicators`, `techniques`, `cves`, `threat_actors`, `campaigns`, `malware`, `hunt_hypotheses`, `detection_rules`, `building_blocks`, `global_fields`, `client_*`.
- No synthetic writes performed; file mtime unchanged by this task.

### 1.5 Honesty caveat (explicit)

**QRadar Inventory has not been verified against a real non-empty ruleset.** In the isolated test DB all QRadar tables are empty; UI shows honest Empty states. Endpoints return 200 with real (empty) data, but rendering of populated rules/BBs/fields is **NOT VERIFIED** against real inventory data.

---

## STAGE 2 — M7 GAP ANALYSIS

### Existing inventory used as basis

| Domain | Existing tables (working DB / isolated DB) | Existing HTTP APIs | Missing |
|---|---|---|---|
| CTI extraction | `cti_reports`, `indicators`, `techniques`, `cves`, `threat_actors`, `campaigns`, `malware`, `cti_claims` | `GET /tenants/{id}/cti/reports`, `GET /cti/reports/{id}[/iocs\|/ttps\|/cves\|/evidence]`, `POST /cti/reports/{id}/analyze` | dedup/normalization, report status machine |
| Evidence Graph | `evidence_entities`, `evidence_graph_edges`, `evidence_references`, `evidence_graph_reviews`, `evidence_edge_history`, `global_publication_queue` | none wired to v3 (plausibly via MCP/direct)` | HTTP API for v3 page; provenance linking to reports/cases |
| Research Cases (M6) | `research_cases`, `case_authorized_participants`, `case_artifacts`, `case_hypotheses`, `case_notes(_revision)`, `case_activity` | full M6 CRUD (cases/participants/reviews/notes/activity/investigations) | **report link** |
| Hypotheses | `hunt_hypotheses`, `hypothesis_evidence`, `hypothesis_reviews`, `investigations`, `investigation_evidence`, `investigation_feedback` | `GET /api/v1/hypotheses`, `POST /cases/{id}/hypotheses` (link), review endpoints | generation API (authoring), `client_id` scoping exists in table |
| Tenant isolation | `user_authorized_clients`, `client_sector_mapping`, `client_technologies` | grant-filtered list endpoints (`/clients`, `/hypotheses`, `/telemetry?X-Client-ID`) | — |
| QRadar Inventory | `detection_rules`, `building_blocks`, `rule_building_blocks`, `global_fields`, `field_mappings`, `rule_field_requirements`, `mitre_mappings` | `/qradar/rules[/{id}]`, `/qradar/building-blocks[/{id}]`, `/qradar/fields`, `/inventory/{rules,fields,telemetry}` | real data (seed empty); field telemetry verification endpoint |

### M7 architecture (A–D)

#### A. CTI ingestion and provenance — **Extend** (no new tables except where noted)

- **Tables**: *Existing* (`cti_reports`, `cti_sources`, extraction tables). *New (minimal)*: `cti_ingestion_runs` (run_id, client_id, source_id, started_at, finished_at, status, artifact_id, checksum, actor) — one table suffices; provenance already partially present via `original_content_ref`+`checksum`+`file_artifacts`. Do not duplicate `indicators` etc. — extend extraction dedup (normalize `indicator_value`, lowercase/type-stable).
- **Go services**: `IngestionService` (file import + checksum + `extractFromJSON/HTML` reuse), provenance writer; no new harness dependency.
- **API contracts (new, minimal)**:
  - `POST /api/v1/cti/import` (exists) — add idempotency_key header.
  - `GET /api/v1/cti/reports/{id}/provenance` (new) — returns source, artifact checksum, ingestion run, analysis status.
- **Frontend**: Hub Inspector shows provenance block (already partially) — no new page.
- **Tenant isolation**: `CanAccessClient` per endpoint (exists); ingestion run scoped to `client_id`.
- **Provenance/confidence**: every indicator/trick row carries `source_reference` + computed `confidence` enum; display "Not verified" when absent.
- **Negative/security tests**: cross-client report fetch 403, import without CreateCTI 403, tampered checksum rejected, idempotent import same-file → same report_id.
- **Risks**: parser coverage (JSON/HTML only), extraction false positives.

#### B. Report-to-Research-Case relationships — **New (one junction table)**

- **Tables**: *New* `case_cti_reports (case_id, report_id, linked_by, linked_at, PRIMARY KEY(case_id, report_id))` — FK to M6 `research_cases` + `cti_reports`. No new IOC/Case/Evidence models.
- **Go services**: `CaseReportLinkService` (Link/Unlink, idempotent, permission `CanCreateCTI` + client grant for both case and report).
- **API contracts (new)**:
  - `GET /api/v1/cases/{id}/cti-reports` — linked reports (client-grant-filtered).
  - `POST /api/v1/cases/{id}/cti-reports` (link), `DELETE .../{report_id}` (unlink, idempotent).
  - `GET /api/v1/cti/reports/{id}/cases` — reverse lookup (grant-filtered).
- **Frontend**: extend Case Workspace CTI tab (currently "backend gap") + Hub "Link to case" button (replaces create-unlinked semantics; keep create for new cases).
- **Tenant isolation**: link requires grant on BOTH endpoints; GLOBAL case metadata ≠ CLIENT content access (M6 semantics preserved).
- **Provenance/confidence**: junction carries linked_by/at; display as `linked (by user, at time)`, not as "detected" claims.
- **Negative/security tests**: link to report outside grant → 403; link same pair twice → idempotent 200; delete non-existent link → 200 no-op; cross-client report never appears in other client's listings.
- **Risks**: over-linking noise without review workflow — mitigate by append-only activity (`case_activity`).

#### C. Client relevance assessment — **Extend** (no new client model)

- **Tables**: *Existing* (`client_sector_mapping`, `client_technologies`, `client_log_source_status`, `det
...[truncated 6158 chars]