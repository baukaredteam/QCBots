# Sentinel Atlas — M7-C Implementation Report (isolated dev only)

> Scope: M7-C Client Relevance Engine per `docs/M7_C_DESIGN.md` final invariants, in **isolated test SQLite only** (`stagef.db`). Production `storage/workbench.db` untouched.

## What was implemented

### 1) Migration 0008 (`migrations/0008_relevance.sql`, additive)
- `relevance_matching_rules` — versioned, immutable matching rules (seeded v1: sector-token, tech-token, telemetry-path).
- `relevance_assessments` — attempt history; **no document-level UNIQUE**; HTTP idempotency via partial unique index `(client_id, request_idempotency_key) WHERE NOT NULL` + `payload_fingerprint`.
- `relevance_findings` — one per (assessment, dimension), CHECK enum MATCH/NO_MATCH/UNKNOWN, **append-only triggers**.
- `relevance_evidence` — multiple rows per finding; UNIQUE `(finding_id, matched_entity_type, matched_entity_id, matching_rule_id)` so **the same entity may be explained by several rules**, each keeping provenance.
- `relevance_reviews` — append-only overrides; trigger enforces `original_verdict` equals the computed finding verdict.
- `relevance_snapshots` — **canonical source snapshot documents** (CTI evidence, inventory, rule set) persisted beside fingerprints, so historical assessments remain reconstructable after source changes.
- Triggers: tenant match (`report.client_id = assessment.client_id`), finding↔assessment existence, **evidence cross-assessment mismatch** (`trg_relevance_evidence_match` asserts finding/assessment/report/client/dimension consistency).

### 2) Go services
- `backend/relevance.go` — `AssessRelevance` (same-client-only + grant + `requireMutation`; idempotent replay; concurrent-key convergence via unique index; FAILED attempts persist with snapshots; transaction includes snapshot documents), `GetRelevanceAssessment`, `LatestCompletedAssessment`, `buildRelevanceSnapshots` (SHA-256 over stable source-row sets; JSON documents stored).
- `backend/relevance_match.go` — three independent dimensions:
  - **SECTOR** — MATCH or UNKNOWN only (NO_MATCH disabled in v1). Client with no sector rows → UNKNOWN.
  - **TECHNOLOGY** — MATCH or UNKNOWN only (NO_MATCH disabled in v1). Exact-token / exact-version matching; no semver inference; no fabricated scores/confidence.
  - **TELEMETRY** — MATCH / NO_MATCH / UNKNOWN from verified evidence only. MATCH requires **all** of: this client's `client_log_source_status` row `CONNECTED` + fresh events (≤7d) + fresh field verification (`last_checked_at` ≤7d) + every `rule_field_requirements` field (a) active in `global_fields` AND (b) named in the client's own `field_availability` (by field_id or field_name, case-insensitive). **Rule existence, global field existence, or a `CONNECTED` marker alone never yield MATCH.** Stale events or stale verification → UNKNOWN (insufficient, never proven-unavailable). Missing telemetry → UNKNOWN. Evidence JSON carries client-owned proof: `{client_id, log_source, rule, field_availability, last_checked_at}`. No deployment/validation claims.

### 2b) Acceptance-verification corrections (narrowly scoped, this acceptance pass)
1. **TELEMETRY observability gap closed** (`backend/relevance_match.go`): previously MATCH only required CONNECTED + fresh + active global field; `field_availability`/`last_checked_at` were never read. Now client-specific field evidence is mandatory for MATCH (which client owns the telemetry row via `client_id`, which log source via `log_source_type_id`, how presence was verified via `field_availability`, when via `last_checked_at`); stale verification/events → UNKNOWN. New tests: `TestM7cTeleNoClientFieldEvidenceUnknown2` (empty availability → UNKNOWN; named field → MATCH with client proof), `TestM7cTeleStaleValidationUnknown` (old `last_checked_at` → UNKNOWN).
2. **Genuine FAILED lifecycle** (`backend/relevance.go`): findings/evidence persistence errors previously rolled back the whole attempt (no FAILED row). Now any compute/persistence failure commits a FAILED attempt with `error_code` (`compute_error`/`persist_error`), zero findings, no mutation of report/M7-A/M7-B records; retry with a new key creates a distinct attempt. Test: `TestM7cGenuineFailureLifecycle` (injected aborting trigger).
3. **Review tenant binding** (`backend/relevance_handlers.go`): review now loads the assessment and enforces path `report_id`/`client_id` equality + reviewer grant (foreign combos → 403, unknown assessment → 404, verdict mismatch → 422 by trigger). Tests: `TestM7cReviewSecurityHTTP` (401/403-no-CSRF/403-analyst/201-reviewer+grant/403-no-grant/403-foreign/422-mismatch/404-unknown).
4. **Snapshot integrity** (tests): `TestM7cSnapshotHashMatchesDocuments` (sha256(document) == stored fingerprint), `TestM7cHistoricalByteIdentical` (raw documents byte-identical across inventory change), `TestM7cConcurrentFullResponse` (4 concurrent HTTP assesses → same assessment_id, 3 findings in every full response, exactly 1 row).

### 3) HTTP API (`backend/relevance_handlers.go`, routes in `main.go`)
| Route | Chain | Semantics |
|---|---|---|
| `POST /api/v1/cti/reports/{report_id}/relevance/{client_id}/assess` | auth + CanViewCTI + CanCreateCTI + audit + csrf | new or replay (200 existing / 201 created; same key + changed fingerprint → 409); cross-client → 403 |
| `GET /api/v1/cti/reports/{report_id}/relevance/{client_id}` | auth + CanViewCTI + audit | latest COMPLETED assessment (404 if none), with documents, evidence, reviews |
| `GET /api/v1/clients/{client_id}/relevant-reports` | auth + CanViewCTI + audit | grant-filtered MATCH list (filter before pagination), `total` in scope |
| `POST /api/v1/cti/reports/{report_id}/relevance/{client_id}/review` | auth + CanViewCTI + audit + csrf | append-only override; original verdict enforced by trigger; 403 without CanReviewArtifact |

### 4) Frontend v3 (existing views only, no redesign)
- **Report Inspector (`#feed`)**: "Client Relevance (M7-C)" section — per-dimension badges (MATCH mint / NO_MATCH muted / UNKNOWN amber), evidence, unknowns, limitations, rule versions, snapshot provenance, reviews; "Assess relevance (POST)" with per-payload idempotency key (409 handling); reviewer override form (ADMINISTRATOR/REVIEWER only). All untrusted data via `textContent` (`escEl`).
- **Client Intelligence (`#clients`)**: "Relevant reports (M7-C)" list via `GET /clients/{id}/relevant-reports`.
- **Case Workspace CTI tab**: read-only relevance badges per linked report.
- `node --check frontend/v3/v3.js` passes.

## Acceptance (isolated fixtures)
M7-C targeted tests: **32 tests PASS** (`go test -run TestM7c`), covering:
- C1 same-client assess (TELEMETRY MATCH with rule+source+field evidence), C2 cross-client 403 + zero rows, C3 revoked grant denial, C4/C5 empty inventory → UNKNOWN, C6/C22 missing telemetry/field evidence → UNKNOWN, C7 legacy/unknown MITRE → UNKNOWN, C8 legacy report runs, C9 replay 200 same ID, C9b new key → new attempt (FAILED preserved), C10/C11 rule-set and inventory changes → new fingerprints/assessments, C11b parser evidence → new CTI snapshot, C12 three independent findings, C13 no invented `source_reference`, C14 no `"score"`/`"confidence"` keys, C15 CTI_ANALYST review → 403, C16 concurrent convergence (1 operation row), C16b same key + changed fingerprint → conflict, C17 historical findings preserved, C18 zero mutation of M7-A/M7-B records, C19 cross-client GET 403, C20 FAILED shape, C21 SECTOR/TECHNOLOGY never NO_MATCH, C23 alternative observable rule → MATCH citing observable rule, C24 review original-verdict mismatch rejected, C25 direct SQL tenant mismatch trigger.
- Additional required: (1) global-field-without-client-evidence → UNKNOWN, (2) no "deployed"/"validated" language in findings, (3) two rules / same entity → both provenances retained, (4) cross-assessment evidence → rejected, (5) snapshot documents reconstructable after inventory change, (6) rule-set change → new snapshot + independent assessment, (7) missing telemetry never NO_MATCH, (8) no M7-A/M7-B mutation (query assertion before/after).

## Regression evidence
- `go build ./...` — PASS (exit 0)
- `go vet ./...` — PASS (exit 0)
- `go test -timeout 900s -count=1 ./...` — PASS (`ok mssp-workbench 248.6s`, exit 0)
- `go test -race -run TestM7c` — PASS (`ok 330.4s`, exit 0)
- `go test -run TestM7c` (final tree, after removing the temporary stagef fixture helper) — PASS (`ok 33.1s`, exit 0)
- `node --check frontend/v3/v3.js` — PASS (exit 0)

## Browser acceptance (Chromium via agent-browser, isolated `stagef.db` on :8080)
- Report Inspector renders Client Relevance with per-dimension badges, unknowns, limitations, rule versions, snapshot provenance; **Assess button works** (created `assessment-24fa3b1c86cef40b`, rendered COMPLETED). No JS errors (`window.__errs == []`).
- **TELEMETRY MATCH rendered with evidence** (after seeding verified fixtures in `stagef.db`): MATCH badge + `• evidence log_source lst-win via rule-telemetry-v1 v1 {...client_id, field_availability, last_checked_at...}`.
- Replay/conflict verified over real HTTP with browser-matching Origin (`WORKBENCH_ORIGIN=http://localhost:8080`): POST key → 201, same key → 200 (same `assessment_id`), same key + different report → 409 `IDEMPOTENCY_CONFLICT`.
- Client Intelligence: "Relevant reports (M7-C)" lists `report-alpha-1 • assessment-a26f6b67fc030997` (MATCH).
- Case Workspace CTI tab: "Relevance: UNKNOWN/SECTOR UNKNOWN/TECHNOLOGY UNKNOWN/TELEMETRY" badges for linked reports.
- Client switch clears inspector (no stale client data); 403/404 honest states verified in Go HTTP tests + UI text.
- Screenshots: `Temp/opencode/m7c-accept-case-cti.png`, `Temp/opencode/m7c-accept-feed-match.png`.
- Note: during this pass the browser repeatedly hung on the Assess click because the test server's CSRF allowlist (`WORKBENCH_ORIGIN`, default `http://localhost:5173`) rejected the UI's own Origin (`http://localhost:8080`) with 403 and the frontend's error `alert()` blocked headless interaction. Resolved by starting the isolated server with `WORKBENCH_ORIGIN=http://localhost:8080` (no code change). Also noted (out of M7-C scope): root `frontend/login.html` hardcodes `http://localhost:8080` as API base, and `frontend/api.js` redirects 401 → relative `login.html` (404 under `/v3/`).

## Remaining limitations
1. SECTOR/TECHNOLOGY NO_MATCH disabled in v1 (needs verified inventory-completeness model) — all non-matches are UNKNOWN.
2. Technology version compared by exact string equality only (no semver).
3. Claim text is never NLP-parsed for relevance; sector/tech signals are conservative exact-token matches.
4. Telemetry staleness threshold fixed at 7 days in v1 rule. Client field evidence relies on `client_log_source_status.field_availability` free text (field named by id or name, substring match) — a structured per-client field registry would be stronger; until then MATCH requires explicit naming + fresh `last_checked_at`.
5. `user_authorized_clients.expires_at` remains ignored (M6 semantics).
6. No live QRadar queries in M7-C (inventory-only evidence).

## Post-acceptance correctness patch (P0-1, P0-2, P1)
1. **P0-1 FAILED atomicity** (`backend/relevance.go`): findings/evidence inserts now run inside `SAVEPOINT relevance_work`; any compute/persistence error does `ROLLBACK TO SAVEPOINT` + `RELEASE`, then persists FAILED with checked UPDATE/COMMIT errors (a failed FAILED-persistence returns an error instead of claiming success). Assessment + canonical snapshots survive; findings/evidence never partially persist. Test: `TestM7cThirdFindingAtomicity` (trigger aborts the 3rd finding, after 2 succeeded) — 0 findings/evidence, snapshots retained, new-key retry completes.
2. **P0-2 Complete input snapshots** (`buildRelevanceSnapshots`): CTI snapshot now includes `malware`; inventory includes telemetry `field_availability`; rule-set fingerprint covers `relevance_matching_rules` (full rows) + `detection_rules` (MITRE + required sources) + `rule_field_requirements` + `global_fields` (identity + active state) — not merely ID/version labels. Test: `TestM7cInputChangeConflicts` (8 independent inputs; same key → conflict, new key → new assessment, history byte-identical) — PASS.
3. **P1 Exact token field matching** (`fieldAvailTokens` in `relevance_match.go`): token-split on identifier boundaries; a field matches only by exact case-insensitive token equality. Test: `TestM7cPartialFieldNameNeverMatches` (`hostname` → UNKNOWN; `host,user` → MATCH) — PASS.
- Targeted: 35 M7-C tests PASS (`go test -run TestM7c`, exit 0, 49.7s). Full regression: `go build` 0, `go vet` 0, `go test -timeout 900s -count=1 ./...` ok 164.4s, `go test -race -run TestM7c` ok 352.9s, `node --check` 0.
- Isolated server (`workbench.exe` on :8080, `stagef.db`) terminated cleanly after verification; production `storage/workbench.db` untouched.

## Final snapshot completeness fix (title + evaluation time)
1. **`cti_reports.title`** added to the canonical CTI evidence snapshot (`buildRelevanceSnapshots`), since SECTOR matching reads it. Test `TestM7cTitleChangeConflicts`: title change + same key → conflict, new key → new assessment, historical CTI document byte-identical.
2. **Evaluation-time pinning** (migration `0009_relevance_eval_time.sql`, additive only; `relevance_assessments.evaluation_at`): one reference time (`evalAt`) is captured per attempt and persisted; `computeRelevanceFindings` now takes `now time.Time` and judges every staleness check against it — historical findings are never reinterpreted with a later clock. Exposed as `evaluation_at` in the assessment API (+ FAILED path). Test `TestM7cEvaluationTimePersisted`: present, RFC3339, in-range, immutable after later attempts.
3. Field audit (every input of `computeRelevanceFindings` vs snapshots): SECTOR — sectors + title ✓; TECHNOLOGY — client_technologies + malware ✓; TELEMETRY — techniques + detection_rules + rule_field_requirements + global_fields + telemetry (status/events/availability/last_checked) ✓.
- Regression: build 0, vet 0, `go test -run TestM7c` ok 57.7s (37 tests), `go test -timeout 900s -count=1 ./...` ok 328.0s, `go test -race -run TestM7c` ok 484.2s, `node --check` 0.

## M7-C GO/NO-GO
- **Development GO** (isolated env): schema, services, 4 endpoints, Frontend v3 integration, C1–C25 + additional 8 tests, full regression — all green.
- **Production NO-GO**: `storage/workbench.db` lacks migrations 0003–0008, has 0 `user_authorized_clients` rows and no ADMINISTRATOR/REVIEWER accounts. Backup + migration procedure (0007→0008) and reviewed grant provisioning require separate explicit approval. **M7-C production deployment is not authorized by this report.** Production SQLite untouched by this patch (LastWriteTime verified).

STOP after corrections. No M7-D, rule deployment, QRadar API, Octop, or Telegram started.
