# Sentinel Atlas — M7-P0: Database Readiness & Migration Compatibility

> Status: **READ-ONLY AUDIT + DRY-RUN ON A COPY**. Original `storage/workbench.db` was opened `mode=ro` and its hash is unchanged; all apply/verify steps ran on `C:/Users/Бауыржан/AppData/Local/Temp/opencode/dryrun_p0.db`. No Go/backend/frontend/migration files were modified. M7-A implementation is **not started**.

---

## 1. Schema compatibility report

### Actual working-DB state (measured, read-only)

- `schema_migrations`: 0001 + 0002 applied (plus legacy duplicated 0001/0002 rows from earlier seeded runs — cosmetic).
- 57 tables before; **M6 tables absent** (`case_activity`, `case_artifacts`, `case_hypotheses`, `user_authorized_clients` — all missing).
- Data present: `users`=3 (`user-analyst-alpha/CTI_ANALYST`, `user-analyst-beta/CTI_ANALYST`, `user-analyst-multi/HYPOTHESIS_WRITER` — **no ADMINISTRATOR or REVIEWER account**), `clients`=2, `cti_reports`=3, `sectors`=0.
- Read-only artifact check on a service layer? No service runs against this DB in production here.

### Migration dependencies (0003 → 0004 → 0005)

- **0003 Evidence Graph** (self-contained): creates `evidence_entities`, `evidence_graph_edges`, `evidence_references`, `evidence_graph_reviews`, `evidence_edge_history`, `global_publication_queue`. FKs → `clients`, `users`. Requires only 0001. Partial indexes (GLOBAL/CLIENT scope uniqueness).
- **0004 P0 MCP/Case**: creates `mcp_client_identity`, `mcp_client_credential`, `user_authorized_clients`, `research_cases`, `case_authorized_participants`, `case_artifacts`. FKs → `clients`, `users`, `file_artifacts` (M1). Requires 0001; does not require 0003.
- **0005 M6**: ALTERs `research_cases` (priority/severity/closed_*/payload_hash/primary_client) and `case_authorized_participants` (revoked_at/revoked_by — note: base `revoked_at` column is added here while 0004's participants has `revoked_at`? 0004 created participants with `revoked_at` already — then 0005 does `ADD COLUMN revoked_at` → on a DB where 0004's definition already includes it this would fail without the runner's duplicate-column tolerance. The Go runner's `columnExistsTx` tolerates this (verified in code review, see §2). `ADD COLUMN revoked_by` similarly. Also extends `case_artifacts` (review_*), creates `case_hypotheses` (FK → `hunt_hypotheses` from 0001, `research_cases`, `users`), `case_hypothesis_review`, `case_notes`, `case_notes_revision`, `case_activity` (immutable triggers), ALTERs `investigations ADD COLUMN case_id`, adds indexes.

**Order matters**: 0005 requires 0004's tables and 0001's `hunt_hypotheses`/`investigations`.

### Critical production-entrypoint gap (not a blocker for dry-run, but for M7-A)

- `OpenDB` (production path) applies **only 0001 + 0002**. Migrations 0003–0005 are applied **only** by `seedStageFDB` (isolated test DB builder). There is **no production migration command** wired to apply 0003–0005 to `storage/workbench.db`. An explicit operator action (documented procedure, using the same `runMigration` + `schema_migrations` recording) is required before go-live; this audit does not perform it.

### Idempotency / runner behavior (verified in code)

`runMigration` (backend/db.go): single transaction; statements split with trigger-aware logic; `INSERT OR IGNORE INTO schema_migrations`; `duplicate column name` tolerated **only if** `columnExistsTx` verifies the column exists. My Python dry-run re-run of 0005 failed with raw `duplicate column name: priority` — exactly the error the Go runner tolerates. **Python-level re-run ≠ runner behavior; the Go runner is idempotent, executescript is not.**

---

## 2. Migration dry-run result (on a copy)

Procedure: `shutil.copyfile` → integrity check → sequential `executescript` 0003, 0004, 0005 → record versions → integrity/FK checks → forced re-run → data count comparison.

**Results**

| Step | Result |
|---|---|
| Copy | OK — 569344 bytes; original sha256 `33f307d3afb259b8…` **unchanged** after all steps (written copy `6882be92…` differs, as expected) |
| `PRAGMA integrity_check` before | **ok** |
| `PRAGMA foreign_key_check` before | **[] (empty)** |
| Apply 0003 | OK |
| Apply 0004 | OK |
| Apply 0005 | OK |
| `PRAGMA integrity_check` after | **ok** |
| `PRAGMA foreign_key_check` after | **[] (empty)** |
| Tables before → after | 55 → 72 (+17: `case_activity`, `case_artifacts`, `case_authorized_participants`, `case_hypotheses`, `case_hypothesis_review`, `case_notes`, `case_notes_revision`, `evidence_*`(5), `global_publication_queue`, `mcp_*`(2), `research_cases`, `user_authorized_clients`) |
| Re-run 0003/0004 | OK (idempotent via IF NOT EXISTS) |
| Re-run 0005 (raw) | FAIL raw `duplicate column name: priority` — **Go runner tolerates** (`columnExistsTx`); not a production failure mode |
| Schema versions recorded | OK (INSERT OR IGNORE) |

**Compatibility verdict: PASS** — 0003/0004/0005 apply cleanly in sequence to the current working-DB schema; FK and integrity checks clean. The one caveat (raw re-run failure) is handled by the existing runner.

## 3. Data preservation verification

On the copy, before vs after (counts identical):

| Table | Before | After |
|---|---|---|
| `users` | 3 | 3 |
| `clients` | 2 | 2 |
| `sectors` | 0 | 0 |
| `cti_reports` | 3 | 3 |
| `cti_sources` | 0 | 0 |
| `audit_log` | 0 | 0 |
| `sessions` | 0 | 0 |

New tables (`research_cases`, `user_authorized_clients`, `case_activity`, `case_hypotheses`, `evidence_entities`) = 0 rows. **No data loss, no synthetic backfill proposed.**

## 4. Authorization readiness report (after applying 0004)

Post-migration state on the copy:

- `user_authorized_clients` = **0 rows** — **no user has any client grant**.
- Existing users: `user-analyst-alpha` (CTI_ANALYST), `user-analyst-beta` (CTI_ANALYST), `user-analyst-multi` (HYPOTHESIS_WRITER). **No ADMINISTRATOR, no REVIEWER** in the working DB.
- Code semantics (mcp_case.go `GetCaseContext` level-2, `ListAvailableHypotheses`, `ListClients`): **grants are mandatory for CLIENT content for every role including ADMINISTRATOR** (admin metadata access does not bypass `user_authorized_clients` for CLIENT-scoped rows). RBAC (`CanCreateCTI`, `CanReviewArtifact/Hypothesis`, etc.) gates operations, not data visibility.
- **Consequence**: with zero grants, every user sees **metadata-only** (Global Research). Tenant-isolation tests pass because there is nothing visible. No cross-client leak is possible in this state.
- **Provisioning plan (NOT executed — explicitly out of scope)**: create an ADMINISTRATOR (out-of-band secure issuance), insert grant rows (one per user×client) via a reviewed operator procedure recording `granted_by`/`granted_at`, then re-run grant-filtered list checks and tenant-isolation tests. No automatic grants were or will be created by this audit.

## 5. M7 updated data model (refinements A–E, no implementation)

- **A. Three independent confidences** — do not merge: `source_reliability` (cti_sources.reliability_rating — is the source trustworthy), `extraction_confidence` (indicators.confidence — how sure are we the extraction is correct), `claim_confidence`/credibility (cti_claims.reliability_rating + credibility_rating — how much should an analyst believe the report's claims). Display them as three separate columns; never average into a single "score".
- **B. IOC normalization (type-specific)**:
  - `domain`: IDNA-2008 lowercase, strip trailing dot, strip `www.` only as separate indicator (never auto-merge).
  - `ip`: canonical IPv4 (`%d.%d.%d.%d`) / IPv6 compressed (netip.Addr).
  - `url`: scheme+host lowercased, default ports stripped, fragment dropped, others verbatim.
  - `hash`: lowercase hex, algorithm implied by length (MD5/SHA1/SHA256).
  - `email`: lowercase, strip `<>`.
  - Normalization is lossless-flagged (`normalized_value` + `normalization_rule` columns are proposals; no silent rewriting of original value).
- **C. `case_cti_reports`** (M7-B): includes `link_action` audit history (separate `case_cti_report_history` or reuse `case_activity` with `linked_report`/`unlinked_report` actions — recommended: reuse `case_activity`, no new table) + read AND write authorization checks: link/unlink requires case access + report client grant; list filters by grant on both sides; GLOBAL case metadata rule preserved.
- **D. Relevance v1**: explainable status `RELEVANT/NOT_RELEVANT/NEEDS_REVIEW/UNKNOWN` + `reasons[]` (e.g. `sector:ENERGY→client sector ENERGY`, `tech:Windows present for client`, `telemetry:log_source_type_id active`) + `missing_evidence[]` (e.g. `telemetry missing for client`, `sector mapping absent`). **No numeric scores in v1.**
- **E. Three separate review concepts**:
  - `hypothesis_reviews` (0001) — *content review of a hypothesis draft* (per-hypothesis, one lifecycle).
  - `case_hypothesis_review` (0005) — *per-client linkage decision* (append-only, latest-wins, scoped by `client_id`).
  - `investigations.final_verdict` (0001) — *operational outcome of a hunt* (TP/FP/benign, per-investigation).
  Keep them independent; M7 links C only to E-second, never overwriting `hypothesis_reviews`.

## 6. M7-A implementation prerequisites

1. **Explicit migration procedure** for 0003–0005 on the working DB (no production runner wiring exists) — backup + operator sign-off (this dry-run is the evidence base, not the operation).
2. **Provisioning grants** (per §4) under a separate approval — no automatic grants.
3. **RBAC review**: no REVIEWER/ADMIN account in working DB today; needed before human-review flows can be exercised.
4. Re-run of tenant-isolation + `case_cti_reports`-design tests against the migrated copy.

## 7. GO / NO-GO — **CONDITIONAL GO**

**Schema compatibility: PASS.** Dry-run applies cleanly, integrity/FK clean, data preserved, runner idempotent. The 0005 raw re-run failure is **not a production risk** (Go runner tolerates it).

**Authorization: NOT READY.** Zero grants, zero admin/reviewer accounts. This does not block code, but blocks any live M7 feature demo against the working DB.

**Blockers for M7-A implementation start**: (1) explicit migration procedure approval; (2) grant provisioning plan approval. **M7-A implementation remains NOT APPROVED** — this report is the precondition, not the go-ahead.

STOP after M7-P0.
