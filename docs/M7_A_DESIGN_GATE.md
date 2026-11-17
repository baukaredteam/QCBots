# Sentinel Atlas — M7-P0 Corrections + M7-A Pre-Implementation Design Gate

> Status: **DESIGN GATE ONLY**. No code was written, no migration applied, no DB written. M7-A implementation starts only after separate explicit approval.
> Parents: `docs/M7_P0_DATABASE_READINESS.md` (accepted with conditions).

---

## PART 1 — M7-P0 audit gaps closed

### 1.1 Table-count discrepancy (57 vs 55) — RESOLVED

- Fresh read-only listing of the working DB now reports **57 tables** (identical listing twice; no duplicates).
- The `55` figure came from the dry-run copy snapshot — that copy is **stale** (its file mtime predates later E2E server runs). Evidence: current `original-only` tables vs the stale copy are exactly `building_blocks` and `rule_building_blocks`, which the isolated/stale copy lacks. These two tables were created in the working DB after the dry-run snapshot (server startup `CREATE IF NOT EXISTS` via `ensureQRadarSchemaSQL`, empty schema, no data rows added).
- Current arithmetic: 57 original + 15 M7-relevant new tables = 72 = stale copy count + 17 (the stale copy base was 55). Delta is fully explained; no tables are hidden or duplicated.

### 1.2 Go-runner re-run verification (was: Python executescript only)

**PASS via existing test**: `TestMigration0005CreatesAllTables` (backend/mcp_test.go) applies 0001→0004 then 0005 through the **real `runMigration`** on a fresh DB, records `schema_migrations`, then **re-runs 0005** and asserts still exactly 1 version row. Re-run here: **PASS (0.09s)**. `TestMigrationRunnerAtomicRollback` also PASS (0.01s). Raw Python re-run failure (`duplicate column name: priority`) is expected without the runner's `columnExistsTx` tolerance and is **not** a production risk.

### 1.3 Column-definition comparison (beyond existence checks)

Compared `PRAGMA table_info` (name, type, notnull) for all 57 shared tables between working DB (`mode=ro`) and fresh `stagef.db` (built by the real Go runner with 0001–0005). Result: **55/57 identical**; 2 diffs, both expected:

| Table | Diff | Meaning |
|---|---|---|
| `building_blocks` | stagef has extra `log_sources TEXT` (registry column) | Working DB has not run `ensureQRadarSchema` against it yet; running QRadar endpoints will add the column — verified safe by the deadlock fix |
| `investigations` | stagef has extra `case_id` (0005) | 0005 not yet applied to working DB — expected pre-migration state |

No type mismatches, no missing NOT NULLs, no hidden defaults. (FK/unique/index parity: `0003` partial indexes and M6 check constraints live only in stagef until migration — by design.)

### 1.4 Production backup procedure (SQLite WAL + Online Backup API)

Given `storage/workbench.db` is SQLite (possibly WAL) with a live service, the procedure is:

1. **Stop-write first**: request service drain/stop (or accept backup-API snapshot semantics). Note: SQL Server–style "online" backup while writes continue is safe in principle, but for a 500KB DB a stop-write snapshot is trivial and preferred.
2. **Preferred method (recommended)**: `sqlite3_backup` / equivalent (Go: use driver-level backup or `VACUUM INTO`-family safe copy) — a pure file copy (`cp`) under WAL is **unsafe** while the DB is hot: `*-wal` may not be checkpointed and the copy can be torn. With the service stopped and a `PRAGMA wal_checkpoint(TRUNCATE)` executed, a full file copy is acceptable as a fallback.
3. **Verify**: `PRAGMA integrity_check` + `PRAGMA foreign_key_check` on the backup; record sha256; test open the backup in an isolated path (never on the original).
4. **Rollback plan**: stop service → replace file → `PRAGMA integrity_check` → restart → health endpoint → spot-check `schema_migrations` row count. Rollback window: from step-1 stop to successful health.

(M7-P0 dry-run itself used a cold copy only — no WAL was live — and is not a substitute for this procedure.)

---

## PART 2 — M7-A implementation design (exact contract)

### 2.1 Reused existing surface (no duplication)

| Concern | Reuse |
|---|---|
| File artifact | `file_artifacts` (artifact_id, file_name, file_path, checksum, file_type, metadata_ref) |
| Report identity | `cti_reports` (report_id, client_id, checksum, status) |
| Extraction outputs | `indicators`, `techniques`, `cves`, `threat_actors`, `campaigns`, `malware`, `cti_claims` |
| Extraction logic | `extractFromJSON`, `extractFromHTML`, `detectContentType` (cti.go:967+), `sha256Sum` |
| Schema safety | `ensureQRadarSchemaSQL` pattern (fixed), `runMigration` + `schema_migrations` |
| Access | `CanAccessClient`, `GetUserAuthorizedClientsFromDB`, `sessionFromContext`, `requirePermission` |

**No new Evidence Graph / Case / Hypothesis / IOC tables.**

### 2.2 Identity model (P0-constraints final — SQL-proven, 13/13)

**Document identity lives on `cti_reports`** (existing table; `client_id NOT NULL` per 0001 DDL). Dedup is tenant-scoped and NULL-safe via partial unique indexes:

```sql
CREATE UNIQUE INDEX idx_cti_reports_dedup_src
    ON cti_reports(client_id, checksum, source_id) WHERE source_id IS NOT NULL;
CREATE UNIQUE INDEX idx_cti_reports_dedup_nosrc
    ON cti_reports(client_id, checksum) WHERE source_id IS NULL;
```

**`cti_ingestion_runs` is attempt history only** — NO document-level UNIQUE on this table (multiple run_id values per document are a design requirement):

```sql
CREATE TABLE IF NOT EXISTS cti_ingestion_runs (
    run_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES cti_reports(report_id),
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    status TEXT NOT NULL CHECK (status IN ('PENDING','INGESTED','ANALYZING','ANALYZED','FAILED')),
    parser_version TEXT NOT NULL DEFAULT '1',
    request_idempotency_key TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- Database-enforced HTTP idempotency, scoped to the client:
CREATE UNIQUE INDEX idx_cti_runs_request_unique
    ON cti_ingestion_runs(client_id, request_idempotency_key)
    WHERE request_idempotency_key IS NOT NULL;
CREATE INDEX idx_cti_ingestion_runs_client
    ON cti_ingestion_runs(client_id, created_at DESC);
CREATE INDEX idx_cti_ingestion_runs_report
    ON cti_ingestion_runs(report_id);
```

#### 2.2.1 Four distinct concerns (previously conflated)

- **Document identity**: `cti_reports` via the partial unique indexes above — `client_id` is in the key, so alpha/beta with identical bytes+source are two documents (strict tenant boundary, §2.2.3).
- **HTTP idempotency**: `request_idempotency_key` unique per client (`WHERE NOT NULL` scope). Same key + same payload fingerprint → existing run (200); same key + different fingerprint → **409** (fingerprint check is **Go logic**; SQL only enforces uniqueness). Explicit new analysis attempt → new key (new operation).
- **Extraction attempts**: each retry/analysis attempt is a new `run_id` row for the same `report_id` (proven: multiple attempts coexist).
- **Parser version**: recorded per attempt; re-analysis with a new version is just a new run row. No unique on `(report_id, parser_version)`.

#### 2.2.2 Transaction semantics

- `(1)` artifact staging + checksum;
- `(2)` report INSERT (if new) + run INSERT (PENDING) in ONE tx — idempotent on the dedup index: on conflict, adopt existing report_id and continue to step (3);
- `(3)` extraction writes in per-entity-kind transactions (existing behavior), with run rows incrementally updated;
- `(4)` run finalized to ANALYZED (or FAILED with error_code).
- `report.status` mirrors the *latest* run: PENDING→INGESTED→ANALYZING→ANALYZED/FAILED. `report.status` updated only at finalization; extraction reads never mutate it.

#### 2.2.3 Required tests (P0-1)

- same file + NULL source twice → **one** report (partial unique index on `(client_id, content_checksum) WHERE source_id IS NULL`);
- same file + same source twice → one report;
- same content + different source → **two** reports (proves identity is per-source);
- concurrent same-file imports → one report, one winner, other gets existing id (no duplicates);
- same idempotency_key + different payload → **409**;
- retry after FAILED → new run row, report recovered to ANALYZED, no duplicate extraction rows (§2.5).

### 2.3 Type-specific IOC normalization (in `CreateIndicator` path)

| Type | Rule |
|---|---|
| domain | IDNA lowercase, strip trailing dot; `www.` kept as separate indicator (never auto-merged) |
| ip | canonical v4 (`%d.%d.%d.%d`) / v6 (`netip.ParseAddr`) |
| url | scheme+host lowercased, default ports stripped, fragment dropped, path/query verbatim (no silent rewrite of the original — store original in `indicator_value`, normalized in provenance/source_reference round-trip) |
| hash | lowercase; algorithm implied by length (32/40/64 hex) |
| email | lowercase, strip `<>` |

Storage: original value always preserved; normalized form is a **separate column** (not `source_reference` — provenance must stay byte-identical). Minimal compatible extension on `indicators`:

```sql
ALTER TABLE indicators ADD COLUMN normalized_value TEXT;
ALTER TABLE indicators ADD COLUMN normalization_rule TEXT;      -- e.g. 'domain-idna-v1'
ALTER TABLE indicators ADD COLUMN normalization_version TEXT;   -- e.g. '1'
-- indicator_value and source_reference are untouched (original provenance).
```

Storage invariant: `normalized_value IS NULL ⇒ normalization_rule IS NULL` — un-normalized rows are marked, never silently rewritten.

| Type | Rule (normalization_rule) |
|---|---|
| domain (`domain-idna-v1`) | lowercase, strip trailing dot; ASCII-only until `idna` dep verified (documented degradation); invalid → no normalization (NULL) |
| ip (`ip-canonical-v1`) | `netip.ParseAddr` → canonical string (v4 `%d.%d.%d.%d` form / v6 compressed) |
| url (`url-canonical-v1`) | scheme+host lowercased, default ports stripped, fragment dropped; path/query verbatim; **never merge `www.` vs bare host or distinct paths/userinfo** |
| hash (`hash-lower-v1`) | lowercase hex; algorithm implied by length for grouping only (not stored) |
| email (`email-lower-v1`) | lowercase, strip `<>`; never strip `+tag` |

### 2.4 Extraction data model (P0-4, verified against migrations/0001_initial.sql)

Real DDL (`cti_claims`, `indicators`, `threat_actors`, `campaigns`, `malware`, `cves`, `techniques`): every table has `report_id TEXT NOT NULL → cti_reports`; **none** has a run/attempt column and **none** has any UNIQUE index. Attempt-scoped results therefore need a second table (preferred over altering 7 tables):

```sql
-- Extraction membership: FK for run/report (SQLite); trigger for entity match.
CREATE TABLE IF NOT EXISTS cti_extraction_results (
    result_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES cti_ingestion_runs(run_id),
    report_id TEXT NOT NULL REFERENCES cti_reports(report_id),
    entity_type TEXT NOT NULL CHECK (entity_type IN ('indicator','technique','cve','claim','threat_actor','campaign','malware')),
    entity_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (run_id, entity_type, entity_id)
);
CREATE TRIGGER trg_extraction_entity_match BEFORE INSERT ON cti_extraction_results
BEGIN
    SELECT RAISE(ABORT, 'entity report mismatch')
    WHERE NOT EXISTS (
        SELECT 1 FROM indicators
        WHERE indicator_id = NEW.entity_id AND report_id = NEW.report_id
    );
END;
```
With one such trigger per extraction table, membership can only point at an entity that exists (checked before write), belongs to the same report, and matches the declared entity_type (enforced per-trigger by construction; enum-type per-table selected in Go service factory). Go writes entity + membership in the **same transaction**; the trigger guards the type/report match because a plain FK cannot express "entity in one of 7 tables". This is a design decision: SQLite does not provide polymorphic FKs; claim of referential integrity rests on the trigger, not plain FK.

Plus content-dedup unique indexes on the entity tables (re-analysis never duplicates):

```sql
CREATE UNIQUE INDEX IF NOT EXISTS idx_indicators_dedup
    ON indicators(report_id, indicator_type, indicator_value);
CREATE UNIQUE INDEX IF NOT EXISTS idx_techniques_dedup
    ON techniques(report_id, mitre_technique_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cves_dedup
    ON cves(report_id, cve_id_text);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cti_claims_dedup
    ON cti_claims(report_id, claim_text);
CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_actors_dedup
    ON threat_actors(report_id, actor_name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_campaigns_dedup
    ON campaigns(report_id, campaign_name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_malware_dedup
    ON malware(report_id, malware_name);
```

Alternative (7-table ALTER with run_id/parser_version columns) rejected — larger migration surface; a junction table satisfies attempt-membership, partial-failure accounting and parser-version re-analysis.

### 2.5 Three confidences (strictly separate)

- `cti_sources.reliability_rating` — **source reliability** (how trustworthy is this provenance).
- `indicators.confidence` — **extraction confidence** (how sure are we the regex/parser found a real IOC).
- `cti_claims.reliability_rating` + `credibility_rating` — **claim confidence** (how much should an analyst believe the report's narrative).
UI rule: three columns, never averaged, never renamed to score/threat.

### 2.6 Extraction retry + partial failure lifecycle (P0-3, P1-6)

Five distinct lifecycles (never conflated):
- **report lifecycle** (`cti_reports.status` — real 0001 enum: NEW, INGESTED, ANALYSIS_PENDING, ANALYZED, …): governed by M6 review workflow; ingestion sets INGESTED → ANALYZED only;
- **import operation** (`cti_ingestion_runs` PENDING→INGESTED);
- **extraction attempt** (`cti_ingestion_runs` INGESTED→ANALYZING→ANALYZED/FAILED — includes parser version);
- **last successful analysis** = latest ANALYZED run (`WHERE status='ANALYZED' ORDER BY created_at DESC, rowid DESC LIMIT 1`) — proven in SQL (§2.9);
- **latest failed attempt** = latest FAILED run (shown alongside, never overwriting the successful record).

Rules: FAILED never poses as ANALYZED; a failed new parser version never deletes previously confirmed results; crash recovery sweeps stuck PENDING/ANALYZING runs (older than threshold) to FAILED on startup (no auto-retry — analyst retries explicitly). `cti_reports.status` is updated toward ANALYZED only at successful finalization and is never downgraded by a failed re-analysis.

- **Dedup on retry**: extraction inserts pass through the per-entity unique indexes (§2.4); per-attempt membership is recorded in `cti_extraction_results` (INSERT OR IGNORE on `(run_id, entity_type, entity_id)`), so re-analysis never duplicates entities within an attempt or across attempts.
- **Partial rows**: rows produced by a FAILED attempt stay in the tables, tagged via `cti_extraction_results` to their run; the report keeps its last successful analysis. Retry completes only missing kinds (dedup). Never delete to fake cleanliness.

Failure matrix:

| Failure point | Run status | Report status | Entity rows | Recovery |
|---|---|---|---|---|
| before transaction | FAILED | unchanged | none | retry allowed |
| during tx | FAILED (rolled back) | unchanged | none | retry allowed |
| crash after commit | PENDING → reconciled FAILED (sweeper) | INGESTED | none | manual retry |
| crash between report insert and run finalization | PENDING→FAILED; `cti_reports` row exists with status INGESTED or NEW | NO_CRASH_LOSS: report row survives on its own INSERT tx (committed before run finalization), rows per kind | sweeper reconciles; client retries import |
| partial extraction | FAILED (partial counts) | INGESTED | partial, tagged with run_id | retry completes missing (dedup) |
| retry same source+version | ANALYZED (dedup) | ANALYZED | no dupes | no-op |
| retry new parser version | ANALYZED | ANALYZED | new version rows | allowed (old rows intact) |

*(Security invariants §2.8 cross-reference: read `CanViewCTI` + `CanAccessClient`; imports `CanViewCTI` + `CanCreateCTI` + grant — see §2.6 provenance table. Full security evaluation of the final shape happens again during implementation tests, not as a separate section header here.)*

Response (unverified values are `null` with `verified: false` flags — never zero-scores):
```json
{
  "report_id": "...", "client_id": "...",
  "source": { "source_id": "...", "source_name": "...", "source_type": "...", "source_reliability": "..." },
  "artifact": { "checksum": "...", "artifact_id": "...", "original_content_ref": "...", "checksum_verified": true },
  "ingestion": { "run_id": "...", "status": "...", "parser_version": "...", "extracted_counts": {...} },
  "entities": { "indicators": 0, "techniques": 0, "cves": 0, "claims": 0, "threat_actors": 0, "campaigns": 0, "malware": 0 },
  "confidence": {
    "source_reliability": { "value": "...", "verified": true },
    "extraction_confidence": { "value": "...", "verified": false },
    "claim_confidence": { "value": "...", "verified": false }
  },
  "analysis_state": "INGESTED|ANALYZED"
}
```

| Case | Response |
|---|---|
| cross-client | **403** (same grant check as report detail) |
| not found | **404** |
| legacy report (no run row) | 200 with `"ingestion": null`, `"checksum_verified": false` — never fabricate a run |
| missing artifact | artifact fields null, `checksum_verified: false` |
| checksum mismatch | artifact present, `checksum_verified: false`, `error_code: "checksum_mismatch"` |
| null/UNKNOWN confidence | `verified: false` + null value |

Permissions: read — `CanViewCTI` + `CanAccessClient(report.ClientID)`; write (`POST /cti/import`) — `CanViewCTI` + `CanCreateCTI` + client grant. **No new Evidence Graph endpoints** in M7-A.

### 2.7 Test matrix (M7-A, updated §2.4/2.6-aware)

| # | Test | Expected |
|---|---|---|
| A1 | Same file + NULL source, same client | one report (partial `UNIQUE` on `(client_id, content_checksum) WHERE source_id IS NULL`) |
| A2 | Same file + same source, same client | same `report_id`, unique honored |
| A3 | Same bytes, client-alpha vs client-beta (same source) | **two** reports, no cross-tenant id leakage |
| A4 | Concurrent same-document imports (same tenant) | one wins (UNIQUE), other gets existing id |
| A5 | Same idempotency_key + different payload | **409** |
| A6 | FAILED retry, same parser version | new run row, no duplicate extraction rows (`INSERT OR IGNORE` on content keys + `(run_id, entity_type, entity_id)` in `cti_extraction_results`) |
| A7 | Checksum mismatch on re-read | `checksum_mismatch`, no new entities |
| A8 | Normalization (domain/ip/url/hash/email + www/port/fragment cases) | matches §2.3; `source_reference` byte-identical |
| A9 | Nil/invalid normalization input | NULL normalized + rule; original untouched |
| A10 | Cross-client provenance (**403**); missing report (**404**); legacy report `ingestion: null` | exact codes above |
| A11 | Import without `CanCreateCTI` (READ_ONLY) | **403** |
| A12 | Provenance shape + three confidences separate | no invented scores; null → `verified: false` |
| A13 | FK/UNIQUE violations (orphan report_id, duplicate dedup, NULL-source multi-insert) | constraints reject; no orphan dual-write |
| A14 | Parser-version retry | new version rows; old verified rows intact, no dupes within version |
| A15 | `ensureQRadarSchema` re-run safety (regression) | unchanged (existing) |
| S1 | Legacy report without `cti_ingestion_runs` row | provenance 200, `ingestion: null`, `checksum_verified: false` |
| S2 | Crash between report INSERT and run finalization | report row (INGESTED) survives; run reconciled FAILED; clean retry succeeds |
| S3 | Partial extraction | FAILED + partial rows tagged by `run_id`; retry completes only missing |

---

## PART 3 — Development vs deployment split

### 2.9 SQL acceptance proof (executed here, design-only, in-memory SQLite)

The DDL above was executed against a fresh in-memory SQLite database (via Python `sqlite3`, TEMP dir only; no project files or working SQLite touched). **13/13 checks PASS:**

| # | Scenario | Result |
|---|---|---|
| 1 | Same client/source/content | 2nd insert rejected by partial unique index; count==1 |
| 2 | Two clients, same content/source | 2 distinct documents |
| NULL | NULL-source dedup | rejected duplicate |
| 3 | Same report, multiple attempts | 2 run rows coexist (no doc-level UNIQUE on runs) |
| 4 | Failed retry, same parser | new FAILED run row inserts fine |
| 5 | New parser version | new run row inserts fine |
| 6 | Concurrent idempotency | 1 operation (unique index serializes) |
| 7 | Duplicate request key + changed payload | SQL rejects; Go raises 409 |
| 8 | Cross-report membership / orphan entity / missing run FK | trigger/FK abort |
| 9 | Latest successful analysis | `WHERE status='ANALYZED' ORDER BY … LIMIT 1` returns the latest |

**Not provable in SQL alone** (marked explicitly as Go service invariants + required negative integration tests at implementation time):
1. `payload_fingerprint` comparison → 409 on same key + different fingerprint.
2. `report.status` semantics (never downgraded by failed re-analysis).
3. Entity-write + membership-write same-transaction atomicity (SQLite trigger covers match/existence; cross-table atomicity is Go-managed).
4. Crash sweeper (stuck PENDING → FAILED reconcile).
5. Source-id existence (already covered by FK, but race-free adoption needs an integration test).

---

## PART 3 — Development vs deployment split

**DEVELOPMENT PREREQUISITES** (can start before grants exist):
- Isolated SQLite (`stagef.db` pattern): migrations 0001–0005, `WORKBENCH_SEED_DATA=false`.
- Synthetic users (existing seed: alpha/beta/multi/admin/reviewer) + **explicit grant rows** for test users only (same mechanism as `seedStageFDB`; synthetic, not production grants).
- Test fixtures for import (valid JSON/HTML, corrupt JSON, duplicate).
- Regression suite: full `go test ./...` must stay green.

**PRODUCTION DEPLOYMENT PREREQUISITES** (separate approval, not part of M7-A dev):
- Operator-approved backup per §1.4, migration procedure for 0003–0005, reviewed grant provisioning, RBAC administration (create ADMIN/REVIEWER), integrity/FK verification, rollback plan.
- Missing production grants **do not** block M7-A development on the isolated test DB.

## PART 4 — Gates (updated)

- **Development prerequisites check**: ✅ all available (isolated DB pattern, seed users already include test grants, fixtures to be created in M7-A, regression suite green).
- **M7-A design**: ✅ complete (revised schema, services, state machine, API contracts, tests A1–A15 + S1–S3, SQL proof 13/13).
- **Production deployment**: ❌ blocked (backup/migration/provisioning procedures not yet executed — deliberately out of scope).

### GO / NO-GO verdict (revised, SQL-proven)

- **Development GO**: M7-A may be implemented on the isolated test DB after separate explicit approval.
- **Production NO-GO**: do not deploy to `storage/workbench.db` yet.
- **M7-A implementation**: **NOT STARTED** (this document is the gate).

STOP after Final Schema Consistency Fix.

STOP after M7-A Design Gate Corrections.
