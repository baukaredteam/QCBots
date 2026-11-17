# Sentinel Atlas — M7-B Design: CTI Reports ↔ Research Cases

> Status: **DESIGN ONLY**. No code, migrations, Frontend, or SQLite touched. M7-B implementation requires separate explicit approval. M7-A (0006 ingestion/provenance) is the dependency baseline.

---

## 1. Verified baseline (from real code/migrations)

| Domain | Real model | Notes |
|---|---|---|
| `cti_reports` (0001 + 0006) | `report_id, client_id NOT NULL → clients, source_id → cti_sources (nullable), title, author, status (0001 enum), original_content_ref, checksum, artifact_id (0006)` | Per-client document. Dedup indexes 0006. `cti_ingestion_runs` + `cti_extraction_results` (M7-A). |
| `research_cases` (0004+0005) | `case_id, idempotency_key UNIQUE, title, description, owner_id → users, status (OPEN/IN_PROGRESS/REVIEW/CLOSED/ARCHIVED), priority/severity/payload_hash/primary_client (0005)` | **No `client_id` column** — case is client-agnostic at case level; `primary_client` is creation context only, not a boundary. |
| `case_authorized_participants` (0004+0005) | `(case_id, user_id) UNIQUE, role_in_case, revoked_at/revoked_by (0005)` | Active = `revoked_at IS NULL` (via `liveParticipantSQL`). |
| `case_activity` (0005) | Immutable (UPDATE/DELETE triggers abort), `visibility_scope GLOBAL/CLIENT` + CHECK, `client_id` required iff CLIENT | **CHECK actions**: `status_changed, participant_added/removed, artifact_added/reviewed, note_added/edited, hypothesis_linked/unlinked, investigation_created, review_requested` — `report_linked/unlinked` **not present** → M7-B requires a table rebuild (see §2). |
| `user_authorized_clients` (0004) | `(user_id, client_id) UNIQUE`, `granted_by, granted_at, expires_at` | Single source of client grants; ADMINISTRATOR **not exempt**. |
| Case access `GetResearchCase` (mcp_case.go:378) | owner → active participant → ADMINISTRATOR (GLOBAL metadata only) | CLIENT content (`GetCaseContext` artifacts, `ListVisibleCaseActivity`, investigations, hypothesis links) gated by `hasClientGrant` for **all** roles incl. ADMIN. |
| Link pattern `LinkCaseHypothesis` (case_stagee.go:51) | `requireM6Schema → GetResearchCase → ARCHIVED reject → getHypothesisClient → hasClientGrant → tx { INSERT OR IGNORE + activity }` | Template for M7-B Report link. Activity `CLIENT`-scoped with `hypClient`. Unlink idempotent. |
| Case create `CreateResearchCaseEx` (mcp_case.go:137) | RBAC `CanCreateCTI` (draft), grant check vs `initial_client_id`, canonical `payload_hash` (v2, length-prefixed), `idempotency_key UNIQUE`, legacy v1 hash accepted on lookup | Atomic title/priority/severity insert; 409 on key reuse with different payload. |
| RBAC | `CanCreateCTI`: CTI_ANALYST, ADMINISTRATOR. `CanViewCTI`: all. `CanReviewArtifact/Hypothesis`: ADMINISTRATOR+REVIEWER only. | No `CanLinkReport` exists. |
| M6 routes (main.go) | `POST /cases` (CanCreateCTI), `POST/DELETE /cases/{id}/hypotheses/{hid}` (CanLinkHypothesis), `GET /cases/{id}/hypotheses` (CanViewCTI) | M7-B routes mirror this shape. |

Global/Client semantics (must be preserved): a **GLOBAL case** grants metadata visibility (owner/participant/ADMIN); **CLIENT report content** still requires an explicit `user_authorized_clients` grant for `report.client_id` for every role. Linking must not create any grant or widen visibility.

---

## 2. `case_cti_reports` — exact DDL proposal (migration 0007)

```sql
-- M7-B: bidirectional CTI Report <-> Research Case links.
-- Document identity stays on cti_reports (M7-A); no new report/case models.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS case_cti_reports (
    case_id   TEXT NOT NULL REFERENCES research_cases(case_id),
    report_id TEXT NOT NULL REFERENCES cti_reports(report_id),
    client_id TEXT NOT NULL REFERENCES clients(client_id),          -- denormalized report.client_id for tenant-safe queries
    linked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    linked_by TEXT NOT NULL REFERENCES users(user_id),
    PRIMARY KEY (case_id, report_id),
    CHECK (client_id IS NOT NULL AND client_id <> '')
);

CREATE INDEX IF NOT EXISTS idx_case_cti_reports_case   ON case_cti_reports(case_id);
CREATE INDEX IF NOT EXISTS idx_case_cti_reports_report ON case_cti_reports(report_id);
CREATE INDEX IF NOT EXISTS idx_case_cti_reports_client ON case_cti_reports(client_id);

-- Tenant consistency: link row client must match the report's client, and
-- the linking user must hold an explicit grant (enforced in Go service;
-- trigger below is defense-in-depth for direct SQL abuse).
CREATE TRIGGER IF NOT EXISTS trg_case_cti_reports_client_match
BEFORE INSERT ON case_cti_reports
BEGIN
    SELECT RAISE(ABORT, 'client mismatch')
    WHERE NOT EXISTS (
        SELECT 1 FROM cti_reports
        WHERE report_id = NEW.report_id AND client_id = NEW.client_id
    );
END;
```

**Why denormalized `client_id`:** report→client join on every list query is avoidable; tenant-scoped listings filter by the link row's `client_id` without joining reports. The trigger guarantees it equals `cti_reports.client_id` (no silent divergence).

**Why not rely on FK alone for cross-client prevention:** FKs guarantee existence, not grant/ownership. Grant + case-access checks live in the Go service (§3); the trigger only guarantees data consistency.

**`case_activity` CHECK extension (required, cannot be ALTERed):** SQLite cannot modify a CHECK. Migration 0007 must rebuild `case_activity`:
1. `PRAGMA foreign_keys=OFF`; copy to `case_activity_new` with the extended CHECK (`+ 'report_linked','report_unlinked'`), copy all rows verbatim, drop old, rename, recreate immutability triggers + indexes.
2. Verify: row count before/after equal, `PRAGMA integrity_check` + `foreign_key_check` clean, trigger smoke test (UPDATE/DELETE still abort).
3. Alternative considered — reuse `artifact_added` action: **rejected** (semantic lie, breaks evidence).

**Historical duplicates check (pre-index):** before `CREATE UNIQUE INDEX`/PK creation, `SELECT case_id, report_id, COUNT(*) ... HAVING COUNT(*)>1` must be empty on the target DB (table is new in 0007, so it is empty by construction; the check guards the copy/re-run path).

---

## 3. Service contracts (`case_cti_report.go`, new file)

Types (mirror `LinkedHypothesis` usage):
```go
type LinkedCTIReport struct {
    CaseID    string `json:"case_id,omitempty"`
    ReportID  string `json:"report_id"`
    Title     string `json:"title,omitempty"`
    ClientID  string `json:"client_id"`
    Status    string `json:"status,omitempty"`
    LinkedAt  string `json:"linked_at,omitempty"`
    LinkedBy  string `json:"linked_by,omitempty"`
}
```

### 3.1 Authorization (both directions, every operation)

1. `requireM7Schema()` — 0006+0007 present, else `ErrSchemaNotReady` (503, never silent degrade).
2. Case access: `GetResearchCase(caseID, userID)` (owner/active participant/ADMIN-metadata) — 404/403 mapping per M6 convention.
3. Report access: `GetCTIReport(reportID)` + `CanAccessClient(userID, report.ClientID)` **and** `hasClientGrant(userID, report.ClientID)` (equivalent to `CanAccessClient`; both checked for defense in depth).
4. Mutation permission: `CanCreateCTI` (CTI_ANALYST, ADMINISTRATOR) — minimal reuse, no new RBAC field (§6). Read: `CanViewCTI`.
5. ARCHIVED case → `ErrCaseArchived` (409) for link/unlink.

### 3.2 Operations

**Link** (single tx):
```
requireM7Schema
GetResearchCase; reject ARCHIVED
GetCTIReport; reject missing (404); reject cross-client (403)
BEGIN
  INSERT OR IGNORE INTO case_cti_reports (case_id, report_id, client_id, linked_by)
  INSERT INTO case_activity (..., 'report_linked', 'CLIENT', report.ClientID, reportID)
COMMIT
```
Idempotent: repeat link → `INSERT OR IGNORE` no-op; activity only when the link row was newly inserted (check `RowsAffected` before writing activity — fixes the always-activity flaw in Hypothesis link).

**Unlink** (single tx): `DELETE WHERE case_id AND report_id`; if `RowsAffected==0` → no-op success (idempotent); else insert `report_unlinked` activity (CLIENT, report's client). Missing report id → no-op success (mirrors UnlinkCaseHypothesis tolerance).

**ListLinkedReports(caseID):**
`SELECT ... FROM case_cti_reports JOIN cti_reports ... WHERE case_id=? AND client_id IN (SELECT client_id FROM user_authorized_clients WHERE user_id=?)` — grant-filtered even though the case is accessible; GLOBAL case never leaks CLIENT reports.

**ListLinkedCases(reportID):** reverse lookup join through the link table + same grant filter on `case_cti_reports.client_id`.

**Concurrent linking:** PK `(case_id, report_id)` serializes; `INSERT OR IGNORE` + affected-row activity gating makes concurrent duplicates collapse to one link + ≤1 activity row for the winning tx (loser no-ops). Test asserts final row count = 1.

### 3.3 Create Case from Report (`POST /api/v1/cti/reports/{id}/create-case`)

Body: `{title, description, priority, severity, idempotency_key}` (client-generated, stable).
Flow (single tx where feasible):
1. AuthZ: `CanCreateCTI` + report access (fetch report first, 404/403 before any write).
2. `CreateResearchCaseEx(userID, title, description, idempotencyKey, report.ClientID, priority, severity)` — grant for `report.ClientID` enforced inside; idempotency (same key+payload → existing case; different payload → 409) preserved by the existing canonical-hash path.
3. Link report (same semantics as §3.2) — if the case already existed and link already present, no-op.
4. Commit case + link + `report_linked` activity atomically where the tx scope allows; any failure rolls back everything (never a case without its link or vice versa on the create path).
Report `status`/provenance/extraction results are **never modified** by link/create (M7-A dependency honored; see §7).

### 3.4 API contracts

| Route | Method | AuthZ chain | Request | Success | Errors |
|---|---|---|---|---|---|
| `/api/v1/cases/{id}/cti-reports` | GET | `requireAuth + CanViewCTI` | — | `200 {reports:[LinkedCTIReport], total}` (grant-filtered, `limit/offset` default 20/max 100) | 404 case, 403 no case access, 503 schema |
| `/api/v1/cases/{id}/cti-reports` | POST | `requireAuth + CanCreateCTI + csrfWrap` | `{report_id}` | `201 {case_id, report_id, linked_at}` (200 on idempotent repeat) | 404, 403 (case/report/grant), 409 ARCHIVED, 400 bad body, 503 |
| `/api/v1/cases/{id}/cti-reports/{report_id}` | DELETE | `requireAuth + CanCreateCTI + csrfWrap` | — | `200 {case_id, report_id, unlinked: bool}` (idempotent) | 403, 409 ARCHIVED, 503 |
| `/api/v1/cti/reports/{id}/cases` | GET | `requireAuth + CanViewCTI` | — | `200 {cases:[…], total}` (grant-filtered to report's client) | 404, 403, 503 |
| `/api/v1/cti/reports/{id}/create-case` | POST | `requireAuth + CanCreateCTI + csrfWrap` | `{title, description, priority, severity, idempotency_key}` | `201 {case_id, report_id, linked:true}` / `200` on replay | 404, 403, 409 (idempotency conflict or ARCHIVED target), 400, 503 |

All responses use the existing `writeJSONError(code, message)` shape; audit via `auditWrap` (existing) **plus** `case_activity` rows for link/unlink (immutable, §2 rebuild).

### 3.5 Frontend integration (no UI redesign)

- **Hub → Link to Case**: in Report Inspector, a "Link to Case" button opens the existing case-picker pattern (`GET /api/v1/hypotheses`-style selection list from `GET /api/v1/cases`); on success shows `Linked to <case title>` badge (no new page).
- **Report Inspector → linked investigations**: `GET /cti/reports/{id}/cases` list (case title + status + Open).
- **Case Workspace → CTI Reports tab**: `GET /cases/{id}/cti-reports` (title/status/client + unlink + Open report). Replaces the honest "backend gap" empty state from V3-F3.
- States: Loading (skeleton panel), Empty ("No linked CTI reports"), 403 (no grant — hides tab content, shows denial), 404 (report gone), Error (retry button). All rendering via `textContent` (existing `escEl` pattern); no cross-client data in DOM.

---

## 4. Security & acceptance matrix (negative tests)

| # | Scenario | Expected |
|---|---|---|
| B1 | alpha links own report to own case | 201, activity `report_linked` CLIENT/alpha |
| B2 | beta links alpha report (has case, no grant for alpha) | **403**, no row, no activity |
| B3 | alpha links beta report | **403** |
| B4 | duplicate link (same pair, sequential) | 201/200 idempotent, **1 row, 1 activity** |
| B5 | concurrent link same pair (×10) | **1 row**, ≤1 activity, 1 winner + n no-ops/existing |
| B6 | unlink existing | 200, row gone, activity `report_unlinked` |
| B7 | unlink non-existent pair | 200 no-op, no activity |
| B8 | unlink after audit history | history rows remain (immutable triggers) |
| B9 | link into ARCHIVED case | **409** |
| B10 | GLOBAL case + CLIENT report, user without grant | case metadata visible, linked list **empty** for that client (no leak) |
| B11 | revoked grant (`user_authorized_clients` row deleted mid-session) | subsequent list/link → 403/empty; existing activity rows unchanged |
| B12 | legacy report (no ingestion runs, pre-M7-A) | link works (identity is on `cti_reports`, not runs); provenance still `ingestion:null` |
| B13 | READ_ONLY / REVIEWER / HYPOTHESIS_WRITER link attempt | **403** (no CanCreateCTI) |
| B14 | Create-from-Report happy path | case created + linked atomically; `primary_client` = report client |
| B15 | Create-from-Report idempotent replay (same key+payload) | **200 same case**, no duplicate link |
| B16 | Create-from-Report replay with different payload | **409** |
| B17 | Create-from-Report for cross-client report | **403**, no case created |
| B18 | Report status/provenance untouched | `cti_reports.status` and M7-A runs/extraction rows identical before/after link+unlink (query assertion) |
| B19 | Unauthenticated / no-session | **401** |
| B20 | CSRF missing on POST/DELETE | **403** (csrfWrap) |

---

## 5. Dependencies on M7-A

- **Hard**: migration 0007 builds on 0006 (0006 must be applied in seed/dev first; same `runMigration` + `schema_migrations` recording; production procedure per M7-P0 still pending and **not** executed by M7-B dev).
- **Soft**: M7-B never reads `cti_ingestion_runs`/`cti_extraction_results` for identity — legacy reports (no runs) remain linkable (B12). Provenance endpoint unchanged.
- **Unchanged invariants**: linking never writes `cti_reports.status`, `file_artifacts`, extraction rows, or M7-A status fields.

## 6. Development vs Production gates

- **Development prerequisites** (isolated `stagef`-pattern SQLite): migrations 0001–0007, `WORKBENCH_SEED_DATA=false`, synthetic users + explicit grants (alpha/beta), fixtures: 2 cases, 2 reports (alpha/beta), 1 legacy report, regression suite green.
- **Production prerequisites** (separate approval, not M7-B dev): §2 `case_activity` rebuild backup/verify/rollback procedure (M7-P0 §1.4), reviewed grant provisioning, RBAC administration. Missing production grants do **not** block M7-B development.
- **Design choice recorded**: mutation permission reuses `CanCreateCTI` (no new RBAC field). If policy later wants finer granularity, a `CanLinkReport` can be added as a follow-up without schema change.

## GO / NO-GO

- **Development GO** (after separate approval): all contracts, DDL, and negative tests are specified and dependency-scoped; no M7-C/D work needed first.
- **Production NO-GO**: until migration 0007 procedure (esp. `case_activity` rebuild + backup) and grants provisioning are approved/executed.
- **M7-B implementation**: **NOT STARTED** (this document is the gate).

STOP after M7-B design.
