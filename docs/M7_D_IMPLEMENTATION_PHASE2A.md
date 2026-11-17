# M7-D Phase 2A — Completion Report

Date: 2026-11-10
Scope: Phase 2A only. Phase 2B (pySigma, Sigma→AQL, Hunt Plans) not started.
Production `storage/workbench.db` was never opened; all work used disposable `%TEMP%` SQLite files.

## 1. Status summary

| Area | Classification |
|---|---|
| Tenant isolation on all field-intel read/write paths | IMPLEMENTED / TESTED |
| Separate import vs review capabilities | IMPLEMENTED / TESTED |
| Forward migration 0012 (0011 untouched) | IMPLEMENTED / TESTED |
| Upload limits (size, rows, format) | IMPLEMENTED / TESTED |
| Redaction before persistence | IMPLEMENTED / TESTED |
| Windows (key=value + TaskContent XML) parser | IMPLEMENTED / TESTED |
| IIS W3C parser with `#Fields`, refusal without it | IMPLEMENTED / TESTED |
| CSV / JSON / JSONL / generic key=value parsers | IMPLEMENTED / TESTED |
| Candidate auto field mapping, type-checked, ambiguity-flagged | IMPLEMENTED / TESTED |
| Analyst approval of mapping (audited, versioned) | IMPLEMENTED / TESTED |
| Review → publish workflow with server-side guards | IMPLEMENTED / TESTED |
| Idempotent duplicate upload | IMPLEMENTED / TESTED |
| Transactional row write / rollback on failure | IMPLEMENTED / TESTED |
| AQL_VERIFIED separation (manual attestation only) | IMPLEMENTED / TESTED |
| Frontend hierarchical loading with real parent IDs | IMPLEMENTED / TESTED (HTTP + syntax) |
| Frontend browser acceptance | **NOT VERIFIED** (see §10) |
| MSSP shared-console tenancy model | **BLOCKER — documented, not changed** (see §9) |
| Live QRadar API / AQL execution | NOT IMPLEMENTED (out of scope by design) |

Phase 2A **GO for the registry + hardened import pipeline**, with the two caveats above (browser acceptance, MSSP model).

## 2. Confirmed root causes fixed

1. **Cross-tenant writes were possible.** `CreateQRadarImportRow` and `CreateQRadarImportFieldMap` took only a `batch_id`: any authenticated user could write into another client's batch. Both now take the user, resolve the batch owner and check the grant. Foreign batch IDs return the same not-found answer as missing ones.
2. **One permission for read and write.** Every route used `CanViewCTI`, so a read-only analyst could upload and publish. Added two capabilities (`CanImportFieldIntel`, `CanReviewFieldIntel`) and split the routes.
3. **Raw client payload was persisted.** `ProcessImportFile` wrote each line to `raw_line` unmodified. It now parses, redacts, and persists only redacted forms (`redacted_line`, redacted `parsed_json`); `raw_line` stays NULL.
4. **`PARSED` lied.** Storing lines was reported as parsing. Status now reflects a real parse (`MAPPED` after parsing + redaction + candidate generation; `FAILED` when nothing parses).
5. **Publish had no real gate.** Any `REVIEWED` string published. Publish now requires `reviewed_status = 'APPROVED'`, `parsed_rows > 0`, and is guarded in the UPDATE so concurrent publishes cannot both win.
6. **`VERIFIED` was client-supplied.** A caller could post `aql_verification_status=VERIFIED` and it was stored. Now requires reviewer capability, the reviewer's own identity, a timestamp and evidence; otherwise 403.
7. **Field-intel errors mapped to 500.** Cross-client access returned 500 before; now 403/404/400 as appropriate.
8. **Frontend errors became empty catalogues.** The old page swallowed every failure into `[]`. The new loader surfaces 400/403/404/503/network as explicit states.
9. **Nested XML leaked through the key=value scanner** (attribute pairs became fake fields and carried secrets). The scanner now runs only on the prefix before the XML body.

## 3. Schema change (forward only)

`migrations/0012_field_intel_hardening.sql` — additive `ALTER TABLE` only:

- `qradar_import_batches`: `parser_version`, `redaction_version`, `parsed_rows`, `rejected_rows`, `redacted_values`, `reviewed_by`, `reviewed_at`, `reviewed_status`.
- `qradar_import_rows`: `redacted_line`, `field_names`, `field_types`.
- `qradar_import_field_map`: `ambiguous`, `evidence`, `parser_version`.
- `qradar_field_mappings`: `approved_by`, `approved_at`, `verification_mode`, `evidence_reference`.
- index on `(client_id, processing_status)`.

`0011` was **not** modified. Rollback: drop the added columns (or drop/recreate the tables in a dev reset); no shared table changed.

## 4. Import pipeline behaviour

```
validate → parse → redact → persist(redacted) → derive candidates → MAPPED
                                              ↘ reviewer: APPROVED → REVIEWED → PUBLISH
                                              ↘ reviewer: REJECTED
                                              ↘ unrecoverable: FAILED (no rows)
```

- File limit 4 MiB, row limit 2000; both enforced in the service, and the handler caps the multipart form at 8 MiB.
- Unsupported `source_type` rejected before reading.
- Whole-file ambiguity (IIS without `#Fields`, duplicate CSV header, unreadable JSON) fails the batch **and stores no rows**.
- Row count, rejected count and redaction count are recorded per batch.
- Rows are written inside one transaction; a failure rolls back and marks the batch `FAILED`.
- Duplicate `(client_id, file_hash)` returns the existing batch (idempotent).
- Nothing about the payload is logged; error text carries counts and format names only.

Redaction (version `redact-1`) replaces: passwords, tokens/secrets/api keys, bearer/basic credentials, cookies/session ids, usernames (including `TaskContent.*` nested names), command lines, hostnames, emails, IPv4/IPv6, URL hosts and URL query strings, and long opaque identifiers. It does **not** guarantee anonymisation; residual identifiability is possible and every batch needs a human review.

## 5. Parser examples (verified by test)

Windows Security:

```
EventID=4624 SourceName=Microsoft-Windows-Security-Auditing TaskName=Logon
TaskContent=<EventData><Data Name="TargetUserName">j.doe</Data><Data Name="IpAddress">10.9.8.7</Data></EventData>
```
→ fields `EventID` (integer), `TaskName` (string), `TaskContent.TargetUserName`, `TaskContent.IpAddress`; values redacted before storage.

IIS W3C:

```
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip sc-status
... GET /admin/default.aspx q=1 443 CONTOSO\jdoe 203.0.113.9 200
```
→ `cs-method`, `cs-uri-stem`, `sc-status`; without `#Fields` the file is rejected (no invented positions).

CSV: first row is the header, duplicate/empty headers rejected, column-count mismatches counted as rejected rows.
JSON/JSONL: objects only; scalars stringified; nested structures marked `[STRUCTURED_VALUE]`.

## 6. Auto mapping results (observed in acceptance)

From a real upload of the Windows fixture:

```
EventID  → event_id   high   "observed integer value on EventID; type matches integer"
TaskName → task_name  high   "observed string value on TaskName; type matches string"
```

Rules enforced and tested:

- A candidate requires a known alias **and** an observed type compatible with the CEP type; `sc-status` with string samples produces nothing.
- Unknown fields never map by name similarity.
- Two raw fields claiming one CEP are both marked `ambiguous=true`, confidence `low`, with evidence listing the collision.
- Candidates are stored per batch with parser version and evidence; they do not become approved mappings.
- Approval (`POST /api/v1/qradar/field-mappings/{id}/approve`) requires reviewer capability, flips `origin` to `manual`, records `approved_by/approved_at` and `verification_mode='MANUAL_ATTESTED'`, and writes an audit event.
- Approved mappings are never rewritten by a later import (candidates are separate rows).

## 7. Permission and audit model

| Capability | READ_ONLY | CTI_ANALYST | HYPOTHESIS_WRITER | REPORT_GENERATOR | REVIEWER | ADMINISTRATOR |
|---|---|---|---|---|---|---|
| CanViewCTI | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| CanImportFieldIntel | – | ✓ | – | – | – | ✓ |
| CanReviewFieldIntel | – | – | – | – | ✓ | ✓ |

Client grants are still mandatory for every field-intel call, including for `ADMINISTRATOR`. Audit events are written for mapping approval and for reviewed/rejected batches (no payload, no secrets).

## 8. API surface added

- `POST /api/v1/qradar/import-batches/{batch_id}/review` — `{decision: APPROVED|REJECTED, reason}`; requires `CanReviewFieldIntel`.
- `POST /api/v1/qradar/field-mappings/{mapping_id}/approve` — `{evidence}`; requires `CanReviewFieldIntel`.
- `POST /api/v1/qradar/import-file` now also requires `CanImportFieldIntel`.
- publish now requires `CanReviewFieldIntel`.

## 9. MSSP model validation — BLOCKER (not changed)

`qradar_instances(client_id)` states that an instance belongs to exactly one Atlas client, and `qradar_domains(instance_id)` chains the client through it. A single shared MSSP QRadar console serving several Atlas clients by domain **cannot** be represented: all domains of that console would inherit one client.

Consequence: today the schema supports one console per client only. This is a real limitation, not a data problem, and it was **not** hidden by seed data.

Proposed forward migration (needs review before implementation):

1. `qradar_instances` drops the `client_id` ownership claim (keep a nullable `owner_client_id` for dedicated consoles).
2. New `qradar_instance_clients(instance_id, domain_id, client_id)` mapping table, unique on `(instance_id, domain_id)`.
3. Tenant triggers resolve `client_id` through that table instead of the instance.
4. Backfill from the existing chain before dropping the column.

Until that lands, keep one instance per client and record dedicated consoles only.

## 10. Frontend

`#/fields` now loads strictly by parent ID: Client → Instances → Domains → Log Source Types → Log Sources → QIDs, each selector populated from its parent and disabled when empty. No request is made with an empty required ID. Failures render explicit 400/403/404/503/network states instead of an empty list. The page provides global search, five tabs (Event Catalog, Field Registry, Auto Import, Mapping Inspector, Hunt Readiness), a right-side inspector, an upload form, a redacted preview with candidate mappings and ambiguity flags, and reviewer accept/reject/publish controls.

**Browser acceptance: NOT VERIFIED.** The local browser automation refuses `localhost` by policy, and I did not bypass it. Evidence is limited to `node --check` passing and HTTP 200/401/403 for the endpoints the page calls. No screenshot exists.

## 11. Test evidence

New/extended tests (all passing):

- windows parser + TaskContent XML + redaction-before-persistence (asserts no literal secret survives in stored row JSON or line)
- IIS with `#Fields` (candidate `cs-method → http_method`), IIS without `#Fields` rejected with zero stored rows
- duplicate CSV header rejected; oversized upload rejected
- duplicate upload idempotent (same batch id)
- cross-client denial on import row, import field map and batch read
- `VERIFIED` denied for analyst, denied for impersonation, denied without evidence, allowed for reviewer with evidence
- review refused for a batch with no parsed rows; publish refused before review and on repeat
- mapping approval denied for analyst, allowed for reviewer, origin moves off `auto`
- mapping determinism, collision ambiguity, type mismatch, unknown field
- full M7-D Phase 1 + M6/M7-A/B/C regression suite

Commands (see §12 for exit codes):

```
go build ./...
go vet ./...
go test -run 'TestM7D_Phase2|TestMapping|TestRedaction|TestParse' -count=1 .
go test -timeout 900s -count=1 ./...
go test -race -run TestM7D_Phase2 -count=1 .
node --check frontend/v3/v3.js
```

Live acceptance against a disposable DB (`%TEMP%\fi2.db`):

| Check | Result |
|---|---|
| health | 200 |
| owner list instances | 200 |
| other client's instances | 403 |
| upload Windows fixture | 201, `MAPPED`, 1 row, redactions recorded |
| stored row | redacted only (`[REDACTED_IP]`, `[REDACTED_USER]`, `[REDACTED_PASSWORD]`) |
| candidates | `EventID→event_id`, `TaskName→task_name` |
| review as CTI_ANALYST | 403 |
| review as REVIEWER | 200 → `REVIEWED` |
| publish as REVIEWER | 200 → `PUBLISHED` |

## 12. Exit codes

| Command | Exit |
|---|---|
| `go build ./...` | 0 |
| `go vet ./...` | 0 |
| targeted `TestM7D_Phase2/Mapping/Redaction/Parse` | 0 |
| full `go test -timeout 900s -count=1 ./...` | 0 |
| `go test -race -run TestM7D_Phase2 -count=1 .` | 0 |
| `node --check frontend/v3/v3.js` | 0 |

## 13. Remaining limitations

- Browser acceptance not performed (§10).
- MSSP shared-console tenancy not representable (§9).
- Redaction is pattern-based; it is not a proof of anonymisation.
- Parsers cover the declared formats only; unknown formats are rejected rather than guessed.
- AQL verification is manual attestation; no query is executed, and none is claimed to be.
- No separate write capability for the plain registry CRUD routes (they still use `CanViewCTI` + grant); only import/review/approve were split.

## 14. Phase 2A GO/NO-GO and Phase 2B prerequisites

**GO** for the registry, hardened import, candidate mapping, review/publish and permission split, on the evidence above.
**NO-GO** on the two open items: browser acceptance, and the MSSP tenancy model.

Before Phase 2B:

1. Decide the MSSP tenancy migration (§9) and schedule it.
2. Provide an approved browser test origin, or accept manual UI verification.
3. Confirm the review policy: who may approve, whether self-review is permitted, and the retention period for redacted samples.
4. Decide whether registry CRUD also needs the write capability split.

---

# Final security gate (second review round)

## A. Service-level authorization

Capability checks now live in the services, not only in HTTP middleware:

| Service | Gate |
|---|---|
| `ProcessImportFile` | `CanImportFieldIntel` + client grant |
| `CreateQRadarImportBatch` | `CanImportFieldIntel` + client grant |
| `CreateQRadarImportFieldMap` | `CanImportFieldIntel` + batch-owner grant |
| `ReviewQRadarImportBatch` | `CanReviewFieldIntel` + batch-owner grant |
| `PublishQRadarImportBatch` | `CanReviewFieldIntel` + batch-owner grant |
| `ApproveQRadarFieldMapping` | `CanReviewFieldIntel` + mapping-owner grant |
| `CreateQRadarFieldObservation` (VERIFIED) | `CanReviewFieldIntel` + self-identity + evidence |

HTTP routes additionally require `CanImportFieldIntel` on import-batch creation,
field-map creation and file upload, and `CanReviewFieldIntel` on review, publish
and mapping approval. Direct service callers and future MCP tools get the same
answers because the check is inside the service.

`TestGate_*` covers READ_ONLY, CTI_ANALYST, REVIEWER and ADMINISTRATOR, granted and
foreign clients, and unknown batch identifiers (unknown and foreign both surface as
not-found, never as "exists for another client").

## B. Trusted redaction write path

`CreateQRadarImportRow` was **removed**. Row payloads (`redacted_line`,
`parsed_json`, `field_names`, `field_types`) can only be written by the import
transaction, after parsing and redaction. There is no exported function that
accepts caller-supplied text for those columns, so the redaction guarantee cannot
be bypassed through the service layer.

`CreateQRadarImportFieldMap` remains (it stores mapping metadata, not payload) but
now rejects: empty/oversized raw field names, CEP targets not in the catalogue,
and confidence values outside `high|medium|low`.

`TestGate_ImporterIsOnlyWriter` uploads a hostile line containing a username,
password, IP and bearer token and asserts none of those literals appear in the
stored row.

## C. Immutable review provenance (migration 0013)

New append-only tables, `0011`/`0012` untouched:

- `qradar_import_reviews(batch, client, reviewer, decision, evidence, previous_status, new_status, created_at)`
- `qradar_mapping_reviews(mapping, client, reviewer, decision, evidence, mapping_version, created_at)`

Both carry `BEFORE UPDATE` / `BEFORE DELETE` triggers that `RAISE(ABORT)`, so
history cannot be rewritten even by direct SQL.

Behaviour:

- Review and publish write their history row **and** an `audit_log` row inside the
  same transaction. An audit failure rolls the decision back instead of losing the
  audit trail.
- Evidence must be at least 12 characters and is rejected when generic
  (`ok`, `approved`, `lgtm`, `n/a`, `test`, …).
- Repeating the same decision is idempotent and adds no history row; a different
  decision after review returns **409 CONFLICT** and the earlier approval stands.
- Mapping approval is immutable: repeat by the same reviewer is idempotent, a
  different reviewer gets 409. The approved row keeps its `mapping_version`, and
  later imports create new candidate rows rather than editing it.

## D. Frontend evidence integrity

- The hardcoded `'approved in Field Intelligence UI'` and
  `'reviewed in Field Intelligence UI'` strings are gone. Review and approval now
  require a typed evidence reference (placeholder plus a 12-character client-side
  check; the server re-validates).
- Upload copy corrected: the browser sends the file to the on-premise Atlas
  backend, which parses and redacts before the database write. No browser-side
  redaction is claimed.

## E. MSSP tenancy

Design proposal written to `docs/M7_D_MSSP_TENANCY_DESIGN.md`
(instance identity, domain bindings, unique `(instance, native domain id)`,
per-domain client, migration order, unassigned/shared handling, verification
gates). **Not implemented**, by instruction.

## F. What changed in this round

| File | Change |
|---|---|
| `migrations/0013_field_intel_review_history.sql` | new append-only history tables + triggers |
| `backend/rbac.go` | `requireFieldCapability` used by services |
| `backend/field_import.go` | service-level capability gates, evidence validation, transactional history + audit, immutable mapping approval, field-map input validation; `CreateQRadarImportRow` removed |
| `backend/field_intel.go` | `ErrFieldConflict`; import-batch creation gated |
| `backend/hunt_handlers.go` | `ErrFieldConflict` → 409 |
| `backend/main.go` | `CanImportFieldIntel` on import-batch / field-map creation; 0013 in seed path |
| `backend/field_intel_gate_test.go` | new: 10 gate tests |
| `frontend/v3/v3.js` | real evidence inputs, corrected upload wording |
| `docs/M7_D_MSSP_TENANCY_DESIGN.md` | new design gate |

## G. Remaining blockers (unchanged)

1. Browser acceptance: the local browser automation refuses `localhost`; the page
   is verified only by `node --check` and endpoint behaviour. NOT VERIFIED.
2. MSSP shared-console tenancy: design only.
3. Redaction remains pattern-based, not an anonymisation proof.


---

# Gate results (live, isolated server on :8080, DB `%TEMP%\fi6.db`)

## Browser acceptance вЂ” now VERIFIED

The local browser automation reached `localhost:8080` this round (the earlier refusal was not a policy block). Real flow performed:

1. `login.html` в†’ `analyst-alpha` / `client-alpha` в†’ session established (CTI_ANALYST).
2. Sidebar в†’ Field Intelligence (`#fields`) rendered.
3. Cascade exercised with real parent IDs: Client `client-alpha` в†’ Instance `QRadar-Alpha` в†’ Domain `Corporate (production)` в†’ DSM `Microsoft Windows Security Event Log` в†’ Log source `CONNECTED вЂў qls-stagef-win` в†’ Event `Scheduled Task Created вЂў qid-stagef-4698`.
4. Mapping Inspector: row `EventCode в†’ event_id`, badge CANDIDATE; inspector shows the **Approval evidence** input and the reviewer-only approve button.
5. Auto Import: batch `Synthetic Windows Export 2026-01 вЂў MAPPED`, `rows 1 / rejected 0 вЂў redactions 3`; inspector shows parser `parse-1/windows`, redaction `redact-1`, parsed/rejected `1 / 0`, redacted values `3`.

Screenshots were captured for each state (viewport).

## Live HTTP gate matrix (CSRF enforced)

| Request | Result |
|---|---|
| analyst approves a mapping | 403 |
| reviewer approves with `ok` | 400 |
| reviewer approves with real evidence | 200 |
| reviewer repeats the same approval | 200 (idempotent, no new history row) |
| admin approves the same mapping | 409 |
| analyst reviews a batch | 403 |
| reviewer reviews with `lgtm` | 400 |
| reviewer approves a batch with evidence | 200 в†’ REVIEWED |
| reviewer repeats the approval | 200 |
| reviewer flips to REJECTED | 409 |
| reviewer publishes | 200 в†’ PUBLISHED |
| second publish | 400 |

A defect was found by this live pass: the review handler still decoded `reason` while the service required `evidence`, so every real review returned 400. Fixed in `field_handlers.go`, rebuilt, and the matrix above is from the fixed binary.



---

# Scope correctness patch (final)

## 1. Import identity contract

Canonical identity: **`(client_id, domain_id, source_type, file_hash)`**.

- Enforced by `UNIQUE INDEX idx_qradar_import_batches_identity` (migration 0014) and by the pre-insert lookup in `ProcessImportFile`; the two agree by construction.
- The old `(client_id, file_hash)` index is dropped by the same migration.
- A Log Source ID is deliberately **not** in the key: it is unknown at upload time (the operator uploads a domain-scoped export), and a nullable key column would make uniqueness depend on NULL semantics. Log-source binding belongs to mapping/experiments.
- `source_type` is in the key because the same bytes parsed as CSV and as IIS are different operations with different parser semantics.
- `parser_version` is recorded as provenance on the batch. A replay returns the stored batch unchanged; the reviewer sees which parser produced it, so stale parse semantics cannot be published silently.
- The duplicate lookup runs only after the client grant is checked, so a revoked grant cannot be used to probe for an existing batch.

### Live verification (isolated server, DB `%TEMP%\fi7.db`)

| Case | Result |
|---|---|
| same file в†’ same domain, twice | same batch `qib-820269bcb28c302d` (idempotent) |
| same file в†’ second domain of the same instance | distinct batch `qib-78f8756b8130ba21`, identical `file_hash` |
| total batches for the client | 3 (seed + corporate + dmz) |

### Tests added (`backend/field_intel_scope_test.go`)

1. same domain replay is idempotent (same batch id)
2. different domain в†’ distinct batches, each owning its own rows
3. different source type в†’ no reuse (and a CSV body declared as generic text is rejected on its own merits)
4. different clients в†’ isolated batches
5. concurrent/sequential duplicate submissions converge; the unique index rejects a forced duplicate row
6. revoked grant в†’ replay denied before lookup (`ACCESS_DENIED`)
7. observations stay bound to their domain; a field from another domain is refused

## 2. Registry write authorization

Every `POST /api/v1/qradar/*` now requires a write capability, and the same check
exists inside the service:

| Route | Capability |
|---|---|
| `/instances`, `/domains`, `/log-source-types`, `/log-sources`, `/qids` | `CanImportFieldIntel` |
| `/field-definitions`, `/field-mappings` | `CanImportFieldIntel` |
| `/field-observations` | import **or** review (a VERIFIED row is a reviewer attestation; the service enforces `CanReviewFieldIntel` + identity + evidence for `VERIFIED`) |
| `/import-batches`, `/import-file`, `/import-field-maps` | `CanImportFieldIntel` |
| `/import-batches/{id}/review`, `/publish`, `/field-mappings/{id}/approve` | `CanReviewFieldIntel` |
| `/import` (legacy inventory) | `IsAdministrator` (pre-existing) |

Service-level gates: `CreateQRadarInstance`, `CreateQRadarDomain`,
`CreateQRadarLogSourceType`, `CreateQRadarLogSource`, `CreateQRadarQID`,
`CreateQRadarFieldDefinition`, `CreateQRadarFieldMapping`,
`CreateQRadarFieldObservation`, `CreateQRadarImportBatch` all check the
capability before touching the database or reading any foreign record.

`READ_ONLY` and `HYPOTHESIS_WRITER` hold neither capability, so they cannot write
registry metadata even with a client grant. Verified by
`TestRegistryWrite_RequiresImportCapability` and live: reviewer `POST /instances`
в†’ **403**.

A real defect was found while wiring this: recording an observation with an empty
`verified_by` produced a foreign-key violation (empty string is not a user id).
Empty timestamp/verified-by/evidence values are now stored as NULL.

## 3. Migration upgrade compatibility

`TestMigrationUpgrade_From0011` builds a disposable SQLite database at **0011**,
inserts a client, user, instance, domain and a legacy batch, then applies
`0012`, `0013`, `0014` through the real `runMigration` runner and asserts:

- the legacy batch row is preserved with its original name and status;
- added columns exist and default to 0 (`parsed_rows`, `redacted_values`);
- the identity index exists and the old `file_hash` index is gone;
- tenant triggers still reject a client/domain mismatch;
- review-history tables accept a row and reject `UPDATE` (append-only holds after upgrade);
- `PRAGMA foreign_key_check` reports no rows and `PRAGMA integrity_check` = `ok`;
- re-running all three migrations is a recorded no-op.

`TestMigrationUpgrade_FailureRollsBack` runs a deliberately broken migration
through the same runner and asserts the probe table does not exist, pre-existing
data is intact, and nothing was recorded in `schema_migrations` вЂ” i.e. the
transactional runner leaves the original state untouched.

No dev reset is required: the upgrade is additive except for dropping the old
unique index, which is re-created with a strictly wider key. If a pre-existing
database already contains rows that collide on the new key, index creation fails,
the transaction rolls back, and that is reported as a blocker rather than
resolved by deleting data.

## 4. Shared QRadar console

`docs/M7_D_MSSP_TENANCY_DESIGN.md` was verified against the schema and corrected:
deriving the native Domain ID from `domain_name` is rejected; inferred bindings
must be stored as `UNASSIGNED`/unverified and excluded from tenant-sensitive
operations until an operator confirms them. The prerequisite list is in В§"Design
verification" of that document. **Not implemented.**

## 5. Verification (final code state)

| Command | Exit |
|---|---|
| `go vet ./...` | 0 |
| `go test -timeout 900s -count=1 ./...` | 0 вЂ” `ok 318.342s` |
| `go test -race -run 'TestImportIdentity\|TestRegistryWrite\|TestMigrationUpgrade\|TestGate\|TestM7D_Phase2\|TestMapping\|TestRedaction\|TestParse'` | 0 |
| `node --check frontend/v3/v3.js` | 0 |

`storage/workbench.db` was not opened; all runs used disposable `%TEMP%` databases.

## 6. Updated GO/NO-GO

**Phase 2A: GO.** Import identity is domain-scoped and enforced in both SQL and
Go; registry writes are capability-gated in routes and services; the 0012вЂ“0014
upgrade is proven on a populated 0011 database with integrity checks and rollback
behaviour.

Open (not blockers for Phase 2A, blockers for MSSP multi-client deployment):

1. Shared-console tenancy is design + prerequisites only.
2. Redaction remains pattern-based, not an anonymisation proof.
3. Registry reads still use `CanViewCTI`; only writes/trust decisions were split.



---

# Phase 2A.1 вЂ” Shared QRadar Console, Native Domain IDs, Tenant Bindings

Status: implemented and verified. Phase 2B not started.

## 1. What changed

| File | Change |
|---|---|
| `migrations/0015_qradar_domain_bindings.sql` | new: native domain identity, `qradar_domain_bindings`, append-only `qradar_domain_binding_history`, backfill of legacy domains as UNASSIGNED, atomic replacement of the four tenant triggers |
| `backend/domain_binding.go` | new: types, `ClientOfDomain`, `requireDomainAccess`, domain-of-X resolvers, `ListDomainBindings`, `UpdateDomainBinding`, `ListDomainBindingHistory` |
| `backend/field_intel.go` | every field-intel service now authorizes through the binding; `ListQRadarInstances` union rule; `GetQRadarImportBatch` via `batchClient`; nested domains resolved by parent chain |
| `backend/field_import.go` | `batchClient` verifies historical attribution against the current binding; concurrent import converges on a unique-index race |
| `backend/field_handlers.go` / `main.go` | binding list / update / history endpoints; `CanManageQRadarBindings` route |
| `backend/rbac.go` | `CanManageQRadarBindings` (ADMINISTRATOR only), `canManageBindings`, `authorizedClientsSet` |
| `backend/hunt_handlers.go` | 403/409/400 mapping for binding errors |
| `backend/domain_binding_test.go` | 10 scenario tests covering the security matrix |
| `backend/import_concurrency_test.go` | genuinely concurrent import test |
| `backend/field_intel_scope_test.go` | upgrade test extended to 0015 |
| `backend/main.go` (seed) | synthetic shared-console demo: verified domain 5 в†’ client-alpha, legacy domain with inferred client-beta and no native ID |
| `frontend/v3/v3.js` | admin-only **Domain Bindings** tab with native ID, client, evidence, confirm and history |
| `docs/M7_D_MSSP_TENANCY_DESIGN.md` | rewritten as the implemented contract (native ID never inferred from `domain_name`) |

## 2. Import identity and provenance

Unchanged contract: `(client_id, domain_id, source_type, file_hash)`. What was
added is integrity checking on read: a batch whose `client_id` disagrees with the
domain's current binding returns `409 CONFLICT` and is never re-attributed. The
historical row keeps its original client, domain and timestamps.

## 3. Security matrix (tests and live)

| # | Scenario | Test | Live |
|---|---|---|---|
| 1-5 | one console, domains 5/8 в†’ alpha/beta, no cross reads | `TestPhase21_TwoClientsTwoDomains` | alpha sees 1 domain, beta sees 1 after binding; cross reads 403 |
| 6 | one user with both grants is argument-scoped | `TestPhase21_UserWithBothGrantsIsScoped` | вЂ” |
| 7 | admin without grant cannot read telemetry | `TestPhase21_AdminNeedsGrantForTelemetry` | вЂ” |
| 8-10 | UNASSIGNED / SHARED / missing binding deny | `TestPhase21_UnassignedSharedMissingDeny` | unassigned DMZ read 403 for alpha and beta |
| 11-13 | native ID format, duplicate per instance, same ID on two consoles | `TestPhase21_NativeDomainIDRules` | вЂ” |
| 14 | revoked grant denies immediately | `TestPhase21_RevokedGrantDenies` | вЂ” |
| 15-16 | historical attribution frozen; cross-client references refused | `TestPhase21_HistoricalBatchAndCrossReferences` | вЂ” |
| 17 | import idempotency stays domain-scoped | `TestPhase21_ImportIdentityStillDomainScoped` | same-file/different-domain produced distinct batches in 2A |
| 18 | reassignment keeps immutable history | `TestPhase21_ReassignmentHistoryImmutable` | history shows rev 1 UNASSIGNED в†’ rev 2 CLIENT client-beta |
| 19 | concurrent confirmation | `TestPhase21_ConcurrentBindingConfirmation` | вЂ” |
| 20 | direct SQL cannot bypass the binding | `TestPhase21_DatabaseEnforcement` | вЂ” |

Live binding flow (isolated `%TEMP%\p21.db`, server on :8080):

| Check | Result |
|---|---|
| admin lists bindings | 2 (verified alpha domain; unassigned legacy domain with inferred client only) |
| beta lists domains before confirmation | 0 |
| alpha lists domains | 1 (its own) |
| beta / alpha read unassigned DMZ | 403 / 403 |
| admin confirms DMZ в†’ native 8, client-beta, evidence | 200 |
| beta lists domains after | 1 (DMZ), alpha still 1 (Corporate) |
| beta / alpha read DMZ after | 200 / 403 |
| binding history | 2 append-only entries |
| analyst attempts the same confirmation | 403 |

## 4. Concurrency

`TestImportIdentity_TrulyConcurrentSubmissions` runs six goroutines through the
real importer against one domain. Exactly one batch exists afterwards, all
callers receive the same id, the batch is `MAPPED` (never a partial `PENDING`),
and it owns exactly one row. The losing inserters converge by re-reading the
identity after the unique-index conflict.

## 5. Frontend

An admin-only **Domain Bindings** tab shows, per instance: domain, native ID and
status, binding kind, bound client, inferred legacy client, verifier, evidence and
revision, plus a confirm form (native ID, kind, client, evidence, expected
revision) and the append-only history. Verified in the browser: both domains
listed as `native 5 в†’ client-alpha` and `native 8 в†’ client-beta`, badge VERIFIED.

## 6. Migration validation

`TestMigrationUpgrade_From0011` now runs 0011 в†’ 0015 through the real runner on a
populated database and asserts: legacy rows preserved, identity index replaced,
tenant triggers active, review history append-only, **legacy domain backfilled as
UNASSIGNED/UNVERIFIED with the old client only as `inferred_client_id`**, native
ID left empty (never derived from the label), a batch insert for that unverified
domain refused, binding history usable and append-only, `foreign_key_check` empty,
`integrity_check = ok`, reruns are recorded no-ops.

## 7. Verification

| Command | Exit |
|---|---|
| `go build ./...` | 0 |
| `go vet ./...` | 0 |
| `go test -timeout 900s -count=1 ./...` | 0 |
| `go test -race` (Phase 2A.1 + Phase 2 + gate + migration sets) | 0 |
| `node --check frontend/v3/v3.js` | 0 |
| browser acceptance on isolated server | PASS (bindings tab, both domains, cross-tenant denial) |

## 8. Capability classification

| Capability | State |
|---|---|
| Domain bindings schema + history (0015) | IMPLEMENTED / TESTED |
| Central resolver and all service consumers | IMPLEMENTED / TESTED |
| Binding-based tenant triggers (atomic cutover) | IMPLEMENTED / TESTED |
| Administrator binding API + audit | IMPLEMENTED / TESTED |
| Admin bindings UI | IMPLEMENTED / TESTED (browser verified) |
| Historical attribution integrity | IMPLEMENTED / TESTED |
| Native ID validation/uniqueness | IMPLEMENTED / TESTED |
| Truly concurrent import convergence | IMPLEMENTED / TESTED |
| Automatic native-ID discovery from QRadar API | NOT IMPLEMENTED (no live API in scope) |
| Dropping legacy `qradar_instances.client_id` | NOT IMPLEMENTED (deliberate, destructive) |

## 9. Remaining blockers / risks

- Legacy `qradar_instances.client_id` still exists. It no longer grants domain
  access, but it is still used to gate *domain creation* on a console and to list
  instances. Removing it needs its own migration.
- An administrator must enter native domain IDs manually with evidence; nothing
  reads them from QRadar yet.
- The seed's synthetic "legacy" domain demonstrates reconciliation; real legacy
  data must be confirmed by an operator before use.
- Redaction remains pattern-based (unchanged from 2A).

## 10. Phase 2A.1 GO/NO-GO

**GO.** No unverified domain is treated as client-owned, cross-client reads are
denied at service, HTTP and database level, historical attribution is never
rewritten, migration integrity is proven on a populated 0011 database, and
browser acceptance was performed.



---

# Phase 2A.1 trust patch вЂ” domain creation and native-ID requirements

Two P0 trust-boundary defects were confirmed in independent review and fixed.

## Root causes

1. **Creation implied ownership.** `CreateDomainBinding` inserted
   `CLIENT`/`VERIFIED` on the strength of the creating user, with no native
   QRadar domain id and a generic "created through the registry API" string as
   evidence. A freshly created domain was therefore client-owned before any
   administrator confirmed anything, and a client could import into it
   immediately.
2. **Verification did not require a native id.** `UpdateDomainBinding` accepted
   `CLIENT` + `VERIFIED` with an empty `NativeQRadarDomainID`, and
   `ClientOfDomain` only checked the binding flags вЂ” it never required
   `native_id_status='VERIFIED'`. An empty or unverified id could therefore back
   a tenant ownership claim. `expected_revision` was also optional.

## Fixed invariants

`ClientOfDomain` now requires **all** of:
binding_kind `CLIENT` В· verification `VERIFIED` В· non-empty `client_id` В·
`verified_by`, `verified_at`, `evidence_reference` present В·
`native_qradar_domain_id` non-empty В· `native_id_status = 'VERIFIED'`.

`CreateDomainBinding` writes `UNASSIGNED` / `UNVERIFIED`, no `client_id`, no
verification fields; the creator's client is stored as `inferred_client_id`
(reconciliation only) and a history row records the unverified creation.

`UpdateDomainBinding` now requires: binding-management capability В· real evidence
(в‰Ґ12 chars, not generic) В· kind/client consistency В· `expected_revision` > 0 and
matching В· for `CLIENT`, either a valid native id in the request **or** an
already-`VERIFIED` native id on the domain row В· digits-only id, unique per
console. It never promotes a binding from an empty or unverified id.

`CreateQRadarDomain` no longer calls the authorized getter; it returns the newly
created domain (still `UNASSIGNED`) so the creator can see what they created
without being granted ownership.

## Migration 0016 (forward, 0001вЂ“0015 untouched)

Database-level UPDATE guards, so a service bug or direct SQL cannot produce an
inconsistent state:

- binding `domain_id`/`instance_id` immutable;
- kind and client must agree on update;
- `VERIFIED` requires actor + timestamp + non-empty evidence;
- `VERIFIED CLIENT` requires a `VERIFIED`, non-empty native id on the domain;
- a native id used by a verified client binding cannot be cleared or invalidated;
- a `VERIFIED` native id cannot exist without an id and a provenance source
  (insert and update guards).

## Tests added (`backend/domain_trust_test.go`)

| # | Test |
|---|---|
| 1-2 | `TestTrust_NewDomainIsUnassigned` вЂ” new domain is UNASSIGNED/UNVERIFIED, no client, no native id, creator client only inferred |
| 3-4 | `TestTrust_NoClientOperationsBeforeConfirmation` вЂ” import, field definition, log source type and client read all refused |
| 5 | `TestTrust_ConfirmationRequiresNativeDomainID` вЂ” 400 and binding unchanged |
| 6 | `TestTrust_InvalidNativeDomainIDRejected` вЂ” label, negative, alphanumeric, oversized, blank, hex |
| 7-8 | `TestTrust_AccessOnlyAfterConfirmation` |
| 9 | `TestTrust_RevokingVerificationBlocksImmediately` |
| 10 | `TestTrust_RebindingNeverTransfersBatches` |
| 11 | `TestTrust_DirectSQLCannotBypassBinding` вЂ” five direct-SQL attempts |
| 12 | `TestTrust_UnverifiedNativeIDCannotBackABinding` |

Existing Phase 2A / 2A.1 suites were updated to confirm bindings explicitly before
client-scoped operations (`mkDomain` helper) rather than weakening the resolver,
and the synthetic seed now performs the same two-step flow (unverified creation,
then an administrator confirmation) instead of inserting a pre-verified binding.

## Live lifecycle (isolated server, `%TEMP%\trust.db`)

| Step | Result |
|---|---|
| analyst creates domain | `UNASSIGNED` / `UNVERIFIED`, native `UNVERIFIED` |
| import before confirmation | 403 |
| client read of field definitions before confirmation | 403 |
| admin confirms without native id | 400 |
| admin confirms with native id 9 + evidence | 200 |
| client read after confirmation | 200 |
| import after confirmation | 201 |
| admin revokes to UNASSIGNED | 200 |
| client read after revocation | 403 |
| import after revocation | 403 |

Browser: Domain Bindings shows `Corporate вЂў native 5 вЂў CLIENT client-alpha вЂў revision 2 вЂў VERIFIED`,
`DMZ вЂў native unverified вЂў UNASSIGNED вЂў inferred client-beta (not authoritative)`,
`Finance вЂў native 9 вЂў UNASSIGNED вЂў inferred client-alpha вЂў revision 3` вЂ” the
revoked domain keeps its verified native id but no longer carries a client claim.

## Verification

| Command | Exit |
|---|---|
| `go build ./...` | 0 |
| `go vet ./...` | 0 |
| `go test -timeout 900s -count=1 ./...` | 0 |
| `go test -race` (trust + 2A.1 + 2A + migration sets) | 0 |
| `node --check frontend/v3/v3.js` | 0 |
| browser lifecycle check | PASS |

## Remaining limitations

- Native ids are entered by an administrator with evidence; nothing reads them
  from the QRadar API yet.
- The legacy `qradar_instances.client_id` remains for console creation/listing and
  grants nothing on its own.
- A domain keeps its verified native id after revocation; the ownership claim, not
  the identity evidence, is what is withdrawn.

