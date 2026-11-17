# M7-F Phase 1 — Offline-First Manual QRadar Inventory

Scope: make manual QRadar inventory practical for an MSSP without any IBM QRadar
API access. No QRadar API call, no AQL execution, no rule deployment, no binding
auto-confirmation, no mapping auto-approval, no new CTI connector, no Octop.
Disposable databases only; `storage/workbench.db` was not opened.

CodeGraph was used to inventory the schema and services before editing.

## 1. Reusable functionality (nothing duplicated)

| Area | Existing component reused |
|---|---|
| Instances, domains, DSM types, log sources, QIDs, field definitions, mappings, observations | tables from migration 0011 and services in `backend/field_intel.go` |
| Domain ownership | `qradar_domain_bindings`, `ClientOfDomain`, `requireDomainAccess`, `UpdateDomainBinding` |
| Mapping review | `ApproveQRadarFieldMapping`, `qradar_mapping_reviews`, audit transaction |
| Readiness | `AnalyzeDetectionScope`, `oneFieldReadiness`, translation revalidation |
| AQL drafts / Hunt Plans | unchanged; they consume the same inventory |
| Raw telemetry import | existing `qradar_import_batches` pipeline left untouched and separate |
| UI shell | `frontend/v3` navigation, `api.js`, shared helpers |

No second registry and no parallel table for the same concept were created.

## 2. Implemented

### 2.1 Provenance (migration 0022)

Forward migration only; 0001–0021 untouched. Adds `source_category`,
`source_reference`, `entered_by`, `entered_at`, `revision` to the eight inventory
tables, and an append-only `qradar_inventory_revisions` log. `AFTER INSERT`
triggers write the revision in the same transaction as the value, so a crash
cannot separate them. Existing service methods now record `entered_by` for manual
entries; imported rows are `IMPORTED_UNVERIFIED`. Revisions cannot be updated or
deleted (triggers).

### 2.2 Structured import

`POST /api/v1/qradar/inventory/import/preview` and `/commit`, five categories:
`log_source_types`, `log_sources`, `qids`, `field_definitions`, `field_mappings`.
CSV (strict header) or JSON (array of objects, unknown keys rejected). Each
request names client, domain, format and declared source. Bounds: 512 KiB and
2000 rows. Classification per row: `CREATE`, `DUPLICATE`, `CONFLICT`, `ERROR`.

- Preview is a dry run: no writes.
- Commit requires `confirm: true`, re-validates inside one transaction, refuses
  the whole import on any conflict or error, and inserts only `CREATE` rows with
  `source_category = IMPORTED_UNVERIFIED`.
- Exact re-import is idempotent (`duplicate`, `created = 0`).
- A different CEP for an existing/approved mapping is a conflict; approved
  mappings are never rewritten.
- Import never changes bindings, approval state or field attestations.
- Templates: `GET /api/v1/qradar/inventory/import-templates/{kind}`.

### 2.3 Completeness

`GET /api/v1/qradar/inventory/completeness?client_id=` reports, per
client-bound domain: binding, native Domain ID, DSM types, log sources, QIDs,
field definitions, mapping evidence (approved / imported / conflicting / stale)
and reviewer-attested observations. Statuses are `MISSING`, `MANUALLY_ENTERED`,
`IMPORTED_UNVERIFIED`, `APPROVED_MAPPING`, `AQL_MANUALLY_ATTESTED`,
`CONFLICTING`, `STALE`. No percentage is computed and the response states that
counts are not live telemetry.

### 2.4 UI

`frontend/v3/inventory-workspace.js` (new route `#inventory`, Detection
Engineering group): Instances, Domain Bindings, Log Sources, DSM & Event IDs,
Custom Properties, Field Mappings, Import & Preview, Inventory Gaps. It uses the
existing endpoints, renders untrusted text with `textContent`, shows evidence
status badges, blocks commit when conflicts exist, and only offers binding
changes to administrators and mapping review to reviewers. The legacy Field
Intelligence page is unchanged.

## 3. Trust boundaries

- Preview: `CanViewCTI` + client grant + `CanImportFieldIntel`; the domain must
  resolve through `ClientOfDomain` (verified binding) and the claimed client must
  match. Cross-client and unassigned domains are rejected in the service.
- Commit: same, plus CSRF and `confirm`.
- Completeness: `CanViewCTI` + grant; only bindings for the requested client are
  listed.
- Approval remains `CanReviewFieldIntel` + reviewer evidence; imports cannot
  approve.
- Binding changes remain administrator-only with evidence and revision.

## 4. Test matrix

| # | Scenario | Test |
|---|---|---|
| 1 | One console with two client domains | existing `TestM7D_Phase2_*`, `TestDomainBinding*`; import scope tests |
| 2 | Alpha cannot access Beta inventory | `TestInventoryImportRequiresScopeAndGrant`, `TestInventoryCompletenessReport` |
| 3 | Unassigned domain inaccessible | `TestInventoryImportRequiresScopeAndGrant` |
| 4 | Import cannot verify ownership | `TestInventoryImportNeverChangesBinding` |
| 5 | Duplicate import idempotent | `TestInventoryImportCommitIsIdempotent` |
| 6 | Cross-domain import uses a separate identity | `TestInventoryImportUsesTheDomainOwnersIdentity` |
| 7 | Invalid CSV/JSON rejected | `TestInventoryImportValidationAndBounds` |
| 8 | Oversized file rejected | same |
| 9 | Dry run does not mutate | `TestInventoryImportPreviewDoesNotPersist` |
| 10 | Conflict preview does not alter approved mappings | `TestInventoryImportConflictDoesNotRewriteApprovedMapping` |
| 11 | Import failure rolls back atomically | `TestInventoryImportRollsBackAtomically` |
| 12 | Reviewer permission required for approval | existing `TestFieldIntel*`, `TestSecurity_*` |
| 13 | Old provenance available after revision | `TestInventoryRevisionsAreImmutable`, revision log (append-only) |
| 14 | Readiness changes only with evidence | existing `TestPreflight_*`, `TestTranslation_*` |
| 15 | AQL remains domain-scoped | existing `TestAQL_TenantScoping*`, translation tests |
| 16 | Approved Hunt Plans immutable | existing `TestHuntPlan_LifecycleApproveAndImmutable` |
| 17 | Missing inventory is not inferred coverage | completeness returns `MISSING`/0; no score |
| 18 | Browser navigation and tenant isolation | `tests/browser` — inventory test |

## 5. API additions

| Method | Path | Permission |
|---|---|---|
| GET | `/api/v1/qradar/inventory/completeness?client_id=` | `CanViewCTI` + grant |
| GET | `/api/v1/qradar/inventory/import-templates/{kind}` | `CanViewCTI` |
| POST | `/api/v1/qradar/inventory/import/preview` | `CanViewCTI` + `CanImportFieldIntel` + CSRF |
| POST | `/api/v1/qradar/inventory/import/commit` | same, requires `confirm: true` |

## 6. Residual limitations

- Imports create rows and provenance; they do not edit or delete existing rows.
  Corrections are new rows/versions, preserving history.
- `STALE` for mappings is a superseded-version heuristic, not a live drift check.
- There is no QRadar-side drift detection: absence from a file is never treated
  as deletion.
- Custom event properties reuse `qradar_field_definitions` with
  `field_origin = 'custom'`; there is no separate property type.
- The UI creates instances/domains/DSMs/log sources/QIDs/definitions/mappings and
  approves mappings, but does not edit them (append-only evidence model).
- Log source online status is operator metadata; it is not verified.
- Worker/QRadar limitations from earlier phases are unchanged.

## 7. Verification

| Command | Exit |
|---|---|
| `go build ./...` | 0 |
| `go vet ./...` | 0 |
| `go test -timeout 900s -count=1 ./...` | 0 — `ok mssp-workbench 479.7s` |
| `go test -race -run 'TestInventory\|TestHuntPlan\|TestSecurity\|TestHardening\|TestAQL\|TestBackup\|TestProxyTrust\|TestForwarded\|TestMigration\|TestField'` | 0 — `ok mssp-workbench 463.3s`, no data race |
| `go test -race -run 'TestInventory'` (final test set) | 0 — `ok mssp-workbench 138.3s` |
| `node --check frontend/v3/v3.js`, `inventory-workspace.js` | 0 / 0 |
| `npm test` in `tests/browser` | 0 — 11/11, 89.6s |

## 8. GO / NO-GO

**GO for M7-F Phase 1**: manual inventory is manageable end to end (create,
import with preview/conflict/rollback, completeness, readiness integration) with
preserved trust boundaries and no duplicate registry.

**NO-GO** for treating imported metadata as verified, for automatic binding or
mapping approval, for live telemetry claims, and for starting Detection Coverage
Matrix or manual Hunt Results before this gate is accepted.

**Excluded as required:** QRadar API, credentials, AQL execution, rule
deployment, QRadar configuration changes, automatic actions and
`storage/workbench.db`.
