# M7-D Phase 2B — Gate 1 (2B-1 Sigma ingestion, 2B-2 client readiness)

Status: **2B-1 and 2B-2 implemented and verified. 2B-3 (pySigma worker) and 2B-4 (Hunt Workspace UI) NOT started**, per the stop gate.

## 1. Scope of this gate

| Milestone | State |
|---|---|
| 2B-1 Sigma ingestion, versioned immutable storage, safe parsing | IMPLEMENTED / TESTED |
| 2B-2 client telemetry resolution + field mapping readiness | IMPLEMENTED / TESTED |
| 2B-3 IBM pySigma worker + AQL draft generation | NOT IMPLEMENTED (blocked by gate) |
| 2B-4 Hunt Workspace UI, Hunt Plans, reviewer flow | NOT IMPLEMENTED (blocked by gate) |
| AQL execution / QRadar API / rule deployment | NOT IMPLEMENTED (excluded) |

## 2. Existing entities reused (nothing duplicated)

- `clients`, `users`, `user_authorized_clients`, RBAC capabilities, audit log, migration runner.
- `qradar_instances`, `qradar_domains`, `qradar_domain_bindings` (+ history) — the only ownership source.
- `qradar_log_source_types`, `qradar_log_sources`, `qradar_qids`.
- `qradar_field_definitions`, `qradar_field_mappings` (approved/versioned), `qradar_field_observations` (manual AQL attestation).
- CEP catalogue and normalisation from `field_mapping.go`.

No second field registry, mapping table, approval model or ownership model was introduced.

## 3. Forward migration

`migrations/0017_sigma_detection_ingestion.sql` (additive; 0001–0016 untouched):

- `sigma_detection_sources` — client, kind (`MANUAL_UPLOAD` / `CTI_REPORT_ATTACHMENT` / `CONNECTOR`), optional report, filename, SHA-256, size, actor.
- `sigma_detection_rules` — immutable rule versions: `sigma_rule_id`, `version` (unique per client+rule), title/status/level/author, logsource product/category/service, `condition_expr`, tags/modifiers/fields JSON, original YAML, YAML hash, size, actor. Unique `(client_id, yaml_sha256)` makes re-upload idempotent.
- BEFORE UPDATE/DELETE triggers on both tables → stored detections cannot be edited or deleted.
- BEFORE INSERT guard → id, title, condition, YAML and hash are mandatory at the storage boundary.

Table names carry the `sigma_` prefix because `detection_rules` already exists as the QRadar inventory table (M7-C) — a real collision found by the tests, not renamed for taste.

## 4. Sigma ingestion contract

`IngestSigmaRule(userID, clientID, reportID, filename, yaml) (*SigmaRule, error)`

- Capability `CanManageDetections` (CTI_ANALYST, ADMINISTRATOR) **and** client grant.
- `report_id`, when given, must exist and belong to the same client.
- Size bound 512 KiB; YAML parsed as data (`go.yaml.in/yaml/v3`), never executed.
- Required: `id`, `title`, `detection`, non-empty `detection.condition`, at least one selection; condition tokens must reference existing selections.
- Extracted and stored: id, title, status, description, author, level, logsource product/category/service, condition, tags (bounded), base field names, modifiers (including unknown ones, recorded for 2B-3), original YAML + SHA-256.
- Idempotent on identical bytes; changed content for the same `sigma_rule_id` becomes `version = max+1`; earlier versions stay untouched.
- Audit event `SIGMA_INGEST` written in the same transaction as the insert.

Reads: `GetSigmaRule`, `ListSigmaRules` — client grant enforced.

## 5. Readiness analysis (2B-2)

`AnalyzeDetectionScope(userID, clientID, ruleID) (*DetectionScope, error)`

Eligible domains come only from bindings satisfying the full trust invariant (CLIENT + VERIFIED + actor/time/evidence + verified non-empty native domain id) for the selected client. Instance ownership, `domain_name`, and inferred attribution are never used.

Per domain:
- **Log source candidates** — QRadar log source types in that domain matched against Sigma logsource tokens (windows/security/sysmon/iis/linux/…). Every match is labelled `CANDIDATE`; no equivalence is asserted. Empty match ⇒ `TELEMETRY_UNKNOWN`.
- **Field readiness**, per Sigma field:
  | State | Meaning |
  |---|---|
  | `AQL_MANUALLY_ATTESTED` | approved mapping **and** a reviewer-attested observation with evidence |
  | `MAPPING_APPROVED` | approved mapping, no attestation |
  | `CEP_DISPLAYED` | QRadar property observed, no approved mapping |
  | `RAW_OBSERVED` | field definition exists only |
  | `UNVERIFIED` | mapping exists, unapproved |
  | `CONFLICTING_MAPPINGS` | more than one target or more than one approved mapping |
  | `MISSING` | no mapping for this client/domain |
  | `UNSUPPORTED` | reserved for constructs 2B-3 cannot represent |

Domain status: `READY_FOR_REVIEW` only when every field is attested and a log source candidate exists; otherwise `NEEDS_FIELD_VERIFICATION`, `TELEMETRY_UNKNOWN`, `UNSUPPORTED` or `BLOCKED` (no verified binding at all). Overall status is the worst domain status.

Mapping approval alone never yields `AQL_MANUALLY_ATTESTED`; the API is read-only and reports no execution.

## 6. API contracts (OpenAPI-style summary)

| Method | Path | Auth | Body / Query | Response |
|---|---|---|---|---|
| POST | `/api/v1/detections/sigma` | `CanViewCTI` + `CanManageDetections`, CSRF | `{client_id, report_id?, filename?, sigma_yaml}` | 201 `SigmaRule` |
| GET | `/api/v1/detections/sigma` | `CanViewCTI` | `?client_id=` | `{rules, count}` |
| GET | `/api/v1/detections/sigma/{rule_id}` | `CanViewCTI` | — | `SigmaRule` |
| GET | `/api/v1/detections/sigma/{rule_id}/scope` | `CanViewCTI` | `?client_id=` | `DetectionScope` |

Errors: 400 `SIGMA_INVALID` / `VALIDATION_ERROR`, 403 `FORBIDDEN`/`DOMAIN_NOT_ASSIGNED`, 404 `NOT_FOUND`, 409 `CONFLICT`.

## 7. IBM pySigma findings (for 2B-3, not implemented)

Verified from the upstream repositories:

| Fact | Value |
|---|---|
| `pySigma-backend-QRadar-AQL` version | `0.3.2` (Poetry) |
| `pySigma_QRadar_base` version | `0.1.0` |
| Python | `^3.10` |
| pySigma | `>=0.9.8,<0.12.0` (backend), `>=0.9.6,<0.12.0` (base) |
| Extra deps | `regex ^2023.12.25`; security floors `requests>=2.33.0`, `urllib3>=2.8.0`, `certifi>=2026.10.18`, `idna>=3.15` |
| License | MIT (both packages) |
| Field-mapping extension point | `QRadar_fields_pipeline(base_pipeline_items, field_mapping)` in `QRadarFieldsPipeline.py`, which adds a `FieldMappingFailureTransformation` raising `SigmaTransformationError` for fields absent from the provided mapping dict |

Consequences for 2B-3: client-specific mapping can be supplied as a dict without forking IBM code, and unsupported fields fail loudly (aligning with "never silently drop a condition"). The exact dict shape and how per-DSM payload pipelines interact must be confirmed against the installed version at integration time; that remains a 2B-3 verification item, not a claim.

## 8. Tests

`backend/detection_test.go` (14 tests), all executed and green:

- parsing: valid rule metadata/logsource/condition/tags/hash; seven malformed variants; oversized; idempotent duplicate; versioned change; unknown modifier recorded.
- isolation: cross-client read/analyse/ingest denied; revoked grant denied; unverified domain excluded from scope; revoked binding removes the domain.
- readiness: attested field, approved-only field, unmapped field, conflicting mappings, multiple log source candidates stay `CANDIDATE`.
- persistence: rules immutable (UPDATE/DELETE rejected), READ_ONLY ingest denied, HTTP 403/201 and cross-client scope 403.
- migrations: upgrade test now runs 0011→0017 on a populated database.

## 9. Verification results

| Command | Result |
|---|---|
| `go build ./...` | 0 |
| `go vet ./...` | 0 |
| `go test -timeout 900s -count=1 ./...` | 0 |
| `go test -race` (Sigma + trust + 2A.1 + migration sets) | 0 |
| `node --check frontend/v3/v3.js` | 0 |
| live API acceptance (isolated `%TEMP%\sigma.db`) | see §10 |

## 10. Live acceptance

| Check | Result |
|---|---|
| `POST /detections/sigma` as CTI_ANALYST | created `drule-…`, `version=1` |
| `GET …/scope?client_id=client-alpha` | domain `Corporate` (native 5, binding revision 2), log source `Microsoft Windows Security Event Log` as `CANDIDATE/CONNECTED`, `EventID`/`CommandLine` = `MISSING`, status `NEEDS_FIELD_VERIFICATION`, modifier `contains` surfaced |
| beta reading alpha's scope | 403 |
| beta ingesting under alpha | 403 |

## 11. Remaining gaps

- No worker, no AQL draft, no Hunt Plan, no UI (2B-3/2B-4, gated).
- Log source matching is token-based and advisory; a curated Sigma-logsource → QRadar-devicetype table is a 2B-3 prerequisite.
- Field readiness ignores modifier semantics (`contains`, `endswith`, …); whether a modifier is representable is a 2B-3 decision and is surfaced today only as a note.
- No OpenAPI file is generated in the repo; the table in §6 documents the contracts.

## 12. GO/NO-GO

**2B-1: GO.** **2B-2: GO.** Both are implemented, isolated by client, immutable in storage, and read-only with respect to QRadar.

**2B-3/2B-4: NOT STARTED** — awaiting explicit authorization.

## 13. Tooling actually used

- `test-driven-development` skill loaded and followed: tests written first, `undefined: IngestSigmaRule` observed as the red state, then implementation.
- No CodeGraph query was executed this session; navigation used targeted `grep`/`read` on the files named in the baseline (the project has an index but it was not queried — stated plainly rather than claimed).
