# Sentinel Atlas Verification Contract

## Authority and scope

This contract implements AGENTS.md (Testing Requirements, Documentation Requirements and Definition of Done), TECHNICAL_SPECIFICATION.md, and docs/TESTING_STRATEGY.md. It applies to every implemented module and every release candidate. GitHub is used for this explicitly requested review; it is not a runtime or deployment dependency.

## Verdicts

| Verdict | Required meaning |
| --- | --- |
| REAL PASS | The exact recorded command completed with exit code 0 on the identified revision and environment; assertions actually ran, required scenarios passed, and reviewable evidence exists. The verdict applies only to the recorded scope. |
| FAIL | An executed check failed, timed out, crashed, failed to compile, or violated an assertion. Preserve the actual exit code or explicitly record that no process exit code was captured. |
| NOT VERIFIED | Not executed, missing evidence, missing infrastructure or credentials, incomplete scope, zero relevant tests, skipped required cases, or no successful integration PoC. This is not a pass. |

Never invent commands, exit codes, test counts, coverage, environments, logs or PoC results. A plan, mock, fixture, static inspection, successful build or old report cannot establish a real integration pass. Record historical claims as historical until their evidence is checked against the candidate and environment. A mixed run cannot be labelled green because some individual tests passed. No-test packages and skipped tests must be visible.

## Mandatory record for every module and check

Create one record per module, check type and execution; do not hide failures behind aggregate totals. Split commands into separate records when their exit codes or environments differ.

| Field | Required value |
| --- | --- |
| Identity | Run ID, UTC start/end, operator, module, requirement/specification section and check type (unit/integration/security/acceptance/build/lint/property/model check). |
| Revision | Commit SHA or source archive SHA-256, dirty diff hash if applicable, dependency lockfile hashes and test/config versions. |
| Command | Exact executable and arguments, working directory, setup steps, selected cases, timeout and sanitized environment overrides. |
| Environment | OS/architecture, Go/Node/Python/tool versions as applicable, CGO_ENABLED, C compiler/version, database engine/version, migration version, relevant service/container/model versions and network policy. No secrets. |
| Exit code | Fresh exit code of the check itself, captured immediately; null with reason if no execution or no captured exit. A logging pipeline's exit code is insufficient. |
| Test counts | Discovered, executed, passed, failed and skipped; count named test cases, keep package totals separate and state whether subtests are included. Unknown is null, never an invented zero. Build/lint counts are N/A. |
| Artifacts | Relative paths or stable links plus SHA-256 for raw stdout/stderr, structured runner results, environment manifest and fixtures/config. Add screenshots/traces, database/migration logs, request/response evidence or counterexample traces as applicable. Redact secrets and client data before sharing. |
| Verdict | REAL PASS, FAIL or NOT VERIFIED; reason, limitations, excluded scenarios, owner and next action. |

Retain failed executions and retries independently. Cache-only results do not establish a fresh run: use Go -count=1. A later pass does not erase an earlier failure. Record fixes and a new execution on the new revision.

## Module verification matrix

Commands below are planned entry points, not results. Run from the stated directory. The broad backend command covers multiple modules: map actual named tests to each row before assigning that module REAL PASS. If a required suite or runner does not exist, record NOT VERIFIED and create a tracked gap; do not invent an executable command.

| Module / scope | Command / directory | Required observable evidence |
| --- | --- | --- |
| Backend API, auth/RBAC, tenant management | `go test -json -count=1 -timeout=5m ./...` in `backend` with working CGO toolchain | API validation, authentication, denied permissions, two distinct tenants and cross-tenant read/write denial; tests and package outcomes. |
| Database, migrations, backup/restore | Same backend command; record selected DB tests separately | Real SQLite, WAL/foreign keys, migration integrity, transactional rollback, restore correctness and concurrency. PostgreSQL remains NOT VERIFIED unless separately exercised. |
| CTI ingestion/processing, IOC normalization | Same backend command | Import failures, untrusted documents, normalization/deduplication and provenance; real ingestion path evidence. |
| Adversary Brain, sector/client relevance | Same backend command | Evidence references, tenant-scoped matching and deterministic calculations; record missing scenarios. |
| Hunt hypotheses, plans, cases and analyst feedback | Same backend command | Validation, allowed/forbidden state transitions, version conflicts, approval and audit behavior. Property-based tests record seeds; statechart/TLA+ checks record model/config, checker version and counterexamples. Missing model checks are NOT VERIFIED. |
| Detection coverage, field mapping and translation | Same backend command | Coverage semantics, inventory/client separation and safe AQL drafts; local fixtures do not verify QRadar connectivity. |
| Knowledge, reporting, audit and monitoring | Same backend command | Approval gates, unauthorized trust/publication denial, durable audit and secret redaction. |
| AI orchestration, harness adapters and model providers | Backend command for local contracts; integration-specific PoC command must be recorded | Real adapter task submission, result retrieval, errors/timeouts, execution metadata, API/MCP-only data access and network boundaries. |
| MCP and external CTI connectors | Backend command for local MCP tests; record real transport PoC separately | Identity, role/client_id, operation and volume checks, cross-tenant denial and actual transport exchange. |
| Frontend | `npm ci`, `npm test -- --reporter=json`, `npm run lint`, `npm run build` in `frontend`, each separately | Dependency install outcome, actual test counts, runner report and build/lint output. Missing lockfile/config/tests is a gap, not a waived check. |
| Browser acceptance | `npm ci`, then `npm test` in `tests/browser`, separately | Supported browser/version, disposable database/server configuration, assertion results, screenshots/traces and cleanup. |
| Sigma worker | NOT VERIFIED until a concrete worker test runner is identified | Worker dependency versions, real translation inputs/outputs, invalid input and failure behavior; dependency installation alone is not testing. |
| End-to-end release flow | Record the exact implemented acceptance runner; missing coverage is NOT VERIFIED | CTI import -> IOC/TTP/CVE -> Adversary Brain -> sector/client matching -> QRadar inventory/telemetry -> hypothesis -> AQL draft -> analyst review -> investigation feedback. |

Every row requires the complete record above, including exit code, counts, environment and artifacts. New modules must add a row. Security verification also covers prompt injection, unauthorized files, secret leakage and deny-by-default outbound traffic; local unit tests alone do not establish deployed network isolation.

## Integration PoC gate

Maintain a separate record for QRadar, ThreadLinqs, HarnessRouter, Octop, each other harness, each model provider and each external enrichment service. Without a successful, reviewable PoC for the stated operation and environment, use NOT VERIFIED. An installed CLI, health endpoint, mocked response or historical VERIFIED label is insufficient for an untested operation.

The PoC record includes the exact sanitized command, service/protocol/version, permitted target, test identity/tenant/role, request/response artifacts, success and negative cases, exit code, assertion counts and environment. QRadar is read-only in MVP. Rule deployment, report publication and trusted knowledge changes retain explicit human approval gates; test results do not authorize them.

## CGO_ENABLED=0 baseline: not green

The current reported backend run with `CGO_ENABLED=0` is **NOT GREEN** and must not be counted as passed or used to approve a release. The backend depends on `github.com/mattn/go-sqlite3`; a CGO-disabled build does not prove that real SQLite operations work. Preserve the failed execution, actual exit code and counts when available. The assignment's report is not a substitute for its raw logs, and missing historical values remain unknown.

Re-run with a supported C compiler and `CGO_ENABLED=1`, recording `go version`, `go env GOOS GOARCH CGO_ENABLED CC`, compiler version and database evidence. Do not skip DB/security tests, replace SQLite with mocks, or reinterpret a build success as a database test pass. This contract itself does not certify backend, frontend or integrations.

## Release decision and review

Release requires fresh REAL PASS evidence for all required module, integration, security and acceptance scopes on the candidate. FAIL blocks release. Required NOT VERIFIED blocks release; optional integrations must remain visibly NOT VERIFIED and excluded from verified capability claims. Record the release decision, evidence links and unresolved gaps explicitly. No release is approved by this document.

Review reports use ISSUE / STATUS / ARTIFACTS / DECISIONS / OPEN / NEXT. Review artifacts and actual outputs, not statements that work is done.
