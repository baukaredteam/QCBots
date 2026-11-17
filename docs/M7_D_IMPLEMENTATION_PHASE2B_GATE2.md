# M7-D Phase 2B — Gate 2 (2B-3 Sigma → QRadar AQL drafts)

Status: **2B-3 implemented.** 2B-4 (Hunt Workspace UI, Hunt Plans, reviewer flow) **NOT started**, per the stop gate. Nothing in this phase executes AQL, calls QRadar, or deploys rules.

## 1. Files changed

| File | Change |
|---|---|
| `backend/sigma.go` | condition validator rewritten (aggregation/wildcards validated, no bypass); rule marked `validation_status=PRELIMINARY` |
| `backend/detection_scope.go` | DSM/event-scoped mapping resolution, catalogue-verified DSM, zero-field guard, registry failures fail closed |
| `backend/sigma_logsource_catalogue.go` | new curated, versioned Sigma-logsource → QRadar DSM catalogue (`logsource-catalogue-1`) |
| `backend/sigma_worker.go` | worker protocol, subprocess runner (timeout, output cap, minimal env), response validation |
| `backend/aql_validate.go` | AQL statement validation + tenant-scoped reconstruction |
| `backend/detection_translation.go` | translation service, mapping snapshot, diagnostics, staleness |
| `backend/detection_translation_handlers.go` | HTTP handlers for drafts |
| `backend/rbac.go` | `CanGenerateAQL` gate function |
| `backend/main.go` | migration 0018, translation routes (`/api/v1/sigma-rules/{rule_id}/translations`, `/api/v1/detection-translations/{id}`) |
| `migrations/0018_detection_translations.sql` | immutable translation table + triggers |
| `workers/sigma_worker/worker.py` | new worker (pySigma + IBM backend, strict JSON protocol) |
| `workers/sigma_worker/requirements.txt`, `README.md` | pins, install/run/protocol docs |
| `backend/detection_test.go` | corrections tests (aggregation, scope, catalogue, zero-field, fail-closed) |
| `backend/detection_translation_test.go` | AQL validator, translation lifecycle, staleness, worker protocol, real-worker gates |

## 2. Corrections to 2B-1 / 2B-2

| Gate issue | Fix |
|---|---|
| A. `1 of` / `all of` / `of them` bypassed reference validation | validator now tokenises every form, resolves `sel*` wildcards, and refuses a pattern with no matching selection; Go validation is labelled `PRELIMINARY` and pySigma re-parses authoritatively |
| B. mappings ignored DSM/event scope | `oneFieldReadiness` now filters by `applicable_dsm` and `applicable_event`; an out-of-scope mapping yields `SCOPE_MISMATCH`, never a silent use |
| C. token match treated as DSM equivalence | curated catalogue (`logsource-catalogue-1`) + real inventory check produces `CATALOGUE_MATCH`/`DSMVerified`; token-only hits stay `CANDIDATE`; zero-field rules are explicitly not ready |
| D. SQL errors became `MISSING` | readiness returns `ErrFieldAnalysisUnavailable` and the analysis fails closed; regression test renames the mapping table and asserts the failure |

## 3. Dependency compatibility evidence

| Item | Value |
|---|---|
| Python | 3.13.13 (3.14.4 also present; 3.13 used) |
| pySigma | 0.11.23 (IBM range `>=0.9.8,<0.12.0`) |
| IBM backend | `pysigma-backend-qradar-aql` 0.3.2 (bundles `pySigma_QRadar_base`) |
| Extension point | `sigma.pipelines.QRadarAQL.QRadarAQL.QRadar_fields_pipeline(base_pipeline_items, field_mapping)` |
| Licence | MIT |

**Reported conflict (not hidden):** the backend declares `regex>=2023.12.25,<2024.0.0`. On Python 3.13 no wheel exists for `regex<2024` and building it needs a Rust toolchain, so an exactly IBM-pinned resolution is not installable here. The verified set uses `regex 2026.11.9`; everything else matches the declared ranges. This is tracked as a blocked item, not claimed as supported.

**Upstream defect found:** `sel and not filt` raises `TypeError: 'str' object is not callable` inside the IBM backend with pySigma 0.11.17 and 0.11.23, with or without the custom pipeline. The worker therefore returns `UNSUPPORTED` with the upstream reason and stores no AQL — the NOT branch is never dropped. This is a real capability gap, recorded rather than worked around by rewriting the rule.

## 4. Worker architecture

Go orchestrates; Python converts. The worker has no QRadar credentials, no database access, no network use, receives a minimal environment (`PYTHONIOENCODING`, `PYTHONNOUSERSITE`, `NO_PROXY`, `PATH`), runs under a hard timeout (default 15 s, override `SIGMA_WORKER_TIMEOUT_MS`), and its stdout is capped at 256 KiB. `SIGMA_WORKER_PYTHON` selects the interpreter; when unset, translations are recorded as `BLOCKED` — no AQL is invented.

## 5. Request/response protocol (`sentinel.sigma.worker/1`)

Request: `protocol`, `request_id`, `sigma_yaml`, `sigma_sha256`, `field_map` (raw Sigma field → QRadar expression, already authorised by Go), `mode`, `limits`.

Response: `status` (`OK|UNSUPPORTED|PARSE_ERROR|ERROR`), `aql`, `converted_fields`, `unmapped_fields`, `unsupported_conditions`, `warnings`, `worker_version`, `pysigma_version`, `backend_version`, `sigma_sha256`, `request_id`, `error_code`/`errors`.

Go rejects: wrong protocol, mismatched `request_id`, mismatched Sigma hash, unknown status, `OK` without AQL or without version provenance, and oversized output.

## 6. Mapping resolver behaviour

Modes: `VERIFIED_FIELDS_ONLY` (only `AQL_MANUALLY_ATTESTED` fields; refuses before conversion otherwise), `REVIEW_REQUIRED_FIELDS` (uses available mappings, marks every unattested field as a warning, status stays `NEEDS_FIELD_VERIFICATION`), `PAYLOAD_FALLBACK` (refused: the worker returns `UNSUPPORTED` rather than silently switching to raw payload matching).

Mappings are read from the existing registry for the exact client + domain, filtered by DSM and event scope. The mapping id/version/approval state is stored in the draft's snapshot. No client-supplied mapping dictionary exists in the API; the Go layer builds it.

## 7. Conversion fidelity matrix (measured against the installed backend)

| Sigma construct | Worker result | Notes |
|---|---|---|
| `AND` | OK | conjunction preserved |
| `OR` of selections | OK | `"Event ID" IN('4624','4625')` — both alternatives present |
| `contains` / `startswith` / `endswith` | OK | `LOWER(...) LIKE` forms; multi-field OR expansion (`Process Path` OR `Process Name`) |
| Wildcards (`*\\powershell.exe`) | OK | expanded per field |
| Numeric comparison | OK | `"Event ID"=4688` unquoted |
| `1 of them` | OK | collapsed to `IN(...)` |
| `all of <pattern>` | OK (structural) | selection wildcard resolution tested in Go |
| `NOT` | **UNSUPPORTED** | upstream `TypeError`; no AQL emitted, reason recorded |
| `cased` modifier | **UNSUPPORTED** | backend: case-sensitive matching not supported |
| `| count()` aggregation | **UNSUPPORTED** | upstream: pipe syntax deprecated, correlations unsupported |

The rule that a successful AQL string is not proof of equivalence is enforced in the docs, the API (`diagnostics.executed=false`) and the tests (NOT-with-AQL must mention the filtered field; otherwise the result must be UNSUPPORTED).

## 8. AQL validation approach

`TenantScopedAQL` never concatenates user text:
1. reject statements containing `;`, comments, newlines/tabs, or mutating/administrative verbs;
2. require exactly `SELECT <list> FROM events WHERE <expr>`; select list restricted to identifiers/commas/dots/stars;
3. reject a worker-supplied `domainid` (competing tenant constraint);
4. check parenthesis and quote balance, ignoring quoted literals;
5. rebuild as `SELECT <list> FROM events WHERE domainid=<native> AND (<expr>) LAST <n> DAYS`.

Because the body is parenthesised after the domain predicate, an `OR` inside the rule cannot escape the tenant filter. The native domain id must be digits; the time window is 1..90 days.

## 9. Tenant isolation results

| Check | Result |
|---|---|
| foreign client translating another client's rule | denied (403 / access error) |
| unverified domain binding | `DOMAIN_NOT_ASSIGNED`, no draft |
| revoked client grant | denied |
| translation listing | filtered by client grant |
| draft scope | includes `domainid=<native>` + binding revision |
| draft immutability | `UPDATE`/`DELETE` rejected by triggers |
| execution claim | table trigger rejects `verified_by_qradar` / `executed=true` |
| staleness | mapping version change and binding change both mark the draft stale |

Live API run (isolated `%TEMP%\b3.db`, real worker): 201 with
`SELECT * FROM events WHERE domainid=5 AND (devicetype=12 AND EventCode LIKE '%4698%') LAST 7 DAYS`,
status `NEEDS_FIELD_VERIFICATION`, `mappings` snapshot with `qfm-stagef-eventcode/v1`, `executed:false`, and cross-client access 403.

## 10. Commands and exit codes

| Command | Exit |
|---|---|
| `go build ./...` | 0 |
| `go vet ./...` | 0 |
| `go test -timeout 900s -count=1 ./...` | 0 |
| `go test -race` (AQL + translation + worker + Sigma + trust + 2A.1) | 0 |
| real worker tests (`SIGMA_WORKER_PYTHON` set) | 0 (3 tests) |
| `python -m py_compile workers/sigma_worker/worker.py` | 0 |
| `node --check frontend/v3/v3.js` | 0 |

## 11. Remaining limitations

- `NOT`, `cased` and aggregation constructs are UNSUPPORTED with the pinned backend — a real functional gap, not a workaround.
- `regex` version is outside the IBM pin (documented above).
- Log source/DSM matching depends on the curated catalogue; fields not in the CEP catalogue need client mappings.
- No semantic equivalence proof: a valid AQL draft is not evidence of correct detection behaviour.
- No reviewer workflow or Hunt Plan yet (2B-4).

## 12. GO/NO-GO

**2B-3: GO, with a documented capability gap.** Draft generation, tenant scoping, validation, immutability and staleness work and are tested against the real IBM backend.

**Blocked items for a future gate:** NOT/aggregation support (upstream), exact `regex` pin, and semantic review of converted fixtures by a QRadar expert.

**2B-4: NOT STARTED** — awaiting authorization.


---

# Gate 2 hardening (2B-3 revalidation, AQL grammar, isolation, dependency truth)

Independent review found four trust gaps in the first 2B-3 cut. This section
records the fixes; the sections above describe the original implementation.

## 1. Root causes

| Gap | Root cause |
|---|---|
| Evidence could change during conversion | authorisation, binding and mapping checks ran before the worker call; the insert only re-checked nothing |
| AQL validation was pattern matching | regex + forbidden substrings + parenthesis counting is not a grammar; quoted literals, functions and operator precedence were unchecked |
| "Isolation" was overstated | a minimal environment is not a network or filesystem sandbox |
| DSM scope failed open | a DSM-scoped mapping matched when the selected DSM was unknown (`sc.DSM == ""`) |

## 2. Changes

**Atomic revalidation** (`backend/translation_revalidate.go`): every draft is
re-checked inside the persistence transaction, immediately before the insert.
`revalidateTranslationTx` verifies capability (`CanGenerateAQL` via the same
transaction), client grant, binding kind/status/evidence, unchanged client,
unchanged native domain id, unchanged binding revision, and for every mapping in
the snapshot: still the newest applicable mapping, same version, approval still
present, DSM and event scope still matching. Any failure returns typed
`TRANSLATION_STALE_SCOPE` (HTTP 409 `STALE_SCOPE`) and **no row is written**.

**AQL grammar** (`backend/aql_validate.go`): the statement is tokenised (quoted
strings with `''` escaping, double-quoted identifiers, numbers, operators,
parens, commas), parsed by recursive descent into `OR в†’ AND в†’ NOT в†’ primary в†’
predicate`, restricted to `= != <> < > <= >= LIKE`, `[NOT] IN (...)`,
`LOWER(field)`/`UPPER(field)` and literal operands. Unknown functions, subqueries,
literal-vs-literal comparisons (`1=1`), trailing tokens, comments, newlines and a
worker-supplied `domainid` are rejected. The AST is re-rendered canonically, so
the emitted AQL preserves grouping and keeps the tenant predicate outermost.

**Worker containment** (`backend/sigma_worker.go`): `python -I -B` (isolated mode,
no bytecode writes), fixed working directory (the script's directory), minimal
environment, hard timeout, capped stdout/stderr, best-effort tree kill via
`taskkill /T /F` on timeout, and optional script integrity pinning through
`SIGMA_WORKER_SCRIPT_SHA256`. The script hash is recorded in the draft
diagnostics. **No OS-level network or filesystem sandbox exists**; the API now
reports this explicitly (`isolation.network_sandbox=false`,
`filesystem_sandbox=false`, `tree_kill=BEST_EFFORT`).

**DSM scope fail-closed** (`backend/detection_scope.go`): a mapping with
`applicable_dsm` now requires an exact match against the selected DSM; an unknown
DSM never matches. Event scope already required an exact match.

## 3. Tests

| # | Requirement | Test |
|---|---|---|
| 1 | domain revoked while worker runs | `TestHardening_BindingRevokedWhileWorkerRuns` |
| 2 | domain reassigned while worker runs | `TestHardening_DomainReassignedWhileWorkerRuns` |
| 3 | grant revoked while worker runs | `TestHardening_GrantRevokedWhileWorkerRuns` |
| 4 | mapping version changed while worker runs | `TestHardening_MappingChangedWhileWorkerRuns` |
| 5 | approval withdrawn | `TestHardening_ApprovalWithdrawnWhileWorkerRuns` |
| 6 | unknown DSM with DSM-scoped mapping | `TestHardening_UnknownDSMDoesNotMatchScopedMapping` |
| 7 | cross-DSM rejection | `TestSigma_DSMMismatchIsScopeMismatch`, `TestHardening_NoDSMInventedFromLabel` |
| 8 | hostile/malformed AQL | `TestAQL_RejectsUnsafeStatements`, `TestAQL_RejectsUnsupportedFunctionsAndNesting` |
| 9 | OR stays tenant-scoped | `TestAQL_TenantScopingWrapsOrCondition`, `TestAQL_PreservesPrecedenceAndParens` |
| 10 | quoted literals | `TestAQL_QuotedLiteralsRoundTrip` |
| 11 | worker timeout/termination | `TestWorker_TimeoutRefused` |
| 12 | oversized output | `TestWorker_ProtocolRejectsMismatchAndOversize` |
| 13 | historical drafts immutable | `TestTranslation_ReadyDraftIsScopedAndPersisted` |
| 14 | NOT produces no AQL | `TestWorker_RealNotNeverDropped`, `TestTranslation_UnsupportedFromWorker` |
| 15 | earlier 2B tests green | full suite |

The concurrency tests use a worker stub that blocks on a channel, mutate the
database while it is blocked, then release it вЂ” so the mutation happens strictly
between analysis and persistence.

## 4. Dependency compatibility matrix

| Component | Declared by IBM | Verified here | Status |
|---|---|---|---|
| Python | `^3.10` | 3.13.13 | in range |
| pySigma | `>=0.9.8,<0.12.0` | 0.11.23 | in range |
| backend | `0.3.2` | 0.3.2 | exact |
| regex | `>=2023.12.25,<2024.0.0` | 2026.11.9 | **outside range вЂ” blocker** |
| licence | MIT | MIT | ok |

No Python 3.10вЂ“3.12 interpreter is installed on this host, and `regex<2024` has
no wheel for 3.13 and fails to build without a Rust toolchain. The combination is
therefore **verified working, not officially supported**, and the divergence is
retained as a blocker rather than papered over.

`NOT`, `cased` and `| count()` remain **UNSUPPORTED**: all three fail inside the
IBM backend/pySigma pairing, and the worker refuses them with the upstream reason
instead of dropping a condition.

## 5. AQL grammar limitations

Supported: comparisons, `LIKE`, `IN`, `NOT`, `AND`/`OR` with grouping,
`LOWER`/`UPPER` around a field, numeric and quoted literals, `SELECT` list of
fields or `*`, optional trailing `LAST n DAYS` (ours replaces it).

Not supported (refused): other functions, nested `SELECT`, string concatenation,
arithmetic, `BETWEEN`, wildcard `IN` patterns, multi-value `MATCHES`, and any
construct that would need semantics the parser cannot verify.

Successful parsing is **not** proof of executability: nothing here claims QRadar
verification.

## 6. Residual risks

- No OS sandbox: the worker could still open sockets or read files if its code
  were tampered with. Mitigations are integrity pinning, `-I`, fixed cwd, timeout
  and output caps вЂ” not containment.
- Diagnostic env-var tampering: `SIGMA_WORKER_PYTHON`/`SCRIPT` are operator
  controlled; a compromised environment can point at another interpreter. The
  script hash only pins the script, not the interpreter.
- Grammar subset may reject a future IBM output shape; it fails closed.
- NOT/aggregation gap is a real capability loss until a supported dependency set
  is proven.

## 7. Hardening verification

| Command | Exit |
|---|---|
| `go build ./...` | 0 |
| `go vet ./...` | 0 |
| `go test -timeout 900s -count=1 ./...` | 0 |
| `go test -race` (hardening + AQL + translation + worker + Sigma + trust) | 0 |
| real worker tests with `SIGMA_WORKER_PYTHON` | 0 (3 tests) |
| `python -m py_compile worker.py` | 0 |
| `node --check frontend/v3/v3.js` | 0 |

## 8. GO/NO-GO

**2B-3: GO with documented blockers.** The draft pipeline now fails closed on
stale evidence, parses AQL against a real grammar, refuses rather than drops
unsupported constructs, and reports its isolation honestly.

**Blockers carried forward:** `regex` outside the IBM pin, `NOT`/`cased`/
aggregation unsupported upstream, no OS sandbox for the worker, and no semantic
equivalence proof for converted rules.

**2B-4: backend continued in `docs/M7_D_IMPLEMENTATION_PHASE2B_GATE3.md`.
Frontend (2B-4B) is still not started.**

