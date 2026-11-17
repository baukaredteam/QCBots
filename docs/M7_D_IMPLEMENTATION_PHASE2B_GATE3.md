# M7-D Phase 2B-4A — Hunt Plan Backend Gate

Status: backend complete, frontend **not started** (2B-4B needs separate
authorization).

Scope of this phase: close the five remaining 2B-3 validation gaps, then add
Hunt Plan persistence, RBAC, review and tests. No QRadar API, no AQL execution,
no rule deployment, no Octop, no production database changes.

---

## 1. Preflight corrections

| # | Gap | Fix |
|---|---|---|
| 1 | `IN`/`NOT IN` accepted a constant on the left | `parsePredicate` now requires a field or `LOWER`/`UPPER` field expression; a literal left operand is `AQL_INVALID` |
| 2 | Revalidation used a different mapping selection rule than readiness | both now use `ORDER BY CAST(mapping_version AS INTEGER) DESC, created_at DESC`; revalidation applies the same DSM/event scope filter |
| 3 | Snapshot was not compared against the current CEP target / approval / attestation | revalidation compares `mapping_id`, version, `target_cep_field`, scope and approval presence, and rejects ambiguous double approvals; plan approval re-checks the stored snapshot the same way |
| 4 | A worker-supplied time window was silently replaced | `LAST n DAYS` is accepted only when `n` equals the requested window, otherwise `AQL_INVALID` |
| 5 | Missing regression coverage | `backend/preflight_2b4_test.go` |

Regression tests:

| Test | Proves |
|---|---|
| `TestPreflight_INRequiresFieldOperand` | constant `IN`/`NOT IN` refused, field expression accepted |
| `TestPreflight_ConflictingWorkerWindowRejected` | `LAST 30 DAYS` vs 7-day request refused; matching window accepted |
| `TestPreflight_MappingVersionOrderIsNumeric` | mapping version `10` wins over `9` (string ordering would invert it) |
| `TestPreflight_CEPMutationDuringConversionIsStale` | CEP target changed while the worker runs → `TRANSLATION_STALE_SCOPE`, nothing persisted |
| `TestPreflight_ValidDraftStillSupported` | a valid scope-bound draft still reaches `READY_FOR_REVIEW` |

No trust-boundary defect remains open. Verdict: **preflight GO**.

---

## 2. Migration 0019

`migrations/0019_hunt_plans.sql` is additive; 0001–0018 are untouched.

Migration 0010 already defines a documentation-only `hunt_plans` table
(narrative fields, `DRAFT_ONLY` steps, `UNIQUE (hypothesis_id, version_no)`,
no review state, no AQL link, no Go code using it). It is **left in place**. The
authoritative reviewable plan is stored in two new tables:

`hunt_plan_versions`
- `plan_id` PK, `logical_id` + `version` (UNIQUE, plan versioning)
- `client_id`, `hypothesis_id` + `hypothesis_version` → composite FK to
  `hunt_hypothesis_versions(hypothesis_id, version_no)`
- `report_id`, `title`
- `status` CHECK `DRAFT | IN_REVIEW | APPROVED | REJECTED`
- `supersedes_plan_id`, `created_by`, `created_at`
- `submitted_by/at`, `reviewed_by/at`, `review_evidence`, `review_note`

`hunt_plan_version_items`
- `(plan_id, translation_id)` PK, `domain_id`, `native_qradar_domain_id`,
  `added_by`, `added_at`
- FKs to `hunt_plan_versions`, `detection_translations`, `qradar_domains`

Storage-boundary guards (triggers):
- approved plan rows cannot be updated or deleted;
- items can only be inserted while the plan is `DRAFT`, and items are never
  updated or deleted;
- only `DRAFT → DRAFT|IN_REVIEW` and `IN_REVIEW → APPROVED|REJECTED` are
  accepted;
- a plan whose title/review note claims execution is refused on insert.

---

## 3. API contracts

| Method | Path | Permission | Result |
|---|---|---|---|
| POST | `/api/v1/hunt-plans` | `CanViewCTI` + `CanCreateHypothesis` + CSRF | 201 plan |
| GET | `/api/v1/hunt-plans?client_id=` | `CanViewCTI` + grant | 200 `{plans,count}` |
| GET | `/api/v1/hunt-plans/{plan_id}` | `CanViewCTI` + grant | 200 plan |
| POST | `/api/v1/hunt-plans/{plan_id}/items` | `CanCreateHypothesis` + CSRF | 200 plan |
| POST | `/api/v1/hunt-plans/{plan_id}/submit` | `CanCreateHypothesis` + CSRF | 200 plan |
| POST | `/api/v1/hunt-plans/{plan_id}/review` | `CanReviewHypothesis` + CSRF | 200 plan |
| POST | `/api/v1/hunt-plans/{plan_id}/versions` | `CanCreateHypothesis` + CSRF | 201 new DRAFT |

Error mapping: `HUNT_PLAN_NOT_FOUND` → 404, access/tenant/role denials → 403
with a generic body (no foreign client metadata), state or evidence drift →
409 `HUNT_PLAN_CONFLICT`, malformed input → 400. A stale draft keeps the 409
`STALE_SCOPE` contract from 2B-3.

A plan item may only reference a translation of the same client that is
non-stale and `READY_FOR_REVIEW`; `UNSUPPORTED`/`BLOCKED` are refused so an
unsupported Sigma construct is never smuggled into an approved plan.

---

## 4. State machine and review rules

```
DRAFT ──submit──▶ IN_REVIEW ──approve──▶ APPROVED
                                 └─reject──▶ REJECTED
APPROVED / REJECTED ──new version──▶ DRAFT (version+1, supersedes the old row)
```

- Submitting requires at least one item, every item `READY_FOR_REVIEW` and not
  stale.
- Approval revalidates **inside the decision transaction**: reviewer capability,
  client grant, binding kind/status/evidence, client ownership, native domain id,
  binding revision, translation status and non-empty AQL, source rule version and
  hash, and every mapping in the stored snapshot (exists, same version, same CEP
  target, approval still present).
- Rejection skips evidence revalidation: it makes no claim that evidence is
  current.
- Approved rows are immutable; a change requires `CreateHuntPlanVersion`, which
  copies only non-stale items.
- `APPROVED` means "reviewed draft for analyst use". It is not execution and not
  QRadar verification.

---

## 5. Tests

| Requirement | Test |
|---|---|
| CTI → Sigma → AQL → plan linkage | `TestHuntPlan_LifecycleApproveAndImmutable` |
| multiple detections per plan | `TestHuntPlan_MultipleDetections` |
| immutable approved versions | `TestHuntPlan_LifecycleApproveAndImmutable` (SQL update/delete refused) |
| stale translation approval denied | `TestHuntPlan_NewerMappingBlocksSubmit`, `TestHuntPlan_WithdrawnApprovalBlocksApproval`, `TestHuntPlan_ChangedCEPBlocksApproval` |
| unverified domain denied | `TestHuntPlan_UnverifiedDomainBlocksApproval` |
| revoked grant denied | `TestHuntPlan_RoleAndTenantEnforcement` |
| cross-client read/write denied | `TestHuntPlan_RoleAndTenantEnforcement`, `TestHuntPlan_HTTPRBACAndTenant` |
| role-based review enforcement | `TestHuntPlan_RoleAndTenantEnforcement`, HTTP test |
| concurrent review conflict | `TestHuntPlan_ConcurrentReviewSingleWinner` |
| audit integrity | `TestHuntPlan_LifecycleApproveAndImmutable` (create/submit/review/version rows) |
| no AQL execution claims | `TestHuntPlan_ApprovedRecordsNoExecution` |
| rejection path | `TestHuntPlan_RejectAndVersion` |

All tests use an in-memory SQLite database and synthetic telemetry.

---

## 6. Verification

Commands run from `backend/` with `CGO_ENABLED=1` and the MinGW toolchain on
`PATH`.

| Command | Exit |
|---|---|
| `go build ./...` | 0 |
| `go vet ./...` | 0 |
| `go test -timeout 900s -count=1 ./...` | 0 — `ok mssp-workbench 495.1s` |
| `go test -race -run 'TestHuntPlan\|TestPreflight\|TestHardening\|TestAQL'` | 0 — `ok mssp-workbench 239.4s`, no data race |
| `node --check frontend/v3/v3.js` | 0 |

Python worker tests were not affected by this phase (no worker, grammar-only
changes were already covered in the 2B-3 hardening gate).

---

## 7. Residual limitations

- **No frontend.** Hunt Workspace UI, cascade/inspector flows and browser
  acceptance belong to 2B-4B and are not implemented.
- **No execution.** No AQL runs against QRadar; `APPROVED` is not verification.
- **Carried 2B-3 blockers:** `regex` outside the IBM dependency pin,
  `NOT`/`cased`/aggregation unsupported upstream, no OS-level sandbox around the
  Python worker.
- **Mapping snapshot scope:** approval compares the snapshot rows by id/version/
  CEP/approval at the transaction boundary. A newer mapping appearing after
  approval does not silently rewrite an approved plan; it surfaces as staleness
  on the next read/submit, and a new version must be created.
- Legacy `hunt_plans` (0010) remains in the schema and is unused by this phase;
  it should be retired in a later migration once confirmed empty.

---

## 8. GO / NO-GO — Phase 2B-4A

**GO for backend Hunt Plans.** Preflight gaps are closed with regression tests,
tenant and role checks are enforced at service and HTTP layers, approval is
transactional, and approved content is immutable.

**2B-4B: NOT STARTED.** No Hunt Workspace UI was added. No QRadar API, AQL
execution, deployment, Octop or production migration was touched.


---

# Final security gate (2B-4A hardening)

Independent review found four trust-boundary gaps in the first Hunt Plan cut.
This section records the fixes; the sections above describe the original design.

## S1. Confirmed root causes

| Gap | Root cause |
|---|---|
| Review authorization was not atomic | `ReviewHuntPlan` checked role and grant before `Begin`; a role change or grant revocation between check and commit was invisible to the decision |
| Snapshot check proved only row identity | `verifyMappingSnapshotTx` looked a mapping up by id, so a newer applicable mapping, a scope change, a second approved mapping or withdrawn attestation could not invalidate the plan |
| Staleness used the author's identity | `loadHuntPlanItems` called `GetDetectionTranslation(..., item.AddedBy)` and `computeStaleness` called `GetSigmaRule(..., translation.CreatedBy)`, so another person's lost grant silently made evidence look stale (or readable) |
| Item relationships were application-only | the item table stored client/domain/native values but nothing at the storage boundary proved they matched the translation |

## S2. Changes

**Atomic review authorization** (`backend/hunt_plan.go`): the authoritative
checks moved inside the decision transaction. `reviewAuthTx` re-reads the plan's
`client_id` and `status`, resolves the reviewer's role with
`GetPermissionOfTx`, requires `CanReviewHypothesis`, counts the live client grant
and refuses anything but `IN_REVIEW`. It runs for **both** `APPROVED` and
`REJECTED`. Plan ownership is compared against the transaction value, and the
`UPDATE ... WHERE status='IN_REVIEW'` still gives a single winner under
concurrency. Approval evidence freshness (`revalidateHuntPlanTx`) is unchanged in
scope but now also compares translation client and domain. An audit write failure
aborts the whole transaction.

**Mapping snapshot fidelity** (`verifyMappingSnapshotTx`): selection now matches
the readiness resolver exactly вЂ” newest numeric version among rows whose
`applicable_dsm`/`applicable_event` match the draft's scope, with an unknown scope
never matching a scoped row. It rejects a superseded mapping, a changed version or
CEP target, a withdrawn approval, more than one approved applicable mapping, an
out-of-scope row, and a field whose `VERIFIED` AQL observation disappeared
(`fieldAttestedTx`, same rule as readiness). No other mapping is ever substituted.

**Viewer-neutral staleness** (`loadHuntPlanItems`, `translationEvidenceState`,
`computeStaleness`): reads are authorized once, by the current plan client grant;
technical staleness is then derived from the evidence alone through
`loadSigmaRule` (no user identity). Each item reports
`evidence_state = OK | STALE_EVIDENCE | EVIDENCE_UNAVAILABLE`, keeps the original
`added_by` provenance, and `stale` remains as a boolean alias. Submission blocks
on stale and unavailable evidence with distinct errors; plan versioning copies
only `OK` items.

**Plan-item integrity** (`migrations/0020_hunt_plan_item_integrity.sql`,
`assertItemEvidenceTx`): attaching a draft now requires `READY_FOR_REVIEW` with a
real AQL draft, revalidated inside the transaction вЂ” same client, same domain and
native id, current verified client binding at the translation's revision, pinned
rule version/hash, and the snapshot checks above. Two database triggers refuse a
direct insert whose translation belongs to another client/domain, whose native id
differs, whose draft is not a reviewed AQL draft, or whose binding is not
currently verified.

## S3. Regression tests

| Requirement | Test |
|---|---|
| reviewer grant revoked before the decision | `TestSecurity_ReviewGrantRevokedBeforeDecision` |
| reviewer role changed during review | `TestSecurity_ReviewRoleChangedBeforeDecision` |
| rejection also authorized | `TestSecurity_RejectionAlsoRequiresAuthorization` |
| foreign client review denied | `TestSecurity_ForeignClientReviewDenied` |
| concurrent reviewers, one winner | `TestHuntPlan_ConcurrentReviewSingleWinner` |
| audit failure rolls back the decision | `TestSecurity_AuditFailureRollsBackDecision` |
| superseded mapping | `TestSecurity_SupersededMappingDenied` |
| scope change | `TestSecurity_ScopeChangeDenied` |
| ambiguous approvals | `TestSecurity_AmbiguousApprovalsDenied` |
| attestation withdrawal | `TestSecurity_AttestationWithdrawalDenied` |
| author grant must not drive staleness | `TestSecurity_ItemStalenessIndependentOfAuthorGrant` |
| `EVIDENCE_UNAVAILABLE` is distinct | `TestSecurity_EvidenceUnavailableIsDistinct` |
| stale evidence blocks submit | `TestSecurity_StaleItemBlocksSubmitAndApproval` |
| attach requires a reviewed AQL draft | `TestSecurity_AttachRequiresReadyDraft` |
| database-level item integrity | `TestSecurity_ItemIntegrityTriggerRejectsMismatch` |
| typed HTTP conflict on unavailable evidence | `TestSecurity_HTTPEvidenceUnavailable` |
| versioning copies only current evidence | `TestSecurity_PlanVersionCopiesOnlyCurrentEvidence` |
| denial never names a client | `TestSecurity_AccessDeniedMessageIsGeneric` |

The existing 2B-4A suite (`TestHuntPlan_*`, `TestPreflight_*`) and the earlier
2B-3 hardening suite remain green.

## S4. Behaviour changes worth knowing

- A `NEEDS_FIELD_VERIFICATION` draft can no longer be attached to a plan. A plan
  bundles **reviewed AQL drafts**; an unready detection stays in Detection
  Translation until it is ready.
- A missing binding row now reports `EVIDENCE_UNAVAILABLE` (409
  `EVIDENCE_UNAVAILABLE`) instead of a generic conflict. The decision is denied
  either way.
- `computeStaleness` no longer depends on the author's grant, which corrects a
  false-stale/false-current classification for every translation reader, not only
  plans.

## S5. Verification

| Command | Exit |
|---|---|
| `go build ./...` | 0 |
| `go vet ./...` | 0 |
| `go test -timeout 900s -count=1 ./...` | 0 — `ok mssp-workbench 484.2s` |
| `go test -race -run 'TestHuntPlan\|TestPreflight\|TestSecurity\|TestHardening\|TestAQL'` | 0 — `ok mssp-workbench 407.5s`, no data race |
| `node --check frontend/v3/v3.js` | 0 |

## S6. Residual risks

- Approval proves that the snapshot is still the newest **applicable** mapping and
  that the field is still attested. It does not prove that the AQL returns the
  intended events in QRadar вЂ” nothing here executes.
- The DSM used for scope comparison comes from the immutable translation
  diagnostics. A translation created before `primary_dsm` was recorded will fail
  approval for a DSM-scoped mapping (fail-closed, not silent acceptance).
- Attestation is checked against `qradar_field_observations`; the registry has no
  update trigger, so an operator can still change an observation through SQL
  outside the review workflow. Approval re-reads it at decision time, but there
  is no signed history for observations.
- Legacy `hunt_plans` (migration 0010) remains unused; retiring it is a later
  migration.
- The 2B-3 blockers are unchanged: `regex` outside the IBM pin, `NOT`/`cased`/
  aggregation unsupported upstream, no OS sandbox around the Python worker.

## S7. GO / NO-GO вЂ” Phase 2B-4B

**GO for Phase 2B-4B (frontend).** Review authorization is transactional for both
decisions, snapshot and attestation drift deny approval, item integrity is proven
at the storage boundary, staleness no longer depends on another user's identity,
and every denial path is covered by an executed test.

**Still excluded:** no Hunt Workspace UI, no QRadar API, no AQL execution, no rule
deployment, no Octop, no production migration. `storage/workbench.db` was never
opened.



---

# Phase 2B-4B вЂ” Hunt Workspace UI and browser acceptance

## S8. SQL preflight: binding owner

Migration 0020 proved plan/translation/item agreement and a VERIFIED binding at
the draft's revision, but never compared `binding.client_id` with
`translation.client_id`. A domain rebound to another client could still satisfy
0020. `migrations/0021_hunt_plan_item_binding_owner.sql` adds a trigger requiring
`binding.client_id = translation.client_id`, `binding.domain_id = item.domain_id`,
`binding_kind = 'CLIENT'`, `verification_status = 'VERIFIED'`, non-empty
`verified_by`/`verified_at`/`evidence_reference`, and
`binding.revision = translation.binding_revision`. 0020 is untouched.

Test `TestSecurity_ItemBindingOwnerMismatchRejected`: with plan client A and
translation client A, the binding is reassigned to client B behind the service;
the direct INSERT is rejected. After restoring ownership the same insert
succeeds, and an attempt to blank the verification evidence is refused by 0016.

## S9. Frontend files changed

| File | Change |
|---|---|
| `frontend/v3/hunt-workspace.js` | new; all four sections, workbench, plan actions, review queue, coverage |
| `frontend/v3/v3.js` | `hunt` route renders the workspace; deep-link query preserved on load and hash change; nav tag `2B-4B` |
| `frontend/v3/index.html` | loads `hunt-workspace.js`; three-column workbench CSS with a stacked fallback |
| `backend/seed_hunt.go` | new; disposable acceptance fixtures (`seed-hunt-acceptance`) |
| `backend/main.go` | subcommand dispatch for the seeder |
| `migrations/0021_hunt_plan_item_binding_owner.sql` | new binding-owner trigger |
| `backend/hunt_plan_security_test.go` | binding-owner test |

The shell, design tokens, navigation, session cookies and CSRF handling are the
existing v3 ones. No framework was introduced and no API client was duplicated.

## S10. What the UI does

- **Hunt Plans** вЂ” real `/api/v1/hunt-plans` rows: title, client, hypothesis and
  version, plan version, status, attached drafts, aggregate evidence state,
  reviewer, created/reviewed timestamps. Create from an authorized hypothesis,
  attach a READY draft, submit, approve/reject with evidence, fork a new version,
  open any version in the history. Buttons are disabled when the role or plan
  state forbids the action; the server remains authoritative.
- **Detection Translation** вЂ” three linked panels. Left: rule title/version,
  logsource, condition, modifiers, MITRE tags, report provenance and the original
  YAML as text. Center: verified domain, native domain id, binding revision, DSM,
  log sources and per-field readiness with state, CEP, mapping id/version,
  approver and AQL observation. Right: draft selector, status, conversion mode,
  staleness, worker/backend versions, AQL in a `<pre>` with copy, diagnostics,
  unsupported conditions, mapping snapshot and attach-to-plan.
- **Coverage & Gaps** вЂ” Detection Scope diagnostics grouped into missing
  telemetry, unknown DSM, missing CEP, unapproved mapping, missing attestation,
  unsupported Sigma condition, stale binding/mapping and other not-ready states.
  No percentage is computed; a link opens Field Intelligence.
- **Review Queue** вЂ” IN_REVIEW plans only, with evidence state, draft context,
  Sigma source, AQL and mapping snapshot. The plan is re-fetched before the
  decision; a 409 is shown as a category without foreign metadata; the approved
  result is re-read from the server.

All untrusted content (Sigma YAML, CTI text, diagnostics) is rendered with
`textContent`; no HTML injection path exists. No credentials are stored in JS.

## S11. API integration matrix

| UI need | Endpoint | Used by |
|---|---|---|
| session/grants | `GET /api/v1/auth/me` | shell |
| plans list | `GET /api/v1/hunt-plans?client_id=` | Plans, Review, attach selector |
| plan detail | `GET /api/v1/hunt-plans/{id}` | inspector, refresh-before-approve |
| create/submit/review/version | `POST /api/v1/hunt-plans`, `/{id}/submit`, `/{id}/review`, `/{id}/versions` | Plans, Review |
| attach draft | `POST /api/v1/hunt-plans/{id}/items` | Workbench, plan inspector |
| hypotheses | `GET /api/v1/hypotheses?client_id=&limit=` | plan creation |
| Sigma rules | `GET /api/v1/detections/sigma?client_id=` | Workbench, Coverage |
| Sigma detail/scope | `GET /api/v1/detections/sigma/{id}`, `/scope` | Workbench, Coverage |
| drafts | `GET /api/v1/sigma-rules/{id}/translations`, `GET /api/v1/detection-translations/{id}` | Workbench, Review |
| generate draft | `POST /api/v1/sigma-rules/{id}/translations` | Workbench |
| clients | `GET /api/v1/clients` | shell context |

No new persistence table and no new read endpoint were required.

## S12. Browser acceptance (isolated server, disposable SQLite)

Environment: `seed-hunt-acceptance` created `%TEMP%\hunt_accept.db`; the server
ran on `:18081` with the v3 shell at `/v3/`. Fixtures: clients Alpha/Beta, one
shared console, verified native domains 5 and 8, three Sigma rules (ready,
aggregation-unsupported, later-stale), one READY draft, one DRAFT plan, one
IN_REVIEW plan with stale evidence. `storage/workbench.db` was never opened.

| Step | Result | Evidence |
|---|---|---|
| A open Hunt Workspace | pass | screenshot 2b4b-01 |
| B select Alpha | pass | client grant selector |
| C Beta not visible to Alpha user | pass вЂ” option list is `["client-alpha"]`; Beta user sees only Beta and no Alpha plans | 2b4b-07 |
| D open a Sigma detection | pass вЂ” three rules, source panel, YAML as text | 2b4b-02 |
| E readiness and mapping provenance | pass вЂ” `AQL_MANUALLY_ATTESTED`, CEP `event_id`, mapping `qfm-вЂ¦` v1, approver, `VERIFIED` observation, DSM verified | 2b4b-02 |
| F open the AQL draft | pass вЂ” `SELECT * вЂ¦ domainid=5 AND ("Event ID" = 4624) LAST 7 DAYS`, status/staleness/versions, copy | 2b4b-02 |
| G attach to a Hunt Plan | pass вЂ” plan items became 1, evidence `OK` | API check |
| H submit the plan | pass вЂ” status `IN_REVIEW`, submitted by `user-analyst-multi` | API check |
| I reviewer approves with evidence | pass вЂ” `APPROVED`, reviewer `user-reviewer`, evidence stored | API + 2b4b-04 |
| J analyst cannot approve | pass вЂ” UI read-only and `POST /review` в†’ 403 `FORBIDDEN` | API check |
| K stale translation denies approval | pass вЂ” 409 вЂњConflict (409): plan state or attached evidence changedвЂќ, status stays `IN_REVIEW`, reason вЂњa newer mapping exists for ImageвЂќ | 2b4b-03 |
| L approved plan cannot be edited | pass вЂ” no edit controls; only вЂњCreate new plan versionвЂќ; storage trigger covered by tests | 2b4b-04 |
| M new version preserves the approved one | pass вЂ” v2 `DRAFT` supersedes v1; v1 stays `APPROVED` with its evidence; history shows both | 2b4b-05 |
| N no execution or deployment | pass вЂ” no execute/deploy control; page text only disclaimers; no QRadar request in the server log | 2b4b-02 |

Screenshots are real captures in `frontend/v3/shots/`:
`2b4b-01-plans.png`, `2b4b-02-translation.png`,
`2b4b-03-review-stale-denied.png`, `2b4b-04-approved-immutable.png`,
`2b4b-05-version-history.png`, `2b4b-06-coverage.png`,
`2b4b-07-beta-isolation.png`.

## S13. RBAC and tenant isolation results

- CTI_ANALYST cannot create, attach or submit; HYPOTHESIS_WRITER can create,
  attach, submit and fork but cannot review; REVIEWER can review but cannot
  create or fork. Enforced by middleware and rechecked in the service.
- A foreign client is absent from every selector and every list; cross-client
  read/attach/submit/review is denied at the service and HTTP layers (tests
  `TestHuntPlan_RoleAndTenantEnforcement`, `TestHuntPlan_HTTPRBACAndTenant`).
- The reviewer decision re-reads role, grant, plan owner and status inside the
  transaction, and refuses stale or unavailable evidence.

## S14. Regression results

| Command | Exit |
|---|---|
| `go build ./...` | 0 |
| `go vet ./...` | 0 |
| `go test -timeout 900s -count=1 ./...` | 0 — `ok mssp-workbench 462.7s` |
| `go test -race -run 'TestHuntPlan\|TestPreflight\|TestSecurity\|TestHardening\|TestAQL'` | 0 — `ok mssp-workbench 460.6s`, no data race |
| `node --check frontend/v3/v3.js` | 0 |
| `node --check frontend/v3/hunt-workspace.js` | 0 |

## S15. Known limitations (unchanged and newly visible)

- `regex` remains outside the IBM dependency pin; `NOT`, `cased` and
  aggregations remain UNSUPPORTED upstream. The unsupported fixture shows the
  exact reason and keeps its original detection.
- The Python worker still has no OS-level network or filesystem sandbox; the UI
  reports `network sandbox: NOT implemented` and `filesystem sandbox: NOT
  implemented` on every draft.
- No QRadar runtime validation. A reviewed AQL is not an executed AQL; the UI
  says so on every draft and on the approval callout.
- `frontend/login.html` still targets the default `:8080` backend, and the v3
  shellвЂ™s `api.js` only switches to `:18081`. The acceptance session was
  established through the real login API against the isolated server; a
  deployment on another port needs the existing base-URL convention.
- Copy-to-clipboard depends on browser permission; when unavailable the button
  says so rather than pretending.
- DSM scope at approval comes from the immutable translation diagnostics, so a
  draft created before `primary_dsm` was recorded fails closed for DSM-scoped
  mappings.

## S16. GO / NO-GO вЂ” Phase 2B-4B

**GO.** The Hunt Workspace is implemented with the existing shell and APIs, the
four sections read real server data, the analyst workflow runs end to end,
review is atomic and evidence-bound, approved plans are immutable and versioned,
and tenant/role boundaries hold in the browser and in tests.

**Excluded:** no QRadar API call, no AQL execution, no rule deployment, no Octop,
no new CTI connector, no production migration. `storage/workbench.db` was not
opened or modified.

