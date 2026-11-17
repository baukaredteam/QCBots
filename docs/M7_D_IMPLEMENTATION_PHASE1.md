# Sentinel Atlas — M7-D Implementation Phase 1 Report (isolated dev only)

> Scope: migration 0010, core versioned hypothesis domain, security invariants, targeted tests. Backend Go + SQLite only; no Frontend v3 changes in Phase 1.

## Implemented

### 1) Migration 0010 (`migrations/0010_hunt_hypothesis.sql`)
- **Rebuild (not purely additive).** `hunt_hypotheses` rebuilt with expanded status CHECK (DRAFT/READY_FOR_REVIEW/APPROVED/REJECTED/SUPERSEDED/ARCHIVED), preserving IDs, legacy reviews, investigations, evidence, and `case_hypotheses` links with unchanged parent identities.
- Legacy status mapping per §1 (INVESTIGATION never manufactures approvals: APPROVED only with a legacy APPROVED review row, else READY_FOR_REVIEW).
- Child backup/empty/restore pattern in a single migration transaction (0007-variant made FK-safe: empty child rows first so `DROP TABLE` on the parent succeeds under `PRAGMA foreign_keys=ON`; runMigration records `INSERT OR IGNORE` so reruns are no-ops).
- New tables: `hunt_hypotheses_new` → renamed to `hunt_hypotheses` (final shape, plus `current_version_no`, `report_id`, `relevance_assessment_id`, `author_id`, `generation_method`, idempotency fields, `migrated_from_status`), `hunt_hypothesis_versions`, `hunt_hypothesis_version_events`, `v_hunt_hypothesis_version_state`, `hunt_hypothesis_reviews`, `hunt_hypothesis_evidence` (with `trg_hunt_hyp_evidence_binding` and CTI-source trigger), `hunt_hypothesis_telemetry`, `hunt_plans`, `hunt_plan_steps`, `hunt_hypothesis_activity`; tenant/completeness triggers; partial unique idempotency index.
- Version model: `creation_status` / `draft_revision` / append-only events / composite FK / single UPDATE trigger (DRAFT-only + monotonic revision + immutable identity columns) / transition trigger (legal edges + no orphan supersession + from_status == effective).

### 2) Core Go services (`backend/hunt_domain.go`, `backend/hunt_handlers.go`, routes in `backend/main.go`)
- `CreateHypothesisManual`, `CreateHypothesisFromReport` (same-client COMPLETED assessment binding; idempotent replay/conflict; evidence binding persisted and tenant-validated by DB triggers).
- `GetHypothesisDetail`, `GetHypothesisVersion` (effective state from the view), `EditDraftVersion` (CAS), `SubmitForReview` (benign-explanations gate), `ReviewVersion` (approval/reject/return, original-status effective check), `CreateNewVersion` (supersession), `ListHypothesisHistory`.
- HTTP endpoints registered with the standard middleware chains (`requireAuth/requirePermission/auditWrap/csrfWrap`); live rehearsal via `seed-stagef` + login (admin smoke create 201, analyst-alpha 403 for missing `CanCreateHypothesis`).

### 3) Security invariants
- `CanCreateHypothesis`/`CanViewCTI`-gated create/edit/submit; `CanReviewHypothesis` gates review; author-or-ADMINISTRATOR edit rule; client grant enforced for all roles including ADMINISTRATOR; no DAFT capability invented.

### 4) Tests (35 M7-D tests, including HTTP)
- Migration: preservation (IDs/status mapping/reviews/investigations/links/counts; no manufactured approvals), **rerun convergence**, **single-transaction rollback** (injected mid-migration abort), FK `PRAGMA foreign_key_check` clean.
- Lifecycle/security: D1/D2/D3/D4/D1f/D8/D13/D14/D16/D33/D32/D18/D19/D17/D39/D34-identity/D22-foreign-evidence/D39c-CTI-source/D10(NOT IMPLEMENTED note), plus TestM7dHuntHTTP (401/403/422/201/409/404).
- Full regression: see below.

## D1–D39 coverage

| Implemented & green | Phase-2 / not implemented |
|---|---|
| D1–D4, D8–D9, D11, D13–D22, D32–D39 (logic) | D10 (legacy report without assessment has no M7-D flow — manual report-less path only), D23–D28 (telemetry/plan content beyond tables; services deferred), D29–D30 (migration no-mutation verified in migration suite), D31 (injection quarantine — AI layer not implemented) |

No M6/M7-A/M7-B/M7-C semantic changes; legacy hypothesis views keep reading the mirror.

## Regression evidence

- `go build ./...` — PASS (exit 0)
- `go vet ./...` — PASS (exit 0)
- `go test -run TestM7d...` — PASS (35 tests)
- `go test -timeout 900s -count=1 ./...` — PASS (`ok mssp-workbench`, 304.8s, exit 0)
- `go test -race -run TestM7d` — PASS (161.2s, exit 0)
- Isolated server (`workbench.exe` :8080, `stagef.db` reseeded incl. 0010 via `seed-stagef`) — `/api/v1/health` 200; `POST /api/v1/hypotheses` as ADMINISTRATOR → 201 (`CurrentVersion.EffectiveStatus=DRAFT`); as CTI_ANALYST → 403 (correct role boundary). Server terminated cleanly afterwards; `storage/workbench.db` LastWriteTime unchanged.

## Remaining limitations

1. `generation_method = AI_ASSISTED` flows not implemented (schema ready, no service writes AI rows).
2. Telemetry path editors/plan services not implemented (tables present; Phase 2).
3. Hunt Plan query execution remains out of scope by design (`DRAFT_ONLY` CHECK + `executed_at IS NULL` CHECK).
4. `expires_at` remains unenforced (M7-B carry-over limitation).
5. Stagef seed only covers admin/reviewer/analyst grants — `analyst-multi` lacks grants (unrelated to M7-D code; pre-existing seed gap).

## Correctness patch (post-review, isolated development)

- **P0-1 migration rerun safety:** `runMigration` now checks `schema_migrations` (logical path) before executing. A recorded migration is a verified no-op only if its expected schema markers exist for 0010; otherwise it fails explicitly.
- **P0-2 complete fingerprint:** canonical payload includes report/assessment plus every semantic content field and sorted evidence bindings; created IDs/time excluded. Caller evidence is supported and persisted/validated.
- **P1 CTI_SOURCE tests:** fixed the quoted-placeholder false positive; now assert the named condition for allow/reject cases without syntax/FK ambiguity.
- Regression evidence: `go build` 0; `go vet` 0; `go test -run TestM7d -count=1` ok 28.229s; `go test -timeout 900s -count=1 ./...` ok 223.122s; `go test -race -run TestM7d -count=1` ok 254.433s.
- Regression evidence: `go build` 0; `go vet` 0; `go test -run TestM7d -count=1` ok 34.648s; `go test -timeout 900s -count=1 ./...` ok 274.084s; `go test -race -run TestM7d -count=1` ok 195.137s.
- Server terminated after acceptance; `storage/workbench.db` LastWriteTime unchanged.

## Final evidence-fingerprint patch

- Fingerprint now uses canonical structured JSON tuples over the **complete** merged evidence set (CTI_SOURCE + RELEVANCE + caller inputs), deterministically ordered and deduplicated, excluding generated IDs/timestamps.
- `CreateHypothesisFromReport` assigns the final merged evidence before fingerprinting; manual creation likewise canonicalizes/deduplicates caller evidence before hashing.
- Regression evidence: `TestM7dDerivedEvidenceFingerprintContract` rebuilds the stored fingerprint from persisted evidence rows, replays unchanged, and conflicts on changed caller evidence; `TestM7dEvidenceDedupe` verifies duplicated exact bindings persist once.
- `TestM7dPatchCtiSourceHonestResults` now uses positional SQL placeholders and asserts the named CTI-source trigger error; no syntax/FK error is accepted as the security result.
- Full regression evidence: `go build ./...` 0; `go vet ./...` 0; `go test -run TestM7d -count=1` ok 34.648s; `go test -timeout 900s -count=1 ./...` ok 274.084s; `go test -race -run TestM7d -count=1` ok 195.137s.

## GO/NO-GO

- **Phase 1: GO** — boundaries respected, migration validated, lifecycle/security tests green, full regression green.
- **Production: NO-GO** — unchanged (0010 rebuild procedure + provisioning need separate approval).

STOP after Phase 1. Phase 2 (telemetry/plan services, Frontend, AI surface) not started.
