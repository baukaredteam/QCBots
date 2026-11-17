# Sentinel Atlas — M7-D Design: Threat Hunting Hypothesis Authoring

> Status: **DESIGN ONLY**. No code, migrations, Frontend, or SQLite touched. M7-D implementation requires separate explicit approval. **Default: hypothesis creation requires a COMPLETED same-client relevance assessment** (§3/§7), **approval binds an immutable hypothesis version** (§4/§8), **M7-D never executes queries or deploys detections** (§6/§9).

All file/table/function references below were verified against the working tree at design time. Where this design differs from a prior suggestion (e.g. `docs/M7_D_FUTURE_PLANNING.md`), this document governs.

---

## STAGE 1 — Verified baseline (file/table/function evidence)

### Legacy hypothesis substrate (0001, verified)

| Table (DDL) | Verified columns / enums | M7-D role |
|---|---|---|
| `hunt_hypotheses` (0001:334) | `hypothesis_id, client_id NOT NULL → clients, title, description, threat_actor, campaign, adversary_brain_id → adversary_brains, sector, mitre_tactics, mitre_techniques, expected_behavior, required_log_sources, required_fields, existing_detection_rules, coverage_status IN (COVERED,PARTIAL,NOT_COVERED,UNKNOWN), evidence, supporting_evidence, contradicting_evidence, assumptions, limitations, confidence (free text), priority, status IN (GENERATED,QUALITY_CHECK,PENDING_REVIEW,APPROVED,REJECTED,NEEDS_MORE_DATA,INVESTIGATION,CLOSED), created_at, updated_at` | Identity + content row for M7-D. `title/description/expected_behavior/assumptions/limitations/supporting_evidence` map directly onto the §3 contract. `confidence` is **legacy free text — M7-D forbids numeric confidence** (§3). `coverage_status` conflates deployment states — M7-D supersedes it for new content with the six-state telemetry model (§5); legacy values preserved during migration (§7). |
| `hypothesis_evidence` (0001:363) | `evidence_id, hypothesis_id → hunt_hypotheses, evidence_type (free text), evidence_ref, source, created_at` | Typed-extension target: M7-D adds role/owner columns in 0010 (§7); legacy rows backfilled as `LEGACY` role. |
| `hypothesis_reviews` (0001:372) | `review_id, hypothesis_id, reviewer_id, decision IN (APPROVED,REJECTED,NEEDS_MORE_DATA), reason NOT NULL, reviewed_at` | **Not reused for approval binding** (no version scope). M7-D approval uses new `hunt_hypothesis_reviews` (version-scoped + original-state trigger, mirroring M7-C `relevance_reviews`); legacy table left read-only for history. |
| `investigations` (0001:381) | `investigation_id, hypothesis_id → hunt_hypotheses, client_id NOT NULL, time_range, evidence, analyst_findings, final_verdict IN (TRUE_POSITIVE,FALSE_POSITIVE,INCONCLUSIVE,NEEDS_MORE_DATA), verdict_reason, mitigation_notes, analyst_id, review_timestamp` | Hunt execution log (post-approval TP/FP). M7-D writes here only via existing M6 `CreateCaseInvestigation`-style flows; new hunt plans reference it, never duplicate it. |
| `investigation_evidence` (0001:395) | polymorphic evidence of an investigation | Reused for executed-query evidence (§6 separation of drafted vs executed). |

**Legacy status → M7-D lifecycle mapping (verified gap).** The legacy CHECK (0001:358) lacks DRAFT/READY_FOR_REVIEW/SUPERSEDED/ARCHIVED. Migration 0010 rebuilds `hunt_hypotheses` with a unified CHECK (§7) and applies this documented row mapping:

| Legacy status | M7-D status (0010 rebuild) | Rationale |
|---|---|---|
| GENERATED | DRAFT | Unvalidated authored artifact. |
| QUALITY_CHECK | READY_FOR_REVIEW | Quality gate done, awaiting human decision (conservative: reviewer may still send back). |
| PENDING_REVIEW | READY_FOR_REVIEW | Same queue. |
| NEEDS_MORE_DATA | DRAFT + review row (requires reason; reason was NOT NULL in reviews, but the hypothesis itself had no reason column → mapping stores it in `hypothesis_reviews`-style history; for legacy rows without a reason this is a documented loss, see §13) | Returned to author. |
| APPROVED | APPROVED | Approval preserved; legacy approvals bind legacy version 1 (§7 backfill). |
| REJECTED | REJECTED | Terminal rejection preserved. |
| INVESTIGATION | **Conditional, never manufactured.** APPROVED **only if** a legacy `hypothesis_reviews` row with `decision='APPROVED'` exists for the hypothesis; otherwise **READY_FOR_REVIEW** with `limitation: legacy_investigation_without_approval` (the investigation happened, but approval provenance is unproven). Trigger `trg_legacy_investigation_needs_proof` rejects synthetic approvals without the review row. | "Was investigating" ≠ "was approved"; approval is never fabricated. |
| CLOSED | ARCHIVED | Terminal. |

**Migration validation plan (§7 / D30).** Before rebuild: `SELECT COUNT(*), status FROM hunt_hypotheses GROUP BY status` snapshot + backup copy (`hunt_hypotheses_backup_0010`); after rebuild: row-count equality, status-mapping count equality per the table above, `PRAGMA foreign_key_check` returns **0 rows**, integrity_check OK, indexes present in `sqlite_master`, `schema_migrations` 0010 recorded once (re-runnable). Rollback: single-transaction restore of `hunt_hypotheses` from the backup copy + drop 0010 tables + drop backup. Compatibility: `ListAvailableHypotheses` reads the mirror column (§4); existing `case_hypotheses` links keep their FK target (ids unchanged), so linked-case lists keep working; legacy `hypothesis_reviews` stay untouched and readable.

### M6 case workspace (0004/0005 + `backend/mcp_case.go`, `backend/case_stagee.go` — verified)

- `research_cases` (0004:41): `case_id, idempotency_key UNIQUE, title, description, owner_id, status IN (OPEN,IN_PROGRESS,REVIEW,CLOSED,ARCHIVED)` + 0005 `priority, severity, primary_client, payload_hash`. **No `client_id`** — client-agnostic metadata; CLIENT content gated by grants via `GetResearchCase` (M6 semantics).
- `case_hypotheses` (0005:27): PK `(case_id, hypothesis_id)` link with `linked_at/linked_by`. **M7-D reuses this as the link table**; no separate `research_case_id` column is introduced (single source of truth; the §3 field is derived at read time — §3 note).
- `case_hypothesis_review` (0005:37): PK `review_id`, `(case_id, hypothesis_id, client_id)`, append-only (UPDATE/DELETE triggers), `GetLatestHypothesisReview` (mcp_case.go:803, deterministic by `reviewed_at DESC, rowid DESC`).
- `case_activity` (0005:77): `case_id NOT NULL` + immutability triggers; actions include `hypothesis_linked/unlinked/review_requested`. **Cannot be reused for hypothesis-scoped activity** (case FK is NOT NULL) → new `hunt_hypothesis_activity` mirroring the same immutability pattern (§7).
- `TransitionCaseStatus` (mcp_case.go:889): allowed-transition map + atomic status+activity commit + ARCHIVED terminal + ADMIN-gated archive edge. **Template for M7-D lifecycle enforcement** (`validHypothesisTransitions`).
- `LinkCaseHypothesis`/`UnlinkCaseHypothesis` (case_stagee.go:51/102): idempotent link/unlink, `hasClientGrant(userID, hypClient)` check, CLIENT activity row, archive guard.
- `ListAvailableHypotheses` (case_stagee.go:149): grant-filtered list (for READ model). `ListLinkedHypotheses` (case_stagee.go:204): grant + case access.
- `ReviewCaseHypothesis` (case_stagee.go:277): appends per-client review; requires `CanReviewHypothesis` + grant.
- Idempotency precedents: `research_cases.idempotency_key UNIQUE`; M7-B `case_cti_create_ops` (0007) + `m7bInternalKey` namespacing (case_cti_report.go:16); partial unique index `idx_relevance_req_unique` (0008:39).

### M7-B links (0007 + `backend/case_cti_report.go` — verified)

`case_cti_reports` PK `(case_id, report_id)`, denormalized `client_id` + client-match trigger. M7-D links hypotheses the same way (`case_hypotheses` already exists); creation/linking endpoints must not auto-create grants or widen visibility (same invariant as `requireReportAccess`, case_cti_report.go:66).

### M7-C relevance (0008/0009 + `backend/relevance.go`, `backend/relevance_match.go`, `backend/relevance_handlers.go` — verified)

- `relevance_assessments`: `assessment_id, report_id → cti_reports, client_id → clients, status IN (PENDING,COMPLETED,FAILED), error_code, request_idempotency_key, payload_fingerprint, cti_evidence_snapshot, inventory_snapshot, rule_set_fingerprint, matching_rule_version, evaluation_at` (0009), `created_by, created_at`; partial unique `(client_id, request_idempotency_key) WHERE NOT NULL`.
- `relevance_findings`: one per `(assessment_id, dimension)`; verdicts: SECTOR/TECHNOLOGY MATCH|UNKNOWN only; TELEMETRY MATCH|NO_MATCH|UNKNOWN.
- `relevance_evidence`: typed evidence (sector/technology/log_source/field/detection_rule/indicator/technique/cve/malware/claim/threat_actor/campaign) with `source_reference`, `source_reliability`, `inventory_evidence` (client proof), matching rule+version; cross-assessment mismatch trigger.
- `relevance_snapshots`: canonical documents; `relevance_reviews`: append-only overrides with original-verdict trigger.
- Service: `AssessRelevance` (same-client-only: `report.ClientID != clientID` → 403; grant required; `requireMutation` = CanCreateCTI in service) — idempotent replay 200 / 201 / 409; `GetRelevanceAssessment`; `LatestCompletedAssessment`.
- TELEMETRY MATCH semantics (verified, relevance_match.go): candidate `detection_rule` requires **this client's** `client_log_source_status` row CONNECTED + fresh events (≤7d vs pinned evaluation clock) + fresh `last_checked_at` + every `rule_field_requirements` field active in `global_fields` **and** exact-token present in the client's `field_availability`. Evidence JSON carries client proof. **TELEMETRY MATCH = supported candidate observation path, not proof of deployment/validation.**
- HTTP (relevance_handlers.go): `POST /assess` (auth + CanViewCTI + CanCreateCTI + audit + csrf), `GET` relevance, `GET /clients/{id}/relevant-reports`, `POST /review` (session + CanReviewArtifact + assessment tenant binding + grant; mismatch → 422 by trigger).

### RBAC + grants (verified, `backend/rbac.go`, `backend/tenant.go`)

| Capability | Roles |
|---|---|
| `CanCreateHypothesis` (rbac.go:172) | HYPOTHESIS_WRITER, ADMINISTRATOR |
| `CanReviewHypothesis` (rbac.go:197) | ADMINISTRATOR, REVIEWER |
| `CanLinkHypothesis` (rbac.go:210) | CTI_ANALYST, HYPOTHESIS_WRITER, ADMINISTRATOR |
| `CanCreateCTI` | CTI_ANALYST, ADMINISTRATOR |
| `CanReviewArtifact` | ADMINISTRATOR, REVIEWER |
| `CanGenerateAQL` | HYPOTHESIS_WRITER, ADMINISTRATOR |

Grants: `user_authorized_clients` UNIQUE `(user_id, client_id)` (0004:29); `hasClientGrant(userID, clientID)` checks **without expires_at enforcement** (documented M7-B limitation, carried into M7-D as a known limitation); ADMINISTRATOR is **not** exempt; `GetResearchCase` covers case metadata/participant/ADMIN semantics; GLOBAL case metadata ≠ CLIENT content.

**Verified RBAC gap for M7-D.** `CanCreateHypothesis` exists, but there is no edit/delete capability, no hunt-plan capability, and CTI_ANALYST (who can run relevance assessments and hold report access) cannot author hypotheses. Minimal proposal (no new role): authoring = `CanCreateHypothesis` + grant + ownership/admin rule (§4); REVIEWER keeps review-only (§4). A future `CanEditHypothesis` is **not** introduced — edit is scoped to the author or ADMINISTRATOR.

### CTI ingestion/extraction (0006 + `backend/cti.go` — verified)

`cti_reports` (client tenant, lifecycle NEW→…→ANALYZED→…), `cti_ingestion_runs` (attempt history), `cti_extraction_results` + per-type triggers, extraction tables `indicators/techniques/cves/malware/cti_claims/threat_actors/campaigns`, `file_artifacts`. Three confidences never merged (source reliability / extraction confidence / claim confidence). `GetCTIReport`, provenance endpoint `GET /cti/reports/{id}/provenance` (403/404/legacy semantics).

### Frontend v3 (`frontend/v3/v3.js` — verified)

Report Inspector (`#feed`) with provenance + relevance section + Assess button (per-payload idempotency, 409 alert); Hypothesis Lab (read-only grant-filtered list, `GET /api/v1/hypotheses`); Case Workspace (CTI Context tab + Hypotheses tab + review drawer); all untrusted text via `escEl`/`textContent`; hash routes. M7-D integration touchpoints reuse these views (§10).

---

## STAGE 2 — Workflow and the ten questions

```
CTI Report (M7-A provenance)
  → Client Relevance Assessment (M7-C: SECTOR/TECHNOLOGY/TELEMETRY, evaluation_at)
    → Hypothesis draft v1 (M7-D: falsifiable claim + evidence bindings)
      → Required Telemetry (per-path: sources/fields/availability @ evaluation clock)
        → Hunt Plan (observation paths; query drafts are documentation-only)
          → Analyst Review (version-bound, CanReviewHypothesis, append-only)
            → Approved Artifact (immutable version; investigation in `investigations`)
```

The ten questions answered by the contract (§3):

| # | Question | Answered by |
|---|---|---|
| 1 | Suspicious/adversarial behavior? | `hypothesis_statement` + `suspected_behavior` (falsifiable, §3) |
| 2 | Which CTI evidence supports it? | `hunt_hypothesis_evidence` rows (role SUPPORTING) + legacy `hypothesis_evidence` |
| 3 | Why relevant to this client? | Bound `relevance_assessment_id` + verdicts + evaluation_at (§3/§5) |
| 4 | Observable events for confirm/refute? | `expected_observables` + per-path evaluation criteria (§3/§6) |
| 5 | Sources/event types/fields required? | `hunt_hypothesis_telemetry` per path (§5) |
| 6 | Sufficient client telemetry? | Availability states + timestamp + gaps (§5); UNKNOWN → DRAFT only |
| 7 | Benign alternative? | `known_benign_explanations` + CONTRADICTING evidence (§3) |
| 8 | Blind spots/alternatives? | `blind_spots` + `assumptions` (§3) |
| 9 | How to investigate? | `hunt_plan_steps` (sequence + search drafts) (§6) |
| 10 | Escalation evidence? | `escalation_criteria` + verdict linkage to `investigations.final_verdict` (§6) |

**Foundational rule.** A hypothesis is an analytical claim to be tested, never a conclusion. IOC/ATT&CK presence, M7-C MATCH, or AI text are *inputs*, never proof of compromise. Every claim in §3 carries a fact-class mark: `FACT` (backed by a named evidence row), `INTERPRETATION` (analyst inference, explicitly marked), `SUGGESTION` (AI, unvalidated, `generation_method = AI_ASSISTED`).

---

## STAGE 3 — Hypothesis data contract

### Identity and provenance

| Field | Source | Mandatory | Notes |
|---|---|---|---|
| `hypothesis_id` | `hunt_hypotheses.hypothesis_id` (existing PK) | — | Stable identity across versions. |
| `client_id` | `hunt_hypotheses.client_id` | — | Tenant from creation; immutable (trigger). |
| `report_id` | new FK → `cti_reports` (0010) | Required for CTI-derived drafts; nullable for fully manual | Tenant-consistency trigger: report.client_id must equal hypothesis.client_id. |
| `relevance_assessment_id` | new FK → `relevance_assessments` (0010) | Required when `report_id` is set | Must be a **COMPLETED** assessment for the same (report, client); trigger-enforced. Never reinterpreted with current inventory — `evaluation_at` travels with it. |
| `research_case_id`(s) | derived from `case_hypotheses` | — | **No new column**: `case_hypotheses` is the single source of truth (M6-verified). API exposes `research_case_ids[]`. This deliberately resolves §3's "optional field" without a dual-source FK. |
| CTI source references | `hunt_hypothesis_evidence` rows (`CTI_SOURCE`) with `source_reference` + `source_reliability` copied verbatim, never invented | — | No fabricated references: every row requires a real `cti_reports`/extraction row id. |
| Linked evidence ids | evidence rows (roles below) | — | — |
| Author | `author_id` (new col, 0010) | — | Distinct from possibly later editors. |
| `generation_method` | new col | — | MANUAL \| AI_ASSISTED. AI rows always born DRAFT (§9). |
| `version_no` | `hunt_hypothesis_versions.version_no` | — | Approval binds (hypothesis, version). |
| `created_at`, `updated_at` | existing | — | — |

### Analytical content (stored per version in `hunt_hypothesis_versions`)

| Field | Legacy column reused | Class | Notes |
|---|---|---|---|
| `title` | `hunt_hypotheses.title` | FACT label | — |
| `hypothesis_statement` | `description` (legacy, NOT NULL) | INTERPRETATION | Falsifiable; must state behavior-inside-scope. |
| `suspected_behavior` | `expected_behavior` (legacy) | INTERPRETATION | |
| `adversary_objective` | new per-version column | INTERPRETATION | Nullable. |
| `mitre_tactics` | legacy TEXT | FACT if `mitre_mappings`-backed | **Validated against `mitre_mappings.mitre_technique_id`** — unsupported ATT&CK IDs rejected (422, D8). Free text that matches nothing = unknown, never accepted silently. |
| `mitre_techniques` | legacy TEXT | FACT if validated | Same rule. |
| `threat_actor` / `campaign` | legacy TEXT | FACT only if linked actor/campaign row exists, else INTERPRETATION labeled as claim | Never invent attribution. |
| `malware_context` | new per-version column | FACT if malware row linked | Nullable. |
| `expected_observables` | new (JSON) | INTERPRETATION | Concrete, measurable signals + confirm/refute thresholds (§6). |
| `required_telemetry` | per-path rows in `hunt_hypothesis_telemetry` (§5) | DERIVED (+ FACT rows) | Availability re-derived at authoring AND re-checked at review against the evaluation clock (§5). |
| `expected_event_relationships` | new (JSON/text) | INTERPRETATION | Sequence/correlation of observables. |
| `known_benign_explanations` | new | INTERPRETATION (required at submit) | Cannot submit for review without ≥1 benign hypothesis (422 otherwise, D9). |
| `assumptions` / `blind_spots` | legacy TEXT × 2, extended per-version | INTERPRETATION | — |
| `validation_plan` | new | INTERPRETATION | Shadow/lab plan; must not claim coverage (§5). |
| `investigation_steps` | per-version summary + `hunt_plan_steps` | INTERPRETATION | — |
| `decision_criteria` | new (`escalation_criteria` JSON) | INTERPRETATION | Typed: confirm / refute / escalate thresholds. |
| `limitations` | legacy TEXT | FACT | Always rendered; no numeric `confidence` semantics. |
| `sector` | legacy TEXT | FACT if client sector row exists | Free text otherwise → label as observation. |

### Evidence roles in `hunt_hypothesis_evidence` (0010 extends legacy `hypothesis_evidence`)

`SUPPORTING` (CTI indicators/techniques/cves/malware + M7-C relevance rows), `CONTRADICTING`, `CTI_SOURCE` (provenance), `RELEVANCE` (pointer to `relevance_evidence.evidence_id` — the owner is authoritative, this row only references), `INVESTIGATION` (pointer to `investigation_evidence.evidence_id`), `LEGACY` (backfill). Every row carries `source_reference`, `source_reliability` verbatim, and `inventory_evidence` copy where client-specific. Polymorphic target validated by rule + trigger (evidence ownership: target's `client_id` must equal hypothesis.client_id — cross-client evidence rejected, D22).

---

## STAGE 4 — Hypothesis states, lifecycle, and authorization

### Version lifecycle (authoritative; mirrors `TransitionCaseStatus` pattern)

```
```
                         ┌──────────────────────────┐
                         ▼                          │
 DRAFT ──submit──▶ READY_FOR_REVIEW ──approve──▶ APPROVED (frozen forever)
   ▲                      │                       │  └─edit──▶ v+1 DRAFT created; v-N state event SUPERSEDED
   │                      ├──reject──▶ REJECTED (terminal)
   └──return (no approve)─┘                       └──archive──▶ ARCHIVED (terminal)
 REJECTED ──resubmit──▶ READY_FOR_REVIEW (audit retains the rejection)
```
All arrows are **events in `hunt_hypothesis_version_events`**; version rows are never rewritten (APPROVED rows stay APPROVED — read model shows "APPROVED (superseded by vN+1)" via the supersession event).

### Version immutability + event-log lifecycle (resolves the APPROVED→SUPERSEDED contradiction)

### Version model — one consistent strategy (validated on disposable SQLite)

The lifecycle is an **append-only event log** over **frozen version rows**; only the pointer column `hunt_hypotheses.current_version_no` ever moves. Definitions:

| Term | Meaning | Source of truth |
|---|---|---|
| `creation_status` | Classification at INSERT time on `hunt_hypothesis_versions` (always DRAFT for M7-D authoring; legacy imports keep their historical class) | Version row column |
| `draft_revision` | Monotonic in-DRAFT revision counter (`update → draft_revision + 1`); CAS token for concurrent drafts | Version row column |
| Event order | `rowid` ASC within (hypothesis_id, version_no) — **never `created_at`** (second-precision collisions; tie-break `rowid DESC` precedent: `GetLatestHypothesisReview`) | `hunt_hypothesis_version_events.rowid` |
| `effective_status` | Last event `to_status` for that (hypothesis, version), else `creation_status` | View `v_hunt_hypothesis_version_state` |
| `current_version_no` | The hypothesis's live version pointer | `hunt_hypotheses` row |
| Review `original_status` | Effective status of the reviewed version **at review time** (trigger compares against the derived effective state, not the row's creation status) | `trg_hunt_review_original_status` |
| Approval provenance | Review row + `→ APPROVED` event, both bound to `(hypothesis_id, version_no)`; supersession appends `APPROVED→SUPERSEDED` but never rewrites the APPROVED row | `hunt_hypothesis_reviews` + events |

**Consistency rules.** One UPDATE trigger governs edits (no second, contradictory trigger); DELETE always aborts; an approved/rejected/archived/returned version's content never changes; a DRAFT is editable only before any event exists on it; every event must advance a legal edge and start from the version's current effective status. Supersession is valid only when a strictly newer version row already exists (the service inserts v+1 *before* the supersede event in the same transaction; `trg_hunt_event_transition` rejects orphan supersessions). The review `original_status` is checked against the **effective** state; reviewers also can only review the version that is the pointer target — mismatches abort (D36 analogue for views: reviews of superseded versions succeed but are marked historical, see tests).

**Exact SQL (validated — see Verification note):**
```sql
CREATE TABLE IF NOT EXISTS hunt_hypothesis_versions (
    version_id TEXT PRIMARY KEY,
    hypothesis_id TEXT NOT NULL REFERENCES hunt_hypotheses(hypothesis_id),
    version_no INTEGER NOT NULL,
    creation_status TEXT NOT NULL DEFAULT 'DRAFT'
        CHECK (creation_status IN ('DRAFT','READY_FOR_REVIEW','APPROVED','REJECTED','ARCHIVED')),
    draft_revision INTEGER NOT NULL DEFAULT 0,
    author_id TEXT NOT NULL REFERENCES users(user_id),
    generation_method TEXT NOT NULL DEFAULT 'MANUAL' CHECK (generation_method IN ('MANUAL','AI_ASSISTED')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (hypothesis_id, version_no)
);

CREATE TABLE IF NOT EXISTS hunt_hypothesis_version_events (
    event_id TEXT PRIMARY KEY,
    hypothesis_id TEXT NOT NULL REFERENCES hunt_hypotheses(hypothesis_id),
    version_no INTEGER NOT NULL,
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL CHECK (to_status IN ('DRAFT','READY_FOR_REVIEW','APPROVED','REJECTED','SUPERSEDED','ARCHIVED')),
    actor_id TEXT NOT NULL REFERENCES users(user_id),
    reason TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    /* Composite FK only — the standalone REFERENCES hunt_hypothesis_versions(version_no) is deliberately absent */
    FOREIGN KEY (hypothesis_id, version_no)
        REFERENCES hunt_hypothesis_versions(hypothesis_id, version_no)
);

CREATE VIEW v_hunt_hypothesis_version_state AS
SELECT v.hypothesis_id, v.version_no, v.creation_status,
    COALESCE((SELECT e.to_status FROM hunt_hypothesis_version_events e
              WHERE e.hypothesis_id = v.hypothesis_id AND e.version_no = v.version_no
              ORDER BY e.rowid DESC LIMIT 1), v.creation_status) AS effective_status
FROM hunt_hypothesis_versions v;

-- ONE update policy (P0-1 strategy): reject unless the version is an
-- unsubmitted DRAFT whose revision advances by exactly one.
CREATE TRIGGER trg_hunt_version_update
BEFORE UPDATE ON hunt_hypothesis_versions
WHEN EXISTS (SELECT 1 FROM hunt_hypothesis_version_events e
             WHERE e.hypothesis_id = OLD.hypothesis_id AND e.version_no = OLD.version_no)
   OR NEW.creation_status <> 'DRAFT'
   OR NEW.draft_revision <> OLD.draft_revision + 1
BEGIN
    SELECT RAISE(ABORT, 'version not an unsubmitted editable DRAFT or revision mismatch');
END;

CREATE TRIGGER trg_hunt_version_no_delete
BEFORE DELETE ON hunt_hypothesis_versions
BEGIN SELECT RAISE(ABORT, 'hunt_hypothesis_versions is immutable'); END;

-- Transition + supersession-existence guard.
CREATE TRIGGER trg_hunt_event_transition
BEFORE INSERT ON hunt_hypothesis_version_events
BEGIN
    SELECT RAISE(ABORT, 'illegal transition ' || NEW.from_status || ' -> ' || NEW.to_status)
    WHERE NOT EXISTS (
        SELECT 1 FROM (
            SELECT 'DRAFT' AS f, 'READY_FOR_REVIEW' AS t UNION
            SELECT 'READY_FOR_REVIEW', 'APPROVED' UNION
            SELECT 'READY_FOR_REVIEW', 'REJECTED' UNION
            SELECT 'READY_FOR_REVIEW', 'DRAFT' UNION
            SELECT 'APPROVED', 'SUPERSEDED' UNION
            SELECT 'APPROVED', 'ARCHIVED' UNION
            SELECT 'REJECTED', 'READY_FOR_REVIEW' UNION
            SELECT 'REJECTED', 'ARCHIVED' UNION
            SELECT 'SUPERSEDED', 'ARCHIVED'
        ) edges WHERE edges.f = NEW.from_status AND edges.t = NEW.to_status
    );
    SELECT RAISE(ABORT, 'supercession without newer version')
    WHERE NEW.to_status = 'SUPERSEDED'
      AND NOT EXISTS (
        SELECT 1 FROM hunt_hypothesis_versions v
        WHERE v.hypothesis_id = NEW.hypothesis_id AND v.version_no > NEW.version_no
    );
    SELECT RAISE(ABORT, 'event from_status mismatch vs effective state')
    WHERE NEW.from_status <> COALESCE(
        (SELECT e.to_status FROM hunt_hypothesis_version_events e
         WHERE e.hypothesis_id = NEW.hypothesis_id AND e.version_no = NEW.version_no
         ORDER BY e.rowid DESC LIMIT 1),
        (SELECT v.creation_status FROM hunt_hypothesis_versions v
         WHERE v.hypothesis_id = NEW.hypothesis_id AND v.version_no = NEW.version_no)
    );
END;

CREATE TRIGGER trg_hunt_event_no_update BEFORE UPDATE ON hunt_hypothesis_version_events
BEGIN SELECT RAISE(ABORT, 'events are immutable'); END;
CREATE TRIGGER trg_hunt_event_no_delete BEFORE DELETE ON hunt_hypothesis_version_events
BEGIN SELECT RAISE(ABORT, 'events are immutable'); END;

CREATE TABLE IF NOT EXISTS hunt_hypothesis_reviews (
    review_id TEXT PRIMARY KEY,
    hypothesis_id TEXT NOT NULL REFERENCES hunt_hypotheses(hypothesis_id),
    version_no INTEGER NOT NULL,
    reviewer_id TEXT NOT NULL REFERENCES users(user_id),
    decision TEXT NOT NULL CHECK (decision IN ('APPROVED','REJECTED','NEEDS_MORE_DATA')),
    reason TEXT NOT NULL,
    original_status TEXT NOT NULL,
    reviewed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (hypothesis_id, version_no)
        REFERENCES hunt_hypothesis_versions(hypothesis_id, version_no)
);
CREATE TRIGGER trg_hunt_review_original_status
BEFORE INSERT ON hunt_hypothesis_reviews
BEGIN
    SELECT RAISE(ABORT, 'original_status mismatch')
    WHERE NEW.original_status <> COALESCE(
        (SELECT e.to_status FROM hunt_hypothesis_version_events e
         WHERE e.hypothesis_id = NEW.hypothesis_id AND e.version_no = NEW.version_no
         ORDER BY e.rowid DESC LIMIT 1),
        (SELECT v.creation_status FROM hunt_hypothesis_versions v
         WHERE v.hypothesis_id = NEW.hypothesis_id AND v.version_no = NEW.version_no)
    );
    SELECT RAISE(ABORT, 'review must bind current version')
    WHERE NOT EXISTS (
        SELECT 1 FROM hunt_hypotheses h
        WHERE h.hypothesis_id = NEW.hypothesis_id AND h.current_version_no = NEW.version_no
    );
END;
```

**Revised state reading rules.**
- Approval: review row + event `→ APPROVED`. The version row's `creation_status` never changes.
- "Edit APPROVED": service inserts **v+1 row (creation_status DRAFT)** first, then the supersede event on **vN**, then bumps `current_version_no` — one tx.
- "Return for more data": event `READY_FOR_REVIEW→DRAFT` on the **same** version (post-submit content edits append a new version; the event records why).
- ARCHIVED: event only. REJECTED: event only.
- The legacy `hunt_hypotheses.status` mirror is a **computed derivative** written by the service in the same tx (`DRAFT` unless the current version's effective status maps into the legacy enum) — never authoritative.
- Supersession reconciliation (test-only query): every SUPERSEDED event must have a strictly newer version with a `version_created` event committed earlier in event order. Orphan supersessions → migration/test failure, not a silent state.

**Optimistic concurrency.** Every event insert and DRAFT edit carries the expected pointer/revision: DRAFT content edits CAS on `draft_revision` (`UPDATE ... SET draft_revision = draft_revision + 1 WHERE version_id = ? AND draft_revision = ?` → 0 rows = stale → 409); lifecycle events CAS on `hunt_hypotheses.current_version_no`. Both mirror `TransitionCaseStatus`/M7-B atomicity precedents.

Lifecycle text-map (unchanged in intent; now implemented via events, not row rewrites):

| Edge (effective state) | Mechanism | Rule |
|---|---|---|
| DRAFT | READY_FOR_REVIEW | Event; submit gates (§5) apply. |
| READY_FOR_REVIEW | APPROVED | Reviewer decision event; binds (hypothesis, version); `creation_status` stays DRAFT and events are authoritative — approval provenance is the review row + APPROVED event, never a row rewrite. |
| READY_FOR_REVIEW | REJECTED | Same pattern; rejection historical. |
| READY_FOR_REVIEW | DRAFT | "Needs more data" event; subsequent content edits append a new version (original version remains in history, review row retains the `NEEDS_MORE_DATA` decision). |
| APPROVED | SUPERSEDED (effective) | Only via v+1 creation event (see above). |
| REJECTED | READY_FOR_REVIEW | Re-submission event (amendment needs new version if content changed). |
| any non-terminal | ARCHIVED | Terminal event; any later write attempt → 422/409. |
| ARCHIVED | — | Terminal. |

### Concurrency, idempotency, tenancy

- **Optimistic concurrency**: every mutation carries `expected_version_no`; `UPDATE ... WHERE current_version_no = ?` — 0 rows → 409 (D21).
- **Idempotent creation**: partial unique index `(client_id, request_idempotency_key) WHERE NOT NULL` on `hunt_hypotheses` + persisted `payload_fingerprint` (canonical JSON of hypothesis identity fields, same pattern as M7-C): same key + same fingerprint → 200 replay (existing id); same key + different fingerprint → 409; new key → new attempt (D1/D14/D15).
- **Immutable history**: version rows, reviews, events, and activity are append-only (UPDATE/DELETE triggers, mirroring 0005/0008). The single exception: an unsubmitted DRAFT's **row content** may be edited in place (trigger-enforced: never after any event exists on that version). Every other change appends a new version/event/review (D17).
- **Grants**: `hasClientGrant(userID, clientID)` on every read/write; revocation takes effect immediately (predicate evaluated per-request; no cached grants). ADMINISTRATOR is not exempt. GLOBAL case access never widens hypothesis visibility (M6 predicate reused).
- **No QRadar/investigation auto execution**: there are no M7-D writes to `detection_rules`, `investigations` (except via existing `CreateCaseInvestigation` flow), or QRadar; hunt plan query text is stored as draft documentation only (§6).

### Who may do what (minimal, no new roles)

| Action | Capability | Grant check |
|---|---|---|
| Create DRAFT (manual or from report/assessment) | `CanCreateHypothesis` | grant for `client_id` |
| Edit own DRAFT | `CanCreateHypothesis` + author match (ADMINISTRATOR may edit any DRAFT) | grant |
| Submit / re-submit | author (or ADMIN) | grant |
| Hunt-plan authoring/editing on DRAFT versions | author (or ADMIN); plan binds the version being edited | grant |
| Review / approve / reject | `CanReviewHypothesis` (REVIEWER, ADMINISTRATOR) | grant for hypothesis.client_id + assessment binding check |
| Link/unlink to case | `CanLinkHypothesis` | existing M6 semantics |
| Read | `CanViewCTI` + grant | grant; case-scoped uses `GetResearchCase` workflow |

**Explicit decision recorded:** CTI_ANALYST can produce relevance assessments and link hypotheses, but **cannot author** (needs HYPOTHESIS_WRITER or ADMINISTRATOR). If the business requires analyst-authored drafts, the later minimal extension is `CTI_ANALYST.CanCreateHypothesis = true` in `rbac.go` — flagged as a product decision, not assumed (§13).

---

## STAGE 5 — Telemetry requirements and the six-state model

Per **observation path** (a path = one way to observe the hypothesis; a hypothesis may have several), `hunt_hypothesis_telemetry` stores:

| Field | Source | Notes |
|---|---|---|
| `log_source_type_id` | → `log_source_types` (FK) | Required log source. |
| `event_categories` | JSON (free text, e.g. `process_start`) | Event types/IDs. |
| `required_fields` | JSON of `field_id`s verified in `global_fields.is_active` | Mirrors `rule_field_requirements` semantics. |
| `optional_fields` | JSON | — |
| `data_components` | JSON ATT&CK data-component refs (must exist in `mitre_mappings` or be labeled free-text) | Unguessable refs rejected like ATT&CK IDs. |
| `client_field_availability` | **copied from the client's `client_log_source_status.field_availability` at authoring time** (free text) + exact-token match status | Evidence of *how* presence was verified. |
| `field_verified_at` | copied `last_checked_at` | — |
| `telemetry_staleness_days` | computed vs the **assessment's `evaluation_at`** (and, at review, vs a fresh pinned `evaluation_at` for the review event — never silently reinterpreted, §2) | — |
| `availability_state` | derived: AVAILABLE / UNAVAILABLE / UNKNOWN | Computed from client row: CONNECTED+fresh+fields = AVAILABLE; NOT_CONNECTED = UNAVAILABLE; else UNKNOWN. |
| `rule_exists` | derived: a `detection_rules` row whose `mitre_techniques` contains any hypothesized technique AND `required_log_sources` covers this path's source | Inventory fact only. |
| `rule_validated` / `rule_deployed` | **always UNKNOWN** | No source of truth exists in the current inventory (verified: `detection_rules` has `rule_status`, but nothing proves per-client deployment or validation). This is the load-bearing honesty rule of M7-D. |
| `gaps` / `blind_spots` | JSON text | — |

**Six states, strictly separated** (UI shows labeled badges; legacy `coverage_status` is **not** reused for display):

1. Telemetry available (verified client row) · 2. Telemetry unavailable (NOT_CONNECTED) · 3. Telemetry unknown · 4. Detection rule exists · 5. Detection rule validated — UNKNOWN (unproven) · 6. Detection rule deployed — UNKNOWN (unproven).

**Submission gate.** READY_FOR_REVIEW requires: ≥1 telemetry path row, `known_benign_explanations` non-empty, benign-basis and blind-spots non-empty, ATT&CK validated, assessment bound. If **all** paths are UNKNOWN, the hypothesis may be submitted but the UI/API must label it "unvalidated observability" and approval displays a warning marker (`oversight_warning: unvalidated_observability` in the response) — **approval never implies deployment or validation**.

**Freshness rule.** Authoring copies M7-C evidence + its `evaluation_at`. Review re-derives availability from *current* inventory BUT comments it against the pinned `evaluation_at`; the UI shows both "as-evaluated (assessment)" and "current" columns. Nothing is silently reinterpreted.

---

## STAGE 6 — Hunt Plan design

`hunt_plans` — one per hypothesis version (header; all sections required at submission):

- `objective`, `scope_and_boundary` (client id + report/assessment refs; scope must not exceed the client's grant).
- `cti_justification` (JSON: evidence ids + one-line interpretations — facts keep their evidence rows).
- `expected_observables` (JSON, mirrors version field; the plan is the operational copy).
- `data_sources_and_fields` (JSON aggregate of telemetry paths).
- `known_benign_activity`, `false_positive_considerations`, `evidence_collection_requirements`, `validation_criteria` (JSON confirm/refute), `escalation_criteria` (JSON), `blind_spots`, `analyst_notes` (free text, `visibility_scope`-agnostic per-client record).
- `query_execution_status` = `DRAFT_ONLY` (constant CHECK; execution is out of M7-D scope).

`hunt_plan_steps` — ordered steps (`step_no`), each: `kind IN (SEARCH_DRAFT, INVESTIGATE, VALIDATE, ESCALATE)`, `title`, `description`, `path_id` (→ telemetry path), `data_sources`, `fields`, `query_draft` (documentation-only; must pass the §9 prompt-injection/unsafe-content scan on write), `executed_at NULL`, `execution_evidence_id NULL`. **Executed steps are never created in M7-D**; `executed_at` is reserved and CHECK-constrained to NULL in 0010 (future milestone may add a controlled write path).

Separation of planes (first-class, enforced in UI and API):

| Plane | Stored where | Status |
|---|---|---|
| What must be investigated | plan header/steps | — |
| What data is available | telemetry rows (§5) | — |
| What queries *could* be drafted | `query_draft` | DRAFT_ONLY |
| What queries *were executed* | `investigations` (existing) via future milestone | not writable in M7-D |
| What findings were validated | `investigations.final_verdict` (existing) | not writable in M7-D |

A hunt plan is readable by an SOC analyst with **no LLM in the loop**: all text fields are complete sentences; every structured term has a legend in the API response (`field_classes`).

---

## STAGE 7 — Proposed migration 0010 (DDL sketch)

Additive; no destructive rewrites outside `hunt_hypotheses`/`hypothesis_evidence` CHECK expansions (precedent: 0007 `case_activity` rebuild). Migration runner requirements: rerunnable (idempotent creates + column-exists fallback), `INSERT OR IGNORE` in `schema_migrations`, row-count verification, backup-first rollout (no auto-migration at runtime), transaction-wrapped.

1. **Rebuild `hunt_hypotheses` — this migration is NOT purely additive.** It includes a legacy table rebuild (precedent: 0007 `case_activity` rebuild). Preserving all rows verified by count + spot checksum. Rebuild steps, in one transaction: `CREATE TABLE hunt_hypotheses_new (... same columns ..., status CHECK (DRAFT, READY_FOR_REVIEW, APPROVED, REJECTED, SUPERSEDED, ARCHIVED), report_id NULL → cti_reports, relevance_assessment_id NULL → relevance_assessments, author_id → users, generation_method IN (MANUAL, AI_ASSISTED) DEFAULT MANUAL, current_version_no INTEGER NOT NULL DEFAULT 1, request_idempotency_key NULL, payload_fingerprint NULL)` keeping legacy columns (`coverage_status`, `confidence`, …) for read-compat; `INSERT INTO hunt_hypotheses_new (shared columns) SELECT ..., CASE status WHEN 'GENERATED' THEN 'DRAFT' WHEN 'QUALITY_CHECK' THEN 'READY_FOR_REVIEW' WHEN 'PENDING_REVIEW' THEN 'READY_FOR_REVIEW' WHEN 'NEEDS_MORE_DATA' THEN 'DRAFT' WHEN 'APPROVED' THEN 'APPROVED' WHEN 'REJECTED' THEN 'REJECTED' WHEN 'INVESTIGATION' THEN CASE WHEN EXISTS (SELECT 1 FROM hypothesis_reviews r WHERE r.hypothesis_id = hunt_hypotheses.hypothesis_id AND r.decision = 'APPROVED') THEN 'APPROVED' ELSE 'READY_FOR_REVIEW' END WHEN 'CLOSED' THEN 'ARCHIVED' END FROM hunt_hypotheses; `DROP TABLE hunt_hypotheses;ALTER TABLE hunt_hypotheses_new RENAME TO hunt_hypotheses;` recreate FK-dependent child references unchanged (ids stable; no FK rewrites — children point at `hypothesis_id`), rebuild indexes (/client-status), recreate row counts. FKs on `case_hypotheses`, `hypothesis_evidence`, `hypothesis_reviews`, `investigations`, `investigation_evidence` remain satisfiable because primary keys never change; assert `PRAGMA foreign_key_check` returns **0 rows** post-commit.
   - Partial unique: `(client_id, request_idempotency_key) WHERE NOT NULL` (M7-C pattern).
   - Rollback (single-transaction): `CREATE TABLE hunt_hypotheses_backup_0010 AS SELECT * FROM hunt_hypotheses` before rebuild; on any failed validation step or aborted migration: drop all new tables/views, restore `hunt_hypotheses` from the backup copy (FKs re-pointed), drop the backup. The migration runner's transaction wraps all of it, so an interrupted run leaves the pre-state; `INSERT OR IGNORE INTO schema_migrations` records only the committed version and reruns are no-ops (idempotent rerun-tolerant: duplicate-column safe via `columnExistsTx` precedent).
   - Rows **preserved by identity (id unchanged)**, original legacy statuses preserved into `hunt_hypotheses.status` mirroring, legacy `hypothesis_reviews` rows untouched and readable, legacy `investigations` untouched, `case_hypotheses` links untouched (no new approvals manufactured — INVESTIGATION without an APPROVED review row maps to READY_FOR_REVIEW, never APPROVED; `trg_legacy_investigation_needs_proof` mirrors this rule for any manual replay).
2. **Backfill** `hunt_hypothesis_versions` v1 per hypothesis (content snapshot); APPROVED legacy rows get a review row marked `LEGACY_IMPORT` (append-only; honest provenance). Every backfilled version gets a genesis view: `creation_status` = mapped status, effective `creation_status` until any new event.
3. **`hunt_hypothesis_versions`** — exactly as §4's SQL sketch (`creation_status`, `draft_revision`, content snapshot with all §3 fields, `UNIQUE(hypothesis_id, version_no)`, `version_id` PK).
   **3b. `hunt_hypothesis_version_events`** — exactly as §4's SQL sketch (`event_id` PK, **composite FK only**, from/to, actor, reason, `created_at`; event sequence = `rowid`); append-only triggers; `trg_hunt_event_transition` validates the edges (§4 SQL, AS + edges alias grammar as validated); `v_hunt_hypothesis_version_state` derives effective status as `COALESCE(last event to_status, creation_status)`.
   Reconciliation assertion (tests / D17+D30): every `SUPERSEDED` event has a strictly newer version row; no `version_created`-style ordering is inferred from timestamps — supersession is valid only because the newer version row was committed earlier in the same transaction (service discipline + `trg_hunt_event_transition` does NOT rely on timestamp equality).
   **Update policy (single trigger, P0-1 corrected):** `trg_hunt_version_update` allows UPDATE iff (no events exist for that version) AND `NEW.creation_status='DRAFT'` AND `NEW.draft_revision = OLD.draft_revision + 1`; `trg_hunt_version_no_delete` aborts DELETE unconditionally. There is **no second unconditional UPDATE trigger** — the draft edit is guarded in exactly one place.
4. **`hunt_hypothesis_evidence`** — `evidence_id` PK, `hypothesis_id FK`, `version_no` (null = legacy), `evidence_role IN (SUPPORTING, CONTRIBUTING… → SUPPORTING, CONTRADICTING, CTI_SOURCE, RELEVANCE, INVESTIGATION, LEGACY)`, polymorphic target `target_entity_type + target_entity_id`, `source_reference`, `source_reliability`, `client_id` (denormalized), `UNIQUE(version_id, role, target_type, target_id, matching_rule_id)`.
5. **`hunt_hypothesis_telemetry`** — per §5 columns, `UNIQUE(version_id, log_source_type_id, kind)`; denormalized `client_id` + tenure trigger checking it matches the hypothesis's.
6. **`hunt_plans`** one per version: `version_id PK → versions`, header text/JSON fields (all §6), `query_execution_status CHECK ('DRAFT_ONLY')` constant.
7. **`hunt_plan_steps`** — `(plan_version_id, step_no)` PK, `kind IN (SEARCH_DRAFT, INVESTIGATE, VALIDATE, ESCALATE)`, `path_id → telemetry`, `query_draft`, `executed_at NULL` with `CHECK (executed_at IS NULL)` in 0010.
8. **`hunt_hypothesis_reviews`** — `review_id` PK, `hypothesis_id + version_no FK`, `reviewer_id`, `decision IN (APPROVED, REJECTED, NEEDS_MORE_DATA)`, `reason NOT NULL`, `original_status` (must equal the version's status at review time — trigger mirroring `trg_relevance_review_original_match`), `reviewed_at`; immutability triggers.
9. **`hunt_hypothesis_activity`** — `activity_id` PK, `hypothesis_id FK`, `version_no NULL`, `user_id`, `action IN (draft_created, version_created, submitted, approved, rejected, returned_for_more_data, superseded, archived, plan_attached, telemetry_attached, linked, unlinked)`, optional `client_id NOT NULL`-for-client-scoped-actions, `details`, `created_at`; immutability triggers (mirrors `case_activity`).
10. **Tenant triggers**: `trg_hypothesis_report_client_match` (report.client == hypothesis.client), `trg_hypothesis_assessment_match` (assessment report/client == hypothesis report/client and `status = 'COMPLETED'`), `trg_hypothesis_evidence_owner` (target client's row must equal hypothesis.client or target is global catalogue), `trg_hypothesis_assessment_freshness` (documents in evidence must reference the *bound* assessment only).
11. **Reuse**: `case_hypotheses` unchanged — M7-D uses it for case linkage. `hypothesis_reviews`/`investigations` unchanged (legacy/history). Legacy `hypothesis_evidence` read-only after 0010 (no new writes; new rows in `hunt_hypothesis_evidence`).

---

## STAGE 8 — Service and API contract

Middleware chain (following relevance_handlers.go): `applyMiddleware(handler, requireAuth, requirePermission(...), auditWrap, csrfWrap)` for mutations; GETs omit csrf. Service layer mirrors `case_cti_report.go` patterns: `requireM7Schema()`-style gate upgraded to `requireM7DSchema()` (tables of 0010 present, else 503), `requireReportAccess`-style helpers, savepoint-wrapped write transactions with checked errors (M7-C P0-1 pattern), optimistic concurrency by `expected_version_no`, filter-before-pagination.

| Endpoint | Chain | Semantics |
|---|---|---|
| `POST /api/v1/hypotheses/from-report` `{report_id, client_id, assessment_id, idempotency_key}` | auth + CanCreateHypothesis + CanViewCTI + audit + csrf | Create draft v1 pre-filled from report+assessment; **report.client must equal client**; assessment must be COMPLETED & bound; idempotent (200 replay / 201 / 409 on changed fingerprint). |
| `POST /api/v1/hypotheses` (manual) `{client_id, title, description, …, idempotency_key}` | same | Manual draft; ATT&CK validated; benign explanations optional at DRAFT, mandatory at submit. |
| `GET /api/v1/hypotheses?client_id&status&limit&offset` | auth + CanViewCTI + audit | Grant-filtered (existing `ListAvailableHypotheses` semantics). |
| `GET /api/v1/hypotheses/{id}` | auth + CanViewCTI + audit | Hypothesis + current version + telemetry + plan + latest review + history pointers. |
| `GET /api/v1/hypotheses/{id}/versions/{v}` | same | Immutable version snapshot. |
| `PATCH /api/v1/hypotheses/{id}/versions/{v}` | + CanCreateHypothesis (author/admin) | Edit DRAFT only; carries `expected_version_no`; on APPROVED version → creates v+1 DRAFT + SUPERSEDES (409 if version drift). |
| `PUT /api/v1/hypotheses/{id}/versions/{v}/telemetry` | same | Replace telemetry path rows of the DRAFT (whole-set replace in tx). |
| `PUT /api/v1/hypotheses/{id}/versions/{v}/plan` | same | Replace hunt plan + steps of the DRAFT. |
| `POST /api/v1/hypotheses/{id}/versions/{v}/submit` | author/admin | Submit → READY_FOR_REVIEW (validation gates: benign explanations, telemetry rows, validated ATT&CK, assessment binding). |
| `POST /api/v1/hypotheses/{id}/versions/{v}/review` | auth + CanReviewHypothesis + audit + csrf | Append-only decision (APPROVED/REJECTED/NEEDS_MORE_DATA); `original_status` trigger-checked → 422 on drift; atomic version status + activity. |
| `GET /api/v1/cases/{case_id}/hypotheses` (exists) | existing | Unchanged semantics; new hypotheses appear via existing `case_hypotheses` link. |
| `GET /api/v1/hypotheses/{id}/history` | auth + CanViewCTI + audit | Versions + reviews + activity (grant-filtered). |

Status taxonomy: 200 ok/replay · 201 created · 400 validation · 401 unauthenticated · 403 no grant/permission/tenant mismatch · 404 missing (report/assessment/version/plan) · 409 idempotency conflict / version conflict / ARCHIVED write / duplicate link · 422 ATT&CK invalid / benign-missing / verdict drift / prompt-injection detected · 500 internal · 503 0010 schema not applied. Pagination: `limit` default 20 / max 100, `offset`; `total` computed on the authorized set; filter before paginate (M7-B pattern). Audit: every mutation writes `hunt_hypothesis_activity` + the HTTP `auditWrap` log (no secrets).

**Approval semantics.** Approval is a review row binding `(hypothesis_id, version_no)`; it never edits version content. Any later edit creates a new version; the approval stays attached to the old version forever (visible in balance of history). Investigative execution against an APPROVED version is recorded in `investigations` by existing flows; M7-D adds no execution endpoints.

---

## STAGE 9 — AI-assisted hypothesis generation (future; design only)

**Boundary:** no harness is implemented. The future component is a *caller of these same service endpoints* operating under the human's session; it receives **no direct database access** (established invariant: AI harness → API/MCP only).

### Contracts

- **Input** (`GenerationInput`): `report_id`, `assessment_id` (pinned), `client_id`, `actor_user_id`, `idempotency_key`, `tenant_grants` (implicit via session), existing hypothesis ids for de-duplication (same client only).
- **Allowed derivation surface**: extracted IOC/TTP/claims rows of that report, M7-C findings + evidence + snapshot references, client telemetry snapshot, `mitre_mappings` catalogue, hunt plan templates. Everything else is out-of-band for v1.
- **Output** (`GenerationOutput`): `title, hypothesis_statement, suspected_behavior, adversary_objective, mitre_tactics, mitre_techniques, expected_observables, required_data_sources, benign_alternatives, unknowns, blind_spots, suggested_hunt_steps, justification`; **every field cites evidence ids from the input surface**; everything else is labeled `SUGGESTION`.

### Security invariants (hard requirements for any future harness)

1. **CTI text is untrusted data.** Report/claim/indicator text must never be interpreted as instructions; outputs are validated as data (schema + field classes), never executed.
2. **Do not block the report.** Instruction-like payload **anywhere inside a report is not, by itself, grounds to reject the report or the analysis.** Defensive analysis must proceed on the remaining evidence. (Prompt-injection resistance is a *containment* requirement, not a gag order.)
3. **Quarantine-and-flag policy.** When the scanner finds instruction-like spans:
   - **Quarantine** the spans — they are stripped from the agent-visible context (or, when they are inline in evidence, rendered to the analyst as `CONTAMINATED: <span>` without the agent treating them as evidence rows), and a `prompt_injection_flag` activity/audit row records presence + location + quarantine channel.
   - **Continue** legitimate defensive analysis on the non-injected evidence (DRAFT hypothesis may still be produced; verdicts are capped at `UNKNOWN` for any dimension whose evidence was quarantined away).
   - **Reject prohibited actions at the tool layer.** A span that *commands* a tool call, privilege grant, secret read, or external query is never forwarded as an instruction; the attempted command is dropped, noted in the flag, and the run continues without it.
   - **Never control authorization, secrets, or external actions.** Injected text cannot read secrets, cannot widen scope, cannot reach tools, and cannot trigger outbound requests; authorization stays with `hasClientGrant`/RBAC server-side. Any output citing a quarantined span as evidence fails; any output influenced by injected directives is rejected at review.
4. **Tenant isolation.** The generator sees only the actor's authorized client rows (same predicates as UI reads); no cross-tenant context ever enters the prompt.
5. **No direct DB access; no automatic approval; no external queries** (no QRadar API calls; no outbound network); **no fabricated confidence or verification status** (all six-state fields §5 remain UNKNOWN unless inventory-bound; `SUGGESTION`-class text is always distinguished).

### Integration

The generator is a **caller of the §8 endpoints** (create-draft with `generation_method = AI_ASSISTED`). AI drafts are always DRAFT with `oversight_warning` until a human submits and approves. The generator's model metadata (harness, template, model, timestamp) is recorded in `generation_method`-adjacent audit fields (`created_by`, `generation_template`), per the M7-D future-planning addendum's audit requirements.

---

## STAGE 10 — Frontend v3 integration (existing views only)

Use existing `pageShell`/`escEl`/`api` helpers (v3.js); all untrusted text via `textContent`; hash routes. New UI states: `empty` (no hypotheses yet), `loading` (`statebox`), `unauthorized` (403 hidden section, as in M7-C), `UNKNOWN` (amber badges), `stale` (assessment older than a "fresh" boundary → banner "assessment is stale; re-assess before review" — review still allowed but flagged), `FAILED` (assess-shaped error surfaces).

| View | Additions |
|---|---|
| **Report Inspector (`#feed`)** | "Create Hypothesis from Report" button (visible only for `CanCreateHypothesis` roles; disabled with reason otherwise); assessment picker (defaults to latest COMPLETED); after creation, link to the Hypothesis Lab. Reuses the M7-C "Client Relevance" section for supporting evidence display. |
| **Hypothesis Lab (`#hypotheses`)** | Extend existing grant-filtered list with status lifecycle badges (DRAFT mint-outline, READY_FOR_REVIEW amber, APPROVED mint, REJECTED muted, SUPERSEDED/ARCHIVED muted) and telemetry-gap indicators (per hypothesis: AVAIL/UNAVAIL/UNKNOWN counts + "unvalidated" marker). Detail pane: version timeline, telemetry per-path cards, review form (ADMINISTRATOR/REVIEWER), submit button (author). |
| **Case Workspace — Hypotheses tab** | Linked hypotheses via existing `GET /cases/{id}/hypotheses`; Hunt Plan previews collapsible; review/action buttons per role; activity history (from `hunt_hypothesis_activity`). |
| **Research Case CTI tab** | Unchanged; relevance badges already shown (M7-C). |
| **Client Intelligence (`#clients`)** | Per-client hypothesis list with status + telemetry gaps (reach via existing `GET /api/v1/hypotheses?client_id=`). |

Cross-navigation: Hypothesis Lab → linked case(s) (inspect link); Case Workspace → hypothesis detail (deep link). No new top-level routes beyond `hypotheses` detail segments.

---

## STAGE 11 — Acceptance matrix (D1–D39)

Tests assume the §8 API, §7 DDL, and M7-C invariants. "DB" assertions are direct SQL counts/checks; "HTTP" are status codes through the real middleware chain (`requireAuth/requirePermission/auditWrap/csrfWrap`).

| ID | Scenario | DB assertions | HTTP assertions |
|---|---|---|---|
| D1 | Authorized same-client create (HYPOTHESIS_WRITER + grant) | 1 hypothesis + v1 DRAFT + evidence rows + activity row | 201; body contains version 1 |
| D2 | Cross-client create (attempt with other client's report) | 0 rows | 403; no metadata leaked |
| D3 | Revoked grant mid-flow | 0 new rows; later GET 403/empty | 403 lists; read 403 |
| D4 | Create with missing relevance assessment | 0 rows; error names the missing assessment | 404/422 (documented: 404) |
| D5 | UNKNOWN sector/technology in assessment | Draft created; verdicts shown UNKNOWN; hypothesis labeled unverified | 201; response shows UNKNOWN |
| D6 | Missing telemetry (no client rows) | Telemetry rows exist with AVAIL=UNKNOWN | 201; UI badge "unknown" |
| D7 | Stale telemetry (>7d at evaluation_at) | Availability UNKNOWN with staleness note | 201; freshness banner in UI response |
| D8 | Unsupported ATT&CK IDs | 0 rows | 422 |
| D9 | Submit without benign explanations | Status stays DRAFT | 422; error names the field |
| D10 | Legacy report (no extraction runs) | Draft created, evidence = CTI_SOURCE only, limitations note legacy | 201; limitations present |
| D11 | Manual hypothesis (no report) | report_id NULL; generation_method MANUAL | 201 |
| D12 | AI-drafted hypothesis | generation_method AI_ASSISTED; status DRAFT; no approval possible until human review | 201 |
| D13 | Idempotent replay (same key+payload) | Exactly 1 hypothesis for the key | 200 (existing id) |
| D14 | Same key, changed payload | Still 1 row | 409 |
| D15 | Concurrent create, same key | 1 row (unique index serializes) | One 201 / one 200 same id (never 2 rows) |
| D16 | DRAFT edit succeeds before submission | Content updated; `draft_revision` 0→1; versions count unchanged; no lifecycle events | 200 |
| D17 | Edit APPROVED version | v+1 created (DRAFT); vN's row **bit-identical** (UPDATE aborts); supersession recorded **only** as an event + pointer bump; approvals bind vN; vN historical approval still readable | 201 (v+1); `GET` vN shows "APPROVED (superseded by vN+1)" |
| D18 | Unauthorized approval (CTI_ANALYST) | 0 review rows; status unchanged | 403 |
| D19 | Analyst rejection (REVIEWER) | version REJECTED (effective); review row appended; history intact | 201 |
| D20 | Concurrent DRAFT edit with stale draft_revision | Stale writer untouched (0 rows); second writer 409s | 409 |
| D21 | Version conflict (stale expected_version_no) | Status unchanged; legacy `hunt_hypotheses.status` mirror untouched for the loser | 409 |
| D22 | Evidence from another client | 0 new evidence rows | 422 (trigger abort surfaces as 422) |
| D23 | Research Case access control (GLOBAL case w/o CLIENT grant) | Linked hypothesis hidden | 403/empty, no metadata leak |
| D24 | GLOBAL vs CLIENT isolation (linked case content) | Other clients' hypotheses not listed | List total excludes foreign rows |
| D25 | Malicious CTI text (prompt-injection in claim) | Quarantined spans flagged (`prompt_injection_flag` audit); draft still produced from remaining evidence; quarantined spans never cited as evidence; no tool instructions executed (no writes beyond flag) | 201 (draft continues; `oversight_warning` present) |
| D26 | Hunt plan with multiple observation paths | 2 telemetry paths + 2+ steps; executed_at NULL on all | 201 plan; steps visible |
| D27 | Missing-field behavior (required field not in availability) | Path AVAILABLE=UNKNOWN for that field | 201; unknowns list the field |
| D28 | No automatic AQL execution | No `detection_rules` writes; no investigation rows created by M7-D endpoints | — (system invariant) |
| D29 | No mutation of M6/M7-A/M7-B/M7-C tables | Byte-identical row counts + checksums before/after a full D1→approve flow (query assertion) | — |
| D30 | Migration integrity & rollback + INVESTIGATION rule | Fresh DB migrates 0001→0010 cleanly (integrity + FK ok, legacy rows preserved, status mapping counts match, INVESTIGATION-with-APPROVED-review → APPROVED / without → READY_FOR_REVIEW with limitation); interrupted migration rolls back entirely | — |
| D31 | Prohibited action from injected content | Span commanding a tool call/secret read/external action is dropped; flag records the attempt; run continues; output unaffected vs. clean-input control | 201; flag present |
| D32 | DRAFT edit after submission is rejected | Content and `draft_revision` unchanged; event history unchanged | 422 |
| D33 | Direct SQL UPDATE of an approved version's content | Row bit-identical after the attempt (`RAISE(ABORT)` surfaces) | — (SQL-level invariant) |
| D34 | Direct SQL insert with invalid version reference | `FOREIGN KEY constraint failed` with `PRAGMA foreign_keys=ON`; run `PRAGMA foreign_key_check` → 0 rows | — (SQL-level invariant) |
| D35 | Review with incorrect effective `original_status` | 0 review rows; version effective state unchanged | 422 (trigger abort) |
| D36 | SUPERSEDED event without a newer version | 0 supersession events; approval fully intact (APPROVED effective) | — (SQL-level invariant) |
| D37 | Rejected migration restores pre-state | Backup table restored (ids/statuses counts equal); `foreign_key_check` 0 rows; `schema_migrations` has no 0010 row after rollback | — |
| D38 | Legacy INVESTIGATION without approval evidence | Version effective READY_FOR_REVIEW (review row absent); **no** APPROVED review row exists; limitation `legacy_investigation_without_approval` present | GET shows READY_FOR_REVIEW, unapproved |
| D39 | Historical approval accessible after supersession | vN review row + APPROVED event still returned; view renders "APPROVED (superseded by vN+1)"; investigations link survives | 200 (approval visible in history) |

---

## STAGE 12 — Design references and tradeoffs

References (conceptual only; not licensing/authorization for the Detection-as-Code platform): Mayank Joshi "Anatomy of a Good Detection Rule" (observability-first rule design, blind-spot discipline), Andrey Pautov "Newest Detection Engineering Techniques" (hypothesis-driven hunting, detection validation rigor), Adam Goss "Detection as Code: A Pipeline That Won't Flood Your SOC" (testability/shadow discipline — echoed in validation plans, not implemented), Rcegan "Implementing Detection as Code as a multi-platform MSSP" (multi-platform, tenant-scoped content discipline).

| Decision | Choice | Tradeoff accepted |
|---|---|---|
| Reuse `hunt_hypotheses` + rebuild status CHECK | History preserved; legacy list endpoints keep working | Migration is a table rebuild — must be backup-guarded, count-verified; no way around it within SQLite. |
| Version immutability + optimistic concurrency | Approval can never silently drift; supersession model matches M6/M7 patterns | More tables than a single mutable row; PATCH of DRAFT must snapshot rather than overwrite. |
| Six-state telemetry vs legacy `coverage_status` | Honest; 5/6 always UNKNOWN | UI badge complexity; replaces the legacy enum for new content (legacy kept read-only). |
| Derivation of `research_case_id` from `case_hypotheses` | Single source of truth; no dual FK drift | API must join to answer "which case" — trivial cost, documented deviation from §3's literal field list. |
| No new roles; author-or-ADMIN edit rule | Minimal RBAC churn; CTI_ANALYST stays non-author | Analyst-supplied drafts go through HYPOTHESIS_WRITER/ADMIN — flagged product decision (§4). |
| Query drafts documentation-only | Safe today; execution can be added later under HITL | SOC must run searches out-of-band via `investigations`. |

---

## STAGE 13 — Known limitations, assumptions, missing dependencies

**Known limitations.**
1. `user_authorized_clients.expires_at` remains unenforced (M7-B carry-over) — grant checks are presence-only.
2. Client field evidence is free-text `field_availability` with exact-token match — structured per-client field registry would be stronger.
3. Telemetry staleness uses a 7-day threshold pinned at `evaluation_at`; per-rule staleness is not yet configurable.
4. Legacy `NEEDS_MORE_DATA` hypotheses with no review reason lose reason detail in the status mapping (honest migration note).
5. `coverage_status` (legacy) and `confidence` (free text) are never written by M7-D; the legacy `confidence` column is forbidden in new content (must remain empty/null to preserve the no-scores rule).
6. Detection rule "validation"/"deployment" states are unrepresentable today (inventory has no source of truth) — always UNKNOWN until a future telemetry-verification milestone.

**Assumptions requiring verification before implementation.**
1. `createM1Tables`/seed templates used in tests must be extended with 0010 tables (test fakes only; production uses migrations).
2. `GetResearchCase` GLOBAL-metadata vs CLIENT-content split must be re-verified for the linked-hypothesis read path (M6 semantics carried, not re-litigated).
3. `mitre_mappings` may be empty in isolated seed DBs — ATT&CK validation must degrade to "catalogue empty → reject with 422 catalog_empty" (documented behavior, not a silent pass).
4. Server session identity via cookie-session + CSRF double-submit (M6/M7-C pattern) is assumed unchanged.

**Missing dependencies (explicitly out of scope).** Live QRadar execution, AQL generation/execution, content packs, CI/CD detection pipeline, Octop/Telegram, agent harness, any LLM call. M7-D's API is the *only* integration surface those future components may use.

---

## STAGE 14 — GO/NO-GO

- **Development GO** (isolated test env, separate explicit approval): 0010 DDL (§7), services (§8), 4-endpoint-family API, frontend additions (§10), D1–D39 matrix. Dependencies verified (§1); no M7-C/M6 redesign required.
- **Production NO-GO**: until 0010 migration procedure is backup-guarded, reviewed, and grants are provisioned (same gate posture as M7-C).
- **Architecture verdict:** M7-D is buildable on the existing substrate with additive changes only; the three real risks are (1) the legacy status rebuild (mitigated by count verification + backup), (2) the author-role boundary (product decision, §4), and (3) telemetry six-state honesty in UI copy (no "covered" language anywhere).

---

## Appendix — Final SQL invariants patch: probe results

Disposable SQLite 3.50.4 probe DB (`%TEMP%\opencode\m7d_ddl_probe.db`); `PRAGMA foreign_keys=ON`:

```
OK    draft insert v1
OK    draft edit rev0->rev1
OK    stale draft revision (expect rev1, try rev3): rejected (version not an unsubmitted editable DRAFT or revision mismatch)
OK    delete draft rejected: rejected (hunt_hypothesis_versions is immutable)
OK    event submit
OK    draft edit after submission rejected: rejected (version not an unsubmitted editable DRAFT or revision mismatch)
OK    approve event
OK    review original_status=APPROVED (effective)
OK    review wrong original_status rejected: rejected (original_status mismatch)
OK    approved version row UPDATE rejected: rejected (version not an unsubmitted editable DRAFT or revision mismatch)
OK    supersede without newer version rejected: rejected (supercession without newer version)
OK    supersede v1 after inserting v2 (same tx)
OK    pointer bump
OK    event with nonexistent version rejected (FK): rejected (FOREIGN KEY constraint failed)
OK    review with nonexistent version rejected (FK): rejected (review must bind current version)
OK    illegal transition APPROVED->READY_FOR_REVIEW: rejected (illegal transition APPROVED -> READY_FOR_REVIEW)
view v1: ('DRAFT', 'SUPERSEDED')     -- row creation_status preserved, effective state SUPERSEDED
view v2: (2, 'DRAFT', 'DRAFT')
foreign_key_check: 0 violations
integrity_check: ['ok']
results pass: 16/16
```

Note: the first attempt at this DDL exposed a PostgreSQL-only column-alias syntax (`FROM (...) edges(f, t)`) — SQLite requires the plain `edges` alias; that error surfaced on the probe DB before any production change, and the final DDL carries the portable form. Remaining limitations: `draft_revision` CAS relies on the service-layer read-modify-write inside a transaction (SQLite single-writer + `MaxOpenConns(1)` serialization precedent in this codebase makes it sound); trigger-body semantic guards (edge map, effective-status read) are validated here, but every 0010 table addition must re-run this probe suite. No code, migrations, or production data were modified.

STOP after M7-D Design Gate + SQL invariants patch. Agent Evaluation is a separate future milestone. Implementation, QRadar, Detection-as-Code, Octop, and Telegram are **not** started or authorized.
...[truncated 27091 chars]