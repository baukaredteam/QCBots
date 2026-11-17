# Sentinel Atlas — M7-C Design: Client Relevance Engine

> Status: **DESIGN ONLY**. No code, migrations, Frontend, or SQLite touched. M7-C implementation requires separate explicit approval. **Default: same-client-only assessment** (see §5.1).

---

## STAGE 1 — Verified baseline (file/function evidence)

### CTI report side (verified)

| Table (0001) | Verified fields (actual DDL) | Used by M7-C |
|---|---|---|
| `cti_reports` | `report_id, client_id NOT NULL → clients, source_id → cti_sources (NULLABLE), title, author, publication_date, collection_date, status (0001 enum: NEW, INGESTED, NORMALIZED, ANALYSIS_PENDING, ANALYZED, QUALITY_REVIEW, APPROVED, REJECTED, ARCHIVED), original_content_ref, checksum, created_at` + `artifact_id` (0006) | Identity + tenant + status gate. |
| `indicators` | `indicator_id, report_id, indicator_type, indicator_value, confidence, source_reference, created_at` + 0006 `normalized_value, normalization_rule, normalization_version` | IOC evidence (type/value only; no sector/tech fields). |
| `techniques` | `technique_id, report_id, mitre_technique_id NULLABLE, mitre_tactic NULLABLE, technique_name NULLABLE` | TTP evidence — **MITRE fields are nullable**: missing = UNKNOWN, never NO_MATCH. |
| `cves` | `cve_id, report_id, cve_id_text, description, severity NULLABLE` | CVE evidence (no affected-product field in table). |
| `malware` | `malware_id, report_id, malware_name, family, type` | Affected-software signal only via `family/type` text. |
| `cti_claims` | `claim_id, report_id, claim_text, source_reference, reliability_rating (A–F), credibility_rating (1–6), assessed_by, assessment_date, assessment_reason` | Analyst-assessment substrate; **claim text is free text** — M7-C does not NLP-parse it in v1 (claims are provenance, not match input). |
| `threat_actors` / `campaigns` | actor name/aliases/motivation; campaign name/objectives/dates | Sector/campaign context signals (free text). |

M7-A provenance (0006): `cti_ingestion_runs` (attempt history, `client_id` in identity), `cti_extraction_results` (polymorphic membership + per-type triggers), `file_artifacts` via `cti_reports.artifact_id`. Three confidences stay separate (source reliability / extraction confidence / claim confidence) — M7-C does not merge them.

**Critical gap (verified): no structured "affected sector / affected technology / affected product" fields exist in any CTI extraction table.** Sector/tech matching in v1 can therefore only use: (a) `techniques` (MITRE), (b) `cves.cve_id_text` + `malware.family/type` (free text), (c) `threat_actors/campaigns` text, (d) `cti_reports.title` (free text). Everything else is honest UNKNOWN.

### Client inventory side (verified)

| Table (0001) | Verified fields | Completeness guarantee |
|---|---|---|
| `sectors` | `sector_id, sector_name UNIQUE, description` | Global catalogue. |
| `client_sector_mapping` | `(client_id, sector_id) PK, created_at` | **No "primary" flag, no source, no timestamp of verification beyond created_at.** Empty = unknown, not "no sector". |
| `client_technologies` | `tech_id, client_id, technology_name, category NULLABLE, version NULLABLE, created_at` | Free-text names; **no normalized product IDs, no verification status**. Empty = unknown. |
| `log_source_types` | `log_source_type_id, type_name, description` | Global catalogue. |
| `client_log_source_status` | `status_id, client_id, log_source_type_id, connection_status (CONNECTED/NOT_CONNECTED/NO_RECENT_EVENTS/UNKNOWN), last_event_timestamp, event_volume_status, field_availability, last_checked_at` | Per-client telemetry. `UNKNOWN` is a real state (not NO_MATCH). |
| `global_fields` + 0002 | `field_id, field_name, field_type, field_description, source_type, normalized_name, aliases, is_active` + 0002 `availability, log_sources, adversary_control, used_in_events, display_name` | Shared QRadar fields; **inventory empty in seed/stagef** (verified: `detection_rules=0, global_fields=0, building_blocks=0`). |
| `detection_rules` + 0002 | `rule_id, rule_name, rule_description, rule_type, mitre_tactics, mitre_techniques, required_fields, required_log_sources, rule_status, rule_version` + 0002 QRadar columns | ATT&CK mapping exists as free text (`mitre_techniques`); **no normalized FK to `mitre_mappings`** (mapping table has `mapping_id, mitre_technique_id, mitre_tactic, technique_name, description` — join is by string key, not FK). |
| `rule_field_requirements` | `(rule_id, field_id, is_required, created_at)` | Required-field evidence for telemetry observability. |
| `field_mappings` | `(mapping_id, source_field_name, normalized_field_id → global_fields, mapping_rule)` | Field-name normalization evidence. |

**Verified: inventory completeness is never guaranteed.** `client_technologies` may be empty for a real client; absence of rows means UNKNOWN. This is load-bearing for §2.

### Links, grants, authorization

- `case_cti_reports` (0007): `(case_id, report_id) PK, client_id NOT NULL` + client-match trigger. M7-C reads links for Case Workspace evidence only; never creates them.
- `user_authorized_clients` (0004): `(user_id, client_id) UNIQUE`; `GetUserAuthorizedClientsFromDB`/`hasClientGrant` (mcp_case.go) — **expires_at ignored** (documented M7-B limitation). ADMINISTRATOR not exempt.
- M6 case access: `GetResearchCase` (owner/active participant/ADMIN-metadata); CLIENT content gated by grants.
- Existing HTTP: `GET /clients`, `GET /sectors`, `GET /inventory/{fields,rules,telemetry}` (telemetry: `X-Client-ID` + `RequireTenantAccess`), `GET /qradar/{rules,building-blocks,fields}`.

---

## STAGE 2 — Three independent dimensions

Each dimension independently returns `MATCH | NO_MATCH | UNKNOWN` + evidence. **Missing inventory ⇒ UNKNOWN, never NO_MATCH.** NO_MATCH requires sufficient contrary evidence (e.g. client has a *verified, complete* sector set that excludes the report's sector — but "complete" is itself a data-quality flag not present today, so in v1 NO_MATCH requires an explicit `inventory_complete=true` signal; default is UNKNOWN).

### A. SECTOR RELEVANCE

**Inputs**: report sector signals: `campaigns` name/objectives, `threat_actors` motivation, `cti_reports.title` keyword hits against `sectors.sector_name` (exact token match only, versioned keyword list); client sectors from `client_sector_mapping`.
**MATCH**: non-empty intersection of report sector tokens with client's sectors.
**NO_MATCH (v1: DISABLED — option B)**: `client_technologies` (and `client_sector_mapping`) have **no verification status column** in the real schema (verified 0001: `tech_id, client_id, technology_name, category, version, created_at` — no completeness source, no verified-by, no checked-at beyond created_at). M7-C adds **no** completeness model in v1 (option A deferred to a future migration with provenance/validity). Therefore **SECTOR and TECHNOLOGY NO_MATCH are disabled in v1**: both dimensions return only MATCH or UNKNOWN. This is the honest minimal approach — absence of inventory rows is never interpreted as absence of exposure.
**UNKNOWN**: report has no sector tokens, or client has no sector rows.
**Why this is safe**: title keyword matching is deliberately conservative (exact sector-name token, case-insensitive); free-text otherwise → UNKNOWN.

### B. TECHNOLOGY RELEVANCE (NO_MATCH also disabled in v1, same option B)

**Inputs**: report tech signals: `cves.cve_id_text` (matched against `client_technologies.technology_name` + `version` by exact CVE↔product rule — **not** text contains; the CVE→product mapping is supplied by a versioned matching-rule table, §4), `malware.family/type` exact-token vs `technology_name/category`, `techniques` are NOT tech evidence (they are TTPs, §C).
**MATCH**: a versioned rule matched a CVE/malware family to a verified client technology row.
**NO_MATCH (v1)**: disabled (see §A). TECHNOLOGY returns MATCH or UNKNOWN only.
**UNKNOWN**: no CVE/malware signals, no tech rows, or no rule covers the signal.
**Note**: `client_technologies.version` is free text; version comparison in v1 is **exact string equality** only (no semver inference — would be fabricated).

### C. TELEMETRY OBSERVABILITY (visibility ≠ relevance) — truth table

This dimension answers "could telemetry support investigation/detection", **not** "is the client affected". Never conflated in UI (separate badges). A `global_fields` row or a `detection_rules` row **alone proves nothing about this client** — the rule may not be deployed to the client, and its fields may not be populated for the client's log source.

**Inputs (all must be client-specific to count as evidence)**: report TTPs (`techniques.mitre_technique_id`) → candidate `detection_rules` whose `mitre_techniques` contains the ID (string match, versioned) → for each candidate: `required_log_sources` + `rule_field_requirements` → client telemetry `client_log_source_status` for those source types.

| Candidate rule condition | Evidence |
|---|---|
| Required source type exists for client with `connection_status='CONNECTED'` AND `last_event_timestamp` within staleness threshold (default 7d, rule-configurable) AND every required field exists in `global_fields(is_active=1)` | **observable path** |
| Required source type exists with `connection_status='NOT_CONNECTED'` or stale timestamps (> threshold) | **proven unavailable path** |
| No telemetry row for required source, or `UNKNOWN` status, or required field absent from inventory | **insufficient evidence** |
| Rule exists in QRadar inventory but client has no telemetry row for its source | **insufficient evidence** (rule existence ≠ deployment) |

**Verdict aggregation across candidate rules for the report's TTPs:**
- ≥1 observable path → **MATCH** (observable), citing that rule + source + field evidence.
- ≥1 candidate rule exists AND **all** candidate paths are proven-unavailable → **NO_MATCH** (not observable).
- Otherwise (no candidate rules, or any path insufficient) → **UNKNOWN**.
- Stale validation (telemetry checked long ago) counts as insufficient, never as proven-unavailable.

---

## STAGE 3 — Evidence and provenance

Every assessment row stores (per-dimension evidence records, §4):
`report_id, client_id, dimension, verdict (MATCH/NO_MATCH/UNKNOWN), matched_entity_type, matched_entity_id, source_reference (from indicators/claims — never invented), source_reliability (cti_sources.reliability_rating — nullable), inventory_evidence (JSON: which sector/tech/telemetry rows were compared + their created_at/last_checked_at timestamps), matching_rule_id, matching_rule_version, explanation (human sentence citing the above), unknowns[] (what was missing), limitations[]`.

Confidence honesty:
- `source_reliability` = `cti_sources.reliability_rating` verbatim (or null).
- `extraction_confidence` = `indicators.confidence` verbatim for matched IOCs (or null).
- `claim_confidence` = `cti_claims.reliability/credibility` verbatim (or null).
- **No numeric scores anywhere.** No `confidence = 0/1`, no averages, no "threat score".

Analyst assessment is separate from computed relevance (§4 review table); overrides never mutate computed rows.

---

## STAGE 4 — Data model (migration 0008, minimal) — FINAL INVARIANTS

```sql
-- Versioned matching rules (immutable once created; new rules = new rows).
CREATE TABLE IF NOT EXISTS relevance_matching_rules (
    rule_id TEXT PRIMARY KEY,
    rule_version TEXT NOT NULL,
    dimension TEXT NOT NULL CHECK (dimension IN ('SECTOR','TECHNOLOGY','TELEMETRY')),
    rule_name TEXT NOT NULL,
    rule_definition TEXT NOT NULL,          -- JSON: tokens/pairs to evaluate
    created_by TEXT REFERENCES users(user_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (dimension, rule_version, rule_name)
);

-- Assessment attempt history: EVERY explicit reassessment (incl. retry after
-- FAILED, with identical inputs) creates a NEW assessment_id. There is NO
-- document-level UNIQUE on (report, client, rule_version, snapshot) — attempts
-- are distinct by identity, never by content. HTTP idempotency is enforced
-- separately (see below), never by blocking attempts.
CREATE TABLE IF NOT EXISTS relevance_assessments (
    assessment_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES cti_reports(report_id),
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    status TEXT NOT NULL CHECK (status IN ('PENDING','COMPLETED','FAILED')),
    error_code TEXT,
    request_idempotency_key TEXT,
    payload_fingerprint TEXT,               -- canonical hash incl. report/client/rule-set/snapshots
    cti_evidence_snapshot TEXT NOT NULL,    -- sha256 hex (see §3 snapshot contract)
    inventory_snapshot TEXT NOT NULL,       -- sha256 hex (see §3)
    rule_set_fingerprint TEXT NOT NULL,     -- sha256 hex over sorted (rule_id, rule_version)
    matching_rule_version TEXT NOT NULL,    -- human label of the rule set (informational)
    created_by TEXT REFERENCES users(user_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_relevance_assessments_report ON relevance_assessments(report_id);
CREATE INDEX idx_relevance_assessments_client ON relevance_assessments(client_id, created_at DESC);
-- Database-enforced HTTP idempotency, scoped to the client (NULL keys never dedupe).
CREATE UNIQUE INDEX IF NOT EXISTS idx_relevance_req_unique
    ON relevance_assessments(client_id, request_idempotency_key)
    WHERE request_idempotency_key IS NOT NULL;

-- Per-dimension findings: exactly one per (assessment, dimension), immutable once COMPLETED.
CREATE TABLE IF NOT EXISTS relevance_findings (
    finding_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES relevance_assessments(assessment_id),
    dimension TEXT NOT NULL CHECK (dimension IN ('SECTOR','TECHNOLOGY','TELEMETRY')),
    verdict TEXT NOT NULL CHECK (verdict IN ('MATCH','NO_MATCH','UNKNOWN')),
    explanation TEXT NOT NULL,
    unknowns TEXT,                            -- JSON array
    limitations TEXT,                         -- JSON array
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (assessment_id, dimension)
);

-- Multiple evidence pieces per finding (one row per matched entity/rule).
CREATE TABLE IF NOT EXISTS relevance_evidence (
    evidence_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES relevance_findings(finding_id),
    assessment_id TEXT NOT NULL REFERENCES relevance_assessments(assessment_id),
    report_id TEXT NOT NULL REFERENCES cti_reports(report_id),
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    dimension TEXT NOT NULL CHECK (dimension IN ('SECTOR','TECHNOLOGY','TELEMETRY')),
    matched_entity_type TEXT NOT NULL CHECK (matched_entity_type IN ('sector','technology','log_source','field','detection_rule','indicator','technique','cve','malware','claim','threat_actor','campaign')),
    matched_entity_id TEXT NOT NULL,
    source_reference TEXT,                    -- verbatim from CTI row (never invented)
    source_reliability TEXT,                  -- verbatim cti_sources.reliability_rating or NULL
    inventory_evidence TEXT,                  -- JSON: rows compared + their timestamps
    matching_rule_id TEXT NOT NULL REFERENCES relevance_matching_rules(rule_id),
    matching_rule_version TEXT NOT NULL,
    UNIQUE (finding_id, matched_entity_type, matched_entity_id)
);
CREATE INDEX idx_relevance_evidence_finding ON relevance_evidence(finding_id);

-- Analyst review / override (append-only; never mutates findings).
-- original_verdict MUST equal the computed finding verdict (enforced by trigger below).
CREATE TABLE IF NOT EXISTS relevance_reviews (
    review_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES relevance_assessments(assessment_id),
    reviewer_id TEXT NOT NULL REFERENCES users(user_id),
    dimension TEXT NOT NULL CHECK (dimension IN ('SECTOR','TECHNOLOGY','TELEMETRY')),
    original_verdict TEXT NOT NULL CHECK (original_verdict IN ('MATCH','NO_MATCH','UNKNOWN')),
    override_verdict TEXT NOT NULL CHECK (override_verdict IN ('MATCH','NO_MATCH','UNKNOWN')),
    reason TEXT NOT NULL,
    reviewed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_relevance_reviews_assessment ON relevance_reviews(assessment_id);

-- Tenant consistency: assessment client must equal report client (direct SQL abuse guard).
CREATE TRIGGER IF NOT EXISTS trg_relevance_client_match
BEFORE INSERT ON relevance_assessments
BEGIN
    SELECT RAISE(ABORT, 'client mismatch')
    WHERE NOT EXISTS (
        SELECT 1 FROM cti_reports WHERE report_id = NEW.report_id AND client_id = NEW.client_id
    );
END;

-- Finding/assessment/report consistency (DEFENSE-IN-DEPTH; see §6 for Go/labels).
CREATE TRIGGER IF NOT EXISTS trg_relevance_finding_assessment_match
BEFORE INSERT ON relevance_findings
BEGIN
    SELECT RAISE(ABORT, 'assessment mismatch')
    WHERE NOT EXISTS (
        SELECT 1 FROM relevance_assessments WHERE assessment_id = NEW.assessment_id
    );
END;

-- Reviewer cannot lie about the computed verdict: original must equal finding.
CREATE TRIGGER IF NOT EXISTS trg_relevance_review_original_match
BEFORE INSERT ON relevance_reviews
BEGIN
    SELECT RAISE(ABORT, 'original verdict mismatch')
    WHERE NOT EXISTS (
        SELECT 1 FROM relevance_findings
        WHERE assessment_id = NEW.assessment_id AND dimension = NEW.dimension AND verdict = NEW.original_verdict
    );
END;

-- Append-only: completed findings and reviews are immutable.
CREATE TRIGGER IF NOT EXISTS trg_relevance_findings_no_update
BEFORE UPDATE ON relevance_findings
BEGIN SELECT RAISE(ABORT, 'relevance_findings is immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_relevance_findings_no_delete
BEFORE DELETE ON relevance_findings
BEGIN SELECT RAISE(ABORT, 'relevance_findings is immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_relevance_reviews_no_update
BEFORE UPDATE ON relevance_reviews
BEGIN SELECT RAISE(ABORT, 'relevance_reviews is immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_relevance_reviews_no_delete
BEFORE DELETE ON relevance_reviews
BEGIN SELECT RAISE(ABORT, 'relevance_reviews is immutable'); END;
```

Notes:
- **Attempt identity** = `assessment_id` (random). Document identity stays on `cti_reports`; HTTP identity = `(client_id, request_idempotency_key)` unique index; evidence identity = `cti_evidence_snapshot`; inventory identity = `inventory_snapshot`; rule identity = `rule_set_fingerprint` (sorted rule_id+version list). A FAILED retry with identical inputs MUST create a new attempt (no content UNIQUE blocks it) — proven by test C9b.
- **Immutability**: COMPLETED findings froz­en by trigger; reassessment = new assessment row; history preserved.
- **No mutation**: M7-C never writes `cti_reports.status`, `cti_ingestion_runs`, extraction tables, or `case_cti_reports`.

---

## STAGE 3b — Reproducible input snapshots (exact contract)

Three independent fingerprints, all SHA-256 hex over **canonical JSON with stable ordering** (keys sorted, arrays sorted by primary ID, no timestamps generated during assessment):

- **`cti_evidence_snapshot`**: `{report_id, indicators:[(indicator_id, indicator_type, indicator_value, normalized_value, normalization_rule, source_reference)], techniques:[(technique_id, mitre_technique_id, mitre_tactic, technique_name)], cves:[(cve_id, cve_id_text)], malware:[(malware_id, malware_name, family)], claims:[(claim_id, claim_text, source_reference, reliability_rating, credibility_rating)], threat_actors:[(actor_id, actor_name)], campaigns:[(campaign_id, campaign_name)], latest_run_id}` — sorted by ID within each list. Changes when parser evidence changes → new snapshot → new assessment is meaningful.
- **`inventory_snapshot`**: `{client_id, sectors:[(sector_id, sector_name)], technologies:[(tech_id, technology_name, category, version)], telemetry:[(status_id, log_source_type_id, connection_status, last_event_timestamp, field_availability, last_checked_at)], rules:[(rule_id, rule_version, mitre_techniques, required_log_sources)]}` — sorted by ID.
- **`rule_set_fingerprint`**: SHA-256 over sorted `[(rule_id, rule_version)]` for all rules in the active set.

Persisted on the assessment row for historical explanation after inventory/parser changes. Hashing uses **source rows only** — never assessment timestamps.

---

## STAGE 6b — Go-enforced invariants (labeled, not DB-enforced)

| # | Invariant | Why not DB-enforced | Integration test |
|---|---|---|---|
| G1 | Assessor holds `CanCreateCTI` + grant for `client_id` at assess time | Role/grant tables change over time; DB trigger cannot know current session | HTTP 401/403 negative tests through real middleware |
| G2 | Snapshot computed **before** findings, from the same read tx | Ordering is procedural | Stale-snapshot test: mutate inventory between snapshot and findings → run aborts FAILED |
| G3 | `payload_fingerprint` = canonical `{report_id, client_id, cti_evidence_snapshot, inventory_snapshot, rule_set_fingerprint}` | Hash input construction is application logic | Same key+changed fingerprint → 409 (HTTP test) |
| G4 | Report status/provenance never mutated | No trigger covers "don't touch"; service discipline | Query assertion before/after assess (byte-identical) |
| G5 | Frontend never renders numeric confidence | Pure UI contract | Text scan of API responses in HTTP tests |

DB-enforced (trusted, not labeled Go-only): tenant client match, finding↔assessment existence, review original_verdict match, immutability triggers, HTTP idempotency uniqueness.

---

## STAGE 5 — Service & API contract

### 5.1 Cross-client decision (explicit)

**Cross-client relevance evaluation is NOT allowed by default.** Rationale: `cti_reports.client_id` is per-tenant (`GetCTIReport` + `CanAccessClient` gate every read); exposing another tenant's report/title/entities to compute relevance would leak tenant content. Decision: **same-client-only** assessments (`assessment.client_id == report.client_id` enforced by the trigger above + service check). A future *authorized publication model* (e.g. a GLOBAL-published report class with explicit publisher + grant) would be a separate project; M7-C does not build it.

### 5.2 Endpoints

| Route | Method | AuthZ chain | Semantics |
|---|---|---|---|
| `POST /api/v1/cti/reports/{report_id}/relevance/{client_id}/assess` | POST | `requireAuth + CanViewCTI + CanCreateCTI + auditWrap + csrfWrap` | Create-or-replay a run. **HTTP idempotency (exact DDL)**: `UNIQUE(client_id, request_idempotency_key) WHERE request_idempotency_key IS NOT NULL` + persisted `payload_fingerprint` (canonical §3: report+client+both snapshots+rule-set). Same key+same fingerprint → existing `assessment_id` (200); same key+different fingerprint → **409**. Client path param **must equal** `report.client_id` (else 403 same-client rule). New key = new attempt (never blocked by document uniqueness). |
| `GET /api/v1/cti/reports/{report_id}/relevance/{client_id}` | GET | `requireAuth + CanViewCTI + auditWrap` | Latest COMPLETED assessment (or 404 if none). Returns findings with evidence. Same-client rule + grant check (report access = `CanAccessClient`). |
| `GET /api/v1/clients/{client_id}/relevant-reports` | GET | `requireAuth + CanViewCTI + auditWrap` | Grant-filtered list of reports **for that client only** that have MATCH in ≥1 dimension (latest assessment per report). `limit/offset` default 20/max 100; `total` counts only returned-scope rows. |
| `POST /api/v1/cti/reports/{report_id}/relevance/{client_id}/review` (analyst override) | POST | `requireAuth + CanReviewArtifact + auditWrap + csrfWrap` | Append-only override row; never mutates findings. 403 for non-reviewers. |

### 5.3 Response shapes

Assessment GET:
```json
{
  "assessment_id": "...", "report_id": "...", "client_id": "...",
  "matching_rule_version": "...", "inventory_snapshot": "sha256:…",
  "status": "COMPLETED",
  "findings": [
    {"dimension": "SECTOR", "verdict": "UNKNOWN",
     "matched_entity": null, "source_reference": null,
     "source_reliability": null,
     "inventory_evidence": {"client_sectors": 0, "checked_at": "…"},
     "matching_rule": {"rule_id": "…", "rule_version": "1"},
     "explanation": "No sector tokens extracted from report entities.",
     "unknowns": ["report has no sector tokens", "client sector inventory unknown"],
     "limitations": ["free-text token match only"]}
  ],
  "reviews": [ …append-only overrides… ]
}
```
- **Response states**: MATCH findings carry evidence; UNKNOWN carry `unknowns[]`; FAILED runs carry `error_code` (no fabricated findings).
- **Reassessment**: POST again with a new key or after inventory change → new assessment row (history preserved); GET returns latest.
- **Pagination**: list endpoint grant-filters before LIMIT/OFFSET (M7-B paginate-after-filter pattern); `total` = accessible-scope count.
- **Errors**: 401 unauthenticated, 403 cross-client/no-grant/no-permission, 404 report/assessment absent, 409 idempotency conflict, 422 assessment failed (run FAILED, findings empty), 503 schema-not-ready.

---

## STAGE 6 — Frontend V3 integration (existing views only)

- **Report Inspector → Client Relevance**: new section in the existing Inspector (`#feed`): per-dimension verdict badges (MATCH mint / NO_MATCH muted / UNKNOWN amber) + evidence drawer (explanation, unknowns, rule version). "Assess" button (POST) only when `CanCreateCTI`; reviewer overrides only when `CanReviewArtifact`. Uses existing `api()` + `escEl/textContent`.
- **Client Intelligence → Relevant Reports**: inside `#clients` inspector, "Relevant reports (MATCH)" list via `GET /clients/{id}/relevant-reports` (limit 20).
- **Case Workspace → relevance evidence**: CTI tab shows relevance badges for linked reports (read-only; assessment button stays in Hub).
- States: Loading (existing `statebox`), Empty ("No assessment yet"), UNKNOWN (“Not available / not verified” — never a fabricated score), 403 (hidden section, no metadata leak), 404, failed-assessment (`error_code` shown, retry allowed).

---

## STAGE 7 — Security & acceptance matrix (C1–C20 updated)

| # | Test | Expected (SQL + service assertions) |
|---|---|---|
| C1 | Same-client assess (sector MATCH) | Verdict MATCH + `relevance_evidence` rows + rule version; assessment COMPLETED |
| C2 | Cross-client assess (alpha report → beta client) | **403**, `SELECT COUNT(*) FROM relevance_assessments WHERE report_id=alpha AND client_id=beta` = 0 |
| C3 | Revoked grant mid-flow | List/assess → 403/empty; existing assessments unchanged (row count same) |
| C4 | Empty sector inventory | SECTOR = UNKNOWN (never NO_MATCH; NO_MATCH disabled v1 — option B) |
| C5 | Incomplete tech inventory (0 rows) | TECHNOLOGY = UNKNOWN |
| C6 | Missing telemetry rows | TELEMETRY = UNKNOWN |
| C7 | Unknown MITRE mapping | TELEMETRY = UNKNOWN, never NO_MATCH |
| C8 | Legacy CTI report (no extraction runs) | Assessment runs on report+inventory only, or UNKNOWN with limitation (never fabricated) |
| C9 | Repeated assessment (same key+payload) | **200 same assessment_id**, exactly 1 row for the key |
| C9b | FAILED reassessment with identical inputs, new key | **New assessment_id** (attempt history); old FAILED row preserved |
| C10 | Rule-version change → POST again | New assessment row, history preserved (2 runs) |
| C11 | Inventory change → POST again | New `inventory_snapshot` → new assessment row |
| C11b | New parser evidence, unchanged inventory | Different `cti_evidence_snapshot` → new assessment (snapshot distinguishes input causes) |
| C12 | Conflicting evidence (sector MATCH + tech UNKNOWN) | Dimensions stay independent (no merged verdict) |
| C13 | Missing source_reference | Finding shows null + limitation, never invented |
| C14 | No invented confidence | Response scan: no numeric confidence/score keys |
| C15 | Unauthorized review (CTI_ANALYST) | **403** on review endpoint |
| C16 | Concurrent assessment same payload+key | Exactly **1** operation row (unique index serializes) |
| C16b | Same idempotency key + different fingerprint | **409** (stored fingerprint vs recomputed) |
| C17 | Historical preservation | Old assessment + findings byte-identical after reassessment |
| C18 | No mutation of M7-A/M7-B | `cti_reports.status`, runs, extraction rows, links byte-identical before/after (query assertion) |
| C19 | Cross-client GET | **403** |
| C20 | Failed assessment (injected inventory error) | Run FAILED + `error_code`, findings empty, report unchanged |
| C21 | Unknown inventory never NO_MATCH (SECTOR/TECH v1) | SECTOR/TECH verdicts ∈ {MATCH, UNKNOWN} across all fixtures (SQL: `SELECT COUNT(*) FROM relevance_findings WHERE dimension IN ('SECTOR','TECHNOLOGY') AND verdict='NO_MATCH'` = 0) |
| C22 | Global field without client field evidence never MATCH | TELEMETRY = UNKNOWN (rule exists, no client telemetry) |
| C23 | Alternative observable rule overrides unavailable rule | One CONNECTED path + one NOT_CONNECTED path → TELEMETRY MATCH citing the observable rule |
| C24 | Review original_verdict mismatch | Trigger abort → review insert rejected (direct SQL + HTTP) |
| C25 | Direct SQL tenant mismatch | `INSERT assessment(report alpha, client beta)` → trigger abort `client mismatch` |

Go-only invariants (§6b G1–G5) each have the integration test listed there; DB-enforced ones (tenant match, review original match, immutability, idempotency uniqueness) are proven by C2/C16/C24/C25 direct SQL.

---

## Gates (final invariants)

- **Development prerequisites** (isolated SQLite): migrations 0001–0007 + 0008, seed users + explicit grants, fixtures (sectors/tech/telemetry/MITRE rules seed), regression suite green.
- **Production prerequisites** (separate approval): backup + migration procedure 0007→0008, reviewed grant provisioning, RBAC administration. Missing production grants do **not** block M7-C development.
- **Remaining limitations (explicit)**:
  1. SECTOR/TECHNOLOGY NO_MATCH disabled in v1 (option B) until an inventory completeness/verification model with provenance exists — all non-matches are UNKNOWN.
  2. `client_technologies.version` compared by exact string equality only (no semver inference).
  3. Claim text is never NLP-parsed for relevance in v1 (provenance only).
  4. Telemetry staleness threshold is rule-configurable (default 7d) — changing it creates a new rule version, hence a new assessment.
  5. `user_authorized_clients.expires_at` remains ignored (M6 semantics, unchanged).
- **Development GO** (after separate approval): final DDL (§4), matching truth table (§2A–C), snapshot/idempotency contracts (§3b/§5.2), evidence model (§3/§4), C1–C25 matrix (§7) are complete and dependency-scoped; no M7-D work required first.
- **Production NO-GO**: until 0008 procedure + provisioning approved/executed.
- **M7-C implementation**: **NOT STARTED** (this document is the gate).

STOP after M7-C Final Design Invariants Correction.
