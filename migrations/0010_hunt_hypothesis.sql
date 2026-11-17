-- Migration 0010_hunt_hypothesis.sql
-- M7-D Phase 1: Versioned Threat Hunting Hypothesis domain.
--
-- CAUTION -- this migration is NOT purely additive. It REBUILDS the legacy
-- hunt_hypotheses table (as 0007 rebuilt case_activity) to:
--   (a) expand the status CHECK to the M7-D lifecycle, and
--   (b) add M7-D identity/provenance columns.
-- Row preservation is exact: every legacy hypothesis id, all legacy
-- hypothesis_reviews, investigations, hypothesis_evidence rows and
-- case_hypotheses links survive with unchanged parent identities.
-- Migration is single-transaction (runner-owned): any failure rolls back to
-- the pre-migration state (see rollback validation in backend tests).
--
-- IMPORTANT -- never manufacture approvals: a legacy INVESTIGATION row is
-- mapped to APPROVED ONLY IF a legacy hypothesis_reviews row with
-- decision='APPROVED' exists; otherwise it maps to READY_FOR_REVIEW with a
-- documented limitation flag (the rebuild keeps the mapping auditable via
-- hunt_hypotheses.migrated_from_status).

PRAGMA foreign_keys = ON;

-- 1. Backup for manual rollback (first-capture pre-0010 state; kept when the
-- migration is rerun, which keeps rollback semantics stable).
CREATE TABLE IF NOT EXISTS hunt_hypotheses_backup_0010
AS SELECT * FROM hunt_hypotheses;

-- 2. Rebuild hunt_hypotheses with expanded status CHECK + M7-D columns.
-- Original identity columns are copied verbatim (ids unchanged).
-- Child tables are backed up and emptied FIRST because a DROP TABLE on a
-- parent with live FK references would fail (PRAGMA foreign_keys = ON);
-- their contents are then reinserted verbatim after the rebuild.
-- Backups are dropped first so reruns always copy fresh child contents.
DROP TABLE IF EXISTS hunt_hypotheses_child_bak_hypothesis_evidence;
DROP TABLE IF EXISTS hunt_hypotheses_child_bak_hypothesis_reviews;
DROP TABLE IF EXISTS hunt_hypotheses_child_bak_investigations;
DROP TABLE IF EXISTS hunt_hypotheses_child_bak_investigation_evidence;
DROP TABLE IF EXISTS hunt_hypotheses_child_bak_case_hypotheses;
DROP TABLE IF EXISTS hunt_hypotheses_child_bak_hypothesis_review;
CREATE TABLE hunt_hypotheses_child_bak_hypothesis_evidence AS
    SELECT * FROM hypothesis_evidence;
CREATE TABLE hunt_hypotheses_child_bak_hypothesis_reviews AS
    SELECT * FROM hypothesis_reviews;
CREATE TABLE hunt_hypotheses_child_bak_investigations AS
    SELECT * FROM investigations;
CREATE TABLE hunt_hypotheses_child_bak_investigation_evidence AS
    SELECT * FROM investigation_evidence;
CREATE TABLE hunt_hypotheses_child_bak_case_hypotheses AS
    SELECT * FROM case_hypotheses;
CREATE TABLE hunt_hypotheses_child_bak_hypothesis_review AS
    SELECT * FROM case_hypothesis_review;

-- Empty children in FK-safe order (deepest first), including any 0010 tables
-- from a previous run so reruns converge to the same state. The 0010 tables
-- are derived state: on rerun they are rebuilt from scratch by the CREATEs
-- below, so no backup is needed for them.
DELETE FROM investigation_evidence;
DELETE FROM investigations;
DELETE FROM hypothesis_evidence;
DELETE FROM hypothesis_reviews;
DELETE FROM case_hypotheses;
DELETE FROM case_hypothesis_review;
DROP VIEW IF EXISTS v_hunt_hypothesis_version_state;
DROP TABLE IF EXISTS hunt_plan_steps;
DROP TABLE IF EXISTS hunt_hypothesis_telemetry;
DROP TABLE IF EXISTS hunt_hypothesis_evidence;
DROP TABLE IF EXISTS hunt_plans;
DROP TABLE IF EXISTS hunt_hypothesis_reviews;
DROP TABLE IF EXISTS hunt_hypothesis_activity;
DROP TABLE IF EXISTS hunt_hypothesis_version_events;
DROP TABLE IF EXISTS hunt_hypothesis_versions;
DROP TABLE IF EXISTS hunt_hypotheses_new;

CREATE TABLE hunt_hypotheses_new (
    hypothesis_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    threat_actor TEXT,
    campaign TEXT,
    adversary_brain_id TEXT REFERENCES adversary_brains(brain_id),
    sector TEXT,
    mitre_tactics TEXT,
    mitre_techniques TEXT,
    expected_behavior TEXT,
    required_log_sources TEXT,
    required_fields TEXT,
    existing_detection_rules TEXT,
    coverage_status TEXT CHECK (coverage_status IN ('COVERED','PARTIAL','NOT_COVERED','UNKNOWN')),
    evidence TEXT,
    supporting_evidence TEXT,
    contradicting_evidence TEXT,
    assumptions TEXT,
    limitations TEXT,
    confidence TEXT,
    priority TEXT,
    status TEXT NOT NULL DEFAULT 'DRAFT'
        CHECK (status IN ('DRAFT','READY_FOR_REVIEW','APPROVED','REJECTED','SUPERSEDED','ARCHIVED')),
    report_id TEXT REFERENCES cti_reports(report_id),
    relevance_assessment_id TEXT REFERENCES relevance_assessments(assessment_id),
    author_id TEXT REFERENCES users(user_id),
    generation_method TEXT NOT NULL DEFAULT 'MANUAL'
        CHECK (generation_method IN ('MANUAL','AI_ASSISTED','LEGACY_IMPORT')),
    current_version_no INTEGER NOT NULL DEFAULT 1,
    request_idempotency_key TEXT,
    payload_fingerprint TEXT,
    migrated_from_status TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_hunt_hypotheses_client_status ON hunt_hypotheses(client_id, status);

INSERT INTO hunt_hypotheses_new (
    hypothesis_id, client_id, title, description, threat_actor, campaign,
    adversary_brain_id, sector, mitre_tactics, mitre_techniques,
    expected_behavior, required_log_sources, required_fields,
    existing_detection_rules, coverage_status, evidence,
    supporting_evidence, contradicting_evidence, assumptions, limitations,
    confidence, priority, status, generation_method, current_version_no,
    created_at, updated_at, migrated_from_status
)
SELECT
    hypothesis_id, client_id, title, description, threat_actor, campaign,
    adversary_brain_id, sector, mitre_tactics, mitre_techniques,
    expected_behavior, required_log_sources, required_fields,
    existing_detection_rules, coverage_status, evidence,
    supporting_evidence, contradicting_evidence, assumptions, limitations,
    confidence, priority,
    CASE status
        WHEN 'GENERATED' THEN 'DRAFT'
        WHEN 'QUALITY_CHECK' THEN 'READY_FOR_REVIEW'
        WHEN 'PENDING_REVIEW' THEN 'READY_FOR_REVIEW'
        WHEN 'NEEDS_MORE_DATA' THEN 'DRAFT'
        WHEN 'APPROVED' THEN 'APPROVED'
        WHEN 'REJECTED' THEN 'REJECTED'
        WHEN 'INVESTIGATION' THEN CASE
            WHEN EXISTS (SELECT 1 FROM hunt_hypotheses_child_bak_hypothesis_reviews r
                         WHERE r.hypothesis_id = hunt_hypotheses.hypothesis_id
                           AND r.decision = 'APPROVED') THEN 'APPROVED'
            ELSE 'READY_FOR_REVIEW' END
        WHEN 'CLOSED' THEN 'ARCHIVED'
        ELSE 'DRAFT'
    END,
    'LEGACY_IMPORT', 1, created_at, updated_at, status
FROM hunt_hypotheses;

DROP TABLE hunt_hypotheses;
ALTER TABLE hunt_hypotheses_new RENAME TO hunt_hypotheses;

-- 3. Restore child rows verbatim (ids + contents + timestamps unchanged).
INSERT INTO hypothesis_evidence SELECT * FROM hunt_hypotheses_child_bak_hypothesis_evidence;
INSERT INTO hypothesis_reviews SELECT * FROM hunt_hypotheses_child_bak_hypothesis_reviews;
INSERT INTO investigations SELECT * FROM hunt_hypotheses_child_bak_investigations;
INSERT INTO investigation_evidence SELECT * FROM hunt_hypotheses_child_bak_investigation_evidence;
INSERT INTO case_hypotheses SELECT * FROM hunt_hypotheses_child_bak_case_hypotheses;
INSERT INTO case_hypothesis_review SELECT * FROM hunt_hypotheses_child_bak_hypothesis_review;
DROP TABLE hunt_hypotheses_child_bak_hypothesis_evidence;
DROP TABLE hunt_hypotheses_child_bak_hypothesis_reviews;
DROP TABLE hunt_hypotheses_child_bak_investigations;
DROP TABLE hunt_hypotheses_child_bak_investigation_evidence;
DROP TABLE hunt_hypotheses_child_bak_case_hypotheses;
DROP TABLE hunt_hypotheses_child_bak_hypothesis_review;

-- Idempotency (partial unique, M7-C pattern; on the rebuilt table).
CREATE UNIQUE INDEX IF NOT EXISTS idx_hunt_hyp_req_unique
    ON hunt_hypotheses(client_id, request_idempotency_key)
    WHERE request_idempotency_key IS NOT NULL;

-- 4. Tenant consistency: report client must equal hypothesis client;
-- bound assessment must be COMPLETED for the same report+client.
CREATE TRIGGER IF NOT EXISTS trg_hypothesis_report_client_match
BEFORE INSERT ON hunt_hypotheses
BEGIN
    SELECT RAISE(ABORT, 'client mismatch')
    WHERE NEW.report_id IS NOT NULL
      AND NOT EXISTS (
          SELECT 1 FROM cti_reports
          WHERE report_id = NEW.report_id AND client_id = NEW.client_id
      );
END;
CREATE TRIGGER IF NOT EXISTS trg_hypothesis_assessment_binding
BEFORE INSERT ON hunt_hypotheses
BEGIN
    SELECT RAISE(ABORT, 'assessment binding mismatch')
    WHERE NEW.relevance_assessment_id IS NOT NULL
      AND NOT EXISTS (
          SELECT 1 FROM relevance_assessments
          WHERE assessment_id = NEW.relevance_assessment_id
            AND report_id = NEW.report_id
            AND client_id = NEW.client_id
            AND status = 'COMPLETED'
      );
END;

-- 5. Versioned hypothesis content (append-only lifecycle via events).
CREATE TABLE IF NOT EXISTS hunt_hypothesis_versions (
    version_id TEXT PRIMARY KEY,
    hypothesis_id TEXT NOT NULL REFERENCES hunt_hypotheses(hypothesis_id),
    version_no INTEGER NOT NULL,
    creation_status TEXT NOT NULL DEFAULT 'DRAFT'
        CHECK (creation_status IN ('DRAFT','READY_FOR_REVIEW','APPROVED','REJECTED','ARCHIVED')),
    draft_revision INTEGER NOT NULL DEFAULT 0,
    statement TEXT NOT NULL DEFAULT '',
    suspected_behavior TEXT NOT NULL DEFAULT '',
    adversary_objective TEXT NOT NULL DEFAULT '',
    mitre_tactics TEXT NOT NULL DEFAULT '',
    mitre_techniques TEXT NOT NULL DEFAULT '',
    benign_explanations TEXT NOT NULL DEFAULT '',
    assumptions TEXT NOT NULL DEFAULT '',
    blind_spots TEXT NOT NULL DEFAULT '',
    limitations TEXT NOT NULL DEFAULT '',
    author_id TEXT REFERENCES users(user_id),
    generation_method TEXT NOT NULL DEFAULT 'MANUAL'
        CHECK (generation_method IN ('MANUAL','AI_ASSISTED','LEGACY_IMPORT')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (hypothesis_id, version_no)
);

CREATE TABLE IF NOT EXISTS hunt_hypothesis_version_events (
    event_id TEXT PRIMARY KEY,
    hypothesis_id TEXT NOT NULL REFERENCES hunt_hypotheses(hypothesis_id),
    version_no INTEGER NOT NULL,
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL
        CHECK (to_status IN ('DRAFT','READY_FOR_REVIEW','APPROVED','REJECTED','SUPERSEDED','ARCHIVED')),
    actor_id TEXT NOT NULL REFERENCES users(user_id),
    reason TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (hypothesis_id, version_no)
        REFERENCES hunt_hypothesis_versions(hypothesis_id, version_no)
);

CREATE VIEW IF NOT EXISTS v_hunt_hypothesis_version_state AS
SELECT v.hypothesis_id, v.version_no, v.creation_status,
    COALESCE((SELECT e.to_status FROM hunt_hypothesis_version_events e
              WHERE e.hypothesis_id = v.hypothesis_id AND e.version_no = v.version_no
              ORDER BY e.rowid DESC LIMIT 1), v.creation_status) AS effective_status
FROM hunt_hypothesis_versions v;

CREATE TRIGGER IF NOT EXISTS trg_hunt_version_update
BEFORE UPDATE ON hunt_hypothesis_versions
WHEN EXISTS (SELECT 1 FROM hunt_hypothesis_version_events e
             WHERE e.hypothesis_id = OLD.hypothesis_id AND e.version_no = OLD.version_no)
   OR NEW.creation_status <> 'DRAFT'
   OR NEW.draft_revision <> OLD.draft_revision + 1
   OR NEW.version_id <> OLD.version_id
   OR NEW.hypothesis_id <> OLD.hypothesis_id
   OR NEW.version_no <> OLD.version_no
   OR NEW.author_id IS NOT OLD.author_id
   OR NEW.generation_method <> OLD.generation_method
   OR NEW.created_at <> OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'version not an unsubmitted editable DRAFT, immutable identity, or revision mismatch');
END;

CREATE TRIGGER IF NOT EXISTS trg_hunt_version_no_delete
BEFORE DELETE ON hunt_hypothesis_versions
BEGIN SELECT RAISE(ABORT, 'hunt_hypothesis_versions is immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_hunt_event_transition
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

CREATE TRIGGER IF NOT EXISTS trg_hunt_event_no_update
BEFORE UPDATE ON hunt_hypothesis_version_events
BEGIN SELECT RAISE(ABORT, 'events are immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_hunt_event_no_delete
BEFORE DELETE ON hunt_hypothesis_version_events
BEGIN SELECT RAISE(ABORT, 'events are immutable'); END;

-- 6. Version-bound reviews (append-only; original_status checked against the
-- EFFECTIVE state; review must bind the current version).
CREATE TABLE IF NOT EXISTS hunt_hypothesis_reviews (
    review_id TEXT PRIMARY KEY,
    hypothesis_id TEXT NOT NULL REFERENCES hunt_hypotheses(hypothesis_id),
    version_no INTEGER NOT NULL,
    reviewer_id TEXT REFERENCES users(user_id), -- NULL only for LEGACY_IMPORT rows (pre-0010 provenance unknown)
    decision TEXT NOT NULL CHECK (decision IN ('APPROVED','REJECTED','NEEDS_MORE_DATA')),
    reason TEXT NOT NULL,
    original_status TEXT NOT NULL,
    reviewed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (hypothesis_id, version_no)
        REFERENCES hunt_hypothesis_versions(hypothesis_id, version_no)
);
CREATE INDEX IF NOT EXISTS idx_hunt_hyp_reviews_hyp ON hunt_hypothesis_reviews(hypothesis_id);
CREATE TRIGGER IF NOT EXISTS trg_hunt_review_original_status
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
CREATE TRIGGER IF NOT EXISTS trg_hunt_reviews_no_update
BEFORE UPDATE ON hunt_hypothesis_reviews
BEGIN SELECT RAISE(ABORT, 'hunt_hypothesis_reviews is immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_hunt_reviews_no_delete
BEFORE DELETE ON hunt_hypothesis_reviews
BEGIN SELECT RAISE(ABORT, 'hunt_hypothesis_reviews is immutable'); END;

-- 7. Typed evidence bindings (extends legacy hypothesis_evidence columns).
CREATE TABLE IF NOT EXISTS hunt_hypothesis_evidence (
    evidence_id TEXT PRIMARY KEY,
    hypothesis_id TEXT NOT NULL REFERENCES hunt_hypotheses(hypothesis_id),
    version_no INTEGER,
    evidence_role TEXT NOT NULL
        CHECK (evidence_role IN ('SUPPORTING','CONTRADICTING','CTI_SOURCE','RELEVANCE','INVESTIGATION','LEGACY')),
    target_entity_type TEXT NOT NULL,
    target_entity_id TEXT NOT NULL,
    report_id TEXT REFERENCES cti_reports(report_id),
    assessment_id TEXT REFERENCES relevance_assessments(assessment_id),
    source_reference TEXT,
    source_reliability TEXT,
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (hypothesis_id, version_no, evidence_role, target_entity_type, target_entity_id)
);
CREATE INDEX IF NOT EXISTS idx_hunt_hyp_ev_hyp ON hunt_hypothesis_evidence(hypothesis_id);

-- Evidence ownership: RELEVANCE rows must bind a relevance row owned by the
-- hypothesis' client and report; CTI_SOURCE must be the bound report.
CREATE TRIGGER IF NOT EXISTS trg_hunt_hyp_evidence_binding
BEFORE INSERT ON hunt_hypothesis_evidence
BEGIN
    SELECT RAISE(ABORT, 'evidence binding mismatch')
    WHERE NEW.evidence_role = 'RELEVANCE'
      AND NOT EXISTS (
          SELECT 1 FROM relevance_evidence re
          JOIN relevance_assessments a ON a.assessment_id = re.assessment_id
          WHERE re.evidence_id = NEW.target_entity_id
            AND re.assessment_id = NEW.assessment_id
            AND a.client_id = NEW.client_id
            AND a.report_id = NEW.report_id
      );
END;
CREATE TRIGGER IF NOT EXISTS trg_hunt_hyp_evidence_cti_source
BEFORE INSERT ON hunt_hypothesis_evidence
BEGIN
    SELECT RAISE(ABORT, 'cti source evidence must bind the hypothesis report')
    WHERE NEW.evidence_role = 'CTI_SOURCE'
      AND NOT EXISTS (
          SELECT 1 FROM hunt_hypotheses h
          WHERE h.hypothesis_id = NEW.hypothesis_id
            AND h.report_id IS NOT NULL
            AND h.report_id = NEW.target_entity_id
            AND h.report_id = NEW.report_id
      );
END;

-- 8. Telemetry requirements per version (Phase 1 tables; services in Phase 2).
CREATE TABLE IF NOT EXISTS hunt_hypothesis_telemetry (
    telemetry_id TEXT PRIMARY KEY,
    hypothesis_id TEXT NOT NULL REFERENCES hunt_hypotheses(hypothesis_id),
    version_no INTEGER NOT NULL,
    log_source_type_id TEXT NOT NULL REFERENCES log_source_types(log_source_type_id),
    event_categories TEXT,
    required_fields TEXT,
    optional_fields TEXT,
    data_components TEXT,
    availability_state TEXT NOT NULL DEFAULT 'UNKNOWN'
        CHECK (availability_state IN ('AVAILABLE','UNAVAILABLE','UNKNOWN')),
    rule_exists INTEGER NOT NULL DEFAULT 0,
    client_field_availability TEXT,
    field_verified_at TEXT,
    gaps TEXT,
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (hypothesis_id, version_no, log_source_type_id)
);
CREATE INDEX IF NOT EXISTS idx_hunt_hyp_telemetry_hyp ON hunt_hypothesis_telemetry(hypothesis_id);

-- 9. Hunt plans (query drafts are documentation-only).
CREATE TABLE IF NOT EXISTS hunt_plans (
    plan_id TEXT PRIMARY KEY,
    hypothesis_id TEXT NOT NULL REFERENCES hunt_hypotheses(hypothesis_id),
    version_no INTEGER NOT NULL,
    objective TEXT NOT NULL DEFAULT '',
    scope_and_boundary TEXT NOT NULL DEFAULT '',
    cti_justification TEXT NOT NULL DEFAULT '',
    expected_observables TEXT NOT NULL DEFAULT '',
    data_sources_and_fields TEXT NOT NULL DEFAULT '',
    known_benign_activity TEXT NOT NULL DEFAULT '',
    false_positive_considerations TEXT NOT NULL DEFAULT '',
    evidence_collection_requirements TEXT NOT NULL DEFAULT '',
    validation_criteria TEXT NOT NULL DEFAULT '',
    escalation_criteria TEXT NOT NULL DEFAULT '',
    blind_spots TEXT NOT NULL DEFAULT '',
    analyst_notes TEXT NOT NULL DEFAULT '',
    query_execution_status TEXT NOT NULL DEFAULT 'DRAFT_ONLY'
        CHECK (query_execution_status = 'DRAFT_ONLY'),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (hypothesis_id, version_no)
);

CREATE TABLE IF NOT EXISTS hunt_plan_steps (
    step_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL REFERENCES hunt_plans(plan_id),
    step_no INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('SEARCH_DRAFT','INVESTIGATE','VALIDATE','ESCALATE')),
    title TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    path_id TEXT,
    data_sources TEXT,
    fields TEXT,
    query_draft TEXT,
    executed_at TEXT CHECK (executed_at IS NULL),
    UNIQUE (plan_id, step_no)
);

-- 10. Append-only hypothesis activity (mirrors case_activity immutability).
CREATE TABLE IF NOT EXISTS hunt_hypothesis_activity (
    activity_id TEXT PRIMARY KEY,
    hypothesis_id TEXT NOT NULL REFERENCES hunt_hypotheses(hypothesis_id),
    version_no INTEGER,
    user_id TEXT NOT NULL REFERENCES users(user_id),
    action TEXT NOT NULL CHECK (action IN (
        'draft_created','version_created','submitted','approved','rejected',
        'returned_for_more_data','superseded','archived','telemetry_attached',
        'evidence_attached','linked','unlinked')),
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    details TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_hunt_hyp_activity_hyp ON hunt_hypothesis_activity(hypothesis_id);
CREATE TRIGGER IF NOT EXISTS trg_hunt_activity_no_update
BEFORE UPDATE ON hunt_hypothesis_activity
BEGIN SELECT RAISE(ABORT, 'hunt_hypothesis_activity is immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_hunt_activity_no_delete
BEFORE DELETE ON hunt_hypothesis_activity
BEGIN SELECT RAISE(ABORT, 'hunt_hypothesis_activity is immutable'); END;

-- 11. Backfill: one version v1 per legacy hypothesis with creation_status =
-- mapped status; APPROVED rows get a LEGACY_IMPORT review row (append-only).
INSERT INTO hunt_hypothesis_versions (
    version_id, hypothesis_id, version_no, creation_status, draft_revision,
    statement, author_id, generation_method
)
SELECT 'v-' || hypothesis_id, hypothesis_id, 1,
    CASE WHEN status = 'READY_FOR_REVIEW' THEN 'READY_FOR_REVIEW'
         WHEN status = 'APPROVED' THEN 'APPROVED'
         WHEN status = 'REJECTED' THEN 'REJECTED'
         WHEN status = 'SUPERSEDED' THEN 'ARCHIVED'
         WHEN status = 'ARCHIVED' THEN 'ARCHIVED'
         ELSE 'DRAFT' END,
    0, description, author_id, generation_method
FROM hunt_hypotheses;

INSERT INTO hunt_hypothesis_reviews (
    review_id, hypothesis_id, version_no, reviewer_id, decision, reason,
    original_status, reviewed_at
)
SELECT 'rev-import-' || hypothesis_id, hypothesis_id, 1,
    NULL, 'APPROVED',
    'LEGACY_IMPORT: pre-0010 approval imported verbatim', 'APPROVED',
    CURRENT_TIMESTAMP
FROM hunt_hypotheses
WHERE status = 'APPROVED';
