-- Migration 0008_relevance.sql
-- M7-C: Client Relevance Engine (additive).
-- Assessment attempts are never blocked by content uniqueness; HTTP idempotency
-- is enforced separately. Historical findings/evidence/reviews are immutable.

PRAGMA foreign_keys = ON;

-- Versioned matching rules (immutable once created; new rules = new rows).
CREATE TABLE IF NOT EXISTS relevance_matching_rules (
    rule_id TEXT PRIMARY KEY,
    rule_version TEXT NOT NULL,
    dimension TEXT NOT NULL CHECK (dimension IN ('SECTOR','TECHNOLOGY','TELEMETRY')),
    rule_name TEXT NOT NULL,
    rule_definition TEXT NOT NULL,
    created_by TEXT REFERENCES users(user_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (dimension, rule_version, rule_name)
);

-- Assessment attempt history: EVERY explicit reassessment (incl. retry after
-- FAILED, identical inputs) creates a NEW assessment_id. No document-level UNIQUE.
CREATE TABLE IF NOT EXISTS relevance_assessments (
    assessment_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES cti_reports(report_id),
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    status TEXT NOT NULL CHECK (status IN ('PENDING','COMPLETED','FAILED')),
    error_code TEXT,
    request_idempotency_key TEXT,
    payload_fingerprint TEXT,
    cti_evidence_snapshot TEXT NOT NULL,
    inventory_snapshot TEXT NOT NULL,
    rule_set_fingerprint TEXT NOT NULL,
    matching_rule_version TEXT NOT NULL,
    created_by TEXT REFERENCES users(user_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_relevance_assessments_report ON relevance_assessments(report_id);
CREATE INDEX IF NOT EXISTS idx_relevance_assessments_client ON relevance_assessments(client_id, created_at DESC);
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
    unknowns TEXT,
    limitations TEXT,
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
    source_reference TEXT,
    source_reliability TEXT,
    inventory_evidence TEXT,
    matching_rule_id TEXT NOT NULL REFERENCES relevance_matching_rules(rule_id),
    matching_rule_version TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (finding_id, matched_entity_type, matched_entity_id, matching_rule_id)
);
-- One evidence row per (finding, matched entity, matching rule). The same
-- entity may be explained by multiple rules — each rule keeps its provenance.
CREATE TABLE IF NOT EXISTS relevance_snapshots (
    assessment_id TEXT PRIMARY KEY REFERENCES relevance_assessments(assessment_id),
    cti_evidence_document TEXT NOT NULL,
    inventory_document TEXT NOT NULL,
    rule_set_document TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_relevance_evidence_finding ON relevance_evidence(finding_id);

-- Analyst review / override (append-only; never mutates findings).
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
CREATE INDEX IF NOT EXISTS idx_relevance_reviews_assessment ON relevance_reviews(assessment_id);

-- Tenant consistency: assessment client must equal report client.
CREATE TRIGGER IF NOT EXISTS trg_relevance_client_match
BEFORE INSERT ON relevance_assessments
BEGIN
    SELECT RAISE(ABORT, 'client mismatch')
    WHERE NOT EXISTS (
        SELECT 1 FROM cti_reports WHERE report_id = NEW.report_id AND client_id = NEW.client_id
    );
END;

-- Finding/assessment existence (DB defense-in-depth).
CREATE TRIGGER IF NOT EXISTS trg_relevance_finding_assessment_match
BEFORE INSERT ON relevance_findings
BEGIN
    SELECT RAISE(ABORT, 'assessment mismatch')
    WHERE NOT EXISTS (
        SELECT 1 FROM relevance_assessments WHERE assessment_id = NEW.assessment_id
    );
END;

-- Reviewer cannot lie about the computed verdict.
CREATE TRIGGER IF NOT EXISTS trg_relevance_review_original_match
BEFORE INSERT ON relevance_reviews
BEGIN
    SELECT RAISE(ABORT, 'original verdict mismatch')
    WHERE NOT EXISTS (
        SELECT 1 FROM relevance_findings
        WHERE assessment_id = NEW.assessment_id AND dimension = NEW.dimension AND verdict = NEW.original_verdict
    );
END;

-- Evidence must belong to the same assessment as its finding, with the same
-- report/client/dimension (cross-assessment mismatch is rejected).
CREATE TRIGGER IF NOT EXISTS trg_relevance_evidence_match
BEFORE INSERT ON relevance_evidence
BEGIN
    SELECT RAISE(ABORT, 'evidence mismatch')
    WHERE NOT EXISTS (
        SELECT 1 FROM relevance_findings f
        JOIN relevance_assessments a ON a.assessment_id = f.assessment_id
        WHERE f.finding_id = NEW.finding_id
          AND f.assessment_id = NEW.assessment_id
          AND f.dimension = NEW.dimension
          AND a.report_id = NEW.report_id
          AND a.client_id = NEW.client_id
    );
END;

-- Append-only: findings and reviews are immutable.
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
