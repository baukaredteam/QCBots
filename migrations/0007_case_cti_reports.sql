-- Migration 0007_case_cti_reports.sql
-- M7-B: CTI Reports <-> Research Cases links (additive).
-- Case_activity is rebuilt to extend its action CHECK with report_linked/report_unlinked.
-- Row preservation is exact: every history row is copied verbatim (same PK, same values).

PRAGMA foreign_keys = ON;

-- 1. Bidirectional link table (attempt identity = PK pair; no separate surrogate).
CREATE TABLE IF NOT EXISTS case_cti_reports (
    case_id   TEXT NOT NULL REFERENCES research_cases(case_id),
    report_id TEXT NOT NULL REFERENCES cti_reports(report_id),
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    linked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    linked_by TEXT NOT NULL REFERENCES users(user_id),
    PRIMARY KEY (case_id, report_id),
    CHECK (client_id IS NOT NULL AND client_id <> '')
);

CREATE INDEX IF NOT EXISTS idx_case_cti_reports_case   ON case_cti_reports(case_id);
CREATE INDEX IF NOT EXISTS idx_case_cti_reports_report ON case_cti_reports(report_id);
CREATE INDEX IF NOT EXISTS idx_case_cti_reports_client ON case_cti_reports(client_id);

-- Tenant consistency: link row client must equal the report's client.
CREATE TRIGGER IF NOT EXISTS trg_case_cti_reports_client_match
BEFORE INSERT ON case_cti_reports
BEGIN
    SELECT RAISE(ABORT, 'client mismatch')
    WHERE NOT EXISTS (
        SELECT 1 FROM cti_reports
        WHERE report_id = NEW.report_id AND client_id = NEW.client_id
    );
END;

-- Link identity is immutable: UPDATE of identity columns is forbidden.
-- (DELETE is the unlink operation and remains allowed.)
CREATE TRIGGER IF NOT EXISTS trg_case_cti_reports_no_update
BEFORE UPDATE ON case_cti_reports
BEGIN
    SELECT RAISE(ABORT, 'case_cti_reports identity is immutable: UPDATE not allowed');
END;

-- 2. Rebuild case_activity with extended action CHECK.
-- No other table references case_activity, so DROP is safe with FK on.
CREATE TABLE IF NOT EXISTS case_activity_new (
    activity_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES research_cases(case_id),
    user_id TEXT NOT NULL REFERENCES users(user_id),
    action TEXT NOT NULL CHECK (action IN ('status_changed','participant_added','participant_removed','artifact_added','artifact_reviewed','note_added','note_edited','hypothesis_linked','hypothesis_unlinked','investigation_created','review_requested','report_linked','report_unlinked')),
    visibility_scope TEXT NOT NULL DEFAULT 'GLOBAL' CHECK (visibility_scope IN ('GLOBAL','CLIENT')),
    client_id TEXT REFERENCES clients(client_id),
    details TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_case_activity_scope CHECK (
        (visibility_scope = 'GLOBAL' AND client_id IS NULL)
        OR (visibility_scope = 'CLIENT' AND client_id IS NOT NULL)
    )
);

INSERT OR IGNORE INTO case_activity_new (activity_id, case_id, user_id, action, visibility_scope, client_id, details, created_at)
    SELECT activity_id, case_id, user_id, action, visibility_scope, client_id, details, created_at FROM case_activity;

DROP TABLE IF EXISTS case_activity;
ALTER TABLE case_activity_new RENAME TO case_activity;

-- Recreate indexes (FK targets unchanged).
CREATE INDEX IF NOT EXISTS idx_case_activity_case ON case_activity(case_id);
CREATE INDEX IF NOT EXISTS idx_case_activity_case_created ON case_activity(case_id, created_at);
CREATE INDEX IF NOT EXISTS idx_case_activity_client ON case_activity(client_id);

-- M7-B scoping: idempotency for create-from-report is per (user, key) and
-- bound to report_id + payload fingerprint, independent of M6 case keys.
CREATE TABLE IF NOT EXISTS case_cti_create_ops (
    idempotency_key TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(user_id),
    case_id TEXT NOT NULL REFERENCES research_cases(case_id),
    report_id TEXT NOT NULL REFERENCES cti_reports(report_id),
    payload_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, idempotency_key)
);

-- Recreate immutability triggers.
CREATE TRIGGER IF NOT EXISTS trg_case_activity_no_update
BEFORE UPDATE ON case_activity
BEGIN
    SELECT RAISE(ABORT, 'case_activity is immutable: UPDATE not allowed');
END;

CREATE TRIGGER IF NOT EXISTS trg_case_activity_no_delete
BEFORE DELETE ON case_activity
BEGIN
    SELECT RAISE(ABORT, 'case_activity is immutable: DELETE not allowed');
END;
