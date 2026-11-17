-- Migration 0005_m6_case_workspace.sql
-- M6: Research Case Workspace
-- Additive only -- no modifications to existing tables or columns

PRAGMA foreign_keys = ON;

-- Extend research_cases with lifecycle metadata.
-- No client_id column here -- case access is client-agnostic at the case level.
ALTER TABLE research_cases ADD COLUMN priority TEXT CHECK (priority IN ('P1','P2','P3','P4'));
ALTER TABLE research_cases ADD COLUMN severity TEXT CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW'));
ALTER TABLE research_cases ADD COLUMN closed_by TEXT REFERENCES users(user_id);
ALTER TABLE research_cases ADD COLUMN closed_reason TEXT;
ALTER TABLE research_cases ADD COLUMN payload_hash TEXT;
ALTER TABLE research_cases ADD COLUMN primary_client TEXT REFERENCES clients(client_id);

-- Extend case_authorized_participants with revocation support.
ALTER TABLE case_authorized_participants ADD COLUMN revoked_at TEXT;
ALTER TABLE case_authorized_participants ADD COLUMN revoked_by TEXT REFERENCES users(user_id);

-- Extend case_artifacts with human review fields.
ALTER TABLE case_artifacts ADD COLUMN reviewed_by TEXT REFERENCES users(user_id);
ALTER TABLE case_artifacts ADD COLUMN reviewed_at TEXT;
ALTER TABLE case_artifacts ADD COLUMN review_reason TEXT;
ALTER TABLE case_artifacts ADD COLUMN review_decision TEXT CHECK (review_decision IN ('APPROVED','REJECTED','NEEDS_MORE_DATA'));

-- New: case_hypotheses -- many-to-many link between cases and hypotheses.
CREATE TABLE IF NOT EXISTS case_hypotheses (
    case_id TEXT NOT NULL REFERENCES research_cases(case_id),
    hypothesis_id TEXT NOT NULL REFERENCES hunt_hypotheses(hypothesis_id),
    linked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    linked_by TEXT NOT NULL REFERENCES users(user_id),
    PRIMARY KEY (case_id, hypothesis_id)
);

-- New: case_hypothesis_review -- per-client review results for linked hypotheses.
-- Append-only: each review gets a new row; latest decision is MAX(reviewed_at).
CREATE TABLE IF NOT EXISTS case_hypothesis_review (
    review_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES research_cases(case_id),
    hypothesis_id TEXT NOT NULL REFERENCES hunt_hypotheses(hypothesis_id),
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    reviewer_id TEXT NOT NULL REFERENCES users(user_id),
    decision TEXT NOT NULL CHECK (decision IN ('APPROVED','REJECTED','NEEDS_MORE_DATA')),
    reason TEXT,
    reviewed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- New: case_notes -- analyst notes attached to cases.
-- visibility_scope: GLOBAL (visible to all with case access) or CLIENT (client-scoped).
-- CLIENT scope requires client_id and restricts visibility to authorized clients.
CREATE TABLE IF NOT EXISTS case_notes (
    note_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES research_cases(case_id),
    user_id TEXT NOT NULL REFERENCES users(user_id),
    note_text TEXT NOT NULL,
    note_type TEXT NOT NULL DEFAULT 'observation' CHECK (note_type IN ('observation','finding','question','escalation')),
    visibility_scope TEXT NOT NULL DEFAULT 'CLIENT' CHECK (visibility_scope IN ('GLOBAL','CLIENT')),
    client_id TEXT REFERENCES clients(client_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_case_notes_scope CHECK (
        (visibility_scope = 'GLOBAL' AND client_id IS NULL)
        OR (visibility_scope = 'CLIENT' AND client_id IS NOT NULL)
    )
);

-- New: case_notes_revision -- append-only revision history for notes.
CREATE TABLE IF NOT EXISTS case_notes_revision (
    revision_id TEXT PRIMARY KEY,
    note_id TEXT NOT NULL REFERENCES case_notes(note_id),
    note_text TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- New: case_activity -- immutable activity feed with client-scoped visibility.
CREATE TABLE IF NOT EXISTS case_activity (
    activity_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES research_cases(case_id),
    user_id TEXT NOT NULL REFERENCES users(user_id),
    action TEXT NOT NULL CHECK (action IN ('status_changed','participant_added','participant_removed','artifact_added','artifact_reviewed','note_added','note_edited','hypothesis_linked','hypothesis_unlinked','investigation_created','review_requested')),
    visibility_scope TEXT NOT NULL DEFAULT 'GLOBAL' CHECK (visibility_scope IN ('GLOBAL','CLIENT')),
    client_id TEXT REFERENCES clients(client_id),
    details TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_case_activity_scope CHECK (
        (visibility_scope = 'GLOBAL' AND client_id IS NULL)
        OR (visibility_scope = 'CLIENT' AND client_id IS NOT NULL)
    )
);

-- Immutability triggers for case_activity -- append-only, never updated or deleted.
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

-- Immutability triggers for case_notes_revision -- append-only, never updated or deleted.
CREATE TRIGGER IF NOT EXISTS trg_case_notes_revision_no_update
BEFORE UPDATE ON case_notes_revision
BEGIN
    SELECT RAISE(ABORT, 'case_notes_revision is immutable: UPDATE not allowed');
END;

CREATE TRIGGER IF NOT EXISTS trg_case_notes_revision_no_delete
BEFORE DELETE ON case_notes_revision
BEGIN
    SELECT RAISE(ABORT, 'case_notes_revision is immutable: DELETE not allowed');
END;

-- Immutability triggers for case_hypothesis_review -- append-only, never updated or deleted.
-- Review history is append-only: each new decision is a new row.
CREATE TRIGGER IF NOT EXISTS trg_case_hyp_review_no_update
BEFORE UPDATE ON case_hypothesis_review
BEGIN
    SELECT RAISE(ABORT, 'case_hypothesis_review is immutable: UPDATE not allowed');
END;

CREATE TRIGGER IF NOT EXISTS trg_case_hyp_review_no_delete
BEFORE DELETE ON case_hypothesis_review
BEGIN
    SELECT RAISE(ABORT, 'case_hypothesis_review is immutable: DELETE not allowed');
END;

-- Extend investigations with case_id link.
ALTER TABLE investigations ADD COLUMN case_id TEXT REFERENCES research_cases(case_id);

-- Indexes.
CREATE INDEX IF NOT EXISTS idx_case_hypotheses_case ON case_hypotheses(case_id);
CREATE INDEX IF NOT EXISTS idx_case_hypotheses_hypothesis ON case_hypotheses(hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_case_hyp_review_case ON case_hypothesis_review(case_id);
CREATE INDEX IF NOT EXISTS idx_case_hyp_review_client ON case_hypothesis_review(case_id, client_id);
CREATE INDEX IF NOT EXISTS idx_case_notes_case ON case_notes(case_id);
CREATE INDEX IF NOT EXISTS idx_case_notes_revision_note ON case_notes_revision(note_id);
CREATE INDEX IF NOT EXISTS idx_case_activity_case ON case_activity(case_id);
CREATE INDEX IF NOT EXISTS idx_case_activity_case_created ON case_activity(case_id, created_at);
CREATE INDEX IF NOT EXISTS idx_case_activity_client ON case_activity(client_id);
CREATE INDEX IF NOT EXISTS idx_investigations_case ON investigations(case_id);
CREATE INDEX IF NOT EXISTS idx_research_cases_priority ON research_cases(priority);
CREATE INDEX IF NOT EXISTS idx_research_cases_severity ON research_cases(severity);
