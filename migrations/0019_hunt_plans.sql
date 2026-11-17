-- 0019_hunt_plans.sql
-- M7-D Phase 2B-4A: Hunt Plans over immutable AQL drafts.
-- Additive only; 0001-0018 are applied and are not rewritten.
--
-- Note: migration 0010 already defines a documentation-only `hunt_plans` table
-- (hypothesis narrative + DRAFT_ONLY steps, UNIQUE per hypothesis version, no
-- review state, no AQL link). It is left untouched. The authoritative,
-- reviewable plan lives in `hunt_plan_versions`, one row per plan version, so
-- an approved plan can be superseded without editing it.
--
-- A Hunt Plan is a reviewed *draft* bundle. It never records execution, and an
-- approved version is immutable: changes create a new version.

CREATE TABLE IF NOT EXISTS hunt_plan_versions (
    plan_id             TEXT PRIMARY KEY,
    logical_id          TEXT NOT NULL,
    version             INTEGER NOT NULL DEFAULT 1,
    client_id           TEXT NOT NULL REFERENCES clients(client_id),
    hypothesis_id       TEXT NOT NULL,
    hypothesis_version  INTEGER NOT NULL,
    report_id           TEXT,
    title               TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'DRAFT'
        CHECK (status IN ('DRAFT','IN_REVIEW','APPROVED','REJECTED')),
    supersedes_plan_id  TEXT,
    created_by          TEXT NOT NULL REFERENCES users(user_id),
    created_at          TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    submitted_by        TEXT REFERENCES users(user_id),
    submitted_at        TEXT,
    reviewed_by         TEXT REFERENCES users(user_id),
    reviewed_at         TEXT,
    review_evidence     TEXT,
    review_note         TEXT,
    UNIQUE (logical_id, version),
    FOREIGN KEY (hypothesis_id, hypothesis_version)
        REFERENCES hunt_hypothesis_versions(hypothesis_id, version_no)
);
CREATE INDEX IF NOT EXISTS idx_hunt_plan_versions_client ON hunt_plan_versions(client_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_hunt_plan_versions_logical ON hunt_plan_versions(logical_id, version DESC);

CREATE TABLE IF NOT EXISTS hunt_plan_version_items (
    plan_id                 TEXT NOT NULL REFERENCES hunt_plan_versions(plan_id),
    translation_id          TEXT NOT NULL REFERENCES detection_translations(translation_id),
    domain_id               TEXT NOT NULL REFERENCES qradar_domains(domain_id),
    native_qradar_domain_id TEXT NOT NULL,
    added_by                TEXT NOT NULL REFERENCES users(user_id),
    added_at                TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (plan_id, translation_id)
);
CREATE INDEX IF NOT EXISTS idx_hunt_plan_version_items_translation ON hunt_plan_version_items(translation_id);

-- An approved plan is evidence and must not be edited afterwards.
CREATE TRIGGER IF NOT EXISTS trg_hunt_plan_versions_approved_immutable
BEFORE UPDATE ON hunt_plan_versions
BEGIN
    SELECT RAISE(ABORT, 'approved hunt plans are immutable; create a new version')
    WHERE OLD.status = 'APPROVED';
END;
CREATE TRIGGER IF NOT EXISTS trg_hunt_plan_versions_approved_no_delete
BEFORE DELETE ON hunt_plan_versions
BEGIN
    SELECT RAISE(ABORT, 'approved hunt plans are immutable; create a new version')
    WHERE OLD.status = 'APPROVED';
END;

-- Items of a plan that has left DRAFT cannot change; approved plans are final.
CREATE TRIGGER IF NOT EXISTS trg_hunt_plan_version_items_locked
BEFORE INSERT ON hunt_plan_version_items
BEGIN
    SELECT RAISE(ABORT, 'plan items can only be added while the plan is DRAFT')
    WHERE EXISTS (SELECT 1 FROM hunt_plan_versions p WHERE p.plan_id = NEW.plan_id AND p.status <> 'DRAFT');
END;
CREATE TRIGGER IF NOT EXISTS trg_hunt_plan_version_items_no_update
BEFORE UPDATE ON hunt_plan_version_items
BEGIN
    SELECT RAISE(ABORT, 'plan items are immutable');
END;
CREATE TRIGGER IF NOT EXISTS trg_hunt_plan_version_items_no_delete
BEFORE DELETE ON hunt_plan_version_items
BEGIN
    SELECT RAISE(ABORT, 'plan items are immutable');
END;

-- Status transitions are restricted at the storage boundary too.
CREATE TRIGGER IF NOT EXISTS trg_hunt_plan_versions_status_transition
BEFORE UPDATE OF status ON hunt_plan_versions
BEGIN
    SELECT RAISE(ABORT, 'invalid hunt plan status transition')
    WHERE NOT (
        (OLD.status = 'DRAFT'     AND NEW.status IN ('DRAFT','IN_REVIEW'))
     OR (OLD.status = 'IN_REVIEW' AND NEW.status IN ('APPROVED','REJECTED'))
    );
END;

-- A plan may never claim that its draft was executed.
CREATE TRIGGER IF NOT EXISTS trg_hunt_plan_versions_no_execution_claim
BEFORE INSERT ON hunt_plan_versions
BEGIN
    SELECT RAISE(ABORT, 'hunt plans must not claim execution')
    WHERE LOWER(NEW.title) LIKE '%executed%'
       OR LOWER(COALESCE(NEW.review_note,'')) LIKE '%verified_by_qradar%';
END;
