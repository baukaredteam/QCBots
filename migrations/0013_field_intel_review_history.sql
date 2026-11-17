-- 0013_field_intel_review_history.sql
-- Forward migration. Append-only review provenance for imports and mappings.
--
-- 0011 and 0012 are already applied and are not rewritten. Nothing here alters
-- existing rows: the history starts empty and records every future decision.

CREATE TABLE IF NOT EXISTS qradar_import_reviews (
    review_id       TEXT PRIMARY KEY,
    batch_id        TEXT NOT NULL REFERENCES qradar_import_batches(batch_id),
    client_id       TEXT NOT NULL REFERENCES clients(client_id),
    reviewer_id     TEXT NOT NULL REFERENCES users(user_id),
    decision        TEXT NOT NULL CHECK (decision IN ('APPROVED','REJECTED','PUBLISHED')),
    evidence        TEXT NOT NULL,
    previous_status TEXT NOT NULL,
    new_status      TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qradar_import_reviews_batch ON qradar_import_reviews(batch_id, created_at);

CREATE TABLE IF NOT EXISTS qradar_mapping_reviews (
    review_id   TEXT PRIMARY KEY,
    mapping_id  TEXT NOT NULL REFERENCES qradar_field_mappings(mapping_id),
    client_id   TEXT NOT NULL REFERENCES clients(client_id),
    reviewer_id TEXT NOT NULL REFERENCES users(user_id),
    decision    TEXT NOT NULL CHECK (decision IN ('APPROVED')),
    evidence    TEXT NOT NULL,
    mapping_version TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qradar_mapping_reviews_mapping ON qradar_mapping_reviews(mapping_id, created_at);

-- Append-only is enforced in the database, not by convention.
CREATE TRIGGER IF NOT EXISTS trg_qradar_import_reviews_no_update
BEFORE UPDATE ON qradar_import_reviews
BEGIN
    SELECT RAISE(ABORT, 'import review history is append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_qradar_import_reviews_no_delete
BEFORE DELETE ON qradar_import_reviews
BEGIN
    SELECT RAISE(ABORT, 'import review history is append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_qradar_mapping_reviews_no_update
BEFORE UPDATE ON qradar_mapping_reviews
BEGIN
    SELECT RAISE(ABORT, 'mapping review history is append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_qradar_mapping_reviews_no_delete
BEFORE DELETE ON qradar_mapping_reviews
BEGIN
    SELECT RAISE(ABORT, 'mapping review history is append-only');
END;
