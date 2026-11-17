-- 0018_detection_translations.sql
-- M7-D Phase 2B-3: immutable, versioned AQL drafts.
-- Additive only; 0001-0017 are applied and are not rewritten.
--
-- A stored draft is evidence of a conversion attempt, not of execution. It keeps
-- the exact provenance needed to decide later whether it is still current.

CREATE TABLE IF NOT EXISTS detection_translations (
    translation_id          TEXT PRIMARY KEY,
    rule_id                 TEXT NOT NULL REFERENCES sigma_detection_rules(rule_id),
    client_id               TEXT NOT NULL REFERENCES clients(client_id),
    instance_id             TEXT NOT NULL REFERENCES qradar_instances(instance_id),
    domain_id               TEXT NOT NULL REFERENCES qradar_domains(domain_id),
    native_qradar_domain_id TEXT NOT NULL,
    binding_revision        INTEGER NOT NULL,
    conversion_mode         TEXT NOT NULL CHECK (conversion_mode IN
        ('VERIFIED_FIELDS_ONLY','REVIEW_REQUIRED_FIELDS','PAYLOAD_FALLBACK')),
    status                  TEXT NOT NULL CHECK (status IN
        ('READY_FOR_REVIEW','NEEDS_FIELD_VERIFICATION','UNSUPPORTED','BLOCKED')),
    aql_draft               TEXT NOT NULL DEFAULT '',
    aql_sha256              TEXT NOT NULL DEFAULT '',
    time_window_days        INTEGER NOT NULL DEFAULT 0,
    mapping_snapshot        TEXT NOT NULL DEFAULT '[]',
    diagnostics             TEXT NOT NULL DEFAULT '{}',
    worker_version          TEXT NOT NULL DEFAULT '',
    backend_version         TEXT NOT NULL DEFAULT '',
    pysigma_version         TEXT NOT NULL DEFAULT '',
    sigma_rule_hash         TEXT NOT NULL,
    sigma_rule_version      INTEGER NOT NULL,
    validation_status       TEXT NOT NULL DEFAULT 'PRELIMINARY',
    created_by              TEXT NOT NULL REFERENCES users(user_id),
    created_at              TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_detection_translations_rule
    ON detection_translations(rule_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_detection_translations_client
    ON detection_translations(client_id, created_at DESC);

-- Drafts are immutable. A changed mapping, binding or rule version produces a
-- new draft; staleness is derived at read time from the stored snapshot.
CREATE TRIGGER IF NOT EXISTS trg_detection_translations_no_update
BEFORE UPDATE ON detection_translations
BEGIN
    SELECT RAISE(ABORT, 'detection translations are immutable');
END;
CREATE TRIGGER IF NOT EXISTS trg_detection_translations_no_delete
BEFORE DELETE ON detection_translations
BEGIN
    SELECT RAISE(ABORT, 'detection translations are immutable');
END;

-- A draft can never claim that QRadar ran it.
CREATE TRIGGER IF NOT EXISTS trg_detection_translations_no_execution_claim
BEFORE INSERT ON detection_translations
BEGIN
    SELECT RAISE(ABORT, 'AQL drafts must not claim execution')
    WHERE LOWER(NEW.aql_draft) LIKE '%verified_by_qradar%'
       OR LOWER(NEW.status) = 'executed'
       OR LOWER(NEW.diagnostics) LIKE '%"executed":true%';
END;
