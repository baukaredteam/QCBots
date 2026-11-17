-- 0017_sigma_detection_ingestion.sql
-- M7-D Phase 2B-1: immutable Sigma detection sources and versioned rules.
-- Additive only; migrations 0001-0016 are applied and are not rewritten.

CREATE TABLE IF NOT EXISTS sigma_detection_sources (
    source_id    TEXT PRIMARY KEY,
    client_id    TEXT NOT NULL REFERENCES clients(client_id),
    source_kind  TEXT NOT NULL CHECK (source_kind IN ('MANUAL_UPLOAD','CTI_REPORT_ATTACHMENT','CONNECTOR')),
    report_id    TEXT,
    filename     TEXT NOT NULL,
    yaml_sha256  TEXT NOT NULL,
    byte_size    INTEGER NOT NULL,
    created_by   TEXT NOT NULL REFERENCES users(user_id),
    created_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sigma_detection_sources_client ON sigma_detection_sources(client_id, created_at);

CREATE TABLE IF NOT EXISTS sigma_detection_rules (
    rule_id             TEXT PRIMARY KEY,
    source_id           TEXT NOT NULL REFERENCES sigma_detection_sources(source_id),
    client_id           TEXT NOT NULL REFERENCES clients(client_id),
    sigma_rule_id       TEXT NOT NULL,
    version             INTEGER NOT NULL,
    title               TEXT NOT NULL,
    status              TEXT,
    description         TEXT,
    author              TEXT,
    level               TEXT,
    logsource_product   TEXT,
    logsource_category  TEXT,
    logsource_service   TEXT,
    condition_expr      TEXT NOT NULL,
    tags_json           TEXT NOT NULL DEFAULT '[]',
    modifiers_json      TEXT NOT NULL DEFAULT '[]',
    fields_json         TEXT NOT NULL DEFAULT '[]',
    yaml_text           TEXT NOT NULL,
    yaml_sha256         TEXT NOT NULL,
    byte_size           INTEGER NOT NULL,
    created_by          TEXT NOT NULL REFERENCES users(user_id),
    created_at          TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (client_id, sigma_rule_id, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_sigma_detection_rules_content
    ON sigma_detection_rules(client_id, yaml_sha256);
CREATE INDEX IF NOT EXISTS idx_sigma_detection_rules_client ON sigma_detection_rules(client_id, created_at);
CREATE INDEX IF NOT EXISTS idx_sigma_detection_rules_sigma ON sigma_detection_rules(client_id, sigma_rule_id, version);

-- A stored detection is evidence: it is never edited or deleted. A changed rule
-- is a new version, and a changed source is a new source row.
CREATE TRIGGER IF NOT EXISTS trg_sigma_detection_rules_no_update
BEFORE UPDATE ON sigma_detection_rules
BEGIN
    SELECT RAISE(ABORT, 'detection rules are immutable');
END;
CREATE TRIGGER IF NOT EXISTS trg_sigma_detection_rules_no_delete
BEFORE DELETE ON sigma_detection_rules
BEGIN
    SELECT RAISE(ABORT, 'detection rules are immutable');
END;
CREATE TRIGGER IF NOT EXISTS trg_sigma_detection_sources_no_update
BEFORE UPDATE ON sigma_detection_sources
BEGIN
    SELECT RAISE(ABORT, 'detection sources are immutable');
END;
CREATE TRIGGER IF NOT EXISTS trg_sigma_detection_sources_no_delete
BEFORE DELETE ON sigma_detection_sources
BEGIN
    SELECT RAISE(ABORT, 'detection sources are immutable');
END;

-- YAML must actually carry a rule identity and a condition; refuse obvious junk
-- at the storage boundary as a second line of defence behind the Go parser.
CREATE TRIGGER IF NOT EXISTS trg_sigma_detection_rules_insert_guard
BEFORE INSERT ON sigma_detection_rules
BEGIN
    SELECT RAISE(ABORT, 'detection rule requires id, title, condition and yaml')
    WHERE TRIM(NEW.sigma_rule_id) = '' OR TRIM(NEW.title) = ''
       OR TRIM(NEW.condition_expr) = '' OR TRIM(NEW.yaml_text) = ''
       OR TRIM(NEW.yaml_sha256) = '';
END;
