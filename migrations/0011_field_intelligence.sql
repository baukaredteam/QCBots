-- Migration 0011_field_intelligence.sql
-- M7-D Phase 1: Field Intelligence Registry (additive only).
--
-- Models client-scoped QRadar telemetry inventory:
--   instances -> domains -> log source types -> log sources -> QIDs/events
--   field definitions -> field mappings -> field observations
--   import batches (staged: upload -> parse -> redact -> map -> review -> publish)
--
-- All tables are client-scoped (tenant isolation). No cross-client access.
-- No existing tables are modified; purely additive.

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- QRadar instance per client
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS qradar_instances (
    instance_id TEXT PRIMARY KEY,
    client_id   TEXT NOT NULL REFERENCES clients(client_id),
    instance_name TEXT NOT NULL,
    host        TEXT,
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (client_id, instance_name)
);
CREATE INDEX IF NOT EXISTS idx_qradar_instances_client ON qradar_instances(client_id);

-- QRadar domain per instance
CREATE TABLE IF NOT EXISTS qradar_domains (
    domain_id     TEXT PRIMARY KEY,
    instance_id   TEXT NOT NULL REFERENCES qradar_instances(instance_id),
    domain_name   TEXT NOT NULL,
    domain_type   TEXT,
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (instance_id, domain_name)
);
CREATE INDEX IF NOT EXISTS idx_qradar_domains_instance ON qradar_domains(instance_id);

-- QRadar log source type per domain
CREATE TABLE IF NOT EXISTS qradar_log_source_types (
    log_source_type_id TEXT PRIMARY KEY,
    domain_id          TEXT NOT NULL REFERENCES qradar_domains(domain_id),
    type_name          TEXT NOT NULL,
    created_at         TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (domain_id, type_name)
);
CREATE INDEX IF NOT EXISTS idx_qradar_log_source_types_domain ON qradar_log_source_types(domain_id);

-- QRadar log source per client (per-client deployment of a log source type)
CREATE TABLE IF NOT EXISTS qradar_log_sources (
    log_source_id       TEXT PRIMARY KEY,
    log_source_type_id  TEXT NOT NULL REFERENCES qradar_log_source_types(log_source_type_id),
    status              TEXT NOT NULL DEFAULT 'UNKNOWN'
                          CHECK (status IN ('CONNECTED','DISCONNECTED','NO_RECENT_EVENTS','UNKNOWN')),
    first_seen          TEXT,
    last_seen           TEXT,
    data_provenance     TEXT,
    created_at          TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qradar_log_sources_type ON qradar_log_sources(log_source_type_id);

-- QRadar QID / event per log source
CREATE TABLE IF NOT EXISTS qradar_qids (
    qid             TEXT PRIMARY KEY,
    log_source_id   TEXT NOT NULL REFERENCES qradar_log_sources(log_source_id),
    event_name      TEXT NOT NULL,
    native_event_id TEXT,
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (log_source_id, event_name)
);
CREATE INDEX IF NOT EXISTS idx_qradar_qids_source ON qradar_qids(log_source_id);

-- ---------------------------------------------------------------------------
-- Field definitions (client + domain scoped)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS qradar_field_definitions (
    field_id            TEXT PRIMARY KEY,
    client_id           TEXT NOT NULL REFERENCES clients(client_id),
    domain_id           TEXT NOT NULL REFERENCES qradar_domains(domain_id),
    field_name          TEXT NOT NULL,
    field_origin        TEXT NOT NULL DEFAULT 'raw_only'
        CHECK (field_origin IN ('system','normalized','custom','raw_only')),
    data_type           TEXT,
    cep_identifier      TEXT,
    supported_event_scope TEXT,
    aql_field_expression TEXT,
    created_at          TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (client_id, domain_id, field_name)
);
CREATE INDEX IF NOT EXISTS idx_qradar_field_definitions_client ON qradar_field_definitions(client_id);
CREATE INDEX IF NOT EXISTS idx_qradar_field_definitions_domain ON qradar_field_definitions(domain_id);

-- ---------------------------------------------------------------------------
-- Field mappings (raw source -> CEP, per client/domain)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS qradar_field_mappings (
    mapping_id          TEXT PRIMARY KEY,
    client_id           TEXT NOT NULL REFERENCES clients(client_id),
    domain_id           TEXT NOT NULL REFERENCES qradar_domains(domain_id),
    raw_source_field    TEXT NOT NULL,
    target_cep_field    TEXT NOT NULL,
    semantic_alias      TEXT,
    applicable_dsm      TEXT,
    applicable_event    TEXT,
    mapping_version     TEXT NOT NULL DEFAULT '1',
    origin              TEXT NOT NULL DEFAULT 'manual'
        CHECK (origin IN ('auto','manual','imported')),
    created_at          TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (client_id, domain_id, raw_source_field, target_cep_field, mapping_version)
);
CREATE INDEX IF NOT EXISTS idx_qradar_field_mappings_client ON qradar_field_mappings(client_id);
CREATE INDEX IF NOT EXISTS idx_qradar_field_mappings_domain ON qradar_field_mappings(domain_id);

-- ---------------------------------------------------------------------------
-- Field observations / verification per client
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS qradar_field_observations (
    observation_id          TEXT PRIMARY KEY,
    client_id               TEXT NOT NULL REFERENCES clients(client_id),
    domain_id               TEXT NOT NULL REFERENCES qradar_domains(domain_id),
    field_id                TEXT NOT NULL REFERENCES qradar_field_definitions(field_id),
    field_present_in_raw    INTEGER NOT NULL DEFAULT 0 CHECK (field_present_in_raw IN (0,1)),
    qradar_property_displayed INTEGER NOT NULL DEFAULT 0 CHECK (qradar_property_displayed IN (0,1)),
    extracted_value_present INTEGER NOT NULL DEFAULT 0 CHECK (extracted_value_present IN (0,1)),
    aql_verification_status TEXT NOT NULL DEFAULT 'UNVERIFIED'
        CHECK (aql_verification_status IN ('VERIFIED','UNVERIFIED','UNVERIFIABLE')),
    verification_timestamp  TEXT,
    verified_by             TEXT REFERENCES users(user_id),
    evidence_reference      TEXT,
    created_at              TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qradar_field_observations_client ON qradar_field_observations(client_id);
CREATE INDEX IF NOT EXISTS idx_qradar_field_observations_field ON qradar_field_observations(field_id);

-- ---------------------------------------------------------------------------
-- Import batches (staged import: UPLOAD -> PARSE -> REDACT -> MAP -> REVIEW -> PUBLISH)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS qradar_import_batches (
    batch_id            TEXT PRIMARY KEY,
    client_id           TEXT NOT NULL REFERENCES clients(client_id),
    domain_id           TEXT NOT NULL REFERENCES qradar_domains(domain_id),
    batch_name          TEXT NOT NULL,
    source_type         TEXT NOT NULL
        CHECK (source_type IN ('csv','json','jsonl','txt','custom_export','windows_kev','iis')),
    file_hash           TEXT NOT NULL,
    imported_by         TEXT NOT NULL REFERENCES users(user_id),
    processing_status   TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (processing_status IN ('PENDING','PARSED','REDACTED','MAPPED','REVIEWED','PUBLISHED','FAILED','REJECTED')),
    redaction_result    TEXT,
    parse_warnings      TEXT,
    import_errors       TEXT,
    created_at          TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    published_at        TEXT
);
CREATE INDEX IF NOT EXISTS idx_qradar_import_batches_client ON qradar_import_batches(client_id);
CREATE INDEX IF NOT EXISTS idx_qradar_import_batches_domain ON qradar_import_batches(domain_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_qradar_import_batches_file_hash
    ON qradar_import_batches(client_id, file_hash);

-- ---------------------------------------------------------------------------
-- Import rows (individual parsed rows from an import batch)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS qradar_import_rows (
    row_id          TEXT PRIMARY KEY,
    batch_id        TEXT NOT NULL REFERENCES qradar_import_batches(batch_id),
    row_number      INTEGER NOT NULL,
    raw_line        TEXT,
    parsed_json     TEXT,
    parse_error     TEXT,
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (batch_id, row_number)
);
CREATE INDEX IF NOT EXISTS idx_qradar_import_rows_batch ON qradar_import_rows(batch_id);

-- ---------------------------------------------------------------------------
-- Import field map (discovered field mappings during import)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS qradar_import_field_map (
    map_id            TEXT PRIMARY KEY,
    batch_id          TEXT NOT NULL REFERENCES qradar_import_batches(batch_id),
    raw_field_name    TEXT NOT NULL,
    normalized_field_name TEXT,
    suggested_cep_field TEXT,
    mapping_confidence  TEXT,
    created_at          TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qradar_import_field_map_batch ON qradar_import_field_map(batch_id);

-- ---------------------------------------------------------------------------
-- Tenant consistency: client taken from the domain's instance chain, because
-- qradar_domains carries no client_id of its own.
-- ---------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS trg_qradar_import_batch_client_match
BEFORE INSERT ON qradar_import_batches
BEGIN
    SELECT RAISE(ABORT, 'import batch client mismatch')
    WHERE NOT EXISTS (
        SELECT 1 FROM qradar_domains d JOIN qradar_instances i ON i.instance_id = d.instance_id
        WHERE d.domain_id = NEW.domain_id AND i.client_id = NEW.client_id
    );
END;

-- Field definition client consistency
CREATE TRIGGER IF NOT EXISTS trg_qradar_field_definition_client_match
BEFORE INSERT ON qradar_field_definitions
BEGIN
    SELECT RAISE(ABORT, 'field definition client mismatch')
    WHERE NOT EXISTS (
        SELECT 1 FROM qradar_domains d JOIN qradar_instances i ON i.instance_id = d.instance_id
        WHERE d.domain_id = NEW.domain_id AND i.client_id = NEW.client_id
    );
END;

-- Field observation client consistency
CREATE TRIGGER IF NOT EXISTS trg_qradar_field_observation_client_match
BEFORE INSERT ON qradar_field_observations
BEGIN
    SELECT RAISE(ABORT, 'field observation client mismatch')
    WHERE NOT EXISTS (
        SELECT 1 FROM qradar_field_definitions f
        JOIN qradar_domains d ON d.domain_id = f.domain_id
        JOIN qradar_instances i ON i.instance_id = d.instance_id
        WHERE f.field_id = NEW.field_id AND f.client_id = NEW.client_id
          AND f.domain_id = NEW.domain_id AND i.client_id = NEW.client_id
    );
END;

-- Field mapping client consistency
CREATE TRIGGER IF NOT EXISTS trg_qradar_field_mapping_client_match
BEFORE INSERT ON qradar_field_mappings
BEGIN
    SELECT RAISE(ABORT, 'field mapping client mismatch')
    WHERE NOT EXISTS (
        SELECT 1 FROM qradar_domains d JOIN qradar_instances i ON i.instance_id = d.instance_id
        WHERE d.domain_id = NEW.domain_id AND i.client_id = NEW.client_id
    );
END;
