-- 0022_manual_inventory_provenance.sql
-- M7-F Phase 1: provenance for manually entered or imported QRadar metadata.
-- Additive only; 0001-0021 are not rewritten. No second inventory registry: the
-- existing tables gain provenance columns and an append-only revision log.

ALTER TABLE qradar_instances ADD COLUMN source_category TEXT NOT NULL DEFAULT 'MANUAL';
ALTER TABLE qradar_instances ADD COLUMN source_reference TEXT;
ALTER TABLE qradar_instances ADD COLUMN entered_by TEXT REFERENCES users(user_id);
ALTER TABLE qradar_instances ADD COLUMN entered_at TEXT;
ALTER TABLE qradar_instances ADD COLUMN revision INTEGER NOT NULL DEFAULT 1;

ALTER TABLE qradar_domains ADD COLUMN source_category TEXT NOT NULL DEFAULT 'MANUAL';
ALTER TABLE qradar_domains ADD COLUMN source_reference TEXT;
ALTER TABLE qradar_domains ADD COLUMN entered_by TEXT REFERENCES users(user_id);
ALTER TABLE qradar_domains ADD COLUMN entered_at TEXT;
ALTER TABLE qradar_domains ADD COLUMN revision INTEGER NOT NULL DEFAULT 1;

ALTER TABLE qradar_log_source_types ADD COLUMN source_category TEXT NOT NULL DEFAULT 'MANUAL';
ALTER TABLE qradar_log_source_types ADD COLUMN source_reference TEXT;
ALTER TABLE qradar_log_source_types ADD COLUMN entered_by TEXT REFERENCES users(user_id);
ALTER TABLE qradar_log_source_types ADD COLUMN entered_at TEXT;
ALTER TABLE qradar_log_source_types ADD COLUMN revision INTEGER NOT NULL DEFAULT 1;

ALTER TABLE qradar_log_sources ADD COLUMN source_category TEXT NOT NULL DEFAULT 'MANUAL';
ALTER TABLE qradar_log_sources ADD COLUMN source_reference TEXT;
ALTER TABLE qradar_log_sources ADD COLUMN entered_by TEXT REFERENCES users(user_id);
ALTER TABLE qradar_log_sources ADD COLUMN entered_at TEXT;
ALTER TABLE qradar_log_sources ADD COLUMN revision INTEGER NOT NULL DEFAULT 1;

ALTER TABLE qradar_qids ADD COLUMN source_category TEXT NOT NULL DEFAULT 'MANUAL';
ALTER TABLE qradar_qids ADD COLUMN source_reference TEXT;
ALTER TABLE qradar_qids ADD COLUMN entered_by TEXT REFERENCES users(user_id);
ALTER TABLE qradar_qids ADD COLUMN entered_at TEXT;
ALTER TABLE qradar_qids ADD COLUMN revision INTEGER NOT NULL DEFAULT 1;

ALTER TABLE qradar_field_definitions ADD COLUMN source_category TEXT NOT NULL DEFAULT 'MANUAL';
ALTER TABLE qradar_field_definitions ADD COLUMN source_reference TEXT;
ALTER TABLE qradar_field_definitions ADD COLUMN entered_by TEXT REFERENCES users(user_id);
ALTER TABLE qradar_field_definitions ADD COLUMN entered_at TEXT;
ALTER TABLE qradar_field_definitions ADD COLUMN revision INTEGER NOT NULL DEFAULT 1;

ALTER TABLE qradar_field_mappings ADD COLUMN source_category TEXT NOT NULL DEFAULT 'MANUAL';
ALTER TABLE qradar_field_mappings ADD COLUMN source_reference TEXT;
ALTER TABLE qradar_field_mappings ADD COLUMN entered_by TEXT REFERENCES users(user_id);
ALTER TABLE qradar_field_mappings ADD COLUMN entered_at TEXT;
ALTER TABLE qradar_field_mappings ADD COLUMN revision INTEGER NOT NULL DEFAULT 1;

ALTER TABLE qradar_field_observations ADD COLUMN source_category TEXT NOT NULL DEFAULT 'MANUAL';
ALTER TABLE qradar_field_observations ADD COLUMN source_reference TEXT;
ALTER TABLE qradar_field_observations ADD COLUMN entered_by TEXT REFERENCES users(user_id);
ALTER TABLE qradar_field_observations ADD COLUMN entered_at TEXT;
ALTER TABLE qradar_field_observations ADD COLUMN revision INTEGER NOT NULL DEFAULT 1;

-- Append-only revision log. Every inserted inventory row produces one entry from
-- the database itself, so manual and imported values share the same provenance
-- and a crash cannot separate the value from its revision record.
CREATE TABLE IF NOT EXISTS qradar_inventory_revisions (
    revision_id      TEXT PRIMARY KEY,
    entity_type      TEXT NOT NULL CHECK (entity_type IN
        ('instance','domain','log_source_type','log_source','qid','field_definition','field_mapping','field_observation')),
    entity_id        TEXT NOT NULL,
    client_id        TEXT,
    domain_id        TEXT,
    revision         INTEGER NOT NULL,
    snapshot_json    TEXT NOT NULL,
    source_category  TEXT NOT NULL CHECK (source_category IN ('MANUAL','IMPORTED_UNVERIFIED','REVIEWED','SYSTEM')),
    source_reference TEXT,
    entered_by       TEXT,
    entered_at       TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    review_status    TEXT NOT NULL DEFAULT 'UNREVIEWED' CHECK (review_status IN ('UNREVIEWED','REVIEWED','REJECTED')),
    reviewer         TEXT,
    reviewed_at      TEXT,
    evidence_reference TEXT
);
CREATE INDEX IF NOT EXISTS idx_inventory_revisions_entity ON qradar_inventory_revisions(entity_type, entity_id, revision);
CREATE INDEX IF NOT EXISTS idx_inventory_revisions_client ON qradar_inventory_revisions(client_id, entered_at);

CREATE TRIGGER IF NOT EXISTS trg_inventory_revisions_no_update
BEFORE UPDATE ON qradar_inventory_revisions
BEGIN SELECT RAISE(ABORT, 'inventory revisions are immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_inventory_revisions_no_delete
BEFORE DELETE ON qradar_inventory_revisions
BEGIN SELECT RAISE(ABORT, 'inventory revisions are immutable'); END;

-- One AFTER INSERT trigger per inventory table. The value and its provenance
-- revision commit or roll back together.
CREATE TRIGGER IF NOT EXISTS trg_inventory_rev_instance AFTER INSERT ON qradar_instances
BEGIN
    INSERT INTO qradar_inventory_revisions
        (revision_id, entity_type, entity_id, client_id, domain_id, revision, snapshot_json,
         source_category, source_reference, entered_by, entered_at)
    VALUES ('rev-' || lower(hex(randomblob(8))), 'instance', NEW.instance_id, NEW.client_id, NULL, NEW.revision,
        json_object('instance_name', NEW.instance_name, 'host', COALESCE(NEW.host,'')),
        NEW.source_category, NEW.source_reference, NEW.entered_by, COALESCE(NEW.entered_at, NEW.created_at));
END;

CREATE TRIGGER IF NOT EXISTS trg_inventory_rev_domain AFTER INSERT ON qradar_domains
BEGIN
    INSERT INTO qradar_inventory_revisions
        (revision_id, entity_type, entity_id, client_id, domain_id, revision, snapshot_json,
         source_category, source_reference, entered_by, entered_at)
    VALUES ('rev-' || lower(hex(randomblob(8))), 'domain', NEW.domain_id, NULL, NEW.domain_id, NEW.revision,
        json_object('domain_name', NEW.domain_name, 'domain_type', COALESCE(NEW.domain_type,''), 'instance_id', NEW.instance_id),
        NEW.source_category, NEW.source_reference, NEW.entered_by, COALESCE(NEW.entered_at, NEW.created_at));
END;

CREATE TRIGGER IF NOT EXISTS trg_inventory_rev_log_source_type AFTER INSERT ON qradar_log_source_types
BEGIN
    INSERT INTO qradar_inventory_revisions
        (revision_id, entity_type, entity_id, client_id, domain_id, revision, snapshot_json,
         source_category, source_reference, entered_by, entered_at)
    VALUES ('rev-' || lower(hex(randomblob(8))), 'log_source_type', NEW.log_source_type_id, NULL, NEW.domain_id, NEW.revision,
        json_object('type_name', NEW.type_name),
        NEW.source_category, NEW.source_reference, NEW.entered_by, COALESCE(NEW.entered_at, NEW.created_at));
END;

CREATE TRIGGER IF NOT EXISTS trg_inventory_rev_log_source AFTER INSERT ON qradar_log_sources
BEGIN
    INSERT INTO qradar_inventory_revisions
        (revision_id, entity_type, entity_id, client_id, domain_id, revision, snapshot_json,
         source_category, source_reference, entered_by, entered_at)
    VALUES ('rev-' || lower(hex(randomblob(8))), 'log_source', NEW.log_source_id, NULL,
        (SELECT domain_id FROM qradar_log_source_types WHERE log_source_type_id = NEW.log_source_type_id), NEW.revision,
        json_object('log_source_type_id', NEW.log_source_type_id, 'status', NEW.status, 'data_provenance', COALESCE(NEW.data_provenance,'')),
        NEW.source_category, NEW.source_reference, NEW.entered_by, COALESCE(NEW.entered_at, NEW.created_at));
END;

CREATE TRIGGER IF NOT EXISTS trg_inventory_rev_qid AFTER INSERT ON qradar_qids
BEGIN
    INSERT INTO qradar_inventory_revisions
        (revision_id, entity_type, entity_id, client_id, domain_id, revision, snapshot_json,
         source_category, source_reference, entered_by, entered_at)
    VALUES ('rev-' || lower(hex(randomblob(8))), 'qid', NEW.qid, NULL,
        (SELECT t.domain_id FROM qradar_log_sources s JOIN qradar_log_source_types t ON t.log_source_type_id = s.log_source_type_id
          WHERE s.log_source_id = NEW.log_source_id), NEW.revision,
        json_object('log_source_id', NEW.log_source_id, 'event_name', NEW.event_name, 'native_event_id', COALESCE(NEW.native_event_id,'')),
        NEW.source_category, NEW.source_reference, NEW.entered_by, COALESCE(NEW.entered_at, NEW.created_at));
END;

CREATE TRIGGER IF NOT EXISTS trg_inventory_rev_field_definition AFTER INSERT ON qradar_field_definitions
BEGIN
    INSERT INTO qradar_inventory_revisions
        (revision_id, entity_type, entity_id, client_id, domain_id, revision, snapshot_json,
         source_category, source_reference, entered_by, entered_at)
    VALUES ('rev-' || lower(hex(randomblob(8))), 'field_definition', NEW.field_id, NEW.client_id, NEW.domain_id, NEW.revision,
        json_object('field_name', NEW.field_name, 'field_origin', NEW.field_origin, 'data_type', COALESCE(NEW.data_type,''),
                    'cep_identifier', COALESCE(NEW.cep_identifier,''), 'aql_field_expression', COALESCE(NEW.aql_field_expression,'')),
        NEW.source_category, NEW.source_reference, NEW.entered_by, COALESCE(NEW.entered_at, NEW.created_at));
END;

CREATE TRIGGER IF NOT EXISTS trg_inventory_rev_field_mapping AFTER INSERT ON qradar_field_mappings
BEGIN
    INSERT INTO qradar_inventory_revisions
        (revision_id, entity_type, entity_id, client_id, domain_id, revision, snapshot_json,
         source_category, source_reference, entered_by, entered_at)
    VALUES ('rev-' || lower(hex(randomblob(8))), 'field_mapping', NEW.mapping_id, NEW.client_id, NEW.domain_id, NEW.revision,
        json_object('raw_source_field', NEW.raw_source_field, 'target_cep_field', NEW.target_cep_field,
                    'applicable_dsm', COALESCE(NEW.applicable_dsm,''), 'applicable_event', COALESCE(NEW.applicable_event,''),
                    'mapping_version', NEW.mapping_version, 'origin', NEW.origin),
        NEW.source_category, NEW.source_reference, NEW.entered_by, COALESCE(NEW.entered_at, NEW.created_at));
END;

CREATE TRIGGER IF NOT EXISTS trg_inventory_rev_field_observation AFTER INSERT ON qradar_field_observations
BEGIN
    INSERT INTO qradar_inventory_revisions
        (revision_id, entity_type, entity_id, client_id, domain_id, revision, snapshot_json,
         source_category, source_reference, entered_by, entered_at)
    VALUES ('rev-' || lower(hex(randomblob(8))), 'field_observation', NEW.observation_id, NEW.client_id, NEW.domain_id, NEW.revision,
        json_object('field_id', NEW.field_id, 'aql_verification_status', NEW.aql_verification_status,
                    'verified_by', COALESCE(NEW.verified_by,''), 'evidence_reference', COALESCE(NEW.evidence_reference,'')),
        NEW.source_category, NEW.source_reference, NEW.entered_by, COALESCE(NEW.entered_at, NEW.created_at));
END;
