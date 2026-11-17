-- 0012_field_intel_hardening.sql
-- Forward migration for M7-D Phase 2A. Additive only: migration 0011 is already
-- applied in dev databases and is never rewritten.
--
-- Adds what the hardened import path and the review workflow need:
--   * a place for redacted payloads (raw client lines must never be stored)
--   * parser / redaction provenance per batch
--   * review + approval identity and time
--   * ambiguity and evidence metadata on candidate field maps
--   * approval metadata on approved field mappings

-- ---------------------------------------------------------------------------
-- Import batch: processing provenance and review identity
-- ---------------------------------------------------------------------------
ALTER TABLE qradar_import_batches ADD COLUMN parser_version TEXT;
ALTER TABLE qradar_import_batches ADD COLUMN redaction_version TEXT;
ALTER TABLE qradar_import_batches ADD COLUMN parsed_rows INTEGER NOT NULL DEFAULT 0;
ALTER TABLE qradar_import_batches ADD COLUMN rejected_rows INTEGER NOT NULL DEFAULT 0;
ALTER TABLE qradar_import_batches ADD COLUMN redacted_values INTEGER NOT NULL DEFAULT 0;
ALTER TABLE qradar_import_batches ADD COLUMN reviewed_by TEXT REFERENCES users(user_id);
ALTER TABLE qradar_import_batches ADD COLUMN reviewed_at TEXT;
ALTER TABLE qradar_import_batches ADD COLUMN reviewed_status TEXT
    CHECK (reviewed_status IS NULL OR reviewed_status IN ('APPROVED','REJECTED'));

-- ---------------------------------------------------------------------------
-- Import row: only redacted payloads are stored. raw_line stays for schema
-- compatibility and is intentionally left empty by the hardened path.
-- ---------------------------------------------------------------------------
ALTER TABLE qradar_import_rows ADD COLUMN redacted_line TEXT;
ALTER TABLE qradar_import_rows ADD COLUMN field_names TEXT;
ALTER TABLE qradar_import_rows ADD COLUMN field_types TEXT;

-- ---------------------------------------------------------------------------
-- Candidate mapping: ambiguity must be explicit, never inferred later
-- ---------------------------------------------------------------------------
ALTER TABLE qradar_import_field_map ADD COLUMN ambiguous INTEGER NOT NULL DEFAULT 0
    CHECK (ambiguous IN (0,1));
ALTER TABLE qradar_import_field_map ADD COLUMN evidence TEXT;
ALTER TABLE qradar_import_field_map ADD COLUMN parser_version TEXT;

-- ---------------------------------------------------------------------------
-- Approved mapping: who approved it, and which evidence backed it
-- ---------------------------------------------------------------------------
ALTER TABLE qradar_field_mappings ADD COLUMN approved_by TEXT REFERENCES users(user_id);
ALTER TABLE qradar_field_mappings ADD COLUMN approved_at TEXT;
ALTER TABLE qradar_field_mappings ADD COLUMN verification_mode TEXT
    CHECK (verification_mode IS NULL OR verification_mode IN ('MANUAL_ATTESTED','SYSTEM_VERIFIED'));
ALTER TABLE qradar_field_mappings ADD COLUMN evidence_reference TEXT;

CREATE INDEX IF NOT EXISTS idx_qradar_import_batches_status
    ON qradar_import_batches(client_id, processing_status);
