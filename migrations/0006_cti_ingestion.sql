-- Migration 0006_cti_ingestion.sql
-- M7-A: CTI Ingestion & Provenance (additive; no existing table modified
-- except planner-safe unique indexes and a few new columns on indicators).

PRAGMA foreign_keys = ON;

-- 1. Document identity: tenant-scoped content dedup on cti_reports.
-- client_id is in the key: identical bytes for alpha and beta stay distinct.
CREATE UNIQUE INDEX IF NOT EXISTS idx_cti_reports_dedup_src
    ON cti_reports(client_id, checksum, source_id) WHERE source_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_cti_reports_dedup_nosrc
    ON cti_reports(client_id, checksum) WHERE source_id IS NULL;

-- 2. Ingestion attempt history (runs are attempts: NO document-level UNIQUE here).
CREATE TABLE IF NOT EXISTS cti_ingestion_runs (
    run_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES cti_reports(report_id),
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    status TEXT NOT NULL CHECK (status IN ('PENDING','INGESTED','ANALYZING','ANALYZED','FAILED')),
    parser_version TEXT NOT NULL DEFAULT '1',
    request_idempotency_key TEXT,
    payload_fingerprint TEXT,
    error_code TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- Database-enforced HTTP idempotency: unique per (client, key).
-- Same key regardless of payload fingerprint occupies one operation row;
-- Go compares the stored fingerprint and returns 409 on mismatch.
CREATE UNIQUE INDEX IF NOT EXISTS idx_cti_runs_request_unique
    ON cti_ingestion_runs(client_id, request_idempotency_key)
    WHERE request_idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cti_ingestion_runs_client
    ON cti_ingestion_runs(client_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cti_ingestion_runs_report
    ON cti_ingestion_runs(report_id);

-- 3. Extraction attempt membership (per entity_type triggers below).
CREATE TABLE IF NOT EXISTS cti_extraction_results (
    result_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES cti_ingestion_runs(run_id),
    report_id TEXT NOT NULL REFERENCES cti_reports(report_id),
    entity_type TEXT NOT NULL CHECK (entity_type IN ('indicator','technique','cve','claim','threat_actor','campaign','malware')),
    entity_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (run_id, entity_type, entity_id)
);
CREATE INDEX IF NOT EXISTS idx_cti_extraction_results_report
    ON cti_extraction_results(report_id, entity_type);

-- 4. Lossless IOC normalization columns (originals untouched).
ALTER TABLE indicators ADD COLUMN normalized_value TEXT;
ALTER TABLE indicators ADD COLUMN normalization_rule TEXT;
ALTER TABLE indicators ADD COLUMN normalization_version TEXT;

-- 4b. Explicit report->artifact association (replaces metadata_ref/filename lookups).
ALTER TABLE cti_reports ADD COLUMN artifact_id TEXT REFERENCES file_artifacts(artifact_id);

-- 5. Content dedup on extraction tables (re-analysis never duplicates).
CREATE UNIQUE INDEX IF NOT EXISTS idx_indicators_dedup
    ON indicators(report_id, indicator_type, indicator_value);
CREATE UNIQUE INDEX IF NOT EXISTS idx_techniques_dedup
    ON techniques(report_id, mitre_technique_id, technique_name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cves_dedup
    ON cves(report_id, cve_id_text);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cti_claims_dedup
    ON cti_claims(report_id, claim_text);
CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_actors_dedup
    ON threat_actors(report_id, actor_name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_campaigns_dedup
    ON campaigns(report_id, campaign_name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_malware_dedup
    ON malware(report_id, malware_name);

-- 6. Extraction membership integrity: one trigger per entity_type.
-- (SQLite cannot express a polymorphic FK across 7 tables.)
CREATE TRIGGER IF NOT EXISTS trg_extraction_indicator_match
BEFORE INSERT ON cti_extraction_results
BEGIN
    SELECT RAISE(ABORT, 'entity report mismatch')
    WHERE NEW.entity_type = 'indicator' AND NOT EXISTS (
        SELECT 1 FROM indicators
        WHERE indicator_id = NEW.entity_id AND report_id = NEW.report_id
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_extraction_technique_match
BEFORE INSERT ON cti_extraction_results
BEGIN
    SELECT RAISE(ABORT, 'entity report mismatch')
    WHERE NEW.entity_type = 'technique' AND NOT EXISTS (
        SELECT 1 FROM techniques
        WHERE technique_id = NEW.entity_id AND report_id = NEW.report_id
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_extraction_cve_match
BEFORE INSERT ON cti_extraction_results
BEGIN
    SELECT RAISE(ABORT, 'entity report mismatch')
    WHERE NEW.entity_type = 'cve' AND NOT EXISTS (
        SELECT 1 FROM cves
        WHERE cve_id = NEW.entity_id AND report_id = NEW.report_id
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_extraction_claim_match
BEFORE INSERT ON cti_extraction_results
BEGIN
    SELECT RAISE(ABORT, 'entity report mismatch')
    WHERE NEW.entity_type = 'claim' AND NOT EXISTS (
        SELECT 1 FROM cti_claims
        WHERE claim_id = NEW.entity_id AND report_id = NEW.report_id
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_extraction_threat_actor_match
BEFORE INSERT ON cti_extraction_results
BEGIN
    SELECT RAISE(ABORT, 'entity report mismatch')
    WHERE NEW.entity_type = 'threat_actor' AND NOT EXISTS (
        SELECT 1 FROM threat_actors
        WHERE actor_id = NEW.entity_id AND report_id = NEW.report_id
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_extraction_campaign_match
BEFORE INSERT ON cti_extraction_results
BEGIN
    SELECT RAISE(ABORT, 'entity report mismatch')
    WHERE NEW.entity_type = 'campaign' AND NOT EXISTS (
        SELECT 1 FROM campaigns
        WHERE campaign_id = NEW.entity_id AND report_id = NEW.report_id
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_extraction_malware_match
BEFORE INSERT ON cti_extraction_results
BEGIN
    SELECT RAISE(ABORT, 'entity report mismatch')
    WHERE NEW.entity_type = 'malware' AND NOT EXISTS (
        SELECT 1 FROM malware
        WHERE malware_id = NEW.entity_id AND report_id = NEW.report_id
    );
END;

-- Run must belong to the same client as its report (tenant consistency).
CREATE TRIGGER IF NOT EXISTS trg_ingestion_run_client_match
BEFORE INSERT ON cti_ingestion_runs
BEGIN
    SELECT RAISE(ABORT, 'run client mismatch')
    WHERE NOT EXISTS (
        SELECT 1 FROM cti_reports
        WHERE report_id = NEW.report_id AND client_id = NEW.client_id
    );
END;

-- Extraction membership: run's report must equal membership's report.
CREATE TRIGGER IF NOT EXISTS trg_extraction_run_report_match
BEFORE INSERT ON cti_extraction_results
BEGIN
    SELECT RAISE(ABORT, 'run report mismatch')
    WHERE NOT EXISTS (
        SELECT 1 FROM cti_ingestion_runs
        WHERE run_id = NEW.run_id AND report_id = NEW.report_id
    );
END;
