-- Migration 0001: Initial schema
-- MSSP Intelligence Workbench
-- SQLite WAL mode, foreign keys enabled, transactional writes

PRAGMA foreign_keys = ON;

-- Identity and MSSP
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'READ_ONLY',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS roles (
    role_id TEXT PRIMARY KEY,
    role_name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS permissions (
    permission_id TEXT PRIMARY KEY,
    permission_name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL REFERENCES users(user_id),
    role_id TEXT NOT NULL REFERENCES roles(role_id),
    assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    assigned_by TEXT REFERENCES users(user_id),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sectors (
    sector_id TEXT PRIMARY KEY,
    sector_name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS client_sector_mapping (
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    sector_id TEXT NOT NULL REFERENCES sectors(sector_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (client_id, sector_id)
);

CREATE TABLE IF NOT EXISTS client_technologies (
    tech_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    technology_name TEXT NOT NULL,
    category TEXT,
    version TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Telemetry and Detection (global)
CREATE TABLE IF NOT EXISTS log_source_types (
    log_source_type_id TEXT PRIMARY KEY,
    type_name TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS client_log_source_status (
    status_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    log_source_type_id TEXT NOT NULL REFERENCES log_source_types(log_source_type_id),
    connection_status TEXT NOT NULL DEFAULT 'UNKNOWN'
        CHECK (connection_status IN ('CONNECTED','NOT_CONNECTED','NO_RECENT_EVENTS','UNKNOWN')),
    last_event_timestamp TEXT,
    event_volume_status TEXT,
    field_availability TEXT,
    last_checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS global_fields (
    field_id TEXT PRIMARY KEY,
    field_name TEXT NOT NULL,
    field_type TEXT NOT NULL,
    field_description TEXT,
    source_type TEXT,
    normalized_name TEXT,
    aliases TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS field_mappings (
    mapping_id TEXT PRIMARY KEY,
    source_field_name TEXT NOT NULL,
    normalized_field_id TEXT NOT NULL REFERENCES global_fields(field_id),
    mapping_rule TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id TEXT PRIMARY KEY,
    rule_name TEXT NOT NULL,
    rule_description TEXT,
    rule_type TEXT,
    mitre_tactics TEXT,
    mitre_techniques TEXT,
    required_fields TEXT,
    required_log_sources TEXT,
    rule_status TEXT,
    rule_version TEXT,
    last_updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rule_field_requirements (
    requirement_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL REFERENCES detection_rules(rule_id),
    field_id TEXT NOT NULL REFERENCES global_fields(field_id),
    is_required INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mitre_mappings (
    mapping_id TEXT PRIMARY KEY,
    mitre_technique_id TEXT NOT NULL,
    mitre_tactic TEXT,
    technique_name TEXT,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CTI
CREATE TABLE IF NOT EXISTS cti_sources (
    source_id TEXT PRIMARY KEY,
    source_name TEXT NOT NULL,
    source_type TEXT,
    reliability_rating TEXT CHECK (reliability_rating IN ('A','B','C','D','E','F')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cti_reports (
    report_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    source_id TEXT REFERENCES cti_sources(source_id),
    title TEXT NOT NULL,
    author TEXT,
    publication_date TEXT,
    collection_date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'NEW'
        CHECK (status IN ('NEW','INGESTED','NORMALIZED','ANALYSIS_PENDING','ANALYZED','QUALITY_REVIEW','APPROVED','REJECTED','ARCHIVED')),
    original_content_ref TEXT,
    checksum TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cti_claims (
    claim_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES cti_reports(report_id),
    claim_text TEXT NOT NULL,
    source_reference TEXT,
    reliability_rating TEXT CHECK (reliability_rating IN ('A','B','C','D','E','F')),
    credibility_rating TEXT CHECK (credibility_rating IN ('1','2','3','4','5','6')),
    assessment_reason TEXT,
    assessed_by TEXT REFERENCES users(user_id),
    assessment_date TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS indicators (
    indicator_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES cti_reports(report_id),
    indicator_type TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    confidence TEXT,
    source_reference TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threat_actors (
    actor_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES cti_reports(report_id),
    actor_name TEXT NOT NULL,
    aliases TEXT,
    motivation TEXT,
    sophistication TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES cti_reports(report_id),
    campaign_name TEXT NOT NULL,
    actor_id TEXT REFERENCES threat_actors(actor_id),
    start_date TEXT,
    end_date TEXT,
    objectives TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS malware (
    malware_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES cti_reports(report_id),
    malware_name TEXT NOT NULL,
    family TEXT,
    type TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES cti_reports(report_id),
    cve_id_text TEXT NOT NULL,
    description TEXT,
    severity TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS techniques (
    technique_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES cti_reports(report_id),
    mitre_technique_id TEXT,
    mitre_tactic TEXT,
    technique_name TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admiralty_assessments (
    assessment_id TEXT PRIMARY KEY,
    source_id TEXT REFERENCES cti_sources(source_id),
    claim_id TEXT REFERENCES cti_claims(claim_id),
    reliability_rating TEXT CHECK (reliability_rating IN ('A','B','C','D','E','F')),
    credibility_rating TEXT CHECK (credibility_rating IN ('1','2','3','4','5','6')),
    assessment_reason TEXT,
    assessed_by TEXT REFERENCES users(user_id),
    assessment_date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Adversary Brain
CREATE TABLE IF NOT EXISTS adversary_brains (
    brain_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    actor_name TEXT NOT NULL,
    campaign_name TEXT,
    description TEXT,
    version TEXT NOT NULL DEFAULT '1.0',
    status TEXT NOT NULL DEFAULT 'draft',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS brain_versions (
    version_id TEXT PRIMARY KEY,
    brain_id TEXT NOT NULL REFERENCES adversary_brains(brain_id),
    version_number TEXT NOT NULL,
    change_summary TEXT,
    approved_by TEXT REFERENCES users(user_id),
    approved_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS brain_sources (
    source_id TEXT PRIMARY KEY,
    brain_id TEXT NOT NULL REFERENCES adversary_brains(brain_id),
    source_ref TEXT NOT NULL,
    source_type TEXT,
    provenance TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS brain_hypotheses (
    hypothesis_id TEXT PRIMARY KEY,
    brain_id TEXT NOT NULL REFERENCES adversary_brains(brain_id),
    hypothesis_text TEXT NOT NULL,
    supporting_evidence TEXT,
    contradicting_evidence TEXT,
    status TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS brain_observables (
    observable_id TEXT PRIMARY KEY,
    brain_id TEXT NOT NULL REFERENCES adversary_brains(brain_id),
    observable_type TEXT NOT NULL,
    observable_value TEXT NOT NULL,
    confidence TEXT,
    source_ref TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS brain_relationships (
    relationship_id TEXT PRIMARY KEY,
    brain_id TEXT NOT NULL REFERENCES adversary_brains(brain_id),
    source_entity TEXT NOT NULL,
    relationship_type TEXT NOT NULL
        CHECK (relationship_type IN ('USES','TARGETS','ASSOCIATED_WITH','EXPLOITS','COMMUNICATES_WITH','OBSERVED_IN','RELATED_TO')),
    target_entity TEXT NOT NULL,
    evidence_ref TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS brain_evidence (
    evidence_id TEXT PRIMARY KEY,
    brain_id TEXT NOT NULL REFERENCES adversary_brains(brain_id),
    evidence_type TEXT NOT NULL,
    evidence_ref TEXT NOT NULL,
    confidence TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS brain_assessments (
    assessment_id TEXT PRIMARY KEY,
    brain_id TEXT NOT NULL REFERENCES adversary_brains(brain_id),
    assessed_by TEXT REFERENCES users(user_id),
    assessment_date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    confidence TEXT,
    conclusion TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Hunting
CREATE TABLE IF NOT EXISTS hunt_hypotheses (
    hypothesis_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    threat_actor TEXT,
    campaign TEXT,
    adversary_brain_id TEXT REFERENCES adversary_brains(brain_id),
    sector TEXT,
    mitre_tactics TEXT,
    mitre_techniques TEXT,
    expected_behavior TEXT,
    required_log_sources TEXT,
    required_fields TEXT,
    existing_detection_rules TEXT,
    coverage_status TEXT CHECK (coverage_status IN ('COVERED','PARTIAL','NOT_COVERED','UNKNOWN')),
    evidence TEXT,
    supporting_evidence TEXT,
    contradicting_evidence TEXT,
    assumptions TEXT,
    limitations TEXT,
    confidence TEXT,
    priority TEXT,
    status TEXT NOT NULL DEFAULT 'GENERATED'
        CHECK (status IN ('GENERATED','QUALITY_CHECK','PENDING_REVIEW','APPROVED','REJECTED','NEEDS_MORE_DATA','INVESTIGATION','CLOSED')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hypothesis_evidence (
    evidence_id TEXT PRIMARY KEY,
    hypothesis_id TEXT NOT NULL REFERENCES hunt_hypotheses(hypothesis_id),
    evidence_type TEXT NOT NULL,
    evidence_ref TEXT NOT NULL,
    source TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hypothesis_reviews (
    review_id TEXT PRIMARY KEY,
    hypothesis_id TEXT NOT NULL REFERENCES hunt_hypotheses(hypothesis_id),
    reviewer_id TEXT NOT NULL REFERENCES users(user_id),
    decision TEXT NOT NULL CHECK (decision IN ('APPROVED','REJECTED','NEEDS_MORE_DATA')),
    reason TEXT NOT NULL,
    reviewed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS investigations (
    investigation_id TEXT PRIMARY KEY,
    hypothesis_id TEXT NOT NULL REFERENCES hunt_hypotheses(hypothesis_id),
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    time_range TEXT,
    evidence TEXT,
    analyst_findings TEXT,
    final_verdict TEXT CHECK (final_verdict IN ('TRUE_POSITIVE','FALSE_POSITIVE','INCONCLUSIVE','NEEDS_MORE_DATA')),
    verdict_reason TEXT,
    mitigation_notes TEXT,
    analyst_id TEXT NOT NULL REFERENCES users(user_id),
    review_timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS investigation_evidence (
    evidence_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id),
    evidence_type TEXT NOT NULL,
    evidence_ref TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS investigation_feedback (
    feedback_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id),
    feedback_type TEXT NOT NULL,
    feedback_content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- AI and Harness
CREATE TABLE IF NOT EXISTS harness_registry (
    agent_id TEXT PRIMARY KEY,
    agent_name TEXT NOT NULL,
    harness_type TEXT NOT NULL,
    integration_type TEXT,
    endpoint TEXT,
    version TEXT,
    status TEXT,
    capabilities TEXT,
    allowed_clients TEXT,
    allowed_tools TEXT,
    permission_profile TEXT DEFAULT 'READ_ONLY',
    trust_level TEXT DEFAULT 'unverified',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TEXT
);

CREATE TABLE IF NOT EXISTS harness_capabilities (
    capability_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES harness_registry(agent_id),
    capability_name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS harness_permissions (
    permission_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES harness_registry(agent_id),
    permission_name TEXT NOT NULL,
    allowed_clients TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ai_tasks (
    task_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    task_type TEXT NOT NULL,
    priority TEXT,
    input TEXT,
    expected_output TEXT,
    human_review_required INTEGER NOT NULL DEFAULT 1,
    status TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ai_executions (
    execution_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES ai_tasks(task_id),
    harness_id TEXT NOT NULL REFERENCES harness_registry(agent_id),
    model_provider TEXT,
    model_name TEXT,
    prompt_version TEXT,
    workflow_version TEXT,
    input_reference TEXT,
    output_reference TEXT,
    start_time TEXT,
    end_time TEXT,
    status TEXT,
    error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ai_execution_events (
    event_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL REFERENCES ai_executions(execution_id),
    event_type TEXT NOT NULL,
    event_data TEXT,
    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ai_results (
    result_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL REFERENCES ai_executions(execution_id),
    result_data TEXT,
    sources TEXT,
    warnings TEXT,
    errors TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ai_runs (
    run_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES ai_tasks(task_id),
    run_number INTEGER NOT NULL,
    status TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- System
CREATE TABLE IF NOT EXISTS audit_log (
    event_id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(user_id),
    agent_id TEXT REFERENCES harness_registry(agent_id),
    client_id TEXT REFERENCES clients(client_id),
    action TEXT NOT NULL,
    resource TEXT,
    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    result TEXT,
    source_ip TEXT,
    correlation_id TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS system_settings (
    setting_id TEXT PRIMARY KEY,
    setting_key TEXT NOT NULL UNIQUE,
    setting_value TEXT,
    description TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS import_jobs (
    import_id TEXT PRIMARY KEY,
    import_type TEXT NOT NULL,
    status TEXT NOT NULL,
    file_ref TEXT,
    error_log TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS file_artifacts (
    artifact_id TEXT PRIMARY KEY,
    file_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    checksum TEXT NOT NULL,
    file_type TEXT,
    metadata_ref TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS knowledge_documents (
    doc_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    content TEXT,
    doc_type TEXT,
    client_id TEXT REFERENCES clients(client_id),
    version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS knowledge_versions (
    version_id TEXT PRIMARY KEY,
    doc_id TEXT NOT NULL REFERENCES knowledge_documents(doc_id),
    version_number TEXT NOT NULL,
    change_summary TEXT,
    approved_by TEXT REFERENCES users(user_id),
    approved_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_cti_reports_client_status ON cti_reports(client_id, status);
CREATE INDEX IF NOT EXISTS idx_hunt_hypotheses_client_status ON hunt_hypotheses(client_id, status);
CREATE INDEX IF NOT EXISTS idx_indicators_report ON indicators(report_id);
CREATE INDEX IF NOT EXISTS idx_threat_actors_report ON threat_actors(report_id);
CREATE INDEX IF NOT EXISTS idx_campaigns_report ON campaigns(report_id);
CREATE INDEX IF NOT EXISTS idx_techniques_report ON techniques(report_id);
CREATE INDEX IF NOT EXISTS idx_ai_executions_harness ON ai_executions(harness_id, status);
CREATE INDEX IF NOT EXISTS idx_ai_executions_task ON ai_executions(task_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_client_ts ON audit_log(client_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action, timestamp);
CREATE INDEX IF NOT EXISTS idx_client_log_source ON client_log_source_status(client_id, log_source_type_id);
CREATE INDEX IF NOT EXISTS idx_brain_relationships ON brain_relationships(brain_id);
CREATE INDEX IF NOT EXISTS idx_hypothesis_reviews ON hypothesis_reviews(hypothesis_id);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);