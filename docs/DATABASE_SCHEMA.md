# Database Schema — MSSP Intelligence Workbench

## Conventions (all tables)

- Primary key on every table
- Foreign keys where relationships exist
- Appropriate indexes on query columns
- `created_at` and `updated_at` timestamps
- Transactional writes
- Client-owned tables include `client_id` (tenant ownership)
- Global tables are NOT duplicated per client

## Identity and MSSP

**users** (global)
- user_id PK, username, email, password_hash, role, is_active, created_at, updated_at

**roles** (global)
- role_id PK, role_name, description, created_at

**permissions** (global)
- permission_id PK, permission_name, description, created_at

**user_roles** (global)
- user_id FK -> users, role_id FK -> roles, assigned_at, assigned_by

**clients** (tenant)
- client_id PK, client_name, sector, status, created_at, updated_at

**sectors** (global)
- sector_id PK, sector_name (ENERGY, FINANCE, GOVERNMENT, etc.), description, created_at

**client_sector_mapping** (tenant)
- client_id FK -> clients, sector_id FK -> sectors, created_at

**client_technologies** (tenant)
- tech_id PK, client_id FK -> clients, technology_name, category, version, created_at

## Telemetry and Detection (global — shared across clients)

**log_source_types** (global)
- log_source_type_id PK, type_name, description, created_at

**client_log_source_status** (tenant)
- status_id PK, client_id FK -> clients, log_source_type_id FK, connection_status
  (CONNECTED/NOT_CONNECTED/NO_RECENT_EVENTS/UNKNOWN), last_event_timestamp,
  event_volume_status, field_availability, last_checked_at

**global_fields** (global)
- field_id PK, field_name, field_type, field_description, source_type,
  normalized_name, aliases, is_active, created_at

**field_mappings** (global)
- mapping_id PK, source_field_name, normalized_field_id FK -> global_fields,
  mapping_rule, created_at

**detection_rules** (global)
- rule_id PK, rule_name, rule_description, rule_type, mitre_tactics, mitre_techniques,
  required_fields, required_log_sources, rule_status, rule_version, last_updated

**rule_field_requirements** (global)
- requirement_id PK, rule_id FK -> detection_rules, field_id FK -> global_fields,
  is_required, created_at

**mitre_mappings** (global)
- mapping_id PK, mitre_technique_id, mitre_tactic, technique_name, description,
  created_at

## CTI

**cti_sources** (global)
- source_id PK, source_name, source_type, reliability_rating (A-F), created_at

**cti_reports** (tenant)
- report_id PK, client_id FK -> clients, source_id FK -> cti_sources, title,
  author, publication_date, collection_date, status (NEW/INGESTED/NORMALIZED/
  ANALYSIS_PENDING/ANALYZED/QUALITY_REVIEW/APPROVED/REJECTED/ARCHIVED),
  original_content_ref, checksum, created_at, updated_at

**cti_claims** (tenant)
- claim_id PK, report_id FK -> cti_reports, claim_text, source_reference,
  reliability_rating, credibility_rating (1-6), assessment_reason,
  assessed_by, assessment_date, created_at

**indicators** (tenant)
- indicator_id PK, report_id FK -> cti_reports, indicator_type, indicator_value,
  confidence, source_reference, created_at

**threat_actors** (tenant)
- actor_id PK, report_id FK -> cti_reports, actor_name, aliases, motivation,
  sophistication, created_at

**campaigns** (tenant)
- campaign_id PK, report_id FK -> cti_reports, campaign_name, actor_id FK,
  start_date, end_date, objectives, created_at

**malware** (tenant)
- malware_id PK, report_id FK -> cti_reports, malware_name, family, type,
  created_at

**cves** (tenant)
- cve_id PK, report_id FK -> cti_reports, cve_id, description, severity,
  created_at

**techniques** (tenant)
- technique_id PK, report_id FK -> cti_reports, mitre_technique_id, mitre_tactic,
  technique_name, created_at

**admiralty_assessments** (tenant)
- assessment_id PK, source_id FK -> cti_sources, claim_id FK -> cti_claims,
  reliability_rating (A-F), credibility_rating (1-6), assessment_reason,
  assessed_by, assessment_date, created_at

## Adversary Brain

**adversary_brains** (tenant)
- brain_id PK, client_id FK -> clients, actor_name, campaign_name, description,
  version, status, created_at, updated_at

**brain_versions** (tenant)
- version_id PK, brain_id FK -> adversary_brains, version_number, change_summary,
  approved_by, approved_at, created_at

**brain_sources** (tenant)
- source_id PK, brain_id FK -> adversary_brains, source_ref, source_type,
  provenance, created_at

**brain_hypotheses** (tenant)
- hypothesis_id PK, brain_id FK -> adversary_brains, hypothesis_text,
  supporting_evidence, contradicting_evidence, status, created_at

**brain_observables** (tenant)
- observable_id PK, brain_id FK -> adversary_brains, observable_type,
  observable_value, confidence, source_ref, created_at

**brain_relationships** (tenant)
- relationship_id PK, brain_id FK -> adversary_brains, source_entity,
  relationship_type (USES/TARGETS/ASSOCIATED_WITH/EXPLOITS/COMMUNICATES_WITH/
  OBSERVED_IN/RELATED_TO), target_entity, evidence_ref, created_at

**brain_evidence** (tenant)
- evidence_id PK, brain_id FK -> adversary_brains, evidence_type, evidence_ref,
  confidence, created_at

**brain_assessments** (tenant)
- assessment_id PK, brain_id FK -> adversary_brains, assessed_by, assessment_date,
  confidence, conclusion, created_at

## Hunting

**hunt_hypotheses** (tenant)
- hypothesis_id PK, client_id FK -> clients, title, description, threat_actor,
  campaign, adversary_brain_id FK -> adversary_brains, sector,
  mitre_tactics, mitre_techniques, expected_behavior, required_log_sources,
  required_fields, existing_detection_rules, coverage_status, evidence,
  supporting_evidence, contradicting_evidence, assumptions, limitations,
  confidence, priority, status (GENERATED/QUALITY_CHECK/PENDING_REVIEW/
  APPROVED/REJECTED/NEEDS_MORE_DATA/INVESTIGATION/CLOSED),
  created_at, updated_at

**hypothesis_evidence** (tenant)
- evidence_id PK, hypothesis_id FK -> hunt_hypotheses, evidence_type,
  evidence_ref, source, created_at

**hypothesis_reviews** (tenant)
- review_id PK, hypothesis_id FK -> hunt_hypotheses, reviewer_id FK -> users,
  decision (APPROVED/REJECTED/NEEDS_MORE_DATA), reason, reviewed_at

**investigations** (tenant)
- investigation_id PK, hypothesis_id FK -> hunt_hypotheses, client_id FK -> clients,
  time_range, evidence, analyst_findings, final_verdict
  (TRUE_POSITIVE/FALSE_POSITIVE/INCONCLUSIVE/NEEDS_MORE_DATA),
  verdict_reason, mitigation_notes, analyst_id FK -> users, review_timestamp

**investigation_evidence** (tenant)
- evidence_id PK, investigation_id FK -> investigations, evidence_type,
  evidence_ref, created_at

**investigation_feedback** (tenant)
- feedback_id PK, investigation_id FK -> investigations, feedback_type,
  feedback_content, created_at

## AI and Harness

**harness_registry** (global)
- agent_id PK, agent_name, harness_type, integration_type, endpoint, version,
  status, capabilities, allowed_clients, allowed_tools, permission_profile,
  trust_level, created_at, updated_at, last_seen_at

**harness_capabilities** (global)
- capability_id PK, agent_id FK -> harness_registry, capability_name
  (CTI_ANALYSIS/IOC_EXTRACTION/IOC_PIVOTING/MITRE_MAPPING/
  ADVERSARY_BRAIN_GENERATION/ACH_ANALYSIS/SECTOR_RELEVANCE/HYPOTHESIS_GENERATION/
  DETECTION_COVERAGE/AQL_DRAFT_GENERATION/REPORT_GENERATION), created_at

**harness_permissions** (global)
- permission_id PK, agent_id FK -> harness_registry, permission_name,
  allowed_clients, created_at

**ai_tasks** (tenant)
- task_id PK, client_id FK -> clients, task_type, priority, input, expected_output,
  human_review_required, status, created_at, updated_at

**ai_executions** (tenant)
- execution_id PK, task_id FK -> ai_tasks, harness_id FK -> harness_registry,
  model_provider, model_name, prompt_version, workflow_version, input_reference,
  output_reference, start_time, end_time, status, error, created_at

**ai_execution_events** (tenant)
- event_id PK, execution_id FK -> ai_executions, event_type, event_data,
  timestamp, created_at

**ai_results** (tenant)
- result_id PK, execution_id FK -> ai_executions, result_data, sources, warnings,
  errors, created_at

**ai_runs** (tenant)
- run_id PK, task_id FK -> ai_tasks, run_number, status, created_at

## System

**audit_log** (global)
- event_id PK, user_id FK -> users, agent_id FK -> harness_registry,
  client_id FK -> clients, action, resource, timestamp, result, source_ip,
  correlation_id, created_at

**system_settings** (global)
- setting_id PK, setting_key, setting_value, description, updated_at

**import_jobs** (global)
- import_id PK, import_type, status, file_ref, error_log, created_at, completed_at

**file_artifacts** (global)
- artifact_id PK, file_name, file_path, checksum, file_type, metadata_ref,
  created_at

**knowledge_documents** (global)
- doc_id PK, title, content, doc_type, client_id FK -> clients (nullable for global),
  version, created_at, updated_at

**knowledge_versions** (global)
- version_id PK, doc_id FK -> knowledge_documents, version_number, change_summary,
  approved_by, approved_at, created_at

## Indexes (recommended)

- cti_reports(client_id, status)
- hunt_hypotheses(client_id, status)
- indicators(report_id)
- threat_actors(report_id)
- campaigns(report_id)
- techniques(report_id)
- ai_executions(harness_id, status)
- ai_executions(task_id)
- audit_log(client_id, timestamp)
- audit_log(action, timestamp)
- client_log_source_status(client_id, log_source_type_id)
- brain_relationships(brain_id)
- hypothesis_reviews(hypothesis_id)