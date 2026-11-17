package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// migrationSQL contains the initial schema migration for testing.
const migrationSQL = `
PRAGMA foreign_keys = ON;

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
`

// testDB creates a fresh in-memory SQLite database for testing.
// testDB creates a fresh in-memory SQLite database for testing.
func testDB(t *testing.T) *DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:?_journal_mode=WAL&_foreign_keys=1")
	if err != nil {
		t.Fatalf("opening test database: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("pinging test database: %v", err)
	}
	// Execute migration SQL directly
	statements := strings.Split(migrationSQL, ";")
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("executing migration statement %q: %v", stmt[:min(50,len(stmt))], err)
		}
	}
	// Serialize all DB access through a single connection to avoid SQLite locking issues on Windows
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := createM1Tables(db); err != nil {
		t.Fatalf("creating M1 tables: %v", err)
	}
	if err := runMigration(db, "migrations/0002_qradar_inventory.sql"); err != nil {
		t.Fatalf("running migration 0002: %v", err)
	}
	if err := runMigration(db, "migrations/0004_p0_mcp_case.sql"); err != nil {
		t.Fatalf("running migration 0004: %v", err)
	}
	if err := seedTestData(db); err != nil {
		t.Fatalf("seeding test data: %v", err)
	}
	// Set up global singletons for handlers that depend on them
	globalDB = &DB{db}
	globalAuditLogger = NewAuditLogger(&DB{db})
	globalCSRFValidator = NewCSRFValidator([]string{"http://localhost:5173"}, false)
	globalConfig = &Config{
		ServerPort: "8080",
		Origin:     "http://localhost:5173",
	}
	return &DB{db}
}

func TestHealthEndpoint(t *testing.T) {
	db := testDB(t)
	defer db.Close()

	// Create a mock config for the handler
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLoginAndLogout(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	// Seed explicit grant for user-analyst-alpha on client-alpha.
	if _, err := db.Exec(`INSERT INTO user_authorized_clients (grant_id, user_id, client_id) VALUES (?, ?, ?)`,
		"grant-test-login-alpha", "user-analyst-alpha", "client-alpha"); err != nil {
		t.Fatalf("inserting grant: %v", err)
	}

	// Test valid login
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"analyst-alpha","password":"alpha-pass-2026","client_id":"client-alpha"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
		return
	}

	// Extract session cookie
	var loginResp struct {
		SessionID string `json:"session_id"`
		User      struct {
			ID   string `json:"id"`
			Role string `json:"role"`
		} `json:"user"`
	}
	if err := json.NewDecoder(w.Body).Decode(&loginResp); err != nil {
		t.Fatalf("decoding login response: %v", err)
	}
	if loginResp.SessionID == "" {
		t.Fatal("empty session_id in login response")
	}

	// Test /api/v1/auth/me with session cookie
	json.NewDecoder(w.Body).Decode(&loginResp)

	req2 := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
	req2 = req2.WithContext(context.WithValue(req2.Context(), sessionCtxKey, &Session{
		SessionID: loginResp.SessionID,
		UserID:    loginResp.User.ID,
		ClientID:  "client-alpha",
	}))
	w2 := httptest.NewRecorder()
	handleMe(w2, req2)

	if w2.Code != 200 {
		t.Errorf("expected 200 for /api/v1/auth/me, got %d: %s", w2.Code, w2.Body.String())
	}

	// Test logout
	req3 := httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
	req3.AddCookie(&http.Cookie{Name: "session_id", Value: loginResp.SessionID})
	req3 = req3.WithContext(context.WithValue(req3.Context(), sessionCtxKey, &Session{
		SessionID: loginResp.SessionID,
		UserID:    loginResp.User.ID,
		ClientID:  "client-alpha",
	}))
	w3 := httptest.NewRecorder()
	handleLogout(w3, req3)

	if w3.Code != 200 {
		t.Errorf("expected 200 for logout, got %d: %s", w3.Code, w3.Body.String())
	}

	// Test access after logout - session still in context, so handleMe still works
	// (the session was deleted from DB but context session is still valid)
	req4 := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
	req4 = req4.WithContext(context.WithValue(req4.Context(), sessionCtxKey, &Session{
		SessionID: loginResp.SessionID,
		UserID:    loginResp.User.ID,
		ClientID:  "client-alpha",
	}))
	w4 := httptest.NewRecorder()
	handleMe(w4, req4)

	if w4.Code != 200 {
		t.Errorf("expected 200 after logout (session still in context), got %d", w4.Code)
	}

	// Session is deleted from DB by logout handler
}

func TestInvalidLogin(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"analyst-alpha","password":"wrong-password"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401 for invalid login, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMissingAuth(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	// Access /api/v1/auth/me without session cookie
	req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
	w := httptest.NewRecorder()
	handleMe(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401 for missing auth, got %d", w.Code)
	}
}

func TestTenantIsolation(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	// Seed explicit grants for test users.
	if _, err := db.Exec(`INSERT INTO user_authorized_clients (grant_id, user_id, client_id) VALUES (?, ?, ?)`,
		"grant-test-tenant-alpha-alpha", "user-analyst-alpha", "client-alpha"); err != nil {
		t.Fatalf("inserting grant: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO user_authorized_clients (grant_id, user_id, client_id) VALUES (?, ?, ?)`,
		"grant-test-tenant-multi-alpha", "user-analyst-multi", "client-alpha"); err != nil {
		t.Fatalf("inserting grant: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO user_authorized_clients (grant_id, user_id, client_id) VALUES (?, ?, ?)`,
		"grant-test-tenant-multi-beta", "user-analyst-multi", "client-beta"); err != nil {
		t.Fatalf("inserting grant: %v", err)
	}

	// Login as analyst-alpha
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"analyst-alpha","password":"alpha-pass-2026","client_id":"client-alpha"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != 200 {
		t.Fatalf("login failed: %d %s", w.Code, w.Body.String())
	}
	var loginResp struct {
		SessionID string `json:"session_id"`
		User      struct {
			ID   string `json:"id"`
			Role string `json:"role"`
		} `json:"user"`
	}
	json.NewDecoder(w.Body).Decode(&loginResp)

	// Access client-alpha (should succeed) - set session in context
	req2 := httptest.NewRequest("GET", "/api/v1/tenants/client-alpha/cti/reports", nil)
	req2 = req2.WithContext(context.WithValue(req2.Context(), sessionCtxKey, &Session{
		SessionID: loginResp.SessionID,
		UserID:    loginResp.User.ID,
		ClientID:  "client-alpha",
	}))
	w2 := httptest.NewRecorder()
	handleTenantCTIReports(w2, req2)

	if w2.Code != 200 {
		t.Errorf("expected 200 for authorized client, got %d: %s", w2.Code, w2.Body.String())
	}

	// Access client-beta (should fail with 403)
	req3 := httptest.NewRequest("GET", "/api/v1/tenants/client-beta/cti/reports", nil)
	req3 = req3.WithContext(context.WithValue(req3.Context(), sessionCtxKey, &Session{
		SessionID: loginResp.SessionID,
		UserID:    loginResp.User.ID,
		ClientID:  "client-alpha",
	}))
	w3 := httptest.NewRecorder()
	handleTenantCTIReports(w3, req3)

	if w3.Code != 403 {
		t.Errorf("expected 403 for unauthorized client, got %d: %s", w3.Code, w3.Body.String())
	}

	// Login as analyst-multi (has access to both clients)
	req4 := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"analyst-multi","password":"multi-pass-2026","client_id":"client-alpha"}`))
	req4.Header.Set("Content-Type", "application/json")
	w4 := httptest.NewRecorder()
	handleLogin(w4, req4)

	if w4.Code != 200 {
		t.Fatalf("multi login failed: %d %s", w4.Code, w4.Body.String())
	}
	var loginResp4 struct {
		SessionID string `json:"session_id"`
		User      struct {
			ID   string `json:"id"`
			Role string `json:"role"`
		} `json:"user"`
	}
	json.NewDecoder(w4.Body).Decode(&loginResp4)

	// Access client-alpha (should succeed)
	req5 := httptest.NewRequest("GET", "/api/v1/tenants/client-alpha/cti/reports", nil)
	req5 = req5.WithContext(context.WithValue(req5.Context(), sessionCtxKey, &Session{
		SessionID: loginResp4.SessionID,
		UserID:    loginResp4.User.ID,
		ClientID:  "client-alpha",
	}))
	w5 := httptest.NewRecorder()
	handleTenantCTIReports(w5, req5)

	if w5.Code != 200 {
		t.Errorf("expected 200 for multi user client-alpha, got %d: %s", w5.Code, w5.Body.String())
	}

	// Access client-beta (should also succeed for multi user)
	req6 := httptest.NewRequest("GET", "/api/v1/tenants/client-beta/cti/reports", nil)
	req6 = req6.WithContext(context.WithValue(req6.Context(), sessionCtxKey, &Session{
		SessionID: loginResp4.SessionID,
		UserID:    loginResp4.User.ID,
		ClientID:  "client-beta",
	}))
	w6 := httptest.NewRecorder()
	handleTenantCTIReports(w6, req6)

	if w6.Code != 200 {
		t.Errorf("expected 200 for multi user client-beta, got %d: %s", w6.Code, w6.Body.String())
	}
}

func TestRBACPermissions(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	// Test CTI_ANALYST can view CTI
	role, err := globalDB.GetUserRole("user-analyst-alpha")
	if err != nil {
		t.Fatalf("getting role: %v", err)
	}
	rp, ok := GetPermission(role)
	if !ok {
		t.Fatalf("unknown role %s", role)
	}
	if !rp.CanViewCTI {
		t.Errorf("CTI_ANALYST should have CanViewCTI")
	}
	if rp.CanCreateHypothesis {
		t.Errorf("CTI_ANALYST should NOT have CanCreateHypothesis")
	}

	// Test HYPOTHESIS_WRITER can create hypothesis
	role2, err := globalDB.GetUserRole("user-analyst-multi")
	if err != nil {
		t.Fatalf("getting role: %v", err)
	}
	rp2, ok := GetPermission(role2)
	if !ok {
		t.Fatalf("unknown role %s", role2)
	}
	if !rp2.CanCreateHypothesis {
		t.Errorf("HYPOTHESIS_WRITER should have CanCreateHypothesis")
	}
	if !rp2.CanGenerateAQL {
		t.Errorf("HYPOTHESIS_WRITER should have CanGenerateAQL")
	}

	// Test ADMINISTRATOR can view audit
	// We need to insert an admin user
	_, err = db.Exec(`INSERT OR IGNORE INTO users (user_id, username, email, password_hash, role, is_active, created_at, updated_at)
		VALUES ('user-admin-test', 'admin-test', 'admin@example.org', 'dummyhash', 'ADMINISTRATOR', 1, datetime('now'), datetime('now'))`)
	if err != nil {
		t.Fatalf("inserting admin user: %v", err)
	}
	role3, err := globalDB.GetUserRole("user-admin-test")
	if err != nil {
		t.Fatalf("getting admin role: %v", err)
	}
	rp3, ok := GetPermission(role3)
	if !ok {
		t.Fatalf("unknown role %s", role3)
	}
	if !rp3.CanViewAudit {
		t.Errorf("ADMINISTRATOR should have CanViewAudit")
	}
	if !rp3.CanManageUsers {
		t.Errorf("ADMINISTRATOR should have CanManageUsers")
	}
}

func TestAuditLogging(t *testing.T) {
	db := testDB(t)
	defer db.Close()

	al := NewAuditLogger(db)
	err := al.Log(AuditEvent{
		UserID:    "user-analyst-alpha",
		Action:    "test.action",
		Resource:  "/api/v1/test",
		Result:    "success",
		SourceIP:  "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("logging audit event: %v", err)
	}

	// Verify the audit log entry was written
	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = ?`, "test.action").Scan(&count)
	if err != nil {
		t.Fatalf("querying audit log: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 audit log entry, got %d", count)
	}

	// Verify no secrets in audit log
	var secretCount int
	err = db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action LIKE '%password%' OR action LIKE '%secret%' OR action LIKE '%token%'`).Scan(&secretCount)
	if err != nil {
		t.Fatalf("querying audit log for secrets: %v", err)
	}
	if secretCount > 0 {
		t.Errorf("found %d audit log entries containing secrets", secretCount)
	}
}

// TestGetSessionRejectedAfterDelete verifies that GetSession() returns nil for
// a session that was deleted (revoked) from the database but may still reside
// in the in-memory sessionCache. This is a fail-closed check: a cached session
// must not be returned after deletion.
func TestGetSessionRejectedAfterDelete(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	// Create a session
	session, err := db.CreateSession("user-analyst-alpha", "client-alpha")
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}

	// Verify session is retrievable from cache
	got, err := db.GetSession(session.SessionID)
	if err != nil {
		t.Fatalf("getting session after create: %v", err)
	}
	if got == nil {
		t.Fatal("expected session to be found after create")
	}
	if got.SessionID != session.SessionID {
		t.Errorf("expected session_id %s, got %s", session.SessionID, got.SessionID)
	}

	// Delete the session (revoke it)
	if err := db.DeleteSession(session.SessionID); err != nil {
		t.Fatalf("deleting session: %v", err)
	}

	// Verify session is rejected after deletion (cache hit but revoked)
	got, err = db.GetSession(session.SessionID)
	if err != nil {
		t.Fatalf("getting session after delete: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil session after deletion, got non-nil")
	}

	// Verify session is no longer in cache
	if s := sessionCache.load(session.SessionID); s != nil {
		t.Error("expected session to be removed from cache after deletion")
	}

	// Verify session is no longer in database
	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE session_id = ?`, session.SessionID).Scan(&count)
	if err != nil {
		t.Fatalf("querying session count: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 rows in sessions after deletion, got %d", count)
	}
}
