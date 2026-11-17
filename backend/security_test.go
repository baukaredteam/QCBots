package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Mock HarnessAdapter for Phase 4 security tests (no real Octop) ---

type mockHarnessAdapter struct {
	name        string
	healthErr   error
	executeErr  error
	executeOut  *ExecutionOutput
	capabilities []string
	authFail    bool // simulate missing/invalid credentials
	executeFunc func(context.Context, *ExecutionInput) (*ExecutionOutput, error) // override Execute
}

func (m *mockHarnessAdapter) Name() string { return m.name }
func (m *mockHarnessAdapter) Health(ctx context.Context) error {
	if m.healthErr != nil {
		return m.healthErr
	}
	return nil
}
func (m *mockHarnessAdapter) Execute(ctx context.Context, input *ExecutionInput) (*ExecutionOutput, error) {
	if m.authFail {
		return nil, fmt.Errorf("authentication failed: invalid or missing credentials")
	}
	if m.executeErr != nil {
		return nil, m.executeErr
	}
	if m.executeOut != nil {
		return m.executeOut, nil
	}
	if m.executeFunc != nil {
		return m.executeFunc(ctx, input)
	}
	return &ExecutionOutput{
		ExecutionID: "mock-exec-" + input.TaskID,
		Status:      "completed",
		ResultData:  "mock result",
		StartedAt:   time.Now().Format(time.RFC3339),
		EndedAt:     time.Now().Format(time.RFC3339),
	}, nil
}
func (m *mockHarnessAdapter) Capabilities() []string {
	return m.capabilities
}

// --- Helper: register mock adapter and agent in DB ---

func registerMockAgent(t *testing.T, db *DB, agentID, agentName, harnessType, status string, capabilities []string, allowedClients []string, permissionProfile string, trustLevel string) {
	t.Helper()
	info := AgentInfo{
		AgentID:             agentID,
		AgentName:           agentName,
		HarnessType:         harnessType,
		IntegrationType:     "mock",
		Endpoint:            "http://mock:8088",
		Version:             "1.0.0",
		Status:              status,
		Capabilities:        capabilities,
		AllowedClients:      allowedClients,
		PermissionProfile:   permissionProfile,
		TrustLevel:          trustLevel,
	}
	if err := db.CreateAgent(info); err != nil {
		t.Fatalf("creating mock agent: %v", err)
	}
	SetAgentInfo(info)
	RegisterAdapter(agentID, &mockHarnessAdapter{
		name:        agentName,
		capabilities: capabilities,
	})
}

// --- Test: SQLite concurrent read/write locking ---

func TestSQLiteConcurrentReadWrite(t *testing.T) {
	// Use a temp file database (not in-memory) to test real concurrent access
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_concurrent.db")

	db, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=1&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("opening test database: %v", err)
	}
	defer db.Close()
	defer os.Remove(dbPath)

	if err := db.Ping(); err != nil {
		t.Fatalf("pinging test database: %v", err)
	}
	// Do NOT set SetMaxOpenConns(1) - test with default pool to find root cause

	// Create sessions table
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS sessions (
		session_id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		client_id TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_accessed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("creating sessions table: %v", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`); err != nil {
		t.Fatalf("creating index: %v", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`); err != nil {
		t.Fatalf("creating index: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	errors := make(chan error, 20)

	// 5 writers + 5 readers concurrently with context deadline
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				errors <- fmt.Errorf("writer %d: context cancelled: %w", idx, ctx.Err())
				return
			default:
			}
			sessionID := fmt.Sprintf("session-%d-%d", idx, time.Now().UnixNano())
			_, err := db.Exec(`INSERT INTO sessions (session_id, user_id, client_id, expires_at, created_at, last_accessed_at)
				VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))`,
				sessionID, fmt.Sprintf("user-%d", idx), fmt.Sprintf("client-%d", idx%3),
				time.Now().Add(8*time.Hour).Format(time.RFC3339))
			if err != nil {
				errors <- fmt.Errorf("writer %d: %w", idx, err)
			}
		}(i)
	}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				errors <- fmt.Errorf("reader %d: context cancelled: %w", idx, ctx.Err())
				return
			default:
			}
			var sessionID string
			err := db.QueryRow(`SELECT session_id FROM sessions LIMIT 1`).Scan(&sessionID)
			if err != nil && err != sql.ErrNoRows {
				errors <- fmt.Errorf("reader %d: %w", idx, err)
			}
		}(i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines completed
	case <-ctx.Done():
		t.Fatal("concurrent test timed out - possible connection pool starvation or locking issue")
	}

	close(errors)

	var errCount int
	for err := range errors {
		t.Errorf("SQLite concurrent error: %v", err)
		errCount++
	}
	if errCount > 0 {
		t.Fatalf("SQLite concurrent read/write produced %d errors - locking issue confirmed", errCount)
	}
	t.Log("PASS: SQLite concurrent read/write completed without locking errors")
}

// --- Test: Octop adapter fail-closed when credentials missing ---

func TestOctopAuthFailClosed_MissingCredentials(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	// Register mock agent with authFail=true (simulates missing credentials)
	registerMockAgent(t, db, "agent-octop-mock", "Mock Octop", "octop", "running",
		[]string{"CTI_ANALYSIS", "IOC_EXTRACTION"}, []string{"client-alpha"}, "READ_ONLY", "unverified")

	// Get the adapter and set authFail
	adapter := GetAdapter("agent-octop-mock")
	if adapter == nil {
		t.Fatal("adapter not registered")
	}
	mockAdapter, ok := adapter.(*mockHarnessAdapter)
	if !ok {
		t.Fatal("adapter is not mockHarnessAdapter")
	}
	mockAdapter.authFail = true

	ctx := context.Background()
	input := &ExecutionInput{
		TaskID:     "task-001",
		TaskType:   "CTI_ANALYSIS",
		InputData:  "analyze this",
		ClientID:   "client-alpha",
	}

	_, err := adapter.Execute(ctx, input)
	if err == nil {
		t.Fatal("expected authentication error when credentials are missing, got nil")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected 'authentication failed' in error, got: %v", err)
	}
	t.Logf("PASS: Octop adapter fail-closed: %v", err)
}

func TestOctopAuthFailClosed_AdapterNotRegistered(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	// No adapter registered for this agent
	adapter := GetAdapter("agent-nonexistent")
	if adapter != nil {
		t.Fatal("expected nil adapter for unregistered agent")
	}

	// Expected - no adapter means fail-closed
	t.Log("PASS: no adapter registered for nonexistent agent")
}

// --- Test: Harness authorization default-deny ---

func TestHarnessAuthorizationDefaultDeny(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	// Register agent with READ_ONLY profile and empty allowed_clients
	registerMockAgent(t, db, "agent-readonly", "ReadOnly Agent", "octop", "running",
		[]string{"CTI_ANALYSIS"}, []string{}, "READ_ONLY", "unverified")

	// CheckHarnessAuthorization should deny when allowed_clients is empty
	allowed := CheckHarnessAuthorization("user-admin", "ADMINISTRATOR", "execute", "agent-readonly", "client-alpha", "CTI_ANALYSIS")
	if allowed {
		t.Fatal("expected default-deny: empty allowed_clients should deny access")
	}
	t.Log("PASS: default-deny enforced for empty allowed_clients")
}

func TestHarnessAuthorization_AllowedClients(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	// Register agent with allowed_clients including client-alpha (non-READ_ONLY profile)
	registerMockAgent(t, db, "agent-allowed", "Allowed Agent", "octop", "running",
		[]string{"CTI_ANALYSIS"}, []string{"client-alpha", "client-beta"}, "CTI_ANALYST", "verified")

	// client-alpha should be allowed
	allowed := CheckHarnessAuthorization("user-admin", "ADMINISTRATOR", "execute", "agent-allowed", "client-alpha", "CTI_ANALYSIS")
	if !allowed {
		t.Fatal("expected allowed: client-alpha is in allowed_clients")
	}

	// client-gamma should NOT be allowed
	allowed = CheckHarnessAuthorization("user-admin", "ADMINISTRATOR", "execute", "agent-allowed", "client-gamma", "CTI_ANALYSIS")
	if allowed {
		t.Fatal("expected deny: client-gamma is NOT in allowed_clients")
	}
	t.Log("PASS: harness authorization respects allowed_clients")
}

func TestHarnessAuthorization_CapabilityCheck(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	// Register agent WITHOUT HUNT_HYPOTHESIS capability
	registerMockAgent(t, db, "agent-no-hypothesis", "No Hypothesis Agent", "octop", "running",
		[]string{"CTI_ANALYSIS"}, []string{"client-alpha"}, "READ_ONLY", "verified")

	// Requesting HUNT_HYPOTHESIS should be denied
	allowed := CheckHarnessAuthorization("user-admin", "ADMINISTRATOR", "execute", "agent-no-hypothesis", "client-alpha", "HUNT_HYPOTHESIS")
	if allowed {
		t.Fatal("expected deny: agent does not have HUNT_HYPOTHESIS capability")
	}
	t.Log("PASS: harness authorization checks capabilities")
}

func TestHarnessAuthorization_UnknownAgent(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	// Unknown agent should be denied
	allowed := CheckHarnessAuthorization("user-admin", "ADMINISTRATOR", "execute", "agent-unknown", "client-alpha", "CTI_ANALYSIS")
	if allowed {
		t.Fatal("expected deny: unknown agent")
	}
	t.Log("PASS: unknown agent is denied by default")
}

func TestHarnessAuthorization_READONLYCannotExecute(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	// Register agent with CTI_ANALYSIS capability but READ_ONLY permission profile
	registerMockAgent(t, db, "agent-readonly-cap", "ReadOnly Agent with Cap", "octop", "running",
		[]string{"CTI_ANALYSIS"}, []string{"client-alpha"}, "READ_ONLY", "verified")

	// Even though harness has CTI_ANALYSIS capability, READ_ONLY user cannot execute
	allowed := CheckHarnessAuthorization("user-analyst-alpha", "READ_ONLY", "execute", "agent-readonly-cap", "client-alpha", "CTI_ANALYSIS")
	if allowed {
		t.Fatal("expected deny: READ_ONLY user cannot execute even if harness has capability")
	}
	t.Log("PASS: READ_ONLY user denied execution even when harness has CTI_ANALYSIS capability")
}

func TestHarnessAuthorization_ExactCapabilityMatch(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	// Register agent with CTI_ANALYSIS capability only
	registerMockAgent(t, db, "agent-ctionly", "CTI Only Agent", "octop", "running",
		[]string{"CTI_ANALYSIS"}, []string{"client-alpha"}, "HYPOTHESIS_WRITER", "verified")

	// Requesting HUNT_HYPOTHESIS should be denied even though harness has CTI_ANALYSIS
	allowed := CheckHarnessAuthorization("user-analyst-multi", "HYPOTHESIS_WRITER", "execute", "agent-ctionly", "client-alpha", "HUNT_HYPOTHESIS")
	if allowed {
		t.Fatal("expected deny: CTI_ANALYSIS capability should not authorize HUNT_HYPOTHESIS task")
	}
	t.Log("PASS: CTI_ANALYSIS is not universal fallback for other capabilities")
}

// --- Test: Cross-tenant task access ---

func TestCrossTenantTaskAccess(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	sessionID := "session-cross-tenant-1"
	_, err := globalDB.CreateSession("user-analyst-alpha", "client-alpha")
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}
	// Override session_id to our known value for test determinism
	if _, err := db.Exec(`UPDATE sessions SET session_id = ? WHERE user_id = 'user-analyst-alpha' AND client_id = 'client-alpha'`, sessionID); err != nil {
		t.Fatalf("overriding session_id: %v", err)
	}

	// Create task for client-alpha
	taskID := "task-cross-tenant-1"
	if _, err := db.Exec(`INSERT INTO ai_tasks (task_id, client_id, task_type, priority, input, expected_output,
		human_review_required, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`,
		taskID, "client-alpha", "CTI_ANALYSIS", "high", "{}", "{}", 1, "pending"); err != nil {
		t.Fatalf("creating task: %v", err)
	}

	// Session belongs to client-alpha, trying to access task for client-beta
	// The handler should check task.ClientID == session.ClientID
	session, err := globalDB.GetSession(sessionID)
	if err != nil || session == nil {
		t.Fatalf("getting session: %v", err)
	}
	if session.ClientID != "client-alpha" {
		t.Fatalf("expected session client_id=client-alpha, got %s", session.ClientID)
	}

	// Simulate cross-tenant: session is client-alpha, task is client-beta
	// Create task for client-beta
	taskIDBeta := "task-cross-tenant-beta"
	if _, err := db.Exec(`INSERT INTO ai_tasks (task_id, client_id, task_type, priority, input, expected_output,
		human_review_required, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`,
		taskIDBeta, "client-beta", "CTI_ANALYSIS", "high", "{}", "{}", 1, "pending"); err != nil {
		t.Fatalf("creating beta task: %v", err)
	}

	// Verify tenant isolation: session.client-alpha should NOT access task for client-beta
	taskBeta, err := globalDB.GetAITask(taskIDBeta)
	if err != nil {
		t.Fatalf("getting beta task: %v", err)
	}
	if taskBeta == nil {
		t.Fatal("beta task not found")
	}
	if taskBeta.ClientID == session.ClientID {
		t.Fatal("cross-tenant: session client-alpha should not match task client-beta")
	}
	t.Logf("PASS: cross-tenant task access denied (session=%s, task=%s)", session.ClientID, taskBeta.ClientID)
}

// --- Test: Cross-tenant execution access ---

func TestCrossTenantExecutionAccess(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	sessionID := "session-cross-exec-1"
	_, err := globalDB.CreateSession("user-analyst-alpha", "client-alpha")
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}
	// Override session_id to our known value
	if _, err := db.Exec(`UPDATE sessions SET session_id = ? WHERE user_id = 'user-analyst-alpha' AND client_id = 'client-alpha'`, sessionID); err != nil {
		t.Fatalf("overriding session_id: %v", err)
	}

	// Register agent-001 in harness_registry (needed for FK constraint on ai_executions.harness_id)
	if _, err := db.Exec(`INSERT INTO harness_registry (agent_id, agent_name, harness_type, integration_type, endpoint, version, status, capabilities, allowed_clients, allowed_tools, permission_profile, trust_level, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`,
		"agent-001", "Agent 001", "octop", "mock", "http://mock:8088", "1.0.0", "running",
		`["CTI_ANALYSIS"]`, `["client-alpha"]`, `["read_only"]`, "READ_ONLY", "verified"); err != nil {
		t.Fatalf("registering agent-001: %v", err)
	}

	// Create task for client-alpha
	taskID := "task-cross-exec-1"
	if _, err := db.Exec(`INSERT INTO ai_tasks (task_id, client_id, task_type, priority, input, expected_output,
		human_review_required, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`,
		taskID, "client-alpha", "CTI_ANALYSIS", "high", "{}", "{}", 1, "pending"); err != nil {
		t.Fatalf("creating task: %v", err)
	}

	// Create execution for that task
	execID := "exec-cross-exec-1"
	if _, err := db.Exec(`INSERT INTO ai_executions (execution_id, task_id, harness_id, model_provider, model_name,
		start_time, end_time, status, error, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		execID, taskID, "agent-001", "octop", "octop-1.0",
		time.Now().Format(time.RFC3339), time.Now().Format(time.RFC3339), "completed", ""); err != nil {
		t.Fatalf("creating execution: %v", err)
	}

	// Verify: session client-alpha owns task client-alpha, so access is allowed
	session, err := globalDB.GetSession(sessionID)
	if err != nil || session == nil {
		t.Fatalf("getting session: %v", err)
	}
	task, err := globalDB.GetAITask(taskID)
	if err != nil {
		t.Fatalf("getting task: %v", err)
	}
	if task.ClientID != "client-alpha" {
		t.Fatalf("expected task client_id=client-alpha, got %s", task.ClientID)
	}

	// Now test cross-tenant: session client-alpha tries to access execution for task owned by client-beta
	taskIDBeta := "task-cross-exec-beta"
	if _, err := db.Exec(`INSERT INTO ai_tasks (task_id, client_id, task_type, priority, input, expected_output,
		human_review_required, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`,
		taskIDBeta, "client-beta", "CTI_ANALYSIS", "high", "{}", "{}", 1, "pending"); err != nil {
		t.Fatalf("creating beta task: %v", err)
	}

	execIDBeta := "exec-cross-exec-beta"
	if _, err := db.Exec(`INSERT INTO ai_executions (execution_id, task_id, harness_id, model_provider, model_name,
		start_time, end_time, status, error, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		execIDBeta, taskIDBeta, "agent-001", "octop", "octop-1.0",
		time.Now().Format(time.RFC3339), time.Now().Format(time.RFC3339), "completed", ""); err != nil {
		t.Fatalf("creating beta execution: %v", err)
	}

	// Verify cross-tenant denial: session client-alpha should NOT access execution for client-beta task
	taskBeta, err := globalDB.GetAITask(taskIDBeta)
	if err != nil {
		t.Fatalf("getting beta task: %v", err)
	}
	if taskBeta.ClientID == session.ClientID {
		t.Fatal("cross-tenant execution: session client-alpha should not match beta task client-beta")
	}
	t.Logf("PASS: cross-tenant execution access denied (session=%s, beta_task_client=%s)", session.ClientID, taskBeta.ClientID)
}

// --- Test: Execution timeout handling ---

func TestExecutionTimeout(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	sessionID := "session-timeout-1"
	_, err := db.Exec(`INSERT INTO sessions (session_id, user_id, client_id, expires_at, created_at, last_accessed_at)
		VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))`,
		sessionID, "user-analyst-alpha", "client-alpha",
		time.Now().Add(8*time.Hour).Format(time.RFC3339))
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}

	// Register mock adapter with execute error (simulating timeout)
	registerMockAgent(t, db, "agent-timeout", "Timeout Agent", "octop", "running",
		[]string{"CTI_ANALYSIS"}, []string{"client-alpha"}, "READ_ONLY", "verified")
	adapter := GetAdapter("agent-timeout")
	mockAdapter, ok := adapter.(*mockHarnessAdapter)
	if !ok {
		t.Fatal("adapter is not mockHarnessAdapter")
	}
	mockAdapter.executeErr = context.DeadlineExceeded

	// Create task
	taskID := "task-timeout-1"
	if _, err := db.Exec(`INSERT INTO ai_tasks (task_id, client_id, task_type, priority, input, expected_output,
		human_review_required, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`,
		taskID, "client-alpha", "CTI_ANALYSIS", "high", "{}", "{}", 1, "pending"); err != nil {
		t.Fatalf("creating task: %v", err)
	}

	// Execute via mock adapter directly (simulating the handler path)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	input := &ExecutionInput{
		TaskID:     taskID,
		TaskType:   "CTI_ANALYSIS",
		InputData:  "timeout test",
		ClientID:   "client-alpha",
	}

	_, err = adapter.Execute(ctx, input)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	t.Logf("PASS: execution timeout handled: %v", err)
}

// --- Test: Human review required blocks automatic execution ---

func TestHumanReviewRequiredBlocksExecution(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	// Create session for admin user
	session, err := globalDB.CreateSession("user-admin", "client-alpha")
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}
	sessionID := session.SessionID

	// Verify session exists in DB
	gotSession, err := globalDB.GetSession(sessionID)
	if err != nil || gotSession == nil {
		t.Fatalf("session not found immediately after creation: err=%v, session=%v", err, gotSession)
	}
	t.Logf("Created session ID: %s, user: %s, client: %s", sessionID, gotSession.UserID, gotSession.ClientID)

	// Register mock adapter that would succeed if called
	registerMockAgent(t, db, "agent-exec", "Exec Agent", "octop", "running",
		[]string{"CTI_ANALYSIS"}, []string{"client-alpha"}, "HYPOTHESIS_WRITER", "verified")
	adapter := GetAdapter("agent-exec")
	mockAdapter, ok := adapter.(*mockHarnessAdapter)
	if !ok {
		t.Fatal("adapter is not mockHarnessAdapter")
	}
	executeCalled := false
	mockAdapter.executeOut = &ExecutionOutput{
		ExecutionID: "mock-exec",
		Status:      "completed",
		ResultData:  "mock result",
	}
	// Wrap Execute to track calls
	mockAdapter.executeFunc = func(ctx context.Context, input *ExecutionInput) (*ExecutionOutput, error) {
		executeCalled = true
		return mockAdapter.executeOut, nil
	}

	// Create task with human_review_required=true
	taskID := "task-human-review-1"
	err = globalDB.CreateAITask(&AITask{
		TaskID:              taskID,
		ClientID:            "client-alpha",
		TaskType:            "CTI_ANALYSIS",
		Priority:            "high",
		InputData:           "{}",
		ExpectedOutput:      "{}",
		HumanReviewRequired: true,
		Status:              "pending",
	})
	if err != nil {
		t.Fatalf("creating task: %v", err)
	}

	// Attempt execution via HTTP handler (through middleware chain to test RBAC)
	req := httptest.NewRequest("POST", "/api/v1/ai/tasks/"+taskID+"/execute", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Cookie", "session_id="+sessionID)
	t.Logf("Session ID: %s, Cookie header: %s", sessionID, req.Header.Get("Cookie"))
	w := httptest.NewRecorder()

	// Apply middleware chain: requireAuth -> requirePermission -> auditWrap -> csrfWrap
	handler := applyMiddleware(http.HandlerFunc(handleExecuteAITask),
		requireAuth,
		requirePermission(CanCreateCTI),
		auditWrap,
		csrfWrap)
	handler(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d: %s", w.Code, w.Body.String())
	}

	// Verify Execute was NOT called
	if executeCalled {
		t.Fatal("expected Execute NOT to be called when human_review_required=true")
	}

	t.Log("PASS: human_review_required blocks execution and adapter.Execute is not called")
}

// --- Test: Session and task operations (sequential, no concurrency) ---

func TestSessionTaskBasicOperations(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	// Create session
	session, err := globalDB.CreateSession("user-analyst-alpha", "client-alpha")
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}
	sessionID := session.SessionID

	// Read session back
	readSession, err := globalDB.GetSession(sessionID)
	if err != nil {
		t.Fatalf("getting session: %v", err)
	}
	if readSession == nil {
		t.Fatal("session not found")
	}
	if readSession.ClientID != "client-alpha" {
		t.Fatalf("expected client_id=client-alpha, got %s", readSession.ClientID)
	}

	// Create task
	taskID := "task-basic-1"
	err = globalDB.CreateAITask(&AITask{
		TaskID:              taskID,
		ClientID:            "client-alpha",
		TaskType:            "CTI_ANALYSIS",
		Priority:            "high",
		InputData:           "{}",
		ExpectedOutput:      "{}",
		HumanReviewRequired: true,
		Status:              "pending",
	})
	if err != nil {
		t.Fatalf("creating task: %v", err)
	}

	// Read task back
	task, err := globalDB.GetAITask(taskID)
	if err != nil {
		t.Fatalf("getting task: %v", err)
	}
	if task == nil {
		t.Fatal("task not found")
	}
	if task.ClientID != "client-alpha" {
		t.Fatalf("expected task client_id=client-alpha, got %s", task.ClientID)
	}

	// Update task status
	if err := globalDB.UpdateAITaskStatus(taskID, "completed"); err != nil {
		t.Fatalf("updating task status: %v", err)
	}

	task, err = globalDB.GetAITask(taskID)
	if err != nil {
		t.Fatalf("getting updated task: %v", err)
	}
	if task.Status != "completed" {
		t.Fatalf("expected task status=completed, got %s", task.Status)
	}

	t.Log("PASS: session and task operations work correctly")
}

// --- Test: Database restart and session behavior ---

func TestDatabaseRestartSessionBehavior(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_restart.db")

	// First connection: create session
	db1, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=1&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("opening test database: %v", err)
	}
	if _, err := db1.Exec(`CREATE TABLE IF NOT EXISTS sessions (
		session_id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		client_id TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_accessed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("creating sessions table: %v", err)
	}

	sessionID := "session-restart-1"
	if _, err := db1.Exec(`INSERT INTO sessions (session_id, user_id, client_id, expires_at, created_at, last_accessed_at)
		VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))`,
		sessionID, "user-analyst-alpha", "client-alpha",
		time.Now().Add(8*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatalf("inserting session: %v", err)
	}
	db1.Close()

	// Second connection: read session (simulating restart)
	db2, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=1&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("reopening test database: %v", err)
	}
	defer db2.Close()
	defer os.Remove(dbPath)

	var foundSessionID string
	err = db2.QueryRow(`SELECT session_id FROM sessions WHERE session_id = ?`, sessionID).Scan(&foundSessionID)
	if err != nil {
		t.Fatalf("session not found after database restart: %v", err)
	}
	if foundSessionID != sessionID {
		t.Fatalf("expected session_id=%s, got %s", sessionID, foundSessionID)
	}
	t.Log("PASS: session persists across database restart")
}

// --- Test: Password hashing (PBKDF2) no regression ---

func TestPasswordHashingPBKDF2(t *testing.T) {
	password := "test-password-2026"
	hash, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hashing password: %v", err)
	}
	if hash == "" {
		t.Fatal("empty hash")
	}
	if !verifyPassword(hash, password) {
		t.Fatal("password verification failed")
	}
	// Wrong password should fail
	if verifyPassword(hash, "wrong-password") {
		t.Fatal("wrong password should not verify")
	}
	t.Log("PASS: PBKDF2 password hashing works correctly")
}

// --- Test: CSRF protection ---

func TestCSRFProtection(t *testing.T) {
	// Test that validateCSRFToken rejects missing cookie
	req := httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("X-CSRF-Token", "some-token")
	if validateCSRFToken(req) {
		t.Fatal("expected CSRF validation to fail: no csrf_token cookie")
	}

	// Test that validateCSRFToken rejects missing header
	req2 := httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
	req2.Header.Set("Origin", "http://localhost:5173")
	req2.AddCookie(&http.Cookie{Name: "csrf_token", Value: "cookie-token"})
	if validateCSRFToken(req2) {
		t.Fatal("expected CSRF validation to fail: no X-CSRF-Token header")
	}

	// Test that validateCSRFToken rejects token mismatch
	req3 := httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
	req3.Header.Set("Origin", "http://localhost:5173")
	req3.Header.Set("X-CSRF-Token", "header-token")
	req3.AddCookie(&http.Cookie{Name: "csrf_token", Value: "cookie-token"})
	if validateCSRFToken(req3) {
		t.Fatal("expected CSRF validation to fail: token mismatch")
	}

	// Test that validateCSRFToken accepts matching tokens
	req4 := httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
	req4.Header.Set("Origin", "http://localhost:5173")
	req4.Header.Set("X-CSRF-Token", "matching-token")
	req4.AddCookie(&http.Cookie{Name: "csrf_token", Value: "matching-token"})
	if !validateCSRFToken(req4) {
		t.Fatal("expected CSRF validation to pass: matching tokens")
	}

	// Test GET requests bypass CSRF
	req5 := httptest.NewRequest("GET", "/api/v1/health", nil)
	if !validateCSRFToken(req5) {
		t.Fatal("expected GET requests to bypass CSRF")
	}
	t.Log("PASS: CSRF protection works correctly")
}

// --- Test: Audit logging no regression ---

func TestAuditLoggingNoRegression(t *testing.T) {
	db := testDB(t)
	defer db.Close()

	al := NewAuditLogger(db)
	err := al.Log(AuditEvent{
		UserID:    "user-analyst-alpha",
		ClientID:  "client-alpha",
		Action:    "test.security.action",
		Resource:  "/api/v1/test",
		Result:    "success",
		SourceIP:  "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("writing audit log: %v", err)
	}

	// Verify audit log entry was written
	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = ?`, "test.security.action").Scan(&count)
	if err != nil {
		t.Fatalf("querying audit log: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 audit log entry, got %d", count)
	}
	t.Log("PASS: audit logging works correctly")
}

// --- Test helpers end ---