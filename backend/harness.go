package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

// --- Domain types for Multi-Harness Foundation (Phase 4) ---

// HarnessAdapter is the interface every harness implementation must satisfy.
// It is intentionally small (deep module): callers only need three methods,
// while the implementation hides HTTP auth, retries, parsing, and harness-specific quirks.
type HarnessAdapter interface {
	// Health checks whether the harness is reachable and responsive.
	Health(ctx context.Context) error

	// Execute runs a task on the harness and returns the result.
	Execute(ctx context.Context, input *ExecutionInput) (*ExecutionOutput, error)

	// Capabilities returns the list of capability names this harness supports.
	Capabilities() []string
}

// ExecutionInput carries everything a harness needs to run a task.
type ExecutionInput struct {
	TaskID     string            `json:"task_id"`
	TaskType   string            `json:"task_type"`
	InputData  string            `json:"input_data"`
	Parameters map[string]string `json:"parameters,omitempty"`
	ClientID   string            `json:"client_id"`
}

// ExecutionOutput is the result of a task execution.
type ExecutionOutput struct {
	ExecutionID string            `json:"execution_id"`
	Status      string            `json:"status"` // running, completed, failed, timed_out
	ResultData  string            `json:"result_data,omitempty"`
	Sources     string            `json:"sources,omitempty"`
	Warnings    string            `json:"warnings,omitempty"`
	Errors      string            `json:"errors,omitempty"`
	StartedAt   string            `json:"started_at"`
	EndedAt     string            `json:"ended_at,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// AgentInfo describes a registered harness from the agent registry.
type AgentInfo struct {
	AgentID         string   `json:"agent_id"`
	AgentName       string   `json:"agent_name"`
	HarnessType     string   `json:"harness_type"`
	IntegrationType string   `json:"integration_type,omitempty"`
	Endpoint        string   `json:"endpoint,omitempty"`
	Version         string   `json:"version,omitempty"`
	Status          string   `json:"status"`
	Capabilities    []string `json:"capabilities"`
	AllowedClients  []string `json:"allowed_clients"`
	AllowedTools    []string `json:"allowed_tools"`
	PermissionProfile string  `json:"permission_profile"`
	TrustLevel      string   `json:"trust_level"`
	LastSeenAt      string   `json:"last_seen_at,omitempty"`
}

// AITask represents a unit of work to be executed by a harness.
type AITask struct {
	TaskID           string            `json:"task_id"`
	ClientID         string            `json:"client_id"`
	TaskType         string            `json:"task_type"`
	Priority         string            `json:"priority,omitempty"`
	InputData        string            `json:"input_data"`
	ExpectedOutput   string            `json:"expected_output,omitempty"`
	HumanReviewRequired bool           `json:"human_review_required"`
	Status           string            `json:"status"` // pending, running, completed, failed, cancelled
	Parameters       map[string]string `json:"parameters,omitempty"`
	CreatedAt        string            `json:"created_at"`
	UpdatedAt        string            `json:"updated_at"`
}

// AITaskExecution is a specific run of a task by a harness.
type AITaskExecution struct {
	ExecutionID    string `json:"execution_id"`
	TaskID         string `json:"task_id"`
	HarnessID      string `json:"harness_id"`
	ModelProvider  string `json:"model_provider,omitempty"`
	ModelName      string `json:"model_name,omitempty"`
	PromptVersion  string `json:"prompt_version,omitempty"`
	WorkflowVersion string `json:"workflow_version,omitempty"`
	InputReference string `json:"input_reference,omitempty"`
	OutputReference string `json:"output_reference,omitempty"`
	StartTime      string `json:"start_time"`
	EndTime        string `json:"end_time,omitempty"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
	CreatedAt      string `json:"created_at"`
}

// --- Harness Registry (in-memory, loaded from DB + config) ---

// adapterRegistry maps agent_id to HarnessAdapter implementations.
var adapterRegistry = make(map[string]HarnessAdapter)

// agentInfos maps agent_id to AgentInfo (from config/DB).
var agentInfos = make(map[string]AgentInfo)

// RegisterAdapter registers a HarnessAdapter for a given agent_id.
// Callers must also ensure AgentInfo is set via SetAgentInfo.
func RegisterAdapter(agentID string, adapter HarnessAdapter) {
	adapterRegistry[agentID] = adapter
	log.Printf("Registered harness adapter: %s", agentID)
}

// SetAgentInfo stores metadata about a registered agent.
func SetAgentInfo(info AgentInfo) {
	agentInfos[info.AgentID] = info
}

// GetAgentInfo returns AgentInfo for an agent, or nil if not found.
func GetAgentInfo(agentID string) *AgentInfo {
	info, ok := agentInfos[agentID]
	if !ok {
		return nil
	}
	return &info
}

// GetAdapter returns the HarnessAdapter for an agent, or nil if not registered.
func GetAdapter(agentID string) HarnessAdapter {
	return adapterRegistry[agentID]
}

// ListAdapters returns all registered agent IDs.
func ListAdapters() []string {
	ids := make([]string, 0, len(adapterRegistry))
	for id := range adapterRegistry {
		ids = append(ids, id)
	}
	return ids
}

// --- DB operations for Harness ---

func (db *DB) CreateAgent(info AgentInfo) error {
	capsJSON, _ := json.Marshal(info.Capabilities)
	clientsJSON, _ := json.Marshal(info.AllowedClients)
	toolsJSON, _ := json.Marshal(info.AllowedTools)
	_, err := db.Exec(`INSERT INTO harness_registry (
		agent_id, agent_name, harness_type, integration_type, endpoint, version, status,
		capabilities, allowed_clients, allowed_tools, permission_profile, trust_level, last_seen_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		info.AgentID, info.AgentName, info.HarnessType, info.IntegrationType, info.Endpoint,
		info.Version, info.Status, string(capsJSON), string(clientsJSON), string(toolsJSON),
		info.PermissionProfile, info.TrustLevel)
	if err != nil {
		return fmt.Errorf("creating agent %s: %w", info.AgentID, err)
	}
	// Insert capabilities
	for _, cap := range info.Capabilities {
		db.Exec(`INSERT INTO harness_capabilities (capability_id, agent_id, capability_name, created_at)
			VALUES (?, ?, ?, datetime('now'))`, fmt.Sprintf("%s-%s", info.AgentID, cap), info.AgentID, cap)
	}
	return nil
}

func (db *DB) ListAgents() ([]AgentInfo, error) {
	rows, err := db.Query(`SELECT agent_id, agent_name, harness_type, integration_type, endpoint, version, status,
		capabilities, allowed_clients, allowed_tools, permission_profile, trust_level, last_seen_at
		FROM harness_registry ORDER BY agent_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []AgentInfo
	for rows.Next() {
		var a AgentInfo
		var caps, clients, tools sql.NullString
		var lastSeen sql.NullString
		if err := rows.Scan(&a.AgentID, &a.AgentName, &a.HarnessType, &a.IntegrationType, &a.Endpoint,
			&a.Version, &a.Status, &caps, &clients, &tools, &a.PermissionProfile, &a.TrustLevel, &lastSeen); err != nil {
			return nil, err
		}
		if caps.Valid && caps.String != "" {
			json.Unmarshal([]byte(caps.String), &a.Capabilities)
		}
		if clients.Valid && clients.String != "" {
			json.Unmarshal([]byte(clients.String), &a.AllowedClients)
		}
		if tools.Valid && tools.String != "" {
			json.Unmarshal([]byte(tools.String), &a.AllowedTools)
		}
		if lastSeen.Valid {
			a.LastSeenAt = lastSeen.String
		}
		agents = append(agents, a)
	}
	return agents, nil
}

func (db *DB) GetAgent(agentID string) (*AgentInfo, error) {
	row := db.QueryRow(`SELECT agent_id, agent_name, harness_type, integration_type, endpoint, version, status,
		capabilities, allowed_clients, allowed_tools, permission_profile, trust_level, last_seen_at
		FROM harness_registry WHERE agent_id = ?`, agentID)
	var a AgentInfo
	var caps, clients, tools sql.NullString
	var lastSeen sql.NullString
	if err := row.Scan(&a.AgentID, &a.AgentName, &a.HarnessType, &a.IntegrationType, &a.Endpoint,
		&a.Version, &a.Status, &caps, &clients, &tools, &a.PermissionProfile, &a.TrustLevel, &lastSeen); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if caps.Valid && caps.String != "" {
		json.Unmarshal([]byte(caps.String), &a.Capabilities)
	}
	if clients.Valid && clients.String != "" {
		json.Unmarshal([]byte(clients.String), &a.AllowedClients)
	}
	if tools.Valid && tools.String != "" {
		json.Unmarshal([]byte(tools.String), &a.AllowedTools)
	}
	if lastSeen.Valid {
		a.LastSeenAt = lastSeen.String
	}
	return &a, nil
}

func (db *DB) UpdateAgentStatus(agentID, status string) error {
	_, err := db.Exec(`UPDATE harness_registry SET status = ?, updated_at = datetime('now'), last_seen_at = datetime('now')
		WHERE agent_id = ?`, status, agentID)
	return err
}

// --- AI Task DB operations ---

func (db *DB) CreateAITask(task *AITask) error {
	_, err := db.Exec(`INSERT INTO ai_tasks (task_id, client_id, task_type, priority, input, expected_output,
		human_review_required, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`,
		task.TaskID, task.ClientID, task.TaskType, task.Priority, task.InputData, task.ExpectedOutput,
		boolToInt(task.HumanReviewRequired), task.Status)
	if err != nil {
		return fmt.Errorf("creating ai task %s: %w", task.TaskID, err)
	}
	return nil
}

func (db *DB) ListAITasks(clientID string) ([]AITask, error) {
	query := `SELECT task_id, client_id, task_type, priority, input, expected_output, human_review_required,
		status, created_at, updated_at FROM ai_tasks`
	args := []interface{}{}
	if clientID != "" {
		query += ` WHERE client_id = ?`
		args = append(args, clientID)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []AITask
	for rows.Next() {
		var t AITask
		var params sql.NullString
		var humanReview int
		if err := rows.Scan(&t.TaskID, &t.ClientID, &t.TaskType, &t.Priority, &t.InputData, &t.ExpectedOutput,
			&humanReview, &t.Status, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		t.HumanReviewRequired = humanReview == 1
		if params.Valid && params.String != "" {
			json.Unmarshal([]byte(params.String), &t.Parameters)
		}
		tasks = append(tasks, t)
	}
	return tasks, nil
}

func (db *DB) GetAITask(taskID string) (*AITask, error) {
	row := db.QueryRow(`SELECT task_id, client_id, task_type, priority, input, expected_output,
		human_review_required, status, created_at, updated_at FROM ai_tasks WHERE task_id = ?`, taskID)
	var t AITask
	var params sql.NullString
	var humanReview int
	if err := row.Scan(&t.TaskID, &t.ClientID, &t.TaskType, &t.Priority, &t.InputData, &t.ExpectedOutput,
		&humanReview, &t.Status, &t.CreatedAt, &t.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	t.HumanReviewRequired = humanReview == 1
	if params.Valid && params.String != "" {
		json.Unmarshal([]byte(params.String), &t.Parameters)
	}
	return &t, nil
}

func (db *DB) UpdateAITaskStatus(taskID, status string) error {
	_, err := db.Exec(`UPDATE ai_tasks SET status = ?, updated_at = datetime('now') WHERE task_id = ?`, status, taskID)
	return err
}

// --- AI Task Execution DB operations ---

func (db *DB) CreateAITaskExecution(exec *AITaskExecution) error {
	_, err := db.Exec(`INSERT INTO ai_executions (execution_id, task_id, harness_id, model_provider, model_name,
		prompt_version, workflow_version, input_reference, output_reference, start_time, end_time, status, error, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		exec.ExecutionID, exec.TaskID, exec.HarnessID, exec.ModelProvider, exec.ModelName,
		exec.PromptVersion, exec.WorkflowVersion, exec.InputReference, exec.OutputReference,
		exec.StartTime, exec.EndTime, exec.Status, exec.Error)
	return err
}

func (db *DB) UpdateAITaskExecution(exec *AITaskExecution) error {
	_, err := db.Exec(`UPDATE ai_executions SET end_time = ?, status = ?, error = ?, output_reference = ? WHERE execution_id = ?`,
		exec.EndTime, exec.Status, exec.Error, exec.OutputReference, exec.ExecutionID)
	return err
}

func (db *DB) ListAITaskExecutions(taskID string) ([]AITaskExecution, error) {
	rows, err := db.Query(`SELECT execution_id, task_id, harness_id, model_provider, model_name, prompt_version,
		workflow_version, input_reference, output_reference, start_time, end_time, status, error, created_at
		FROM ai_executions WHERE task_id = ? ORDER BY created_at DESC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var executions []AITaskExecution
	for rows.Next() {
		var e AITaskExecution
		if err := rows.Scan(&e.ExecutionID, &e.TaskID, &e.HarnessID, &e.ModelProvider, &e.ModelName,
			&e.PromptVersion, &e.WorkflowVersion, &e.InputReference, &e.OutputReference,
			&e.StartTime, &e.EndTime, &e.Status, &e.Error, &e.CreatedAt); err != nil {
			return nil, err
		}
		executions = append(executions, e)
	}
	return executions, nil
}

func (db *DB) CreateAITaskExecutionEvent(executionID, eventType, eventData string) error {
	eventID := fmt.Sprintf("evt-%d", time.Now().UnixNano())
	_, err := db.Exec(`INSERT INTO ai_execution_events (event_id, execution_id, event_type, event_data, timestamp, created_at)
		VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))`,
		eventID, executionID, eventType, eventData)
	return err
}

func (db *DB) CreateAIResult(executionID, resultData, sources, warnings, errors string) error {
	resultID := fmt.Sprintf("result-%d", time.Now().UnixNano())
	_, err := db.Exec(`INSERT INTO ai_results (result_id, execution_id, result_data, sources, warnings, errors, created_at)
		VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
		resultID, executionID, resultData, sources, warnings, errors)
	return err
}

// --- Harness capability and permission helpers ---

// CheckHarnessAuthorization checks if a harness is authorized to execute a task
// for a given user and client. Default-deny: all checks must pass, otherwise access is denied.
// All client, user, and role data must come from trusted server-side context, never from client input.
func CheckHarnessAuthorization(userID, userRole, action, agentID, clientID, taskType string) bool {
	info := GetAgentInfo(agentID)
	if info == nil {
		return false
	}

	// Default permission profile to READ_ONLY if not set
	if info.PermissionProfile == "" {
		info.PermissionProfile = "READ_ONLY"
	}

	// READ_ONLY profile cannot execute tasks that write data
	if info.PermissionProfile == "READ_ONLY" {
		return false
	}

	// Action-specific permission check: only HYPOTHESIS_WRITER or ADMINISTRATOR can execute
	if userRole != "ADMINISTRATOR" && userRole != "HYPOTHESIS_WRITER" {
		return false
	}

	// Check allowed_clients - client must be explicitly listed or "*"
	clientAllowed := false
	for _, c := range info.AllowedClients {
		if c == clientID || c == "*" {
			clientAllowed = true
			break
		}
	}
	if !clientAllowed {
		return false
	}

	// Check capabilities - exact match required, no universal fallback
	adapter := GetAdapter(agentID)
	if adapter == nil {
		return false
	}
	capAllowed := false
	for _, cap := range adapter.Capabilities() {
		if cap == taskType {
			capAllowed = true
			break
		}
	}
	if !capAllowed {
		return false
	}

	return true
}

func (db *DB) AddAgentCapability(agentID, capabilityName string) error {
	capabilityID := fmt.Sprintf("%s-%s", agentID, capabilityName)
	_, err := db.Exec(`INSERT INTO harness_capabilities (capability_id, agent_id, capability_name, created_at)
		VALUES (?, ?, ?, datetime('now'))
		ON CONFLICT(capability_id) DO UPDATE SET capability_name = excluded.capability_name`,
		capabilityID, agentID, capabilityName)
	return err
}

func (db *DB) AddAgentPermission(agentID, permissionName, allowedClients string) error {
	permissionID := fmt.Sprintf("%s-%s", agentID, permissionName)
	_, err := db.Exec(`INSERT INTO harness_permissions (permission_id, agent_id, permission_name, allowed_clients, created_at)
		VALUES (?, ?, ?, ?, datetime('now'))
		ON CONFLICT(permission_id) DO UPDATE SET permission_name = excluded.permission_name, allowed_clients = excluded.allowed_clients`,
		permissionID, agentID, permissionName, allowedClients)
	return err
}

// --- Utility ---

func parseJSONArray(s string) []string {
	if s == "" {
		return nil
	}
	var arr []string
	if err := json.Unmarshal([]byte(s), &arr); err != nil {
		// Fallback: split by comma
		parts := strings.Split(s, ",")
		arr = make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				arr = append(arr, p)
			}
		}
	}
	return arr
}

// seedHarnessesFromConfig loads harness definitions from config into the registry.
func seedHarnessesFromConfig(db *DB, harnesses []HarnessConfig) error {
	for _, h := range harnesses {
		info := AgentInfo{
			AgentID:         h.AgentID,
			AgentName:       h.AgentName,
			HarnessType:     h.HarnessType,
			IntegrationType: h.IntegrationType,
			Endpoint:        h.Endpoint,
			Version:         h.Version,
			Status:          h.Status,
			Capabilities:    h.Capabilities,
			AllowedClients:  h.AllowedClients,
			AllowedTools:    h.AllowedTools,
			PermissionProfile: h.PermissionProfile,
			TrustLevel:      h.TrustLevel,
		}
		// Ensure DB row exists (idempotent)
		existing, err := db.GetAgent(h.AgentID)
		if err != nil {
			log.Printf("Warning: checking agent %s: %v", h.AgentID, err)
			continue
		}
		if existing == nil {
			if err := db.CreateAgent(info); err != nil {
				log.Printf("Warning: creating agent %s: %v", h.AgentID, err)
			}
		}
		SetAgentInfo(info)
		// Register adapter based on harness type
		switch strings.ToLower(h.HarnessType) {
		case "octop":
			if h.Endpoint != "" {
				RegisterAdapter(h.AgentID, NewOctopAdapter(h.Endpoint, h.AllowedTools))
			}
		case "harnessrouter", "opencode", "codex", "deepseek":
			// No adapter implemented yet — placeholder
			log.Printf("Harness type %s not yet implemented (agent %s)", h.HarnessType, h.AgentID)
		}
	}
	return nil
}