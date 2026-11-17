package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// --- Octop Adapter (Phase 4, Multi-Harness Foundation) ---

// octopConfig holds connection settings for the Octop harness.
type octopConfig struct {
	endpoint    string
	allowedTools []string
	authToken   string
	authExpiry  time.Time
}

// octopAdapter implements HarnessAdapter for Tencent Octop.
type octopAdapter struct {
	config octopConfig
	client *http.Client
}

// NewOctopAdapter creates a new Octop adapter instance.
func NewOctopAdapter(endpoint string, allowedTools []string) *octopAdapter {
	return &octopAdapter{
		config: octopConfig{
			endpoint:     strings.TrimSuffix(endpoint, "/"),
			allowedTools: allowedTools,
		},
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Name returns the adapter name.
func (a *octopAdapter) Name() string {
	return "Tencent Octop"
}

// Health checks whether Octop is reachable.
func (a *octopAdapter) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", a.config.endpoint+"/health", nil)
	if err != nil {
		return fmt.Errorf("creating health request: %w", err)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("octop health check failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("octop health check returned status %d", resp.StatusCode)
	}
	return nil
}

// Capabilities returns the list of Octop capabilities.
func (a *octopAdapter) Capabilities() []string {
	return []string{"CTI_ANALYSIS", "IOC_EXTRACTION", "REPORT_GENERATION", "HUNT_HYPOTHESIS"}
}

// authenticate obtains a JWT token from Octop. Fail-closed: if credentials are
// unavailable or invalid, authentication fails and no task is executed.
func (a *octopAdapter) authenticate(ctx context.Context) error {
	// Check if we still have a valid token
	if a.config.authToken != "" && time.Now().Before(a.config.authExpiry.Add(-5*time.Minute)) {
		return nil
	}

	// Try to authenticate with Octop
	// Credentials come from environment variables or config (not hardcoded)
	username := getEnv("OCTOP_USERNAME", "")
	password := getEnv("OCTOP_PASSWORD", "")

	if username == "" || password == "" {
		// Fail-closed: no credentials means no authentication, no execution
		return fmt.Errorf("authentication failed: OCTOP_USERNAME and OCTOP_PASSWORD environment variables are required")
	}

	authReq := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{
		Username: username,
		Password: password,
	}
	body, err := json.Marshal(authReq)
	if err != nil {
		return fmt.Errorf("marshalling auth request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.config.endpoint+"/api/v1/auth/login", strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("creating auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("octop auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("octop auth returned status %d", resp.StatusCode)
	}

	var authResp struct {
		Token     string `json:"token"`
		AccessToken string `json:"access_token"`
		JWT       string `json:"jwt"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("decoding auth response: %w", err)
	}

	token := authResp.Token
	if token == "" {
		token = authResp.AccessToken
	}
	if token == "" {
		token = authResp.JWT
	}
	if token == "" {
		return fmt.Errorf("no token in octop auth response")
	}

	a.config.authToken = token
	a.config.authExpiry = time.Now().Add(time.Duration(authResp.ExpiresIn) * time.Second)
	if a.config.authExpiry.IsZero() {
		a.config.authExpiry = time.Now().Add(1 * time.Hour)
	}
	return nil
}

// Execute runs a task on Octop via its ACP endpoint.
func (a *octopAdapter) Execute(ctx context.Context, input *ExecutionInput) (*ExecutionOutput, error) {
	// Fail-closed: authentication must succeed before executing any task
	if err := a.authenticate(ctx); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Build ACP execution request
	execReq := struct {
		TaskID     string            `json:"task_id"`
		TaskType   string            `json:"task_type"`
		InputData  string            `json:"input_data"`
		ClientID   string            `json:"client_id"`
		Parameters map[string]string `json:"parameters,omitempty"`
		Tools      []string          `json:"tools,omitempty"`
	}{
		TaskID:     input.TaskID,
		TaskType:   input.TaskType,
		InputData:  input.InputData,
		ClientID:   input.ClientID,
		Parameters: input.Parameters,
		Tools:      a.config.allowedTools,
	}

	body, err := json.Marshal(execReq)
	if err != nil {
		return nil, fmt.Errorf("marshalling execution request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.config.endpoint+"/api/v1/acp/execute", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("creating execution request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if a.config.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.config.authToken)
	}

	startTime := time.Now()
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("octop execute request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading execution response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("octop execute returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var execResp struct {
		ExecutionID string `json:"execution_id"`
		Status      string `json:"status"`
		ResultData  string `json:"result_data"`
		Sources     string `json:"sources"`
		Warnings    string `json:"warnings"`
		Errors      string `json:"errors"`
	}
	if err := json.Unmarshal(respBody, &execResp); err != nil {
		// If response is not JSON, treat body as result_data
		return &ExecutionOutput{
			ExecutionID: fmt.Sprintf("exec-%d", time.Now().UnixNano()),
			Status:      "completed",
			ResultData:  string(respBody),
			StartedAt:   startTime.Format(time.RFC3339),
			EndedAt:     time.Now().Format(time.RFC3339),
			Metadata:    map[string]string{"raw_response": "true"},
		}, nil
	}

	return &ExecutionOutput{
		ExecutionID: execResp.ExecutionID,
		Status:      execResp.Status,
		ResultData:  execResp.ResultData,
		Sources:     execResp.Sources,
		Warnings:    execResp.Warnings,
		Errors:      execResp.Errors,
		StartedAt:   startTime.Format(time.RFC3339),
		EndedAt:     time.Now().Format(time.RFC3339),
	}, nil
}