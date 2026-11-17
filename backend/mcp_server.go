package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
)

// MCPServer handles JSON-RPC 2.0 over stdio for local harness connections.
// It implements the MCP specification (2025-06-18) for stdio transport:
// newline-delimited JSON-RPC messages on stdin/stdout.
// stdout carries only MCP protocol messages; logs go to stderr.
//
// Authentication flow:
//   1. Client connects via stdio.
//   2. Client sends `initialize` with optional mcp_client_id (identification).
//      MCP_CREDENTIAL from the server process environment is the shared secret;
//      the client must present it out-of-band or in initialize params.
//   3. Server validates credential and resolves mcp_client_id → userID.
//   4. Identity is bound to the stdio session.
//   5. Protected tools (tools/call) require prior authentication.
//   6. Notifications (e.g., notifications/initialized) require no response.
type MCPServer struct {
	handler map[string]mcpToolHandler
	mu      sync.Mutex
	logger  *slog.Logger

	// authenticated binding established at initialize
	authMu   sync.Mutex
	authed   bool
	authedID string // mcp_client_id
	authedUser string // resolved userID
}

// mcpToolHandler is the application-level tool handler.
// It receives the server-resolved userID (never from client arguments)
// and raw tool arguments (never containing mcp_client_id or mcp_credential).
type mcpToolHandler func(ctx context.Context, userID string, args json.RawMessage) (interface{}, error)

// NewMCPServer creates a new MCP server with no tools registered.
func NewMCPServer() *MCPServer {
	return &MCPServer{
		handler: make(map[string]mcpToolHandler),
		logger:  slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}
}

// AddTool registers an MCP tool with the given name, description, input schema,
// and handler. The handler receives the server-resolved userID and raw args.
// mcp_client_id and mcp_credential are NOT passed to the handler — they are
// validated during initialize and never appear in tool arguments.
func (s *MCPServer) AddTool(name, description string, inputSchema json.RawMessage, handler mcpToolHandler) {
	s.mu.Lock()
	s.handler[name] = handler
	s.mu.Unlock()
	s.logger.Info("MCP tool registered", "name", name)
}

// RegisterMCPTools registers all P0 MCP tools with the server.
func (s *MCPServer) RegisterMCPTools() {
	s.AddTool(
		"search_cases",
		"Search evidence graph cases accessible to the caller.",
		json.RawMessage(`{"type":"object","properties":{"status":{"type":"string"},"client_id":{"type":"string"},"limit":{"type":"integer","minimum":1},"offset":{"type":"integer","minimum":0}},"additionalProperties":false}`),
		handleSearchCases,
	)
	s.AddTool(
		"create_research_case",
		"Create a new research case.",
		json.RawMessage(`{"type":"object","required":["title","idempotency_key"],"properties":{"title":{"type":"string"},"idempotency_key":{"type":"string"},"description":{"type":"string"},"initial_client_id":{"type":"string"}},"additionalProperties":false}`),
		handleCreateResearchCase,
	)
	s.AddTool(
		"get_case_context",
		"Get the authorized context of a research case.",
		json.RawMessage(`{"type":"object","required":["case_id"],"properties":{"case_id":{"type":"string"}},"additionalProperties":false}`),
		handleGetCaseContext,
	)
	s.AddTool(
		"get_authorized_clients",
		"Get the list of clients the user is authorized for.",
		json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		handleGetAuthorizedClients,
	)
}

// RunStdio runs the MCP server over stdio using newline-delimited JSON-RPC.
// stdout carries only MCP protocol messages; logs go to stderr.
// Blocks until stdin EOF or context cancellation.
func (s *MCPServer) RunStdio() error {
	s.logger.Info("MCP server starting over stdio")
	decoder := json.NewDecoder(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)

	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				s.logger.Info("MCP server stdio closed")
				return nil
			}
			// Parse error: respond with JSON-RPC parse error
			resp := jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      nil,
				Error: &jsonRPCError{
					Code:    jsonRPCParseError,
					Message: fmt.Sprintf("Parse error: %v", err),
				},
			}
			if encErr := encoder.Encode(resp); encErr != nil {
				return encErr
			}
			continue
		}

		resp := s.handleRequest(raw)
		// Notifications (no id) get no response per JSON-RPC 2.0 spec.
		if resp.ID == nil {
			continue
		}
		if encErr := encoder.Encode(resp); encErr != nil {
			return encErr
		}
	}
}

// jsonRPCRequest is an incoming JSON-RPC 2.0 request.
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id,omitempty"`
}

// jsonRPCResponse is an outgoing JSON-RPC 2.0 response.
type jsonRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *jsonRPCError `json:"error,omitempty"`
	ID      interface{} `json:"id,omitempty"`
}

// jsonRPCError is a JSON-RPC 2.0 error object.
type jsonRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

const (
	jsonRPCParseError      = -32700
	jsonRPCInvalidRequest  = -32600
	jsonRPCMethodNotFound  = -32601
	jsonRPCInvalidParams   = -32602
	jsonRPCInternalError   = -32603
	jsonRPCServerErrorStart = -32000
)

// handleRequest processes a single JSON-RPC 2.0 request and returns a response.
// Requests without an id (notifications) return a response with nil ID,
// which the caller skips (no response sent per JSON-RPC spec).
func (s *MCPServer) handleRequest(raw json.RawMessage) jsonRPCResponse {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
	}

	var req jsonRPCRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		resp.Error = &jsonRPCError{
			Code:    jsonRPCParseError,
			Message: fmt.Sprintf("Parse error: %v", err),
		}
		return resp
	}

	if req.JSONRPC != "2.0" {
		resp.Error = &jsonRPCError{
			Code:    jsonRPCInvalidRequest,
			Message: "Invalid Request: missing or invalid jsonrpc field",
		}
		return resp
	}

	// Handle initialize — establishes authenticated binding.
	if req.Method == "initialize" {
		return s.handleInitialize(req)
	}

	// Handle initialized notification (no response needed per MCP spec).
	if req.Method == "initialized" {
		s.logger.Info("MCP client initialized")
		return jsonRPCResponse{JSONRPC: "2.0", ID: nil}
	}

	// For all other methods, require prior authentication.
	if !s.isAuthenticated() {
		resp.Error = &jsonRPCError{
			Code:    jsonRPCInvalidRequest,
			Message: "AUTH_FAILED: not authenticated — initialize with mcp_client_id and mcp_credential first",
		}
		return resp
	}

	// Handle tool calls.
	if req.Method == "tools/call" {
		return s.handleToolCall(req)
	}

	// Handle tools/list.
	if req.Method == "tools/list" {
		return s.handleListTools(req)
	}

	resp.Error = &jsonRPCError{
		Code:    jsonRPCMethodNotFound,
		Message: fmt.Sprintf("Method not found: %s", req.Method),
	}
	return resp
}

// handleInitialize handles the MCP initialize request.
// Authenticates the client using mcp_client_id + mcp_credential from params.
// The credential is validated against MCP_CREDENTIAL env var (shared credential)
// and/or the per-client credential hash in mcp_client_credential table.
// Expiry and revocation are checked.
func (s *MCPServer) handleInitialize(req jsonRPCRequest) jsonRPCResponse {
	var params struct {
		ClientInfo       struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"clientInfo"`
		Capabilities     json.RawMessage `json:"capabilities"`
		ProtocolVersion string `json:"protocolVersion"`
		MCPClientID     string          `json:"mcp_client_id"`
		MCPCredential   string          `json:"mcp_credential"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &jsonRPCError{
				Code:    jsonRPCInvalidParams,
				Message: fmt.Sprintf("Invalid initialize params: %v", err),
			},
		}
	}

	s.logger.Info("MCP client initialized",
		"client", params.ClientInfo.Name,
		"version", params.ClientInfo.Version,
		"protocol", params.ProtocolVersion)

	// Authenticate: validate credential and resolve client_id to userID.
	// Credential is validated against MCP_CREDENTIAL env var and/or
	// per-client credential hash in mcp_client_credential table.
	userID, err := ValidateMCPClientCredential(params.MCPClientID, params.MCPCredential)
	if err != nil {
		s.logger.Warn("MCP initialize auth failed", "error", err)
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &jsonRPCError{
				Code:    jsonRPCInvalidRequest,
				Message: err.Error(),
			},
		}
	}

	// Resolve mcp_client_id to user and verify it matches the credential-bound user.
	resolvedUserID, err := ResolveMCPClientIdentity(params.MCPClientID)
	if err != nil {
		s.logger.Warn("MCP initialize identity resolution failed", "error", err)
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &jsonRPCError{
				Code:    jsonRPCInvalidRequest,
				Message: err.Error(),
			},
		}
	}
	if userID != resolvedUserID {
		s.logger.Warn("MCP initialize credential-user mismatch",
			"credential_user", userID, "client_user", resolvedUserID)
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &jsonRPCError{
				Code:    jsonRPCInvalidRequest,
				Message: "AUTH_FAILED: credential bound to different user than mcp_client_id",
			},
		}
	}

	// Store authenticated binding for this stdio session.
	s.setAuthenticated(params.MCPClientID, userID)

	return jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"protocolVersion": "2025-06-18",
			"serverInfo": map[string]string{
				"name":    "mssp-workbench",
				"version": "1.0.0",
			},
			"capabilities": map[string]interface{}{
				"tools": map[string]bool{
					"listChanged": true,
				},
			},
		},
	}
}

// handleListTools returns the list of available MCP tools.
func (s *MCPServer) handleListTools(req jsonRPCRequest) jsonRPCResponse {
	s.mu.Lock()
	tools := make([]map[string]interface{}, 0, len(s.handler))
	for name := range s.handler {
		tools = append(tools, map[string]interface{}{
			"name":        name,
			"description": "",
			"inputSchema": map[string]interface{}{
				"type":                "object",
				"properties":          map[string]interface{}{},
				"additionalProperties": false,
			},
		})
	}
	s.mu.Unlock()

	return jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"tools": tools,
		},
	}
}

// handleToolCall processes a tools/call request.
// mcp_client_id is taken from the authenticated binding established at
// initialize — NOT from tool arguments. mcp_credential is NOT accepted
// in tools/call arguments (authentication was done at initialize).
func (s *MCPServer) handleToolCall(req jsonRPCRequest) jsonRPCResponse {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &jsonRPCError{
				Code:    jsonRPCInvalidParams,
				Message: fmt.Sprintf("Invalid arguments: %v", err),
			},
		}
	}

	// Get authenticated userID from initialize binding.
	s.authMu.Lock()
	if !s.authed {
		s.authMu.Unlock()
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &jsonRPCError{
				Code:    jsonRPCInvalidRequest,
				Message: "AUTH_FAILED: not authenticated",
			},
		}
	}
	userID := s.authedUser
	s.authMu.Unlock()

	s.mu.Lock()
	handler, ok := s.handler[params.Name]
	s.mu.Unlock()
	if !ok {
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &jsonRPCError{
				Code:    jsonRPCMethodNotFound,
				Message: fmt.Sprintf("Method not found: %s", params.Name),
			},
		}
	}

	// Call the application handler with server-resolved userID.
	// params.Arguments never contains mcp_client_id or mcp_credential.
	result, err := handler(context.Background(), userID, params.Arguments)
	if err != nil {
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &jsonRPCError{
				Code:    jsonRPCServerErrorStart + 1,
				Message: err.Error(),
			},
		}
	}

	return jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: result,
	}
}

// isAuthenticated returns true if initialize was completed with valid credentials.
func (s *MCPServer) isAuthenticated() bool {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	return s.authed
}

// setAuthenticated records the authenticated binding from initialize.
func (s *MCPServer) setAuthenticated(clientID, userID string) {
	s.authMu.Lock()
	s.authed = true
	s.authedID = clientID
	s.authedUser = userID
	s.authMu.Unlock()
}

// resetAuthentication clears the authenticated binding.
func (s *MCPServer) resetAuthentication() {
	s.authMu.Lock()
	s.authed = false
	s.authedID = ""
	s.authedUser = ""
	s.authMu.Unlock()
}

// Ensure MCPServer implements required interfaces at compile time.
var _ interface{ RunStdio() error } = (*MCPServer)(nil)
