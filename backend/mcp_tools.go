package main

import (
	"context"
	"encoding/json"
	"fmt"
)

// SearchCasesResponse is the response for the search_cases MCP tool.
type SearchCasesResponse struct {
	Cases []CaseContext `json:"cases"`
	Count int           `json:"count"`
}

// CreateResearchCaseResponse is the response for the create_research_case MCP tool.
type CreateResearchCaseResponse struct {
	CaseID string `json:"case_id"`
}

// GetCaseContextResponse is the response for the get_case_context MCP tool.
type GetCaseContextResponse struct {
	Case *CaseContext `json:"case"`
}

// GetAuthorizedClientsResponse is the response for the get_authorized_clients MCP tool.
type GetAuthorizedClientsResponse struct {
	Clients []string `json:"clients"`
	Count   int      `json:"count"`
}

// handleSearchCases implements the search_cases MCP tool.
// userID is the server-resolved authenticated user ID (never from client args).
func handleSearchCases(ctx context.Context, userID string, args json.RawMessage) (interface{}, error) {
	var input struct {
		Status   string `json:"status"`
		ClientID string `json:"client_id"`
		Limit    int    `json:"limit"`
		Offset   int    `json:"offset"`
	}
	if err := json.Unmarshal(args, &input); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	cases, err := SearchCases(userID, input.Status, input.ClientID, input.Limit, input.Offset)
	if err != nil {
		return nil, err
	}
	return &SearchCasesResponse{Cases: cases, Count: len(cases)}, nil
}

// handleCreateResearchCase implements the create_research_case MCP tool.
// userID is the server-resolved authenticated user ID (never from client args).
func handleCreateResearchCase(ctx context.Context, userID string, args json.RawMessage) (interface{}, error) {
	var input struct {
		Title           string `json:"title"`
		IdempotencyKey  string `json:"idempotency_key"`
		Description     string `json:"description"`
		InitialClientID string `json:"initial_client_id"`
	}
	if err := json.Unmarshal(args, &input); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	caseID, err := CreateResearchCase(userID, input.Title, input.Description, input.IdempotencyKey, input.InitialClientID)
	if err != nil {
		return nil, err
	}
	return &CreateResearchCaseResponse{CaseID: caseID}, nil
}

// handleGetCaseContext implements the get_case_context MCP tool.
// userID is the server-resolved authenticated user ID (never from client args).
func handleGetCaseContext(ctx context.Context, userID string, args json.RawMessage) (interface{}, error) {
	var input struct {
		CaseID string `json:"case_id"`
	}
	if err := json.Unmarshal(args, &input); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if input.CaseID == "" {
		return nil, fmt.Errorf("case_id is required")
	}

	cCtx, err := GetCaseContext(input.CaseID, userID)
	if err != nil {
		return nil, err
	}
	return &GetCaseContextResponse{Case: cCtx}, nil
}

// handleGetAuthorizedClients implements the get_authorized_clients MCP tool.
// userID is the server-resolved authenticated user ID (never from client args).
func handleGetAuthorizedClients(ctx context.Context, userID string, args json.RawMessage) (interface{}, error) {
	clients, err := GetUserAuthorizedClientsFromDB(userID)
	if err != nil {
		return nil, err
	}
	return &GetAuthorizedClientsResponse{Clients: clients, Count: len(clients)}, nil
}
