package main

import (
	"encoding/json"
	"fmt"
)

// MCPInputSchema returns the JSON input schema for the given MCP tool.
//
// Security: the returned schema MUST NOT contain user_id or mcp_client_id
// in properties or required. Those values are resolved server-side from
// trusted authentication context (session + CSRF + MCP_CREDENTIAL), never
// from client input.
//
// client_id may appear only as an optional filter property (search_cases),
// never as a required authentication field.
func MCPInputSchema(tool string) (json.RawMessage, error) {
	var schema string
	switch tool {
	case "search_cases":
		schema = `{
			"type": "object",
			"properties": {
				"status": {"type": "string"},
				"client_id": {"type": "string"},
				"limit": {"type": "integer", "minimum": 1},
				"offset": {"type": "integer", "minimum": 0}
			},
			"additionalProperties": false
		}`
	case "create_research_case":
		schema = `{
			"type": "object",
			"required": ["title", "idempotency_key"],
			"properties": {
				"title": {"type": "string"},
				"idempotency_key": {"type": "string"},
				"description": {"type": "string"},
				"initial_client_id": {"type": "string"}
			},
			"additionalProperties": false
		}`
	case "get_case_context":
		schema = `{
			"type": "object",
			"required": ["case_id"],
			"properties": {
				"case_id": {"type": "string"}
			},
			"additionalProperties": false
		}`
	case "get_authorized_clients":
		schema = `{
			"type": "object",
			"properties": {},
			"additionalProperties": false
		}`
	default:
		return nil, fmt.Errorf("unknown MCP tool: %s", tool)
	}
	return json.RawMessage(schema), nil
}
