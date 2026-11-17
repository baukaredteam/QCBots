package main

import (
	"encoding/json"
	"net/http"
)

// M7-D Phase 2B-1 / 2B-2 HTTP surface: Sigma ingestion and readiness analysis.
// No worker, no AQL execution, no QRadar calls.

func handleIngestSigma(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	var req struct {
		ClientID   string `json:"client_id"`
		ReportID   string `json:"report_id"`
		Filename   string `json:"filename"`
		SigmaYAML  string `json:"sigma_yaml"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSigmaBytes+16<<10)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid request body")
		return
	}
	if req.ClientID == "" || req.SigmaYAML == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id and sigma_yaml are required")
		return
	}
	name := req.Filename
	if name == "" {
		name = "sigma.yml"
	}
	rule, err := IngestSigmaRule(session.UserID, req.ClientID, req.ReportID, name, req.SigmaYAML)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(rule)
}

func handleListSigmaRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id required")
		return
	}
	rules, err := ListSigmaRules(session.UserID, clientID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"rules": rules, "count": len(rules)})
}

func handleGetSigmaRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	rule, err := GetSigmaRule(r.PathValue("rule_id"), session.UserID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rule)
}

func handleDetectionScope(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id required")
		return
	}
	scope, err := AnalyzeDetectionScope(session.UserID, clientID, r.PathValue("rule_id"))
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scope)
}
