package main

import (
	"encoding/json"
	"net/http"
)

// M7-D Phase 2B-3 HTTP surface: translation drafts. No execution, no QRadar.

func handleCreateDetectionTranslation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	var req TranslationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid translation request")
		return
	}
	if req.ClientID == "" || req.DomainID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id and domain_id are required")
		return
	}
	t, err := CreateDetectionTranslation(r.Context(), session.UserID, r.PathValue("rule_id"), req)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(t)
}

func handleListDetectionTranslations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	items, err := ListDetectionTranslations(session.UserID, r.PathValue("rule_id"))
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"translations": items, "count": len(items)})
}

func handleGetDetectionTranslation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	t, err := GetDetectionTranslation(r.PathValue("translation_id"), session.UserID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(t)
}
