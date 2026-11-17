package main

import (
	"encoding/json"
	"errors"
	"net/http"
)

// M7-F Phase 1 HTTP surface: manual inventory import and completeness. No
// QRadar call, no binding change, no mapping approval.

func handleInventoryCompleteness(w http.ResponseWriter, r *http.Request) {
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
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id is required")
		return
	}
	report, err := InventoryCompletenessReport(session.UserID, clientID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

func handleInventoryTemplate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	kind := r.PathValue("kind")
	body, err := InventoryImportTemplate(kind)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+kind+`.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(body))
}

func decodeInventoryImport(w http.ResponseWriter, r *http.Request) (InventoryImportRequest, bool) {
	var req InventoryImportRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 768<<10)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid import request")
		return req, false
	}
	return req, true
}

func handleInventoryImportPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	req, ok := decodeInventoryImport(w, r)
	if !ok {
		return
	}
	req.DryRun = true
	preview, err := previewInventoryImport(session.UserID, req)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(preview)
}

func handleInventoryImportCommit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	req, ok := decodeInventoryImport(w, r)
	if !ok {
		return
	}
	preview, err := commitInventoryImport(session.UserID, req)
	if err != nil {
		if errors.Is(err, ErrFieldConflict) && preview != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   map[string]string{"code": "IMPORT_CONFLICT", "message": "import conflicts; nothing was written"},
				"preview": preview,
			})
			return
		}
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(preview)
}
