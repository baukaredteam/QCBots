package main

import (
	"encoding/json"
	"net/http"
)

// M7-D Phase 2B-4A HTTP surface: Hunt Plans. No execution, no QRadar calls.
// Tenant checks live in the service layer; these handlers only decode, delegate
// and map typed errors, so a foreign client's metadata is never echoed back.

func handleCreateHuntPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	var req CreateHuntPlanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid hunt plan request")
		return
	}
	plan, err := CreateHuntPlan(session.UserID, req)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(plan)
}

func handleListHuntPlans(w http.ResponseWriter, r *http.Request) {
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
	plans, err := ListHuntPlans(session.UserID, clientID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"plans": plans, "count": len(plans)})
}

func handleGetHuntPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	plan, err := GetHuntPlan(r.PathValue("plan_id"), session.UserID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(plan)
}

func handleAddHuntPlanItem(w http.ResponseWriter, r *http.Request) {
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
		TranslationID string `json:"translation_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid item request")
		return
	}
	if req.TranslationID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "translation_id is required")
		return
	}
	plan, err := AddHuntPlanItem(session.UserID, r.PathValue("plan_id"), req.TranslationID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(plan)
}

func handleSubmitHuntPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	plan, err := SubmitHuntPlan(session.UserID, r.PathValue("plan_id"))
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(plan)
}

func handleReviewHuntPlan(w http.ResponseWriter, r *http.Request) {
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
		Decision string `json:"decision"`
		Evidence string `json:"evidence"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid review request")
		return
	}
	plan, err := ReviewHuntPlan(session.UserID, r.PathValue("plan_id"), req.Decision, req.Evidence, req.Note)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(plan)
}

func handleCreateHuntPlanVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	plan, err := CreateHuntPlanVersion(session.UserID, r.PathValue("plan_id"))
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(plan)
}
