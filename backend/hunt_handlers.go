package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

func handleCreateHypothesisManual(w http.ResponseWriter, r *http.Request) {
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
		ClientID           string `json:"client_id"`
		Title              string `json:"title"`
		Description        string `json:"description"`
		Statement          string `json:"statement"`
		SuspectedBehavior  string `json:"suspected_behavior"`
		AdversaryObjective string `json:"adversary_objective"`
		MitreTactics       string `json:"mitre_tactics"`
		MitreTechniques    string `json:"mitre_techniques"`
		BenignExplanations string `json:"known_benign_explanations"`
		Assumptions        string `json:"assumptions"`
		BlindSpots         string `json:"blind_spots"`
		Limitations        string `json:"limitations"`
		GenerationMethod   string `json:"generation_method"`
		IdempotencyKey     string `json:"idempotency_key"`
		Evidence           []HypothesisEvidenceInput `json:"evidence"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ClientID == "" || req.Title == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id and title required")
		return
	}
	in := &HypothesisInput{
		Title: req.Title, Description: req.Description, Statement: req.Statement,
		SuspectedBehavior: req.SuspectedBehavior, AdversaryObjective: req.AdversaryObjective,
		MitreTactics: req.MitreTactics, MitreTechniques: req.MitreTechniques,
		BenignExplanations: req.BenignExplanations, Assumptions: req.Assumptions,
		BlindSpots: req.BlindSpots, Limitations: req.Limitations,
		GenerationMethod: req.GenerationMethod, IdempotencyKey: req.IdempotencyKey,
		Evidence: req.Evidence,
	}
	detail, created, err := CreateHypothesisManual(session.UserID, req.ClientID, in)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if created {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"hypothesis": detail, "created": created})
}

func handleCreateHypothesisFromReport(w http.ResponseWriter, r *http.Request) {
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
		ClientID       string `json:"client_id"`
		ReportID       string `json:"report_id"`
		AssessmentID   string `json:"assessment_id"`
		Title          string `json:"title"`
		Description    string `json:"description"`
		Statement      string `json:"statement"`
		MitreTactics   string `json:"mitre_tactics"`
		MitreTechniques string `json:"mitre_techniques"`
		BenignExplanations string `json:"known_benign_explanations"`
		Assumptions    string `json:"assumptions"`
		BlindSpots     string `json:"blind_spots"`
		Limitations    string `json:"limitations"`
		IdempotencyKey string `json:"idempotency_key"`
		Evidence       []HypothesisEvidenceInput `json:"evidence"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	in := &HypothesisInput{
		Title: req.Title, Description: req.Description, Statement: req.Statement,
		MitreTactics: req.MitreTactics, MitreTechniques: req.MitreTechniques,
		BenignExplanations: req.BenignExplanations, Assumptions: req.Assumptions,
		BlindSpots: req.BlindSpots, Limitations: req.Limitations,
		IdempotencyKey: req.IdempotencyKey, Evidence: req.Evidence,
	}
	detail, created, err := CreateHypothesisFromReport(session.UserID, req.ReportID, req.ClientID, req.AssessmentID, in)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if created {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"hypothesis": detail, "created": created})
}

func handleGetHypothesis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	detail, err := GetHypothesisDetail(r.PathValue("hypothesis_id"), session.UserID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(detail)
}

func handleGetHypothesisVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	genNO, err := strconv.Atoi(r.PathValue("version_no"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid version_no")
		return
	}
	v, err := GetHypothesisVersion(session.UserID, r.PathValue("hypothesis_id"), genNO)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func handleEditHypothesisVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "PATCH required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	genNO, err := strconv.Atoi(r.PathValue("version_no"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid version_no")
		return
	}
	var req struct {
		Statement             string `json:"statement"`
		SuspectedBehavior     string `json:"suspected_behavior"`
		AdversaryObjective    string `json:"adversary_objective"`
		MitreTactics          string `json:"mitre_tactics"`
		MitreTechniques       string `json:"mitre_techniques"`
		BenignExplanations    string `json:"known_benign_explanations"`
		Assumptions           string `json:"assumptions"`
		BlindSpots            string `json:"blind_spots"`
		Limitations           string `json:"limitations"`
		ExpectedDraftRevision int    `json:"expected_draft_revision"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	err = EditDraftVersion(session.UserID, r.PathValue("hypothesis_id"), genNO, HypothesisEdit{
		Statement: req.Statement, Suspected: req.SuspectedBehavior, Objective: req.AdversaryObjective,
		Tactics: req.MitreTactics, Techniques: req.MitreTechniques, Benign: req.BenignExplanations,
		Assumptions: req.Assumptions, BlindSpots: req.BlindSpots, Limitations: req.Limitations,
		ExpectedDraftRevision: req.ExpectedDraftRevision,
	})
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "updated"})
}

func handleSubmitHypothesisReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	if err := SubmitForReview(session.UserID, r.PathValue("hypothesis_id")); err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "submitted"})
}

func handleReviewHypothesisVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	genNO, err := strconv.Atoi(r.PathValue("version_no"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid version_no")
		return
	}
	var req struct {
		Decision       string `json:"decision"`
		Reason         string `json:"reason"`
		OriginalStatus string `json:"original_status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Decision == "" || req.Reason == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "decision and reason required")
		return
	}
	res, err := ReviewVersion(session.UserID, r.PathValue("hypothesis_id"), genNO, req.Decision, req.Reason, req.OriginalStatus)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(res)
}

func handleGetHypothesisHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	hist, err := ListHypothesisHistory(session.UserID, r.PathValue("hypothesis_id"))
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"events": hist})
}

func mapHuntError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrFieldInventoryNotFound):
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "not found")
	case errors.Is(err, ErrFieldAccessDenied), errors.Is(err, ErrFieldVerificationDenied):
		writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "access denied")
	case errors.Is(err, ErrFieldImportInvalid), errors.Is(err, ErrFieldImportRedacted):
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
	case errors.Is(err, ErrFieldConflict):
		writeJSONError(w, http.StatusConflict, "CONFLICT", "an earlier review decision already stands")
	case errors.Is(err, ErrDomainBindingMissing):
		writeJSONError(w, http.StatusForbidden, "DOMAIN_BINDING_MISSING", "domain has no binding; access denied")
	case errors.Is(err, ErrDomainNotAssigned):
		writeJSONError(w, http.StatusForbidden, "DOMAIN_NOT_ASSIGNED", "domain is not bound to a client")
	case errors.Is(err, ErrDomainBindingOwned):
		writeJSONError(w, http.StatusConflict, "BINDING_CONFLICT", "binding changed concurrently or is already decided")
	case errors.Is(err, ErrNativeDomainIDBad):
		writeJSONError(w, http.StatusBadRequest, "NATIVE_DOMAIN_ID_INVALID", "native QRadar domain id is invalid or already used on this instance")
	case errors.Is(err, ErrTranslationStale):
		writeJSONError(w, http.StatusConflict, "STALE_SCOPE", "authorisation, binding or mapping evidence changed during translation")
	case errors.Is(err, ErrHuntPlanNotFound):
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "hunt plan not found")
	case errors.Is(err, ErrHuntPlanAccessDenied):
		writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "access denied")
	case errors.Is(err, ErrHuntPlanConflict):
		writeJSONError(w, http.StatusConflict, "HUNT_PLAN_CONFLICT", "plan state or attached evidence changed")
	case errors.Is(err, ErrHuntPlanEvidenceUnavailable):
		writeJSONError(w, http.StatusConflict, "EVIDENCE_UNAVAILABLE", "evidence a decision depends on is no longer readable")
	case errors.Is(err, ErrHuntPlanInvalid):
		writeJSONError(w, http.StatusBadRequest, "HUNT_PLAN_INVALID", err.Error())
	case errors.Is(err, ErrSigmaInvalid):
		writeJSONError(w, http.StatusBadRequest, "SIGMA_INVALID", err.Error())
	case errors.Is(err, ErrHuntNotFound):
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "hypothesis not found")
	case errors.Is(err, ErrHuntAccessDenied), errors.Is(err, ErrDraftPermissionDenied):
		writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "access denied")
	case errors.Is(err, ErrHuntReviewDenied):
		writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
	case errors.Is(err, ErrHuntIdempotencyConflict):
		writeJSONError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "same idempotency key with different payload")
	case errors.Is(err, ErrVersionConflict):
		writeJSONError(w, http.StatusConflict, "VERSION_CONFLICT", "stale version")
	case errors.Is(err, ErrHuntInvalidTransition):
		writeJSONError(w, http.StatusConflict, "INVALID_TRANSITION", "invalid lifecycle transition")
	case errors.Is(err, ErrInvalidHypothesis):
		writeJSONError(w, http.StatusUnprocessableEntity, "INVALID_HYPOTHESIS", "validation failed")
	default:
		mapCaseError(w, err)
	}
}
