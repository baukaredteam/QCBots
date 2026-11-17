package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

// M7-B HTTP handlers. AuthZ: requireAuth + role via middleware; case/report
// access + client grants enforced in the service layer (defense in depth).

func parseM7BLimitOffset(r *http.Request) (int, int) {
	limit, offset := 20, 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}

func handleListCaseCTIReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	caseID := r.PathValue("case_id")
	limit, offset := parseM7BLimitOffset(r)
	rows, total, err := ListCaseCTIReports(caseID, session.UserID, limit, offset)
	if err != nil {
		mapCaseError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"reports": rows, "total": total, "limit": limit, "offset": offset})
}

func handleLinkCaseCTIReport(w http.ResponseWriter, r *http.Request) {
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
		ReportID string `json:"report_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ReportID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "report_id required")
		return
	}
	if created, err := LinkCaseCTIReport(r.PathValue("case_id"), session.UserID, req.ReportID); err != nil {
		mapCaseError(w, err)
		return
	} else {
		w.Header().Set("Content-Type", "application/json")
		if created {
			w.WriteHeader(http.StatusCreated)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"case_id": r.PathValue("case_id"), "report_id": req.ReportID, "linked": true, "created": created})
	}
}

func handleUnlinkCaseCTIReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "DELETE required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	if unlinked, err := UnlinkCaseCTIReport(r.PathValue("case_id"), session.UserID, r.PathValue("report_id")); err != nil {
		mapCaseError(w, err)
		return
	} else {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"case_id": r.PathValue("case_id"), "report_id": r.PathValue("report_id"), "unlinked": unlinked})
	}
}

func handleListReportCases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	limit, offset := parseM7BLimitOffset(r)
	rows, total, err := ListReportCases(r.PathValue("report_id"), session.UserID, limit, offset)
	if err != nil {
		mapCaseError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"cases": rows, "total": total, "limit": limit, "offset": offset})
}

func handleCreateCaseFromReport(w http.ResponseWriter, r *http.Request) {
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
		Title          string `json:"title"`
		Description    string `json:"description"`
		Priority       string `json:"priority"`
		Severity       string `json:"severity"`
		IdempotencyKey string `json:"idempotency_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Title == "" || req.IdempotencyKey == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "title and idempotency_key required")
		return
	}
	caseID, created, linked, err := CreateCaseFromReport(session.UserID, r.PathValue("report_id"), req.Title, req.Description, req.IdempotencyKey, req.Priority, req.Severity)
	if err != nil {
		if errors.Is(err, ErrIdempotencyConflict) {
			writeJSONError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "same idempotency key with different payload")
			return
		}
		mapCaseError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if created {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"case_id": caseID, "report_id": r.PathValue("report_id"), "linked": linked, "created": created})
}

func mapCaseError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrSchemaNotReady):
		writeJSONError(w, http.StatusServiceUnavailable, "SCHEMA_NOT_READY", "M7 schema not applied")
	case errors.Is(err, ErrCaseNotFound), errors.Is(err, ErrReportNotFound):
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "not found")
	case errors.Is(err, ErrCaseAccessDenied), errors.Is(err, ErrReportAccessDenied), errors.Is(err, ErrDraftPermissionDenied), errors.Is(err, ErrClientAccessDenied):
		writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "access denied")
	case errors.Is(err, ErrCaseArchived):
		writeJSONError(w, http.StatusConflict, "CASE_ARCHIVED", "case is archived")
	case errors.Is(err, ErrIdempotencyConflict):
		writeJSONError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "idempotency conflict")
	default:
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
	}
}
