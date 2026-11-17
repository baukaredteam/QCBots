package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

func parseRelevanceLimit(r *http.Request) (limit, offset int) {
	return parseM7BLimitOffset(r)
}

var _ = strconv.Atoi

func handleAssessRelevance(w http.ResponseWriter, r *http.Request) {
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
		IdempotencyKey string `json:"idempotency_key"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	a, created, err := AssessRelevance(session.UserID, r.PathValue("report_id"), r.PathValue("client_id"), req.IdempotencyKey)
	if err != nil {
		if errors.Is(err, ErrRelevanceIdempotencyConflict) {
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
	json.NewEncoder(w).Encode(map[string]interface{}{"assessment": a, "created": created, "status": a.Status})
}

func handleGetRelevance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	reportID, clientID := r.PathValue("report_id"), r.PathValue("client_id")
	report, err := globalDB.GetCTIReport(reportID)
	if err != nil || report == nil {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "report not found")
		return
	}
	if report.ClientID != clientID || !hasClientGrant(session.UserID, clientID) {
		writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "access denied")
		return
	}
	a, err := LatestCompletedAssessment(reportID, clientID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "no completed assessment")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a)
}

func handleListRelevantReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	clientID := r.PathValue("client_id")
	if !hasClientGrant(session.UserID, clientID) {
		writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "access denied")
		return
	}
	limit, offset := parseM7BLimitOffset(r)
	// Latest MATCH assessment per report for this client (grant + tenant scoped).
	rows, err := globalDB.Query(`SELECT a.report_id, a.assessment_id, a.created_at
		FROM relevance_assessments a
		WHERE a.client_id = ? AND a.status = 'COMPLETED'
		  AND a.report_id IN (SELECT report_id FROM cti_reports WHERE client_id = ?)
		ORDER BY a.created_at DESC, a.rowid DESC`, clientID, clientID)
	if err != nil {
		mapCaseError(w, err)
		return
	}
	defer rows.Close()
	type cand struct{ reportID, assessmentID string }
	var cands []cand
	seen := map[string]bool{}
	for rows.Next() {
		var c cand
		var at string
		if err := rows.Scan(&c.reportID, &c.assessmentID, &at); err != nil {
			mapCaseError(w, err)
			return
		}
		if seen[c.reportID] {
			continue
		}
		seen[c.reportID] = true
		cands = append(cands, c)
	}
	rows.Close()
	// Filter to MATCH-in-any-dimension (paginate AFTER filter).
	out := []map[string]interface{}{}
	for _, c := range cands {
		a, err := GetRelevanceAssessment(c.assessmentID)
		if err != nil {
			continue
		}
		match := false
		for _, f := range a.Findings {
			if f.Verdict == "MATCH" {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		out = append(out, map[string]interface{}{"report_id": c.reportID, "assessment_id": c.assessmentID, "status": a.Status})
	}
	total := len(out)
	start := offset
	if start > len(out) {
		start = len(out)
	}
	end := start + limit
	if end > len(out) {
		end = len(out)
	}
	if out == nil {
		out = []map[string]interface{}{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"reports": out[start:end], "total": total, "limit": limit, "offset": offset})
}

func handleReviewRelevance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	role, err := globalDB.GetUserRole(session.UserID)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "user not found")
		return
	}
	rp, ok := GetPermission(role)
	if !ok || !rp.CanReviewArtifact {
		writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}
	var req struct {
		AssessmentID    string `json:"assessment_id"`
		Dimension       string `json:"dimension"`
		OriginalVerdict string `json:"original_verdict"`
		OverrideVerdict string `json:"override_verdict"`
		Reason          string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AssessmentID == "" || req.Dimension == "" || req.Reason == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "assessment_id, dimension and reason required")
		return
	}
	// Tenant binding: path report/client must match the assessment, and the
	// reviewer must hold a grant for that client (foreign combos rejected).
	reportID, clientID := r.PathValue("report_id"), r.PathValue("client_id")
	assessment, err := GetRelevanceAssessment(req.AssessmentID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "assessment not found")
		return
	}
	if assessment.ReportID != reportID || assessment.ClientID != clientID || !hasClientGrant(session.UserID, clientID) {
		writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "access denied")
		return
	}
	// Original verdict is validated by the DB trigger against the computed finding.
	reviewID := newID("review")
	if _, err := globalDB.Exec(`INSERT INTO relevance_reviews (review_id, assessment_id, reviewer_id, dimension, original_verdict, override_verdict, reason, reviewed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`, reviewID, req.AssessmentID, session.UserID, req.Dimension, req.OriginalVerdict, req.OverrideVerdict, req.Reason); err != nil {
		writeJSONError(w, http.StatusUnprocessableEntity, "REVIEW_REJECTED", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"review_id": reviewID})
}
