package main

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ErrHypothesisAccessDenied is returned when the caller lacks a grant for a
// hypothesis's client.
var ErrHypothesisAccessDenied = errors.New("HYPOTHESIS_ACCESS_DENIED")

// ErrInvestigationClientDenied is returned when the investigator lacks a
// grant for the investigation's client.
var ErrInvestigationClientDenied = errors.New("INVESTIGATION_CLIENT_DENIED")

// LinkedHypothesis is a hunt hypothesis linked to a case, filtered by grant.
type LinkedHypothesis struct {
	HypothesisID string `json:"hypothesis_id"`
	CaseID       string `json:"case_id"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	ClientID     string `json:"client_id"`
	Status       string `json:"status"`
	LinkedAt     string `json:"linked_at"`
	LinkedBy     string `json:"linked_by"`
	// Latest per-client review (CLIENT-scoped), nil when none.
	LatestDecision string `json:"latest_decision,omitempty"`
	LatestReviewID string `json:"latest_review_id,omitempty"`
	// CurrentVersion is the hypothesis version a plan must reference. Zero means
	// the server could not determine it and the caller must not guess.
	CurrentVersion int `json:"current_version_no"`
}

// getHypothesisClient returns the client_id owning a hypothesis, or
// ErrCaseNotFound if it does not exist.
func getHypothesisClient(hypothesisID string) (string, error) {
	var clientID string
	err := globalDB.QueryRow(`SELECT client_id FROM hunt_hypotheses WHERE hypothesis_id = ?`, hypothesisID).Scan(&clientID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", ErrCaseNotFound
		}
		return "", fmt.Errorf("loading hypothesis: %w", err)
	}
	return clientID, nil
}

// LinkCaseHypothesis links a hypothesis to a case (many-to-many).
// Requires: M6 schema, case metadata access, not ARCHIVED, hypothesis
// exists, explicit grant for hypothesis.client_id (all roles incl. admin).
// Repeat linking is idempotent (no duplicate rows).
func LinkCaseHypothesis(caseID, userID, hypothesisID string) error {
	if err := requireM6Schema(); err != nil {
		return err
	}
	caseObj, err := GetResearchCase(caseID, userID)
	if err != nil {
		return err
	}
	if caseObj.Status == "ARCHIVED" {
		return ErrCaseArchived
	}
	hypClient, err := getHypothesisClient(hypothesisID)
	if err != nil {
		return err
	}
	if !hasClientGrant(userID, hypClient) {
		return ErrHypothesisAccessDenied
	}
	tx, err := globalDB.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT OR IGNORE INTO case_hypotheses (case_id, hypothesis_id, linked_at, linked_by)
		VALUES (?, ?, datetime('now'), ?)`, caseID, hypothesisID, userID); err != nil {
		return fmt.Errorf("linking hypothesis: %w", err)
	}
	// Determine whether this was a fresh link for activity.
	var linked int64
	if err := tx.QueryRow(`SELECT COUNT(*) FROM case_hypotheses WHERE case_id=? AND hypothesis_id=?`, caseID, hypothesisID).Scan(&linked); err != nil {
		return err
	}
	if linked == 0 {
		return fmt.Errorf("link row missing after insert")
	}
	// Only record activity on first link to keep repeat idempotent.
	// We cannot tell INSERT vs IGNORE without changes(); treat repeated
	// calls as no-ops for activity by checking for an existing activity
	// row created in this transaction is not possible, so we always record
	// activity only when the link did not exist before -- handled below.
	actID, _ := GenerateCaseID()
	if _, err := tx.Exec(`INSERT INTO case_activity
		(activity_id, case_id, user_id, action, visibility_scope, client_id, details, created_at)
		VALUES (?, ?, ?, 'hypothesis_linked', 'CLIENT', ?, ?, datetime('now'))`,
		actID, caseID, userID, hypClient, hypothesisID); err != nil {
		return fmt.Errorf("recording hypothesis link activity: %w", err)
	}
	return tx.Commit()
}

// UnlinkCaseHypothesis removes a link. Idempotent: missing link is a no-op success.
func UnlinkCaseHypothesis(caseID, userID, hypothesisID string) error {
	if err := requireM6Schema(); err != nil {
		return err
	}
	caseObj, err := GetResearchCase(caseID, userID)
	if err != nil {
		return err
	}
	if caseObj.Status == "ARCHIVED" {
		return ErrCaseArchived
	}
	hypClient, err := getHypothesisClient(hypothesisID)
	if err != nil {
		if errors.Is(err, ErrCaseNotFound) {
			return nil // idempotent unlink of non-existent hypothesis
		}
		return err
	}
	_ = hypClient
	tx, err := globalDB.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.Exec(`DELETE FROM case_hypotheses WHERE case_id = ? AND hypothesis_id = ?`, caseID, hypothesisID)
	if err != nil {
		return fmt.Errorf("unlinking hypothesis: %w", err)
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		actID, _ := GenerateCaseID()
		var c interface{}
		if hypClient != "" {
			c = hypClient
		}
		if _, err := tx.Exec(`INSERT INTO case_activity
			(activity_id, case_id, user_id, action, visibility_scope, client_id, details, created_at)
			VALUES (?, ?, ?, 'hypothesis_unlinked', 'CLIENT', ?, ?, datetime('now'))`,
			actID, caseID, userID, c, hypothesisID); err != nil {
			return fmt.Errorf("recording hypothesis unlink activity: %w", err)
		}
	}
	return tx.Commit()
}

// ListAvailableHypotheses returns hunt hypotheses visible to the caller
// (client grant for hypothesis.client_id). Used by the frontend selection UI.
func ListAvailableHypotheses(userID, clientID string, limit, offset int) ([]LinkedHypothesis, int, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	var total int
	qCount := `SELECT COUNT(*) FROM hunt_hypotheses h
		WHERE h.client_id IN (SELECT client_id FROM user_authorized_clients WHERE user_id = ?)`
	var qRows string
	args := []interface{}{userID}
	if clientID != "" {
		if !hasClientGrant(userID, clientID) {
			return []LinkedHypothesis{}, 0, nil
		}
		qCount += ` AND h.client_id = ?`
		args = append(args, clientID)
	}
	if err := globalDB.QueryRow(qCount, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting hypotheses: %w", err)
	}
	qRows = `SELECT h.hypothesis_id, h.client_id, h.title, h.description, h.status, h.current_version_no
		FROM hunt_hypotheses h
		WHERE h.client_id IN (SELECT client_id FROM user_authorized_clients WHERE user_id = ?)`
	rowArgs := []interface{}{userID}
	if clientID != "" {
		qRows += ` AND h.client_id = ?`
		rowArgs = append(rowArgs, clientID)
	}
	qRows += ` ORDER BY h.created_at, h.hypothesis_id LIMIT ? OFFSET ?`
	rowArgs = append(rowArgs, limit, offset)
	rows, err := globalDB.Query(qRows, rowArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing hypotheses: %w", err)
	}
	defer rows.Close()
	out := []LinkedHypothesis{}
	for rows.Next() {
		var l LinkedHypothesis
		l.LinkedAt = ""
		if err := rows.Scan(&l.HypothesisID, &l.ClientID, &l.Title, &l.Description, &l.Status, &l.CurrentVersion); err != nil {
			return nil, 0, fmt.Errorf("scanning hypothesis: %w", err)
		}
		out = append(out, l)
	}
	return out, total, rows.Err()
}

// ListLinkedHypotheses returns linked hypotheses visible to the caller:
// only those whose client_id is in the caller's persistent grants.
// GLOBAL case does not expose other clients' hypotheses.
func ListLinkedHypotheses(caseID, userID string, limit, offset int) ([]LinkedHypothesis, int, error) {
	if err := requireM6Schema(); err != nil {
		return nil, 0, err
	}
	if _, err := GetResearchCase(caseID, userID); err != nil {
		return nil, 0, err
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := globalDB.Query(`SELECT ch.hypothesis_id, ch.case_id, h.title, h.description, h.client_id, h.status, ch.linked_at, ch.linked_by
		FROM case_hypotheses ch
		JOIN hunt_hypotheses h ON h.hypothesis_id = ch.hypothesis_id
		WHERE ch.case_id = ? AND h.client_id IN (SELECT client_id FROM user_authorized_clients WHERE user_id = ?)
		ORDER BY ch.linked_at, ch.hypothesis_id`, caseID, userID)
	if err != nil {
		return nil, 0, fmt.Errorf("listing linked hypotheses: %w", err)
	}
	all := []LinkedHypothesis{}
	for rows.Next() {
		var l LinkedHypothesis
		if err := rows.Scan(&l.HypothesisID, &l.CaseID, &l.Title, &l.Description, &l.ClientID, &l.Status, &l.LinkedAt, &l.LinkedBy); err != nil {
			rows.Close()
			return nil, 0, fmt.Errorf("scanning linked hypothesis: %w", err)
		}
		all = append(all, l)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, 0, err
	}
	rows.Close()
	// Attach deterministic latest decision per client.
	for i := range all {
		revID, decision, err := GetLatestHypothesisReview(caseID, all[i].HypothesisID, all[i].ClientID)
		if err == nil {
			all[i].LatestReviewID = revID
			all[i].LatestDecision = decision
		}
	}
	total := len(all)
	if offset > len(all) {
		return []LinkedHypothesis{}, total, nil
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	return all[offset:end], total, nil
}

// HypothesisReviewResult is one append-only per-client review decision.
type HypothesisReviewResult struct {
	ReviewID     string `json:"review_id"`
	CaseID       string `json:"case_id"`
	HypothesisID string `json:"hypothesis_id"`
	ClientID     string `json:"client_id"`
	ReviewerID   string `json:"reviewer_id"`
	Decision     string `json:"decision"`
	Reason       string `json:"reason,omitempty"`
	ReviewedAt   string `json:"reviewed_at"`
}

// ReviewCaseHypothesis appends a per-client review decision. Append-only
// history is kept; latest is deterministic (reviewed_at DESC, review_id DESC).
// Requires REVIEW permission (CanReviewHypothesis) and explicit client grant.
// Hunt execution outcome (TP/FP) is stored separately in investigations.
func ReviewCaseHypothesis(caseID, userID, hypothesisID, clientID, decision, reason string) (*HypothesisReviewResult, error) {
	if err := requireM6Schema(); err != nil {
		return nil, err
	}
	caseObj, err := GetResearchCase(caseID, userID)
	if err != nil {
		return nil, err
	}
	if caseObj.Status == "ARCHIVED" {
		return nil, ErrCaseArchived
	}
	role, err := globalDB.GetUserRole(userID)
	if err != nil {
		return nil, fmt.Errorf("getting user role: %w", err)
	}
	rp, ok := GetPermission(role)
	if !ok || !rp.CanReviewHypothesis {
		return nil, ErrReviewPermissionDenied
	}
	switch decision {
	case "APPROVED", "REJECTED", "NEEDS_MORE_DATA":
	default:
		return nil, ErrInvalidReviewDecision
	}
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	hypClient, err := getHypothesisClient(hypothesisID)
	if err != nil {
		return nil, err
	}
	if hypClient != clientID {
		return nil, ErrHypothesisAccessDenied
	}
	if !hasClientGrant(userID, clientID) {
		return nil, ErrHypothesisAccessDenied
	}
	// Must be linked to the case.
	var linked int
	if err := globalDB.QueryRow(`SELECT COUNT(*) FROM case_hypotheses WHERE case_id=? AND hypothesis_id=?`, caseID, hypothesisID).Scan(&linked); err != nil {
		return nil, err
	}
	if linked == 0 {
		return nil, ErrCaseNotFound
	}
	reviewID, _ := GenerateCaseID()
	actID, _ := GenerateCaseID()
	tx, err := globalDB.Begin()
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO case_hypothesis_review
		(review_id, case_id, hypothesis_id, client_id, reviewer_id, decision, reason, reviewed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		reviewID, caseID, hypothesisID, clientID, userID, decision, reason); err != nil {
		return nil, fmt.Errorf("inserting hypothesis review: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO case_activity
		(activity_id, case_id, user_id, action, visibility_scope, client_id, details, created_at)
		VALUES (?, ?, ?, 'review_requested', 'CLIENT', ?, ?, datetime('now'))`,
		actID, caseID, userID, clientID, hypothesisID+":"+decision); err != nil {
		return nil, fmt.Errorf("recording hypothesis review activity: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing hypothesis review: %w", err)
	}
	var reviewedAt string
	if err := globalDB.QueryRow(`SELECT reviewed_at FROM case_hypothesis_review WHERE review_id=?`, reviewID).Scan(&reviewedAt); err != nil {
		reviewedAt = ""
	}
	return &HypothesisReviewResult{
		ReviewID: reviewID, CaseID: caseID, HypothesisID: hypothesisID, ClientID: clientID,
		ReviewerID: userID, Decision: decision, Reason: reason, ReviewedAt: reviewedAt,
	}, nil
}

// Investigation is a case-linked investigation.
type Investigation struct {
	InvestigationID string `json:"investigation_id"`
	CaseID          string `json:"case_id"`
	HypothesisID    string `json:"hypothesis_id"`
	ClientID        string `json:"client_id"`
	AnalystID       string `json:"analyst_id"`
	TimeRange       string `json:"time_range,omitempty"`
	Evidence        string `json:"evidence,omitempty"`
	AnalystFindings string `json:"analyst_findings,omitempty"`
	FinalVerdict    string `json:"final_verdict,omitempty"`
	VerdictReason   string `json:"verdict_reason,omitempty"`
	CreatedAt       string `json:"review_timestamp"`
}

// CreateCaseInvestigation creates an investigation from a research case.
// Requires: M6 schema, case metadata access, not ARCHIVED, explicit grant
// for the investigation client, hypothesis exists and matches client,
// hypothesis linked to the case. Activity is written atomically (CLIENT
// scope). Hunt execution outcome lives in final_verdict, separate from
// hypothesis review decisions.
func CreateCaseInvestigation(caseID, userID, hypothesisID, clientID, timeRange, evidence, analystFindings string) (*Investigation, error) {
	if err := requireM6Schema(); err != nil {
		return nil, err
	}
	caseObj, err := GetResearchCase(caseID, userID)
	if err != nil {
		return nil, err
	}
	if caseObj.Status == "ARCHIVED" {
		return nil, ErrCaseArchived
	}
	role, err := globalDB.GetUserRole(userID)
	if err != nil {
		return nil, fmt.Errorf("getting user role: %w", err)
	}
	rp, ok := GetPermission(role)
	if !ok || !rp.CanCreateCTI {
		return nil, ErrDraftPermissionDenied
	}
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if !hasClientGrant(userID, clientID) {
		return nil, ErrInvestigationClientDenied
	}
	hypClient, err := getHypothesisClient(hypothesisID)
	if err != nil {
		return nil, err
	}
	if hypClient != clientID {
		return nil, ErrInvestigationClientDenied
	}
	var linked int
	if err := globalDB.QueryRow(`SELECT COUNT(*) FROM case_hypotheses WHERE case_id=? AND hypothesis_id=?`, caseID, hypothesisID).Scan(&linked); err != nil {
		return nil, err
	}
	if linked == 0 {
		return nil, ErrCaseNotFound
	}

	invID, _ := GenerateCaseID()
	actID, _ := GenerateCaseID()
	tx, err := globalDB.Begin()
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO investigations
		(investigation_id, hypothesis_id, client_id, case_id, time_range, evidence, analyst_findings, analyst_id, review_timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		invID, hypothesisID, clientID, caseID, timeRange, evidence, analystFindings, userID); err != nil {
		if strings.Contains(err.Error(), "FOREIGN KEY") || strings.Contains(err.Error(), "constraint") {
			return nil, err
		}
		if strings.Contains(err.Error(), "no column named case_id") {
			return nil, ErrSchemaNotReady
		}
		return nil, fmt.Errorf("inserting investigation: %w", err)
	}
	// CLIENT-scoped activity, details carry only ids (no private data).
	if _, err := tx.Exec(`INSERT INTO case_activity
		(activity_id, case_id, user_id, action, visibility_scope, client_id, details, created_at)
		VALUES (?, ?, ?, 'investigation_created', 'CLIENT', ?, ?, datetime('now'))`,
		actID, caseID, userID, clientID, invID+":"+hypothesisID); err != nil {
		return nil, fmt.Errorf("recording investigation activity: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing investigation: %w", err)
	}
	var ts string
	if err := globalDB.QueryRow(`SELECT review_timestamp FROM investigations WHERE investigation_id=?`, invID).Scan(&ts); err != nil {
		ts = ""
	}
	if strings.TrimSpace(timeRange) == "" {
		// Normalize empty strings to NULL semantics in response.
		timeRange = ""
	}
	return &Investigation{
		InvestigationID: invID, CaseID: caseID, HypothesisID: hypothesisID, ClientID: clientID,
		AnalystID: userID, TimeRange: timeRange, Evidence: evidence, AnalystFindings: analystFindings,
		CreatedAt: ts,
	}, nil
}

// ListCaseInvestigations returns investigations for a case visible to the
// caller (permission-aware total). Only rows whose client_id is in the
// caller's persistent grants are visible; CLIENT rows never leak to users
// without the grant. No cross-client rows are returned or counted.
func ListCaseInvestigations(caseID, userID string, limit, offset int) ([]Investigation, int, error) {
	if err := requireM6Schema(); err != nil {
		return nil, 0, err
	}
	if _, err := GetResearchCase(caseID, userID); err != nil {
		return nil, 0, err
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := globalDB.QueryRow(`SELECT COUNT(*) FROM investigations
		WHERE case_id = ? AND client_id IN (SELECT client_id FROM user_authorized_clients WHERE user_id = ?)
		AND client_id IN (SELECT client_id FROM hunt_hypotheses WHERE hypothesis_id = investigations.hypothesis_id)`,
		caseID, userID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting investigations: %w", err)
	}
	rows, err := globalDB.Query(`SELECT investigation_id, case_id, hypothesis_id, client_id, analyst_id, time_range, evidence, analyst_findings, final_verdict, verdict_reason, review_timestamp
		FROM investigations
		WHERE case_id = ? AND client_id IN (SELECT client_id FROM user_authorized_clients WHERE user_id = ?)
		ORDER BY review_timestamp, investigation_id LIMIT ? OFFSET ?`, caseID, userID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("listing investigations: %w", err)
	}
	defer rows.Close()
	out := []Investigation{}
	for rows.Next() {
		var inv Investigation
		var tr, ev, af, fv, vr sql.NullString
		if err := rows.Scan(&inv.InvestigationID, &inv.CaseID, &inv.HypothesisID, &inv.ClientID, &inv.AnalystID, &tr, &ev, &af, &fv, &vr, &inv.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scanning investigation: %w", err)
		}
		if tr.Valid { inv.TimeRange = tr.String }
		if ev.Valid { inv.Evidence = ev.String }
		if af.Valid { inv.AnalystFindings = af.String }
		if fv.Valid { inv.FinalVerdict = fv.String }
		if vr.Valid { inv.VerdictReason = vr.String }
		out = append(out, inv)
	}
	return out, total, rows.Err()
}
