package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// m7bInternalKey returns a collision-resistant internal M6 idempotency key scoped
// to the M7-B user+operation. Length-ambiguous concatenation is avoided by hashing:
// two different (user,key) pairs cannot produce the same internal identity, and an
// ordinary M6 key cannot impersonate an M7-B operation (different namespace + hash).
func m7bInternalKey(userID, idempotencyKey string) string {
	sum := sha256.Sum256([]byte(userID + "\x00" + idempotencyKey))
	return "m7b_" + hex.EncodeToString(sum[:])
}

// M7-B: CTI Report <-> Research Case links.
// Case access via GetResearchCase (M6 semantics); report access via explicit
// client grant (user_authorized_clients) for every role including ADMINISTRATOR.
// Linking never creates grants and never widens visibility.

var (
	ErrReportNotFound     = errors.New("REPORT_NOT_FOUND")
	ErrReportAccessDenied = errors.New("REPORT_ACCESS_DENIED")
)

func requireM7Schema() error {
	if err := requireM6Schema(); err != nil {
		return err
	}
	var n int
	if err := globalDB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='case_cti_reports'`).Scan(&n); err != nil || n == 0 {
		return ErrSchemaNotReady
	}
	return nil
}

type LinkedCTIReport struct {
	CaseID   string `json:"case_id,omitempty"`
	ReportID string `json:"report_id"`
	Title    string `json:"title,omitempty"`
	ClientID string `json:"client_id"`
	Status   string `json:"status,omitempty"`
	LinkedAt string `json:"linked_at,omitempty"`
	LinkedBy string `json:"linked_by,omitempty"`
}

func getReportClient(reportID string) (string, error) {
	var clientID string
	err := globalDB.QueryRow(`SELECT client_id FROM cti_reports WHERE report_id = ?`, reportID).Scan(&clientID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", ErrReportNotFound
		}
		return "", fmt.Errorf("querying report client: %w", err)
	}
	return clientID, nil
}

// requireReportAccess checks report existence + explicit client grant.
// Internal DB errors are preserved (not converted to NotFound).
func requireReportAccess(userID, reportID string) (string, error) {
	clientID, err := getReportClient(reportID)
	if err != nil {
		if errors.Is(err, ErrReportNotFound) {
			return "", ErrReportNotFound
		}
		return "", err
	}
	if !hasClientGrant(userID, clientID) {
		return "", ErrReportAccessDenied
	}
	return clientID, nil
}

// requireMutation checks CanCreateCTI (service-level, in addition to route middleware).
func requireMutation(userID string) error {
	role, err := globalDB.GetUserRole(userID)
	if err != nil {
		return fmt.Errorf("getting user role: %w", err)
	}
	rp, ok := GetPermission(role)
	if !ok || !rp.CanCreateCTI {
		return ErrDraftPermissionDenied
	}
	return nil
}

// LinkCaseCTIReport links a report to a case (idempotent, atomic with activity).
// Returns created=true only for a newly inserted link (HTTP 201), false for replay (200).
func LinkCaseCTIReport(caseID, userID, reportID string) (bool, error) {
	if err := requireM7Schema(); err != nil {
		return false, err
	}
	if err := requireMutation(userID); err != nil {
		return false, err
	}
	caseObj, err := GetResearchCase(caseID, userID)
	if err != nil {
		return false, err
	}
	if caseObj.Status == "ARCHIVED" {
		return false, ErrCaseArchived
	}
	reportClient, err := requireReportAccess(userID, reportID)
	if err != nil {
		return false, err
	}
	tx, err := globalDB.Begin()
	if err != nil {
		return false, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT OR IGNORE INTO case_cti_reports (case_id, report_id, client_id, linked_by)
		VALUES (?, ?, ?, ?)`, caseID, reportID, reportClient, userID)
	if err != nil {
		return false, fmt.Errorf("linking report: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return false, nil // idempotent repeat: no new activity
	}
	actID, _ := GenerateCaseID()
	if _, err := tx.Exec(`INSERT INTO case_activity
		(activity_id, case_id, user_id, action, visibility_scope, client_id, details, created_at)
		VALUES (?, ?, ?, 'report_linked', 'CLIENT', ?, ?, datetime('now'))`,
		actID, caseID, userID, reportClient, reportID); err != nil {
		return false, fmt.Errorf("recording report link activity: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// UnlinkCaseCTIReport removes a link (idempotent). Returns unlinked=true only on actual change.
func UnlinkCaseCTIReport(caseID, userID, reportID string) (bool, error) {
	if err := requireM7Schema(); err != nil {
		return false, err
	}
	if err := requireMutation(userID); err != nil {
		return false, err
	}
	caseObj, err := GetResearchCase(caseID, userID)
	if err != nil {
		return false, err
	}
	if caseObj.Status == "ARCHIVED" {
		return false, ErrCaseArchived
	}
	reportClient, err := requireReportAccess(userID, reportID)
	if err != nil {
		return false, err
	}
	tx, err := globalDB.Begin()
	if err != nil {
		return false, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.Exec(`DELETE FROM case_cti_reports WHERE case_id = ? AND report_id = ?`, caseID, reportID)
	if err != nil {
		return false, fmt.Errorf("unlinking report: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return false, nil // idempotent no-op
	}
	actID, _ := GenerateCaseID()
	if _, err := tx.Exec(`INSERT INTO case_activity
		(activity_id, case_id, user_id, action, visibility_scope, client_id, details, created_at)
		VALUES (?, ?, ?, 'report_unlinked', 'CLIENT', ?, ?, datetime('now'))`,
		actID, caseID, userID, reportClient, reportID); err != nil {
		return false, fmt.Errorf("recording report unlink activity: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// ListCaseCTIReports returns linked reports visible to the caller (grant-filtered).
func ListCaseCTIReports(caseID, userID string, limit, offset int) ([]LinkedCTIReport, int, error) {
	if err := requireM7Schema(); err != nil {
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
	if err := globalDB.QueryRow(`SELECT COUNT(*) FROM case_cti_reports WHERE case_id = ? AND client_id IN (SELECT client_id FROM user_authorized_clients WHERE user_id = ?)`, caseID, userID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := globalDB.Query(`SELECT l.case_id, l.report_id, l.client_id, l.linked_at, l.linked_by, r.title, r.status
		FROM case_cti_reports l JOIN cti_reports r ON r.report_id = l.report_id
		WHERE l.case_id = ? AND l.client_id IN (SELECT client_id FROM user_authorized_clients WHERE user_id = ?)
		ORDER BY l.linked_at, l.report_id LIMIT ? OFFSET ?`, caseID, userID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []LinkedCTIReport{}
	for rows.Next() {
		var l LinkedCTIReport
		var title, status string
		if err := rows.Scan(&l.CaseID, &l.ReportID, &l.ClientID, &l.LinkedAt, &l.LinkedBy, &title, &status); err != nil {
			return nil, 0, err
		}
		l.Title, l.Status = title, status
		out = append(out, l)
	}
	return out, total, rows.Err()
}

// ListReportCases returns cases linked to a report, each gated by case access.
func ListReportCases(reportID, userID string, limit, offset int) ([]LinkedCTIReport, int, error) {
	if err := requireM7Schema(); err != nil {
		return nil, 0, err
	}
	if _, err := requireReportAccess(userID, reportID); err != nil {
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
	rows, err := globalDB.Query(`SELECT case_id, report_id, client_id, linked_at, linked_by
		FROM case_cti_reports WHERE report_id = ? AND client_id IN (SELECT client_id FROM user_authorized_clients WHERE user_id = ?)
		ORDER BY linked_at, case_id`, reportID, userID)
	if err != nil {
		return nil, 0, err
	}
	// Materialize rows first: per-row case-access checks below query the DB,
	// which would deadlock on MaxOpenConns(1) while rows holds the connection.
	var links []LinkedCTIReport
	for rows.Next() {
		var l LinkedCTIReport
		if err := rows.Scan(&l.CaseID, &l.ReportID, &l.ClientID, &l.LinkedAt, &l.LinkedBy); err != nil {
			rows.Close()
			return nil, 0, err
		}
		links = append(links, l)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, 0, err
	}
	rows.Close()
	// Filter inaccessible cases BEFORE pagination.
	// Authorization denials hide the row; unexpected DB errors abort (never silently hide).
	var visible []LinkedCTIReport
	for _, l := range links {
		// Reverse lookup must also check case access per row; hide inaccessible cases.
		if _, err := GetResearchCase(l.CaseID, userID); err != nil {
			if errors.Is(err, ErrCaseAccessDenied) || errors.Is(err, ErrCaseNotFound) {
				continue
			}
			return nil, 0, err
		}
		if err := globalDB.QueryRow(`SELECT title, status FROM research_cases WHERE case_id = ?`, l.CaseID).Scan(&l.Title, &l.Status); err != nil {
			return nil, 0, fmt.Errorf("querying linked case title: %w", err)
		}
		visible = append(visible, l)
	}
	total := len(visible)
	// Apply LIMIT/OFFSET only to accessible rows.
	start := offset
	if start > len(visible) {
		start = len(visible)
	}
	end := start + limit
	if end > len(visible) {
		end = len(visible)
	}
	if visible == nil {
		visible = []LinkedCTIReport{}
	}
	return visible[start:end], total, nil
}

// CreateCaseFromReport atomically creates (or adopts) a case and links the report.
// One SQL transaction covers case insert + participant + link + activity + M7-B idem row;
// any failure rolls back all of it. Idempotent replay returns the existing case.
// Returns (caseID, created, linked, err): created=true only for a newly created
// case+link (HTTP 201), linked reflects the CURRENT link state after the call
// (a replay after explicit Unlink returns linked=false and does NOT reinsert).
// M7-B scope: (user_id, idempotency_key) -> (case, report, payload_hash incl. report_id).
// M6 casePayloadHash (without report_id) is not reused for the M7-B fingerprint.
func CreateCaseFromReport(userID, reportID, title, description, idempotencyKey, priority, severity string) (string, bool, bool, error) {
	if err := requireM7Schema(); err != nil {
		return "", false, false, err
	}
	reportClient, err := requireReportAccess(userID, reportID)
	if err != nil {
		return "", false, false, err
	}
	role, err := globalDB.GetUserRole(userID)
	if err != nil {
		return "", false, false, fmt.Errorf("getting user role: %w", err)
	}
	rp, ok := GetPermission(role)
	if !ok || !rp.CanCreateCTI {
		return "", false, false, ErrDraftPermissionDenied
	}
	if strings.TrimSpace(title) == "" {
		return "", false, false, fmt.Errorf("title required")
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		return "", false, false, fmt.Errorf("idempotency_key required")
	}
	fp := casePayloadHash(title, description, reportClient, priority, severity) + ":" + reportID
	for attempt := 0; attempt < 3; attempt++ {
		caseID, created, linked, err := createCaseFromReportOnce(userID, reportID, reportClient, title, description, idempotencyKey, priority, severity, fp)
		if err != nil {
			if errors.Is(err, ErrIdempotencyConflict) {
				// Concurrent winner committed between our check and insert:
				// re-read and decide EXISTING vs 409.
				if existing, ok := lookupCreateOp(userID, idempotencyKey); ok {
					if existing.reportID != reportID || existing.payloadHash != fp {
						return "", false, false, ErrIdempotencyConflict
					}
					if _, err := GetResearchCase(existing.caseID, userID); err != nil {
						return "", false, false, err
					}
					linked := isReportLinked(existing.caseID, reportID)
					return existing.caseID, false, linked, nil
				}
			}
			return "", false, false, err
		}
		return caseID, created, linked, nil
	}
	return "", false, false, fmt.Errorf("concurrent create-in-progress, retry")
}

func isReportLinked(caseID, reportID string) bool {
	var n int
	if err := globalDB.QueryRow(`SELECT COUNT(*) FROM case_cti_reports WHERE case_id = ? AND report_id = ?`, caseID, reportID).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

type createOpRow struct {
	caseID       string
	reportID     string
	payloadHash  string
}

func lookupCreateOp(userID, key string) (createOpRow, bool) {
	var r createOpRow
	err := globalDB.QueryRow(`SELECT case_id, report_id, payload_hash FROM case_cti_create_ops WHERE user_id = ? AND idempotency_key = ? LIMIT 1`, userID, key).Scan(&r.caseID, &r.reportID, &r.payloadHash)
	if err != nil {
		return r, false
	}
	return r, true
}

func createCaseFromReportOnce(userID, reportID, reportClient, title, description, idempotencyKey, priority, severity, fp string) (string, bool, bool, error) {
	// Pre-check outside the tx (avoids nested queries on MaxOpenConns(1)).
	var preCase, preReport, preHash string
	preErr := globalDB.QueryRow(`SELECT case_id, report_id, payload_hash FROM case_cti_create_ops WHERE user_id = ? AND idempotency_key = ? LIMIT 1`, userID, idempotencyKey).Scan(&preCase, &preReport, &preHash)
	if preErr == nil {
		if preReport != reportID || preHash != fp {
			return "", false, false, ErrIdempotencyConflict
		}
		if _, err := GetResearchCase(preCase, userID); err != nil {
			return "", false, false, err
		}
		// Replay: return the ACTUAL current linked state. Never silently reinsert
		// a link removed by a later explicit Unlink; no new activity.
		return preCase, false, isReportLinked(preCase, reportID), nil
	}
	tx, err := globalDB.Begin()
	if err != nil {
		return "", false, false, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()
	// M7-B idempotency first (per-user scope, re-checked inside tx for races).
	var exCase, exReport, exHash string
	err = tx.QueryRow(`SELECT case_id, report_id, payload_hash FROM case_cti_create_ops WHERE user_id = ? AND idempotency_key = ? LIMIT 1`, userID, idempotencyKey).Scan(&exCase, &exReport, &exHash)
	if err == nil {
		if exReport != reportID || exHash != fp {
			return "", false, false, ErrIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return "", false, false, err
		}
		return exCase, false, isReportLinked(exCase, reportID), nil
	}
	// Collision-resistant internal M6 key scoped to M7-B user+operation.
	internalKey := m7bInternalKey(userID, idempotencyKey)
	caseID, _, err := createResearchCaseInTx(tx, userID, title, description, internalKey, reportClient, priority, severity)
	if err != nil {
		return "", false, false, err
	}
	res, err := tx.Exec(`INSERT OR IGNORE INTO case_cti_reports (case_id, report_id, client_id, linked_by)
		VALUES (?, ?, ?, ?)`, caseID, reportID, reportClient, userID)
	if err != nil {
		return "", false, false, fmt.Errorf("linking report: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		actID, _ := GenerateCaseID()
		if _, err := tx.Exec(`INSERT INTO case_activity
			(activity_id, case_id, user_id, action, visibility_scope, client_id, details, created_at)
			VALUES (?, ?, ?, 'report_linked', 'CLIENT', ?, ?, datetime('now'))`,
			actID, caseID, userID, reportClient, reportID); err != nil {
			return "", false, false, fmt.Errorf("recording report link activity: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO case_cti_create_ops (idempotency_key, user_id, case_id, report_id, payload_hash)
		VALUES (?, ?, ?, ?, ?)`, idempotencyKey, userID, caseID, reportID, fp); err != nil {
		// UNIQUE on M7-B op row (concurrent winner): rollback and let caller re-check.
		return "", false, false, fmt.Errorf("recording create op: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", false, false, fmt.Errorf("committing transaction: %w", err)
	}
	return caseID, true, true, nil
}
