package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ResearchCase represents a research case record.
type ResearchCase struct {
	CaseID         string `json:"case_id"`
	IdempotencyKey string `json:"idempotency_key"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	OwnerID        string `json:"owner_id"`
	Status         string `json:"status"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

// CaseListItem is a lightweight row for GET /api/v1/cases.
type CaseListItem struct {
	CaseID      string `json:"case_id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	OwnerID     string `json:"owner_id"`
	Status      string `json:"status"`
	Priority    string `json:"priority,omitempty"`
	Severity    string `json:"severity,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// Sentinel errors for research case operations.
var (
	// ErrDraftPermissionDenied is returned when the user lacks case creation (draft) permission.
	ErrDraftPermissionDenied = errors.New("DRAFT_PERMISSION_DENIED")
	// ErrClientAccessDenied is returned when the user is not authorized for the initial client.
	ErrClientAccessDenied = errors.New("CLIENT_ACCESS_DENIED")
	// ErrIdempotencyConflict is returned when the idempotency key already exists with different content.
	ErrIdempotencyConflict = errors.New("IDEMPOTENCY_CONFLICT")
	// ErrCaseNotFound is returned when a case does not exist.
	ErrCaseNotFound = errors.New("CASE_NOT_FOUND")
	// ErrCaseAccessDenied is returned when the caller cannot access the case.
	ErrCaseAccessDenied = errors.New("CASE_ACCESS_DENIED")
	// ErrArtifactPermissionDenied is returned when the user lacks artifact_create permission.
	ErrArtifactPermissionDenied = errors.New("ARTIFACT_PERMISSION_DENIED")
	// ErrGlobalArtifactClientData is returned when a GLOBAL-scoped artifact contains client data.
	ErrGlobalArtifactClientData = errors.New("GLOBAL_ARTIFACT_CLIENT_DATA")
	// ErrSchemaNotReady is returned by Stage D functions when migration 0005
	// has not been applied. Stage D never falls back to a degraded silent mode.
	ErrSchemaNotReady = errors.New("SCHEMA_NOT_READY")
	// ErrReviewPermissionDenied is returned when the caller lacks REVIEW permission.
	ErrReviewPermissionDenied = errors.New("REVIEW_PERMISSION_DENIED")
	// ErrInvalidReviewDecision is returned for an unknown review decision.
	ErrInvalidReviewDecision = errors.New("INVALID_REVIEW_DECISION")
)

// GenerateCaseID creates a server-generated case_id: 16 random bytes encoded as hex.
func GenerateCaseID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GetUserAuthorizedClientsFromDB returns the client IDs a user is authorized for,
// queried from the persistent user_authorized_clients table (migration 0004).
// This is the persistent replacement for the in-memory ClientAccessStore.
func GetUserAuthorizedClientsFromDB(userID string) ([]string, error) {
	rows, err := globalDB.Query(`SELECT client_id FROM user_authorized_clients WHERE user_id = ?`, userID)
	if err != nil {
		return nil, fmt.Errorf("querying user authorized clients: %w", err)
	}
	defer rows.Close()

	var clients []string
	for rows.Next() {
		var clientID string
		if err := rows.Scan(&clientID); err != nil {
			return nil, fmt.Errorf("scanning client id: %w", err)
		}
		clients = append(clients, clientID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating client rows: %w", err)
	}
	return clients, nil
}

// casePayloadHash returns the deterministic SHA-256 hash of the canonical
// logical payload for a create-case request. The hash covers the fields that
// define the logical operation; a reused idempotency key with a different
// hash must be rejected with 409. Serialization is length-prefixed and
// unambiguous even if fields contain '|', ':' or other separators.
func casePayloadHash(title, description, initialClientID, priority, severity string) string {
	fields := []string{title, description, initialClientID, priority, severity}
	var b strings.Builder
	b.WriteString("v2")
	for _, f := range fields {
		fmt.Fprintf(&b, "|%d:", len(f))
		b.WriteString(f)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// legacyCasePayloadHash is the pre-Stage-D canonical form. It is accepted on
// lookup only so existing rows created before the canonical change remain
// idempotency-compatible; new rows always use casePayloadHash (v2).
func legacyCasePayloadHash(title, description, initialClientID, priority, severity string) string {
	canonical := "v1\x00" + title + "\x00" + description + "\x00" + initialClientID + "\x00" + priority + "\x00" + severity
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// payloadHashMatches reports whether stored matches either the canonical v2
// hash or (for legacy rows) the v1 hash.
func payloadHashMatches(stored, title, description, initialClientID, priority, severity string) bool {
	if stored == casePayloadHash(title, description, initialClientID, priority, severity) {
		return true
	}
	if stored == legacyCasePayloadHash(title, description, initialClientID, priority, severity) {
		return true
	}
	return false
}

// createResearchCaseInTx inserts a case (or adopts the existing one on
// idempotency-key replay with matching payload) inside an existing tx.
// Caller owns the tx lifecycle (commit/rollback).
func createResearchCaseInTx(tx *sql.Tx, userID, title, description, idempotencyKey, initialClientID, priority, severity string) (string, bool, error) {
	caseID, err := GenerateCaseID()
	if err != nil {
		return "", false, fmt.Errorf("generating case id: %w", err)
	}
	payloadHash := casePayloadHash(title, description, initialClientID, priority, severity)
	var prioArg, sevArg, clientArg interface{}
	if priority != "" {
		prioArg = priority
	}
	if severity != "" {
		sevArg = severity
	}
	if initialClientID != "" {
		clientArg = initialClientID
	}
	hasMeta := false
	cols, qerr := tx.Query(`PRAGMA table_info(research_cases)`)
	if qerr == nil {
		for cols.Next() {
			var cid, notnull, pk int
			var name, ctype string
			var dflt sql.NullString
			if cols.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk) == nil && name == "priority" {
				hasMeta = true
				break
			}
		}
		cols.Close()
	}
	var execErr error
	if hasMeta {
		_, execErr = tx.Exec(`INSERT INTO research_cases
			(case_id, idempotency_key, title, description, owner_id, status, priority, severity, payload_hash, primary_client, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, datetime('now'), datetime('now'))`,
			caseID, idempotencyKey, title, description, userID, prioArg, sevArg, payloadHash, clientArg)
	} else {
		_, execErr = tx.Exec(`INSERT INTO research_cases
			(case_id, idempotency_key, title, description, owner_id, status, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, 'OPEN', datetime('now'), datetime('now'))`,
			caseID, idempotencyKey, title, description, userID)
	}
	if execErr != nil {
		if isUniqueConstraintError(execErr) {
			if !hasMeta {
				// Pre-0005 schema: no payload_hash column; preserve legacy
				// behavior (conflict on any key reuse).
				return "", false, ErrIdempotencyConflict
			}
			// Idempotent replay: adopt existing case if payload matches.
			var existingID, storedHash string
			if err := tx.QueryRow(`SELECT case_id, COALESCE(payload_hash,'') FROM research_cases WHERE idempotency_key = ?`, idempotencyKey).Scan(&existingID, &storedHash); err != nil {
				return "", false, err
			}
			if !payloadHashMatches(storedHash, title, description, initialClientID, priority, severity) {
				return "", false, ErrIdempotencyConflict
			}
			return existingID, true, nil
		}
		return "", false, fmt.Errorf("inserting research case: %w", execErr)
	}
	if initialClientID != "" {
		grantID, err := GenerateCaseID()
		if err != nil {
			return "", false, fmt.Errorf("generating grant id: %w", err)
		}
		if _, err := tx.Exec(`INSERT INTO case_authorized_participants
			(grant_id, case_id, user_id, role_in_case, granted_at)
			VALUES (?, ?, ?, 'OWNER', datetime('now'))`,
			grantID, caseID, userID); err != nil {
			return "", false, fmt.Errorf("inserting case participant: %w", err)
		}
	}
	return caseID, false, nil
}

// CreateResearchCaseEx is the full create path with priority/severity.
// Priority and severity are inserted in the same transaction (atomic),
// avoiding a separate UPDATE that could diverge on retries.
func CreateResearchCaseEx(userID, title, description, idempotencyKey, initialClientID, priority, severity string) (string, error) {
	if priority == "" {
		priority = ""
	}
	if severity == "" {
		severity = ""
	}
	// 1. Draft permission check (RBAC).
	role, err := globalDB.GetUserRole(userID)
	if err != nil {
		return "", fmt.Errorf("getting user role: %w", err)
	}
	rp, ok := GetPermission(role)
	if !ok {
		return "", fmt.Errorf("unknown role %q for user %q", role, userID)
	}
	if !rp.CanCreateCTI {
		return "", ErrDraftPermissionDenied
	}

	// 2. Client grant validation for initial_client_id.
	if initialClientID != "" {
		authorized, err := GetUserAuthorizedClientsFromDB(userID)
		if err != nil {
			return "", fmt.Errorf("checking client grant: %w", err)
		}
		granted := false
		for _, c := range authorized {
			if c == initialClientID {
				granted = true
				break
			}
		}
		if !granted {
			return "", ErrClientAccessDenied
		}
	}

	// 3. Begin transaction.
	tx, err := globalDB.Begin()
	if err != nil {
		return "", fmt.Errorf("beginning transaction: %w", err)
	}
	// Roll back on any error path (no partial changes). A no-op after a successful commit.
	defer tx.Rollback()

	// 4. Create (or adopt on idempotent replay) inside the tx.
	caseID, existed, err := createResearchCaseInTx(tx, userID, title, description, idempotencyKey, initialClientID, priority, severity)
	if err != nil {
		if errors.Is(err, ErrIdempotencyConflict) {
			return "", ErrIdempotencyConflict
		}
		return "", err
	}
	_ = existed

	// 6. Commit.
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("committing transaction: %w", err)
	}

	return caseID, nil
}

// CreateResearchCase atomically creates a research case.
//
// Logic:
//  1. Check draft permission (RBAC: CanCreateCTI).
//  2. If initialClientID is provided, verify the user has a grant for it.
//  3. Begin a transaction.
//  4. INSERT into research_cases (UNIQUE constraint on idempotency_key).
//  5. If initialClientID is provided, INSERT into case_authorized_participants as OWNER.
//  6. Commit. On any error, roll back (no partial changes).
func CreateResearchCase(userID, title, description, idempotencyKey, initialClientID string) (string, error) {
	return CreateResearchCaseEx(userID, title, description, idempotencyKey, initialClientID, "", "")
}

// isUniqueConstraintError reports whether err is a SQLite UNIQUE constraint violation.
func isUniqueConstraintError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// hasM6Schema reports whether migration 0005 has been applied.
func hasM6Schema() bool {
	db := globalDB
	if db == nil {
		return false
	}
	var cnt int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('case_notes','case_notes_revision','case_activity','case_hypotheses','case_hypothesis_review')`).Scan(&cnt); err != nil || cnt != 5 {
		return false
	}
	for _, tc := range []struct{ table, col string }{
		{"research_cases", "priority"},
		{"case_artifacts", "reviewed_by"},
		{"case_artifacts", "review_decision"},
		{"case_authorized_participants", "revoked_at"},
	} {
		var c int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, tc.table, tc.col).Scan(&c); err != nil || c == 0 {
			return false
		}
	}
	return true
}

func requireM6Schema() error {
	if !hasM6Schema() {
		return ErrSchemaNotReady
	}
	return nil
}

// hasClientGrant reports whether userID has an explicit grant for clientID
// in the persistent user_authorized_clients table. ADMINISTRATOR is not
// exempt: there is exactly one source of client grants.
func hasClientGrant(userID, clientID string) bool {
	clients, err := GetUserAuthorizedClientsFromDB(userID)
	if err != nil {
		return false
	}
	for _, c := range clients {
		if c == clientID {
			return true
		}
	}
	return false
}

// noteContainsClientData reports whether text contains any known client_id.
// Used to protect GLOBAL notes from including private client information.
func noteContainsClientData(text string) bool {
	rows, err := globalDB.Query(`SELECT client_id FROM clients`)
	if err != nil {
		return false
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	for _, id := range ids {
		if id != "" && strings.Contains(text, id) {
			return true
		}
	}
	return false
}

// revokedCol reports whether case_authorized_participants has the revoked_at
// column (migration 0005). Some older test DBs apply only up to 0004; the
// participant liveness predicate must adapt instead of failing.
func revokedCol(db *DB) bool {
	var cnt int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('case_authorized_participants') WHERE name = 'revoked_at'`).Scan(&cnt); err != nil {
		return false
	}
	return cnt > 0
}

// liveParticipantSQL returns a SQL fragment active-participant test:
// " AND revoked_at IS NULL" when the column exists, else "".
func liveParticipantSQL(db *DB) string {
	if revokedCol(db) {
		return " AND revoked_at IS NULL"
	}
	return ""
}

// GetResearchCase returns GLOBAL case metadata with a 4-level access check:
//
//	1. case exists (else ErrCaseNotFound)
//	2. caller is the owner
//	3. caller is an active (non-revoked) authorized participant
//	4. caller is an ADMINISTRATOR — GLOBAL metadata access only. This does
//	   NOT confer access to CLIENT-scoped content (artifacts, notes,
//	   activity, reviews, investigations); those are gated separately by
//	   persistent user_authorized_clients for every role including
//	   ADMINISTRATOR (see GetCaseContext / ListVisibleCaseActivity).
//
// Otherwise returns ErrCaseAccessDenied.
func GetResearchCase(caseID, userID string) (*ResearchCase, error) {
	var c ResearchCase
	var description sql.NullString
	err := globalDB.QueryRow(`SELECT case_id, idempotency_key, title, description, owner_id, status, created_at, updated_at
		FROM research_cases WHERE case_id = ?`, caseID).
		Scan(&c.CaseID, &c.IdempotencyKey, &c.Title, &description, &c.OwnerID, &c.Status, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrCaseNotFound
		}
		return nil, fmt.Errorf("querying research case: %w", err)
	}
	c.Description = description.String

	// Level 2: owner access.
	if c.OwnerID == userID {
		return &c, nil
	}

	// Level 3: authorized participant access (active participants only).
	var participantID string
	err = globalDB.QueryRow(`SELECT user_id FROM case_authorized_participants
		WHERE case_id = ? AND user_id = ?`+liveParticipantSQL(globalDB),
		caseID, userID).Scan(&participantID)
	if err == nil {
		return &c, nil
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("querying case participant: %w", err)
	}

	// Level 4: administrator global access.
	role, err := globalDB.GetUserRole(userID)
	if err != nil {
		return nil, fmt.Errorf("getting user role: %w", err)
	}
	rp, ok := GetPermission(role)
	if ok && rp.Role == "ADMINISTRATOR" {
		return &c, nil
	}

	return nil, ErrCaseAccessDenied
}

// CaseArtifact is a case artifact annotated with the caller's access level.
// Fields are populated only for artifacts the caller is authorized to see;
// denied artifacts carry minimal identifying metadata and an AccessStatus.
type CaseArtifact struct {
	ArtifactID              string `json:"artifact_id"`
	VisibilityScope         string `json:"visibility_scope"`
	ClientID                string `json:"client_id,omitempty"`
	DataClassification      string `json:"data_classification"`
	ProvenanceSource        string `json:"provenance_source"`
	ArtifactHash            string `json:"artifact_hash,omitempty"`
	SanitizedRepresentation string `json:"sanitized_representation,omitempty"`
	AccessStatus            string `json:"access_status"` // VISIBLE, DATA_TYPE_DENIED
	DetailLevel             string `json:"detail_level"`  // SUMMARY, FULL, NONE
}

// CaseContext is the authorized view of a research case.
// Artifacts are filtered by the 4-level access model.
type CaseContext struct {
	CaseID         string         `json:"case_id"`
	IdempotencyKey string         `json:"idempotency_key"`
	Title          string         `json:"title"`
	Description    string         `json:"description,omitempty"`
	OwnerID        string         `json:"owner_id"`
	Status         string         `json:"status"`
	CreatedAt      string         `json:"created_at"`
	UpdatedAt      string         `json:"updated_at"`
	Artifacts      []CaseArtifact `json:"artifacts"`
}

// errAccessDenied is the single generic error returned for any access failure
// in GetCaseContext. It deliberately does not distinguish "case not found"
// from "access denied" (no enumeration) nor reveal which artifact check failed.
var errAccessDenied = errors.New("access denied")

// GetCaseContext returns the authorized view of a case.
//
// 4-level access:
//  1. Case access (owner / participant / administrator) — reused from
//     GetResearchCase; any failure yields a generic access-denied error.
//  2. Client grant — artifacts for clients the user is not authorized for
//     are filtered out (no client name leaked).
//  3. Data type right (RBAC artifact_view) — denied artifacts are reported
//     as DATA_TYPE_DENIED with no content.
//  4. Detail level (summary vs full based on role).
func GetCaseContext(caseID, userID string) (*CaseContext, error) {
	// Level 1: case access + metadata. Any failure is a generic access denied
	// (no enumeration of whether the case exists).
	caseObj, err := GetResearchCase(caseID, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errAccessDenied, ErrCaseAccessDenied)
	}

	role, err := globalDB.GetUserRole(userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errAccessDenied, ErrCaseAccessDenied)
	}
	rp, _ := GetPermission(role)
	isAdmin := rp.Role == "ADMINISTRATOR"

	authorizedClients, err := GetUserAuthorizedClientsFromDB(userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errAccessDenied, ErrCaseAccessDenied)
	}

	rows, err := globalDB.Query(`SELECT artifact_id, visibility_scope, client_id, data_classification, provenance_source, artifact_hash, sanitized_representation
		FROM case_artifacts WHERE case_id = ?`, caseID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errAccessDenied, ErrCaseAccessDenied)
	}
	defer rows.Close()

	var artifacts []CaseArtifact
	for rows.Next() {
		var a CaseArtifact
		var clientID sql.NullString
		if err := rows.Scan(&a.ArtifactID, &a.VisibilityScope, &clientID, &a.DataClassification,
			&a.ProvenanceSource, &a.ArtifactHash, &a.SanitizedRepresentation); err != nil {
			return nil, fmt.Errorf("%s: %w", errAccessDenied, ErrCaseAccessDenied)
		}
		if clientID.Valid {
			a.ClientID = clientID.String
		}

		// Level 2a: client grant — filter out artifacts for unauthorized clients.
		// This applies to ADMINISTRATOR as well: persistent user_authorized_clients
		// is the single source of client grants; the administrator metadata
		// access in GetResearchCase never bypasses it for CLIENT-scoped content.
		if a.ClientID != "" {
			granted := false
			for _, c := range authorizedClients {
				if c == a.ClientID {
					granted = true
					break
				}
			}
			if !granted {
				continue
			}
		}

		// Level 2b: data type right (RBAC artifact_view).
		if !canViewDataClassification(rp, a.DataClassification) {
			artifacts = append(artifacts, CaseArtifact{
				ArtifactID:         a.ArtifactID,
				DataClassification: a.DataClassification,
				AccessStatus:       "DATA_TYPE_DENIED",
				DetailLevel:        "NONE",
			})
			continue
		}

		// Level 2c: detail level (summary vs full based on role).
		detailLevel := "SUMMARY"
		if isAdmin {
			detailLevel = "FULL"
		}

		artifacts = append(artifacts, CaseArtifact{
			ArtifactID:              a.ArtifactID,
			VisibilityScope:         a.VisibilityScope,
			ClientID:                a.ClientID,
			DataClassification:      a.DataClassification,
			ProvenanceSource:        a.ProvenanceSource,
			ArtifactHash:            a.ArtifactHash,
			SanitizedRepresentation: a.SanitizedRepresentation,
			AccessStatus:            "VISIBLE",
			DetailLevel:             detailLevel,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", errAccessDenied, ErrCaseAccessDenied)
	}

	return &CaseContext{
		CaseID:         caseObj.CaseID,
		IdempotencyKey: caseObj.IdempotencyKey,
		Title:          caseObj.Title,
		Description:    caseObj.Description,
		OwnerID:        caseObj.OwnerID,
		Status:         caseObj.Status,
		CreatedAt:      caseObj.CreatedAt,
		UpdatedAt:      caseObj.UpdatedAt,
		Artifacts:      artifacts,
	}, nil
}

// canViewDataClassification reports whether the given role may view an artifact
// with the given data classification (RBAC artifact_view).
//
//   - PUBLIC:   any authenticated user
//   - INTERNAL: CanViewCTI
//   - CONFIDENTIAL: CanCreateCTI (CTI_ANALYST and above)
//   - RESTRICTED: ADMINISTRATOR only
func canViewDataClassification(rp RolePermission, classification string) bool {
	switch classification {
	case "PUBLIC":
		return true
	case "INTERNAL":
		return rp.CanViewCTI
	case "CONFIDENTIAL":
		return rp.CanCreateCTI
	case "RESTRICTED":
		return rp.Role == "ADMINISTRATOR"
	default:
		return false
	}
}

// SearchCases returns cases the user can access (level 1), optionally filtered
// by status and client_id, with artifacts filtered by all 4 levels.
func SearchCases(userID string, statusFilter, clientIDFilter string, limit, offset int) ([]CaseContext, error) {
	role, err := globalDB.GetUserRole(userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errAccessDenied, ErrCaseAccessDenied)
	}
	rp, _ := GetPermission(role)
	isAdmin := rp.Role == "ADMINISTRATOR"

	authorizedClients, err := GetUserAuthorizedClientsFromDB(userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errAccessDenied, ErrCaseAccessDenied)
	}

	// client_id filter: caller must be authorized for the requested client.
	// ADMINISTRATOR is not exempt: explicit grant required for CLIENT scope.
	if clientIDFilter != "" {
		allowed := false
		for _, c := range authorizedClients {
			if c == clientIDFilter {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("%s: %w", errAccessDenied, ErrCaseAccessDenied)
		}
	}

	// Enumerate cases the caller can access (level 1 — GLOBAL metadata).
	var query string
	var args []interface{}
	if isAdmin {
		query = `SELECT case_id FROM research_cases c WHERE 1=1`
	} else {
		v := fmt.Sprintf(`SELECT DISTINCT c.case_id FROM research_cases c
			LEFT JOIN case_authorized_participants p ON p.case_id = c.case_id AND p.user_id = ?%s
			WHERE c.owner_id = ? OR p.user_id = ?`, liveParticipantSQL(globalDB))
		query = v
		args = []interface{}{userID, userID, userID}
	}
	if statusFilter != "" {
		query += ` AND c.status = ?`
		args = append(args, statusFilter)
	}
	if clientIDFilter != "" {
		query += ` AND EXISTS (SELECT 1 FROM case_artifacts a WHERE a.case_id = c.case_id AND a.client_id = ?)`
		args = append(args, clientIDFilter)
	}
	query += ` ORDER BY c.updated_at DESC`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	if offset > 0 {
		query += ` OFFSET ?`
		args = append(args, offset)
	}

	rows, err := globalDB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errAccessDenied, ErrCaseAccessDenied)
	}
	defer rows.Close()

	var caseIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("%s: %w", errAccessDenied, ErrCaseAccessDenied)
		}
		caseIDs = append(caseIDs, id)
	}

	var cases []CaseContext
	for _, id := range caseIDs {
		ctx, err := GetCaseContext(id, userID)
		if err != nil {
			// Per-call authorization: skip cases that became inaccessible.
			continue
		}
		cases = append(cases, *ctx)
	}
	return cases, nil
}

// ListResearchCases returns the cases the user can access (level-1: owner /
// participant / administrator, mirroring GetResearchCase) with pagination and
// a permission-aware total. Ordering is stable: updated_at DESC, case_id DESC.
// Optional filters (status, priority, client) narrow within the accessible set.
// The returned total uses the same predicate as the page query.
func ListResearchCases(userID, statusFilter, priorityFilter, clientIDFilter string, limit, offset int) ([]CaseListItem, int, error) {
	role, err := globalDB.GetUserRole(userID)
	if err != nil {
		return nil, 0, fmt.Errorf("getting user role: %w", err)
	}
	rp, ok := GetPermission(role)
	if !ok || !rp.CanViewCTI {
		return []CaseListItem{}, 0, nil
	}
	isAdmin := rp.Role == "ADMINISTRATOR"

	// Client-scope filter: requires explicit grant for every role,
	// including ADMINISTRATOR (no bypass for CLIENT-scoped content).
	if clientIDFilter != "" {
		authorized, err := GetUserAuthorizedClientsFromDB(userID)
		if err != nil {
			return nil, 0, err
		}
		allowed := false
		for _, c := range authorized {
			if c == clientIDFilter {
				allowed = true
				break
			}
		}
		if !allowed {
			return []CaseListItem{}, 0, nil
		}
	}

	where := []string{"1=1"}
	args := []interface{}{}
	if !isAdmin {
		where = append(where, fmt.Sprintf("(c.owner_id = ? OR EXISTS (SELECT 1 FROM case_authorized_participants p WHERE p.case_id = c.case_id AND p.user_id = ?%s))", liveParticipantSQL(globalDB)))
		args = append(args, userID, userID)
	}
	if statusFilter != "" {
		where = append(where, "c.status = ?")
		args = append(args, statusFilter)
	}
	if priorityFilter != "" {
		where = append(where, "c.priority = ?")
		args = append(args, priorityFilter)
	}
	if clientIDFilter != "" {
		where = append(where, "EXISTS (SELECT 1 FROM case_artifacts a WHERE a.case_id = c.case_id AND a.client_id = ?)")
		args = append(args, clientIDFilter)
	}
	whereSQL := strings.Join(where, " AND ")

	var total int
	if err := globalDB.QueryRow("SELECT COUNT(*) FROM research_cases c WHERE "+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting cases: %w", err)
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
	q := "SELECT c.case_id, c.title, c.description, c.owner_id, c.status, c.priority, c.severity, c.created_at, c.updated_at " +
		"FROM research_cases c WHERE " + whereSQL + " ORDER BY c.updated_at DESC, c.case_id DESC LIMIT ? OFFSET ?"
	qArgs := append(append([]interface{}{}, args...), limit, offset)

	rows, err := globalDB.Query(q, qArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing cases: %w", err)
	}
	defer rows.Close()

	items := []CaseListItem{}
	for rows.Next() {
		var it CaseListItem
		var desc, prio, sev sql.NullString
		if err := rows.Scan(&it.CaseID, &it.Title, &desc, &it.OwnerID, &it.Status, &prio, &sev, &it.CreatedAt, &it.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("scanning case list item: %w", err)
		}
		if desc.Valid {
			it.Description = desc.String
		}
		if prio.Valid {
			it.Priority = prio.String
		}
		if sev.Valid {
			it.Severity = sev.String
		}
		items = append(items, it)
	}
	return items, total, rows.Err()
}

// GetLatestHypothesisReview returns the most recent review for a
// case/hypothesis/client triple. Ordering is deterministic:
// reviewed_at DESC, rowid DESC (insertion order tie-breaker for identical
// second-precision timestamps).
func GetLatestHypothesisReview(caseID, hypothesisID, clientID string) (string, string, error) {
	var reviewID, decision string
	err := globalDB.QueryRow(`SELECT review_id, decision FROM case_hypothesis_review
		WHERE case_id = ? AND hypothesis_id = ? AND client_id = ?
		ORDER BY reviewed_at DESC, rowid DESC LIMIT 1`,
		caseID, hypothesisID, clientID).Scan(&reviewID, &decision)
	return reviewID, decision, err
}

// CaseActivityRow is a visible case_activity record.
type CaseActivityRow struct {
	ActivityID      string `json:"activity_id"`
	CaseID          string `json:"case_id"`
	UserID          string `json:"user_id"`
	Action          string `json:"action"`
	VisibilityScope string `json:"visibility_scope"`
	ClientID        string `json:"client_id,omitempty"`
	Details         string `json:"details,omitempty"`
	CreatedAt       string `json:"created_at"`
}

// ListVisibleCaseActivity returns activity the caller may see.
// The visibility predicate is mandatory for every role including
// ADMINISTRATOR: GLOBAL rows are metadata and visible with case access;
// CLIENT rows additionally require a persistent grant for that client_id.
// Stage D HTTP handlers must call this helper (or the identical WHERE
// predicate) — direct SELECT on case_activity without the predicate is
// forbidden. The case must first pass GetResearchCase (metadata access).
func ListVisibleCaseActivity(caseID, userID string) ([]CaseActivityRow, error) {
	if _, err := GetResearchCase(caseID, userID); err != nil {
		return nil, err
	}
	rows, err := globalDB.Query(`SELECT activity_id, case_id, user_id, action, visibility_scope, client_id, details, created_at
		FROM case_activity
		WHERE case_id = ? AND (visibility_scope = 'GLOBAL'
			OR client_id IN (SELECT client_id FROM user_authorized_clients WHERE user_id = ?))
		ORDER BY created_at, activity_id`, caseID, userID)
	if err != nil {
		return nil, fmt.Errorf("querying case activity: %w", err)
	}
	defer rows.Close()

	out := []CaseActivityRow{}
	for rows.Next() {
		var a CaseActivityRow
		var clientID, details sql.NullString
		if err := rows.Scan(&a.ActivityID, &a.CaseID, &a.UserID, &a.Action, &a.VisibilityScope, &clientID, &details, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning case activity: %w", err)
		}
		if clientID.Valid {
			a.ClientID = clientID.String
		}
		if details.Valid {
			a.Details = details.String
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ErrInvalidTransition is returned when a requested status change is not allowed.
var ErrInvalidTransition = errors.New("INVALID_TRANSITION")

// ErrCaseArchived is returned when mutating an archived (terminal) case.
var ErrCaseArchived = errors.New("CASE_ARCHIVED")

// ErrNotCaseOwner is returned when a participant mutation is attempted by a non-owner.
var ErrNotCaseOwner = errors.New("NOT_CASE_OWNER")

// ErrParticipantNotFound is returned when no active participant row exists.
var ErrParticipantNotFound = errors.New("PARTICIPANT_NOT_FOUND")

// validCaseTransitions defines the allowed lifecycle graph (M6 spec §3).
var validCaseTransitions = map[string][]string{
	"OPEN":        {"IN_PROGRESS", "CLOSED"},
	"IN_PROGRESS": {"REVIEW", "CLOSED"},
	"REVIEW":      {"CLOSED", "ARCHIVED"},
	"CLOSED":      {"ARCHIVED"},
	"ARCHIVED":    {},
}

// TransitionCaseStatus moves a case through its lifecycle. `from` must be
// an allowed edge; REVIEW/CLOSED→ARCHIVED additionally requires
// ADMINISTRATOR. ARCHIVED is terminal. closeReason is recorded on
// CLOSED/ARCHIVED. The status update and the GLOBAL activity row are
// committed atomically; no other write is made when the transition is invalid.
func TransitionCaseStatus(caseID, userID, toStatus, closeReason string) error {
	caseObj, err := GetResearchCase(caseID, userID)
	if err != nil {
		return err
	}
	if caseObj.Status == "ARCHIVED" {
		return ErrCaseArchived
	}
	allowed := false
	for _, s := range validCaseTransitions[caseObj.Status] {
		if s == toStatus {
			allowed = true
			break
		}
	}
	if !allowed {
		return ErrInvalidTransition
	}
	if toStatus == "ARCHIVED" && (caseObj.Status == "REVIEW" || caseObj.Status == "CLOSED") {
		role, _ := globalDB.GetUserRole(userID)
		rp, _ := GetPermission(role)
		if rp.Role != "ADMINISTRATOR" {
			return ErrDraftPermissionDenied
		}
	}
	// REVIEW→CLOSED is also ADMINISTRATOR-only (M6 spec §3).
	if caseObj.Status == "REVIEW" && toStatus == "CLOSED" {
		role, _ := globalDB.GetUserRole(userID)
		rp, _ := GetPermission(role)
		if rp.Role != "ADMINISTRATOR" {
			return ErrDraftPermissionDenied
		}
	}

	tx, err := globalDB.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()

	if toStatus == "CLOSED" || toStatus == "ARCHIVED" {
		_, err = tx.Exec(`UPDATE research_cases SET status = ?, closed_at = datetime('now'), closed_by = ?, closed_reason = ?, updated_at = datetime('now') WHERE case_id = ?`,
			toStatus, userID, closeReason, caseID)
	} else {
		_, err = tx.Exec(`UPDATE research_cases SET status = ?, updated_at = datetime('now') WHERE case_id = ?`,
			toStatus, caseID)
	}
	if err != nil {
		return fmt.Errorf("updating case status: %w", err)
	}
	actID, _ := GenerateCaseID()
	if _, err := tx.Exec(`INSERT INTO case_activity (activity_id, case_id, user_id, action, visibility_scope, details, created_at)
		VALUES (?, ?, ?, 'status_changed', 'GLOBAL', ?, datetime('now'))`,
		actID, caseID, userID, caseObj.Status+"->"+toStatus); err != nil {
		return fmt.Errorf("recording status activity: %w", err)
	}
	return tx.Commit()
}

// --- Participants (Stage C) ---

// CaseParticipant is an active case_authorized_participants row.
type CaseParticipant struct {
	GrantID    string `json:"grant_id"`
	CaseID     string `json:"case_id"`
	UserID     string `json:"user_id"`
	RoleInCase string `json:"role_in_case"`
	GrantedAt  string `json:"granted_at"`
	RevokedAt  string `json:"revoked_at,omitempty"`
}

// ListCaseParticipants returns active (non-revoked) participants.
// Caller must have GLOBAL case metadata access.
func ListCaseParticipants(caseID, userID string) ([]CaseParticipant, error) {
	if _, err := GetResearchCase(caseID, userID); err != nil {
		return nil, err
	}
	rows, err := globalDB.Query(`SELECT grant_id, case_id, user_id, role_in_case, granted_at, revoked_at
		FROM case_authorized_participants WHERE case_id = ? AND revoked_at IS NULL
		ORDER BY granted_at, grant_id`, caseID)
	if err != nil {
		return nil, fmt.Errorf("listing participants: %w", err)
	}
	defer rows.Close()
	out := []CaseParticipant{}
	for rows.Next() {
		var p CaseParticipant
		var revoked sql.NullString
		if err := rows.Scan(&p.GrantID, &p.CaseID, &p.UserID, &p.RoleInCase, &p.GrantedAt, &revoked); err != nil {
			return nil, fmt.Errorf("scanning participant: %w", err)
		}
		if revoked.Valid {
			p.RevokedAt = revoked.String
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func requireCaseOwner(caseID, userID string) (*ResearchCase, error) {
	caseObj, err := GetResearchCase(caseID, userID)
	if err != nil {
		return nil, err
	}
	if caseObj.OwnerID != userID {
		return nil, ErrNotCaseOwner
	}
	return caseObj, nil
}

func requireNotArchived(caseObj *ResearchCase) error {
	if caseObj.Status == "ARCHIVED" {
		return ErrCaseArchived
	}
	return nil
}

// AddCaseParticipant grants a user case access. Owner only (EDIT+owner).
// Re-adding a revoked participant reactivates the existing row.
func AddCaseParticipant(caseID, actorID, targetUserID, roleInCase string) error {
	caseObj, err := requireCaseOwner(caseID, actorID)
	if err != nil {
		return err
	}
	if err := requireNotArchived(caseObj); err != nil {
		return err
	}
	if targetUserID == "" {
		return fmt.Errorf("user_id is required")
	}
	switch roleInCase {
	case "", "OWNER", "EDITOR", "VIEWER":
	default:
		return fmt.Errorf("invalid role_in_case")
	}
	if roleInCase == "" {
		roleInCase = "VIEWER"
	}
	var cnt int
	if err := globalDB.QueryRow(`SELECT COUNT(*) FROM users WHERE user_id = ?`, targetUserID).Scan(&cnt); err != nil {
		return err
	}
	if cnt == 0 {
		return ErrParticipantNotFound
	}

	var existingGrant string
	var revoked sql.NullString
	err = globalDB.QueryRow(`SELECT grant_id, revoked_at FROM case_authorized_participants
		WHERE case_id = ? AND user_id = ?`, caseID, targetUserID).Scan(&existingGrant, &revoked)
	if err == nil {
		if !revoked.Valid {
			return ErrInvalidTransition // already an active participant
		}
		_, err = globalDB.Exec(`UPDATE case_authorized_participants SET revoked_at = NULL, revoked_by = NULL, role_in_case = ? WHERE grant_id = ?`,
			roleInCase, existingGrant)
		if err != nil {
			return fmt.Errorf("reactivating participant: %w", err)
		}
		return recordParticipantActivity(caseID, actorID, "participant_added", targetUserID)
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("querying participant: %w", err)
	}
	grantID, err := GenerateCaseID()
	if err != nil {
		return err
	}
	if _, err := globalDB.Exec(`INSERT INTO case_authorized_participants (grant_id, case_id, user_id, role_in_case, granted_at)
		VALUES (?, ?, ?, ?, datetime('now'))`, grantID, caseID, targetUserID, roleInCase); err != nil {
		if isUniqueConstraintError(err) {
			return ErrInvalidTransition
		}
		return fmt.Errorf("inserting participant: %w", err)
	}
	return recordParticipantActivity(caseID, actorID, "participant_added", targetUserID)
}

func recordParticipantActivity(caseID, actorID, action, targetUserID string) error {
	actID, _ := GenerateCaseID()
	_, err := globalDB.Exec(`INSERT INTO case_activity (activity_id, case_id, user_id, action, visibility_scope, details, created_at)
		VALUES (?, ?, ?, ?, 'GLOBAL', ?, datetime('now'))`, actID, caseID, actorID, action, targetUserID)
	return err
}

// RemoveCaseParticipant soft-revokes a participant (never hard-deletes).
func RemoveCaseParticipant(caseID, actorID, targetUserID string) error {
	caseObj, err := requireCaseOwner(caseID, actorID)
	if err != nil {
		return err
	}
	if err := requireNotArchived(caseObj); err != nil {
		return err
	}
	if caseObj.OwnerID == targetUserID {
		return ErrNotCaseOwner
	}
	var grantID string
	err = globalDB.QueryRow(`SELECT grant_id FROM case_authorized_participants
		WHERE case_id = ? AND user_id = ? AND revoked_at IS NULL`, caseID, targetUserID).Scan(&grantID)
	if err != nil {
		return ErrParticipantNotFound
	}
	if _, err := globalDB.Exec(`UPDATE case_authorized_participants SET revoked_at = datetime('now'), revoked_by = ? WHERE grant_id = ?`, actorID, grantID); err != nil {
		return fmt.Errorf("revoking participant: %w", err)
	}
	return recordParticipantActivity(caseID, actorID, "participant_removed", targetUserID)
}

// computeArtifactHash returns the SHA-256 hex digest of the sanitized content.
// Used as the idempotency key for case artifacts.
func computeArtifactHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// AppendCaseArtifact adds a sanitized artifact to a research case.
//
// Logic:
//   1. Check case access (4-level via GetResearchCase).
//   2. Check artifact_create permission (RBAC CanCreateArtifact).
//   3. If visibilityScope=GLOBAL, reject if clientID is set or content contains client identifiers.
//   4. Server sanitizes raw content (client "sanitized" flag always ignored).
//   5. Compute artifactHash from sanitized content.
//   6. Idempotency: same artifact_hash returns existing artifact (UNIQUE constraint).
//   7. Insert into case_artifacts in a single transaction.
func AppendCaseArtifact(caseID, userID, visibilityScope, clientID, dataClassification, provenanceSource, rawContent string) (string, error) {
	// 1. Case access (4-level via GetResearchCase).
	if _, err := GetResearchCase(caseID, userID); err != nil {
		return "", err
	}

	// 2. artifact_create permission check (RBAC).
	role, err := globalDB.GetUserRole(userID)
	if err != nil {
		return "", fmt.Errorf("getting user role: %w", err)
	}
	rp, ok := GetPermission(role)
	if !ok {
		return "", fmt.Errorf("unknown role %q for user %q", role, userID)
	}
	if !rp.CanCreateArtifact {
		return "", ErrArtifactPermissionDenied
	}

	// 3. GLOBAL scope must not contain client data.
	if visibilityScope == "GLOBAL" {
		if clientID != "" {
			return "", ErrGlobalArtifactClientData
		}
		authorizedClients, err := GetUserAuthorizedClientsFromDB(userID)
		if err != nil {
			return "", fmt.Errorf("getting authorized clients: %w", err)
		}
		for _, c := range authorizedClients {
			if strings.Contains(rawContent, c) {
				return "", ErrGlobalArtifactClientData
			}
		}
	}

	// 4. Server sanitizes raw content; client "sanitized" flag is always ignored.
	authorizedClients, err := GetUserAuthorizedClientsFromDB(userID)
	if err != nil {
		return "", fmt.Errorf("getting authorized clients: %w", err)
	}
	sanitizedRepresentation, _, err := SanitizeContent(rawContent, userID, authorizedClients)
	if err != nil {
		return "", fmt.Errorf("sanitizing content: %w", err)
	}

	// 5. Compute artifact hash from sanitized content.
	artifactHash := computeArtifactHash(sanitizedRepresentation)

	// 6. Generate artifact ID.
	artifactID, err := GenerateCaseID()
	if err != nil {
		return "", fmt.Errorf("generating artifact id: %w", err)
	}

	// 7. Insert in a single transaction; UNIQUE constraint on artifact_hash gives idempotency.
	tx, err := globalDB.Begin()
	if err != nil {
		return "", fmt.Errorf("beginning transaction: %w", err)
	}
	// Roll back on any error path. A no-op after successful commit.
	defer tx.Rollback()

	var clientIDArg interface{}
	if clientID != "" {
		clientIDArg = clientID
	}

	_, err = tx.Exec(`INSERT INTO case_artifacts
		(artifact_id, case_id, visibility_scope, client_id, data_classification, provenance_source, artifact_hash, sanitized_representation, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		artifactID, caseID, visibilityScope, clientIDArg, dataClassification, provenanceSource, artifactHash, sanitizedRepresentation, userID)
	if err != nil {
		if isUniqueConstraintError(err) {
			// Idempotent: same hash → return existing artifact_id, no duplicate row.
			if rbErr := tx.Rollback(); rbErr != nil {
				return "", fmt.Errorf("rolling back transaction: %w", rbErr)
			}
			var existingID string
			err = globalDB.QueryRow(`SELECT artifact_id FROM case_artifacts WHERE artifact_hash = ?`, artifactHash).Scan(&existingID)
			if err != nil {
				return "", fmt.Errorf("finding existing artifact: %w", err)
			}
			return existingID, nil
		}
		return "", fmt.Errorf("inserting case artifact: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("committing transaction: %w", err)
	}

	return artifactID, nil
}

// --- Stage D: Artifacts Review, Notes, Activity ---

// ArtifactReviewResult is the stored review state after a successful review.
type ArtifactReviewResult struct {
	ArtifactID     string `json:"artifact_id"`
	CaseID         string `json:"case_id"`
	Decision       string `json:"decision"`
	Reason         string `json:"reason,omitempty"`
	ReviewedBy     string `json:"reviewed_by"`
	ReviewedAt     string `json:"reviewed_at"`
	ReviewStatus   string `json:"review_status"`
	VisibilityScope string `json:"visibility_scope"`
	ClientID       string `json:"client_id,omitempty"`
}

// ReviewCaseArtifact records a human review decision for an artifact.
//
// Contract (M6 Stage D-A):
//   - requires migration 0005 (ErrSchemaNotReady otherwise)
//   - caller must have GLOBAL case metadata access (GetResearchCase)
//   - caller must have REVIEW permission (CanReviewArtifact: ADMINISTRATOR
//     or REVIEWER roles) -- CTI_ANALYST explicitly lacks REVIEW
//   - CLIENT-scoped artifacts additionally require an explicit persistent
//     grant for that client_id (role does not exempt from tenant grant)
//   - classification must be viewable (canViewDataClassification)
//   - decision in APPROVED / REJECTED / NEEDS_MORE_DATA
//   - first submission wins: an already-reviewed artifact is not overwritten
//     (history is append-only via case_activity; NULL review_decision
//     is required for the first review)
//   - review UPDATE + activity INSERT are atomic; invalid input leaves no changes.
//   - GLOBAL activity details never carry CLIENT artifact content.
func ReviewCaseArtifact(caseID, userID, artifactID, decision, reason string) (*ArtifactReviewResult, error) {
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
	if !ok || !rp.CanReviewArtifact {
		return nil, ErrReviewPermissionDenied
	}
	switch decision {
	case "APPROVED", "REJECTED", "NEEDS_MORE_DATA":
	default:
		return nil, ErrInvalidReviewDecision
	}

	var visibilityScope, classification string
	var clientID sql.NullString
	err = globalDB.QueryRow(`SELECT visibility_scope, client_id, data_classification
		FROM case_artifacts WHERE artifact_id = ? AND case_id = ?`, artifactID, caseID).
		Scan(&visibilityScope, &clientID, &classification)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrCaseAccessDenied
		}
		return nil, fmt.Errorf("loading artifact: %w", err)
	}
	if clientID.Valid && clientID.String != "" && !hasClientGrant(userID, clientID.String) {
		return nil, ErrClientAccessDenied
	}
	if !canViewDataClassification(rp, classification) {
		return nil, ErrReviewPermissionDenied
	}

	// Map decision onto the legacy review_status column (no NEEDS_MORE_DATA there).
	reviewStatus := "PENDING"
	switch decision {
	case "APPROVED":
		reviewStatus = "APPROVED"
	case "REJECTED":
		reviewStatus = "REJECTED"
	}

	actID, _ := GenerateCaseID()
	tx, err := globalDB.Begin()
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`UPDATE case_artifacts
		SET reviewed_by = ?, reviewed_at = datetime('now'), review_reason = ?,
		    review_decision = ?, review_status = ?
		WHERE artifact_id = ? AND case_id = ? AND review_decision IS NULL`,
		userID, reason, decision, reviewStatus, artifactID, caseID); err != nil {
		return nil, fmt.Errorf("updating artifact review: %w", err)
	}
	var affected int64
	if err := tx.QueryRow(`SELECT changes()`).Scan(&affected); err != nil {
		return nil, fmt.Errorf("checking review update: %w", err)
	}
	if affected == 0 {
		return nil, ErrInvalidTransition // already reviewed
	}

	var clientArg interface{}
	if clientID.Valid && clientID.String != "" {
		clientArg = clientID.String
	}
	details := artifactID + ":" + decision
	if _, err := tx.Exec(`INSERT INTO case_activity
		(activity_id, case_id, user_id, action, visibility_scope, client_id, details, created_at)
		VALUES (?, ?, ?, 'artifact_reviewed', ?, ?, ?, datetime('now'))`,
		actID, caseID, userID, visibilityScope, clientArg, details); err != nil {
		return nil, fmt.Errorf("recording review activity: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing review: %w", err)
	}

	var reviewedAt string
	if err := globalDB.QueryRow(`SELECT reviewed_at FROM case_artifacts WHERE artifact_id = ?`, artifactID).Scan(&reviewedAt); err != nil {
		reviewedAt = ""
	}
	return &ArtifactReviewResult{
		ArtifactID: artifactID,
		CaseID: caseID,
		Decision: decision,
		Reason: reason,
		ReviewedBy: userID,
		ReviewedAt: reviewedAt,
		ReviewStatus: reviewStatus,
		VisibilityScope: visibilityScope,
		ClientID: clientID.String,
	}, nil
}

// CaseNote is a visible analyst note with its append-only revisions.
type CaseNote struct {
	NoteID          string             `json:"note_id"`
	CaseID          string             `json:"case_id"`
	UserID          string             `json:"user_id"`
	NoteText        string             `json:"note_text"`
	NoteType        string             `json:"note_type"`
	VisibilityScope string             `json:"visibility_scope"`
	ClientID        string             `json:"client_id,omitempty"`
	CreatedAt       string             `json:"created_at"`
	UpdatedAt       string             `json:"updated_at"`
	Revisions       []CaseNoteRevision `json:"revisions"`
}

// CaseNoteRevision is an immutable note revision.
type CaseNoteRevision struct {
	RevisionID string `json:"revision_id"`
	NoteID     string `json:"note_id"`
	NoteText   string `json:"note_text"`
	CreatedBy  string `json:"created_by"`
	CreatedAt  string `json:"created_at"`
}

// CreateCaseNote creates an analyst note. GLOBAL notes must not contain any
// client_id string; CLIENT notes require client_id and an explicit grant.
// The note, its initial revision and a scoped activity row are atomic.
func CreateCaseNote(caseID, userID, noteText, noteType, visibilityScope, clientID string) (string, error) {
	if err := requireM6Schema(); err != nil {
		return "", err
	}
	caseObj, err := GetResearchCase(caseID, userID)
	if err != nil {
		return "", err
	}
	if caseObj.Status == "ARCHIVED" {
		return "", ErrCaseArchived
	}
	if strings.TrimSpace(noteText) == "" {
		return "", fmt.Errorf("note_text is required")
	}
	if noteType == "" {
		noteType = "observation"
	}
	switch noteType {
	case "observation", "finding", "question", "escalation":
	default:
		return "", fmt.Errorf("invalid note_type")
	}
	if visibilityScope == "" {
		visibilityScope = "CLIENT"
	}
	switch visibilityScope {
	case "GLOBAL", "CLIENT":
	default:
		return "", fmt.Errorf("invalid visibility_scope")
	}
	if visibilityScope == "GLOBAL" {
		if clientID != "" {
			return "", fmt.Errorf("client_id must be empty for GLOBAL notes")
		}
		if noteContainsClientData(noteText) {
			return "", ErrGlobalArtifactClientData
		}
	}
	if visibilityScope == "CLIENT" {
		if clientID == "" {
			return "", fmt.Errorf("client_id is required for CLIENT notes")
		}
		if !hasClientGrant(userID, clientID) {
			return "", ErrClientAccessDenied
		}
	}

	noteID, _ := GenerateCaseID()
	revID, _ := GenerateCaseID()
	actID, _ := GenerateCaseID()

	tx, err := globalDB.Begin()
	if err != nil {
		return "", fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()

	var clientArg interface{}
	if clientID != "" {
		clientArg = clientID
	}
	if _, err := tx.Exec(`INSERT INTO case_notes
		(note_id, case_id, user_id, note_text, note_type, visibility_scope, client_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`,
		noteID, caseID, userID, noteText, noteType, visibilityScope, clientArg); err != nil {
		return "", fmt.Errorf("inserting note: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO case_notes_revision
		(revision_id, note_id, note_text, created_by, created_at)
		VALUES (?, ?, ?, ?, datetime('now'))`, revID, noteID, noteText, userID); err != nil {
		return "", fmt.Errorf("inserting note revision: %w", err)
	}
	// Activity details carry only the note id + type (never the note body).
	if _, err := tx.Exec(`INSERT INTO case_activity
		(activity_id, case_id, user_id, action, visibility_scope, client_id, details, created_at)
		VALUES (?, ?, ?, 'note_added', ?, ?, ?, datetime('now'))`,
		actID, caseID, userID, visibilityScope, clientArg, noteID+":"+noteType); err != nil {
		return "", fmt.Errorf("recording note activity: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("committing note: %w", err)
	}
	return noteID, nil
}

// ListCaseNotes returns visible notes with permission-aware total.
// Visibility: GLOBAL always; CLIENT only with an explicit grant.
// Revisions are returned only for visible notes.
func ListCaseNotes(caseID, userID string, limit, offset int) ([]CaseNote, int, error) {
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
	rows, err := globalDB.Query(`SELECT note_id, case_id, user_id, note_text, note_type, visibility_scope, client_id, created_at, updated_at
		FROM case_notes
		WHERE case_id = ? AND (visibility_scope = 'GLOBAL'
			OR client_id IN (SELECT client_id FROM user_authorized_clients WHERE user_id = ?))
		ORDER BY created_at, note_id`, caseID, userID)
	if err != nil {
		return nil, 0, fmt.Errorf("listing notes: %w", err)
	}
	all := []CaseNote{}
	for rows.Next() {
		var n CaseNote
		var clientID sql.NullString
		if err := rows.Scan(&n.NoteID, &n.CaseID, &n.UserID, &n.NoteText, &n.NoteType, &n.VisibilityScope, &clientID, &n.CreatedAt, &n.UpdatedAt); err != nil {
			rows.Close()
			return nil, 0, fmt.Errorf("scanning note: %w", err)
		}
		if clientID.Valid {
			n.ClientID = clientID.String
		}
		all = append(all, n)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, 0, err
	}
	rows.Close()
	for i := range all {
		if err := loadNoteRevisions(&all[i]); err != nil {
			return nil, 0, err
		}
	}
	total := len(all)
	if offset > len(all) {
		return []CaseNote{}, total, nil
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	return all[offset:end], total, nil
}

func loadNoteRevisions(n *CaseNote) error {
	q := globalDB
	_ = q
	rows, err := globalDB.Query(`SELECT revision_id, note_id, note_text, created_by, created_at
		FROM case_notes_revision WHERE note_id = ? ORDER BY created_at, revision_id`, n.NoteID)
	if err != nil {
		return fmt.Errorf("loading note revisions: %w", err)
	}
	defer rows.Close()
	var revs []CaseNoteRevision
	for rows.Next() {
		var r CaseNoteRevision
		if err := rows.Scan(&r.RevisionID, &r.NoteID, &r.NoteText, &r.CreatedBy, &r.CreatedAt); err != nil {
			return fmt.Errorf("scanning note revision: %w", err)
		}
		revs = append(revs, r)
	}
	n.Revisions = revs
	return rows.Err()
}

// ListVisibleCaseActivityPaged returns a page of visible activity plus the
// permission-aware total. The visibility predicate (GLOBAL or grant-based
// CLIENT) is mandatory; total counts only visible rows.
func ListVisibleCaseActivityPaged(caseID, userID string, limit, offset int) ([]CaseActivityRow, int, error) {
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
	if err := globalDB.QueryRow(`SELECT COUNT(*) FROM case_activity
		WHERE case_id = ? AND (visibility_scope = 'GLOBAL'
			OR client_id IN (SELECT client_id FROM user_authorized_clients WHERE user_id = ?))`,
		caseID, userID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting visible activity: %w", err)
	}
	rows, err := globalDB.Query(`SELECT activity_id, case_id, user_id, action, visibility_scope, client_id, details, created_at
		FROM case_activity
		WHERE case_id = ? AND (visibility_scope = 'GLOBAL'
			OR client_id IN (SELECT client_id FROM user_authorized_clients WHERE user_id = ?))
		ORDER BY created_at, activity_id LIMIT ? OFFSET ?`, caseID, userID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("listing visible activity: %w", err)
	}
	defer rows.Close()
	out := []CaseActivityRow{}
	for rows.Next() {
		var a CaseActivityRow
		var clientID, details sql.NullString
		if err := rows.Scan(&a.ActivityID, &a.CaseID, &a.UserID, &a.Action, &a.VisibilityScope, &clientID, &details, &a.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scanning case activity: %w", err)
		}
		if clientID.Valid {
			a.ClientID = clientID.String
		}
		if details.Valid {
			a.Details = details.String
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}
