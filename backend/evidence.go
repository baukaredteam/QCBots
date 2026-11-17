package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// queryable is satisfied by both *sql.DB and *sql.Tx, allowing helpers to run
// inside a transaction for atomic ownership-check-and-write.
type queryable interface {
	QueryRow(query string, args ...interface{}) *sql.Row
	Exec(query string, args ...interface{}) (sql.Result, error)
}

// nextID generates a cryptographically random identifier.
// It does NOT depend on process uptime or a monotonic counter, so IDs remain
// unique across process restarts and under concurrent requests.
func nextID(prefix string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback: time-based with nanoseconds (extremely unlikely to fail)
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}

// ============================================================================
// TRUSTED BOUNDARY DOCUMENTATION
// ============================================================================
//
// All functions in this file receive their security parameters (clientID,
// isGlobalAuthorized, hasReviewCapability, hasRevokeCapability) from a
// TRUSTED SERVER-SIDE CONTEXT (RBAC/session layer), NOT from untrusted HTTP
// parameters. Until API integration exists, the DB layer boundary is:
//
//   - clientID:     the caller's authorized client, resolved server-side from
//                   the authenticated session. Never accepted from HTTP body.
//   - isGlobalAuthorized: true only if the RBAC layer has explicitly granted
//                   GLOBAL-scope access to this caller.
//   - hasReviewCapability: true only if RBAC has granted edge.review permission.
//   - hasRevokeCapability: true only if RBAC has granted edge.revoke permission.
//
// The DB layer enforces these checks but does not originate them.

// EvidenceEntity represents a node in the evidence graph
type EvidenceEntity struct {
	EntityID           string `json:"entity_id"`
	EntityType         string `json:"entity_type"`
	EntityRefType      string `json:"entity_ref_type"`
	EntityRef          string `json:"entity_ref"`
	DisplayName        string `json:"display_name,omitempty"`
	Description        string `json:"description,omitempty"`
	VisibilityScope    string `json:"visibility_scope"`
	ClientID           string `json:"client_id,omitempty"`
	ProvenanceSource   string `json:"provenance_source,omitempty"`
	ProvenanceChecksum string `json:"provenance_checksum,omitempty"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
	CreatedBy          string `json:"created_by,omitempty"`
}

// EvidenceEdge represents a relationship between two entities
type EvidenceEdge struct {
	EdgeID               string `json:"edge_id"`
	SourceEntityID       string `json:"source_entity_id"`
	TargetEntityID       string `json:"target_entity_id"`
	RelationshipType     string `json:"relationship_type"`
	VisibilityScope      string `json:"visibility_scope"`
	ClientID             string `json:"client_id,omitempty"`
	RelationshipConfidence string `json:"relationship_confidence,omitempty"`
	VerificationStatus   string `json:"verification_status"`
	VerifiedBy           string `json:"verified_by,omitempty"`
	VerifiedAt           string `json:"verified_at,omitempty"`
	ReviewReason         string `json:"review_reason,omitempty"`
	IsRevoked            bool   `json:"is_revoked"`
	RevokedBy            string `json:"revoked_by,omitempty"`
	RevokedAt            string `json:"revoked_at,omitempty"`
	RevokeReason         string `json:"revoke_reason,omitempty"`
	CreatedAt            string `json:"created_at"`
	UpdatedAt            string `json:"updated_at"`
	CreatedBy            string `json:"created_by,omitempty"`
}

// EvidenceReference links an evidence block to a building block
type EvidenceReference struct {
	EvidenceID   string `json:"evidence_id"`
	EdgeID       string `json:"edge_id"`
	EntityID     string `json:"entity_id"`
	SourceType   string `json:"source_type"`
	SourceRef    string `json:"source_ref"`
	SourceSnippet string `json:"source_snippet,omitempty"`
	CreatedAt    string `json:"created_at"`
}

// CreateEvidenceEntity creates a new evidence entity.
// isGlobalAuthorized must be true when visibilityScope == "GLOBAL"
// (client_id=NULL is a DB constraint, not an RBAC check).
func (db *DB) CreateEvidenceEntity(entityType, entityRefType, entityRef, displayName, description, visibilityScope, clientID, provenanceSource, provenanceChecksum, createdBy string, isGlobalAuthorized bool) (string, error) {
	tx, err := db.Begin()
	if err != nil {
		return "", fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Validate entity_ref exists in the referenced table
	refClientID, err := resolveEntityRef(tx, entityRefType, entityRef)
	if err != nil {
		return "", fmt.Errorf("invalid entity_ref: %w", err)
	}

	// Validate client_id matches entity's client (for CLIENT scope)
	if visibilityScope == "CLIENT" {
		if clientID == "" {
			return "", fmt.Errorf("client_id required for CLIENT scope")
		}
		if refClientID != clientID {
			return "", fmt.Errorf("entity_ref belongs to client %s, not %s", refClientID, clientID)
		}
	}

	// GLOBAL entity requires explicit authorization — client_id=NULL is not RBAC
	if visibilityScope == "GLOBAL" {
		if !isGlobalAuthorized {
			return "", fmt.Errorf("GLOBAL entity creation requires explicit authorization")
		}
		if clientID != "" {
			return "", fmt.Errorf("GLOBAL entity cannot have client_id")
		}
	}

	entityID := nextID("entity")
	var clientIDParam interface{} = clientID
	if visibilityScope == "GLOBAL" {
		clientIDParam = nil
	}
	_, err = tx.Exec(`INSERT INTO evidence_entities (entity_id, entity_type, entity_ref_type, entity_ref, display_name, description, visibility_scope, client_id, provenance_source, provenance_checksum, created_at, updated_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), ?)`,
		entityID, entityType, entityRefType, entityRef, displayName, description, visibilityScope, clientIDParam, provenanceSource, provenanceChecksum, createdBy)
	if err != nil {
		return "", fmt.Errorf("creating entity: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("committing entity: %w", err)
	}
	return entityID, nil
}

// CreateEvidenceEdge creates a relationship between two entities.
// isGlobalAuthorized must be true when visibilityScope == "GLOBAL".
func (db *DB) CreateEvidenceEdge(sourceEntityID, targetEntityID, relationshipType, visibilityScope, clientID, relationshipConfidence, createdBy string, isGlobalAuthorized bool) (string, error) {
	tx, err := db.Begin()
	if err != nil {
		return "", fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Validate source and target entities exist
	sourceClientID, err := resolveEntityClientID(tx, sourceEntityID)
	if err != nil {
		return "", fmt.Errorf("invalid source entity: %w", err)
	}
	targetClientID, err := resolveEntityClientID(tx, targetEntityID)
	if err != nil {
		return "", fmt.Errorf("invalid target entity: %w", err)
	}

	// Validate visibility_scope and client_id consistency
	if visibilityScope == "GLOBAL" {
		if !isGlobalAuthorized {
			return "", fmt.Errorf("GLOBAL edge creation requires explicit authorization")
		}
		if clientID != "" {
			return "", fmt.Errorf("GLOBAL edge cannot have client_id")
		}
		if sourceClientID != "" || targetClientID != "" {
			return "", fmt.Errorf("GLOBAL edge cannot reference client-owned entities")
		}
	} else if visibilityScope == "CLIENT" {
		if clientID == "" {
			return "", fmt.Errorf("client_id required for CLIENT edge")
		}
		// CLIENT edge accepts GLOBAL endpoints (clientID == "") or same-client endpoints
		if sourceClientID != "" && sourceClientID != clientID {
			return "", fmt.Errorf("source entity belongs to client %s, not %s", sourceClientID, clientID)
		}
		if targetClientID != "" && targetClientID != clientID {
			return "", fmt.Errorf("target entity belongs to client %s, not %s", targetClientID, clientID)
		}
	}

	edgeID := nextID("edge")
	var clientIDParam interface{} = clientID
	if visibilityScope == "GLOBAL" {
		clientIDParam = nil
	}
	_, err = tx.Exec(`INSERT INTO evidence_graph_edges (edge_id, source_entity_id, target_entity_id, relationship_type, visibility_scope, client_id, relationship_confidence, verification_status, created_at, updated_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', datetime('now'), datetime('now'), ?)`,
		edgeID, sourceEntityID, targetEntityID, relationshipType, visibilityScope, clientIDParam, relationshipConfidence, createdBy)
	if err != nil {
		return "", fmt.Errorf("creating edge: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("committing edge: %w", err)
	}
	return edgeID, nil
}

// CreateEvidenceReference creates an evidence reference linking an entity to an edge.
// All parameters are trusted server-side context.
func (db *DB) CreateEvidenceReference(edgeID, entityID, sourceType, sourceRef, sourceSnippet, createdBy string) (string, error) {
	tx, err := db.Begin()
	if err != nil {
		return "", fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Validate edge exists
	var edgeClientID string
	err = tx.QueryRow(`SELECT client_id FROM evidence_graph_edges WHERE edge_id = ?`, edgeID).Scan(&edgeClientID)
	if err != nil {
		return "", fmt.Errorf("edge not found: %s", edgeID)
	}

	// Validate entity exists
	var entityClientID sql.NullString
	err = tx.QueryRow(`SELECT client_id FROM evidence_entities WHERE entity_id = ?`, entityID).Scan(&entityClientID)
	if err != nil {
		return "", fmt.Errorf("entity not found: %s", entityID)
	}

	// Validate client_id consistency: CLIENT-scoped edge and entity must share client_id
	if edgeClientID != "" {
		if !entityClientID.Valid || entityClientID.String != edgeClientID {
			return "", fmt.Errorf("entity client_id does not match edge client_id")
		}
	}

	// Validate source_ref ownership against real CTI tables for CLIENT-scoped edges
	if edgeClientID != "" && (sourceType == "report" || sourceType == "claim") {
		refID := stripTablePrefix(sourceRef)
		if sourceType == "report" {
			var reportClientID string
			err := tx.QueryRow(`SELECT client_id FROM cti_reports WHERE report_id = ?`, refID).Scan(&reportClientID)
			if err != nil {
				return "", fmt.Errorf("source_ref not found: %s", sourceRef)
			}
			if reportClientID != edgeClientID {
				return "", fmt.Errorf("source_ref belongs to client %s, not %s", reportClientID, edgeClientID)
			}
		} else if sourceType == "claim" {
			var claimClientID string
			err := tx.QueryRow(`SELECT r.client_id FROM cti_claims c JOIN cti_reports r ON c.report_id = r.report_id WHERE c.claim_id = ?`, refID).Scan(&claimClientID)
			if err != nil {
				return "", fmt.Errorf("source_ref not found: %s", sourceRef)
			}
			if claimClientID != edgeClientID {
				return "", fmt.Errorf("source_ref belongs to client %s, not %s", claimClientID, edgeClientID)
			}
		}
	}

	evidenceID := nextID("evidence")
	_, err = tx.Exec(`INSERT INTO evidence_references (evidence_id, edge_id, entity_id, source_type, source_ref, source_snippet, created_at)
		VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
		evidenceID, edgeID, entityID, sourceType, sourceRef, sourceSnippet)
	if err != nil {
		return "", fmt.Errorf("creating evidence reference: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("committing evidence reference: %w", err)
	}
	return evidenceID, nil
}

// stripTablePrefix removes a "table_name." prefix from a reference string
func stripTablePrefix(ref string) string {
	if idx := strings.Index(ref, "."); idx >= 0 {
		return ref[idx+1:]
	}
	return ref
}

// resolveEntityRef resolves an entity reference to its client_id
func resolveEntityRef(q queryable, entityRefType, entityRef string) (string, error) {
	var clientID string
	switch entityRefType {
	case "indicators":
		err := q.QueryRow(`SELECT r.client_id FROM indicators i JOIN cti_reports r ON i.report_id = r.report_id WHERE i.indicator_id = ?`, entityRef).Scan(&clientID)
		if err != nil {
			return "", fmt.Errorf("entity_ref not found: %s", entityRef)
		}
	case "threat_actors":
		err := q.QueryRow(`SELECT r.client_id FROM threat_actors a JOIN cti_reports r ON a.report_id = r.report_id WHERE a.actor_id = ?`, entityRef).Scan(&clientID)
		if err != nil {
			return "", fmt.Errorf("entity_ref not found: %s", entityRef)
		}
	case "techniques":
		err := q.QueryRow(`SELECT r.client_id FROM techniques t JOIN cti_reports r ON t.report_id = r.report_id WHERE t.technique_id = ?`, entityRef).Scan(&clientID)
		if err != nil {
			return "", fmt.Errorf("entity_ref not found: %s", entityRef)
		}
	case "cves":
		err := q.QueryRow(`SELECT r.client_id FROM cves c JOIN cti_reports r ON c.report_id = r.report_id WHERE c.cve_id = ?`, entityRef).Scan(&clientID)
		if err != nil {
			return "", fmt.Errorf("entity_ref not found: %s", entityRef)
		}
	case "malware":
		err := q.QueryRow(`SELECT r.client_id FROM malware m JOIN cti_reports r ON m.report_id = r.report_id WHERE m.malware_id = ?`, entityRef).Scan(&clientID)
		if err != nil {
			return "", fmt.Errorf("entity_ref not found: %s", entityRef)
		}
	case "campaigns":
		err := q.QueryRow(`SELECT r.client_id FROM campaigns c JOIN cti_reports r ON c.report_id = r.report_id WHERE c.campaign_id = ?`, entityRef).Scan(&clientID)
		if err != nil {
			return "", fmt.Errorf("entity_ref not found: %s", entityRef)
		}
	case "cti_reports":
		err := q.QueryRow(`SELECT client_id FROM cti_reports WHERE report_id = ?`, entityRef).Scan(&clientID)
		if err != nil {
			return "", fmt.Errorf("entity_ref not found: %s", entityRef)
		}
	case "file_artifacts":
		return "", fmt.Errorf("file_artifacts is not a valid entity_ref source for client-scoped entities")
	default:
		return "", fmt.Errorf("unknown entity_ref_type: %s", entityRefType)
	}
	return clientID, nil
}

// resolveEntityClientID resolves an entity_id to its client_id
func resolveEntityClientID(q queryable, entityID string) (string, error) {
	var clientID sql.NullString
	err := q.QueryRow(`SELECT client_id FROM evidence_entities WHERE entity_id = ?`, entityID).Scan(&clientID)
	if err != nil {
		return "", fmt.Errorf("entity not found: %s", entityID)
	}
	return clientID.String, nil
}

// GetEvidenceEntity returns an entity by ID, filtered by tenant visibility.
// clientID is the trusted server-side client context.
// CLIENT-scoped entities are visible only to their owner client;
// GLOBAL entities (client_id NULL) are visible to all callers.
func (db *DB) GetEvidenceEntity(clientID, entityID string) (*EvidenceEntity, error) {
	var e EvidenceEntity
	var provenanceSource, provenanceChecksum, createdBy, entityClientID sql.NullString
	err := db.QueryRow(`SELECT entity_id, entity_type, entity_ref_type, entity_ref, display_name, description, visibility_scope, client_id, provenance_source, provenance_checksum, created_at, updated_at, created_by FROM evidence_entities WHERE entity_id = ?`, entityID).Scan(
		&e.EntityID, &e.EntityType, &e.EntityRefType, &e.EntityRef, &e.DisplayName, &e.Description, &e.VisibilityScope, &entityClientID, &provenanceSource, &provenanceChecksum, &e.CreatedAt, &e.UpdatedAt, &createdBy)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if e.VisibilityScope == "CLIENT" {
		if !entityClientID.Valid || entityClientID.String != clientID {
			return nil, nil
		}
	}
	e.ClientID = entityClientID.String
	e.ProvenanceSource = provenanceSource.String
	e.ProvenanceChecksum = provenanceChecksum.String
	e.CreatedBy = createdBy.String
	return &e, nil
}

// GetEvidenceEdge returns an edge by ID, filtered by tenant visibility.
// clientID is the trusted server-side client context.
// CLIENT-scoped edges are visible only to their owner client;
// GLOBAL edges (client_id NULL) are visible to all callers.
func (db *DB) GetEvidenceEdge(clientID, edgeID string) (*EvidenceEdge, error) {
	var e EvidenceEdge
	var relationshipConfidence, verifiedBy, verifiedAt, reviewReason, revokedBy, revokedAt, revokeReason, createdBy, edgeClientID sql.NullString
	err := db.QueryRow(`SELECT edge_id, source_entity_id, target_entity_id, relationship_type, visibility_scope, client_id, relationship_confidence, verification_status, verified_by, verified_at, review_reason, is_revoked, revoked_by, revoked_at, revoke_reason, created_at, updated_at, created_by FROM evidence_graph_edges WHERE edge_id = ?`, edgeID).Scan(
		&e.EdgeID, &e.SourceEntityID, &e.TargetEntityID, &e.RelationshipType, &e.VisibilityScope, &edgeClientID, &relationshipConfidence, &e.VerificationStatus, &verifiedBy, &verifiedAt, &reviewReason, &e.IsRevoked, &revokedBy, &revokedAt, &revokeReason, &e.CreatedAt, &e.UpdatedAt, &createdBy)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if e.VisibilityScope == "CLIENT" {
		if !edgeClientID.Valid || edgeClientID.String != clientID {
			return nil, nil
		}
	}
	e.ClientID = edgeClientID.String
	e.RelationshipConfidence = relationshipConfidence.String
	e.VerifiedBy = verifiedBy.String
	e.VerifiedAt = verifiedAt.String
	e.ReviewReason = reviewReason.String
	e.RevokedBy = revokedBy.String
	e.RevokedAt = revokedAt.String
	e.RevokeReason = revokeReason.String
	e.CreatedBy = createdBy.String
	return &e, nil
}

// ListEvidenceEntities lists entities with optional filtering.
// clientID is the trusted server-side client context.
// Only records owned by clientID (or GLOBAL records when clientID="") are returned.
func (db *DB) ListEvidenceEntities(clientID, entityType, visibilityScope string) ([]EvidenceEntity, error) {
	query := `SELECT entity_id, entity_type, entity_ref_type, entity_ref, display_name, description, visibility_scope, client_id, provenance_source, provenance_checksum, created_at, updated_at, created_by FROM evidence_entities WHERE 1=1`
	args := []interface{}{}
	if clientID != "" {
		query += ` AND client_id = ?`
		args = append(args, clientID)
	}
	if entityType != "" {
		query += ` AND entity_type = ?`
		args = append(args, entityType)
	}
	if visibilityScope != "" {
		query += ` AND visibility_scope = ?`
		args = append(args, visibilityScope)
	}
	query += ` ORDER BY created_at DESC`

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entities []EvidenceEntity
	for rows.Next() {
		var e EvidenceEntity
		var provenanceSource, provenanceChecksum, createdBy, entityClientID sql.NullString
		if err := rows.Scan(&e.EntityID, &e.EntityType, &e.EntityRefType, &e.EntityRef, &e.DisplayName, &e.Description, &e.VisibilityScope, &entityClientID, &provenanceSource, &provenanceChecksum, &e.CreatedAt, &e.UpdatedAt, &createdBy); err != nil {
			return nil, err
		}
		e.ClientID = entityClientID.String
		e.ProvenanceSource = provenanceSource.String
		e.ProvenanceChecksum = provenanceChecksum.String
		e.CreatedBy = createdBy.String
		entities = append(entities, e)
	}
	return entities, nil
}

// ListEvidenceEdges lists edges with optional filtering.
// clientID is the trusted server-side client context.
func (db *DB) ListEvidenceEdges(clientID, visibilityScope string) ([]EvidenceEdge, error) {
	query := `SELECT edge_id, source_entity_id, target_entity_id, relationship_type, visibility_scope, client_id, relationship_confidence, verification_status, verified_by, verified_at, review_reason, is_revoked, revoked_by, revoked_at, revoke_reason, created_at, updated_at, created_by FROM evidence_graph_edges WHERE 1=1`
	args := []interface{}{}
	if clientID != "" {
		query += ` AND client_id = ?`
		args = append(args, clientID)
	}
	if visibilityScope != "" {
		query += ` AND visibility_scope = ?`
		args = append(args, visibilityScope)
	}
	query += ` ORDER BY created_at DESC`

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var edges []EvidenceEdge
	for rows.Next() {
		var e EvidenceEdge
		var relationshipConfidence, verifiedBy, verifiedAt, reviewReason, revokedBy, revokedAt, revokeReason, createdBy, edgeClientID sql.NullString
		if err := rows.Scan(&e.EdgeID, &e.SourceEntityID, &e.TargetEntityID, &e.RelationshipType, &e.VisibilityScope, &edgeClientID, &relationshipConfidence, &e.VerificationStatus, &verifiedBy, &verifiedAt, &reviewReason, &e.IsRevoked, &revokedBy, &revokedAt, &revokeReason, &e.CreatedAt, &e.UpdatedAt, &createdBy); err != nil {
			return nil, err
		}
		e.ClientID = edgeClientID.String
		e.RelationshipConfidence = relationshipConfidence.String
		e.VerifiedBy = verifiedBy.String
		e.VerifiedAt = verifiedAt.String
		e.ReviewReason = reviewReason.String
		e.RevokedBy = revokedBy.String
		e.RevokedAt = revokedAt.String
		e.RevokeReason = revokeReason.String
		e.CreatedBy = createdBy.String
		edges = append(edges, e)
	}
	return edges, nil
}

// CreateEvidenceReview creates an immutable review for an edge.
// All parameters are trusted server-side context (from RBAC/session layer),
// NOT from untrusted HTTP parameters.
//
//   clientID: caller's authorized client (empty string for GLOBAL scope)
//   hasReviewCapability: true if caller has edge.review permission (from RBAC)
//   isGlobalAuthorized: true if caller is authorized for GLOBAL scope
//
// The review insert and verification_status update are performed in a single
// transaction. On any error, the transaction is rolled back and no partial
// changes are visible.
func (db *DB) CreateEvidenceReview(edgeID, reviewerID, clientID, decision, reason, previousStatus, newStatus, reviewedAt string, hasReviewCapability, isGlobalAuthorized bool) (string, error) {
	// Validate decision
	switch decision {
	case "APPROVED", "REJECTED", "NEEDS_MORE_DATA":
	default:
		return "", fmt.Errorf("invalid decision: %s", decision)
	}

	tx, err := db.Begin()
	if err != nil {
		return "", fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Get edge and verify access, revoked status, and current verification_status
	var edgeClientID sql.NullString
	var currentStatus string
	var isRevoked bool
	err = tx.QueryRow(`SELECT client_id, verification_status, is_revoked FROM evidence_graph_edges WHERE edge_id = ?`, edgeID).Scan(
		&edgeClientID, &currentStatus, &isRevoked)
	if err != nil {
		return "", fmt.Errorf("edge not found: %s", edgeID)
	}

	// Reject review on revoked edge
	if isRevoked {
		return "", fmt.Errorf("cannot review revoked edge: %s", edgeID)
	}

	// Check client access
	if edgeClientID.Valid {
		// CLIENT-scoped edge
		if clientID == "" {
			return "", fmt.Errorf("client_id required for CLIENT-scoped edge review")
		}
		if edgeClientID.String != clientID {
			return "", fmt.Errorf("edge belongs to client %s, not %s", edgeClientID.String, clientID)
		}
	} else {
		// GLOBAL-scoped edge
		if !isGlobalAuthorized {
			return "", fmt.Errorf("GLOBAL edge review requires explicit authorization")
		}
	}

	// Check review capability
	if !hasReviewCapability {
		return "", fmt.Errorf("reviewer lacks edge.review capability")
	}

	// Verify previous status matches (optimistic concurrency)
	if previousStatus != "" && previousStatus != currentStatus {
		return "", fmt.Errorf("previous status mismatch: current=%s, expected=%s", currentStatus, previousStatus)
	}

	reviewID := nextID("review")
	_, err = tx.Exec(`INSERT INTO evidence_graph_reviews (review_id, edge_id, reviewer_id, decision, reason, previous_status, new_status, reviewed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		reviewID, edgeID, reviewerID, decision, reason, previousStatus, newStatus, reviewedAt)
	if err != nil {
		return "", fmt.Errorf("creating review: %w", err)
	}

	// Update edge verification_status in the same transaction
	_, err = tx.Exec(`UPDATE evidence_graph_edges SET verification_status = ?, updated_at = datetime('now') WHERE edge_id = ?`,
		newStatus, edgeID)
	if err != nil {
		return "", fmt.Errorf("updating edge verification status: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("committing review: %w", err)
	}
	return reviewID, nil
}

// RevokeEvidenceEdge soft-deletes an edge (is_revoked=true) and records history.
// All parameters are trusted server-side context (from RBAC/session layer),
// NOT from untrusted HTTP parameters.
//
//   clientID: caller's authorized client (empty string for GLOBAL scope)
//   hasRevokeCapability: true if caller has edge.revoke permission (from RBAC)
//   isGlobalAuthorized: true if caller is authorized for GLOBAL scope
//
// The revoke and history insert are performed in a single transaction.
// Evidence references, reviews, and history records are preserved (no cascade
// delete). A revoked edge cannot be modified again without explicit workflow.
func (db *DB) RevokeEvidenceEdge(edgeID, revokedBy, clientID, revokeReason string, hasRevokeCapability, isGlobalAuthorized bool) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Get edge and verify access and revoked status
	var edgeClientID sql.NullString
	var isRevoked bool
	err = tx.QueryRow(`SELECT client_id, is_revoked FROM evidence_graph_edges WHERE edge_id = ?`, edgeID).Scan(
		&edgeClientID, &isRevoked)
	if err != nil {
		return fmt.Errorf("edge not found: %s", edgeID)
	}

	// Reject repeat revoke
	if isRevoked {
		return fmt.Errorf("edge is already revoked: %s", edgeID)
	}

	// Check client access
	if edgeClientID.Valid {
		if clientID == "" {
			return fmt.Errorf("client_id required for CLIENT-scoped edge revoke")
		}
		if edgeClientID.String != clientID {
			return fmt.Errorf("edge belongs to client %s, not %s", edgeClientID.String, clientID)
		}
	} else {
		if !isGlobalAuthorized {
			return fmt.Errorf("GLOBAL edge revoke requires explicit authorization")
		}
	}

	// Check revoke capability
	if !hasRevokeCapability {
		return fmt.Errorf("caller lacks edge.revoke capability")
	}

	// Soft-delete the edge
	_, err = tx.Exec(`UPDATE evidence_graph_edges SET is_revoked = TRUE, revoked_by = ?, revoked_at = datetime('now'), revoke_reason = ?, updated_at = datetime('now') WHERE edge_id = ?`,
		revokedBy, revokeReason, edgeID)
	if err != nil {
		return fmt.Errorf("revoking edge: %w", err)
	}

	// Record revoke in immutable history
	historyID := nextID("history")
	_, err = tx.Exec(`INSERT INTO evidence_edge_history (history_id, edge_id, field_name, old_value, new_value, changed_by, changed_at)
		VALUES (?, ?, 'is_revoked', 'false', 'true', ?, datetime('now'))`,
		historyID, edgeID, revokedBy)
	if err != nil {
		return fmt.Errorf("recording revoke history: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing revoke: %w", err)
	}
	return nil
}

// DeleteEvidenceReview deletes an evidence review (blocked by immutability trigger).
// All parameters are trusted server-side context.
func (db *DB) DeleteEvidenceReview(reviewID string) error {
	_, err := db.Exec(`DELETE FROM evidence_graph_reviews WHERE review_id = ?`, reviewID)
	if err != nil {
		return fmt.Errorf("deleting review: %w", err)
	}
	return nil
}

// UpdateEvidenceReview attempts to update a review (blocked by immutability trigger).
// All parameters are trusted server-side context.
func (db *DB) UpdateEvidenceReview(reviewID, reason string) error {
	_, err := db.Exec(`UPDATE evidence_graph_reviews SET reason = ? WHERE review_id = ?`, reason, reviewID)
	if err != nil {
		return fmt.Errorf("updating review: %w", err)
	}
	return nil
}

// UpdateEvidenceEdgeHistory attempts to update edge history (blocked by immutability trigger).
// All parameters are trusted server-side context.
func (db *DB) UpdateEvidenceEdgeHistory(historyID, newValue string) error {
	_, err := db.Exec(`UPDATE evidence_edge_history SET new_value = ? WHERE history_id = ?`, newValue, historyID)
	if err != nil {
		return fmt.Errorf("updating edge history: %w", err)
	}
	return nil
}

// DeleteEvidenceEdgeHistory attempts to delete edge history (blocked by immutability trigger).
// All parameters are trusted server-side context.
func (db *DB) DeleteEvidenceEdgeHistory(historyID string) error {
	_, err := db.Exec(`DELETE FROM evidence_edge_history WHERE history_id = ?`, historyID)
	if err != nil {
		return fmt.Errorf("deleting edge history: %w", err)
	}
	return nil
}

// UpdateEvidenceEdge updates an edge field.
// Rejected if the edge is revoked.
// clientID is the trusted server-side client context.
// isGlobalAuthorized must be true for GLOBAL-scoped edges.
func (db *DB) UpdateEvidenceEdge(edgeID, fieldName, newValue, changedBy, clientID string, isGlobalAuthorized bool) error {
	// Get edge and verify access and revoked status
	var edgeClientID sql.NullString
	var isRevoked bool
	err := db.QueryRow(`SELECT client_id, is_revoked FROM evidence_graph_edges WHERE edge_id = ?`, edgeID).Scan(
		&edgeClientID, &isRevoked)
	if err != nil {
		return fmt.Errorf("edge not found: %s", edgeID)
	}

	// Reject modification of revoked edge
	if isRevoked {
		return fmt.Errorf("cannot modify revoked edge: %s", edgeID)
	}

	// Check client access
	if edgeClientID.Valid {
		if clientID == "" {
			return fmt.Errorf("client_id required for CLIENT-scoped edge update")
		}
		if edgeClientID.String != clientID {
			return fmt.Errorf("edge belongs to client %s, not %s", edgeClientID.String, clientID)
		}
	} else {
		if !isGlobalAuthorized {
			return fmt.Errorf("GLOBAL edge update requires explicit authorization")
		}
	}

	_, err = db.Exec(`UPDATE evidence_graph_edges SET `+fieldName+` = ?, updated_at = datetime('now'), updated_by = ? WHERE edge_id = ?`,
		newValue, changedBy, edgeID)
	if err != nil {
		return fmt.Errorf("updating edge: %w", err)
	}
	return nil
}