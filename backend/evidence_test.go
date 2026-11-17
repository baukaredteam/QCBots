package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCTIDB creates a test database with migration 0003 applied
func testCTIDB(t *testing.T) *DB {
	t.Helper()
	db := testDB(t)
	// Find and read migration 0003, then execute as a whole to preserve
	// trigger bodies (BEGIN...END blocks) that break on naive ';' splitting.
	candidatePaths := []string{
		"migrations/0003_evidence_graph.sql",
		filepath.Join("..", "migrations", "0003_evidence_graph.sql"),
		filepath.Join("..", "..", "migrations", "0003_evidence_graph.sql"),
	}
	var data []byte
	var readErr error
	for _, p := range candidatePaths {
		data, readErr = os.ReadFile(p)
		if readErr == nil {
			break
		}
	}
	if readErr != nil {
		t.Fatalf("reading migration 0003: %v", readErr)
	}
	if _, err := db.DB.Exec(string(data)); err != nil {
		t.Fatalf("executing migration 0003: %v", err)
	}

	// Seed indicator and technique data needed for entity_ref resolution.
	// Seed data only creates cti_reports; indicators/techniques must exist
	// for resolveEntityRef to find them.
	_, err := db.DB.Exec(`INSERT INTO indicators (indicator_id, report_id, indicator_type, indicator_value) VALUES
		('ind_alpha_1', 'report-alpha-1', 'ipv4', '10.0.0.1'),
		('ind_alpha_2', 'report-alpha-2', 'domain', 'example.com'),
		('ind_beta_1', 'report-beta-1', 'ipv4', '10.0.0.2')`)
	if err != nil {
		t.Fatalf("seeding indicators: %v", err)
	}
	_, err = db.DB.Exec(`INSERT INTO techniques (technique_id, report_id, mitre_technique_id, technique_name) VALUES
		('T1001', 'report-alpha-1', 'T1001', 'Credential Dumping'),
		('T1002', 'report-alpha-1', 'T1002', 'Remote Services'),
		('T1003', 'report-beta-1', 'T1003', 'Browser Exploit')`)
	if err != nil {
		t.Fatalf("seeding techniques: %v", err)
	}
	return db
}

// --- TestEvidenceEntityCreate ---

func TestEvidenceEntityCreate(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	entityID, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Test Indicator", "Test indicator description", "CLIENT", "client-alpha", "test_source", "checksum123", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity: %v", err)
	}
	if entityID == "" {
		t.Fatal("expected entity ID")
	}

	entity, err := globalDB.GetEvidenceEntity("client-alpha", entityID)
	if err != nil {
		t.Fatalf("getting entity: %v", err)
	}
	if entity == nil {
		t.Fatal("entity not found")
	}
	if entity.EntityID != entityID {
		t.Fatalf("expected entity_id %s, got %s", entityID, entity.EntityID)
	}
	if entity.ClientID != "client-alpha" {
		t.Fatalf("expected client_id client-alpha, got %s", entity.ClientID)
	}
	if entity.VisibilityScope != "CLIENT" {
		t.Fatalf("expected visibility_scope CLIENT, got %s", entity.VisibilityScope)
	}
	t.Log("PASS: TestEvidenceEntityCreate")
}

// TestEvidenceEntityCreateGlobal - create a GLOBAL entity
func TestEvidenceEntityCreateGlobal(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	entityID, err := globalDB.CreateEvidenceEntity("technique", "techniques", "T1001", "Test Technique", "Test technique description", "GLOBAL", "", "test_source", "checksum456", "user-admin", true)
	if err != nil {
		t.Fatalf("creating global entity: %v", err)
	}
	if entityID == "" {
		t.Fatal("expected entity ID")
	}

	entity, err := globalDB.GetEvidenceEntity("", entityID)
	if err != nil {
		t.Fatalf("getting entity: %v", err)
	}
	if entity == nil {
		t.Fatal("entity not found")
	}
	if entity.ClientID != "" {
		t.Fatalf("expected empty client_id for GLOBAL, got %s", entity.ClientID)
	}
	if entity.VisibilityScope != "GLOBAL" {
		t.Fatalf("expected visibility_scope GLOBAL, got %s", entity.VisibilityScope)
	}
	t.Log("PASS: TestEvidenceEntityCreateGlobal")
}

// TestEvidenceEntityCreateForbiddenEntityRef - entity_ref doesn't exist
func TestEvidenceEntityCreateForbiddenEntityRef(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	_, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "nonexistent_id", "Test", "Test", "CLIENT", "client-alpha", "test_source", "checksum", "user-admin", false)
	if err == nil {
		t.Fatal("expected error for non-existent entity_ref")
	}
	t.Log("PASS: TestEvidenceEntityCreateForbiddenEntityRef")
}

// TestEvidenceEntityCreateWrongClient - entity_ref belongs to different client
func TestEvidenceEntityCreateWrongClient(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	_, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Test", "Test", "CLIENT", "client-beta", "test_source", "checksum", "user-admin", false)
	if err == nil {
		t.Fatal("expected error for cross-client entity_ref")
	}
	t.Log("PASS: TestEvidenceEntityCreateWrongClient")
}

// TestEvidenceEdgeCreate - create CLIENT edge between same client entities
func TestEvidenceEdgeCreate(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_2", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}

	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}
	if edgeID == "" {
		t.Fatal("expected edge ID")
	}

	edge, err := globalDB.GetEvidenceEdge("client-alpha", edgeID)
	if err != nil {
		t.Fatalf("getting edge: %v", err)
	}
	if edge == nil {
		t.Fatal("edge not found")
	}
	if edge.ClientID != "client-alpha" {
		t.Fatalf("expected client_id client-alpha, got %s", edge.ClientID)
	}
	t.Log("PASS: TestEvidenceEdgeCreate")
}

// TestEvidenceEdgeCrossTenant - create edge between different clients
func TestEvidenceEdgeCrossTenant(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_beta_1", "Entity 2", "Test", "CLIENT", "client-beta", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}

	_, err = globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err == nil {
		t.Fatal("expected error for cross-client edge")
	}
	t.Log("PASS: TestEvidenceEdgeCrossTenant")
}

// TestEvidenceEdgeCreateGLOBAL - create GLOBAL edge between GLOBAL entities
func TestEvidenceEdgeCreateGLOBAL(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("technique", "techniques", "T1001", "Tech 1", "Test", "GLOBAL", "", "src", "chk1", "user-admin", true)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("technique", "techniques", "T1002", "Tech 2", "Test", "GLOBAL", "", "src", "chk2", "user-admin", true)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}

	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "GLOBAL", "", "3", "user-admin", true)
	if err != nil {
		t.Fatalf("creating GLOBAL edge: %v", err)
	}
	if edgeID == "" {
		t.Fatal("expected edge ID")
	}
	edge, err := globalDB.GetEvidenceEdge("", edgeID)
	if err != nil {
		t.Fatalf("getting edge: %v", err)
	}
	if edge == nil {
		t.Fatal("edge not found")
	}
	if edge.ClientID != "" {
		t.Fatalf("expected empty client_id for GLOBAL edge, got %s", edge.ClientID)
	}
	t.Log("PASS: TestEvidenceEdgeCreateGLOBAL")
}

// TestEvidenceEdgeClientWithGlobalEndpoint - CLIENT edge with GLOBAL endpoint is allowed
func TestEvidenceEdgeClientWithGlobalEndpoint(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating client entity: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("technique", "techniques", "T1001", "Tech 1", "Test", "GLOBAL", "", "src", "chk2", "user-admin", true)
	if err != nil {
		t.Fatalf("creating global entity: %v", err)
	}

	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating CLIENT edge with GLOBAL endpoint: %v", err)
	}
	if edgeID == "" {
		t.Fatal("expected edge ID")
	}
	edge, err := globalDB.GetEvidenceEdge("client-alpha", edgeID)
	if err != nil {
		t.Fatalf("getting edge: %v", err)
	}
	if edge.ClientID != "client-alpha" {
		t.Fatalf("expected client_id client-alpha, got %s", edge.ClientID)
	}
	t.Log("PASS: TestEvidenceEdgeClientWithGlobalEndpoint")
}

// TestEvidenceEdgeCrossTenantCLIENT - CLIENT edge referencing another client's entity -> error
func TestEvidenceEdgeCrossTenantCLIENT(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_beta_1", "Entity 2", "Test", "CLIENT", "client-beta", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}

	_, err = globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err == nil {
		t.Fatal("expected error for cross-client CLIENT edge")
	}
	t.Log("PASS: TestEvidenceEdgeCrossTenantCLIENT")
}

// TestEvidenceReferenceCreate - create evidence reference
func TestEvidenceReferenceCreate(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("technique", "techniques", "T1001", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}

	refID, err := globalDB.CreateEvidenceReference(edgeID, e1, "report", "cti_reports.report-alpha-1", "Evidence snippet", "user-admin")
	if err != nil {
		t.Fatalf("creating evidence reference: %v", err)
	}
	if refID == "" {
		t.Fatal("expected evidence ID")
	}
	t.Log("PASS: TestEvidenceReferenceCreate")
}

// TestEvidenceReferenceForgedEntityRef - entity_ref doesn't exist
func TestEvidenceReferenceForgedEntityRef(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("technique", "techniques", "T1001", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}

	_, err = globalDB.CreateEvidenceReference(edgeID, "nonexistent_entity", "report", "cti_reports.report_nonexistent", "Snippet", "user-admin")
	if err == nil {
		t.Fatal("expected error for forged entity_ref")
	}
	t.Log("PASS: TestEvidenceReferenceForgedEntityRef")
}

// TestEvidenceReferenceForgedSourceRef - source_ref belongs to different client
func TestEvidenceReferenceForgedSourceRef(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("technique", "techniques", "T1001", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}

	_, err = globalDB.CreateEvidenceReference(edgeID, e1, "report", "cti_reports.report-beta-1", "Snippet", "user-admin")
	if err == nil {
		t.Fatal("expected error for forged source_ref")
	}
	t.Log("PASS: TestEvidenceReferenceForgedSourceRef")
}

// TestEvidenceReferenceUsesFileArtifact - file_artifacts should be rejected
func TestEvidenceReferenceUsesFileArtifact(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("technique", "techniques", "T1001", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}

	_, err = globalDB.CreateEvidenceReference(edgeID, e1, "file_artifact", "file_artifacts.fa1", "Snippet", "user-admin")
	if err == nil {
		t.Fatal("expected error for file_artifacts entity_ref")
	}
	t.Log("PASS: TestEvidenceReferenceUsesFileArtifact")
}

// TestEvidenceReviewImmutableUpdate - UPDATE evidence_graph_reviews should fail
func TestEvidenceReviewImmutableUpdate(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("technique", "techniques", "T1001", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}
	reviewID, err := globalDB.CreateEvidenceReview(edgeID, "user-admin", "client-alpha", "APPROVED", "Good evidence", "", "verified", time.Now().Format(time.RFC3339), true, false)
	if err != nil {
		t.Fatalf("creating review: %v", err)
	}

		err = globalDB.UpdateEvidenceReview(reviewID, "Changed reason")
	if err == nil {
		t.Fatal("expected error for UPDATE review")
	}
	t.Log("PASS: TestEvidenceReviewImmutableUpdate")
}

// TestEvidenceReviewImmutableDelete - DELETE evidence_graph_reviews should fail
func TestEvidenceReviewImmutableDelete(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("technique", "techniques", "T1001", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}
	reviewID, err := globalDB.CreateEvidenceReview(edgeID, "user-admin", "client-alpha", "APPROVED", "Good evidence", "", "verified", time.Now().Format(time.RFC3339), true, false)
	if err != nil {
		t.Fatalf("creating review: %v", err)
	}

		err = globalDB.DeleteEvidenceReview(reviewID)
	if err == nil {
		t.Fatal("expected error for DELETE review")
	}
	t.Log("PASS: TestEvidenceReviewImmutableDelete")
}

// TestEvidenceEdgeHistoryImmutableUpdate - UPDATE evidence_edge_history should fail
func TestEvidenceEdgeHistoryImmutableUpdate(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("technique", "techniques", "T1001", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}

	// Insert a history record directly to test immutability
	historyID := fmt.Sprintf("history-%d", time.Now().UnixNano())
	_, err = db.Exec(`INSERT INTO evidence_edge_history (history_id, edge_id, field_name, old_value, new_value, changed_by, changed_at)
		VALUES (?, ?, 'relationship_confidence', '3', '4', 'user-admin', datetime('now'))`,
		historyID, edgeID)
	if err != nil {
		t.Fatalf("creating edge history: %v", err)
	}

		err = globalDB.UpdateEvidenceEdgeHistory(historyID, "5")
	if err == nil {
		t.Fatal("expected error for UPDATE edge history")
	}
	t.Log("PASS: TestEvidenceEdgeHistoryImmutableUpdate")
}

// TestEvidenceEdgeHistoryImmutableDelete - DELETE evidence_edge_history should fail
func TestEvidenceEdgeHistoryImmutableDelete(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("technique", "techniques", "T1001", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}

	// Insert a history record directly to test immutability
	historyID := fmt.Sprintf("history-%d", time.Now().UnixNano())
	_, err = db.Exec(`INSERT INTO evidence_edge_history (history_id, edge_id, field_name, old_value, new_value, changed_by, changed_at)
		VALUES (?, ?, 'relationship_confidence', '3', '4', 'user-admin', datetime('now'))`,
		historyID, edgeID)
	if err != nil {
		t.Fatalf("creating edge history: %v", err)
	}

		err = globalDB.DeleteEvidenceEdgeHistory(historyID)
	if err == nil {
		t.Fatal("expected error for DELETE edge history")
	}
	t.Log("PASS: TestEvidenceEdgeHistoryImmutableDelete")
}

// TestListEvidenceEntities - list entities filtered by client
func TestListEvidenceEntities(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	_, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	_, err = globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_2", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	_, err = globalDB.CreateEvidenceEntity("technique", "techniques", "T1003", "Tech 1", "Test", "CLIENT", "client-beta", "src", "chk3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 3: %v", err)
	}

	entities, err := globalDB.ListEvidenceEntities("client-alpha", "", "")
	if err != nil {
		t.Fatalf("listing entities: %v", err)
	}
	if len(entities) != 2 {
		t.Fatalf("expected 2 entities, got %d", len(entities))
	}
	t.Log("PASS: TestListEvidenceEntities")
}

// TestListEvidenceEdges - list edges filtered by client
func TestListEvidenceEdges(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("technique", "techniques", "T1001", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	_, err = globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}

	edges, err := globalDB.ListEvidenceEdges("client-alpha", "")
	if err != nil {
		t.Fatalf("listing edges: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	t.Log("PASS: TestListEvidenceEdges")
}

// TestGetEvidenceEntityNotFound - non-existent entity returns nil
func TestGetEvidenceEntityNotFound(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	entity, err := globalDB.GetEvidenceEntity("client-alpha", "nonexistent")
	if err != nil {
		t.Fatalf("getting non-existent entity: %v", err)
	}
	if entity != nil {
		t.Fatal("expected nil for non-existent entity")
	}
	t.Log("PASS: TestGetEvidenceEntityNotFound")
}

// TestGetEvidenceEdgeNotFound - non-existent edge returns nil
func TestGetEvidenceEdgeNotFound(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	edge, err := globalDB.GetEvidenceEdge("client-alpha", "nonexistent")
	if err != nil {
		t.Fatalf("getting non-existent edge: %v", err)
	}
	if edge != nil {
		t.Fatal("expected nil for non-existent edge")
	}
	t.Log("PASS: TestGetEvidenceEdgeNotFound")
}

// TestGetEvidenceEntityCrossClient - Get on another client's entity returns nil
func TestGetEvidenceEntityCrossClient(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	entityID, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity: %v", err)
	}

	// client-beta must not be able to read client-alpha's entity
	entity, err := globalDB.GetEvidenceEntity("client-beta", entityID)
	if err != nil {
		t.Fatalf("getting cross-client entity: %v", err)
	}
	if entity != nil {
		t.Fatal("expected nil for cross-client entity via Get")
	}
	t.Log("PASS: TestGetEvidenceEntityCrossClient")
}

// TestGetEvidenceEdgeCrossClient - Get on another client's edge returns nil
func TestGetEvidenceEdgeCrossClient(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_2", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}

	// client-beta must not be able to read client-alpha's edge
	edge, err := globalDB.GetEvidenceEdge("client-beta", edgeID)
	if err != nil {
		t.Fatalf("getting cross-client edge: %v", err)
	}
	if edge != nil {
		t.Fatal("expected nil for cross-client edge via Get")
	}
	t.Log("PASS: TestGetEvidenceEdgeCrossClient")
}

// TestListEvidenceEntitiesExcludesOtherClient - List does not return other clients' entities
func TestListEvidenceEntitiesExcludesOtherClient(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	_, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating alpha entity: %v", err)
	}
	_, err = globalDB.CreateEvidenceEntity("technique", "techniques", "T1003", "Entity 2", "Test", "CLIENT", "client-beta", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating beta entity: %v", err)
	}

	entities, err := globalDB.ListEvidenceEntities("client-alpha", "", "")
	if err != nil {
		t.Fatalf("listing entities: %v", err)
	}
	if len(entities) != 1 {
		t.Fatalf("expected 1 entity for client-alpha, got %d", len(entities))
	}
	for _, e := range entities {
		if e.ClientID != "client-alpha" {
			t.Fatalf("expected client_id client-alpha, got %s", e.ClientID)
		}
	}
	t.Log("PASS: TestListEvidenceEntitiesExcludesOtherClient")
}

// TestListEntitiesExcludesGlobalInClientScope - GLOBAL entities not in client-scoped List
func TestListEntitiesExcludesGlobalInClientScope(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	_, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating client entity: %v", err)
	}
	_, err = globalDB.CreateEvidenceEntity("technique", "techniques", "T1001", "Global Tech", "Test", "GLOBAL", "", "src", "chk2", "user-admin", true)
	if err != nil {
		t.Fatalf("creating global entity: %v", err)
	}

	entities, err := globalDB.ListEvidenceEntities("client-alpha", "", "")
	if err != nil {
		t.Fatalf("listing entities: %v", err)
	}
	if len(entities) != 1 {
		t.Fatalf("expected 1 entity (client only), got %d", len(entities))
	}
	t.Log("PASS: TestListEntitiesExcludesGlobalInClientScope")
}

// TestEvidenceReviewCreate - positive: create review on own edge, verify verification_status updated
func TestEvidenceReviewCreate(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_2", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}

	reviewID, err := globalDB.CreateEvidenceReview(edgeID, "user-admin", "client-alpha", "APPROVED", "Good evidence", "pending", "verified", time.Now().Format(time.RFC3339), true, false)
	if err != nil {
		t.Fatalf("creating review: %v", err)
	}
	if reviewID == "" {
		t.Fatal("expected review ID")
	}

	// Verify edge verification_status was updated in the same transaction
	edge, err := globalDB.GetEvidenceEdge("client-alpha", edgeID)
	if err != nil {
		t.Fatalf("getting edge: %v", err)
	}
	if edge.VerificationStatus != "verified" {
		t.Fatalf("expected verification_status verified, got %s", edge.VerificationStatus)
	}
	t.Log("PASS: TestEvidenceReviewCreate")
}

// TestEvidenceReviewCrossClient - negative: review other client's edge
func TestEvidenceReviewCrossClient(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_2", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}

	// client-beta must not be able to review client-alpha's edge
	_, err = globalDB.CreateEvidenceReview(edgeID, "user-admin", "client-beta", "APPROVED", "Good evidence", "pending", "verified", time.Now().Format(time.RFC3339), true, false)
	if err == nil {
		t.Fatal("expected error for cross-client edge review")
	}
	t.Log("PASS: TestEvidenceReviewCrossClient")
}

// TestEvidenceReviewWithoutCapability - negative: review without capability
func TestEvidenceReviewWithoutCapability(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_2", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}

	// Without review capability, review should fail
	_, err = globalDB.CreateEvidenceReview(edgeID, "user-admin", "client-alpha", "APPROVED", "Good evidence", "pending", "verified", time.Now().Format(time.RFC3339), false, false)
	if err == nil {
		t.Fatal("expected error for review without capability")
	}
	t.Log("PASS: TestEvidenceReviewWithoutCapability")
}

// TestEvidenceReviewGlobalWithoutAuth - negative: GLOBAL edge review without auth
func TestEvidenceReviewGlobalWithoutAuth(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("technique", "techniques", "T1001", "Tech 1", "Test", "GLOBAL", "", "src", "chk1", "user-admin", true)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("technique", "techniques", "T1002", "Tech 2", "Test", "GLOBAL", "", "src", "chk2", "user-admin", true)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "GLOBAL", "", "3", "user-admin", true)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}

	// Without GLOBAL authorization, review should fail
	_, err = globalDB.CreateEvidenceReview(edgeID, "user-admin", "", "APPROVED", "Good evidence", "pending", "verified", time.Now().Format(time.RFC3339), true, false)
	if err == nil {
		t.Fatal("expected error for GLOBAL edge review without authorization")
	}
	t.Log("PASS: TestEvidenceReviewGlobalWithoutAuth")
}

// TestEvidenceRevokeEdge - positive: revoke own edge
func TestEvidenceRevokeEdge(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_2", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}

	err = globalDB.RevokeEvidenceEdge(edgeID, "user-admin", "client-alpha", "Compromised indicator", true, false)
	if err != nil {
		t.Fatalf("revoking edge: %v", err)
	}

	// Verify edge is revoked
	edge, err := globalDB.GetEvidenceEdge("client-alpha", edgeID)
	if err != nil {
		t.Fatalf("getting edge: %v", err)
	}
	if !edge.IsRevoked {
		t.Fatal("expected edge to be revoked")
	}
	if edge.RevokedBy != "user-admin" {
		t.Fatalf("expected revoked_by user-admin, got %s", edge.RevokedBy)
	}
	if edge.RevokeReason != "Compromised indicator" {
		t.Fatalf("expected revoke_reason Compromised indicator, got %s", edge.RevokeReason)
	}
	if edge.RevokedAt == "" {
		t.Fatal("expected revoked_at to be set")
	}
	t.Log("PASS: TestEvidenceRevokeEdge")
}

// TestEvidenceRevokeCrossClient - negative: revoke other client's edge
func TestEvidenceRevokeCrossClient(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_2", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}

	// client-beta must not be able to revoke client-alpha's edge
	err = globalDB.RevokeEvidenceEdge(edgeID, "user-admin", "client-beta", "Compromised", true, false)
	if err == nil {
		t.Fatal("expected error for cross-client edge revoke")
	}
	t.Log("PASS: TestEvidenceRevokeCrossClient")
}

// TestEvidenceRevokeWithoutCapability - negative: revoke without capability
func TestEvidenceRevokeWithoutCapability(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_2", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}

	// Without revoke capability, revoke should fail
	err = globalDB.RevokeEvidenceEdge(edgeID, "user-admin", "client-alpha", "Compromised", false, false)
	if err == nil {
		t.Fatal("expected error for revoke without capability")
	}
	t.Log("PASS: TestEvidenceRevokeWithoutCapability")
}

// TestEvidenceRevokeAlreadyRevoked - negative: repeat revoke
func TestEvidenceRevokeAlreadyRevoked(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_2", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}

	err = globalDB.RevokeEvidenceEdge(edgeID, "user-admin", "client-alpha", "First revoke", true, false)
	if err != nil {
		t.Fatalf("first revoke: %v", err)
	}

	// Second revoke should fail
	err = globalDB.RevokeEvidenceEdge(edgeID, "user-admin", "client-alpha", "Second revoke", true, false)
	if err == nil {
		t.Fatal("expected error for repeat revoke")
	}
	t.Log("PASS: TestEvidenceRevokeAlreadyRevoked")
}

// TestEvidenceRevokeGlobalWithoutAuth - negative: GLOBAL edge revoke without auth
func TestEvidenceRevokeGlobalWithoutAuth(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("technique", "techniques", "T1001", "Tech 1", "Test", "GLOBAL", "", "src", "chk1", "user-admin", true)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("technique", "techniques", "T1002", "Tech 2", "Test", "GLOBAL", "", "src", "chk2", "user-admin", true)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "GLOBAL", "", "3", "user-admin", true)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}

	// Without GLOBAL authorization, revoke should fail
	err = globalDB.RevokeEvidenceEdge(edgeID, "user-admin", "", "Compromised", true, false)
	if err == nil {
		t.Fatal("expected error for GLOBAL edge revoke without authorization")
	}
	t.Log("PASS: TestEvidenceRevokeGlobalWithoutAuth")
}

// TestEvidenceUpdateRevokedEdge - negative: update revoked edge
func TestEvidenceUpdateRevokedEdge(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_2", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}

	err = globalDB.RevokeEvidenceEdge(edgeID, "user-admin", "client-alpha", "Compromised", true, false)
	if err != nil {
		t.Fatalf("revoking edge: %v", err)
	}

	// Update on revoked edge should fail
	err = globalDB.UpdateEvidenceEdge(edgeID, "relationship_confidence", "4", "user-admin", "client-alpha", false)
	if err == nil {
		t.Fatal("expected error for updating revoked edge")
	}
	t.Log("PASS: TestEvidenceUpdateRevokedEdge")
}

// TestEvidenceTransactionRollback - error in transaction doesn't leave partial changes
func TestEvidenceTransactionRollback(t *testing.T) {
	db := testCTIDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()

	// Verify CreateEvidenceReview fails atomically: validation error before tx
	e1, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_1", "Entity 1", "Test", "CLIENT", "client-alpha", "src", "chk1", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 1: %v", err)
	}
	e2, err := globalDB.CreateEvidenceEntity("indicator", "indicators", "ind_alpha_2", "Entity 2", "Test", "CLIENT", "client-alpha", "src", "chk2", "user-admin", false)
	if err != nil {
		t.Fatalf("creating entity 2: %v", err)
	}
	edgeID, err := globalDB.CreateEvidenceEdge(e1, e2, "USES", "CLIENT", "client-alpha", "3", "user-admin", false)
	if err != nil {
		t.Fatalf("creating edge: %v", err)
	}

	edge, err := globalDB.GetEvidenceEdge("client-alpha", edgeID)
	if err != nil {
		t.Fatalf("getting edge: %v", err)
	}
	originalStatus := edge.VerificationStatus

	// Review without capability fails at validation, before any transaction
	_, err = globalDB.CreateEvidenceReview(edgeID, "user-admin", "client-alpha", "APPROVED", "Good evidence", "pending", "verified", time.Now().Format(time.RFC3339), false, false)
	if err == nil {
		t.Fatal("expected error for review without capability")
	}

	// Verify no partial changes: verification_status unchanged
	edge, err = globalDB.GetEvidenceEdge("client-alpha", edgeID)
	if err != nil {
		t.Fatalf("getting edge: %v", err)
	}
	if edge.VerificationStatus != originalStatus {
		t.Fatalf("expected verification_status %s, got %s", originalStatus, edge.VerificationStatus)
	}

	// Verify SQLite transaction rollback: force constraint violation, rollback, verify nothing persisted
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("beginning transaction: %v", err)
	}
	validID := nextID("entity")
	_, err = tx.Exec(`INSERT INTO evidence_entities (entity_id, entity_type, entity_ref_type, entity_ref, display_name, description, visibility_scope, client_id, provenance_source, provenance_checksum, created_at, updated_at, created_by)
		VALUES (?, 'indicator', 'indicators', 'ind_rollback_test', 'Rollback Test', 'Test', 'CLIENT', 'client-alpha', 'src', 'chk', datetime('now'), datetime('now'), 'user-admin')`,
		validID)
	if err != nil {
		t.Fatalf("inserting entity: %v", err)
	}
	// Duplicate entity_id = constraint violation
	_, err = tx.Exec(`INSERT INTO evidence_entities (entity_id, entity_type, entity_ref_type, entity_ref, display_name, description, visibility_scope, client_id, provenance_source, provenance_checksum, created_at, updated_at, created_by)
		VALUES (?, 'indicator', 'indicators', 'ind_rollback_test2', 'Rollback Test 2', 'Test', 'CLIENT', 'client-alpha', 'src', 'chk', datetime('now'), datetime('now'), 'user-admin')`,
		validID)
	if err == nil {
		t.Fatal("expected constraint violation for duplicate entity_id")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rolling back transaction: %v", err)
	}

	// Verify the entity was NOT persisted (rollback worked)
	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM evidence_entities WHERE entity_id = ?`, validID).Scan(&count)
	if err != nil {
		t.Fatalf("counting entities: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 entities after rollback, got %d", count)
	}

	t.Log("PASS: TestEvidenceTransactionRollback")
}
