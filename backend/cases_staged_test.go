package main

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// seedArtifact associates an artifact with a newly created case.
func seedArtifactDB(t *testing.T, db *DB, caseID, artifactID, scope, clientID, classification, hash string) {
	t.Helper()
	var clientArg interface{}
	if clientID != "" {
		clientArg = clientID
	}
	if _, err := db.Exec(`INSERT INTO case_artifacts
		(artifact_id, case_id, visibility_scope, client_id, data_classification, provenance_source, artifact_hash, sanitized_representation, created_by)
		VALUES (?, ?, ?, ?, ?, 'test-provenance', ?, ?, ?)`,
		artifactID, caseID, scope, clientArg, classification, hash, "SANITIZED_"+artifactID, "user-analyst-alpha"); err != nil {
		t.Fatalf("inserting artifact %s: %v", artifactID, err)
	}
}

func TestStageDArtifactReviewForbiddenForNonReviewer(t *testing.T) {
	db := seedCaseTestEnv(t)
	defer db.Close()
	caseID, err := CreateResearchCase("user-analyst-alpha", "Review Case", "d", "idem-review-1", "client-alpha")
	if err != nil {
		t.Fatalf("creating case: %v", err)
	}
	seedArtifactDB(t, db, caseID, "art-1", "CLIENT", "client-alpha", "PUBLIC", "hash-art-1")

	// Non-admin (CTI_ANALYST) cannot review -> 403.
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/v1/cases/{case_id}/artifacts/{artifact_id}/review", http.HandlerFunc(handleReviewArtifact))
	r := sessionRequest(t, "PUT", "/api/v1/cases/"+caseID+"/artifacts/art-1/review", `{"decision":"APPROVED"}`, "user-analyst-alpha", "client-alpha")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	// Handler does not enforce IsAdministrator itself; middleware does in prod.
	// Direct-handler path must still deny non-reviewers.
	if w.Code != 403 {
		t.Errorf("expected 403 for non-reviewer, got %d: %s", w.Code, w.Body.String())
	}
}

func TestStageDArtifactReviewCrossClientDenied(t *testing.T) {
	db := seedCaseTestEnv(t)
	defer db.Close()
	// Beta case with beta artifact.
	betaCase, err := CreateResearchCase("user-analyst-beta", "Beta Case", "d", "idem-review-beta-1", "client-beta")
	if err != nil {
		t.Fatalf("creating beta case: %v", err)
	}
	seedArtifactDB(t, db, betaCase, "art-beta-1", "CLIENT", "client-beta", "PUBLIC", "hash-art-beta-1")

	// Admin has grant only for client-alpha (seeded) -> reviewing beta artifact must fail.
	if _, err := ReviewCaseArtifact(betaCase, "user-admin", "art-beta-1", "APPROVED", "ok"); !errors.Is(err, ErrClientAccessDenied) {
		t.Fatalf("expected ErrClientAccessDenied, got %v", err)
	}
	// Sanity: beta author (not admin) also denied as non-reviewer.
	if _, err := ReviewCaseArtifact(betaCase, "user-analyst-beta", "art-beta-1", "APPROVED", "ok"); !errors.Is(err, ErrReviewPermissionDenied) {
		t.Fatalf("expected ErrReviewPermissionDenied, got %v", err)
	}
}

func TestStageDArtifactReviewSuccessAtomicAndImmutable(t *testing.T) {
	db := seedCaseTestEnv(t)
	defer db.Close()
	caseID, err := CreateResearchCase("user-analyst-alpha", "Review Case2", "d", "idem-review-2", "client-alpha")
	if err != nil {
		t.Fatalf("creating case: %v", err)
	}
	seedArtifactDB(t, db, caseID, "art-2", "CLIENT", "client-alpha", "PUBLIC", "hash-art-2")

	// Invalid decision leaves no trace.
	if _, err := ReviewCaseArtifact(caseID, "user-admin", "art-2", "LGTM", "x"); !errors.Is(err, ErrInvalidReviewDecision) {
		t.Fatalf("expected ErrInvalidReviewDecision, got %v", err)
	}
	var reviewedBy sql.NullString
	if err := db.QueryRow(`SELECT reviewed_by FROM case_artifacts WHERE artifact_id='art-2'`).Scan(&reviewedBy); err != nil {
		t.Fatalf("reading artifact: %v", err)
	}
	if reviewedBy.Valid {
		t.Error("invalid review must leave no trace")
	}

	// Successful review.
	res, err := ReviewCaseArtifact(caseID, "user-admin", "art-2", "NEEDS_MORE_DATA", "need more")
	if err != nil {
		t.Fatalf("ReviewCaseArtifact: %v", err)
	}
	if res.Decision != "NEEDS_MORE_DATA" || res.ReviewedBy != "user-admin" {
		t.Errorf("unexpected review result %+v", res)
	}
	// Atomic activity row exists.
	var actCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM case_activity WHERE case_id=? AND action='artifact_reviewed' AND details='art-2:NEEDS_MORE_DATA'`, caseID).Scan(&actCount); err != nil {
		t.Fatalf("counting activity: %v", err)
	}
	if actCount != 1 {
		t.Errorf("expected 1 review activity row, got %d", actCount)
	}
	// Global activity must not leak artifact sanitized content.
	var globalLeak int
	if err := db.QueryRow(`SELECT COUNT(*) FROM case_activity WHERE visibility_scope='GLOBAL' AND details LIKE '%SANITIZED_art-2%'`).Scan(&globalLeak); err != nil {
		t.Fatalf("checking global leak: %v", err)
	}
	if globalLeak != 0 {
		t.Error("GLOBAL activity leaked artifact content")
	}
	// Second review is an invalid transition (first wins, history append-only).
	if _, err := ReviewCaseArtifact(caseID, "user-admin", "art-2", "APPROVED", "x"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected fatal invalid transition for second review, got %v", err)
	}
	// Immutable history: UPDATE and DELETE on case_activity must fail.
	if _, err := db.Exec(`UPDATE case_activity SET details='tampered' WHERE case_id=?`, caseID); err == nil {
		t.Fatal("expected UPDATE on case_activity to fail")
	}
	if _, err := db.Exec(`DELETE FROM case_activity WHERE case_id=?`, caseID); err == nil {
		t.Fatal("expected DELETE on case_activity to fail")
	}
	// case_notes_revision immutability is covered in notes test.
}

func TestStageDNotesVisibilityAndRevokedGrant(t *testing.T) {
	db := seedCaseTestEnv(t)
	defer db.Close()
	caseID, err := CreateResearchCase("user-analyst-alpha", "Notes Case", "d", "idem-note-1", "client-alpha")
	if err != nil {
		t.Fatalf("creating case: %v", err)
	}
	// Alpha CLIENT note by alpha (granted alpha).
	noteA, err := CreateCaseNote(caseID, "user-analyst-alpha", "alpha-only body", "observation", "CLIENT", "client-alpha")
	if err != nil {
		t.Fatalf("CreateCaseNote alpha: %v", err)
	}
	// Beta note on same case via direct SQL (beta is not participant yet, but note row creation check precedence is done at API; simulate beta CLIENT note directly).
	if _, err := db.Exec(`INSERT INTO case_notes (note_id, case_id, user_id, note_text, note_type, visibility_scope, client_id, created_at, updated_at)
		VALUES ('note-beta-1', ?, 'user-analyst-beta', 'beta-only body', 'observation', 'CLIENT', 'client-beta', datetime('now'), datetime('now'))`, caseID); err != nil {
		t.Fatalf("inserting beta note: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO case_notes_revision (revision_id, note_id, note_text, created_by, created_at)
		VALUES ('rev-beta-1', 'note-beta-1', 'beta-only body', 'user-analyst-beta', datetime('now'))`); err != nil {
		t.Fatalf("inserting beta revision: %v", err)
	}
	// GLOBAL note.
	if _, err := CreateCaseNote(caseID, "user-analyst-alpha", "public global body", "observation", "GLOBAL", ""); err != nil {
		t.Fatalf("CreateCaseNote global: %v", err)
	}

	// Alpha sees alpha + global, not beta.
	notes, total, err := ListCaseNotes(caseID, "user-analyst-alpha", 20, 0)
	if err != nil {
		t.Fatalf("ListCaseNotes alpha: %v", err)
	}
	if total != 2 {
		t.Errorf("expected total 2 for alpha, got %d (%+v)", total, notes)
	}
	for _, n := range notes {
		if n.NoteID == "note-beta-1" {
			t.Error("beta note leaked to alpha")
		}
		if len(n.Revisions) == 0 {
			t.Errorf("expected revision for note %s", n.NoteID)
		}
		for _, r := range n.Revisions {
			if strings.Contains(r.NoteText, "beta-only") && n.NoteID != "note-beta-1" {
				t.Error("beta revision leaked")
			}
		}
	}
	if noteA == "" {
		t.Fatal("expected note id")
	}

	// Revoke alpha's grant -> alpha loses CLIENT visibility, keeps GLOBAL.
	if _, err := db.Exec(`DELETE FROM user_authorized_clients WHERE grant_id='grant-alpha-alpha'`); err != nil {
		t.Fatalf("revoking grant: %v", err)
	}
	notes2, total2, err := ListCaseNotes(caseID, "user-analyst-alpha", 20, 0)
	if err != nil {
		t.Fatalf("ListCaseNotes after revoke: %v", err)
	}
	if total2 != 1 {
		t.Errorf("expected total 1 (global only) after revoke, got %d (%+v)", total2, notes2)
	}
	for _, n := range notes2 {
		if n.ClientID == "client-alpha" {
			t.Error("alpha CLIENT note visible after grant revoked")
		}
	}

	// Immutable revision history.
	if _, err := db.Exec(`UPDATE case_notes_revision SET note_text='tampered' WHERE note_id=?`, noteA); err == nil {
		t.Fatal("expected UPDATE on case_notes_revision to fail")
	}
	if _, err := db.Exec(`DELETE FROM case_notes_revision WHERE note_id=?`, noteA); err == nil {
		t.Fatal("expected DELETE on case_notes_revision to fail")
	}
}

func TestStageDGlobalNoteRejectsClientData(t *testing.T) {
	db := seedCaseTestEnv(t)
	defer db.Close()
	caseID, err := CreateResearchCase("user-analyst-alpha", "Global Note Case", "d", "idem-note-2", "client-alpha")
	if err != nil {
		t.Fatalf("creating case: %v", err)
	}
	if _, err := CreateCaseNote(caseID, "user-analyst-alpha", "leaking client-alpha identifier", "observation", "GLOBAL", ""); !errors.Is(err, ErrGlobalArtifactClientData) {
		t.Fatalf("expected ErrGlobalArtifactClientData, got %v", err)
	}
	if _, err := CreateCaseNote(caseID, "user-analyst-alpha", "leaking client-beta identifier", "observation", "GLOBAL", ""); !errors.Is(err, ErrGlobalArtifactClientData) {
		t.Fatalf("expected ErrGlobalArtifactClientData for beta, got %v", err)
	}
}

func TestStageDActivityPaginationCountsAndNoLeak(t *testing.T) {
	db := seedCaseTestEnv(t)
	defer db.Close()
	caseID, err := CreateResearchCase("user-analyst-alpha", "Act Case", "d", "idem-act-1", "client-alpha")
	if err != nil {
		t.Fatalf("creating case: %v", err)
	}
	insertAct := func(id, scope, clientID, details string) {
		t.Helper()
		var c interface{}
		if clientID != "" {
			c = clientID
		}
		if _, err := db.Exec(`INSERT INTO case_activity (activity_id, case_id, user_id, action, visibility_scope, client_id, details, created_at)
			VALUES (?, ?, 'user-analyst-alpha', 'status_changed', ?, ?, ?, datetime('now'))`, id, caseID, scope, c, details); err != nil {
			t.Fatalf("inserting activity %s: %v", id, err)
		}
	}
	insertAct("act-g1", "GLOBAL", "", "public-g1")
	insertAct("act-a1", "CLIENT", "client-alpha", "alpha-secret-a1")
	insertAct("act-b1", "CLIENT", "client-beta", "BETA_SECRET_b1")

	// Admin (grant alpha only) sees global + alpha, total 2, no beta details.
	rows, total, err := ListVisibleCaseActivityPaged(caseID, "user-admin", 20, 0)
	if err != nil {
		t.Fatalf("ListVisibleCaseActivityPaged: %v", err)
	}
	if total != 2 {
		t.Errorf("expected total 2 for admin, got %d", total)
	}
	body := ""
	for _, r := range rows {
		body += r.Details + "|"
	}
	if strings.Contains(body, "BETA_SECRET_b1") {
		t.Error("beta CLIENT details leaked to admin")
	}
	if strings.Contains(body, "b1") && !strings.Contains(body, "alpha-secret") {
		// isolated check for beta leak handled above
	}

	// Pagination: page 1 of limit=1.
	page1, total1, err := ListVisibleCaseActivityPaged(caseID, "user-admin", 1, 0)
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1) != 1 || total1 != 2 {
		t.Errorf("expected page1 len 1 total 2, got len=%d total=%d", len(page1), total1)
	}

	// HTTP endpoint returns same total.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/cases/{case_id}/activity", http.HandlerFunc(handleListActivity))
	r := sessionRequest(t, "GET", "/api/v1/cases/"+caseID+"/activity?limit=20&offset=0", "", "user-admin", "client-alpha")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "BETA_SECRET_b1") {
		t.Error("HTTP leaked beta details")
	}
	if !strings.Contains(w.Body.String(), `"total":2`) {
		t.Errorf("expected total 2 in response, got %s", w.Body.String())
	}
}

func TestStageDHTTPReviewSuccess(t *testing.T) {
	db := seedCaseTestEnv(t)
	defer db.Close()
	caseID, err := CreateResearchCase("user-analyst-alpha", "HTTP Review", "d", "idem-http-review-1", "client-alpha")
	if err != nil {
		t.Fatalf("creating case: %v", err)
	}
	seedArtifactDB(t, db, caseID, "art-h1", "CLIENT", "client-alpha", "PUBLIC", "hash-h1")
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/v1/cases/{case_id}/artifacts/{artifact_id}/review", http.HandlerFunc(handleReviewArtifact))
	r := sessionRequest(t, "PUT", "/api/v1/cases/"+caseID+"/artifacts/art-h1/review", `{"decision":"APPROVED","reason":"verified"}`, "user-admin", "client-alpha")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"decision":"APPROVED"`) {
		t.Errorf("unexpected body %s", w.Body.String())
	}
}

func TestCasePayloadHashUnambiguousWithPipes(t *testing.T) {
	h1 := casePayloadHash("a|b", "c", "x", "P1", "LOW")
	h2 := casePayloadHash("a", "b|c", "x", "P1", "LOW")
	h3 := casePayloadHash("a|b", "c", "x", "P1", "LOW")
	if h1 == h2 {
		t.Fatalf("hashes collide for piped fields: %s", h1)
	}
	if h1 != h3 {
		t.Fatalf("deterministic hash expected: %s vs %s", h1, h3)
	}
}

func TestStageDSchemaNotReady(t *testing.T) {
	// testDB applies only up to 0004 (no 0005 tables). Stage D must refuse.
	db := testDB(t)
	defer db.Close()
	origDB := globalDB
	globalDB = db
	defer func() { globalDB = origDB }()
	// Seed case without 0005.
	if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES ('g1','user-analyst-alpha','client-alpha')`); err != nil {
		t.Fatalf("grant: %v", err)
	}
	caseID, err := CreateResearchCase("user-analyst-alpha", "No Schema Case", "d", "idem-noschema-1", "client-alpha")
	if err != nil {
		t.Fatalf("creating case: %v", err)
	}
	if _, err := CreateCaseNote(caseID, "user-analyst-alpha", "body", "observation", "GLOBAL", ""); !errors.Is(err, ErrSchemaNotReady) {
		t.Fatalf("expected ErrSchemaNotReady for notes, got %v", err)
	}
	if _, err := ReviewCaseArtifact(caseID, "user-admin", "art-x", "APPROVED", ""); !errors.Is(err, ErrSchemaNotReady) {
		t.Fatalf("expected ErrSchemaNotReady for review, got %v", err)
	}
	if _, _, err := ListVisibleCaseActivityPaged(caseID, "user-analyst-alpha", 20, 0); !errors.Is(err, ErrSchemaNotReady) {
		t.Fatalf("expected ErrSchemaNotReady for activity, got %v", err)
	}
}
