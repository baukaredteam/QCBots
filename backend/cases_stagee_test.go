package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func seedHypothesis(t *testing.T, db *DB, hypID, clientID string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO hunt_hypotheses (hypothesis_id, client_id, title, description, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'GENERATED', datetime('now'), datetime('now'))`, hypID, clientID, "Hunt "+hypID, "desc "+hypID); err != nil {
		t.Fatalf("inserting hypothesis %s: %v", hypID, err)
	}
}

// Blocker fix 1: non-admin reviewer succeeds, CTI_ANALYST without REVIEW gets 403.
func TestReviewPermissionIsSeparateFromAdmin(t *testing.T) {
	db := seedCaseTestEnv(t)
	defer db.Close()
	caseID, err := CreateResearchCase("user-analyst-alpha", "Reviewer Case", "d", "idem-reviewer-1", "client-alpha")
	if err != nil {
		t.Fatalf("creating case: %v", err)
	}
	// Reviewer is not a participant; make reviewer an active participant via owner.
	if err := AddCaseParticipant(caseID, "user-analyst-alpha", "user-reviewer", "VIEWER"); err != nil {
		t.Fatalf("adding reviewer participant: %v", err)
	}
	seedArtifactDB(t, db, caseID, "art-reviewer-1", "CLIENT", "client-alpha", "PUBLIC", "hash-reviewer-1")

	// Non-admin reviewer succeeds.
	if _, err := ReviewCaseArtifact(caseID, "user-reviewer", "art-reviewer-1", "APPROVED", "ok"); err != nil {
		t.Fatalf("reviewer should be allowed, got %v", err)
	}
	// CTI_ANALYST owner without REVIEW is denied.
	seedArtifactDB(t, db, caseID, "art-reviewer-2", "CLIENT", "client-alpha", "PUBLIC", "hash-reviewer-2")
	if _, err := ReviewCaseArtifact(caseID, "user-analyst-alpha", "art-reviewer-2", "APPROVED", "ok"); !errors.Is(err, ErrReviewPermissionDenied) {
		t.Fatalf("expected ErrReviewPermissionDenied for CTI_ANALYST, got %v", err)
	}
	// HTTP: analyst gets 403 even with valid body.
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/v1/cases/{case_id}/artifacts/{artifact_id}/review", http.HandlerFunc(handleReviewArtifact))
	r := sessionRequest(t, "PUT", "/api/v1/cases/"+caseID+"/artifacts/art-reviewer-2/review", `{"decision":"APPROVED"}`, "user-analyst-alpha", "client-alpha")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Errorf("expected 403 for analyst HTTP review, got %d: %s", w.Code, w.Body.String())
	}
}

// Blocker fix 2: CLIENT review activity is CLIENT-scoped; beta activity hidden from alpha.
func TestReviewActivityIsClientScoped(t *testing.T) {
	db := seedCaseTestEnv(t)
	defer db.Close()
	caseID, err := CreateResearchCase("user-analyst-alpha", "Act Scope", "d", "idem-act-scope-1", "client-alpha")
	if err != nil {
		t.Fatalf("creating case: %v", err)
	}
	seedArtifactDB(t, db, caseID, "art-alpha-scope", "CLIENT", "client-alpha", "PUBLIC", "hash-scope-alpha")
	seedArtifactDB(t, db, caseID, "art-beta-scope", "CLIENT", "client-beta", "PUBLIC", "hash-scope-beta")

	// Admin with alpha grant reviews alpha artifact -> CLIENT activity for alpha.
	if _, err := ReviewCaseArtifact(caseID, "user-admin", "art-alpha-scope", "APPROVED", "ok"); err != nil {
		t.Fatalf("review alpha: %v", err)
	}
	// Verify DB row scope.
	var scopeClient string
	if err := db.QueryRow(`SELECT visibility_scope || ':' || IFNULL(client_id,'NULL') FROM case_activity WHERE action='artifact_reviewed' AND details='art-alpha-scope:APPROVED'`).Scan(&scopeClient); err != nil {
		t.Fatalf("reading review activity: %v", err)
	}
	if scopeClient != "CLIENT:client-alpha" {
		t.Errorf("expected CLIENT:client-alpha activity, got %s", scopeClient)
	}
	// Simulate a beta CLIENT review activity directly (admin without beta grant cannot create it via API, but beta attacker inserts).
	if _, err := db.Exec(`INSERT INTO case_activity (activity_id, case_id, user_id, action, visibility_scope, client_id, details)
		VALUES ('act-beta-review', ?, 'user-analyst-beta', 'artifact_reviewed', 'CLIENT', 'client-beta', 'art-beta-scope:APPROVED')`, caseID); err != nil {
		t.Fatalf("inserting beta review activity: %v", err)
	}
	// Alpha user with GLOBAL case + alpha grant must not see beta review activity.
	rows, total, err := ListVisibleCaseActivityPaged(caseID, "user-analyst-alpha", 20, 0)
	if err != nil {
		t.Fatalf("ListVisibleCaseActivityPaged: %v", err)
	}
	if total != 1 {
		t.Errorf("expected total 1 (only alpha), got %d (%+v)", total, rows)
	}
	for _, a := range rows {
		if strings.Contains(a.Details, "art-beta-scope") {
			t.Error("beta review activity leaked to alpha")
		}
	}
}

func TestStageELinkFilterAndIdempotency(t *testing.T) {
	db := seedCaseTestEnv(t)
	defer db.Close()
	caseID, err := CreateResearchCase("user-analyst-alpha", "Hyp Case", "d", "idem-hyp-1", "client-alpha")
	if err != nil {
		t.Fatalf("creating case: %v", err)
	}
	seedHypothesis(t, db, "hyp-alpha-1", "client-alpha")
	seedHypothesis(t, db, "hyp-beta-1", "client-beta")

	// Cross-client linking via business layer denied for alpha (no beta grant).
	if err := LinkCaseHypothesis(caseID, "user-analyst-alpha", "hyp-beta-1"); !errors.Is(err, ErrHypothesisAccessDenied) {
		t.Fatalf("expected ErrHypothesisAccessDenied, got %v", err)
	}
	// Valid linking.
	if err := LinkCaseHypothesis(caseID, "user-analyst-alpha", "hyp-alpha-1"); err != nil {
		t.Fatalf("LinkCaseHypothesis: %v", err)
	}
	// Repeat linking: no duplicate.
	if err := LinkCaseHypothesis(caseID, "user-analyst-alpha", "hyp-alpha-1"); err != nil {
		t.Fatalf("repeat link: %v", err)
	}
	var cnt int
	if err := db.QueryRow(`SELECT COUNT(*) FROM case_hypotheses WHERE case_id=? AND hypothesis_id='hyp-alpha-1'`, caseID).Scan(&cnt); err != nil {
		t.Fatalf("counting links: %v", err)
	}
	if cnt != 1 {
		t.Errorf("expected 1 link row, got %d", cnt)
	}
	// List: alpha sees only alpha.
	rows, total, err := ListLinkedHypotheses(caseID, "user-analyst-alpha", 20, 0)
	if err != nil {
		t.Fatalf("ListLinkedHypotheses: %v", err)
	}
	if total != 1 {
		t.Errorf("expected total 1, got %d", total)
	}
	for _, h := range rows {
		if h.ClientID == "client-beta" {
			t.Error("beta hypothesis leaked to alpha")
		}
	}
	// Unlink idempotent.
	if err := UnlinkCaseHypothesis(caseID, "user-analyst-alpha", "hyp-alpha-1"); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if err := UnlinkCaseHypothesis(caseID, "user-analyst-alpha", "hyp-alpha-1"); err != nil {
		t.Fatalf("repeat unlink: %v", err)
	}
	rows2, total2, err := ListLinkedHypotheses(caseID, "user-analyst-alpha", 20, 0)
	if err != nil {
		t.Fatalf("ListLinkedHypotheses after unlink: %v", err)
	}
	if total2 != 0 || len(rows2) != 0 {
		t.Errorf("expected 0 after unlink, got total=%d len=%d", total2, len(rows2))
	}
}

func TestStageEPerClientReviewHistoryAndOutcome(t *testing.T) {
	db := seedCaseTestEnv(t)
	defer db.Close()
	caseID, err := CreateResearchCase("user-analyst-alpha", "Hyp Rev", "d", "idem-hyprev-1", "client-alpha")
	if err != nil {
		t.Fatalf("creating case: %v", err)
	}
	seedHypothesis(t, db, "hyp-rev-1", "client-alpha")
	if err := LinkCaseHypothesis(caseID, "user-analyst-alpha", "hyp-rev-1"); err != nil {
		t.Fatalf("link: %v", err)
	}
	// Reviewer needs participant status for case access: add reviewer as participant.
	if err := AddCaseParticipant(caseID, "user-analyst-alpha", "user-reviewer", "VIEWER"); err != nil {
		t.Fatalf("adding reviewer: %v", err)
	}
	// Unauthorized reviewer (analyst) denied.
	if _, err := ReviewCaseHypothesis(caseID, "user-analyst-alpha", "hyp-rev-1", "client-alpha", "APPROVED", "x"); !errors.Is(err, ErrReviewPermissionDenied) {
		t.Fatalf("expected ErrReviewPermissionDenied, got %v", err)
	}
	// Per-client review append-only.
	r1, err := ReviewCaseHypothesis(caseID, "user-reviewer", "hyp-rev-1", "client-alpha", "REJECTED", "first")
	if err != nil {
		t.Fatalf("first review: %v", err)
	}
	r2, err := ReviewCaseHypothesis(caseID, "user-reviewer", "hyp-rev-1", "client-alpha", "APPROVED", "second")
	if err != nil {
		t.Fatalf("second review: %v", err)
	}
	if r1.ReviewID == r2.ReviewID {
		t.Error("review ids must differ")
	}
	// History both rows preserved.
	var cnt int
	if err := db.QueryRow(`SELECT COUNT(*) FROM case_hypothesis_review WHERE case_id=? AND hypothesis_id='hyp-rev-1' AND client_id='client-alpha'`, caseID).Scan(&cnt); err != nil {
		t.Fatalf("counting reviews: %v", err)
	}
	if cnt != 2 {
		t.Errorf("expected 2 reviews, got %d", cnt)
	}
	// Latest is APPROVED (r2).
	rows, total, err := ListLinkedHypotheses(caseID, "user-analyst-alpha", 20, 0)
	if err != nil {
		t.Fatalf("list hypotheses: %v", err)
	}
	if total != 1 || rows[0].LatestDecision != "APPROVED" || rows[0].LatestReviewID != r2.ReviewID {
		t.Errorf("expected latest APPROVED r2, got %+v", rows)
	}
	// Hunt execution outcome is separate: investigation verdict does not overwrite review.
	inv, err := CreateCaseInvestigation(caseID, "user-analyst-alpha", "hyp-rev-1", "client-alpha", "2026-11-07--2026-11-08", "evidence", "found insecure config")
	if err != nil {
		t.Fatalf("CreateCaseInvestigation: %v", err)
	}
	if inv.InvestigationID == "" {
		t.Fatal("expected investigation id")
	}
	// Investigation is CLIENT agency; alpha activity total grows.
	act, actTotal, err := ListVisibleCaseActivityPaged(caseID, "user-analyst-alpha", 20, 0)
	if err != nil {
		t.Fatalf("activity: %v", err)
	}
	if actTotal < 3 {
		t.Errorf("expected at least 3 activity rows (link+2 reviews+investigation), got %d (%+v)", actTotal, act)
	}
	// Cross-client review denied.
	if _, err := ReviewCaseHypothesis(caseID, "user-reviewer", "hyp-rev-1", "client-beta", "APPROVED", "x"); err == nil {
		t.Fatal("expected client mismatch denial")
	}
	// Immutable review history triggers.
	if _, err := db.Exec(`UPDATE case_hypothesis_review SET decision='REJECTED' WHERE review_id=?`, r1.ReviewID); err == nil {
		t.Fatal("expected UPDATE on case_hypothesis_review to fail")
	}
	if _, err := db.Exec(`DELETE FROM case_hypothesis_review WHERE review_id=?`, r1.ReviewID); err == nil {
		t.Fatal("expected DELETE on case_hypothesis_review to fail")
	}
}

func TestStageEHTTPLinkReviewInvestigation(t *testing.T) {
	db := seedCaseTestEnv(t)
	defer db.Close()
	caseID, err := CreateResearchCase("user-analyst-alpha", "HTTP Hyp", "d", "idem-httphyp-1", "client-alpha")
	if err != nil {
		t.Fatalf("creating case: %v", err)
	}
	seedHypothesis(t, db, "hyp-http-1", "client-alpha")
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/cases/{case_id}/hypotheses/{hypothesis_id}", http.HandlerFunc(handleLinkHypothesis))
	mux.HandleFunc("DELETE /api/v1/cases/{case_id}/hypotheses/{hypothesis_id}", http.HandlerFunc(handleUnlinkHypothesis))
	mux.HandleFunc("GET /api/v1/cases/{case_id}/hypotheses", http.HandlerFunc(handleListHypotheses))
	mux.HandleFunc("POST /api/v1/cases/{case_id}/hypotheses/{hypothesis_id}/review", http.HandlerFunc(handleReviewHypothesis))
	mux.HandleFunc("POST /api/v1/cases/{case_id}/investigations", http.HandlerFunc(handleCreateInvestigation))

	// analyst-multi needs case access (participant) to link hypotheses.
	if err := AddCaseParticipant(caseID, "user-analyst-alpha", "user-analyst-multi", "EDITOR"); err != nil {
		t.Fatalf("adding multi participant: %v", err)
	}
	// analyst-multi is HYPOTHESIS_WRITER with alpha grant -> can link.
	r := sessionRequest(t, "POST", "/api/v1/cases/"+caseID+"/hypotheses/hyp-http-1", "", "user-analyst-multi", "client-alpha")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatalf("link expected 201, got %d: %s", w.Code, w.Body.String())
	}
	// List via HTTP.
	r2 := sessionRequest(t, "GET", "/api/v1/cases/"+caseID+"/hypotheses", "", "user-analyst-alpha", "client-alpha")
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, r2)
	if w2.Code != 200 {
		t.Fatalf("list expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	// Review via HTTP by reviewer (need participant).
	if err := AddCaseParticipant(caseID, "user-analyst-alpha", "user-reviewer", "VIEWER"); err != nil {
		t.Fatalf("adding reviewer: %v", err)
	}
	r3 := sessionRequest(t, "POST", "/api/v1/cases/"+caseID+"/hypotheses/hyp-http-1/review", `{"client_id":"client-alpha","decision":"APPROVED"}`, "user-reviewer", "client-alpha")
	w3 := httptest.NewRecorder()
	mux.ServeHTTP(w3, r3)
	if w3.Code != 201 {
		t.Fatalf("review expected 201, got %d: %s", w3.Code, w3.Body.String())
	}
	// Unauthorized reviewer (analyst) denied on HTTP.
	r4 := sessionRequest(t, "POST", "/api/v1/cases/"+caseID+"/hypotheses/hyp-http-1/review", `{"client_id":"client-alpha","decision":"APPROVED"}`, "user-analyst-alpha", "client-alpha")
	w4 := httptest.NewRecorder()
	mux.ServeHTTP(w4, r4)
	if w4.Code != 403 {
		t.Errorf("expected 403 for analyst review HTTP, got %d: %s", w4.Code, w4.Body.String())
	}
	// Investigation via HTTP (analyst).
	r5 := sessionRequest(t, "POST", "/api/v1/cases/"+caseID+"/investigations", `{"hypothesis_id":"hyp-http-1","client_id":"client-alpha","time_range":"t1","evidence":"e","analyst_findings":"f"}`, "user-analyst-alpha", "client-alpha")
	w5 := httptest.NewRecorder()
	mux.ServeHTTP(w5, r5)
	if w5.Code != 201 {
		t.Fatalf("investigation expected 201, got %d: %s", w5.Code, w5.Body.String())
	}
	// Cross-client investigation denied (alpha lacks beta grant).
	r6 := sessionRequest(t, "POST", "/api/v1/cases/"+caseID+"/investigations", `{"hypothesis_id":"hyp-http-1","client_id":"client-beta","time_range":"t1"}`, "user-analyst-alpha", "client-alpha")
	w6 := httptest.NewRecorder()
	mux.ServeHTTP(w6, r6)
	if w6.Code != 403 {
		t.Errorf("expected 403 cross-client investigation, got %d: %s", w6.Code, w6.Body.String())
	}
}

// Ensure errors import used even when file otherwise standalone.
var _ = errors.Is
