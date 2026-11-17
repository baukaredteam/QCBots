package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLatestHypothesisReviewDeterministicOnTie(t *testing.T) {
	db := seedCaseTestEnv(t)
	defer db.Close()

	caseID, err := CreateResearchCase("user-analyst-alpha", "Review Case", "d", "idem-rev-tie-1", "client-alpha")
	if err != nil {
		t.Fatalf("creating case: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO hunt_hypotheses (hypothesis_id, client_id, title, description, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'GENERATED', datetime('now'), datetime('now'))`, "hyp-tie", "client-alpha", "Hyp", "desc"); err != nil {
		t.Fatalf("inserting hypothesis: %v", err)
	}
	// Identical reviewed_at: tie-break is review_id DESC -> "rev-b" wins.
	if _, err := db.Exec(`INSERT INTO case_hypothesis_review (review_id, case_id, hypothesis_id, client_id, reviewer_id, decision, reviewed_at)
		VALUES (?, ?, ?, ?, ?, 'REJECTED', '2026-11-08 10:00:00')`, "rev-a", caseID, "hyp-tie", "client-alpha", "user-analyst-alpha"); err != nil {
		t.Fatalf("inserting review a: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO case_hypothesis_review (review_id, case_id, hypothesis_id, client_id, reviewer_id, decision, reviewed_at)
		VALUES (?, ?, ?, ?, ?, 'APPROVED', '2026-11-08 10:00:00')`, "rev-b", caseID, "hyp-tie", "client-alpha", "user-analyst-alpha"); err != nil {
		t.Fatalf("inserting review b: %v", err)
	}
	id, decision, err := GetLatestHypothesisReview(caseID, "hyp-tie", "client-alpha")
	if err != nil {
		t.Fatalf("GetLatestHypothesisReview: %v", err)
	}
	if id != "rev-b" || decision != "APPROVED" {
		t.Errorf("expected rev-b/APPROVED deterministically, got %s/%s", id, decision)
	}
}

func TestStageCLifecycleAndParticipants(t *testing.T) {
	db := seedCaseTestEnv(t)
	defer db.Close()

	// Owner: analyst-alpha (CTI_ANALYST). Second user beta added as participant.
	caseID, err := CreateResearchCase("user-analyst-alpha", "Lifecycle Case", "d", "idem-life-1", "client-alpha")
	if err != nil {
		t.Fatalf("creating case: %v", err)
	}

	// Add participant beta as EDITOR by owner.
	if err := AddCaseParticipant(caseID, "user-analyst-alpha", "user-analyst-beta", "EDITOR"); err != nil {
		t.Fatalf("AddCaseParticipant: %v", err)
	}
	parts, err := ListCaseParticipants(caseID, "user-analyst-alpha")
	if err != nil {
		t.Fatalf("ListCaseParticipants: %v", err)
	}
	found := false
	for _, p := range parts {
		if p.UserID == "user-analyst-beta" && p.RoleInCase == "EDITOR" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected beta as EDITOR participant, got %+v", parts)
	}

	// Non-owner (beta) cannot add participants via HTTP.
	muxAdd := http.NewServeMux()
	muxAdd.HandleFunc("POST /api/v1/cases/{case_id}/participants", http.HandlerFunc(handleAddCaseParticipant))
	r := sessionRequest(t, "POST", "/api/v1/cases/"+caseID+"/participants", `{"user_id":"user-admin","role_in_case":"VIEWER"}`, "user-analyst-beta", "client-beta")
	w := httptest.NewRecorder()
	muxAdd.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Errorf("non-owner add expected 403, got %d: %s", w.Code, w.Body.String())
	}

	// OPEN -> IN_PROGRESS by owner analyst.
	if err := TransitionCaseStatus(caseID, "user-analyst-alpha", "IN_PROGRESS", ""); err != nil {
		t.Fatalf("OPEN->IN_PROGRESS: %v", err)
	}
	// IN_PROGRESS -> ARCHIVED is not an allowed edge.
	if err := TransitionCaseStatus(caseID, "user-analyst-alpha", "ARCHIVED", ""); err == nil {
		t.Fatal("expected ErrInvalidTransition for IN_PROGRESS->ARCHIVED")
	} else if !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("expected ErrInvalidTransition, got %v", err)
	}
	// IN_PROGRESS -> REVIEW by analyst.
	if err := TransitionCaseStatus(caseID, "user-analyst-alpha", "REVIEW", ""); err != nil {
		t.Fatalf("IN_PROGRESS->REVIEW: %v", err)
	}
	// REVIEW -> CLOSED by analyst must be denied (ADMIN only).
	if err := TransitionCaseStatus(caseID, "user-analyst-alpha", "CLOSED", ""); err == nil {
		t.Fatal("expected denial for analyst REVIEW->CLOSED")
	}
	// REVIEW -> CLOSED by admin.
	if err := TransitionCaseStatus(caseID, "user-admin", "CLOSED", "resolved"); err != nil {
		t.Fatalf("admin REVIEW->CLOSED: %v", err)
	}
	// CLOSED -> ARCHIVED by admin.
	if err := TransitionCaseStatus(caseID, "user-admin", "ARCHIVED", ""); err != nil {
		t.Fatalf("admin CLOSED->ARCHIVED: %v", err)
	}
	// ARCHIVED is terminal: any further transition fails.
	if err := TransitionCaseStatus(caseID, "user-admin", "OPEN", ""); err == nil {
		t.Fatal("expected terminal failure on ARCHIVED")
	} else if !errors.Is(err, ErrCaseArchived) {
		t.Errorf("expected ErrCaseArchived, got %v", err)
	}
	// Participant mutation on archived case fails.
	if err := RemoveCaseParticipant(caseID, "user-analyst-alpha", "user-analyst-beta"); err == nil {
		t.Fatal("expected archived block on participant removal")
	} else if !errors.Is(err, ErrCaseArchived) {
		t.Errorf("expected ErrCaseArchived, got %v", err)
	}

	// Revocation cuts off access (separate non-archived case).
	case2, err := CreateResearchCase("user-analyst-alpha", "Revoke Case", "d", "idem-life-2", "client-alpha")
	if err != nil {
		t.Fatalf("creating case2: %v", err)
	}
	if err := AddCaseParticipant(case2, "user-analyst-alpha", "user-analyst-beta", "VIEWER"); err != nil {
		t.Fatalf("adding beta to case2: %v", err)
	}
	if err := RemoveCaseParticipant(case2, "user-analyst-alpha", "user-analyst-beta"); err != nil {
		t.Fatalf("revoking beta: %v", err)
	}
	if _, err := GetResearchCase(case2, "user-analyst-beta"); !errors.Is(err, ErrCaseAccessDenied) {
		t.Errorf("revoked participant must lose access, got %v", err)
	}

	// HTTP participant list works for the owner (via mux for PathValue).
	mux2 := http.NewServeMux()
	mux2.HandleFunc("GET /api/v1/cases/{case_id}/participants", http.HandlerFunc(handleListCaseParticipants))
	r2 := sessionRequest(t, "GET", "/api/v1/cases/"+caseID+"/participants", "", "user-admin", "client-alpha")
	w2 := httptest.NewRecorder()
	mux2.ServeHTTP(w2, r2)
	if w2.Code != 200 {
		t.Errorf("list participants expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	if w2.Code == 200 && len(w2.Body.String()) == 0 {
		t.Error("non-empty participants body expected")
	}
}
