package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestM7dHuntHTTP(t *testing.T) {
	db := openM7DDB(t)
	defer db.Close()
	applyM7DMigration(t, db.DB)
	seedMitre(t, db)
	seedM7CFixture(t, db)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/hypotheses", applyMiddleware(http.HandlerFunc(handleCreateHypothesisManual), requireAuth, requirePermission(CanViewCTI), requirePermission(CanCreateHypothesis), auditWrap, csrfWrap))
	mux.HandleFunc("POST /api/v1/hypotheses/from-report", applyMiddleware(http.HandlerFunc(handleCreateHypothesisFromReport), requireAuth, requirePermission(CanViewCTI), requirePermission(CanCreateHypothesis), auditWrap, csrfWrap))
	mux.HandleFunc("GET /api/v1/hypotheses/{hypothesis_id}", applyMiddleware(http.HandlerFunc(handleGetHypothesis), requireAuth, requirePermission(CanViewCTI), auditWrap))
	mux.HandleFunc("PATCH /api/v1/hypotheses/{hypothesis_id}/versions/{version_no}", applyMiddleware(http.HandlerFunc(handleEditHypothesisVersion), requireAuth, requirePermission(CanViewCTI), requirePermission(CanCreateHypothesis), auditWrap, csrfWrap))
	mux.HandleFunc("POST /api/v1/hypotheses/{hypothesis_id}/submit", applyMiddleware(http.HandlerFunc(handleSubmitHypothesisReview), requireAuth, requirePermission(CanViewCTI), requirePermission(CanCreateHypothesis), auditWrap, csrfWrap))
	mux.HandleFunc("POST /api/v1/hypotheses/{hypothesis_id}/versions/{version_no}/review", applyMiddleware(http.HandlerFunc(handleReviewHypothesisVersion), requireAuth, requirePermission(CanViewCTI), requirePermission(CanReviewHypothesis), auditWrap, csrfWrap))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := &http.Client{Timeout: 15 * time.Second}

	do := func(method, url, user, clientID, body string, csrf bool) *http.Response {
		req, _ := http.NewRequest(method, srv.URL+url, strings.NewReader(body))
		if user != "" {
			sess, _ := db.CreateSession(user, clientID)
			req.AddCookie(&http.Cookie{Name: "session_id", Value: sess.SessionID})
		}
		if csrf {
			req.Header.Set("Origin", "http://localhost:5173")
			req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "tok-1"})
			req.Header.Set("X-CSRF-Token", "tok-1")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// 401 unauthenticated.
	if resp := do("POST", "/api/v1/hypotheses", "", "", `{}`, true); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth: %d", resp.StatusCode)
	}
	// 403: CTI_ANALYST lacks CanCreateHypothesis.
	if resp := do("POST", "/api/v1/hypotheses", "user-analyst-alpha", "client-alpha",
		`{"client_id":"client-alpha","title":"T","description":"S","statement":"S"}`, true); resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Fatalf("analyst create must be 403, got %d", resp.StatusCode)
	}
	// 403: missing CSRF.
	if resp := do("POST", "/api/v1/hypotheses", "user-hyp-writer", "client-alpha",
		`{"client_id":"client-alpha","title":"T","description":"S","statement":"S"}`, false); resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Fatalf("missing CSRF must be 403, got %d", resp.StatusCode)
	}
	// 403: admin has hypothesis-archive edit perms via can-create; reviewer can't create.
	if resp := do("POST", "/api/v1/hypotheses", "user-reviewer", "client-alpha",
		`{"client_id":"client-alpha","title":"T","description":"S","statement":"S"}`, true); resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Fatalf("reviewer create must be 403, got %d", resp.StatusCode)
	}

	// 422: ATT&CK not in catalogue (mitre_mappings unseeded beyond fixtures).
	resp := do("POST", "/api/v1/hypotheses", "user-hyp-writer", "client-alpha",
		`{"client_id":"client-alpha","title":"T","description":"S","statement":"S","mitre_techniques":"T9999.999"}`, true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("bad ATT&CK must be 422, got %d", resp.StatusCode)
	}
	// 422: unknown client grant-less path from reporter.
	resp = do("POST", "/api/v1/hypotheses", "user-hyp-writer", "client-alpha",
		`{"client_id":"client-beta","title":"T","description":"S","statement":"S","idempotency_key":"kx"}`, true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no grant must be 403, got %d", resp.StatusCode)
	}
	// 201 happy path (with MITRE seeded).
	resp = do("POST", "/api/v1/hypotheses", "user-hyp-writer", "client-alpha",
		`{"client_id":"client-alpha","title":"T","description":"S","statement":"S","mitre_techniques":"T1059.001","known_benign_explanations":"benign","idempotency_key":"http-m7d-1"}`, true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create must be 201, got %d", resp.StatusCode)
	}
	// 200 replay.
	resp = do("POST", "/api/v1/hypotheses", "user-hyp-writer", "client-alpha",
		`{"client_id":"client-alpha","title":"T","description":"S","statement":"S","mitre_techniques":"T1059.001","known_benign_explanations":"benign","idempotency_key":"http-m7d-1"}`, true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("replay must be 200, got %d", resp.StatusCode)
	}
	// 409 conflict (same key, changed payload).
	resp = do("POST", "/api/v1/hypotheses", "user-hyp-writer", "client-alpha",
		`{"client_id":"client-alpha","title":"T2","description":"S","statement":"S","idempotency_key":"http-m7d-1"}`, true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("conflict must be 409, got %d", resp.StatusCode)
	}
	// from-report 201.
	resp = do("POST", "/api/v1/hypotheses/from-report", "user-hyp-writer", "client-alpha",
		`{"client_id":"client-alpha","report_id":"report-alpha-1","assessment_id":"asm-alpha-1","title":"T","description":"S","statement":"S","known_benign_explanations":"benign","idempotency_key":"http-m7d-fr"}`, true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("from-report must be 201, got %d", resp.StatusCode)
	}
	// from-report 404 (unknown assessment).
	resp = do("POST", "/api/v1/hypotheses/from-report", "user-hyp-writer", "client-alpha",
		`{"client_id":"client-alpha","report_id":"report-alpha-1","assessment_id":"asm-nope","title":"T","description":"S","statement":"S"}`, true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("from-report missing assessment must be 404, got %d", resp.StatusCode)
	}
}
