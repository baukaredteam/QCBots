package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// seedCaseTestEnv creates the standard test DB with migrations 0004+0005 and
// returns it with globalDB swapped in.
func seedCaseTestEnv(t *testing.T) *DB {
	t.Helper()
	db := testDB(t)
	origDB := globalDB
	globalDB = db
	t.Cleanup(func() { globalDB = origDB })
	if err := runMigration(db.DB, "migrations/0005_m6_case_workspace.sql"); err != nil {
		t.Fatalf("running migration 0005: %v", err)
	}
	seedGrant := func(grantID, userID, clientID string) {
		t.Helper()
		if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES (?, ?, ?)`,
			grantID, userID, clientID); err != nil {
			t.Fatalf("inserting grant: %v", err)
		}
	}
	seedGrant("grant-alpha-alpha", "user-analyst-alpha", "client-alpha")
	seedGrant("grant-beta-beta", "user-analyst-beta", "client-beta")
	seedGrant("grant-alpha-admin", "user-admin", "client-alpha")
	seedGrant("grant-alpha-reviewer", "user-reviewer", "client-alpha")
	seedGrant("grant-alpha-multi", "user-analyst-multi", "client-alpha")
	return db
}

func sessionRequest(t *testing.T, method, target, body, userID, clientID string) *http.Request {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r = r.WithContext(context.WithValue(r.Context(), sessionCtxKey, &Session{
		SessionID: "ses-test",
		UserID:    userID,
		ClientID:  clientID,
	}))
	return r
}

func TestHTTPListCasesPaginationStableAndPermissionAware(t *testing.T) {
	db := seedCaseTestEnv(t)
	defer db.Close()

	// Alpha creates 2 cases, beta creates 1. Alpha must not see beta's.
	for i, title := range []string{"Case A1", "Case A2"} {
		if _, err := CreateResearchCase("user-analyst-alpha", title, "desc", "idem-list"+string(rune('1'+i)), "client-alpha"); err != nil {
			t.Fatalf("creating case: %v", err)
		}
	}
	if _, err := CreateResearchCase("user-analyst-beta", "Case B1", "desc", "idem-list-beta-1", "client-beta"); err != nil {
		t.Fatalf("creating beta case: %v", err)
	}

	r := sessionRequest(t, "GET", "/api/v1/cases?limit=1&offset=0", "", "user-analyst-alpha", "client-alpha")
	w := httptest.NewRecorder()
	handleListCases(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Cases []struct {
			CaseID string `json:"case_id"`
			Title  string `json:"title"`
		} `json:"cases"`
		Total  int `json:"total"`
		Limit  int `json:"limit"`
		Offset int `json:"offset"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding list response: %v", err)
	}
	if resp.Total != 2 {
		t.Errorf("expected total 2 for alpha, got %d", resp.Total)
	}
	if len(resp.Cases) != 1 {
		t.Fatalf("expected 1 case with limit=1, got %d", len(resp.Cases))
	}
	if resp.Limit != 1 || resp.Offset != 0 {
		t.Errorf("expected limit=1 offset=0 echo, got limit=%d offset=%d", resp.Limit, resp.Offset)
	}
	for _, c := range resp.Cases {
		if strings.Contains(c.Title, "B1") {
			t.Errorf("alpha must not see beta case")
		}
	}

	r2 := sessionRequest(t, "GET", "/api/v1/cases?limit=1&offset=1", "", "user-analyst-alpha", "client-alpha")
	w2 := httptest.NewRecorder()
	handleListCases(w2, r2)
	if w2.Code != 200 {
		t.Fatalf("expected 200 on page 2, got %d: %s", w2.Code, w2.Body.String())
	}
	var resp2 struct {
		Cases []struct {
			CaseID string `json:"case_id"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("decoding page 2: %v", err)
	}
	if len(resp2.Cases) != 1 {
		t.Fatalf("expected 1 case on page 2, got %d", len(resp2.Cases))
	}
	if resp2.Cases[0].CaseID == resp.Cases[0].CaseID {
		t.Error("pagination must return distinct cases (stable sort)")
	}
}

func TestHTTPCreateCaseAndIdempotentRetry(t *testing.T) {
	db := seedCaseTestEnv(t)
	defer db.Close()

	body := `{"title":"New Hunt Case","description":"d","initial_client_id":"client-alpha","priority":"P2","severity":"HIGH"}`
	r := sessionRequest(t, "POST", "/api/v1/cases", body, "user-analyst-alpha", "client-alpha")
	w := httptest.NewRecorder()
	handleCreateCase(w, r)
	if w.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var created struct {
		CaseID         string `json:"case_id"`
		Title          string `json:"title"`
		Priority       string `json:"priority"`
		Severity       string `json:"severity"`
		IdempotencyKey string `json:"idempotency_key"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decoding create response: %v", err)
	}
	if created.CaseID == "" || created.IdempotencyKey == "" {
		t.Fatal("expected server-generated case_id and idempotency_key")
	}
	if created.Priority != "P2" || created.Severity != "HIGH" {
		t.Errorf("expected P2/HIGH, got %q/%q", created.Priority, created.Severity)
	}

	// Retry with the same idempotency_key + identical payload returns the same case (no duplicate).
	// The full payload (including priority/severity) must be replayed verbatim.
	retryBody := `{"title":"New Hunt Case","description":"d","initial_client_id":"client-alpha","priority":"P2","severity":"HIGH","idempotency_key":"` + created.IdempotencyKey + `"}`
	r2 := sessionRequest(t, "POST", "/api/v1/cases", retryBody, "user-analyst-alpha", "client-alpha")
	w2 := httptest.NewRecorder()
	handleCreateCase(w2, r2)
	if w2.Code != 200 && w2.Code != 201 {
		t.Fatalf("retry expected 200/201, got %d: %s", w2.Code, w2.Body.String())
	}
	var retried struct {
		CaseID string `json:"case_id"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &retried); err != nil {
		t.Fatalf("decoding retry response: %v", err)
	}
	if retried.CaseID != created.CaseID {
		t.Errorf("retry must return existing case %s, got %s", created.CaseID, retried.CaseID)
	}
	var cnt int
	if err := db.QueryRow(`SELECT COUNT(*) FROM research_cases WHERE idempotency_key = ?`, created.IdempotencyKey).Scan(&cnt); err != nil {
		t.Fatalf("counting cases: %v", err)
	}
	if cnt != 1 {
		t.Errorf("expected exactly 1 case row, got %d", cnt)
	}
}

func TestHTTPCreateCaseDeniedForUnauthorizedClientAndBadInput(t *testing.T) {
	db := seedCaseTestEnv(t)
	defer db.Close()

	// Grant check: alpha cannot create for beta.
	body := `{"title":"X","description":"d","initial_client_id":"client-beta"}`
	r := sessionRequest(t, "POST", "/api/v1/cases", body, "user-analyst-alpha", "client-alpha")
	w := httptest.NewRecorder()
	handleCreateCase(w, r)
	if w.Code != 403 {
		t.Errorf("expected 403 for unauthorized client, got %d: %s", w.Code, w.Body.String())
	}

	// Validation: empty title.
	body2 := `{"title":"","description":"d"}`
	r2 := sessionRequest(t, "POST", "/api/v1/cases", body2, "user-analyst-alpha", "client-alpha")
	w2 := httptest.NewRecorder()
	handleCreateCase(w2, r2)
	if w2.Code != 400 {
		t.Errorf("expected 400 for empty title, got %d: %s", w2.Code, w2.Body.String())
	}

	// Validation: invalid priority.
	body3 := `{"title":"X","description":"d","priority":"P9"}`
	r3 := sessionRequest(t, "POST", "/api/v1/cases", body3, "user-analyst-alpha", "client-alpha")
	w3 := httptest.NewRecorder()
	handleCreateCase(w3, r3)
	if w3.Code != 400 {
		t.Errorf("expected 400 for bad priority, got %d: %s", w3.Code, w3.Body.String())
	}
}

func TestHTTPListCasesRequiresAuth(t *testing.T) {
	_ = seedCaseTestEnv(t)
	r := httptest.NewRequest("GET", "/api/v1/cases", nil) // no session
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/cases", applyMiddleware(http.HandlerFunc(handleListCases), requireAuth, requirePermission(CanViewCTI)))
	mux.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Errorf("expected 401 without session, got %d: %s", w.Code, w.Body.String())
	}
}
