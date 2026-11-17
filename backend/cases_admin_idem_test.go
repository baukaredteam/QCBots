package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Blocker 1: ADMINISTRATOR with grant only for client-alpha must not obtain
// CLIENT-scoped content for client-beta via artifacts, activity, filters or
// counts. GLOBAL case metadata (title/status) remains visible by design.
func TestAdminCannotSeeBetaClientContent(t *testing.T) {
	db := seedCaseTestEnv(t)
	defer db.Close()

	// Beta creates a case and attaches a CLIENT-scoped secret artifact + activity.
	betaCase, err := CreateResearchCase("user-analyst-beta", "Beta Secret Case", "desc", "idem-beta-secret-1", "client-beta")
	if err != nil {
		t.Fatalf("creating beta case: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO case_artifacts (artifact_id, case_id, visibility_scope, client_id, data_classification, provenance_source, artifact_hash, sanitized_representation, created_by)
		VALUES (?, ?, 'CLIENT', 'client-beta', 'PUBLIC', 'test', ?, 'BETA_SECRET_CONTENT', 'user-analyst-beta')`,
		"art-beta-secret", betaCase, "hash-beta-secret"); err != nil {
		t.Fatalf("inserting beta artifact: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO case_activity (activity_id, case_id, user_id, action, visibility_scope, client_id, details)
		VALUES (?, ?, 'user-analyst-beta', 'status_changed', 'CLIENT', 'client-beta', 'BETA_ACTIVITY_SECRET')`,
		"act-beta-secret", betaCase); err != nil {
		t.Fatalf("inserting beta activity: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO case_activity (activity_id, case_id, user_id, action, visibility_scope, details)
		VALUES (?, ?, 'user-analyst-beta', 'status_changed', 'GLOBAL', 'PUBLIC_GLOBAL_EVENT')`,
		"act-global-1", betaCase); err != nil {
		t.Fatalf("inserting global activity: %v", err)
	}

	// 1. Admin GET /api/v1/cases/{id}: metadata OK, beta content must be absent.
	// Route through a mux so PathValue("case_id") is set, as in production.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/cases/{case_id}", http.HandlerFunc(handleGetCase))
	r := sessionRequest(t, "GET", "/api/v1/cases/"+betaCase, "", "user-admin", "client-alpha")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("admin metadata access expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "Beta Secret Case") {
		t.Error("admin should see GLOBAL case metadata (title)")
	}
	if strings.Contains(body, "BETA_SECRET_CONTENT") {
		t.Error("admin without beta grant must not see beta artifact content")
	}
	if strings.Contains(body, "BETA_ACTIVITY_SECRET") {
		t.Error("admin without beta grant must not see beta activity details")
	}

	// 2. Business layer: business context artifact list is empty for beta content.
	ctx, err := GetCaseContext(betaCase, "user-admin")
	if err != nil {
		t.Fatalf("GetCaseContext failed for admin metadata: %v", err)
	}
	if len(ctx.Artifacts) != 0 {
		t.Errorf("expected 0 visible artifacts for admin without beta grant, got %d", len(ctx.Artifacts))
	}

	// 3. Filter oracle sealed: admin filtering by client-beta sees nothing.
	filtered, total, err := ListResearchCases("user-admin", "", "", "client-beta", 20, 0)
	if err != nil {
		t.Fatalf("ListResearchCases: %v", err)
	}
	if total != 0 || len(filtered) != 0 {
		t.Errorf("admin without beta grant must get 0 results for client-beta filter, got total=%d len=%d", total, len(filtered))
	}

	// 4. Count oracle sealed for a non-admin alpha user without participation:
	// case list must not include beta's case at all.
	alphaList, alphaTotal, err := ListResearchCases("user-analyst-alpha", "", "", "client-beta", 20, 0)
	if err != nil {
		t.Fatalf("ListResearchCases alpha: %v", err)
	}
	if alphaTotal != 0 || len(alphaList) != 0 {
		t.Errorf("alpha must not see beta cases, got total=%d", alphaTotal)
	}

	// 5. Activity helper: only GLOBAL visible to admin.
	visible, err := ListVisibleCaseActivity(betaCase, "user-admin")
	if err != nil {
		t.Fatalf("ListVisibleCaseActivity: %v", err)
	}
	if len(visible) != 1 || visible[0].ActivityID != "act-global-1" {
		t.Errorf("expected only the GLOBAL event for admin, got %+v", visible)
	}
	for _, a := range visible {
		if strings.Contains(a.Details, "BETA_ACTIVITY_SECRET") {
			t.Error("beta activity details leaked to admin")
		}
	}
}

// Blocker 2: idempotency — same key+payload returns same case; same
// key+different payload is 409; different keys+same payload creates distinct cases.
func TestIdempotencyPayloadSemantics(t *testing.T) {
	// Covered verbosely in cases_stageb_test (retry returns existing, priority
	// persisted). Here assert the conflict branch and distinct-keys branch.
	db := seedCaseTestEnv(t)
	defer db.Close()

	mk := func(body, user, client string) *httptest.ResponseRecorder {
		r := sessionRequest(t, "POST", "/api/v1/cases", body, user, client)
		w := httptest.NewRecorder()
		handleCreateCase(w, r)
		return w
	}

	w1 := mk(`{"title":"Idem Case","description":"d","initial_client_id":"client-alpha","idempotency_key":"key-1","priority":"P1","severity":"LOW"}`, "user-analyst-alpha", "client-alpha")
	if w1.Code != 201 {
		t.Fatalf("first create expected 201, got %d: %s", w1.Code, w1.Body.String())
	}
	w2 := mk(`{"title":"Idem Case","description":"d","initial_client_id":"client-alpha","idempotency_key":"key-1","priority":"P1","severity":"LOW"}`, "user-analyst-alpha", "client-alpha")
	if w2.Code != 200 {
		t.Errorf("retry same payload expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	w3 := mk(`{"title":"DIFFERENT","description":"d","initial_client_id":"client-alpha","idempotency_key":"key-1","priority":"P1","severity":"LOW"}`, "user-analyst-alpha", "client-alpha")
	if w3.Code != http.StatusConflict {
		t.Errorf("same key different payload expected 409, got %d: %s", w3.Code, w3.Body.String())
	}
	w4 := mk(`{"title":"Idem Case","description":"d","initial_client_id":"client-alpha","idempotency_key":"key-2","priority":"P1","severity":"LOW"}`, "user-analyst-alpha", "client-alpha")
	if w4.Code != 201 {
		t.Errorf("different key same payload expected 201, got %d: %s", w4.Code, w4.Body.String())
	}

	var cnt int
	if err := db.QueryRow(`SELECT COUNT(*) FROM research_cases WHERE idempotency_key = 'key-1'`).Scan(&cnt); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if cnt != 1 {
		t.Errorf("expected exactly one row for key-1, got %d", cnt)
	}
}
