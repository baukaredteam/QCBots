package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// M7-D Phase 2B-4A: Hunt Plans. Every test runs on a disposable in-memory
// database and synthetic telemetry; no QRadar, no execution.

func huntPlanFixture(t *testing.T) (db *DB, hypID string, tr *DetectionTranslation) {
	t.Helper()
	db = openM7DFI_DB(t)
	t.Cleanup(func() { db.Close() })
	seedMitre(t, db)
	detail, _, err := CreateHypothesisManual("user-admin", "client-alpha", newHypothesisInput("HP-fx-"+newID("k")))
	if err != nil {
		t.Fatalf("hypothesis fixture: %v", err)
	}
	rule, dom := readySigmaDomain(t, db)
	stubWorker(t, func(req sigmaWorkerRequest) (sigmaWorkerResponse, string) {
		return sigmaWorkerResponse{
			Status:          "OK",
			AQL:             `SELECT * FROM events WHERE "Event ID"=4624`,
			ConvertedFields: []string{"EventID"},
		}, ""
	})
	tr, err = CreateDetectionTranslation(context.Background(), "user-admin", rule.RuleID, TranslationRequest{
		ClientID: "client-alpha", DomainID: dom.DomainID, Mode: "VERIFIED_FIELDS_ONLY", TimeWindowDays: 7,
	})
	if err != nil {
		t.Fatalf("translation fixture: %v", err)
	}
	if tr.Status != ReadinessReady {
		t.Fatalf("fixture translation must be READY, got %s", tr.Status)
	}
	return db, detail.HypothesisID, tr
}

func newPlanWithItem(t *testing.T, db *DB, hypID string, tr *DetectionTranslation) *HuntPlan {
	t.Helper()
	plan, err := CreateHuntPlan("user-admin", CreateHuntPlanRequest{
		ClientID: "client-alpha", HypothesisID: hypID, HypothesisVersion: 1,
		Title: "Reviewed PowerShell hunt",
	})
	if err != nil {
		t.Fatalf("create plan: %v", err)
	}
	plan, err = AddHuntPlanItem("user-admin", plan.PlanID, tr.TranslationID)
	if err != nil {
		t.Fatalf("add item: %v", err)
	}
	if len(plan.Items) != 1 {
		t.Fatalf("expected one item, got %d", len(plan.Items))
	}
	return plan
}

func TestHuntPlan_LifecycleApproveAndImmutable(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := newPlanWithItem(t, db, hypID, tr)

	plan, err := SubmitHuntPlan("user-admin", plan.PlanID)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if plan.Status != "IN_REVIEW" || plan.SubmittedBy != "user-admin" {
		t.Fatalf("bad submitted state: %+v", plan)
	}
	// Items are locked once the plan leaves DRAFT.
	if _, err := AddHuntPlanItem("user-admin", plan.PlanID, tr.TranslationID); !errors.Is(err, ErrHuntPlanConflict) {
		t.Fatalf("items must be locked in review, got %v", err)
	}

	plan, err = ReviewHuntPlan("user-reviewer", plan.PlanID, "APPROVED", "Reviewed binding and mapping evidence, ticket HP-1", "approved for analyst use")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if plan.Status != "APPROVED" || plan.ReviewedBy != "user-reviewer" || plan.ReviewEvidence == "" {
		t.Fatalf("approval provenance missing: %+v", plan)
	}

	// Approved content is immutable at the storage boundary.
	if _, err := db.Exec(`UPDATE hunt_plan_versions SET title='rewritten' WHERE plan_id=?`, plan.PlanID); err == nil {
		t.Fatal("approved plan must not be editable")
	}
	if _, err := db.Exec(`DELETE FROM hunt_plan_versions WHERE plan_id=?`, plan.PlanID); err == nil {
		t.Fatal("approved plan must not be deletable")
	}

	// Changing it creates a new version; the approved row keeps its content.
	v2, err := CreateHuntPlanVersion("user-admin", plan.PlanID)
	if err != nil {
		t.Fatalf("new version: %v", err)
	}
	if v2.Version != 2 || v2.LogicalID != plan.LogicalID || v2.Status != "DRAFT" || v2.SupersedesPlanID != plan.PlanID {
		t.Fatalf("bad fork: %+v", v2)
	}
	if len(v2.Items) != 1 {
		t.Fatalf("non-stale items must be copied, got %d", len(v2.Items))
	}
	old, err := GetHuntPlan(plan.PlanID, "user-admin")
	if err != nil {
		t.Fatal(err)
	}
	if old.Status != "APPROVED" || old.Title != plan.Title || old.ReviewedBy != "user-reviewer" {
		t.Fatalf("approved version changed: %+v", old)
	}

	// Audit rows exist for create, submit and review.
	for _, action := range []string{"HUNT_PLAN_CREATE", "HUNT_PLAN_SUBMIT", "HUNT_PLAN_REVIEW", "HUNT_PLAN_VERSION"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=? AND client_id='client-alpha'`, action).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatalf("missing audit row for %s", action)
		}
	}
}

func TestHuntPlan_MultipleDetections(t *testing.T) {
	_, hypID, tr := huntPlanFixture(t)
	second := `title: Second Detection
id: 33333333-3333-3333-3333-333333333333
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
  condition: selection
level: low
`
	rule2, err := IngestSigmaRule("user-admin", "client-alpha", "", "second.yml", second)
	if err != nil {
		t.Fatal(err)
	}
	tr2, err := CreateDetectionTranslation(context.Background(), "user-admin", rule2.RuleID, TranslationRequest{
		ClientID: "client-alpha", DomainID: tr.DomainID, Mode: "VERIFIED_FIELDS_ONLY", TimeWindowDays: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tr2.Status != ReadinessReady {
		t.Fatalf("second draft must be READY, got %s", tr2.Status)
	}
	plan, err := CreateHuntPlan("user-admin", CreateHuntPlanRequest{
		ClientID: "client-alpha", HypothesisID: hypID, HypothesisVersion: 1, Title: "Two detections",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{tr.TranslationID, tr2.TranslationID} {
		if _, err := AddHuntPlanItem("user-admin", plan.PlanID, id); err != nil {
			t.Fatalf("attach %s: %v", id, err)
		}
	}
	plan, err = SubmitHuntPlan("user-admin", plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = ReviewHuntPlan("user-reviewer", plan.PlanID, "APPROVED", "Two drafts reviewed, ticket HP-11", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Items) != 2 {
		t.Fatalf("approved plan must keep both detections, got %d", len(plan.Items))
	}
	seen := map[string]bool{}
	for _, it := range plan.Items {
		seen[it.TranslationID] = true
	}
	if !seen[tr.TranslationID] || !seen[tr2.TranslationID] {
		t.Fatalf("both translations must be linked: %+v", plan.Items)
	}
}

func TestHuntPlan_RejectAndVersion(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := newPlanWithItem(t, db, hypID, tr)
	if _, err := SubmitHuntPlan("user-admin", plan.PlanID); err != nil {
		t.Fatal(err)
	}
	// Evidence is mandatory even for a rejection: the decision must be auditable.
	if _, err := ReviewHuntPlan("user-reviewer", plan.PlanID, "REJECTED", "ok", ""); !errors.Is(err, ErrHuntPlanInvalid) {
		t.Fatalf("generic evidence must be refused, got %v", err)
	}
	plan, err := ReviewHuntPlan("user-reviewer", plan.PlanID, "REJECTED", "Telemetry gap on DSM scope, ticket HP-2", "needs field verification")
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if plan.Status != "REJECTED" || plan.ReviewedBy != "user-reviewer" {
		t.Fatalf("bad rejection: %+v", plan)
	}
	v2, err := CreateHuntPlanVersion("user-admin", plan.PlanID)
	if err != nil {
		t.Fatalf("version a rejected plan: %v", err)
	}
	if v2.Status != "DRAFT" || v2.Version != 2 {
		t.Fatalf("bad fork: %+v", v2)
	}
	// A DRAFT plan is not decidable.
	if _, err := ReviewHuntPlan("user-reviewer", v2.PlanID, "APPROVED", "Reviewed the fork, ticket HP-3", ""); !errors.Is(err, ErrHuntPlanConflict) {
		t.Fatalf("draft plan must not be reviewable, got %v", err)
	}
}

func TestHuntPlan_NewerMappingBlocksSubmit(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := newPlanWithItem(t, db, hypID, tr)
	// A newer mapping version appears after the draft was attached.
	if _, err := CreateQRadarFieldMapping("user-admin", "client-alpha", tr.DomainID,
		"EventID", "event_id", "event_id", "Microsoft Windows Security Event Log", "4624", "2", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := SubmitHuntPlan("user-admin", plan.PlanID); !errors.Is(err, ErrHuntPlanConflict) {
		t.Fatalf("a stale draft must not be submitted, got %v", err)
	}
	got, err := GetHuntPlan(plan.PlanID, "user-admin")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "DRAFT" || len(got.Items) != 1 || !got.Items[0].Stale {
		t.Fatalf("item must be reported stale: %+v", got.Items)
	}
}

func TestHuntPlan_WithdrawnApprovalBlocksApproval(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := newPlanWithItem(t, db, hypID, tr)
	if _, err := SubmitHuntPlan("user-admin", plan.PlanID); err != nil {
		t.Fatal(err)
	}
	// Direct SQL stands in for a future un-approve workflow.
	if _, err := db.Exec(`UPDATE qradar_field_mappings SET approved_by=NULL, approved_at=NULL WHERE domain_id=?`, tr.DomainID); err != nil {
		t.Fatal(err)
	}
	if _, err := ReviewHuntPlan("user-reviewer", plan.PlanID, "APPROVED", "Reviewed mapping evidence, ticket HP-4", ""); !errors.Is(err, ErrHuntPlanConflict) {
		t.Fatalf("withdrawn mapping approval must deny approval, got %v", err)
	}
	got, err := GetHuntPlan(plan.PlanID, "user-admin")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "IN_REVIEW" {
		t.Fatalf("a denied decision must not change status, got %s", got.Status)
	}
}

func TestHuntPlan_ChangedCEPBlocksApproval(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := newPlanWithItem(t, db, hypID, tr)
	if _, err := SubmitHuntPlan("user-admin", plan.PlanID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE qradar_field_mappings SET target_cep_field='different_cep' WHERE domain_id=?`, tr.DomainID); err != nil {
		t.Fatal(err)
	}
	if _, err := ReviewHuntPlan("user-reviewer", plan.PlanID, "APPROVED", "Reviewed CEP evidence, ticket HP-5", ""); !errors.Is(err, ErrHuntPlanConflict) {
		t.Fatalf("a changed CEP target must deny approval, got %v", err)
	}
}

func TestHuntPlan_UnverifiedDomainBlocksApproval(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := newPlanWithItem(t, db, hypID, tr)
	if _, err := SubmitHuntPlan("user-admin", plan.PlanID); err != nil {
		t.Fatal(err)
	}
	b, err := GetDomainBinding(tr.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateDomainBinding("user-admin", tr.DomainID, DomainBindingUpdate{
		BindingKind: "UNASSIGNED", Evidence: "revoked during hunt review, ticket HP-6", ExpectedRevision: b.Revision,
	}); err != nil {
		t.Fatalf("revoke binding: %v", err)
	}
	if _, err := ReviewHuntPlan("user-reviewer", plan.PlanID, "APPROVED", "Reviewed binding state, ticket HP-6", ""); !errors.Is(err, ErrHuntPlanConflict) && !errors.Is(err, ErrHuntPlanEvidenceUnavailable) {
		t.Fatalf("an unverified domain must deny approval, got %v", err)
	}
}

func TestHuntPlan_RoleAndTenantEnforcement(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := newPlanWithItem(t, db, hypID, tr)
	if _, err := SubmitHuntPlan("user-admin", plan.PlanID); err != nil {
		t.Fatal(err)
	}
	// CTI_ANALYST has neither create nor review rights.
	if _, err := ReviewHuntPlan("user-analyst-alpha", plan.PlanID, "APPROVED", "Self-approved, ticket HP-7", ""); !errors.Is(err, ErrHuntPlanAccessDenied) {
		t.Fatalf("analyst must not review, got %v", err)
	}
	if _, err := CreateHuntPlan("user-analyst-alpha", CreateHuntPlanRequest{
		ClientID: "client-alpha", HypothesisID: hypID, HypothesisVersion: 1, Title: "unauthorised",
	}); !errors.Is(err, ErrHuntPlanAccessDenied) {
		t.Fatalf("analyst must not create, got %v", err)
	}
	// A user of another client cannot read or list the plan.
	if _, err := GetHuntPlan(plan.PlanID, "user-analyst-beta"); !errors.Is(err, ErrHuntPlanAccessDenied) {
		t.Fatalf("cross-client read must be denied, got %v", err)
	}
	if _, err := ListHuntPlans("user-analyst-beta", "client-alpha"); !errors.Is(err, ErrHuntPlanAccessDenied) {
		t.Fatalf("cross-client list must be denied, got %v", err)
	}
	// Cross-client writes are denied too, including attach and submit.
	if _, err := AddHuntPlanItem("user-analyst-beta", plan.PlanID, tr.TranslationID); !errors.Is(err, ErrHuntPlanAccessDenied) {
		t.Fatalf("cross-client attach must be denied, got %v", err)
	}
	if _, err := SubmitHuntPlan("user-analyst-beta", plan.PlanID); !errors.Is(err, ErrHuntPlanAccessDenied) {
		t.Fatalf("cross-client submit must be denied, got %v", err)
	}
	// Revoked grant loses access immediately.
	if _, err := db.Exec(`DELETE FROM user_authorized_clients WHERE user_id='user-analyst-alpha' AND client_id='client-alpha'`); err != nil {
		t.Fatal(err)
	}
	if _, err := GetHuntPlan(plan.PlanID, "user-analyst-alpha"); !errors.Is(err, ErrHuntPlanAccessDenied) {
		t.Fatalf("revoked grant must lose access, got %v", err)
	}
}

func TestHuntPlan_ConcurrentReviewSingleWinner(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := newPlanWithItem(t, db, hypID, tr)
	if _, err := SubmitHuntPlan("user-admin", plan.PlanID); err != nil {
		t.Fatal(err)
	}
	users := []string{"user-reviewer", "user-admin"}
	errs := make([]error, len(users))
	var wg sync.WaitGroup
	for i, u := range users {
		wg.Add(1)
		go func(i int, u string) {
			defer wg.Done()
			_, errs[i] = ReviewHuntPlan(u, plan.PlanID, "APPROVED", "Concurrent review evidence, ticket HP-8", "")
		}(i, u)
	}
	wg.Wait()
	okCount, conflictCount := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			okCount++
		case errors.Is(err, ErrHuntPlanConflict):
			conflictCount++
		default:
			t.Fatalf("unexpected review error: %v", err)
		}
	}
	if okCount != 1 || conflictCount != 1 {
		t.Fatalf("exactly one reviewer must win, got ok=%d conflict=%d", okCount, conflictCount)
	}
	got, err := GetHuntPlan(plan.PlanID, "user-admin")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "APPROVED" {
		t.Fatalf("plan status must be APPROVED, got %s", got.Status)
	}
}

func TestHuntPlan_ApprovedRecordsNoExecution(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := newPlanWithItem(t, db, hypID, tr)
	if _, err := SubmitHuntPlan("user-admin", plan.PlanID); err != nil {
		t.Fatal(err)
	}
	if _, err := ReviewHuntPlan("user-reviewer", plan.PlanID, "APPROVED", "Reviewed draft only, ticket HP-9", ""); err != nil {
		t.Fatal(err)
	}
	var diag string
	if err := db.QueryRow(`SELECT diagnostics FROM detection_translations WHERE translation_id=?`, tr.TranslationID).Scan(&diag); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(diag), `"executed":true`) || strings.Contains(strings.ToLower(diag), "verified_by_qradar") {
		t.Fatalf("a draft must never claim execution: %s", diag)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM hunt_plan_versions WHERE plan_id=? AND status='APPROVED'`, plan.PlanID).Scan(new(int)); err != nil {
		t.Fatal(err)
	}
}

// HTTP surface -----------------------------------------------------------------

func TestHuntPlan_HTTPRBACAndTenant(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := newPlanWithItem(t, db, hypID, tr)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/hunt-plans", applyMiddleware(http.HandlerFunc(handleCreateHuntPlan),
		requireAuth, requirePermission(CanViewCTI), requirePermission(CanCreateHypothesis), auditWrap, csrfWrap))
	mux.HandleFunc("GET /api/v1/hunt-plans/{plan_id}", applyMiddleware(http.HandlerFunc(handleGetHuntPlan),
		requireAuth, requirePermission(CanViewCTI), auditWrap))
	mux.HandleFunc("POST /api/v1/hunt-plans/{plan_id}/submit", applyMiddleware(http.HandlerFunc(handleSubmitHuntPlan),
		requireAuth, requirePermission(CanViewCTI), requirePermission(CanCreateHypothesis), auditWrap, csrfWrap))
	mux.HandleFunc("POST /api/v1/hunt-plans/{plan_id}/review", applyMiddleware(http.HandlerFunc(handleReviewHuntPlan),
		requireAuth, requirePermission(CanViewCTI), requirePermission(CanReviewHypothesis), auditWrap, csrfWrap))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := &http.Client{Timeout: 15 * time.Second}

	do := func(method, url, user, clientID, body string, csrf bool) *http.Response {
		req, _ := http.NewRequest(method, srv.URL+url, strings.NewReader(body))
		if user != "" {
			sess, err := db.CreateSession(user, clientID)
			if err != nil {
				t.Fatalf("session: %v", err)
			}
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

	reviewBody := `{"decision":"APPROVED","evidence":"Reviewed evidence via API, ticket HP-10","note":""}`
	// No session → 401.
	if resp := do("GET", "/api/v1/hunt-plans/"+plan.PlanID, "", "", "", false); resp.StatusCode != http.StatusUnauthorized {
		resp.Body.Close()
		t.Fatalf("unauth read: %d", resp.StatusCode)
	}
	// Foreign client → 403, no plan metadata leaked.
	if resp := do("GET", "/api/v1/hunt-plans/"+plan.PlanID, "user-analyst-beta", "client-beta", "", false); resp.StatusCode != http.StatusForbidden {
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("cross-client read must be 403, got %d: %s", resp.StatusCode, string(bodyBytes))
	}
	// Missing CSRF on a write → 403, before the service is reached.
	if resp := do("POST", "/api/v1/hunt-plans/"+plan.PlanID+"/submit", "user-admin", "client-alpha", `{}`, false); resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Fatalf("submit without CSRF must be 403, got %d", resp.StatusCode)
	}
	// CTI_ANALYST cannot create a plan → 403 at middleware.
	if resp := do("POST", "/api/v1/hunt-plans", "user-analyst-alpha", "client-alpha",
		`{"client_id":"client-alpha","hypothesis_id":"`+hypID+`","hypothesis_version":1,"title":"x"}`, true); resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Fatalf("analyst create must be 403, got %d", resp.StatusCode)
	}
	// Admin submits; analyst cannot review; reviewer can.
	if resp := do("POST", "/api/v1/hunt-plans/"+plan.PlanID+"/submit", "user-admin", "client-alpha", `{}`, true); resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("submit: %d", resp.StatusCode)
	}
	if resp := do("POST", "/api/v1/hunt-plans/"+plan.PlanID+"/review", "user-analyst-alpha", "client-alpha", reviewBody, true); resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Fatalf("analyst review must be 403, got %d", resp.StatusCode)
	}
	if resp := do("POST", "/api/v1/hunt-plans/"+plan.PlanID+"/review", "user-reviewer", "client-alpha", reviewBody, true); resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("reviewer approve: %d", resp.StatusCode)
	}
	// A second decision conflicts.
	if resp := do("POST", "/api/v1/hunt-plans/"+plan.PlanID+"/review", "user-reviewer", "client-alpha", reviewBody, true); resp.StatusCode != http.StatusConflict {
		resp.Body.Close()
		t.Fatalf("double decision must be 409, got %d", resp.StatusCode)
	}
}
