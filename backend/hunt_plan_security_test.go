package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// M7-D Phase 2B-4A final security gate: transactional review authorization,
// mapping-snapshot fidelity, viewer-neutral staleness and item integrity.

func submittedPlan(t *testing.T, db *DB, hypID string, tr *DetectionTranslation) *HuntPlan {
	t.Helper()
	plan := newPlanWithItem(t, db, hypID, tr)
	plan, err := SubmitHuntPlan("user-admin", plan.PlanID)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	return plan
}

// P0 — authorization is re-checked inside the decision transaction.

func TestSecurity_ReviewGrantRevokedBeforeDecision(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := submittedPlan(t, db, hypID, tr)

	if _, err := db.Exec(`DELETE FROM user_authorized_clients WHERE user_id='user-reviewer' AND client_id='client-alpha'`); err != nil {
		t.Fatal(err)
	}
	if _, err := ReviewHuntPlan("user-reviewer", plan.PlanID, "APPROVED", "Reviewed evidence, ticket SG-1", ""); !errors.Is(err, ErrHuntPlanAccessDenied) {
		t.Fatalf("revoked grant must deny the decision, got %v", err)
	}
	got, err := GetHuntPlan(plan.PlanID, "user-admin")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "IN_REVIEW" || got.ReviewedBy != "" {
		t.Fatalf("a denied decision must not be recorded: %+v", got)
	}
}

func TestSecurity_ReviewRoleChangedBeforeDecision(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := submittedPlan(t, db, hypID, tr)

	if _, err := db.Exec(`UPDATE users SET role='CTI_ANALYST' WHERE user_id='user-reviewer'`); err != nil {
		t.Fatal(err)
	}
	if _, err := ReviewHuntPlan("user-reviewer", plan.PlanID, "APPROVED", "Reviewed evidence, ticket SG-2", ""); !errors.Is(err, ErrHuntPlanAccessDenied) {
		t.Fatalf("a demoted reviewer must be denied, got %v", err)
	}
}

func TestSecurity_RejectionAlsoRequiresAuthorization(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := submittedPlan(t, db, hypID, tr)
	if _, err := db.Exec(`UPDATE users SET role='CTI_ANALYST' WHERE user_id='user-reviewer'`); err != nil {
		t.Fatal(err)
	}
	if _, err := ReviewHuntPlan("user-reviewer", plan.PlanID, "REJECTED", "Rejecting, ticket SG-3", ""); !errors.Is(err, ErrHuntPlanAccessDenied) {
		t.Fatalf("rejection must require review capability, got %v", err)
	}
}

func TestSecurity_ForeignClientReviewDenied(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := submittedPlan(t, db, hypID, tr)
	for _, decision := range []string{"APPROVED", "REJECTED"} {
		if _, err := ReviewHuntPlan("user-analyst-beta", plan.PlanID, decision, "Foreign decision, ticket SG-4", ""); !errors.Is(err, ErrHuntPlanAccessDenied) {
			t.Fatalf("%s by a foreign client must be denied, got %v", decision, err)
		}
	}
}

func TestSecurity_AuditFailureRollsBackDecision(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := submittedPlan(t, db, hypID, tr)
	if _, err := db.Exec(`CREATE TRIGGER zz_block_audit BEFORE INSERT ON audit_log
		BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := ReviewHuntPlan("user-reviewer", plan.PlanID, "APPROVED", "Reviewed evidence, ticket SG-5", ""); err == nil {
		t.Fatal("an audit failure must fail the decision")
	}
	got, err := GetHuntPlan(plan.PlanID, "user-admin")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "IN_REVIEW" || got.ReviewedBy != "" || got.ReviewEvidence != "" {
		t.Fatalf("decision must be rolled back with the audit row: %+v", got)
	}
}

// P1 — mapping snapshot fidelity.

func TestSecurity_SupersededMappingDenied(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := submittedPlan(t, db, hypID, tr)
	if _, err := CreateQRadarFieldMapping("user-admin", "client-alpha", tr.DomainID,
		"EventID", "event_id", "event_id", "Microsoft Windows Security Event Log", "4624", "2", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := ReviewHuntPlan("user-reviewer", plan.PlanID, "APPROVED", "Reviewed snapshot, ticket SG-6", ""); !errors.Is(err, ErrHuntPlanConflict) {
		t.Fatalf("a superseded mapping must deny approval, got %v", err)
	}
}

func TestSecurity_ScopeChangeDenied(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := submittedPlan(t, db, hypID, tr)
	if _, err := db.Exec(`UPDATE qradar_field_mappings SET applicable_event='9999' WHERE domain_id=?`, tr.DomainID); err != nil {
		t.Fatal(err)
	}
	if _, err := ReviewHuntPlan("user-reviewer", plan.PlanID, "APPROVED", "Reviewed scope, ticket SG-7", ""); !errors.Is(err, ErrHuntPlanConflict) {
		t.Fatalf("a mapping out of scope must deny approval, got %v", err)
	}
}

func TestSecurity_AmbiguousApprovalsDenied(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := submittedPlan(t, db, hypID, tr)
	// A second approved mapping for the same raw field, lower version so the
	// snapshot mapping is still the newest applicable one. The ambiguity itself
	// must be refused.
	old, err := CreateQRadarFieldMapping("user-admin", "client-alpha", tr.DomainID,
		"EventID", "event_id_old", "event_id_old", "Microsoft Windows Security Event Log", "4624", "0", "manual")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApproveQRadarFieldMapping("user-reviewer", old.MappingID, "older approved mapping, ticket SG-8"); err != nil {
		t.Fatal(err)
	}
	if _, err := ReviewHuntPlan("user-reviewer", plan.PlanID, "APPROVED", "Reviewed ambiguity, ticket SG-8", ""); !errors.Is(err, ErrHuntPlanConflict) {
		t.Fatalf("conflicting approved mappings must deny approval, got %v", err)
	}
}

func TestSecurity_AttestationWithdrawalDenied(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := submittedPlan(t, db, hypID, tr)
	if _, err := db.Exec(`UPDATE qradar_field_observations SET aql_verification_status='UNVERIFIED' WHERE domain_id=?`, tr.DomainID); err != nil {
		t.Fatal(err)
	}
	if _, err := ReviewHuntPlan("user-reviewer", plan.PlanID, "APPROVED", "Reviewed attestation, ticket SG-9", ""); !errors.Is(err, ErrHuntPlanConflict) {
		t.Fatalf("withdrawn AQL attestation must deny approval, got %v", err)
	}
}

// P1 — staleness is derived from evidence, never from the author's grants.

func TestSecurity_ItemStalenessIndependentOfAuthorGrant(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := newPlanWithItem(t, db, hypID, tr)
	// The author loses the client grant after attaching. Another authorised
	// user must still see current evidence and the original provenance.
	if _, err := db.Exec(`DELETE FROM user_authorized_clients WHERE user_id='user-admin' AND client_id='client-alpha'`); err != nil {
		t.Fatal(err)
	}
	got, err := GetHuntPlan(plan.PlanID, "user-reviewer")
	if err != nil {
		t.Fatalf("an authorised viewer must still read the plan: %v", err)
	}
	if len(got.Items) != 1 {
		t.Fatalf("expected one item, got %d", len(got.Items))
	}
	item := got.Items[0]
	if item.AddedBy != "user-admin" {
		t.Fatalf("original author must be preserved, got %q", item.AddedBy)
	}
	if item.EvidenceState != EvidenceStateOK || item.Stale {
		t.Fatalf("evidence must be judged on its own merits, got %s stale=%v reasons=%v",
			item.EvidenceState, item.Stale, item.StaleReasons)
	}
	// A foreign viewer is still denied by the plan-level grant check.
	if _, err := GetHuntPlan(plan.PlanID, "user-analyst-beta"); !errors.Is(err, ErrHuntPlanAccessDenied) {
		t.Fatalf("foreign viewer must be denied, got %v", err)
	}
}

func TestSecurity_EvidenceUnavailableIsDistinct(t *testing.T) {
	openM7DFI_DB(t)
	state, reasons := translationEvidenceState("no-such-translation", "client-alpha")
	if state != EvidenceStateUnavailable {
		t.Fatalf("missing evidence must be %s, got %s", EvidenceStateUnavailable, state)
	}
	if len(reasons) == 0 {
		t.Fatal("unavailable evidence must be explained")
	}
}

func TestSecurity_StaleItemBlocksSubmitAndApproval(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := newPlanWithItem(t, db, hypID, tr)
	if _, err := CreateQRadarFieldMapping("user-admin", "client-alpha", tr.DomainID,
		"EventID", "event_id", "event_id", "Microsoft Windows Security Event Log", "4624", "2", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := SubmitHuntPlan("user-admin", plan.PlanID); !errors.Is(err, ErrHuntPlanConflict) {
		t.Fatalf("stale evidence must block submit, got %v", err)
	}
}

// P1 — plan-item integrity, at attachment and at the storage boundary.

func TestSecurity_AttachRequiresReadyDraft(t *testing.T) {
	db, hypID, _ := huntPlanFixture(t)
	rule, dom := sigmaScopeFixture(t, db, "client-alpha")
	stubWorker(t, func(req sigmaWorkerRequest) (sigmaWorkerResponse, string) {
		t.Fatal("worker must not run for an unattested draft")
		return sigmaWorkerResponse{}, ""
	})
	unready, err := CreateDetectionTranslation(context.Background(), "user-admin", rule.RuleID, TranslationRequest{
		ClientID: "client-alpha", DomainID: dom.DomainID, Mode: "VERIFIED_FIELDS_ONLY",
	})
	if err != nil {
		t.Fatal(err)
	}
	if unready.Status != ReadinessNeedsVerification {
		t.Fatalf("fixture must be NEEDS_FIELD_VERIFICATION, got %s", unready.Status)
	}
	plan, err := CreateHuntPlan("user-admin", CreateHuntPlanRequest{
		ClientID: "client-alpha", HypothesisID: hypID, HypothesisVersion: 1, Title: "Unready attach",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AddHuntPlanItem("user-admin", plan.PlanID, unready.TranslationID); !errors.Is(err, ErrHuntPlanConflict) {
		t.Fatalf("an unready draft must not be attachable, got %v", err)
	}
}

func TestSecurity_ItemIntegrityTriggerRejectsMismatch(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan, err := CreateHuntPlan("user-admin", CreateHuntPlanRequest{
		ClientID: "client-alpha", HypothesisID: hypID, HypothesisVersion: 1, Title: "Integrity",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Direct SQL bypassing the service: the native domain id must match the
	// translation, and the storage boundary refuses it.
	if _, err := db.Exec(`INSERT INTO hunt_plan_version_items
		(plan_id, translation_id, domain_id, native_qradar_domain_id, added_by, added_at)
		VALUES (?, ?, ?, '999', 'user-admin', datetime('now'))`,
		plan.PlanID, tr.TranslationID, tr.DomainID); err == nil {
		t.Fatal("a mismatched native domain id must be refused by the database")
	}
	// The correct relationship is accepted, then locked.
	if _, err := db.Exec(`INSERT INTO hunt_plan_version_items
		(plan_id, translation_id, domain_id, native_qradar_domain_id, added_by, added_at)
		VALUES (?, ?, ?, ?, 'user-admin', datetime('now'))`,
		plan.PlanID, tr.TranslationID, tr.DomainID, tr.NativeDomainID); err != nil {
		t.Fatalf("the correct relationship must be accepted: %v", err)
	}
	if _, err := db.Exec(`UPDATE hunt_plan_version_items SET native_qradar_domain_id='1' WHERE plan_id=?`, plan.PlanID); err == nil {
		t.Fatal("plan items must stay immutable")
	}
}

func TestSecurity_PlanVersionCopiesOnlyCurrentEvidence(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := submittedPlan(t, db, hypID, tr)
	if _, err := ReviewHuntPlan("user-reviewer", plan.PlanID, "REJECTED", "Needs rework, ticket SG-10", ""); err != nil {
		t.Fatal(err)
	}
	// The mapping is superseded after the decision; the fork must not copy the
	// stale item as if it were current.
	if _, err := CreateQRadarFieldMapping("user-admin", "client-alpha", tr.DomainID,
		"EventID", "event_id", "event_id", "Microsoft Windows Security Event Log", "4624", "2", "manual"); err != nil {
		t.Fatal(err)
	}
	v2, err := CreateHuntPlanVersion("user-admin", plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(v2.Items) != 0 {
		t.Fatalf("stale items must not be carried forward, got %d", len(v2.Items))
	}
	// And such a plan cannot be submitted without current evidence.
	if _, err := SubmitHuntPlan("user-admin", v2.PlanID); !errors.Is(err, ErrHuntPlanInvalid) {
		t.Fatalf("a plan without items must not be submitted, got %v", err)
	}
}

// The exact failure to be reported in an HTTP response must not leak details.
func TestSecurity_AccessDeniedMessageIsGeneric(t *testing.T) {
	if strings.Contains(strings.ToLower(ErrHuntPlanAccessDenied.Error()), "client-alpha") {
		t.Fatal("access-denied errors must not name a client")
	}
}

func TestSecurity_ItemBindingOwnerMismatchRejected(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan, err := CreateHuntPlan("user-admin", CreateHuntPlanRequest{
		ClientID: "client-alpha", HypothesisID: hypID, HypothesisVersion: 1, Title: "Binding owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	insert := func() error {
		_, err := db.Exec(`INSERT INTO hunt_plan_version_items
			(plan_id, translation_id, domain_id, native_qradar_domain_id, added_by, added_at)
			VALUES (?, ?, ?, ?, 'user-admin', datetime('now'))`,
			plan.PlanID, tr.TranslationID, tr.DomainID, tr.NativeDomainID)
		return err
	}
	// Plan client A, translation client A, binding client B: every 0020 check
	// still passes, so only the binding-owner trigger can stop it.
	if _, err := db.Exec(`UPDATE qradar_domain_bindings SET client_id='client-beta' WHERE domain_id=?`, tr.DomainID); err != nil {
		t.Fatal(err)
	}
	if err := insert(); err == nil {
		t.Fatal("a binding owned by another client must be refused by the database")
	}
	// Restore ownership: the same insert is then legitimate.
	if _, err := db.Exec(`UPDATE qradar_domain_bindings SET client_id='client-alpha' WHERE domain_id=?`, tr.DomainID); err != nil {
		t.Fatal(err)
	}
	if err := insert(); err != nil {
		t.Fatalf("the correct binding owner must be accepted: %v", err)
	}

	// Verification metadata is part of the evidence. 0016 already refuses an
	// empty evidence reference on a VERIFIED binding, so the trigger cannot be
	// starved of it through an update.
	if _, err := db.Exec(`UPDATE qradar_domain_bindings SET evidence_reference='' WHERE domain_id=?`, tr.DomainID); err == nil {
		t.Fatal("a verified binding must not lose its verification evidence")
	}
}

// API acceptance: a revoked binding produces a typed conflict at the HTTP layer,
// not a 200 and not an untyped 500.
func TestSecurity_HTTPEvidenceUnavailable(t *testing.T) {
	db, hypID, tr := huntPlanFixture(t)
	plan := submittedPlan(t, db, hypID, tr)
	b, err := GetDomainBinding(tr.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateDomainBinding("user-admin", tr.DomainID, DomainBindingUpdate{
		BindingKind: "UNASSIGNED", Evidence: "revoked for acceptance, ticket SG-11", ExpectedRevision: b.Revision,
	}); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/hunt-plans/{plan_id}/review", applyMiddleware(http.HandlerFunc(handleReviewHuntPlan),
		requireAuth, requirePermission(CanViewCTI), requirePermission(CanReviewHypothesis), auditWrap, csrfWrap))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/hunt-plans/"+plan.PlanID+"/review",
		strings.NewReader(`{"decision":"APPROVED","evidence":"Reviewed after revocation, ticket SG-11"}`))
	sess, err := db.CreateSession("user-reviewer", "client-alpha")
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "session_id", Value: sess.SessionID})
	req.Header.Set("Origin", "http://localhost:5173")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "tok-1"})
	req.Header.Set("X-CSRF-Token", "tok-1")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("revoked binding must be 409, got %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "EVIDENCE_UNAVAILABLE") && !strings.Contains(string(body), "HUNT_PLAN_CONFLICT") {
		t.Fatalf("response must carry a typed evidence error: %s", body)
	}
	got, err := GetHuntPlan(plan.PlanID, "user-admin")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "IN_REVIEW" {
		t.Fatalf("denied decision must not change status, got %s", got.Status)
	}
}
