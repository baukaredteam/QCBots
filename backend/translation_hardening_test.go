package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// Phase 2B-3 hardening: prove that evidence revalidation happens inside the
// persistence transaction, so a change made while the worker runs cannot produce
// a READY draft.

// blockingWorker holds the conversion until the test releases it, so a mutation
// can be applied at the exact moment between analysis and persistence.
func blockingWorker(t *testing.T) (entered chan struct{}, release chan struct{}) {
	t.Helper()
	entered = make(chan struct{})
	release = make(chan struct{})
	old := workerCommand
	workerCommand = func(ctx context.Context, req sigmaWorkerRequest) ([]byte, []byte, error) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
		out := `{"protocol":"sentinel.sigma.worker/1","status":"OK","aql":"SELECT * FROM events WHERE \"Event ID\"=4624","converted_fields":["EventID"],"worker_version":"1","backend_version":"0.3.2","pysigma_version":"0.11.23","sigma_sha256":"` + req.SigmaSHA + `","request_id":"` + req.RequestID + `"}`
		return []byte(out), nil, nil
	}
	t.Cleanup(func() { workerCommand = old })
	return entered, release
}

func runTranslationWhile(t *testing.T, rule *SigmaRule, domainID string, mutate func()) error {
	t.Helper()
	entered, release := blockingWorker(t)
	var wg sync.WaitGroup
	wg.Add(1)
	var trerr error
	go func() {
		defer wg.Done()
		_, trerr = CreateDetectionTranslation(context.Background(), "user-admin", rule.RuleID, TranslationRequest{
			ClientID: "client-alpha", DomainID: domainID, Mode: "VERIFIED_FIELDS_ONLY", TimeWindowDays: 7,
		})
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("worker was not reached")
	}
	mutate()
	close(release)
	wg.Wait()
	return trerr
}

func TestHardening_BindingRevokedWhileWorkerRuns(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	rule, dom := readySigmaDomain(t, db)
	err := runTranslationWhile(t, rule, dom.DomainID, func() {
		b, _ := GetDomainBinding(dom.DomainID)
		if _, uerr := UpdateDomainBinding("user-admin", dom.DomainID, DomainBindingUpdate{
			BindingKind: "UNASSIGNED", Evidence: "revoked during conversion, ticket TB-40", ExpectedRevision: b.Revision,
		}); uerr != nil {
			t.Fatalf("mutate: %v", uerr)
		}
	})
	if !errors.Is(err, ErrTranslationStale) {
		t.Fatalf("revoked binding must abort persistence with STALE_SCOPE, got %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM detection_translations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("no draft may be persisted on stale evidence, found %d", n)
	}
}

func TestHardening_DomainReassignedWhileWorkerRuns(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	rule, dom := readySigmaDomain(t, db)
	for _, c := range []string{"client-alpha", "client-beta"} {
		if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES (?,?,?)`, "g-admin-"+c, "user-admin", c); err != nil {
			t.Fatal(err)
		}
	}
	err := runTranslationWhile(t, rule, dom.DomainID, func() {
		b, _ := GetDomainBinding(dom.DomainID)
		if _, uerr := UpdateDomainBinding("user-admin", dom.DomainID, DomainBindingUpdate{
			NativeQRadarDomainID: "5", ClientID: "client-beta", BindingKind: "CLIENT",
			Evidence: "reassigned during conversion, ticket TB-41", ExpectedRevision: b.Revision,
		}); uerr != nil {
			t.Fatalf("mutate: %v", uerr)
		}
	})
	if !errors.Is(err, ErrTranslationStale) {
		t.Fatalf("reassignment must abort persistence, got %v", err)
	}
}

func TestHardening_GrantRevokedWhileWorkerRuns(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	rule, dom := readySigmaDomain(t, db)
	err := runTranslationWhile(t, rule, dom.DomainID, func() {
		if _, uerr := db.Exec(`DELETE FROM user_authorized_clients WHERE user_id='user-admin' AND client_id='client-alpha'`); uerr != nil {
			t.Fatalf("mutate: %v", uerr)
		}
	})
	if !errors.Is(err, ErrTranslationStale) {
		t.Fatalf("revoked grant must abort persistence, got %v", err)
	}
}

func TestHardening_MappingChangedWhileWorkerRuns(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	rule, dom := readySigmaDomain(t, db)
	err := runTranslationWhile(t, rule, dom.DomainID, func() {
		if _, uerr := CreateQRadarFieldMapping("user-admin", "client-alpha", dom.DomainID,
			"EventID", "event_id", "event_id", "Microsoft Windows Security Event Log", "4624", "3", "manual"); uerr != nil {
			t.Fatalf("mutate: %v", uerr)
		}
	})
	if !errors.Is(err, ErrTranslationStale) {
		t.Fatalf("a newer mapping during conversion must abort persistence, got %v", err)
	}
}

func TestHardening_ApprovalWithdrawnWhileWorkerRuns(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	rule, dom := readySigmaDomain(t, db)
	err := runTranslationWhile(t, rule, dom.DomainID, func() {
		// Direct SQL stands in for a future un-approve workflow.
		if _, uerr := db.Exec(`UPDATE qradar_field_mappings SET approved_by=NULL, approved_at=NULL WHERE domain_id=?`, dom.DomainID); uerr != nil {
			t.Fatalf("mutate: %v", uerr)
		}
	})
	if !errors.Is(err, ErrTranslationStale) {
		t.Fatalf("withdrawn approval must abort persistence, got %v", err)
	}
}

// DSM/event scope ---------------------------------------------------------------

func TestHardening_UnknownDSMDoesNotMatchScopedMapping(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	rule, dom := sigmaScopeFixture(t, db, "client-alpha")
	m, err := CreateQRadarFieldMapping("user-admin", "client-alpha", dom.DomainID, "EventID", "event_id", "event_id", "Microsoft Windows Security Event Log", "", "1", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApproveQRadarFieldMapping("user-reviewer", m.MappingID, "dsm-scoped mapping, ticket TB-42"); err != nil {
		t.Fatal(err)
	}
	// The rule's logsource matches no catalogue DSM and the inventory has no
	// matching type, so the selected DSM is unknown.
	if _, err := db.Exec(`DELETE FROM qradar_log_source_types WHERE domain_id=?`, dom.DomainID); err != nil {
		t.Fatal(err)
	}
	sc, err := AnalyzeDetectionScope("user-analyst-alpha", "client-alpha", rule.RuleID)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Domains[0].DSMVerified {
		t.Fatal("an empty inventory must not verify a DSM")
	}
	for _, f := range sc.Domains[0].Fields {
		if f.Field == "EventID" && f.State != FieldStateScopeMismatch {
			t.Fatalf("an unknown DSM must not match a DSM-scoped mapping, got %s", f.State)
		}
	}
}

func TestHardening_NoDSMInventedFromLabel(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	rule, dom := sigmaScopeFixture(t, db, "client-alpha")
	// Rename the log source type so that only a loose token match remains.
	if _, err := db.Exec(`UPDATE qradar_log_source_types SET type_name='Windows something' WHERE domain_id=?`, dom.DomainID); err != nil {
		t.Fatal(err)
	}
	sc, err := AnalyzeDetectionScope("user-analyst-alpha", "client-alpha", rule.RuleID)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Domains[0].DSMVerified {
		t.Fatal("a token-only match must not verify a DSM")
	}
	if sc.Domains[0].Status == ReadinessReady {
		t.Fatal("token-only DSM must not produce READY")
	}
}

// Worker isolation -------------------------------------------------------------

func TestHardening_WorkerScriptIntegrityRefused(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	rule, dom := readySigmaDomain(t, db)
	t.Setenv("SIGMA_WORKER_PYTHON", "python-does-not-matter")
	t.Setenv("SIGMA_WORKER_SCRIPT", "worker.py")
	t.Setenv("SIGMA_WORKER_SCRIPT_SHA256", strings.Repeat("0", 64))
	old := workerCommand
	workerCommand = run()
	defer func() { workerCommand = old }()

	tr, err := CreateDetectionTranslation(context.Background(), "user-admin", rule.RuleID, TranslationRequest{
		ClientID: "client-alpha", DomainID: dom.DomainID, Mode: "VERIFIED_FIELDS_ONLY",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tr.Status != ReadinessBlocked || tr.AQLDraft != "" {
		t.Fatalf("a tampered worker script must block, got %s %q", tr.Status, tr.AQLDraft)
	}
}

func TestHardening_IsolationIsReportedHonestly(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	rule, dom := readySigmaDomain(t, db)
	stubWorker(t, func(req sigmaWorkerRequest) (sigmaWorkerResponse, string) {
		return sigmaWorkerResponse{Status: "OK", AQL: `SELECT * FROM events WHERE "Event ID"=4624`}, ""
	})
	tr, err := CreateDetectionTranslation(context.Background(), "user-admin", rule.RuleID, TranslationRequest{
		ClientID: "client-alpha", DomainID: dom.DomainID, Mode: "VERIFIED_FIELDS_ONLY",
	})
	if err != nil {
		t.Fatal(err)
	}
	iso := tr.Diagnostics.Isolation
	if !iso.TimeoutEnforced || !iso.OutputCapped {
		t.Fatalf("enforced limits must be reported: %+v", iso)
	}
	if iso.NetworkSandbox || iso.FilesystemSandbox {
		t.Fatalf("no OS sandbox exists; it must not be claimed: %+v", iso)
	}
	if tr.Diagnostics.Executed {
		t.Fatal("a draft must never claim execution")
	}
}
