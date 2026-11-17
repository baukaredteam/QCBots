package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

const sigmaReadyFixture = `title: Logon Event Only
id: 22222222-2222-2222-2222-222222222222
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
  condition: selection
level: low
`

// stubWorker replaces the Python process for deterministic protocol tests.
func stubWorker(t *testing.T, fn func(req sigmaWorkerRequest) (sigmaWorkerResponse, string)) {
	t.Helper()
	old := workerCommand
	workerCommand = func(ctx context.Context, req sigmaWorkerRequest) ([]byte, []byte, error) {
		resp, status := fn(req)
		resp.Protocol = sigmaWorkerProtocol
		resp.RequestID = req.RequestID
		resp.SigmaSHA = req.SigmaSHA
		resp.WorkerVersion = "1"
		resp.BackendVersion = "0.3.2"
		resp.PySigmaVersion = "0.11.23"
		if resp.Status == "" {
			resp.Status = status
		}
		if resp.Status == "" {
			resp.Status = "OK"
		}
		out, _ := json.Marshal(resp)
		return out, []byte("stub"), nil
	}
	t.Cleanup(func() { workerCommand = old })
}

// readySigmaDomain builds a domain whose single Sigma field is attested and whose
// DSM is catalogue-verified, so a VERIFIED_FIELDS_ONLY draft can reach READY.
func readySigmaDomain(t *testing.T, db *DB) (*SigmaRule, *QRadarDomain) {
	t.Helper()
	inst, err := CreateQRadarInstance("user-admin", "client-alpha", "QRadar-Prod", "qr.internal")
	if err != nil {
		t.Fatal(err)
	}
	dom := mkDomain(t, db, "user-admin", inst.InstanceID, "Corporate", "production")
	if _, err := CreateQRadarLogSourceType("user-admin", dom.DomainID, "Microsoft Windows Security Event Log"); err != nil {
		t.Fatal(err)
	}
	m, err := CreateQRadarFieldMapping("user-admin", "client-alpha", dom.DomainID, "EventID", "event_id", "event_id", "Microsoft Windows Security Event Log", "4624", "1", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApproveQRadarFieldMapping("user-reviewer", m.MappingID, "CEP export compared, ticket TB-20"); err != nil {
		t.Fatal(err)
	}
	fd, err := CreateQRadarFieldDefinition("user-admin", "client-alpha", dom.DomainID, "EventID", "system", "integer", "event_id", "4624", "event_id")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateQRadarFieldObservation("user-reviewer", "client-alpha", dom.DomainID, fd.FieldID, true, true, true, "VERIFIED", "2026-01-01T00:00:00Z", "user-reviewer", "ticket TB-20: AQL event_id"); err != nil {
		t.Fatal(err)
	}
	rule, err := IngestSigmaRule("user-admin", "client-alpha", "", "ready.yml", sigmaReadyFixture)
	if err != nil {
		t.Fatal(err)
	}
	return rule, dom
}

// AQL validator ----------------------------------------------------------------

func TestAQL_TenantScopingWrapsOrCondition(t *testing.T) {
	v, err := TenantScopedAQL(`SELECT * FROM events WHERE "Event ID"=4624 OR "Event ID"=4625`, "5", 7)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(v.AQL, "SELECT * FROM events WHERE domainid=5 AND (") {
		t.Fatalf("tenant predicate must come first: %s", v.AQL)
	}
	if !strings.HasSuffix(v.AQL, ") LAST 7 DAYS") {
		t.Fatalf("time window missing: %s", v.AQL)
	}
	// The OR is inside the parenthesised body, so it cannot bypass the domain.
	if strings.Index(v.AQL, "domainid=5") > strings.Index(v.AQL, "OR ") {
		t.Fatalf("domain filter must precede the rule body: %s", v.AQL)
	}
	// A literal compared to a literal is refused: that is the shape used to
	// smuggle always-true predicates into a query.
	if _, err := TenantScopedAQL(`SELECT * FROM events WHERE 1=1`, "5", 7); !errors.Is(err, ErrAQLInvalid) {
		t.Fatalf("literal-only comparison must be refused, got %v", err)
	}
}

func TestAQL_QuotedLiteralsRoundTrip(t *testing.T) {
	v, err := TenantScopedAQL(`SELECT * FROM events WHERE Command LIKE '%it''s%'`, "5", 7)
	if err != nil {
		t.Fatalf("quoted literal with an escaped quote: %v", err)
	}
	if !strings.Contains(v.AQL, `'%it''s%'`) {
		t.Fatalf("literal was not re-escaped correctly: %s", v.AQL)
	}
}

func TestAQL_FunctionsAndKeywordOperators(t *testing.T) {
	v, err := TenantScopedAQL(`SELECT * FROM events WHERE LOWER(Command) LIKE '%-enc%' AND "Event ID" IN(4688, 4624)`, "5", 7)
	if err != nil {
		t.Fatalf("LOWER/IN must be accepted: %v", err)
	}
	if !strings.Contains(v.AQL, "LOWER(Command) LIKE '%-enc%'") || !strings.Contains(v.AQL, "IN(4688, 4624)") {
		t.Fatalf("canonical rendering lost structure: %s", v.AQL)
	}
}

func TestAQL_RejectsUnsupportedFunctionsAndNesting(t *testing.T) {
	cases := []string{
		`SELECT * FROM events WHERE JSONEXTRACT(Command) LIKE 'x'`,
		`SELECT * FROM events WHERE Command LIKE CONCAT('a','b')`,
		`SELECT * FROM events WHERE Command = (SELECT Command FROM events)`,
		`SELECT * FROM events WHERE Command LIKE 'a' AND`,
		`SELECT * FROM events WHERE Command LIKE 'a' EXTRA`,
		`SELECT name FROM users WHERE a=1`,
	}
	for _, q := range cases {
		if _, err := TenantScopedAQL(q, "5", 7); err == nil {
			t.Fatalf("statement must be refused: %s", q)
		}
	}
}

func TestAQL_PreservesPrecedenceAndParens(t *testing.T) {
	v, err := TenantScopedAQL(`SELECT * FROM events WHERE ("Event ID"=4624 OR "Event ID"=4625) AND Command LIKE '%x%'`, "5", 7)
	if err != nil {
		t.Fatal(err)
	}
	// OR stays grouped inside AND; the tenant predicate remains outermost.
	if !strings.Contains(v.AQL, `("Event ID" = 4624 OR "Event ID" = 4625) AND Command LIKE '%x%'`) {
		t.Fatalf("precedence not preserved: %s", v.AQL)
	}
}

func TestAQL_RejectsUnsafeStatements(t *testing.T) {
	cases := []string{
		`SELECT * FROM events WHERE a=1; DROP TABLE events`,
		`SELECT * FROM events WHERE a=1 -- comment`,
		`SELECT * FROM events WHERE a=1 /* x */`,
		`SELECT * FROM events WHERE (a=1`,
		`SELECT * FROM events WHERE a='unterminated`,
		`DELETE FROM events`,
		`SELECT * FROM events WHERE domainid=5 AND a=1`,
		"SELECT * FROM events WHERE a=1\nAND b=2",
		`SELECT * FROM events WHERE a=1 UNION SELECT * FROM events`,
	}
	for _, q := range cases {
		if _, err := TenantScopedAQL(q, "5", 7); err == nil {
			t.Fatalf("statement must be rejected: %s", q)
		}
	}
}

func TestAQL_RejectsBadDomainAndWindow(t *testing.T) {
	q := `SELECT * FROM events WHERE a=1`
	for _, id := range []string{"", "corporate", "-1", "12345678901"} {
		if _, err := TenantScopedAQL(q, id, 7); err == nil {
			t.Fatalf("domain id %q must be rejected", id)
		}
	}
	for _, w := range []int{0, -1, 91, 1000} {
		if _, err := TenantScopedAQL(q, "5", w); err == nil {
			t.Fatalf("time window %d must be rejected", w)
		}
	}
}

// Translation end to end (stubbed worker) --------------------------------------

func TestTranslation_ReadyDraftIsScopedAndPersisted(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	rule, dom := readySigmaDomain(t, db)
	stubWorker(t, func(req sigmaWorkerRequest) (sigmaWorkerResponse, string) {
		return sigmaWorkerResponse{
			Status:          "OK",
			AQL:             `SELECT * FROM events WHERE "Event ID"=4624`,
			ConvertedFields: []string{"EventID"},
		}, ""
	})

	tr, err := CreateDetectionTranslation(context.Background(), "user-admin", rule.RuleID, TranslationRequest{
		ClientID: "client-alpha", DomainID: dom.DomainID, Mode: "VERIFIED_FIELDS_ONLY", TimeWindowDays: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tr.Status != ReadinessReady {
		t.Fatalf("expected READY_FOR_REVIEW, got %s (%+v)", tr.Status, tr.Diagnostics)
	}
	if !strings.Contains(tr.AQLDraft, "domainid="+tr.NativeDomainID) || !strings.Contains(tr.AQLDraft, "LAST 7 DAYS") {
		t.Fatalf("draft not tenant scoped: %s", tr.AQLDraft)
	}
	if tr.AQLSHA256 == "" || tr.Diagnostics.Executed {
		t.Fatalf("provenance wrong: %+v", tr)
	}
	if len(tr.Mappings) != 1 || tr.Mappings[0].MappingID == "" {
		t.Fatalf("mapping snapshot missing: %+v", tr.Mappings)
	}
	// Immutable.
	if _, err := db.Exec(`UPDATE detection_translations SET aql_draft='rewritten' WHERE translation_id=?`, tr.TranslationID); err == nil {
		t.Fatal("translations must be immutable")
	}
	if _, err := db.Exec(`DELETE FROM detection_translations WHERE translation_id=?`, tr.TranslationID); err == nil {
		t.Fatal("translations must not be deletable")
	}
}

func TestTranslation_RefusesWithoutAttestedFields(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	// Reuse the fixture rule from 2B-2 (EventID + CommandLine + Image, unmapped).
	rule, dom := sigmaScopeFixture(t, db, "client-alpha")
	stubWorker(t, func(req sigmaWorkerRequest) (sigmaWorkerResponse, string) {
		t.Fatal("worker must not be called when the verified-fields policy fails")
		return sigmaWorkerResponse{}, ""
	})
	tr, err := CreateDetectionTranslation(context.Background(), "user-admin", rule.RuleID, TranslationRequest{
		ClientID: "client-alpha", DomainID: dom.DomainID, Mode: "VERIFIED_FIELDS_ONLY",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tr.Status != ReadinessNeedsVerification || tr.AQLDraft != "" {
		t.Fatalf("expected refusal without AQL, got %s %q", tr.Status, tr.AQLDraft)
	}
	if len(tr.Diagnostics.Notes) == 0 {
		t.Fatal("refusal must be explained")
	}
}

func TestTranslation_UnverifiedBindingDenied(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, _ := CreateQRadarInstance("user-admin", "client-alpha", "QRadar-Prod", "qr.internal")
	unbound, _ := CreateQRadarDomain("user-admin", inst.InstanceID, "Corporate", "production")
	rule, err := IngestSigmaRule("user-admin", "client-alpha", "", "r.yml", sigmaReadyFixture)
	if err != nil {
		t.Fatal(err)
	}
	_, err = CreateDetectionTranslation(context.Background(), "user-admin", rule.RuleID, TranslationRequest{
		ClientID: "client-alpha", DomainID: unbound.DomainID, Mode: "VERIFIED_FIELDS_ONLY",
	})
	if !errors.Is(err, ErrDomainNotAssigned) {
		t.Fatalf("unverified binding must deny translation, got %v", err)
	}
}

func TestTranslation_CrossClientAndRevokedGrant(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	rule, dom := readySigmaDomain(t, db)
	if _, err := CreateDetectionTranslation(context.Background(), "user-analyst-beta", rule.RuleID, TranslationRequest{
		ClientID: "client-beta", DomainID: dom.DomainID, Mode: "VERIFIED_FIELDS_ONLY",
	}); err == nil {
		t.Fatal("foreign client must not translate this rule")
	}
	if _, err := db.Exec(`DELETE FROM user_authorized_clients WHERE user_id='user-admin' AND client_id='client-alpha'`); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateDetectionTranslation(context.Background(), "user-admin", rule.RuleID, TranslationRequest{
		ClientID: "client-alpha", DomainID: dom.DomainID, Mode: "VERIFIED_FIELDS_ONLY",
	}); !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("revoked grant must deny, got %v", err)
	}
}

func TestTranslation_WorkerUnavailableBlocks(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	rule, dom := readySigmaDomain(t, db)
	old := workerCommand
	workerCommand = func(ctx context.Context, req sigmaWorkerRequest) ([]byte, []byte, error) {
		return nil, nil, ErrWorkerUnavailable
	}
	defer func() { workerCommand = old }()

	tr, err := CreateDetectionTranslation(context.Background(), "user-admin", rule.RuleID, TranslationRequest{
		ClientID: "client-alpha", DomainID: dom.DomainID, Mode: "VERIFIED_FIELDS_ONLY",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tr.Status != ReadinessBlocked || tr.AQLDraft != "" {
		t.Fatalf("missing worker must block, got %s %q", tr.Status, tr.AQLDraft)
	}
	if tr.Diagnostics.WorkerError == "" {
		t.Fatal("blocked draft must explain why")
	}
}

func TestTranslation_MalformedWorkerOutputBlocks(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	rule, dom := readySigmaDomain(t, db)
	old := workerCommand
	workerCommand = func(ctx context.Context, req sigmaWorkerRequest) ([]byte, []byte, error) {
		return []byte(`{"protocol":"sentinel.sigma.worker/1","status":"OK"`), nil, nil
	}
	defer func() { workerCommand = old }()

	tr, err := CreateDetectionTranslation(context.Background(), "user-admin", rule.RuleID, TranslationRequest{
		ClientID: "client-alpha", DomainID: dom.DomainID, Mode: "VERIFIED_FIELDS_ONLY",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tr.Status != ReadinessBlocked || tr.AQLDraft != "" {
		t.Fatalf("malformed worker output must block, got %s %q", tr.Status, tr.AQLDraft)
	}
}

func TestTranslation_InvalidWorkerAQLBlocks(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	rule, dom := readySigmaDomain(t, db)
	stubWorker(t, func(req sigmaWorkerRequest) (sigmaWorkerResponse, string) {
		return sigmaWorkerResponse{Status: "OK", AQL: `SELECT * FROM events WHERE a=1; DROP TABLE x`}, ""
	})
	tr, err := CreateDetectionTranslation(context.Background(), "user-admin", rule.RuleID, TranslationRequest{
		ClientID: "client-alpha", DomainID: dom.DomainID, Mode: "VERIFIED_FIELDS_ONLY",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tr.Status != ReadinessBlocked || tr.AQLDraft != "" {
		t.Fatalf("invalid AQL must not be stored, got %s %q", tr.Status, tr.AQLDraft)
	}
}

func TestTranslation_UnsupportedFromWorker(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	rule, dom := readySigmaDomain(t, db)
	stubWorker(t, func(req sigmaWorkerRequest) (sigmaWorkerResponse, string) {
		return sigmaWorkerResponse{Status: "UNSUPPORTED", UnsupportedConditions: []string{"field 'X' is not supported"}}, ""
	})
	tr, err := CreateDetectionTranslation(context.Background(), "user-admin", rule.RuleID, TranslationRequest{
		ClientID: "client-alpha", DomainID: dom.DomainID, Mode: "REVIEW_REQUIRED_FIELDS",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tr.Status != ReadinessUnsupported || len(tr.Diagnostics.UnsupportedConditions) == 0 {
		t.Fatalf("unsupported conversion must be recorded: %+v", tr)
	}
}

func TestTranslation_StaleAfterMappingChange(t *testing.T) {
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
	if tr.Stale {
		t.Fatal("a fresh draft must not be stale")
	}
	// A new mapping version for the same field makes the snapshot obsolete.
	if _, err := CreateQRadarFieldMapping("user-admin", "client-alpha", dom.DomainID, "EventID", "event_id", "event_id", "Microsoft Windows Security Event Log", "4624", "2", "manual"); err != nil {
		t.Fatal(err)
	}
	got, err := GetDetectionTranslation(tr.TranslationID, "user-admin")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Stale {
		t.Fatalf("expected stale draft, reasons=%+v", got.StaleReasons)
	}
}

func TestTranslation_StaleAfterBindingChange(t *testing.T) {
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
	b, _ := GetDomainBinding(dom.DomainID)
	if _, err := UpdateDomainBinding("user-admin", dom.DomainID, DomainBindingUpdate{
		BindingKind: "UNASSIGNED", Evidence: "ownership withdrawn for staleness test, ticket TB-21",
		ExpectedRevision: b.Revision,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := GetDetectionTranslation(tr.TranslationID, "user-admin")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Stale {
		t.Fatalf("binding change must stale the draft, reasons=%+v", got.StaleReasons)
	}
}

// Worker protocol guards -------------------------------------------------------

func TestWorker_ProtocolRejectsMismatchAndOversize(t *testing.T) {
	old := workerCommand
	defer func() { workerCommand = old }()

	workerCommand = func(ctx context.Context, req sigmaWorkerRequest) ([]byte, []byte, error) {
		out, _ := json.Marshal(sigmaWorkerResponse{Protocol: sigmaWorkerProtocol, RequestID: "other", Status: "OK"})
		return out, nil, nil
	}
	if _, err := CallSigmaWorker(context.Background(), "x", "", map[string]string{}, "VERIFIED_FIELDS_ONLY"); !errors.Is(err, ErrWorkerProtocol) {
		t.Fatalf("request id mismatch must be refused, got %v", err)
	}

	workerCommand = func(ctx context.Context, req sigmaWorkerRequest) ([]byte, []byte, error) {
		big := make([]byte, 300<<10)
		return big, nil, nil
	}
	if _, err := CallSigmaWorker(context.Background(), "x", "", map[string]string{}, "VERIFIED_FIELDS_ONLY"); !errors.Is(err, ErrWorkerProtocol) {
		t.Fatalf("oversized output must be refused, got %v", err)
	}
}

func TestWorker_TimeoutRefused(t *testing.T) {
	old := workerCommand
	oldTimeout := workerTimeout()
	defer func() { workerCommand = old }()
	workerCommand = func(ctx context.Context, req sigmaWorkerRequest) ([]byte, []byte, error) {
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}
	t.Setenv("SIGMA_WORKER_TIMEOUT_MS", "50")
	if workerTimeout() > 200*time.Millisecond {
		t.Fatalf("timeout override not applied: %v", workerTimeout())
	}
	_, err := CallSigmaWorker(context.Background(), "x", "", map[string]string{}, "VERIFIED_FIELDS_ONLY")
	if err == nil {
		t.Fatal("timeout must surface as an error")
	}
	_ = oldTimeout
}

// Real worker integration (opt-in) --------------------------------------------

func TestWorker_RealPySigmaConversion(t *testing.T) {
	if testing.Short() {
		t.Skip("real worker test skipped in short mode")
	}
	if os.Getenv("SIGMA_WORKER_PYTHON") == "" {
		t.Skip("SIGMA_WORKER_PYTHON not set: real pySigma worker not available")
	}
	resp, err := CallSigmaWorker(context.Background(), sigmaReadyFixture, "", map[string]string{"EventID": "event_id"}, "VERIFIED_FIELDS_ONLY")
	if err != nil {
		t.Fatalf("worker call: %v", err)
	}
	if resp.Status != "OK" {
		t.Fatalf("worker status %s: %+v", resp.Status, resp.UnsupportedConditions)
	}
	if !strings.Contains(strings.ToUpper(resp.AQL), "FROM EVENTS") {
		t.Fatalf("unexpected AQL: %s", resp.AQL)
	}
	if _, err := TenantScopedAQL(resp.AQL, "5", 7); err != nil {
		t.Fatalf("real worker AQL did not pass validation: %v %s", err, resp.AQL)
	}
}



const sigmaNotFixture = `title: Negated Filter
id: 10000000-0000-0000-0000-000000000010
logsource: {product: windows, service: security}
detection:
  sel: {EventID: 4624}
  filt: {Image|endswith: '\trusted.exe'}
  condition: sel and not filt
`

const sigmaOrFixture = `title: Either Event
id: 10000000-0000-0000-0000-000000000011
logsource: {product: windows, service: security}
detection:
  s1: {EventID: 4624}
  s2: {EventID: 4625}
  condition: s1 or s2
`

// Real worker: a quality gate on semantics, not syntax. If the backend converts a
// NOT rule, the excluded field must appear in the AQL; if it cannot, the result
// must be UNSUPPORTED with a reason вЂ” never a silently dropped filter.
func TestWorker_RealNotNeverDropped(t *testing.T) {
	if os.Getenv("SIGMA_WORKER_PYTHON") == "" {
		t.Skip("SIGMA_WORKER_PYTHON not set: real pySigma worker not available")
	}
	resp, err := CallSigmaWorker(context.Background(), sigmaNotFixture, "", map[string]string{
		"EventID": "event_id", "Image": "image",
	}, "REVIEW_REQUIRED_FIELDS")
	if err != nil {
		t.Fatalf("worker call: %v", err)
	}
	if resp.Status == "OK" {
		lower := strings.ToLower(resp.AQL)
		if !strings.Contains(lower, "process") && !strings.Contains(lower, "image") {
			t.Fatalf("converted AQL dropped the NOT filter: %s", resp.AQL)
		}
		return
	}
	if len(resp.UnsupportedConditions) == 0 {
		t.Fatalf("unsupported NOT must carry a reason: %+v", resp)
	}
}

func TestWorker_RealOrPreserved(t *testing.T) {
	if os.Getenv("SIGMA_WORKER_PYTHON") == "" {
		t.Skip("SIGMA_WORKER_PYTHON not set: real pySigma worker not available")
	}
	resp, err := CallSigmaWorker(context.Background(), sigmaOrFixture, "", map[string]string{"EventID": "event_id"}, "REVIEW_REQUIRED_FIELDS")
	if err != nil {
		t.Fatalf("worker call: %v", err)
	}
	if resp.Status != "OK" {
		t.Fatalf("OR should convert, got %s: %+v", resp.Status, resp.UnsupportedConditions)
	}
	if !strings.Contains(resp.AQL, "4624") || !strings.Contains(resp.AQL, "4625") {
		t.Fatalf("OR alternatives were not preserved: %s", resp.AQL)
	}
}

