package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sigmaFixture = `title: Suspicious PowerShell Encoded Command
id: 8c4f3e2a-1b2c-4d5e-9f10-aabbccddeeff
status: experimental
description: Detects encoded PowerShell execution on Windows endpoints
author: Sentinel Atlas
references:
  - https://example.invalid/report
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    CommandLine|contains: '-enc'
  filter_trusted:
    Image|endswith: '\trusted.exe'
  condition: selection and not filter_trusted
falsepositives:
  - Administrative scripts
level: high
tags:
  - attack.execution
  - attack.t1059.001
`

func sigmaScopeFixture(t *testing.T, db *DB, clientID string) (rule *SigmaRule, domain *QRadarDomain) {
	t.Helper()
	user := "user-analyst-alpha"
	if clientID == "client-beta" {
		user = "user-analyst-beta"
	}
	inst, err := CreateQRadarInstance(user, clientID, "QRadar-Prod-"+clientID, "qr.internal")
	if err != nil {
		t.Fatalf("instance: %v", err)
	}
	dom := mkDomain(t, db, user, inst.InstanceID, "Corporate-"+clientID, "production")
	if _, err := CreateQRadarLogSourceType(user, dom.DomainID, "Microsoft Windows Security Event Log"); err != nil {
		t.Fatalf("log source type: %v", err)
	}
	r, err := IngestSigmaRule(user, clientID, "", "rule.yml", sigmaFixture)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	return r, dom
}

// A. Sigma ingestion and parsing ------------------------------------------------

func TestSigma_ValidRuleParsedAndStored(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	r, err := IngestSigmaRule("user-analyst-alpha", "client-alpha", "", "rule.yml", sigmaFixture)
	if err != nil {
		t.Fatal(err)
	}
	if r.SigmaRuleID != "8c4f3e2a-1b2c-4d5e-9f10-aabbccddeeff" {
		t.Fatalf("rule id: %s", r.SigmaRuleID)
	}
	if r.Title != "Suspicious PowerShell Encoded Command" || r.Level != "high" {
		t.Fatalf("metadata: %+v", r)
	}
	if r.LogsourceProduct != "windows" || r.LogsourceService != "security" {
		t.Fatalf("logsource: %+v", r)
	}
	if r.Condition != "selection and not filter_trusted" {
		t.Fatalf("condition not preserved: %q", r.Condition)
	}
	if len(r.Tags) != 2 || r.Tags[1] != "attack.t1059.001" {
		t.Fatalf("tags: %+v", r.Tags)
	}
	if r.YAMLSHA256 == "" || r.ByteSize == 0 {
		t.Fatalf("hash/size missing: %+v", r)
	}
	got, err := GetSigmaRule(r.RuleID, "user-analyst-alpha")
	if err != nil || got.RuleID != r.RuleID {
		t.Fatalf("retrieval: %v", err)
	}
}

func TestSigma_MalformedRejected(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	cases := map[string]string{
		"bad yaml":        "title: [unclosed\n",
		"missing id":      "title: X\ndetection:\n  sel:\n    a: 1\n  condition: sel\n",
		"missing title":   "id: r-1\ndetection:\n  sel:\n    a: 1\n  condition: sel\n",
		"missing detect":  "id: r-2\ntitle: X\n",
		"empty detection": "id: r-3\ntitle: X\ndetection: {}\n",
		"unknown condition ref": "id: r-4\ntitle: X\ndetection:\n  sel:\n    a: 1\n  condition: other\n",
	}
	for name, body := range cases {
		if _, err := IngestSigmaRule("user-analyst-alpha", "client-alpha", "", name+".yml", body); err == nil {
			t.Fatalf("%s: expected rejection", name)
		}
	}
}

func TestSigma_OversizedRejected(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	big := sigmaFixture + "\n# " + strings.Repeat("A", maxSigmaBytes)
	if _, err := IngestSigmaRule("user-analyst-alpha", "client-alpha", "", "big.yml", big); !errors.Is(err, ErrSigmaInvalid) {
		t.Fatalf("oversized rule must be rejected, got %v", err)
	}
}

func TestSigma_DuplicateIdSameContentIsIdempotent(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	a, err := IngestSigmaRule("user-analyst-alpha", "client-alpha", "", "a.yml", sigmaFixture)
	if err != nil {
		t.Fatal(err)
	}
	b, err := IngestSigmaRule("user-analyst-alpha", "client-alpha", "", "b.yml", sigmaFixture)
	if err != nil || b.RuleID != a.RuleID {
		t.Fatalf("same content must reuse the stored rule: %v", err)
	}
}

func TestSigma_DuplicateIdDifferentContentIsNewVersion(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	a, err := IngestSigmaRule("user-analyst-alpha", "client-alpha", "", "a.yml", sigmaFixture)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(sigmaFixture, "level: high", "level: medium", 1)
	b, err := IngestSigmaRule("user-analyst-alpha", "client-alpha", "", "b.yml", changed)
	if err != nil {
		t.Fatal(err)
	}
	if b.RuleID == a.RuleID {
		t.Fatal("changed content must create a new immutable version, not overwrite")
	}
	if b.Version != a.Version+1 {
		t.Fatalf("expected version %d, got %d", a.Version+1, b.Version)
	}
	// The first version is untouched.
	old, _ := GetSigmaRule(a.RuleID, "user-analyst-alpha")
	if old.Level != "high" {
		t.Fatalf("earlier version was modified: %s", old.Level)
	}
}

func TestSigma_UnsupportedModifiersRecorded(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	rule := strings.Replace(sigmaFixture, "EventID: 4688", "EventID: 4688\n    Field|unknownmod: x", 1)
	r, err := IngestSigmaRule("user-analyst-alpha", "client-alpha", "", "mod.yml", rule)
	if err != nil {
		t.Fatalf("ingestion should record, not execute, modifiers: %v", err)
	}
	found := false
	for _, m := range r.Modifiers {
		if m == "unknownmod" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unsupported modifier not recorded: %+v", r.Modifiers)
	}
}

// C. MSSP isolation -------------------------------------------------------------

func TestSigma_CrossClientDenied(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	r, err := IngestSigmaRule("user-analyst-alpha", "client-alpha", "", "x.yml", sigmaFixture)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GetSigmaRule(r.RuleID, "user-analyst-beta"); !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("beta must not read alpha's rule, got %v", err)
	}
	if _, err := AnalyzeDetectionScope("user-analyst-beta", "client-beta", r.RuleID); err == nil {
		t.Fatal("beta must not analyse alpha's rule")
	}
	if _, err := IngestSigmaRule("user-analyst-beta", "client-alpha", "", "x.yml", sigmaFixture); !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("beta must not ingest under alpha, got %v", err)
	}
}

func TestSigma_RevokedGrantDenied(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	r, err := IngestSigmaRule("user-analyst-alpha", "client-alpha", "", "x.yml", sigmaFixture)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM user_authorized_clients WHERE user_id='user-analyst-alpha' AND client_id='client-alpha'`); err != nil {
		t.Fatal(err)
	}
	if _, err := GetSigmaRule(r.RuleID, "user-analyst-alpha"); !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("revoked grant must deny, got %v", err)
	}
}

// B + C. Scope resolution and field readiness ------------------------------------

func TestSigma_ScopeUnverifiedDomainIsBlocked(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr.internal")
	if err != nil {
		t.Fatal(err)
	}
	d, err := CreateQRadarDomain("user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	if err != nil {
		t.Fatal(err)
	}
	r, err := IngestSigmaRule("user-analyst-alpha", "client-alpha", "", "x.yml", sigmaFixture)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := AnalyzeDetectionScope("user-analyst-alpha", "client-alpha", r.RuleID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.Domains) != 0 {
		t.Fatalf("an unverified domain must not appear in scope: %+v", sc.Domains)
	}
	if sc.Status != "TELEMETRY_UNKNOWN" && sc.Status != "BLOCKED" {
		t.Fatalf("unexpected status %s", sc.Status)
	}
	_ = d
}

func TestSigma_ScopeReadinessStates(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	r, dom := sigmaScopeFixture(t, db, "client-alpha")

	// Approved mapping + reviewer attestation for EventID; CommandLine stays raw-only.
	m, err := CreateQRadarFieldMapping("user-analyst-alpha", "client-alpha", dom.DomainID, "EventID", "event_id", "event_id", "Microsoft Windows Security Event Log", "4688", "1", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApproveQRadarFieldMapping("user-reviewer", m.MappingID, "values compared with CEP export, ticket TB-1"); err != nil {
		t.Fatal(err)
	}
	fd, err := CreateQRadarFieldDefinition("user-analyst-alpha", "client-alpha", dom.DomainID, "EventID", "system", "integer", "event_id", "4688", "event_id")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateQRadarFieldObservation("user-reviewer", "client-alpha", dom.DomainID, fd.FieldID, true, true, true, "VERIFIED", "2026-01-01T00:00:00Z", "user-reviewer", "ticket TB-1: AQL event_id"); err != nil {
		t.Fatal(err)
	}

	sc, err := AnalyzeDetectionScope("user-analyst-alpha", "client-alpha", r.RuleID)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Status != "NEEDS_FIELD_VERIFICATION" {
		t.Fatalf("expected NEEDS_FIELD_VERIFICATION (CommandLine unmapped), got %s (%+v)", sc.Status, sc.Notes)
	}
	if len(sc.Domains) != 1 {
		t.Fatalf("expected one verified domain, got %+v", sc.Domains)
	}
	states := map[string]string{}
	for _, f := range sc.Domains[0].Fields {
		states[f.Field] = f.State
	}
	if states["EventID"] != "AQL_MANUALLY_ATTESTED" {
		t.Fatalf("EventID readiness: %+v", sc.Domains[0].Fields)
	}
	if states["CommandLine"] == "AQL_MANUALLY_ATTESTED" || states["CommandLine"] == "MAPPING_APPROVED" {
		t.Fatalf("unmapped field must not look ready: %v", states)
	}
	if states["Image"] != "MISSING" && states["Image"] != "UNSUPPORTED" {
		t.Fatalf("Image should be missing/unsupported, got %q", states["Image"])
	}
}

func TestSigma_ScopeApprovedMappingWithoutAttestationNeedsVerification(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	r, dom := sigmaScopeFixture(t, db, "client-alpha")
	m, err := CreateQRadarFieldMapping("user-analyst-alpha", "client-alpha", dom.DomainID, "EventID", "event_id", "event_id", "Microsoft Windows Security Event Log", "4688", "1", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApproveQRadarFieldMapping("user-reviewer", m.MappingID, "mapping approved from CEP export, ticket TB-2"); err != nil {
		t.Fatal(err)
	}
	sc, err := AnalyzeDetectionScope("user-analyst-alpha", "client-alpha", r.RuleID)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range sc.Domains[0].Fields {
		if f.Field == "EventID" {
			if f.State != "MAPPING_APPROVED" {
				t.Fatalf("approved but unattested field must be MAPPING_APPROVED, got %s", f.State)
			}
		}
	}
	if sc.Status == "READY_FOR_REVIEW" {
		t.Fatal("an approved mapping alone must not make the translation ready")
	}
}

func TestSigma_ScopeCrossClientMappingNotReused(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	// Alpha has an approved mapping in its own domain.
	ra, domA := sigmaScopeFixture(t, db, "client-alpha")
	m, err := CreateQRadarFieldMapping("user-analyst-alpha", "client-alpha", domA.DomainID, "EventID", "event_id", "event_id", "Microsoft Windows Security Event Log", "4688", "1", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApproveQRadarFieldMapping("user-reviewer", m.MappingID, "alpha mapping, ticket TB-3"); err != nil {
		t.Fatal(err)
	}
	// Beta has its own rule and domain, with no mappings.
	rb, _ := sigmaScopeFixture(t, db, "client-beta")
	sc, err := AnalyzeDetectionScope("user-analyst-beta", "client-beta", rb.RuleID)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range sc.Domains {
		for _, f := range d.Fields {
			if f.State == "MAPPING_APPROVED" || f.State == "AQL_MANUALLY_ATTESTED" {
				t.Fatalf("beta must not inherit alpha's mapping: %+v", f)
			}
		}
	}
	_ = ra
}

// E. Persistence -----------------------------------------------------------------

func TestSigma_StoredRuleIsImmutable(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	r, err := IngestSigmaRule("user-analyst-alpha", "client-alpha", "", "x.yml", sigmaFixture)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE sigma_detection_rules SET title='rewritten' WHERE rule_id=?`, r.RuleID); err == nil {
		t.Fatal("stored Sigma rules must be immutable")
	}
	if _, err := db.Exec(`DELETE FROM sigma_detection_rules WHERE rule_id=?`, r.RuleID); err == nil {
		t.Fatal("stored Sigma rules must not be deletable")
	}
}

func TestSigma_IngestRequiresCapability(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	if _, err := IngestSigmaRule("user-readonly", "client-alpha", "", "x.yml", sigmaFixture); !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("READ_ONLY must not ingest detections, got %v", err)
	}
}

func TestSigma_ScopeUsesVerifiedBindingOnly(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	r, dom := sigmaScopeFixture(t, db, "client-alpha")
	// Revoke the binding; the domain must drop out of scope immediately.
	b, _ := GetDomainBinding(dom.DomainID)
	if _, err := UpdateDomainBinding("user-admin", dom.DomainID, DomainBindingUpdate{
		BindingKind: "UNASSIGNED", Evidence: "ownership withdrawn for test, ticket TB-4",
		ExpectedRevision: b.Revision,
	}); err != nil {
		t.Fatal(err)
	}
	sc, err := AnalyzeDetectionScope("user-analyst-alpha", "client-alpha", r.RuleID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.Domains) != 0 {
		t.Fatalf("revoked binding must remove the domain from scope: %+v", sc.Domains)
	}
}

func TestSigma_ScopeConflictingMappings(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	r, dom := sigmaScopeFixture(t, db, "client-alpha")
	// Two different targets for one raw field: not resolvable here.
	if _, err := CreateQRadarFieldMapping("user-analyst-alpha", "client-alpha", dom.DomainID, "EventID", "event_id", "event_id", "Microsoft Windows Security Event Log", "4688", "1", "auto"); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateQRadarFieldMapping("user-analyst-alpha", "client-alpha", dom.DomainID, "EventID", "qid", "qid", "Microsoft Windows Security Event Log", "4688", "1", "auto"); err != nil {
		t.Fatal(err)
	}
	sc, err := AnalyzeDetectionScope("user-analyst-alpha", "client-alpha", r.RuleID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range sc.Domains[0].Fields {
		if f.Field == "EventID" && f.State == FieldStateConflict {
			found = true
		}
	}
	if !found {
		t.Fatalf("conflicting mappings must be reported, got %+v", sc.Domains[0].Fields)
	}
	if sc.Status == ReadinessReady {
		t.Fatal("conflicting mappings must not be READY")
	}
}

func TestSigma_ScopeMultipleLogSourcesAreCandidates(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	r, dom := sigmaScopeFixture(t, db, "client-alpha")
	if _, err := CreateQRadarLogSourceType("user-analyst-alpha", dom.DomainID, "Microsoft Windows Sysmon"); err != nil {
		t.Fatal(err)
	}
	sc, err := AnalyzeDetectionScope("user-analyst-alpha", "client-alpha", r.RuleID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.Domains[0].LogSources) < 2 {
		t.Fatalf("expected both windows log source types as candidates, got %+v", sc.Domains[0].LogSources)
	}
	catalogueMatches := 0
	for _, c := range sc.Domains[0].LogSources {
		if c.Match != CandidateToken && c.Match != CandidateDSM {
			t.Fatalf("unexpected candidate label %q", c.Match)
		}
		if c.Match == CandidateDSM {
			catalogueMatches++
		}
	}
	if catalogueMatches == 0 {
		t.Fatal("a curated catalogue DSM present in inventory must be marked CATALOGUE_MATCH")
	}
	if !sc.Domains[0].DSMVerified {
		t.Fatal("catalogue match against real inventory must set DSMVerified")
	}
}

func TestSigma_HTTPIngestAndScope(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	_, _ = sigmaScopeFixture(t, db, "client-alpha")
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/detections/sigma", applyMiddleware(http.HandlerFunc(handleIngestSigma), requireAuth, requirePermission(CanViewCTI), requirePermission(CanManageDetections), auditWrap, csrfWrap))
	mux.HandleFunc("GET /api/v1/detections/sigma/{rule_id}/scope", applyMiddleware(http.HandlerFunc(handleDetectionScope), requireAuth, requirePermission(CanViewCTI), auditWrap))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sessRO, err := db.CreateSession("user-readonly", "client-alpha")
	if err != nil {
		t.Fatal(err)
	}
	sessA, err := db.CreateSession("user-analyst-alpha", "client-alpha")
	if err != nil {
		t.Fatal(err)
	}
	post := func(sessionID, body string) int {
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/detections/sigma", strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "session_id", Value: sessionID})
		req.Header.Set("Origin", "http://localhost:5173")
		req.Header.Set("X-CSRF-Token", "t")
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "t"})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	payload := `{"client_id":"client-alpha","filename":"r.yml","sigma_yaml":` + jsonQuote(sigmaFixture) + `}`
	if code := post(sessRO.SessionID, payload); code != http.StatusForbidden {
		t.Fatalf("READ_ONLY ingest must be 403, got %d", code)
	}
	if code := post(sessA.SessionID, payload); code != http.StatusCreated {
		t.Fatalf("analyst ingest must be 201, got %d", code)
	}
	// Beta must not read alpha's scope through HTTP.
	sessB, err := db.CreateSession("user-analyst-beta", "client-beta")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := ListSigmaRules("user-analyst-alpha", "client-alpha")
	if err != nil || len(rules) == 0 {
		t.Fatalf("rules: %v %d", err, len(rules))
	}
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/detections/sigma/"+rules[0].RuleID+"/scope?client_id=client-beta", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: sessB.SessionID})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("beta scope read must be 403, got %d", resp.StatusCode)
	}
	req2, _ := http.NewRequest("GET", srv.URL+"/api/v1/detections/sigma/"+rules[0].RuleID+"/scope?client_id=client-alpha", nil)
	req2.AddCookie(&http.Cookie{Name: "session_id", Value: sessA.SessionID})
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("owner scope read must be 200, got %d", resp2.StatusCode)
	}
}

func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// ---- 2B-1/2B-2 corrections -------------------------------------------------

func TestSigma_AggregationConditionValidatesReferences(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	twoSel := strings.Replace(sigmaFixture, "  condition: selection and not filter_trusted",
		"  condition: 1 of them", 1)
	if _, err := IngestSigmaRule("user-analyst-alpha", "client-alpha", "", "a.yml", twoSel); err != nil {
		t.Fatalf("1 of them with real selections must be accepted structurally: %v", err)
	}
	wildcard := strings.Replace(sigmaFixture, "  condition: selection and not filter_trusted",
		"  condition: all of sel*", 1)
	wildcard = strings.Replace(wildcard, "  selection:", "  sel_main:", 1)
	if _, err := IngestSigmaRule("user-analyst-alpha", "client-alpha", "", "b.yml", wildcard); err != nil {
		t.Fatalf("all of sel* with a matching selection must be accepted: %v", err)
	}
	bad := strings.Replace(sigmaFixture, "  condition: selection and not filter_trusted",
		"  condition: 1 of missing*", 1)
	if _, err := IngestSigmaRule("user-analyst-alpha", "client-alpha", "", "c.yml", bad); !errors.Is(err, ErrSigmaInvalid) {
		t.Fatalf("aggregation over a nonexistent selection must be refused, got %v", err)
	}
	bad2 := strings.Replace(sigmaFixture, "  condition: selection and not filter_trusted",
		"  condition: selection and nosuch", 1)
	if _, err := IngestSigmaRule("user-analyst-alpha", "client-alpha", "", "d.yml", bad2); !errors.Is(err, ErrSigmaInvalid) {
		t.Fatalf("unknown selection must be refused, got %v", err)
	}
}

func TestSigma_IngestedRuleIsMarkedPreliminary(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	r, err := IngestSigmaRule("user-analyst-alpha", "client-alpha", "", "p.yml", sigmaFixture)
	if err != nil {
		t.Fatal(err)
	}
	if r.ValidationStatus != "PRELIMINARY" {
		t.Fatalf("Go parsing must not claim authoritative validation, got %q", r.ValidationStatus)
	}
}

func TestSigma_EventScopedMappingRespectsEvent(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	r, dom := sigmaScopeFixture(t, db, "client-alpha")
	// Mapping restricted to a different event than the rule's 4688.
	m, err := CreateQRadarFieldMapping("user-admin", "client-alpha", dom.DomainID, "EventID", "event_id", "event_id", "Microsoft Windows Security Event Log", "9999", "1", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApproveQRadarFieldMapping("user-reviewer", m.MappingID, "event-scoped mapping, ticket TB-30"); err != nil {
		t.Fatal(err)
	}
	sc, err := AnalyzeDetectionScope("user-analyst-alpha", "client-alpha", r.RuleID)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range sc.Domains[0].Fields {
		if f.Field == "EventID" && f.State != FieldStateScopeMismatch {
			t.Fatalf("an event-scoped mapping for 9999 must not apply to 4688, got %s", f.State)
		}
	}
}

func TestSigma_DSMMismatchIsScopeMismatch(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	r, dom := sigmaScopeFixture(t, db, "client-alpha")
	m, err := CreateQRadarFieldMapping("user-admin", "client-alpha", dom.DomainID, "EventID", "proxy_event", "evt", "Blue Coat ProxySG", "", "1", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApproveQRadarFieldMapping("user-reviewer", m.MappingID, "proxy mapping, ticket TB-31"); err != nil {
		t.Fatal(err)
	}
	sc, err := AnalyzeDetectionScope("user-analyst-alpha", "client-alpha", r.RuleID)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range sc.Domains[0].Fields {
		if f.Field == "EventID" && f.State != FieldStateScopeMismatch {
			t.Fatalf("mapping for another DSM must not apply, got %s", f.State)
		}
	}
	if sc.Status == ReadinessReady {
		t.Fatal("a DSM-scoped mismatch must not be READY")
	}
}

func TestSigma_ZeroFieldRuleIsNotReady(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	if _, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr.internal"); err != nil {
		t.Fatal(err)
	}
	inst, _ := firstInstanceID(db)
	dom := mkDomain(t, db, "user-analyst-alpha", inst, "Corporate", "production")
	if _, err := CreateQRadarLogSourceType("user-analyst-alpha", dom.DomainID, "Microsoft Windows Security Event Log"); err != nil {
		t.Fatal(err)
	}
	keywordRule := `title: Keyword Only
id: 33333333-3333-3333-3333-333333333333
logsource:
  product: windows
  service: security
detection:
  keywords:
    - 'suspicious'
  condition: keywords
level: low
`
	r, err := IngestSigmaRule("user-analyst-alpha", "client-alpha", "", "kw.yml", keywordRule)
	if err != nil {
		t.Fatalf("keyword rule: %v", err)
	}
	if len(r.Fields) != 0 {
		t.Fatalf("expected no extracted fields, got %+v", r.Fields)
	}
	sc, err := AnalyzeDetectionScope("user-analyst-alpha", "client-alpha", r.RuleID)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Status == ReadinessReady {
		t.Fatal("a zero-field rule must not be READY just because a DSM matched")
	}
	if !strings.Contains(strings.Join(sc.Notes, " "), "no extractable fields") {
		t.Fatalf("zero-field limitation must be explained: %+v", sc.Notes)
	}
}

func TestSigma_RegistryFailureFailsClosed(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	r, _ := sigmaScopeFixture(t, db, "client-alpha")
	// Simulate an unreadable registry. The analysis must fail, not report MISSING.
	if _, err := db.Exec(`ALTER TABLE qradar_field_mappings RENAME TO qradar_field_mappings_hidden`); err != nil {
		t.Fatal(err)
	}
	_, err := AnalyzeDetectionScope("user-analyst-alpha", "client-alpha", r.RuleID)
	if !errors.Is(err, ErrFieldAnalysisUnavailable) {
		t.Fatalf("registry read failure must fail closed, got %v", err)
	}
}

func firstInstanceID(db *DB) (string, error) {
	var id string
	err := db.QueryRow(`SELECT instance_id FROM qradar_instances ORDER BY created_at LIMIT 1`).Scan(&id)
	return id, err
}
