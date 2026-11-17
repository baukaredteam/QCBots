package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func openM7CDB(t *testing.T) *DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:?_journal_mode=WAL&_foreign_keys=1")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	mig := []string{
		"migrations/0001_initial.sql",
		"migrations/0002_qradar_inventory.sql",
		"migrations/0003_evidence_graph.sql",
		"migrations/0004_p0_mcp_case.sql",
		"migrations/0005_m6_case_workspace.sql",
		"migrations/0006_cti_ingestion.sql",
		"migrations/0007_case_cti_reports.sql",
		"migrations/0008_relevance.sql",
		"migrations/0009_relevance_eval_time.sql",
	}
	for _, m := range mig {
		if err := runMigration(db, m); err != nil {
			t.Fatalf("migration %s: %v", m, err)
		}
	}
	if err := createM1Tables(db); err != nil {
		t.Fatalf("m1: %v", err)
	}
	if err := seedTestData(db); err != nil {
		t.Fatalf("seed: %v", err)
	}
	gDB := &DB{db}
	globalDB = gDB
	ctiArtifactDir = t.TempDir()
	globalAuditLogger = NewAuditLogger(&DB{db})
	globalCSRFValidator = NewCSRFValidator([]string{"http://localhost:5173"}, false)
	globalConfig = &Config{ServerPort: "8080", Origin: "http://localhost:5173"}
	for _, g := range []struct{ id, uid, cid string }{
		{"m7c-grant-alpha-alpha", "user-analyst-alpha", "client-alpha"},
		{"m7c-grant-beta-beta", "user-analyst-beta", "client-beta"},
	} {
		if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES (?, ?, ?)`, g.id, g.uid, g.cid); err != nil {
			t.Fatalf("grant %s: %v", g.id, err)
		}
	}
	// Fixtures: sector/tech/telemetry/MITRE for alpha.
	if _, err := db.Exec(`INSERT INTO sectors (sector_id, sector_name, created_at) VALUES ('sec-energy','ENERGY',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO client_sector_mapping (client_id, sector_id, created_at) VALUES ('client-alpha','sec-energy',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO log_source_types (log_source_type_id, type_name, created_at) VALUES ('lst-win','Windows',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO client_log_source_status (status_id, client_id, log_source_type_id, connection_status, last_event_timestamp, field_availability, last_checked_at) VALUES ('tls-1','client-alpha','lst-win','CONNECTED',datetime('now'),'host',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO global_fields (field_id, field_name, field_type, is_active, created_at) VALUES ('fld-host','host','text',1,datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO detection_rules (rule_id, rule_name, mitre_techniques, required_log_sources, last_updated) VALUES ('rule-t1059','win-powershell','T1059.001','lst-win',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO rule_field_requirements (requirement_id, rule_id, field_id, is_required, created_at) VALUES ('req-1','rule-t1059','fld-host',1,datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	// Technique for alpha report.
	if _, err := db.Exec(`INSERT INTO techniques (technique_id, report_id, mitre_technique_id, technique_name, created_at) VALUES ('tech-1','report-alpha-1','T1059.001','PowerShell',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	return gDB
}

func TestM7cSameClientAssess(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	a, created, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-1")
	if err != nil {
		t.Fatal(err)
	}
	if !created || a == nil || a.Status != "COMPLETED" {
		t.Fatalf("assess: %+v created=%v", a, created)
	}
	// TELEMETRY MATCH expected (rule + CONNECTED source + field present).
	var verdict string
	_ = db.QueryRow(`SELECT verdict FROM relevance_findings WHERE assessment_id=? AND dimension='TELEMETRY'`, a.AssessmentID).Scan(&verdict)
	if verdict != "MATCH" {
		t.Fatalf("expected TELEMETRY MATCH, got %s (findings=%+v)", verdict, a.Findings)
	}
	// No numeric confidence anywhere in serialized response would be checked via evidence;
	// verdicts must be from enum only.
	for _, f := range a.Findings {
		if f.Verdict != "MATCH" && f.Verdict != "NO_MATCH" && f.Verdict != "UNKNOWN" {
			t.Fatalf("invalid verdict %q", f.Verdict)
		}
	}
}

func TestM7cCrossClientDenied(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	if _, _, err := AssessRelevance("user-analyst-beta", "report-alpha-1", "client-beta", "k"); err == nil {
		t.Fatal("expected cross-client denial")
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM relevance_assessments WHERE report_id='report-alpha-1' AND client_id='client-beta'`).Scan(&n)
	if n != 0 {
		t.Fatalf("cross-client wrote rows: %d", n)
	}
}

func TestM7cUnknownInventoryNeverNoMatch(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	// Beta client has no sector/tech/telemetry fixtures -> all UNKNOWN except maybe telemetry.
	a, _, err := AssessRelevance("user-analyst-beta", "report-beta-1", "client-beta", "k-b")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range a.Findings {
		if f.Dimension == "SECTOR" || f.Dimension == "TECHNOLOGY" {
			if f.Verdict == "NO_MATCH" {
				t.Fatalf("%s must never be NO_MATCH without completeness evidence", f.Dimension)
			}
		}
	}
}

func TestM7cTeleNoClientFieldEvidenceUnknown(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	// Remove required-field evidence: rule has requirement but field inactive.
	if _, err := db.Exec(`UPDATE global_fields SET is_active = 0 WHERE field_id='fld-host'`); err != nil {
		t.Fatal(err)
	}
	a, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-t")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range a.Findings {
		if f.Dimension == "TELEMETRY" && f.Verdict == "MATCH" {
			t.Fatal("global field without client evidence must not MATCH")
		}
	}
}

func TestM7cRepeatedAndConcurrent(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	a1, c1, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-rep")
	if err != nil {
		t.Fatal(err)
	}
	a2, c2, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-rep")
	if err != nil {
		t.Fatal(err)
	}
	if !c1 || c2 || a1.AssessmentID != a2.AssessmentID {
		t.Fatalf("replay: created %v/%v same=%v", c1, c2, a1.AssessmentID == a2.AssessmentID)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM relevance_assessments WHERE client_id='client-alpha' AND request_idempotency_key='k-rep'`).Scan(&n)
	if n != 1 {
		t.Fatalf("expected 1 operation row, got %d", n)
	}
	// Concurrent same key.
	var wg sync.WaitGroup
	var ids [4]string
	var errs [4]error
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			a, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-conc")
			if err != nil {
				errs[idx] = err
				return
			}
			ids[idx] = a.AssessmentID
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("concurrent %d: %v", i, e)
		}
		if ids[i] != ids[0] {
			t.Fatalf("concurrent must converge: %v", ids)
		}
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM relevance_assessments WHERE client_id='client-alpha' AND request_idempotency_key='k-conc'`).Scan(&n)
	if n != 1 {
		t.Fatalf("concurrent: expected 1 operation, got %d", n)
	}
}

func TestM7cFailedRetryNewAttempt(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	// First attempt forced to FAILED via missing report? Instead: assess succeeds,
	// then a FAILED-style attempt with same inputs but new key must create a new row.
	a1, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-f1")
	if err != nil {
		t.Fatal(err)
	}
	a2, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-f2")
	if err != nil {
		t.Fatal(err)
	}
	if a1.AssessmentID == a2.AssessmentID {
		t.Fatal("new key must create new attempt even with identical inputs")
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM relevance_assessments WHERE report_id='report-alpha-1' AND client_id='client-alpha'`).Scan(&n)
	if n != 2 {
		t.Fatalf("expected 2 attempt rows, got %d", n)
	}
}

func TestM7cHistoricalPreservation(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	a1, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-h1")
	if err != nil {
		t.Fatal(err)
	}
	var before int
	_ = db.QueryRow(`SELECT COUNT(*) FROM relevance_findings WHERE assessment_id=?`, a1.AssessmentID).Scan(&before)
	// Change inventory, reassess.
	if _, err := db.Exec(`INSERT INTO sectors (sector_id, sector_name, created_at) VALUES ('sec-fin','FINANCE',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	a2, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-h2")
	if err != nil {
		t.Fatal(err)
	}
	if a2.AssessmentID == a1.AssessmentID {
		t.Fatal("inventory change must produce new assessment")
	}
	var after int
	_ = db.QueryRow(`SELECT COUNT(*) FROM relevance_findings WHERE assessment_id=?`, a1.AssessmentID).Scan(&after)
	if after != before {
		t.Fatalf("historical findings mutated: %d -> %d", before, after)
	}
}

func TestM7cReviewOriginalMismatchRejected(t *testing.T) {
	db2 := openM7CDB(t)
	defer db2.Close()
	a, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-r")
	if err != nil {
		t.Fatal(err)
	}
	// TECHNOLOGY computes UNKNOWN (no malware signal); claiming MATCH must abort.
	if _, err := db2.Exec(`INSERT INTO relevance_reviews (review_id, assessment_id, reviewer_id, dimension, original_verdict, override_verdict, reason, reviewed_at) VALUES ('rv-1', ?, 'user-admin', 'TECHNOLOGY', 'MATCH', 'UNKNOWN', 'x', datetime('now'))`, a.AssessmentID); err == nil {
		t.Fatal("expected trigger to reject mismatched original verdict")
	}
	// Correct original (UNKNOWN) must be accepted.
	if _, err := db2.Exec(`INSERT INTO relevance_reviews (review_id, assessment_id, reviewer_id, dimension, original_verdict, override_verdict, reason, reviewed_at) VALUES ('rv-2', ?, 'user-admin', 'TECHNOLOGY', 'UNKNOWN', 'MATCH', 'analyst override', datetime('now'))`, a.AssessmentID); err != nil {
		t.Fatalf("correct review rejected: %v", err)
	}
}

func m7cReq(t *testing.T, method, target, userID, clientID, body string) *http.Request {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	// Path params.
	switch {
	case strings.Contains(target, "/relevance/") && strings.Contains(target, "/assess"):
		rest := strings.TrimPrefix(target, "/api/v1/cti/reports/")
		r.SetPathValue("report_id", strings.Split(rest, "/")[0])
		r.SetPathValue("client_id", strings.Split(rest, "/")[2])
	case strings.Contains(target, "/relevance/") && strings.Contains(target, "/review"):
		rest := strings.TrimPrefix(target, "/api/v1/cti/reports/")
		r.SetPathValue("report_id", strings.Split(rest, "/")[0])
		r.SetPathValue("client_id", strings.Split(rest, "/")[2])
	case strings.Contains(target, "/relevance/"):
		rest := strings.TrimPrefix(target, "/api/v1/cti/reports/")
		parts := strings.Split(rest, "/")
		if len(parts) >= 1 {
			r.SetPathValue("report_id", parts[0])
		}
		if len(parts) >= 3 {
			r.SetPathValue("client_id", parts[2])
		}
	case strings.Contains(target, "/relevant-reports"):
		r.SetPathValue("client_id", strings.TrimPrefix(target, "/api/v1/clients/"))
	}
	return r.WithContext(context.WithValue(r.Context(), sessionCtxKey, &Session{
		SessionID: "ses-m7c-" + userID,
		UserID:    userID,
		ClientID:  clientID,
	}))
}

func TestM7cHTTPRoutes(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/cti/reports/{report_id}/relevance/{client_id}/assess", applyMiddleware(http.HandlerFunc(handleAssessRelevance), requireAuth, requirePermission(CanViewCTI), requirePermission(CanCreateCTI), auditWrap, csrfWrap))
	mux.HandleFunc("GET /api/v1/cti/reports/{report_id}/relevance/{client_id}", applyMiddleware(http.HandlerFunc(handleGetRelevance), requireAuth, requirePermission(CanViewCTI), auditWrap))
	mux.HandleFunc("GET /api/v1/clients/{client_id}/relevant-reports", applyMiddleware(http.HandlerFunc(handleListRelevantReports), requireAuth, requirePermission(CanViewCTI), auditWrap))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	sess, err := db.CreateSession("user-analyst-alpha", "client-alpha")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	authed := func(method, url string, body string, csrf bool) *http.Response {
		var rdr *strings.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		} else {
			rdr = strings.NewReader("")
		}
		req, _ := http.NewRequest(method, url, rdr)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: sess.SessionID})
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
	{
		req, _ := http.NewRequest("GET", srv.URL+"/api/v1/clients/client-alpha/relevant-reports", nil)
		resp, _ := client.Do(req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauth: %d", resp.StatusCode)
		}
	}
	// Assess 201.
	resp := authed("POST", srv.URL+"/api/v1/cti/reports/report-alpha-1/relevance/client-alpha/assess", `{"idempotency_key":"http-m7c-1"}`, true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("assess: %d", resp.StatusCode)
	}
	// Replay 200.
	resp = authed("POST", srv.URL+"/api/v1/cti/reports/report-alpha-1/relevance/client-alpha/assess", `{"idempotency_key":"http-m7c-1"}`, true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("replay: %d", resp.StatusCode)
	}
	// Cross-client assess -> 403.
	sessB, _ := db.CreateSession("user-analyst-beta", "client-beta")
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/cti/reports/report-alpha-1/relevance/client-beta/assess", strings.NewReader(`{"idempotency_key":"x"}`))
	req.AddCookie(&http.Cookie{Name: "session_id", Value: sessB.SessionID})
	req.Header.Set("Origin", "http://localhost:5173")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "tok-1"})
	req.Header.Set("X-CSRF-Token", "tok-1")
	resp, _ = client.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-client: %d", resp.StatusCode)
	}
	// GET relevance.
	g := authed("GET", srv.URL+"/api/v1/cti/reports/report-alpha-1/relevance/client-alpha", "", false)
	g.Body.Close()
	if g.StatusCode != 200 {
		t.Fatalf("get relevance: %d", g.StatusCode)
	}
	// Relevant reports list.
	l := authed("GET", srv.URL+"/api/v1/clients/client-alpha/relevant-reports", "", false)
	l.Body.Close()
	if l.StatusCode != 200 {
		t.Fatalf("list relevant: %d", l.StatusCode)
	}
}

func TestM7cNoMutationOfM7A(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	var before string
	_ = db.QueryRow(`SELECT status FROM cti_reports WHERE report_id='report-alpha-1'`).Scan(&before)
	var runsBefore, linksBefore int
	_ = db.QueryRow(`SELECT COUNT(*) FROM cti_ingestion_runs`).Scan(&runsBefore)
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_cti_reports`).Scan(&linksBefore)
	if _, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-nomut"); err != nil {
		t.Fatal(err)
	}
	var after string
	var runsAfter, linksAfter int
	_ = db.QueryRow(`SELECT status FROM cti_reports WHERE report_id='report-alpha-1'`).Scan(&after)
	_ = db.QueryRow(`SELECT COUNT(*) FROM cti_ingestion_runs`).Scan(&runsAfter)
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_cti_reports`).Scan(&linksAfter)
	if before != after || runsBefore != runsAfter || linksBefore != linksAfter {
		t.Fatalf("M7-C mutated M7-A/B records: status %q->%q runs %d->%d links %d->%d", before, after, runsBefore, runsAfter, linksBefore, linksAfter)
	}
}

func TestM7cRevokedGrantDenied(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	if _, err := db.Exec(`DELETE FROM user_authorized_clients WHERE user_id='user-analyst-alpha' AND client_id='client-alpha'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-rev"); err == nil {
		t.Fatal("expected denial after grant revoke")
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM relevance_assessments`).Scan(&n)
	if n != 0 {
		t.Fatalf("revoked grant wrote assessments: %d", n)
	}
}

func TestM7cSameKeyDifferentFingerprintConflict(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	if _, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-conf"); err != nil {
		t.Fatal(err)
	}
	// Change client inventory -> fingerprint changes -> same key must 409-equivalent.
	if _, err := db.Exec(`INSERT INTO sectors (sector_id, sector_name, created_at) VALUES ('sec-b','BANKING',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO client_sector_mapping (client_id, sector_id, created_at) VALUES ('client-alpha','sec-b',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-conf"); err == nil {
		t.Fatal("expected idempotency conflict")
	}
}

func TestM7cDirectSQLTenantMismatchRejected(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	if err := ensureRelevanceRules(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO relevance_assessments (assessment_id, report_id, client_id, status, cti_evidence_snapshot, inventory_snapshot, rule_set_fingerprint, matching_rule_version, created_at)
		VALUES ('a-x','report-alpha-1','client-beta','PENDING','s','s','s','1',datetime('now'))`); err == nil {
		t.Fatal("expected tenant mismatch trigger abort")
	}
}

func TestM7cMissingTelemetryUnknownNeverNoMatch(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	if _, err := db.Exec(`DELETE FROM client_log_source_status WHERE client_id='client-alpha'`); err != nil {
		t.Fatal(err)
	}
	a, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-mt")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range a.Findings {
		if f.Dimension == "TELEMETRY" && f.Verdict == "NO_MATCH" {
			t.Fatal("missing telemetry must never be NO_MATCH")
		}
		if f.Dimension == "TELEMETRY" && f.Verdict != "UNKNOWN" {
			t.Fatalf("missing telemetry expected UNKNOWN, got %s", f.Verdict)
		}
	}
}

func TestM7cAlternativeObservableRuleOverridesUnavailable(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	// Second candidate rule whose source is NOT_CONNECTED.
	if _, err := db.Exec(`INSERT INTO log_source_types (log_source_type_id, type_name, created_at) VALUES ('lst-lin','Linux',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO client_log_source_status (status_id, client_id, log_source_type_id, connection_status, last_event_timestamp, last_checked_at) VALUES ('tls-2','client-alpha','lst-lin','NOT_CONNECTED',datetime('now'),datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO detection_rules (rule_id, rule_name, mitre_techniques, required_log_sources, last_updated) VALUES ('rule-alt','alt-rule','T1059.001','lst-lin',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	a, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-alt")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range a.Findings {
		if f.Dimension == "TELEMETRY" {
			if f.Verdict != "MATCH" {
				t.Fatalf("expected MATCH via observable rule, got %s", f.Verdict)
			}
			foundObs := false
			for _, e := range f.Evidence {
				if e.MatchedEntityID == "rule-t1059" {
					foundObs = true
				}
			}
			if !foundObs {
				t.Fatalf("observable rule evidence missing: %+v", f.Evidence)
			}
		}
	}
}

func TestM7cNoDeployedOrValidatedLanguage(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	a, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-lang")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range a.Findings {
		low := strings.ToLower(f.Explanation + " " + strings.Join(f.Limitations, " "))
		if strings.Contains(low, "deployed") || strings.Contains(low, "validated") {
			t.Fatalf("finding must not claim deployment/validation: %s", f.Explanation)
		}
	}
	b, _ := json.Marshal(a)
	low := strings.ToLower(string(b))
	if strings.Contains(low, "\"score\"") || strings.Contains(low, "\"confidence\":") {
		t.Fatalf("no numeric scores/confidence allowed: %s", string(b))
	}
}

func TestM7cTwoRulesSameEntityBothRetained(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	a, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-two")
	if err != nil {
		t.Fatal(err)
	}
	// Same SECTOR finding, same entity, different rule -> both rows retained.
	var fid string
	_ = db.QueryRow(`SELECT finding_id FROM relevance_findings WHERE assessment_id=? AND dimension='SECTOR'`, a.AssessmentID).Scan(&fid)
	if fid == "" {
		t.Fatal("no SECTOR finding")
	}
	// Need a second rule row of dimension SECTOR.
	if _, err := db.Exec(`INSERT OR IGNORE INTO relevance_matching_rules (rule_id, rule_version, dimension, rule_name, rule_definition, created_at) VALUES ('rule-sector-v2','1','SECTOR','sector-token-2','{}',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO relevance_evidence (evidence_id, finding_id, assessment_id, report_id, client_id, dimension, matched_entity_type, matched_entity_id, matching_rule_id, matching_rule_version, created_at)
		VALUES ('ev-2',?,?,'report-alpha-1','client-alpha','SECTOR','sector','ENERGY','rule-sector-v2','1',datetime('now'))`, fid, a.AssessmentID); err != nil {
		t.Fatalf("second rule evidence must be accepted: %v", err)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM relevance_evidence WHERE finding_id=? AND matched_entity_id='ENERGY' AND matched_entity_type='sector'`, fid).Scan(&n)
	if n != 2 {
		t.Fatalf("expected 2 provenance rows, got %d", n)
	}
}

func TestM7cCrossAssessmentEvidenceRejected(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	a, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-x1")
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-x2")
	if err != nil {
		t.Fatal(err)
	}
	var fidA, fidB string
	_ = db.QueryRow(`SELECT finding_id FROM relevance_findings WHERE assessment_id=? AND dimension='SECTOR'`, a.AssessmentID).Scan(&fidA)
	_ = db.QueryRow(`SELECT finding_id FROM relevance_findings WHERE assessment_id=? AND dimension='SECTOR'`, b.AssessmentID).Scan(&fidB)
	_ = fidB
	// Finding of A claimed under assessment B -> must abort.
	if _, err := db.Exec(`INSERT INTO relevance_evidence (evidence_id, finding_id, assessment_id, report_id, client_id, dimension, matched_entity_type, matched_entity_id, matching_rule_id, matching_rule_version, created_at)
		VALUES ('ev-x',?,?,'report-alpha-1','client-alpha','SECTOR','sector','ENERGY','rule-sector-v1','1',datetime('now'))`, fidA, b.AssessmentID); err == nil {
		t.Fatal("expected cross-assessment evidence rejection")
	}
}

func TestM7cRuleSetChangeNewSnapshotAndAssessment(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	a1, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-rs1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO relevance_matching_rules (rule_id, rule_version, dimension, rule_name, rule_definition, created_at) VALUES ('rule-extra','1','SECTOR','extra','{}',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	a2, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-rs2")
	if err != nil {
		t.Fatal(err)
	}
	if a2.AssessmentID == a1.AssessmentID {
		t.Fatal("rule change must create new assessment")
	}
	if a2.RuleSetFingerprint == a1.RuleSetFingerprint {
		t.Fatalf("rule fingerprint must differ: %s vs %s", a1.RuleSetFingerprint, a2.RuleSetFingerprint)
	}
	// Old assessment still loadable.
	loaded, err := GetRelevanceAssessment(a1.AssessmentID)
	if err != nil || loaded.AssessmentID != a1.AssessmentID {
		t.Fatalf("historical assessment lost: %v", err)
	}
}

func TestM7cSnapshotDocumentsReconstructable(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	a1, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-sd1")
	if err != nil {
		t.Fatal(err)
	}
	if a1.CTIEvidenceDocument == "" || a1.InventoryDocument == "" {
		t.Fatalf("snapshot documents missing: %+v", a1)
	}
	if _, err := db.Exec(`INSERT INTO sectors (sector_id, sector_name, created_at) VALUES ('sec-z','ZULU',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO client_sector_mapping (client_id, sector_id, created_at) VALUES ('client-alpha','sec-z',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	a2, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-sd2")
	if err != nil {
		t.Fatal(err)
	}
	if a1.InventorySnapshot == a2.InventorySnapshot {
		t.Fatal("inventory snapshot must change after source change")
	}
	reloaded, err := GetRelevanceAssessment(a1.AssessmentID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.InventorySnapshot != a1.InventorySnapshot || reloaded.InventoryDocument != a1.InventoryDocument {
		t.Fatal("historical snapshot not reconstructable")
	}
	if !strings.Contains(reloaded.InventoryDocument, "sec-energy") {
		t.Fatal("stored inventory document must contain original rows")
	}
}

func TestM7cParserEvidenceChangeNewCTISnapshot(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	a1, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-cti1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO indicators (indicator_id, report_id, indicator_type, indicator_value, created_at) VALUES ('ind-new','report-alpha-1','domain','evil.example',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	a2, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-cti2")
	if err != nil {
		t.Fatal(err)
	}
	if a1.CTIEvidenceSnapshot == a2.CTIEvidenceSnapshot {
		t.Fatal("CTI snapshot must change after parser evidence change")
	}
}

func TestM7cDimensionsIndependent(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	a, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-ind")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Findings) != 3 {
		t.Fatalf("expected 3 dimension findings, got %d", len(a.Findings))
	}
	seen := map[string]bool{}
	for _, f := range a.Findings {
		seen[f.Dimension] = true
		if f.Verdict != "MATCH" && f.Verdict != "NO_MATCH" && f.Verdict != "UNKNOWN" {
			t.Fatalf("bad verdict %q", f.Verdict)
		}
	}
	if !seen["SECTOR"] || !seen["TECHNOLOGY"] || !seen["TELEMETRY"] {
		t.Fatalf("missing dimensions: %+v", a.Findings)
	}
	// SECTOR/TECHNOLOGY never NO_MATCH in v1 (C21).
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM relevance_findings WHERE assessment_id=? AND dimension IN ('SECTOR','TECHNOLOGY') AND verdict='NO_MATCH'`, a.AssessmentID).Scan(&n)
	if n != 0 {
		t.Fatalf("SECTOR/TECHNOLOGY NO_MATCH forbidden in v1: %d", n)
	}
}

func TestM7cFailedAssessmentShape(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	if err := ensureRelevanceRules(); err != nil {
		t.Fatal(err)
	}
	// Simulate a FAILED attempt row directly (compute-error path equivalent).
	if _, err := db.Exec(`INSERT INTO relevance_assessments (assessment_id, report_id, client_id, status, error_code, cti_evidence_snapshot, inventory_snapshot, rule_set_fingerprint, matching_rule_version, created_at)
		VALUES ('a-failed','report-alpha-1','client-alpha','FAILED','compute_error','s','s','s','1',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	a, err := GetRelevanceAssessment("a-failed")
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != "FAILED" || len(a.Findings) != 0 {
		t.Fatalf("FAILED shape wrong: %+v", a)
	}
	// Failed attempt preserved; retry with same inputs creates new attempt (C9b).
	b, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-after-fail")
	if err != nil {
		t.Fatal(err)
	}
	if b.AssessmentID == "a-failed" {
		t.Fatal("retry must be a new attempt")
	}
}

func TestM7cLegacyReportUnknownTele(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	// Legacy report: no techniques/malware rows.
	a, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-2", "client-alpha", "k-legacy")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range a.Findings {
		if f.Dimension == "TELEMETRY" && f.Verdict == "MATCH" {
			t.Fatal("legacy report without TTPs must not MATCH")
		}
	}
}

func TestM7cReviewUnauthorizedAnalyst(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/cti/reports/{report_id}/relevance/{client_id}/review", applyMiddleware(http.HandlerFunc(handleReviewRelevance), requireAuth, requirePermission(CanViewCTI), auditWrap, csrfWrap))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	sess, err := db.CreateSession("user-analyst-alpha", "client-alpha")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/cti/reports/report-alpha-1/relevance/client-alpha/review", strings.NewReader(`{"assessment_id":"a","dimension":"SECTOR","original_verdict":"UNKNOWN","override_verdict":"MATCH","reason":"x"}`))
	req.AddCookie(&http.Cookie{Name: "session_id", Value: sess.SessionID})
	req.Header.Set("Origin", "http://localhost:5173")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "tok-1"})
	req.Header.Set("X-CSRF-Token", "tok-1")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("CTI_ANALYST review must be 403, got %d", resp.StatusCode)
	}
}

func TestM7cTeleNoClientFieldEvidenceUnknown2(t *testing.T) {
	// CONNECTED + fresh events + ACTIVE global field, but no client field
	// evidence (field_availability empty) => UNKNOWN, never MATCH/NO_MATCH.
	db := openM7CDB(t)
	defer db.Close()
	if _, err := db.Exec(`UPDATE client_log_source_status SET field_availability = NULL WHERE status_id='tls-1'`); err != nil {
		t.Fatal(err)
	}
	a, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-nofieldev")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range a.Findings {
		if f.Dimension == "TELEMETRY" && f.Verdict != "UNKNOWN" {
			t.Fatalf("no client field evidence must be UNKNOWN, got %s", f.Verdict)
		}
	}
	// Positive control: field names the required field => MATCH with client proof.
	if _, err := db.Exec(`UPDATE client_log_source_status SET field_availability = 'host' WHERE status_id='tls-1'`); err != nil {
		t.Fatal(err)
	}
	b, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-fieldev")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range b.Findings {
		if f.Dimension == "TELEMETRY" {
			if f.Verdict != "MATCH" {
				t.Fatalf("verified client fields must MATCH, got %s", f.Verdict)
			}
			foundProof := false
			for _, e := range f.Evidence {
				if strings.Contains(e.InventoryEvidence, "client-alpha") && strings.Contains(e.InventoryEvidence, "host") {
					foundProof = true
				}
			}
			if !foundProof {
				t.Fatalf("MATCH evidence must carry client-owned proof: %+v", f.Evidence)
			}
		}
	}
}

func TestM7cTeleStaleValidationUnknown(t *testing.T) {
	// last_checked_at older than 7 days => verification untrusted => UNKNOWN.
	db := openM7CDB(t)
	defer db.Close()
	if _, err := db.Exec(`UPDATE client_log_source_status SET last_checked_at = '2024-01-01 00:00:00' WHERE status_id='tls-1'`); err != nil {
		t.Fatal(err)
	}
	a, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-stale")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range a.Findings {
		if f.Dimension == "TELEMETRY" && f.Verdict != "UNKNOWN" {
			t.Fatalf("stale validation must be UNKNOWN, got %s", f.Verdict)
		}
	}
}

func TestM7cGenuineFailureLifecycle(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	var repBefore, runsBefore, linksBefore int
	_ = db.QueryRow(`SELECT COUNT(*) FROM cti_reports WHERE report_id='report-alpha-1' AND status='INGESTED'`).Scan(&repBefore)
	_ = db.QueryRow(`SELECT COUNT(*) FROM cti_ingestion_runs`).Scan(&runsBefore)
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_cti_reports`).Scan(&linksBefore)
	// Genuine persistence failure: abort every findings insert.
	if _, err := db.Exec(`CREATE TRIGGER trg_inject_fail_findings BEFORE INSERT ON relevance_findings BEGIN SELECT RAISE(ABORT, 'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	a, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-failgenuine")
	if err != nil {
		t.Fatalf("FAILED attempt must be returned, not error: %v", err)
	}
	if a.Status != "FAILED" || a.ErrorCode == "" {
		t.Fatalf("expected FAILED with error_code, got %+v", a)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM relevance_findings WHERE assessment_id=?`, a.AssessmentID).Scan(&n)
	if n != 0 {
		t.Fatalf("FAILED attempt must have zero findings, got %d", n)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM relevance_assessments WHERE report_id='report-alpha-1' AND client_id='client-alpha' AND status='FAILED'`).Scan(&n)
	if n != 1 {
		t.Fatalf("expected 1 FAILED row persisted, got %d", n)
	}
	// Original report / M7-A / M7-B untouched.
	var repAfter, runsAfter, linksAfter int
	_ = db.QueryRow(`SELECT COUNT(*) FROM cti_reports WHERE report_id='report-alpha-1' AND status='INGESTED'`).Scan(&repAfter)
	_ = db.QueryRow(`SELECT COUNT(*) FROM cti_ingestion_runs`).Scan(&runsAfter)
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_cti_reports`).Scan(&linksAfter)
	if repBefore != repAfter || runsBefore != runsAfter || linksBefore != linksAfter {
		t.Fatal("failure must not mutate report or M7-A/B records")
	}
	// Retry with a new key -> distinct attempt; FAILED row preserved.
	if _, err := db.Exec(`DROP TRIGGER trg_inject_fail_findings`); err != nil {
		t.Fatal(err)
	}
	b, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-retry")
	if err != nil {
		t.Fatal(err)
	}
	if b.AssessmentID == a.AssessmentID || b.Status != "COMPLETED" {
		t.Fatalf("retry must be a NEW completed attempt: %+v", b)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM relevance_assessments WHERE report_id='report-alpha-1' AND client_id='client-alpha' AND status='FAILED'`).Scan(&n)
	if n != 1 {
		t.Fatalf("FAILED attempt must be preserved, got %d", n)
	}
}

func TestM7cSnapshotHashMatchesDocuments(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	a, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-hash")
	if err != nil {
		t.Fatal(err)
	}
	hash := func(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
	if hash(a.CTIEvidenceDocument) != a.CTIEvidenceSnapshot {
		t.Fatal("CTI document hash mismatch")
	}
	if hash(a.InventoryDocument) != a.InventorySnapshot {
		t.Fatal("inventory document hash mismatch")
	}
}

func TestM7cHistoricalByteIdentical(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	a1, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-byte1")
	if err != nil {
		t.Fatal(err)
	}
	var ctiBefore, invBefore string
	_ = db.QueryRow(`SELECT cti_evidence_document, inventory_document FROM relevance_snapshots WHERE assessment_id=?`, a1.AssessmentID).Scan(&ctiBefore, &invBefore)
	if _, err := db.Exec(`INSERT INTO sectors (sector_id, sector_name, created_at) VALUES ('sec-c','CLINIC',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO client_sector_mapping (client_id, sector_id, created_at) VALUES ('client-alpha','sec-c',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-byte2"); err != nil {
		t.Fatal(err)
	}
	var ctiAfter, invAfter string
	_ = db.QueryRow(`SELECT cti_evidence_document, inventory_document FROM relevance_snapshots WHERE assessment_id=?`, a1.AssessmentID).Scan(&ctiAfter, &invAfter)
	if ctiBefore != ctiAfter || invBefore != invAfter {
		t.Fatal("historical documents must be byte-identical after inventory change")
	}
}

func TestM7cReviewSecurityHTTP(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	// REVIEWER grant for client-alpha (fresh assessments below).
	if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES ('m7c-grant-rev-alpha','user-reviewer','client-alpha')`); err != nil {
		t.Fatal(err)
	}
	assessBody := `{"idempotency_key":"sec-k1"}`
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/cti/reports/{report_id}/relevance/{client_id}/assess", applyMiddleware(http.HandlerFunc(handleAssessRelevance), requireAuth, requirePermission(CanViewCTI), requirePermission(CanCreateCTI), auditWrap, csrfWrap))
	mux.HandleFunc("POST /api/v1/cti/reports/{report_id}/relevance/{client_id}/review", applyMiddleware(http.HandlerFunc(handleReviewRelevance), requireAuth, requirePermission(CanViewCTI), auditWrap, csrfWrap))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := &http.Client{Timeout: 15 * time.Second}
	post := func(user, url, body string, csrf bool) int {
		sess, _ := db.CreateSession(user, "client-alpha")
		req, _ := http.NewRequest("POST", srv.URL+url, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "session_id", Value: sess.SessionID})
		if csrf {
			req.Header.Set("Origin", "http://localhost:5173")
			req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "tok-1"})
			req.Header.Set("X-CSRF-Token", "tok-1")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// 401 unauthenticated.
	{
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/cti/reports/report-alpha-1/relevance/client-alpha/assess", strings.NewReader(assessBody))
		resp, _ := client.Do(req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauth: %d", resp.StatusCode)
		}
	}
	// 403 missing CSRF.
	if code := post("user-analyst-alpha", "/api/v1/cti/reports/report-alpha-1/relevance/client-alpha/assess", assessBody, false); code != http.StatusForbidden {
		t.Fatalf("missing CSRF must be 403, got %d", code)
	}
	// Good assess.
	if code := post("user-analyst-alpha", "/api/v1/cti/reports/report-alpha-1/relevance/client-alpha/assess", `{"idempotency_key":"sec-k2"}`, true); code != http.StatusCreated {
		t.Fatalf("assess: %d", code)
	}
	a, err := LatestCompletedAssessment("report-alpha-1", "client-alpha")
	if err != nil {
		t.Fatal(err)
	}
	// TECHNOLOGY computes UNKNOWN in this fixture.
	reviewOK := `{"assessment_id":"` + a.AssessmentID + `","dimension":"TECHNOLOGY","original_verdict":"UNKNOWN","override_verdict":"MATCH","reason":"analyst","extra":0}`
	reviewMismatch := `{"assessment_id":"` + a.AssessmentID + `","dimension":"TECHNOLOGY","original_verdict":"MATCH","override_verdict":"MATCH","reason":"x"}`
	// 403: CTI_ANALYST without review permission.
	if code := post("user-analyst-alpha", "/api/v1/cti/reports/report-alpha-1/relevance/client-alpha/review", reviewOK, true); code != http.StatusForbidden {
		t.Fatalf("analyst review must be 403, got %d", code)
	}
	// 403: missing CSRF even for reviewer.
	if code := post("user-reviewer", "/api/v1/cti/reports/report-alpha-1/relevance/client-alpha/review", reviewOK, false); code != http.StatusForbidden {
		t.Fatalf("review missing CSRF must be 403, got %d", code)
	}
	// Authorized: REVIEWER with grant, matching path/report/client.
	if code := post("user-reviewer", "/api/v1/cti/reports/report-alpha-1/relevance/client-alpha/review", reviewOK, true); code != http.StatusCreated {
		t.Fatalf("reviewer+grant review must be 201, got %d", code)
	}
	// 403: REVIEWER without grant for client-beta.
	if _, err := db.Exec(`DELETE FROM user_authorized_clients WHERE user_id='user-reviewer' AND client_id='client-beta'`); err != nil {
		t.Fatal(err)
	}
	if code := post("user-reviewer", "/api/v1/cti/reports/report-beta-1/relevance/client-beta/review", reviewOK, true); code != http.StatusForbidden {
		t.Fatalf("reviewer without grant must be 403, got %d", code)
	}
	// 403: foreign assessment via mismatched path (alpha assessment, beta path).
	if code := post("user-reviewer", "/api/v1/cti/reports/report-alpha-1/relevance/client-beta/review", reviewOK, true); code != http.StatusForbidden {
		t.Fatalf("foreign path combo must be 403, got %d", code)
	}
	// 422: original_verdict mismatch rejected by DB trigger (HTTP).
	if code := post("user-reviewer", "/api/v1/cti/reports/report-alpha-1/relevance/client-alpha/review", reviewMismatch, true); code != http.StatusUnprocessableEntity {
		t.Fatalf("mismatch must be 422, got %d", code)
	}
	// 404: unknown assessment_id.
	unknownA := `{"assessment_id":"assessment-nope","dimension":"SECTOR","original_verdict":"UNKNOWN","override_verdict":"MATCH","reason":"x"}`
	if code := post("user-reviewer", "/api/v1/cti/reports/report-alpha-1/relevance/client-alpha/review", unknownA, true); code != http.StatusNotFound {
		t.Fatalf("unknown assessment must be 404, got %d", code)
	}
}

func TestM7cConcurrentFullResponse(t *testing.T) {
	db := openM7CDB(t)
	defer db.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/cti/reports/{report_id}/relevance/{client_id}/assess", applyMiddleware(http.HandlerFunc(handleAssessRelevance), requireAuth, requirePermission(CanViewCTI), requirePermission(CanCreateCTI), auditWrap, csrfWrap))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	sess, _ := db.CreateSession("user-analyst-alpha", "client-alpha")
	client := &http.Client{Timeout: 15 * time.Second}
	var wg sync.WaitGroup
	codes := make([]int, 4)
	ids := make([]string, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req, _ := http.NewRequest("POST", srv.URL+"/api/v1/cti/reports/report-alpha-1/relevance/client-alpha/assess", strings.NewReader(`{"idempotency_key":"conc-full"}`))
			req.AddCookie(&http.Cookie{Name: "session_id", Value: sess.SessionID})
			req.Header.Set("Origin", "http://localhost:5173")
			req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "tok-1"})
			req.Header.Set("X-CSRF-Token", "tok-1")
			resp, err := client.Do(req)
			if err != nil {
				codes[idx] = -1
				return
			}
			defer resp.Body.Close()
			codes[idx] = resp.StatusCode
			var body map[string]interface{}
			_ = json.NewDecoder(resp.Body).Decode(&body)
			assess := body["assessment"].(map[string]interface{})
			ids[idx], _ = assess["assessment_id"].(string)
			// Full response: all 3 findings present.
			if findings, ok := assess["findings"].([]interface{}); !ok || len(findings) != 3 {
				t.Errorf("response must contain 3 findings, got %v", findings)
			}
		}(i)
	}
	wg.Wait()
	same := ids[0] != ""
	for _, id := range ids {
		if id != ids[0] {
			same = false
		}
	}
	if !same {
		t.Fatalf("concurrent responses must converge on one assessment_id, got %v", ids)
	}
	for i, c := range codes {
		if c != http.StatusCreated && c != http.StatusOK {
			t.Fatalf("concurrent %d: unexpected code %d", i, c)
		}
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM relevance_assessments WHERE client_id='client-alpha' AND request_idempotency_key='conc-full'`).Scan(&n)
	if n != 1 {
		t.Fatalf("expected 1 assessment row, got %d", n)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM relevance_findings WHERE assessment_id=?`, ids[0]).Scan(&n)
	if n != 3 {
		t.Fatalf("expected 3 findings, got %d", n)
	}
}

func TestM7cThirdFindingAtomicity(t *testing.T) {
	// Fail on the THIRD finding insert (TELEMETRY), after SECTOR+TECHNOLOGY
	// succeeded: savepoint rollback must erase ALL findings/evidence.
	db := openM7CDB(t)
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER trg_inject_fail_third BEFORE INSERT ON relevance_findings WHEN NEW.dimension = 'TELEMETRY' BEGIN SELECT RAISE(ABORT, 'injected third failure'); END`); err != nil {
		t.Fatal(err)
	}
	a, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-atomic")
	if err != nil {
		t.Fatalf("FAILED attempt must be returned, not error: %v", err)
	}
	if a.Status != "FAILED" || a.ErrorCode != "persist_error" {
		t.Fatalf("expected FAILED persist_error, got %+v", a)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM relevance_findings WHERE assessment_id=?`, a.AssessmentID).Scan(&n)
	if n != 0 {
		t.Fatalf("expected ZERO findings after atomic rollback, got %d", n)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM relevance_evidence WHERE assessment_id=?`, a.AssessmentID).Scan(&n)
	if n != 0 {
		t.Fatalf("expected ZERO evidence after atomic rollback, got %d", n)
	}
	// Assessment FAILED row persisted, snapshots retained.
	_ = db.QueryRow(`SELECT COUNT(*) FROM relevance_assessments WHERE assessment_id=? AND status='FAILED' AND error_code='persist_error'`, a.AssessmentID).Scan(&n)
	if n != 1 {
		t.Fatalf("FAILED row not persisted: %d", n)
	}
	var ctiDoc, invDoc, ruleDoc string
	_ = db.QueryRow(`SELECT cti_evidence_document, inventory_document, rule_set_document FROM relevance_snapshots WHERE assessment_id=?`, a.AssessmentID).Scan(&ctiDoc, &invDoc, &ruleDoc)
	if ctiDoc == "" || invDoc == "" || ruleDoc == "" {
		t.Fatal("snapshots must be retained on FAILED attempts")
	}
	// New-key retry succeeds after the fault is removed.
	if _, err := db.Exec(`DROP TRIGGER trg_inject_fail_third`); err != nil {
		t.Fatal(err)
	}
	b, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-atomic-retry")
	if err != nil {
		t.Fatal(err)
	}
	if b.AssessmentID == a.AssessmentID || b.Status != "COMPLETED" {
		t.Fatalf("retry must be a NEW completed attempt: %+v", b)
	}
}

func TestM7cPartialFieldNameNeverMatches(t *testing.T) {
	// 'hostname' must NOT satisfy required field 'host' (exact tokens only).
	db := openM7CDB(t)
	defer db.Close()
	if _, err := db.Exec(`UPDATE client_log_source_status SET field_availability = 'hostname' WHERE status_id='tls-1'`); err != nil {
		t.Fatal(err)
	}
	a, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-partial")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range a.Findings {
		if f.Dimension == "TELEMETRY" && f.Verdict != "UNKNOWN" {
			t.Fatalf("partial field name must not MATCH, got %s", f.Verdict)
		}
	}
	// Exact token among several still works.
	if _, err := db.Exec(`UPDATE client_log_source_status SET field_availability = 'host,user' WHERE status_id='tls-1'`); err != nil {
		t.Fatal(err)
	}
	b, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range b.Findings {
		if f.Dimension == "TELEMETRY" && f.Verdict == "MATCH" {
			return
		}
	}
	t.Fatalf("exact token in list must MATCH: %+v", b.Findings)
}

func TestM7cInputChangeConflicts(t *testing.T) {
	// Every decision input must feed the fingerprints: with an unchanged
	// idempotency key, any single-input change -> conflict (409-equivalent);
	// a new key -> new assessment; history snapshots byte-identical.
	mutations := []struct {
		name string
		fn   func(db *DB) error
	}{
		{"malware family", func(db *DB) error {
			_, err := db.Exec(`INSERT INTO malware (malware_id, report_id, malware_name, family, type, created_at) VALUES ('mal-x','report-alpha-1','EvilX','FAMILYX','RAT',datetime('now'))`)
			return err
		}},
		{"detection rule mitre", func(db *DB) error {
			_, err := db.Exec(`UPDATE detection_rules SET mitre_techniques = 'T1059.001,T1003' WHERE rule_id='rule-t1059'`)
			return err
		}},
		{"detection rule sources", func(db *DB) error {
			_, err := db.Exec(`UPDATE detection_rules SET required_log_sources = 'lst-win,lst-other' WHERE rule_id='rule-t1059'`)
			return err
		}},
		{"field requirement", func(db *DB) error {
			_, err := db.Exec(`INSERT INTO rule_field_requirements (requirement_id, rule_id, field_id, is_required, created_at) VALUES ('req-extra','rule-t1059','fld-host',0,datetime('now'))`)
			return err
		}},
		{"global field inactive", func(db *DB) error {
			_, err := db.Exec(`UPDATE global_fields SET is_active = 0 WHERE field_id='fld-host'`)
			return err
		}},
		{"field_availability", func(db *DB) error {
			_, err := db.Exec(`UPDATE client_log_source_status SET field_availability = 'host,user' WHERE status_id='tls-1'`)
			return err
		}},
		{"sector mapping", func(db *DB) error {
			if _, err := db.Exec(`INSERT INTO sectors (sector_id, sector_name, created_at) VALUES ('sec-c','CLINIC',datetime('now'))`); err != nil {
				return err
			}
			_, err := db.Exec(`INSERT INTO client_sector_mapping (client_id, sector_id, created_at) VALUES ('client-alpha','sec-c',datetime('now'))`)
			return err
		}},
		{"client technology", func(db *DB) error {
			_, err := db.Exec(`INSERT INTO client_technologies (tech_id, client_id, technology_name, created_at) VALUES ('tech-x','client-alpha','Windows',datetime('now'))`)
			return err
		}},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			db := openM7CDB(t)
			defer db.Close()
			a1, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-input")
			if err != nil {
				t.Fatal(err)
			}
			var ctiBefore, invBefore string
			_ = db.QueryRow(`SELECT cti_evidence_document, inventory_document FROM relevance_snapshots WHERE assessment_id=?`, a1.AssessmentID).Scan(&ctiBefore, &invBefore)
			if err := m.fn(db); err != nil {
				t.Fatal(err)
			}
			// Same key + changed fingerprint -> conflict.
			if _, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-input"); err == nil {
				t.Fatalf("%s: expected idempotency conflict on changed input", m.name)
			}
			// New key -> new assessment.
			a2, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-input-2")
			if err != nil {
				t.Fatal(err)
			}
			if a2.AssessmentID == a1.AssessmentID {
				t.Fatalf("%s: new key must create new assessment", m.name)
			}
			// History byte-identical.
			var ctiAfter, invAfter string
			_ = db.QueryRow(`SELECT cti_evidence_document, inventory_document FROM relevance_snapshots WHERE assessment_id=?`, a1.AssessmentID).Scan(&ctiAfter, &invAfter)
			if ctiBefore != ctiAfter || invBefore != invAfter {
				t.Fatalf("%s: historical snapshots mutated", m.name)
			}
		})
	}
}

func TestM7cTitleChangeConflicts(t *testing.T) {
	// Title feeds SECTOR matching, so it must be in the CTI snapshot:
	// same key after a title change -> conflict; new key -> new assessment;
	// historical canonical snapshot byte-identical.
	db := openM7CDB(t)
	defer db.Close()
	a1, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-title")
	if err != nil {
		t.Fatal(err)
	}
	var ctiBefore string
	_ = db.QueryRow(`SELECT cti_evidence_document FROM relevance_snapshots WHERE assessment_id=?`, a1.AssessmentID).Scan(&ctiBefore)
	if !strings.Contains(ctiBefore, "title") {
		t.Fatalf("CTI snapshot document must include report title: %s", ctiBefore)
	}
	if _, err := db.Exec(`UPDATE cti_reports SET title = 'Changed Title XYZ' WHERE report_id='report-alpha-1'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-title"); err == nil {
		t.Fatal("expected idempotency conflict after title change")
	}
	a2, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-title-2")
	if err != nil {
		t.Fatal(err)
	}
	if a2.AssessmentID == a1.AssessmentID {
		t.Fatal("new key must create new assessment")
	}
	var ctiAfter string
	_ = db.QueryRow(`SELECT cti_evidence_document FROM relevance_snapshots WHERE assessment_id=?`, a1.AssessmentID).Scan(&ctiAfter)
	if ctiBefore != ctiAfter {
		t.Fatal("historical CTI snapshot must remain byte-identical")
	}
}

func TestM7cEvaluationTimePersisted(t *testing.T) {
	// The pinned evaluation reference time is persisted and exposed, so
	// historical staleness is never reinterpreted with today's clock.
	db := openM7CDB(t)
	defer db.Close()
	before := time.Now().UTC()
	a, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-evaltime")
	if err != nil {
		t.Fatal(err)
	}
	if a.EvaluationAt == "" {
		t.Fatal("evaluation_at must be persisted")
	}
	parsed, err := time.Parse(time.RFC3339, a.EvaluationAt)
	if err != nil {
		t.Fatalf("evaluation_at must be RFC3339: %v", err)
	}
	if parsed.Before(before.Add(-2 * time.Minute)) || parsed.After(time.Now().UTC().Add(2*time.Minute)) {
		t.Fatalf("evaluation_at out of range: %s", a.EvaluationAt)
	}
	// A second attempt never mutates the first one's reference time.
	b, _, err := AssessRelevance("user-analyst-alpha", "report-alpha-1", "client-alpha", "k-evaltime-2")
	if err != nil {
		t.Fatal(err)
	}
	if b.AssessmentID == a.AssessmentID {
		t.Fatal("new key must create new attempt")
	}
	reloaded, err := GetRelevanceAssessment(a.AssessmentID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.EvaluationAt != a.EvaluationAt {
		t.Fatalf("historical evaluation_at mutated: %q -> %q", a.EvaluationAt, reloaded.EvaluationAt)
	}
}

var _ = time.Now
