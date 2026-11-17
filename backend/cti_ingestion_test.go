package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type IngestFixture struct {
	T       *testing.T
	DB      *DB
	Session *Session
}

func openM7DB(t *testing.T) *DB {
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
	// Seed client grants for test users (synthetic, explicit).
	for _, g := range []struct{ id, uid, cid string }{
		{"m7-grant-alpha-alpha", "user-analyst-alpha", "client-alpha"},
		{"m7-grant-beta-beta", "user-analyst-beta", "client-beta"},
	} {
		if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES (?, ?, ?)`, g.id, g.uid, g.cid); err != nil {
			t.Fatalf("grant %s: %v", g.id, err)
		}
	}
	return gDB
}

// A1: Same file + NULL source (via direct report path) -> one report.
func TestM7aSameFileNullSourceDedup(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	r1, err := db.CreateCTIReport("client-alpha", "", "t", "a", "", "ref1", "ck1")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := db.CreateCTIReport("client-alpha", "", "t", "a", "", "ref1", "ck1")
	if err != nil {
		t.Fatal(err)
	}
	if r1 != r2 {
		t.Errorf("expected dedup reuse, got %s vs %s (unique index missing?)", r1, r2)
	}
}

// A3: Same content, different client -> distinct documents.
func TestM7aTwoClientsDistinct(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	sid, err := db.CreateCTISource("srcx", "file", "C")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := db.CreateCTIReport("client-alpha", sid, "t", "a", "", "r", "ck")
	b, _ := db.CreateCTIReport("client-beta", sid, "t", "a", "", "r", "ck")
	if a == b {
		t.Errorf("expected distinct documents per tenant, got %s", a)
	}
}

// Direct check of the unique index presence.
func TestM7aDedupIndexesExist(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	for _, name := range []string{"idx_cti_reports_dedup_src", "idx_cti_reports_dedup_nosrc", "idx_cti_runs_request_unique", "idx_cti_extraction_results_report"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Errorf("index %s missing", name)
		}
	}
	// Idempotency indexes implicitly enforce per-client scoping.
	var txt string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_cti_reports_dedup_src'`).Scan(&txt); err != nil {
		t.Fatal(err)
	}
	if !contains(txt, "client_id") {
		t.Errorf("dedup index not tenant-scoped: %s", txt)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (func() bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
})() }

// A2/A4: concurrent same-file creates -> dedup index serializes (one wins).
func TestM7aConcurrentSameFileDedup(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	sid, _ := db.CreateCTISource("srcc", "file", "C")
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Direct dedup-aware creation path (service layer uses the same indexes).
			id, err := db.CreateCTIReport("client-alpha", sid, "t", "a", "", "r", "ck-concurrent")
			if err != nil {
				errs <- err
				return
			}
			_ = id
		}()
	}
	wg.Wait()
	close(errs)
	// One may fail on UNIQUE — both outcomes acceptable if final count is 1.
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM cti_reports WHERE client_id='client-alpha' AND checksum='ck-concurrent'`).Scan(&n)
	if n != 1 {
		t.Errorf("expected exactly 1 deduplicated report, got %d", n)
	}
}

// Parser retry idempotency: re-analysis never duplicates entities.
func TestM7aRetryDedupEntities(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	rid, err := db.CreateCTIReport("client-alpha", "", "t", "a", "", "ref", "ck-retry")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		runID, err := db.CreateIngestionRun(rid, "client-alpha", "1", "")
		if err != nil {
			t.Fatalf("attempt %d run: %v", i, err)
		}
		id, err := db.CreateIndicator(rid, "domain", "evil.example", "", "src")
		if err != nil {
			t.Fatalf("attempt %d indicator: %v", i, err)
		}
		if err := db.RecordExtractionResult(runID, rid, "indicator", id); err != nil {
			t.Fatalf("attempt %d membership: %v", i, err)
		}
		_ = db.SetIngestionRunStatus(runID, "ANALYZED", "")
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM indicators WHERE report_id = ?`, rid).Scan(&n)
	if n != 1 {
		t.Errorf("expected 1 deduped indicator after retry, got %d", n)
	}
}

// S1: Legacy report (seeded, no run) -> provenance null ingestion.
func TestM7aLegacyReportProvenance(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM cti_ingestion_runs WHERE report_id='report-alpha-1'`).Scan(&n)
	if n != 0 {
		t.Errorf("expected 0 runs for legacy report, got %d", n)
	}
}

// run.client_id != report.client_id must be rejected by trigger.
func TestM7aRunClientMismatchRejected(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO cti_ingestion_runs (run_id, report_id, client_id, status, parser_version, created_at) VALUES ('run-mismatch','report-alpha-1','client-beta','PENDING','1',datetime('now'))`); err == nil {
		t.Fatal("expected run/client mismatch to be rejected")
	}
}

// extraction membership run.report != membership.report must be rejected.
func TestM7aMembershipRunReportMismatchRejected(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	runID, err := db.CreateIngestionRun("report-alpha-1", "client-alpha", "1", "")
	if err != nil {
		t.Fatal(err)
	}
	// Entity belongs to report-alpha-1; membership claims report-alpha-2.
	if err := db.RecordExtractionResult(runID, "report-alpha-2", "indicator", "nonexistent-id"); err == nil {
		t.Fatal("expected membership run/report mismatch to be rejected")
	}
}

// --- HTTP handler helpers (direct handler + session context, as in cases_stageb_test.go) ---

func m7sessionReq(t *testing.T, method, target, userID, clientID string, body io.Reader, contentType string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, target, body)
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	return r.WithContext(context.WithValue(r.Context(), sessionCtxKey, &Session{
		SessionID: "ses-m7-" + userID,
		UserID:    userID,
		ClientID:  clientID,
	}))
}

func m7multipart(t *testing.T, fields map[string]string, filename string, content []byte) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	part, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, mw.FormDataContentType()
}

func m7import(t *testing.T, userID, clientID, idemKey, filename string, content []byte) *httptest.ResponseRecorder {
	t.Helper()
	fields := map[string]string{"client_id": clientID, "source_name": "src-test"}
	if idemKey != "" {
		fields["idempotency_key"] = idemKey
	}
	body, ct := m7multipart(t, fields, filename, content)
	r := m7sessionReq(t, "POST", "/api/v1/cti/import", userID, clientID, body, ct)
	w := httptest.NewRecorder()
	handleCTIImport(w, r)
	return w
}

func TestM7aIdemSameKeyChangedPayload409(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	w1 := m7import(t, "user-analyst-alpha", "client-alpha", "key-409-1", "a.json", []byte(`{"indicators":[{"type":"domain","value":"a.example"}]}`))
	if w1.Code != 201 {
		t.Fatalf("first import: %d %s", w1.Code, w1.Body.String())
	}
	w2 := m7import(t, "user-analyst-alpha", "client-alpha", "key-409-1", "b.json", []byte(`{"indicators":[{"type":"domain","value":"b.example"}]}`))
	if w2.Code != http.StatusConflict {
		t.Fatalf("expected 409 for changed payload, got %d %s", w2.Code, w2.Body.String())
	}
	// Same key + same payload -> existing, not 409.
	w3 := m7import(t, "user-analyst-alpha", "client-alpha", "key-409-1", "a.json", []byte(`{"indicators":[{"type":"domain","value":"a.example"}]}`))
	if w3.Code != 200 {
		t.Fatalf("expected 200 EXISTING for same payload, got %d %s", w3.Code, w3.Body.String())
	}
}

func TestM7aConcurrentSameKeyOneRun(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	var wg sync.WaitGroup
	codes := make([]int, 2)
	bodies := make([]string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			w := m7import(t, "user-analyst-alpha", "client-alpha", "key-conc-1", "a.json", []byte(`{"indicators":[{"type":"domain","value":"c.example"}]}`))
			codes[idx] = w.Code
			bodies[idx] = w.Body.String()
		}(i)
	}
	wg.Wait()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM cti_ingestion_runs WHERE client_id='client-alpha' AND request_idempotency_key='key-conc-1'`).Scan(&n); err != nil {
		t.Fatalf("run count: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 run for concurrent same-key, got %d (codes %v bodies %v)", n, codes, bodies)
	}
	// Exactly one 201 and one 200 EXISTING (order nondeterministic).
	created, existing := 0, 0
	for _, c := range codes {
		if c == 201 {
			created++
		} else if c == 200 {
			existing++
		}
	}
	if created != 1 || existing != 1 {
		t.Fatalf("expected one 201 + one 200 EXISTING, got %v", codes)
	}
	var reports, artifacts int
	if err := db.QueryRow(`SELECT COUNT(*) FROM cti_reports WHERE client_id='client-alpha' AND checksum != '' AND report_id LIKE 'report-%'`).Scan(&reports); err != nil {
		t.Fatal(err)
	}
	// No unreferenced artifact rows: every file_artifacts row is referenced by exactly one report (or none for loser, which must be cleaned).
	var unref int
	if err := db.QueryRow(`SELECT COUNT(*) FROM file_artifacts WHERE artifact_id NOT IN (SELECT artifact_id FROM cti_reports WHERE artifact_id IS NOT NULL)`).Scan(&unref); err != nil {
		t.Fatal(err)
	}
	if unref != 0 {
		t.Fatalf("expected 0 unreferenced artifact rows after concurrent test, got %d", unref)
	}
	entries, _ := os.ReadDir(ctiArtifactDir)
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 artifact file on disk, got %d", len(entries))
	}
	_ = reports
	_ = artifacts
}

func TestM7aDedupReturnsExistingID(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	rid, err := db.CreateCTIReport("client-alpha", "", "t", "a", "", "ref", "ck-dedup-id")
	if err != nil {
		t.Fatal(err)
	}
	id1, err := db.CreateIndicator(rid, "domain", "dup.example", "", "src")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := db.CreateIndicator(rid, "domain", "dup.example", "", "src")
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 || id1 == "" {
		t.Fatalf("expected same existing id, got %q vs %q", id1, id2)
	}
	for _, tc := range []struct {
		name string
		fn   func() (string, error)
	}{
		{"threat_actor", func() (string, error) { return db.CreateThreatActor(rid, "ActorX", "", "", "") }},
		{"campaign", func() (string, error) { return db.CreateCampaign(rid, "CampX", "", "", "", "") }},
		{"malware", func() (string, error) { return db.CreateMalware(rid, "MalX", "", "") }},
		{"cve", func() (string, error) { return db.CreateCVE(rid, "CVE-2026-0001", "", "") }},
		{"technique", func() (string, error) { return db.CreateTechnique(rid, "T1059", "", "Command") }},
		{"claim", func() (string, error) { return db.CreateCTIClaim(rid, "ClaimX", "", "", "") }},
	} {
		a, err := tc.fn()
		if err != nil {
			t.Fatalf("%s first: %v", tc.name, err)
		}
		b, err := tc.fn()
		if err != nil {
			t.Fatalf("%s second: %v", tc.name, err)
		}
		if a != b || a == "" {
			t.Fatalf("%s: expected dedup id reuse, got %q vs %q", tc.name, a, b)
		}
	}
}

func TestM7aForcedMembershipFailureFAILED(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	ridA, _ := db.CreateCTIReport("client-alpha", "", "t", "a", "", "rA", "ck-A")
	ridB, _ := db.CreateCTIReport("client-alpha", "", "t", "a", "", "rB", "ck-B")
	runID, err := db.CreateIngestionRun(ridA, "client-alpha", "1", "")
	if err != nil {
		t.Fatal(err)
	}
	// Entity belongs to A; membership claiming B must abort and roll back the entity insert.
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.CreateIndicatorInTx(tx, ridA, "domain", "cross.example", "", "")
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	err = db.RecordExtractionResultTx(tx, runID, ridB, "indicator", id)
	if err == nil {
		tx.Rollback()
		t.Fatal("expected membership trigger to reject cross-report entity")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM indicators WHERE report_id = ? AND indicator_value='cross.example'`, ridA).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("entity must be rolled back when membership fails")
	}
	// Extraction path failure surfaces as FAILED run with error, not ANALYZED.
	_, run2, err := extractWithRun(db, ridA, "client-alpha", []byte(`{invalid`), "json", "")
	if err == nil {
		t.Fatal("expected extraction error")
	}
	if run2 == "" {
		t.Fatal("expected run id for failed attempt")
	}
	var st string
	if err := db.QueryRow(`SELECT status FROM cti_ingestion_runs WHERE run_id = ?`, run2).Scan(&st); err != nil {
		t.Fatal(err)
	}
	if st != "FAILED" {
		t.Fatalf("expected FAILED, got %s", st)
	}
}

func TestM7aCorruptJSONFAILED(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	rid, err := db.CreateCTIReport("client-alpha", "", "t", "a", "", "ref", "ck-corrupt")
	if err != nil {
		t.Fatal(err)
	}
	_, runID, err := extractWithRun(db, rid, "client-alpha", []byte(`{not json`), "json", "")
	if err == nil {
		t.Fatal("expected extraction error for corrupt JSON")
	}
	var st string
	_ = db.QueryRow(`SELECT status FROM cti_ingestion_runs WHERE run_id = ?`, runID).Scan(&st)
	if st != "FAILED" {
		t.Fatalf("expected FAILED, got %s", st)
	}
	var repSt string
	_ = db.QueryRow(`SELECT status FROM cti_reports WHERE report_id = ?`, rid).Scan(&repSt)
	if repSt == "ANALYZED" {
		t.Fatal("failed extraction must not mark report ANALYZED")
	}
}

func m7reportWithArtifact(t *testing.T, db *DB, clientID, checksum, content string) (reportID, runOK string) {
	t.Helper()
	rid, err := db.CreateCTIReport(clientID, "", "t", "a", "", "dummy.pdf", checksum)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := dir + "/art.bin"
	if content == "<<MISSING>>" {
		// no file written
	} else {
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	artID := fmt.Sprintf("artifact-%d", time.Now().UnixNano())
	if _, err := db.Exec(`INSERT INTO file_artifacts (artifact_id, file_name, file_path, checksum, file_type, metadata_ref, created_at) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`, artID, "f.bin", p, checksum, ".bin", "src"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetReportArtifact(rid, artID); err != nil {
		t.Fatal(err)
	}
	return rid, artID
}

func m7analyze(t *testing.T, userID, clientID, reportID string) *httptest.ResponseRecorder {
	t.Helper()
	r := m7sessionReq(t, "POST", "/api/v1/cti/reports/"+reportID+"/analyze", userID, clientID, nil, "")
	r.SetPathValue("report_id", reportID)
	w := httptest.NewRecorder()
	handleCTIAnalyze(w, r)
	return w
}

func TestM7aMissingArtifactNotAnalyzed(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	rid, _ := m7reportWithArtifact(t, db, "client-alpha", "ck-missing", "<<MISSING>>")
	w := m7analyze(t, "user-analyst-alpha", "client-alpha", rid)
	if w.Code == 200 {
		t.Fatalf("missing artifact must not succeed: %s", w.Body.String())
	}
	var st, errCode string
	if err := db.QueryRow(`SELECT status, COALESCE(error_code,'') FROM cti_ingestion_runs WHERE report_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1`, rid).Scan(&st, &errCode); err != nil {
		t.Fatalf("run lookup: %v", err)
	}
	if st != "FAILED" || (errCode != "artifact_missing" && errCode != "artifact_unreadable") {
		t.Fatalf("expected FAILED/artifact_missing|artifact_unreadable, got %s/%s", st, errCode)
	}
	var repSt string
	if err := db.QueryRow(`SELECT status FROM cti_reports WHERE report_id = ?`, rid).Scan(&repSt); err != nil {
		t.Fatal(err)
	}
	if repSt == "ANALYZED" {
		t.Fatal("missing artifact must not become ANALYZED")
	}
}

func TestM7aChecksumMismatchFAILED(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	// Stored checksum (report + artifact) differs from file bytes.
	rid, _ := m7reportWithArtifact(t, db, "client-alpha", "deadbeef-not-the-hash", `{"indicators":[]}`)
	w := m7analyze(t, "user-analyst-alpha", "client-alpha", rid)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 checksum mismatch, got %d %s", w.Code, w.Body.String())
	}
	var latest string
	_ = db.QueryRow(`SELECT status FROM cti_ingestion_runs WHERE report_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1`, rid).Scan(&latest)
	if latest != "FAILED" {
		t.Fatalf("expected run FAILED, got %s", latest)
	}
}

func TestM7aCrossClientProvenance403(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	r := m7sessionReq(t, "GET", "/api/v1/cti/reports/report-alpha-1/provenance", "user-analyst-beta", "client-beta", nil, "")
	r.SetPathValue("report_id", "report-alpha-1")
	w := httptest.NewRecorder()
	handleCTIProvenance(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 cross-client, got %d %s", w.Code, w.Body.String())
	}
}

func TestM7aLegacyProvenanceNull(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	r := m7sessionReq(t, "GET", "/api/v1/cti/reports/report-alpha-1/provenance", "user-analyst-alpha", "client-alpha", nil, "")
	r.SetPathValue("report_id", "report-alpha-1")
	w := httptest.NewRecorder()
	handleCTIProvenance(w, r)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"ingestion":null`) {
		t.Fatalf("expected ingestion null for legacy report: %s", w.Body.String())
	}
}

func TestM7aCrossClientAnalyze403(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	w := m7analyze(t, "user-analyst-beta", "client-beta", "report-alpha-1")
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 cross-client analyze, got %d %s", w.Code, w.Body.String())
	}
}

func TestM7aReadOnlyCannotAnalyze403(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	// READ_ONLY has CanViewCTI but not CanCreateCTI.
	// m7 session helper needs a READ_ONLY user: reuse analyst session and swap role expectation via route-level check is not possible here,
	// so verify handler-level role gate by using an unknown/readonly session user inserted on the fly.
	if _, err := db.Exec(`INSERT OR IGNORE INTO users (user_id, username, email, password_hash, role, is_active, created_at, updated_at) VALUES ('user-ro','ro','ro@example.org','x','READ_ONLY',1,datetime('now'),datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES ('g-ro','user-ro','client-alpha')`); err != nil {
		t.Fatal(err)
	}
	w := m7analyze(t, "user-ro", "client-alpha", "report-alpha-1")
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for READ_ONLY analyze, got %d %s", w.Code, w.Body.String())
	}
}

func TestM7aFailedRetryPreservesSuccess(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	rid, err := db.CreateCTIReport("client-alpha", "", "t", "a", "", "ref", "ck-preserve")
	if err != nil {
		t.Fatal(err)
	}
	_, run1, err := extractWithRun(db, rid, "client-alpha", []byte(`{"indicators":[{"type":"domain","value":"good.example"}]}`), "json", "")
	if err != nil {
		t.Fatalf("first analysis: %v", err)
	}
	_ = run1
	var before string
	_ = db.QueryRow(`SELECT status FROM cti_reports WHERE report_id = ?`, rid).Scan(&before)
	// Failed reanalysis (corrupt) must not downgrade.
	_, _, err = extractWithRun(db, rid, "client-alpha", []byte(`{broken`), "json", "")
	if err == nil {
		t.Fatal("expected failure on corrupt retry")
	}
	var after string
	_ = db.QueryRow(`SELECT status FROM cti_reports WHERE report_id = ?`, rid).Scan(&after)
	if after != before {
		t.Fatalf("failed retry changed report status %q -> %q", before, after)
	}
	var latest string
	_ = db.QueryRow(`SELECT status FROM cti_ingestion_runs WHERE report_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1`, rid).Scan(&latest)
	if latest != "FAILED" {
		t.Fatalf("latest attempt should be FAILED, got %s", latest)
	}
	var okCount int
	_ = db.QueryRow(`SELECT COUNT(*) FROM cti_ingestion_runs WHERE report_id = ? AND status='ANALYZED'`, rid).Scan(&okCount)
	if okCount < 1 {
		t.Fatal("previous successful analysis must remain identifiable")
	}
}

func TestM7aNormalizationRoundTrip(t *testing.T) {
	n, rule := normalizeIndicatorValue("url", "HTTPS://EXAMPLE.COM:443/Path?Q=1#frag")
	if rule != "url-canonical-v1" {
		t.Fatalf("expected url rule, got %q -> %q", n, rule)
	}
	if n != "https://example.com/Path?Q=1" {
		t.Fatalf("unexpected normalized url: %q", n)
	}
	n2, _ := normalizeIndicatorValue("url", n)
	if n2 != n {
		t.Fatalf("not idempotent: %q vs %q", n2, n)
	}
	// Bad input -> no normalization (null-equivalent), never a fabricated value.
	if got, rule := normalizeIndicatorValue("ipv4", "not-an-ip"); rule != "" || got != "" {
		t.Fatalf("invalid ip must not normalize, got %q %q", got, rule)
	}
	if got, _ := normalizeIndicatorValue("hash", "ABCDEF0123456789ABCDEF0123456789"); got != "abcdef0123456789abcdef0123456789" {
		t.Fatalf("hash lower failed: %q", got)
	}
	// source_reference preservation at DB level.
	db := openM7DB(t)
	defer db.Close()
	rid, _ := db.CreateCTIReport("client-alpha", "", "t", "a", "", "r", "ck-norm")
	id, err := db.CreateIndicator(rid, "domain", "Example.COM", "", "origin:xyz")
	if err != nil {
		t.Fatal(err)
	}
	var storedRef, nv, nrule string
	var nver sql.NullString
	_ = db.QueryRow(`SELECT source_reference, normalized_value, normalization_rule, normalization_version FROM indicators WHERE indicator_id = ?`, id).Scan(&storedRef, &nv, &nrule, &nver)
	if storedRef != "origin:xyz" {
		t.Fatalf("source_reference mutated: %q", storedRef)
	}
	if nv != "example.com" || nrule != "domain-idna-v1" {
		t.Fatalf("normalization not stored: %q %q", nv, nrule)
	}
}

func TestM7aTenantIsolationConcurrent(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	sid, _ := db.CreateCTISource("src-iso", "file", "C")
	var wg sync.WaitGroup
	ids := make([]string, 2)
	clients := []string{"client-alpha", "client-beta"}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id, err := db.CreateCTIReport(clients[idx], sid, "t", "a", "", "r", "ck-iso")
			if err != nil {
				t.Errorf("create %s: %v", clients[idx], err)
				return
			}
			ids[idx] = id
		}(i)
	}
	wg.Wait()
	if ids[0] == "" || ids[1] == "" || ids[0] == ids[1] {
		t.Fatalf("tenants must get distinct documents: %v", ids)
	}
}

// P1-6: real routes through httptest.Server with the same middleware chain as main.go.
func TestM7aHTTPRouteRegression(t *testing.T) {
	db := openM7DB(t)
	defer db.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/cti/import", applyMiddleware(http.HandlerFunc(handleCTIImport), requireAuth, requirePermission(CanViewCTI), requirePermission(CanCreateCTI), auditWrap, csrfWrap))
	mux.HandleFunc("POST /api/v1/cti/reports/{report_id}/analyze", applyMiddleware(http.HandlerFunc(handleCTIAnalyze), requireAuth, requirePermission(CanViewCTI), requirePermission(CanCreateCTI), auditWrap, csrfWrap))
	mux.HandleFunc("GET /api/v1/cti/reports/{report_id}/provenance", applyMiddleware(http.HandlerFunc(handleCTIProvenance), requireAuth, requirePermission(CanViewCTI), auditWrap))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sess, err := db.CreateSession("user-analyst-alpha", "client-alpha")
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	_ = jar
	client := &http.Client{Timeout: 15 * time.Second}
	const csrfTok = "csrf-test-token"
	doReq := func(method, url string, body io.Reader, origin bool) *http.Response {
		req, _ := http.NewRequest(method, url, body)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: sess.SessionID})
		if origin {
			req.Header.Set("Origin", "http://localhost:5173")
			req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfTok})
			req.Header.Set("X-CSRF-Token", csrfTok)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, url, err)
		}
		return resp
	}

	// Unauthenticated -> 401.
	{
		req, _ := http.NewRequest("GET", srv.URL+"/api/v1/cti/reports/report-alpha-1/provenance", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauth provenance: expected 401, got %d", resp.StatusCode)
		}
	}
	// CSRF: state-changing POST without Origin -> 403.
	{
		body, ct := m7multipart(t, map[string]string{"client_id": "client-alpha"}, "x.json", []byte(`{}`))
		_ = ct
		resp := doReq("POST", srv.URL+"/api/v1/cti/import", body, false)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 CSRF, got %d", resp.StatusCode)
		}
	}
	// Successful import through real chain -> 201 with honest fields.
	var firstReport string
	{
		body, ct := m7multipart(t, map[string]string{"client_id": "client-alpha", "source_name": "src-http", "idempotency_key": "http-key-1"}, "h.json", []byte(`{"indicators":[{"type":"domain","value":"http.example"}]}`))
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/cti/import", body)
		req.Header.Set("Content-Type", ct)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: sess.SessionID})
		req.Header.Set("Origin", "http://localhost:5173")
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfTok})
		req.Header.Set("X-CSRF-Token", csrfTok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 201 {
			t.Fatalf("import via server: %d %s", resp.StatusCode, string(b))
		}
		if !strings.Contains(string(b), `"analysis_status":"ANALYZED"`) || !strings.Contains(string(b), `"import_status":"INGESTED"`) {
			t.Fatalf("expected honest import/analysis fields: %s", string(b))
		}
		var out struct {
			ReportID string `json:"report_id"`
			RunID    string `json:"run_id"`
		}
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		firstReport = out.ReportID
		if out.RunID == "" {
			t.Fatal("expected run_id in import response")
		}
		// Idempotent repeat -> 200 EXISTING.
		body2, ct2 := m7multipart(t, map[string]string{"client_id": "client-alpha", "source_name": "src-http", "idempotency_key": "http-key-1"}, "h.json", []byte(`{"indicators":[{"type":"domain","value":"http.example"}]}`))
		req2, _ := http.NewRequest("POST", srv.URL+"/api/v1/cti/import", body2)
		req2.Header.Set("Content-Type", ct2)
		req2.AddCookie(&http.Cookie{Name: "session_id", Value: sess.SessionID})
		req2.Header.Set("Origin", "http://localhost:5173")
		req2.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfTok})
		req2.Header.Set("X-CSRF-Token", csrfTok)
		resp2, err := client.Do(req2)
		if err != nil {
			t.Fatal(err)
		}
		b2, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		if resp2.StatusCode != 200 || !strings.Contains(string(b2), `"EXISTING"`) {
			t.Fatalf("expected 200 EXISTING repeat, got %d %s", resp2.StatusCode, string(b2))
		}
		// Changed payload -> 409.
		body3, ct3 := m7multipart(t, map[string]string{"client_id": "client-alpha", "source_name": "src-http", "idempotency_key": "http-key-1"}, "h.json", []byte(`{"indicators":[{"type":"domain","value":"other.example"}]}`))
		req3, _ := http.NewRequest("POST", srv.URL+"/api/v1/cti/import", body3)
		req3.Header.Set("Content-Type", ct3)
		req3.AddCookie(&http.Cookie{Name: "session_id", Value: sess.SessionID})
		req3.Header.Set("Origin", "http://localhost:5173")
		req3.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfTok})
		req3.Header.Set("X-CSRF-Token", csrfTok)
		resp3, err := client.Do(req3)
		if err != nil {
			t.Fatal(err)
		}
		resp3.Body.Close()
		if resp3.StatusCode != http.StatusConflict {
			t.Fatalf("expected 409 changed payload, got %d", resp3.StatusCode)
		}
	}
	// Cross-client analyze via HTTP -> 403; own analyze -> 200 (artifact bytes verified).
	{
		sessB, _ := db.CreateSession("user-analyst-beta", "client-beta")
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/cti/reports/"+firstReport+"/analyze", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: sessB.SessionID})
		req.Header.Set("Origin", "http://localhost:5173")
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfTok})
		req.Header.Set("X-CSRF-Token", csrfTok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 cross-client analyze, got %d", resp.StatusCode)
		}
		req2, _ := http.NewRequest("POST", srv.URL+"/api/v1/cti/reports/"+firstReport+"/analyze", nil)
		req2.AddCookie(&http.Cookie{Name: "session_id", Value: sess.SessionID})
		req2.Header.Set("Origin", "http://localhost:5173")
		req2.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfTok})
		req2.Header.Set("X-CSRF-Token", csrfTok)
		resp2, err := client.Do(req2)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		if resp2.StatusCode != 200 || !strings.Contains(string(b), `"ANALYZED"`) {
			t.Fatalf("expected 200 ANALYZED own analyze, got %d %s", resp2.StatusCode, string(b))
		}
	}
}
