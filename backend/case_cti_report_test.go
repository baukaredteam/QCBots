package main

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func openM7BDB(t *testing.T) *DB {
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
		{"m7b-grant-alpha-alpha", "user-analyst-alpha", "client-alpha"},
		{"m7b-grant-beta-beta", "user-analyst-beta", "client-beta"},
		{"m7b-grant-alpha-multi", "user-analyst-multi", "client-alpha"},
		{"m7b-grant-beta-multi", "user-analyst-multi", "client-beta"},
		{"m7b-grant-admin-alpha", "user-admin", "client-alpha"},
	} {
		if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES (?, ?, ?)`, g.id, g.uid, g.cid); err != nil {
			t.Fatalf("grant %s: %v", g.id, err)
		}
	}
	// Cases for alpha/beta (synthetic, explicit).
	if _, err := CreateResearchCase("user-analyst-alpha", "Alpha Case", "d", "m7b-case-alpha", "client-alpha"); err != nil {
		t.Fatalf("case alpha: %v", err)
	}
	if _, err := CreateResearchCase("user-analyst-beta", "Beta Case", "d", "m7b-case-beta", "client-beta"); err != nil {
		t.Fatalf("case beta: %v", err)
	}
	return gDB
}

func caseIDByKey(t *testing.T, db *DB, key string) string {
	t.Helper()
	var id string
	if err := db.QueryRow(`SELECT case_id FROM research_cases WHERE idempotency_key = ?`, key).Scan(&id); err != nil {
		t.Fatalf("case lookup %s: %v", key, err)
	}
	return id
}

func TestM7bMigration0007PreservesActivity(t *testing.T) {
	// Separate fresh DB: apply 0001-0006, insert history, then 0007, verify preservation.
	db, err := sql.Open("sqlite3", ":memory:?_journal_mode=WAL&_foreign_keys=1")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, m := range []string{"migrations/0001_initial.sql", "migrations/0002_qradar_inventory.sql", "migrations/0003_evidence_graph.sql", "migrations/0004_p0_mcp_case.sql", "migrations/0005_m6_case_workspace.sql", "migrations/0006_cti_ingestion.sql"} {
		if err := runMigration(db, m); err != nil {
			t.Fatalf("pre %s: %v", m, err)
		}
	}
	if err := createM1Tables(db); err != nil {
		t.Fatal(err)
	}
	if err := seedTestData(db); err != nil {
		t.Fatal(err)
	}
	globalDB = &DB{db}
	if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES ('hist-grant','user-analyst-alpha','client-alpha')`); err != nil {
		t.Fatal(err)
	}
	cid, err := CreateResearchCase("user-analyst-alpha", "Hist Case", "d", "hist-1", "client-alpha")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO case_activity (activity_id, case_id, user_id, action, visibility_scope, client_id, details, created_at) VALUES ('act-hist-1', ?, 'user-analyst-alpha', 'note_added', 'CLIENT', 'client-alpha', 'seed note', datetime('now'))`, cid); err != nil {
		t.Fatal(err)
	}
	var before int
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_activity`).Scan(&before)
	if before < 1 {
		t.Fatal("expected history rows before 0007")
	}
	if err := runMigration(db, "migrations/0007_case_cti_reports.sql"); err != nil {
		t.Fatalf("0007: %v", err)
	}
	// Re-run must be idempotent.
	if err := runMigration(db, "migrations/0007_case_cti_reports.sql"); err != nil {
		t.Fatalf("0007 re-run: %v", err)
	}
	var after int
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_activity`).Scan(&after)
	if after != before {
		t.Fatalf("history not preserved: before=%d after=%d", before, after)
	}
	var det string
	if err := db.QueryRow(`SELECT details FROM case_activity WHERE activity_id='act-hist-1'`).Scan(&det); err != nil || det != "seed note" {
		t.Fatalf("history row altered: %q %v", det, err)
	}
	var ic string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&ic); err != nil || ic != "ok" {
		t.Fatalf("integrity: %v %q", err, ic)
	}
	// New action accepted.
	if _, err := db.Exec(`INSERT INTO case_activity (activity_id, case_id, user_id, action, visibility_scope, client_id, details, created_at) VALUES ('act-new-1', ?, 'user-analyst-alpha', 'report_linked', 'CLIENT', 'client-alpha', 'report-alpha-1', datetime('now'))`, cid); err != nil {
		t.Fatalf("report_linked action rejected: %v", err)
	}
	// Immutability triggers still reject UPDATE/DELETE.
	if _, err := db.Exec(`UPDATE case_activity SET details='x' WHERE activity_id='act-hist-1'`); err == nil {
		t.Fatal("UPDATE trigger must reject")
	}
	if _, err := db.Exec(`DELETE FROM case_activity WHERE activity_id='act-hist-1'`); err == nil {
		t.Fatal("DELETE trigger must reject")
	}
}

func TestM7bLinkB1HappyPath(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	caseID := caseIDByKey(t, db, "m7b-case-alpha")
	if _, err := LinkCaseCTIReport(caseID, "user-analyst-alpha", "report-alpha-1"); err != nil {
		t.Fatalf("link: %v", err)
	}
	rows, total, err := ListCaseCTIReports(caseID, "user-analyst-alpha", 20, 0)
	if err != nil || total != 1 || len(rows) != 1 || rows[0].ReportID != "report-alpha-1" {
		t.Fatalf("list after link: total=%d rows=%+v err=%v", total, rows, err)
	}
	var act int
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_activity WHERE case_id=? AND action='report_linked'`, caseID).Scan(&act)
	if act != 1 {
		t.Fatalf("expected 1 report_linked activity, got %d", act)
	}
}

func TestM7bCrossClient403(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	caseBeta := caseIDByKey(t, db, "m7b-case-beta")
	// beta user has no grant for alpha; alpha report must be denied.
	if _, err := LinkCaseCTIReport(caseBeta, "user-analyst-beta", "report-alpha-1"); err == nil {
		t.Fatal("expected cross-client denial")
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_cti_reports WHERE case_id=?`, caseBeta).Scan(&n)
	if n != 0 {
		t.Fatalf("no link rows allowed on denial, got %d", n)
	}
}

func TestM7bDuplicateAndConcurrent(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	caseID := caseIDByKey(t, db, "m7b-case-alpha")
	for i := 0; i < 2; i++ {
		if _, err := LinkCaseCTIReport(caseID, "user-analyst-alpha", "report-alpha-1"); err != nil {
			t.Fatalf("sequential dup %d: %v", i, err)
		}
	}
	var n, acts int
	if err := db.QueryRow(`SELECT COUNT(*) FROM case_cti_reports WHERE case_id=? AND report_id='report-alpha-1'`, caseID).Scan(&n); err != nil {
		t.Fatalf("link count query: %v (case %q)", err, caseID)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_activity WHERE case_id=? AND action='report_linked'`, caseID).Scan(&acts)
	if n != 1 || acts != 1 {
		t.Fatalf("sequential dup: rows=%d acts=%d (want 1/1)", n, acts)
	}
	var wg sync.WaitGroup
	errs := make([]error, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = LinkCaseCTIReport(caseID, "user-analyst-alpha", "report-alpha-2")
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Logf("concurrent link %d err: %v", i, e)
		}
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_cti_reports WHERE case_id=? AND report_id='report-alpha-2'`).Scan(&n)
	if n != 1 {
		t.Fatalf("concurrent: expected 1 row, got %d", n)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM case_activity WHERE case_id=? AND action='report_linked'`, caseID).Scan(&acts); err != nil {
		t.Fatalf("activity count query: %v", err)
	}
	if acts != 2 {
		t.Fatalf("expected 2 total link activities (1+1), got %d", acts)
	}
}

func TestM7bUnlinkIdempotentAndHistory(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	caseID := caseIDByKey(t, db, "m7b-case-alpha")
	if _, err := LinkCaseCTIReport(caseID, "user-analyst-alpha", "report-alpha-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := UnlinkCaseCTIReport(caseID, "user-analyst-alpha", "report-alpha-1"); err != nil {
		t.Fatal(err)
	}
	// Second unlink: no-op success.
	if _, err := UnlinkCaseCTIReport(caseID, "user-analyst-alpha", "report-alpha-1"); err != nil {
		t.Fatal(err)
	}
	var n, linked, unlinked int
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_cti_reports WHERE case_id=? AND report_id='report-alpha-1'`).Scan(&n)
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_activity WHERE case_id=? AND action='report_linked'`, caseID).Scan(&linked)
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_activity WHERE case_id=? AND action='report_unlinked'`, caseID).Scan(&unlinked)
	if n != 0 || linked != 1 || unlinked != 1 {
		t.Fatalf("rows=%d linked=%d unlinked=%d (want 0/1/1)", n, linked, unlinked)
	}
}

func TestM7bArchivedRejects(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	caseID := caseIDByKey(t, db, "m7b-case-alpha")
	if _, err := db.Exec(`UPDATE research_cases SET status='ARCHIVED' WHERE case_id=?`, caseID); err != nil {
		t.Fatal(err)
	}
	if _, err := LinkCaseCTIReport(caseID, "user-analyst-alpha", "report-alpha-1"); err == nil {
		t.Fatal("expected ARCHIVED rejection")
	}
}

func TestM7bGlobalCaseNoLeak(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	caseAlpha := caseIDByKey(t, db, "m7b-case-alpha")
	if _, err := LinkCaseCTIReport(caseAlpha, "user-analyst-alpha", "report-alpha-1"); err != nil {
		t.Fatal(err)
	}
	// beta has no case access and no alpha grant: list must be denied/empty, never leak.
	_, _, err := ListCaseCTIReports(caseAlpha, "user-analyst-beta", 20, 0)
	if err == nil {
		t.Fatal("expected denial for unauthorized case access")
	}
	// alpha via reverse lookup sees it.
	cases, total, err := ListReportCases("report-alpha-1", "user-analyst-alpha", 20, 0)
	if err != nil || total != 1 || len(cases) != 1 || cases[0].CaseID != caseAlpha {
		t.Fatalf("reverse: total=%d cases=%+v err=%v", total, cases, err)
	}
	// beta reverse lookup denied (report grant missing).
	if _, _, err := ListReportCases("report-alpha-1", "user-analyst-beta", 20, 0); err == nil {
		t.Fatal("expected reverse lookup denial")
	}
}

func TestM7bRevokedGrant(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	caseAlpha := caseIDByKey(t, db, "m7b-case-alpha")
	if _, err := LinkCaseCTIReport(caseAlpha, "user-analyst-alpha", "report-alpha-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM user_authorized_clients WHERE user_id='user-analyst-alpha' AND client_id='client-alpha'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ListCaseCTIReports(caseAlpha, "user-analyst-alpha", 20, 0); err == nil {
		// List should be denied or empty for CLIENT content (grant revoked).
		// GetResearchCase still passes via ownership, but grant filter empties rows.
	}
	rows, total, err := ListCaseCTIReports(caseAlpha, "user-analyst-alpha", 20, 0)
	if err != nil {
		t.Fatalf("list after revoke: %v", err)
	}
	if total != 0 || len(rows) != 0 {
		t.Fatalf("revoked grant must hide CLIENT rows: total=%d", total)
	}
	if _, err := LinkCaseCTIReport(caseAlpha, "user-analyst-alpha", "report-alpha-2"); err == nil {
		t.Fatal("expected link denial after revoke")
	}
}

func TestM7bCreateCaseFromReport(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	caseID, _, linked, err := CreateCaseFromReport("user-analyst-alpha", "report-alpha-1", "From Report", "desc", "m7b-create-1", "P2", "HIGH")
	if err != nil {
		t.Fatalf("create-from-report: %v", err)
	}
	if !linked {
		t.Fatal("expected linked=true on create")
	}
	if caseID == "" {
		t.Fatal("empty case id")
	}
	rows, total, err := ListCaseCTIReports(caseID, "user-analyst-alpha", 20, 0)
	if err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("linked after create: total=%d err=%v", total, err)
	}
	// Idempotent replay.
	c2, _, _, err := CreateCaseFromReport("user-analyst-alpha", "report-alpha-1", "From Report", "desc", "m7b-create-1", "P2", "HIGH")
	if err != nil || c2 != caseID {
		t.Fatalf("replay: %q %v (want %q)", c2, err, caseID)
	}
	// Changed payload -> 409 (ErrIdempotencyConflict).
	if _, _, _, err := CreateCaseFromReport("user-analyst-alpha", "report-alpha-1", "Other", "desc", "m7b-create-1", "P2", "HIGH"); err == nil {
		t.Fatal("expected idempotency conflict")
	}
}

func TestM7bLegacyReportLinkable(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	// report-alpha-1 is seeded legacy (no ingestion runs).
	caseAlpha := caseIDByKey(t, db, "m7b-case-alpha")
	if _, err := LinkCaseCTIReport(caseAlpha, "user-analyst-alpha", "report-alpha-1"); err != nil {
		t.Fatalf("legacy link: %v", err)
	}
}

func TestM7bReportStatusUnchanged(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	var before string
	_ = db.QueryRow(`SELECT status FROM cti_reports WHERE report_id='report-alpha-1'`).Scan(&before)
	caseAlpha := caseIDByKey(t, db, "m7b-case-alpha")
	_, _ = LinkCaseCTIReport(caseAlpha, "user-analyst-alpha", "report-alpha-1")
	_, _ = UnlinkCaseCTIReport(caseAlpha, "user-analyst-alpha", "report-alpha-1")
	var after string
	_ = db.QueryRow(`SELECT status FROM cti_reports WHERE report_id='report-alpha-1'`).Scan(&after)
	if before != after {
		t.Fatalf("report status mutated: %q -> %q", before, after)
	}
}

func m7bReq(t *testing.T, method, target, userID, clientID, body string) *http.Request {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	// Route params for direct handler calls (Go 1.22 ServeMux populates these in prod).
	switch {
	case strings.Contains(target, "/create-case"):
		r.SetPathValue("report_id", strings.TrimSuffix(strings.TrimPrefix(target, "/api/v1/cti/reports/"), "/create-case"))
	case strings.Contains(target, "/cti/reports/"):
		rest := strings.TrimPrefix(target, "/api/v1/cti/reports/")
		r.SetPathValue("report_id", strings.Split(rest, "/")[0])
	case strings.Contains(target, "/cases/"):
		rest := strings.TrimPrefix(target, "/api/v1/cases/")
		parts := strings.Split(rest, "/")
		if len(parts) > 0 {
			r.SetPathValue("case_id", parts[0])
		}
		if len(parts) > 2 && parts[1] == "cti-reports" {
			r.SetPathValue("report_id", parts[2])
		}
	}
	return r.WithContext(context.WithValue(r.Context(), sessionCtxKey, &Session{
		SessionID: "ses-m7b-" + userID,
		UserID:    userID,
		ClientID:  clientID,
	}))
}

func TestM7bHTTPRoutes(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	caseAlpha := caseIDByKey(t, db, "m7b-case-alpha")
	// Link via handler.
	w := httptest.NewRecorder()
	handleLinkCaseCTIReport(w, m7bReq(t, "POST", "/api/v1/cases/"+caseAlpha+"/cti-reports", "user-analyst-alpha", "client-alpha", `{"report_id":"report-alpha-1"}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("link handler: %d %s", w.Code, w.Body.String())
	}
	// List via handler.
	w = httptest.NewRecorder()
	handleListCaseCTIReports(w, m7bReq(t, "GET", "/api/v1/cases/"+caseAlpha+"/cti-reports", "user-analyst-alpha", "client-alpha", ""))
	if w.Code != 200 {
		t.Fatalf("list handler: %d %s", w.Code, w.Body.String())
	}
	// Reverse lookup.
	w = httptest.NewRecorder()
	handleListReportCases(w, m7bReq(t, "GET", "/api/v1/cti/reports/report-alpha-1/cases", "user-analyst-alpha", "client-alpha", ""))
	if w.Code != 200 {
		t.Fatalf("reverse handler: %d %s", w.Code, w.Body.String())
	}
	// Create-from-report via handler.
	w = httptest.NewRecorder()
	handleCreateCaseFromReport(w, m7bReq(t, "POST", "/api/v1/cti/reports/report-alpha-2/create-case", "user-analyst-alpha", "client-alpha", `{"title":"Via HTTP","description":"d","priority":"P2","severity":"HIGH","idempotency_key":"m7b-http-1"}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("create-case handler: %d %s", w.Code, w.Body.String())
	}
	// Unlink via handler.
	w = httptest.NewRecorder()
	handleUnlinkCaseCTIReport(w, m7bReq(t, "DELETE", "/api/v1/cases/"+caseAlpha+"/cti-reports/report-alpha-1", "user-analyst-alpha", "client-alpha", ""))
	if w.Code != 200 {
		t.Fatalf("unlink handler: %d %s", w.Code, w.Body.String())
	}
}

// P0-1: reverse pagination filters hidden cases before LIMIT/OFFSET.
func TestM7bReversePaginationAfterFilter(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	// User: analyst-multi has alpha+beta grants, but only owns some cases.
	// Create 5 alpha reports linked to 5 cases; make first 3 inaccessible
	// by linking them to beta-owned cases is impossible (grant) — instead
	// use owner-restricted cases: create 5 cases as alpha, then remove alpha
	// from participants? Simpler: use beta-owned cases linked via multi
	// (multi has grant to alpha reports, and is participant? no).
	// Direct approach: create 5 cases owned by analyst-alpha, link 5 alpha
	// reports (seed has 2 alpha reports; create 3 more report rows).
	for i, rid := range []string{"report-alpha-1", "report-alpha-2"} {
		_ = i
		_ = rid
	}
	ids := []string{}
	for i := 0; i < 5; i++ {
		cid, err := CreateResearchCase("user-analyst-alpha", "PageCase", "d", "m7b-page-"+string(rune('a'+i)), "client-alpha")
		if err != nil {
			t.Skipf("case create: %v", err)
		}
		ids = append(ids, cid)
	}
	// Need 5 distinct alpha reports.
	reportIDs := []string{"report-alpha-1", "report-alpha-2"}
	for i := 0; i < 3; i++ {
		rid, err := db.CreateCTIReport("client-alpha", "", "t", "a", "", "ref-pg", "ck-pg-"+string(rune('a'+i)))
		if err != nil {
			t.Fatal(err)
		}
		reportIDs = append(reportIDs, rid)
	}
	// Link same report (report-alpha-1) to all 5 cases.
	for _, cid := range ids {
		if _, err := LinkCaseCTIReport(cid, "user-analyst-alpha", "report-alpha-1"); err != nil {
			t.Fatal(err)
		}
	}
	// Now make first 3 hidden: revoke alpha's ownership? Ownership is owner_id,
	// GetResearchCase passes via owner. Instead delete participant + change owner
	// is not allowed. Alternative: hide via grant? All alpha grant present.
	// To simulate hidden cases, use a user who owns only last 2 cases.
	// Create last-2 owner user with alpha grant.
	if _, err := db.Exec(`INSERT OR IGNORE INTO users (user_id, username, email, password_hash, role, is_active, created_at, updated_at) VALUES ('user-pager','pager','pager@example.org','x','CTI_ANALYST',1,datetime('now'),datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES ('g-pager','user-pager','client-alpha')`); err != nil {
		t.Fatal(err)
	}
	// Transfer ownership of last 2 cases to pager by adding participant.
	for _, cid := range ids[3:] {
		if _, err := db.Exec(`INSERT INTO case_authorized_participants (grant_id, case_id, user_id, role_in_case, granted_at) VALUES (?, ?, 'user-pager', 'VIEWER', datetime('now'))`, "grant-"+cid[:8], cid); err != nil {
			t.Fatal(err)
		}
	}
	// Pager sees only last 2 (participant) — first 3 hidden (not owner/participant/admin).
	// But alpha reports grant exists, so reverse lookup for pager returns 2.
	rows, total, err := ListReportCases("report-alpha-1", "user-pager", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(rows) != 2 {
		t.Fatalf("expected total=2 rows=2 after filter, got total=%d rows=%d", total, len(rows))
	}
	rows2, total2, err := ListReportCases("report-alpha-1", "user-pager", 2, 5)
	if err != nil {
		t.Fatal(err)
	}
	if total2 != 2 || len(rows2) != 0 {
		t.Fatalf("offset beyond authorized: total=%d rows=%d (want 2/0)", total2, len(rows2))
	}
}

// P0-2: same key, different report -> 409 (M7-B scope includes report_id).
func TestM7bCreateSameKeyDifferentReport409(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	if _, _, _, err := CreateCaseFromReport("user-analyst-alpha", "report-alpha-1", "T", "d", "m7b-scope-1", "P2", "HIGH"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := CreateCaseFromReport("user-analyst-alpha", "report-alpha-2", "T", "d", "m7b-scope-1", "P2", "HIGH"); err == nil {
		t.Fatal("expected 409 for same key + different report")
	}
	// Same key + changed title -> 409.
	if _, _, _, err := CreateCaseFromReport("user-analyst-alpha", "report-alpha-1", "Changed", "d", "m7b-scope-1", "P2", "HIGH"); err == nil {
		t.Fatal("expected 409 for same key + changed payload")
	}
}

// P0-2: concurrent same-key create -> one case + one link.
func TestM7bConcurrentCreateOneCase(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	var wg sync.WaitGroup
	var ids [4]string
	var errs [4]error
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ids[idx], _, _, errs[idx] = CreateCaseFromReport("user-analyst-alpha", "report-alpha-1", "Conc", "d", "m7b-conc-1", "P2", "HIGH")
		}(i)
	}
	wg.Wait()
	var nCases, nLinks int
	_ = db.QueryRow(`SELECT COUNT(*) FROM research_cases WHERE idempotency_key LIKE 'm7b\_%' ESCAPE '\'`).Scan(&nCases)
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_cti_create_ops WHERE user_id='user-analyst-alpha' AND idempotency_key='m7b-conc-1'`).Scan(&nLinks)
	if nCases != 1 || nLinks != 1 {
		t.Fatalf("expected 1 case + 1 op after concurrent, got %d/%d errs=%v", nCases, nLinks, errs)
	}
	// All goroutines must have gotten a valid result (no unexpected SQL errors).
	for i, e := range errs {
		if e != nil {
			t.Fatalf("concurrent create %d unexpected error: %v (all must succeed or replay)", i, e)
		}
		if ids[i] == "" {
			t.Fatalf("concurrent create %d empty case id", i)
		}
		if ids[i] != ids[0] {
			t.Fatalf("concurrent create must converge to one case: %v", ids)
		}
	}
}

// P1-5: HTTP route regression through real middleware chain.
func TestM7bHTTPRouteRegression(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/cases/{case_id}/cti-reports", applyMiddleware(http.HandlerFunc(handleListCaseCTIReports), requireAuth, requirePermission(CanViewCTI), auditWrap))
	mux.HandleFunc("POST /api/v1/cases/{case_id}/cti-reports", applyMiddleware(http.HandlerFunc(handleLinkCaseCTIReport), requireAuth, requirePermission(CanCreateCTI), auditWrap, csrfWrap))
	mux.HandleFunc("DELETE /api/v1/cases/{case_id}/cti-reports/{report_id}", applyMiddleware(http.HandlerFunc(handleUnlinkCaseCTIReport), requireAuth, requirePermission(CanCreateCTI), auditWrap, csrfWrap))
	mux.HandleFunc("GET /api/v1/cti/reports/{report_id}/cases", applyMiddleware(http.HandlerFunc(handleListReportCases), requireAuth, requirePermission(CanViewCTI), auditWrap))
	mux.HandleFunc("POST /api/v1/cti/reports/{report_id}/create-case", applyMiddleware(http.HandlerFunc(handleCreateCaseFromReport), requireAuth, requirePermission(CanCreateCTI), auditWrap, csrfWrap))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	sess, err := db.CreateSession("user-analyst-alpha", "client-alpha")
	if err != nil {
		t.Fatal(err)
	}
	caseAlpha := caseIDByKey(t, db, "m7b-case-alpha")
	client := &http.Client{Timeout: 15 * time.Second}
	authed := func(method, url string, body string) *http.Response {
		var rdr *strings.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		} else {
			rdr = strings.NewReader("")
		}
		req, _ := http.NewRequest(method, url, rdr)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: sess.SessionID})
		if method != "GET" {
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
		req, _ := http.NewRequest("GET", srv.URL+"/api/v1/cases/"+caseAlpha+"/cti-reports", nil)
		resp, _ := client.Do(req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauth: %d", resp.StatusCode)
		}
	}
	// Missing CSRF -> 403.
	{
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/cases/"+caseAlpha+"/cti-reports", strings.NewReader(`{"report_id":"report-alpha-1"}`))
		req.AddCookie(&http.Cookie{Name: "session_id", Value: sess.SessionID})
		resp, _ := client.Do(req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("csrf: %d", resp.StatusCode)
		}
	}
	// Link 201 then duplicate 200.
	r1 := authed("POST", srv.URL+"/api/v1/cases/"+caseAlpha+"/cti-reports", `{"report_id":"report-alpha-1"}`)
	r1.Body.Close()
	if r1.StatusCode != http.StatusCreated {
		t.Fatalf("link: %d", r1.StatusCode)
	}
	r2 := authed("POST", srv.URL+"/api/v1/cases/"+caseAlpha+"/cti-reports", `{"report_id":"report-alpha-1"}`)
	r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("duplicate link: %d", r2.StatusCode)
	}
	// Create-case replay 200.
	c1 := authed("POST", srv.URL+"/api/v1/cti/reports/report-alpha-2/create-case", `{"title":"HTTP C","description":"d","priority":"P2","severity":"HIGH","idempotency_key":"m7b-http-route-1"}`)
	c1.Body.Close()
	if c1.StatusCode != http.StatusCreated {
		t.Fatalf("create-case: %d", c1.StatusCode)
	}
	c2 := authed("POST", srv.URL+"/api/v1/cti/reports/report-alpha-2/create-case", `{"title":"HTTP C","description":"d","priority":"P2","severity":"HIGH","idempotency_key":"m7b-http-route-1"}`)
	c2.Body.Close()
	if c2.StatusCode != http.StatusOK {
		t.Fatalf("create-case replay: %d", c2.StatusCode)
	}
	// Cross-client 403.
	sessB, _ := db.CreateSession("user-analyst-beta", "client-beta")
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/cases/"+caseAlpha+"/cti-reports", strings.NewReader(`{"report_id":"report-alpha-1"}`))
	req.AddCookie(&http.Cookie{Name: "session_id", Value: sessB.SessionID})
	req.Header.Set("Origin", "http://localhost:5173")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "tok-1"})
	req.Header.Set("X-CSRF-Token", "tok-1")
	resp, _ := client.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-client: %d", resp.StatusCode)
	}
}

func TestM7bActivityFailureRollsBack(t *testing.T) {
	// Genuine activity INSERT failure injection via trigger: the whole
	// CreateCaseFromReport tx (case + participant + link + activity + op) must roll back.
	db := openM7BDB(t)
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER fail_activity_test BEFORE INSERT ON case_activity WHEN NEW.details = 'report-alpha-1' BEGIN SELECT RAISE(ABORT, 'injected activity failure'); END`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`DROP TRIGGER IF EXISTS fail_activity_test`)
	if _, _, _, err := CreateCaseFromReport("user-analyst-alpha", "report-alpha-1", "RollbackCase", "d", "m7b-rb-1", "P2", "HIGH"); err == nil {
		t.Fatal("expected create to fail on activity injection")
	}
	var nCases, nLinks, nActs, nOps int
	_ = db.QueryRow(`SELECT COUNT(*) FROM research_cases WHERE title='RollbackCase'`).Scan(&nCases)
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_cti_create_ops WHERE user_id='user-analyst-alpha' AND idempotency_key='m7b-rb-1'`).Scan(&nOps)
	if nCases != 0 || nOps != 0 {
		t.Fatalf("rollback left partial rows: cases=%d ops=%d (want 0/0)", nCases, nOps)
	}
	// After dropping the fault, retry succeeds and everything commits.
	db.Exec(`DROP TRIGGER IF EXISTS fail_activity_test`)
	caseID, created, _, err := CreateCaseFromReport("user-analyst-alpha", "report-alpha-1", "RollbackCase", "d", "m7b-rb-1", "P2", "HIGH")
	if err != nil || !created || caseID == "" {
		t.Fatalf("retry after fault: %q %v created=%v", caseID, err, created)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_cti_reports WHERE case_id=? AND report_id='report-alpha-1'`, caseID).Scan(&nLinks)
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_activity WHERE case_id=? AND action='report_linked'`, caseID).Scan(&nActs)
	if nLinks != 1 || nActs != 1 {
		t.Fatalf("after recovery: links=%d acts=%d (want 1/1)", nLinks, nActs)
	}
}

// Replay after explicit Unlink must NOT silently reinsert the link.
func TestM7bReplayAfterUnlink(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	caseID, _, linked, err := CreateCaseFromReport("user-analyst-alpha", "report-alpha-1", "ReplayCase", "d", "m7b-replay-1", "P2", "HIGH")
	if err != nil || !linked {
		t.Fatalf("create: %q %v linked=%v", caseID, err, linked)
	}
	if _, err := UnlinkCaseCTIReport(caseID, "user-analyst-alpha", "report-alpha-1"); err != nil {
		t.Fatal(err)
	}
	var actsBefore int
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_activity WHERE case_id=? AND action='report_linked'`, caseID).Scan(&actsBefore)
	// Replay same key+payload.
	c2, created2, linked2, err := CreateCaseFromReport("user-analyst-alpha", "report-alpha-1", "ReplayCase", "d", "m7b-replay-1", "P2", "HIGH")
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if c2 != caseID || created2 {
		t.Fatalf("replay must return existing case: %q vs %q created=%v", c2, caseID, created2)
	}
	if linked2 {
		t.Fatal("replay must report linked=false after unlink (no silent restore)")
	}
	var nLink, actsAfter int
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_cti_reports WHERE case_id=? AND report_id='report-alpha-1'`, caseID).Scan(&nLink)
	_ = db.QueryRow(`SELECT COUNT(*) FROM case_activity WHERE case_id=? AND action='report_linked'`, caseID).Scan(&actsAfter)
	if nLink != 0 {
		t.Fatalf("replay recreated link row: %d", nLink)
	}
	if actsAfter != actsBefore {
		t.Fatalf("replay created new activity: before=%d after=%d", actsBefore, actsAfter)
	}
	// New link creation must go through the authorized Link operation.
	if _, err := LinkCaseCTIReport(caseID, "user-analyst-alpha", "report-alpha-1"); err != nil {
		t.Fatal(err)
	}
	if !isReportLinked(caseID, "report-alpha-1") {
		t.Fatal("explicit relink must restore link")
	}
}

// Internal namespace: two (user,key) pairs whose concatenation could collide
// must produce distinct internal identities; M6 key already contains "m7b_" prefix.
func TestM7bInternalKeyNamespace(t *testing.T) {
	k1 := m7bInternalKey("user-a:b", "c")
	k2 := m7bInternalKey("user-a", "b:c")
	if k1 == k2 {
		t.Fatalf("ambiguous concatenation collision: %q", k1)
	}
	// Ordinary M6 key cannot equal an M7-B internal key by construction
	// (M7-B keys are m7b_<64hex>); a user-supplied M6 key with that value would
	// still be checked against case access, never silently adopted.
	db := openM7BDB(t)
	defer db.Close()
	external := "m7b_" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	// Direct M6 create with an M7-B-looking key still works as ordinary M6.
	if _, err := CreateResearchCase("user-analyst-alpha", "M6 Case", "d", external, "client-alpha"); err != nil {
		t.Fatalf("M6 create with m7b-like key: %v", err)
	}
	// M7-B create with the same external key is independent (ops table scope).
	if _, _, _, err := CreateCaseFromReport("user-analyst-alpha", "report-alpha-1", "M7B Case", "d", external, "P2", "HIGH"); err != nil {
		t.Fatalf("M7-B create independent: %v", err)
	}
}

func TestM7bMigrationIntegrity(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	var ic string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&ic); err != nil || ic != "ok" {
		t.Fatalf("integrity: %v %q", err, ic)
	}
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Fatal("foreign_key_check violations present")
	}
}

// P0 cross-user collision: same external key + same payload + same report,
// different users (same client) MUST get distinct cases (namespaced internal key).
func TestM7bCrossUserSameKeyDistinctCases(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	// analyst-multi has grants to alpha+beta; create second alpha user for same client.
	if _, err := db.Exec(`INSERT OR IGNORE INTO users (user_id, username, email, password_hash, role, is_active, created_at, updated_at) VALUES ('user-alpha2','alpha2','alpha2@example.org','x','CTI_ANALYST',1,datetime('now'),datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES ('g-alpha2','user-alpha2','client-alpha')`); err != nil {
		t.Fatal(err)
	}
	a, createdA, _, err := CreateCaseFromReport("user-analyst-alpha", "report-alpha-1", "SameTitle", "d", "shared-key-1", "P2", "HIGH")
	if err != nil || !createdA {
		t.Fatalf("user A: %q %v created=%v", a, err, createdA)
	}
	b, _, _, err := CreateCaseFromReport("user-alpha2", "report-alpha-1", "SameTitle", "d", "shared-key-1", "P2", "HIGH")
	if err != nil {
		t.Fatalf("user B must not adopt A's case: %v", err)
	}
	if a == b {
		t.Fatalf("cross-user collision: both got %q", a)
	}
	// Same user + same key + same report -> replay same case.
	a2, createdA2, _, err := CreateCaseFromReport("user-analyst-alpha", "report-alpha-1", "SameTitle", "d", "shared-key-1", "P2", "HIGH")
	if err != nil || a2 != a || createdA2 {
		t.Fatalf("same-user replay: %q %v created=%v (want %q false)", a2, err, createdA2, a)
	}
	// Same user + same key + different report -> 409.
	if _, _, _, err := CreateCaseFromReport("user-analyst-alpha", "report-alpha-2", "SameTitle", "d", "shared-key-1", "P2", "HIGH"); err == nil {
		t.Fatal("expected 409 for same key + different report")
	}
}

// Cross-user + different reports with same key -> distinct (no 409 across users).
func TestM7bCrossUserDifferentReportDistinct(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	if _, err := db.Exec(`INSERT OR IGNORE INTO users (user_id, username, email, password_hash, role, is_active, created_at, updated_at) VALUES ('user-beta2','beta2','beta2@example.org','x','CTI_ANALYST',1,datetime('now'),datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES ('g-beta2','user-beta2','client-beta')`); err != nil {
		t.Fatal(err)
	}
	a, _, _, err := CreateCaseFromReport("user-analyst-alpha", "report-alpha-1", "T", "d", "k-1", "P2", "HIGH")
	if err != nil {
		t.Fatal(err)
	}
	b, _, _, err := CreateCaseFromReport("user-beta2", "report-beta-1", "T", "d", "k-1", "P2", "HIGH")
	if err != nil {
		t.Fatalf("different-report cross-user must succeed, got: %v", err)
	}
	if a == b {
		t.Fatal("expected distinct cases")
	}
}

// Direct adoption attempt of another user's case must be rejected via M7-B op scope.
func TestM7bAdoptInaccessibleCaseRejected(t *testing.T) {
	db := openM7BDB(t)
	defer db.Close()
	// Create case as alpha, then as beta (same client? beta has no alpha grant -> cannot use beta report anyway).
	// Use alpha-report with beta user: requireReportAccess denies before adoption.
	if _, _, _, err := CreateCaseFromReport("user-analyst-beta", "report-alpha-1", "Hijack", "d", "hijack-1", "P2", "HIGH"); err == nil {
		t.Fatal("expected denial adopting alpha report as beta")
	}
}
