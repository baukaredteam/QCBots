package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// openSingleConnMemoryDB opens an in-memory SQLite DB with MaxOpenConns(1),
// matching production OpenDB pooling.
func openSingleConnMemoryDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:?_journal_mode=WAL&_foreign_keys=1")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db
}

// runTimeout runs fn and returns its error, or a timeout error if fn does not
// return within d. A timeout alone does NOT abort a hung SQL query; operations
// under test bound their own SQL work with context timeouts (ensureColumnSQL: 5s),
// so the goroutine is expected to finish via context cancellation, not escape.
func runTimeout(d time.Duration, fn func() error) error {
	errCh := make(chan error, 1)
	go func() { errCh <- fn() }()
	select {
	case err := <-errCh:
		return err
	case <-time.After(d):
		return fmt.Errorf("deadlock: did not complete within %s", d)
	}
}

// A. Fresh SQLite + MaxOpenConns(1): ensureColumnSQL completes without deadlock.
func TestEnsureColumnSQLNoDeadlock(t *testing.T) {
	db := openSingleConnMemoryDB(t)
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE detection_rules (rule_id TEXT PRIMARY KEY, rule_name TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if err := runTimeout(5*time.Second, func() error {
		return ensureColumnSQL(db, "detection_rules", "criticality", "TEXT")
	}); err != nil {
		t.Fatalf("ensureColumnSQL: %v", err)
	}
}

// B. Existing column: repeated call is a no-op and does not hang.
func TestEnsureColumnSQLExistingColumn(t *testing.T) {
	db := openSingleConnMemoryDB(t)
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE detection_rules (rule_id TEXT PRIMARY KEY, criticality TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := runTimeout(5*time.Second, func() error {
		for i := 0; i < 3; i++ {
			if err := ensureColumnSQL(db, "detection_rules", "criticality", "TEXT"); err != nil {
				return fmt.Errorf("repeat %d: %w", i, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("%v", err)
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('detection_rules') WHERE name='criticality'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 criticality column, got %d", n)
	}
}

// C. Missing column: created.
func TestEnsureColumnSQLMissingColumn(t *testing.T) {
	db := openSingleConnMemoryDB(t)
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE detection_rules (rule_id TEXT PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	if err := ensureColumnSQL(db, "detection_rules", "criticality", "TEXT"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('detection_rules') WHERE name='criticality'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected criticality created, got n=%d", n)
	}
}

// D. Invalid input: error returned, no ALTER TABLE performed.
func TestEnsureColumnSQLInvalidInput(t *testing.T) {
	db := openSingleConnMemoryDB(t)
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE detection_rules (rule_id TEXT PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	cases := [][3]string{
		{"detection_rules; DROP TABLE x", "criticality", "TEXT"},
		{"detection_rules", "criticality; DROP", "TEXT"},
		{"detection_rules", "criticality", "TEXT DEFAULT 0; DROP TABLE x"},
		{"unknown_table", "criticality", "TEXT"},
		{"detection_rules", "unknown_column", "TEXT"},
	}
	for _, tc := range cases {
		if err := ensureColumnSQL(db, tc[0], tc[1], tc[2]); err == nil {
			t.Errorf("expected error for %+v, got nil", tc)
		}
	}
	// Table still exists and no stray columns were added.
	var total int
	if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('detection_rules')").Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Errorf("expected only rule_id column after invalid calls, got %d", total)
	}
}

// D2. Registry pairs/types: wrong table/column pairing and wrong SQL type rejected.
func TestEnsureColumnSQLRegistryRejectsBadPairsAndTypes(t *testing.T) {
	db := openSingleConnMemoryDB(t)
	defer db.Close()
	for _, tbl := range []string{"detection_rules", "global_fields", "building_blocks"} {
		if _, err := db.Exec("CREATE TABLE IF NOT EXISTS " + tbl + " (rule_id TEXT PRIMARY KEY)"); err != nil {
			t.Fatal(err)
		}
	}
	bad := [][3]string{
		// column from another table
		{"global_fields", "criticality", "TEXT"},
		{"detection_rules", "availability", "TEXT"},
		{"building_blocks", "criticality", "TEXT"},
		// wrong SQL type for a valid pair
		{"detection_rules", "criticality", "INTEGER NOT NULL DEFAULT 0"},
		{"detection_rules", "enabled", "TEXT"},
		{"global_fields", "availability", "INTEGER NOT NULL DEFAULT 0"},
		{"building_blocks", "sysmon_required", "TEXT"},
		// injection attempts
		{"detection_rules", "criticality\"; DROP TABLE detection_rules; --", "TEXT"},
	}
	for _, tc := range bad {
		if err := ensureColumnSQL(db, tc[0], tc[1], tc[2]); err == nil {
			t.Errorf("expected rejection for %+v, got nil", tc)
		}
	}
	// Valid pairs still succeed.
	if err := ensureColumnSQL(db, "detection_rules", "criticality", "TEXT"); err != nil {
		t.Errorf("valid pair rejected: %v", err)
	}
	if err := ensureColumnSQL(db, "global_fields", "availability", "TEXT"); err != nil {
		t.Errorf("valid pair rejected: %v", err)
	}
}

// E. Concurrent requests complete without connection exhaustion.
func TestEnsureColumnSQLConcurrent(t *testing.T) {
	db := openSingleConnMemoryDB(t)
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE detection_rules (rule_id TEXT PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	if err := runTimeout(20*time.Second, func() error {
		var wg sync.WaitGroup
		errs := make(chan error, 20)
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := ensureColumnSQL(db, "detection_rules", "criticality", "TEXT"); err != nil {
					errs <- err
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				if strings.Contains(err.Error(), "context deadline exceeded") {
					return fmt.Errorf("deadline exceeded failure: %w", err)
				}
				return fmt.Errorf("concurrent ensureColumnSQL: %w", err)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("%v", err)
	}
	st := db.Stats()
	if st.InUse != 0 {
		t.Errorf("expected InUse=0 after concurrent calls, got %d", st.InUse)
	}
	t.Logf("stats: open=%d in_use=%d idle=%d wait=%d wait_dur=%s", st.OpenConnections, st.InUse, st.Idle, st.WaitCount, st.WaitDuration)
	// Pool still usable afterwards (no restart, no leaked connection).
	if err := runTimeout(5*time.Second, func() error {
		return ensureColumnSQL(db, "detection_rules", "criticality", "TEXT")
	}); err != nil {
		t.Fatalf("pool not usable after concurrency: %v", err)
	}
}

// F. QRadar API integration: real HTTP handlers return without hanging.
func TestQRadarEndpointsReturnWithoutDeadlock(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	cases := []struct {
		name    string
		path    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"rules", "/api/v1/qradar/rules", handleQRadarRules},
		{"bbs", "/api/v1/qradar/building-blocks", handleQRadarBuildingBlocks},
		{"fields", "/api/v1/qradar/fields", handleQRadarFields},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", tc.path, nil)
		req = req.WithContext(context.WithValue(req.Context(), sessionCtxKey, &Session{
			SessionID: "test-session",
			UserID:    "user-analyst-alpha",
			ClientID:  "client-alpha",
		}))
		if err := runTimeout(10*time.Second, func() error {
			tc.handler(rec, req)
			return nil
		}); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d: %s", tc.name, rec.Code, rec.Body.String())
		}
	}
}

// F2. Real routes through httptest.Server: auth + middleware + QRadar endpoints.
func TestQRadarRoutesViaHTTPServer(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	sess, err := globalDB.CreateSession("user-analyst-alpha", "client-alpha")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/qradar/rules", applyMiddleware(http.HandlerFunc(handleQRadarRules), requireAuth, requirePermission(CanViewCTI), auditWrap))
	mux.HandleFunc("GET /api/v1/qradar/building-blocks", applyMiddleware(http.HandlerFunc(handleQRadarBuildingBlocks), requireAuth, requirePermission(CanViewCTI), auditWrap))
	mux.HandleFunc("GET /api/v1/qradar/fields", applyMiddleware(http.HandlerFunc(handleQRadarFields), requireAuth, requirePermission(CanViewCTI), auditWrap))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}

	// Unauthenticated -> 401 through middleware.
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/qradar/rules", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unauth request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without session, got %d", resp.StatusCode)
	}

	// Authenticated via real session cookie -> 200 for all three routes.
	baseReq, _ := http.NewRequest("GET", srv.URL+"/api/v1/qradar/rules", nil)
	baseReq.AddCookie(&http.Cookie{Name: "session_id", Value: sess.SessionID})
	for _, path := range []string{"/api/v1/qradar/rules", "/api/v1/qradar/building-blocks", "/api/v1/qradar/fields"} {
		r, err := http.NewRequest("GET", srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.AddCookie(&http.Cookie{Name: "session_id", Value: sess.SessionID})
		resp, err := client.Do(r)
		if err != nil {
			t.Fatalf("GET %s: %v (deadlock?)", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: expected 200, got %d: %s", path, resp.StatusCode, string(body))
		}
		if !strings.Contains(string(body), `"count"`) {
			t.Errorf("GET %s: response missing count: %s", path, string(body))
		}
	}
	_ = baseReq
}

// G. Repeated ListQRadar* calls leave the pool healthy.
func TestQRadarPoolHealthyAfterRepeatedCalls(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	if err := runTimeout(15*time.Second, func() error {
		for i := 0; i < 5; i++ {
			if _, err := db.ListQRadarRules("", "", ""); err != nil {
				return fmt.Errorf("rules iter %d: %w", i, err)
			}
			if _, err := db.ListBuildingBlocks(); err != nil {
				return fmt.Errorf("bbs iter %d: %w", i, err)
			}
			if _, err := db.ListQRadarFields("", ""); err != nil {
				return fmt.Errorf("fields iter %d: %w", i, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("%v", err)
	}
	st := db.Stats()
	t.Logf("pool after repeats: open=%d in_use=%d idle=%d wait=%d wait_dur=%s", st.OpenConnections, st.InUse, st.Idle, st.WaitCount, st.WaitDuration)
	if st.InUse != 0 {
		t.Errorf("expected InUse=0 after calls, got %d", st.InUse)
	}
	fmt.Println("db.Stats:", fmt.Sprintf("%+v", st))
}
