package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// M7-E Phase 1: session expiry, migration rollback, backup/restore and seeder
// isolation. Disposable databases only.

func TestSessionExpiryRejected(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()

	// Cached session whose expiry has passed must be refused and evicted.
	s1, err := db.CreateSession("user-admin", "client-alpha")
	if err != nil {
		t.Fatal(err)
	}
	if cached := sessionCache.load(s1.SessionID); cached != nil {
		cached.ExpiresAt = time.Now().Add(-time.Minute)
	}
	if got, err := db.GetSession(s1.SessionID); err != nil || got != nil {
		t.Fatalf("expired cached session must be rejected, got %+v %v", got, err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE session_id = ?`, s1.SessionID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("expired session must be removed from the database")
	}

	// Database path: a session expired while the process was not running.
	s2, err := db.CreateSession("user-admin", "client-alpha")
	if err != nil {
		t.Fatal(err)
	}
	sessionCache.delete(s2.SessionID)
	if _, err := db.Exec(`UPDATE sessions SET expires_at = ? WHERE session_id = ?`,
		time.Now().Add(-time.Hour).Format(time.RFC3339), s2.SessionID); err != nil {
		t.Fatal(err)
	}
	if got, err := db.GetSession(s2.SessionID); err != nil || got != nil {
		t.Fatalf("expired stored session must be rejected, got %+v %v", got, err)
	}
}

func TestExpiredSessionHTTP401(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	sess, err := db.CreateSession("user-admin", "client-alpha")
	if err != nil {
		t.Fatal(err)
	}
	if cached := sessionCache.load(sess.SessionID); cached != nil {
		cached.ExpiresAt = time.Now().Add(-time.Minute)
	}
	h := applyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), requireAuth)
	r := httptest.NewRequest("GET", "/api/v1/hunt-plans", nil)
	r.AddCookie(&http.Cookie{Name: "session_id", Value: sess.SessionID})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expired session must be 401, got %d", w.Code)
	}
}

func TestMigrationFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	mig := filepath.Join(dir, "0099_bad.sql")
	if err := os.WriteFile(mig, []byte(
		"CREATE TABLE zz_m7e_partial (id TEXT PRIMARY KEY);\nCREATE TABLE broken (;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite3", ":memory:?_foreign_keys=1")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetMaxOpenConns(1)
	if err := createM1Tables(raw); err != nil {
		t.Fatal(err)
	}
	if err := runMigration(raw, mig); err == nil {
		t.Fatal("a broken migration must fail")
	}
	var tables int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='zz_m7e_partial'`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 0 {
		t.Fatal("a failed migration must not leave partial schema")
	}
	var recorded int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, mig).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != 0 {
		t.Fatal("a failed migration must not be recorded")
	}
}

func TestBackupRestoreIntegrity(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "live.db")
	db, err := OpenDB(src)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO clients (client_id, client_name, status, created_at, updated_at)
		VALUES ('client-backup', 'Backup Fixture', 'active', datetime('now'), datetime('now'))`); err != nil {
		t.Fatal(err)
	}

	backup := filepath.Join(dir, "backup.db")
	if err := backupSQLite(src, backup); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if err := backupSQLite(src, backup); err == nil {
		t.Fatal("an existing backup must never be overwritten")
	}

	// The backup is a consistent snapshot: later source writes do not appear.
	if _, err := db.Exec(`INSERT INTO clients (client_id, client_name, status, created_at, updated_at)
		VALUES ('client-after-backup', 'After', 'active', datetime('now'), datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	verify := func(path string) {
		t.Helper()
		vdb, err := sql.Open("sqlite3", path+"?_busy_timeout=30000")
		if err != nil {
			t.Fatal(err)
		}
		defer vdb.Close()
		var integrity string
		if err := vdb.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
			t.Fatalf("integrity check: %q %v", integrity, err)
		}
		var n int
		if err := vdb.QueryRow(`SELECT COUNT(*) FROM clients WHERE client_id='client-backup'`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("backup lost its data: %d %v", n, err)
		}
		if err := vdb.QueryRow(`SELECT COUNT(*) FROM clients WHERE client_id='client-after-backup'`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("backup is not a point-in-time snapshot: %d %v", n, err)
		}
	}
	verify(backup)

	// Restore into a new file (the documented procedure replaces a stopped
	// database; here the copy is verified before use).
	restored := filepath.Join(dir, "restored.db")
	data, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(restored, data, 0o600); err != nil {
		t.Fatal(err)
	}
	verify(restored)
}

func TestMigrateCommandIsIdempotentAndSetsSafetyPragmas(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pilot.db")
	if err := runMigrateCommand(dbPath); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := runMigrateCommand(dbPath); err != nil {
		t.Fatalf("migrate must be idempotent: %v", err)
	}
	db, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=1&_busy_timeout=30000")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, table := range []string{"hunt_plan_versions", "sigma_detection_rules", "qradar_domain_bindings", "audit_log"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n); err != nil || n != 1 {
			t.Fatalf("table %s missing after migrate: %d %v", table, n, err)
		}
	}
	var versions int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&versions); err != nil || versions < 21 {
		t.Fatalf("migration history incomplete: %d %v", versions, err)
	}
	var journal string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&journal); err != nil || journal != "wal" {
		t.Fatalf("journal_mode = %q (want wal): %v", journal, err)
	}
	var fk int
	if err := db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		t.Fatalf("foreign_keys = %d (want 1): %v", fk, err)
	}
}

func TestTestSeederRequiresExplicitOptIn(t *testing.T) {
	t.Setenv("SENTINEL_ENABLE_TEST_SEEDERS", "")
	if err := requireTestSeederEnv(); err == nil {
		t.Fatal("synthetic seeding must be refused without an explicit opt-in")
	}
	t.Setenv("SENTINEL_ENABLE_TEST_SEEDERS", "1")
	if err := requireTestSeederEnv(); err != nil {
		t.Fatalf("explicit opt-in must be accepted: %v", err)
	}
}
