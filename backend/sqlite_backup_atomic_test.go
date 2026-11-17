package main

import (
	"crypto/sha256"
	"fmt"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// M7-E Phase 1.2: atomic publication contract.
//
// The final backup name must never be visible as a partial file. The staged
// snapshot is complete and verified before it is published, publication is
// no-replace, and only files created by this invocation are cleaned up.

func sha256File(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func backupFixture(t *testing.T, dir string, rows int) string {
	t.Helper()
	src := filepath.Join(dir, "source.db")
	db, err := OpenDB(src)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < rows; i++ {
		if _, err := db.Exec(`INSERT INTO clients (client_id, client_name, status, created_at, updated_at)
			VALUES (?, ?, 'active', datetime('now'), datetime('now'))`,
			fmt.Sprintf("client-%06d", i), "Fixture"); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return src
}

func TestBackupStagesBeforePublishing(t *testing.T) {
	dir := t.TempDir()
	src := backupFixture(t, dir, 250)
	dst := filepath.Join(dir, "backup.db")

	var stagedHash string
	backupAfterStageHook = func(tmp string) {
		if _, err := os.Stat(dst); !os.IsNotExist(err) {
			t.Fatalf("final destination must not exist while staging: %v", err)
		}
		if err := verifySQLiteFile(tmp); err != nil {
			t.Fatalf("staged snapshot must already be complete and valid: %v", err)
		}
		stagedHash = sha256File(t, tmp)
	}
	defer func() { backupAfterStageHook = nil }()

	backupBeforePublishHook = func(tmp, target string) {
		if _, err := os.Stat(dst); !os.IsNotExist(err) {
			t.Fatalf("final destination must not exist before publication: %v", err)
		}
	}
	defer func() { backupBeforePublishHook = nil }()

	if err := backupSQLite(src, dst); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if stagedHash == "" {
		t.Fatal("staging hook was not called")
	}
	if got := sha256File(t, dst); got != stagedHash {
		t.Fatalf("published content differs from the verified snapshot: %s != %s", got, stagedHash)
	}
}

func TestBackupReaderNeverSeesPartialDestination(t *testing.T) {
	dir := t.TempDir()
	src := backupFixture(t, dir, 4000) // large enough to take measurable time
	dst := filepath.Join(dir, "backup.db")

	var mu sync.Mutex
	var observed []string // hashes of any file that appeared at dst
	pollDone := make(chan struct{})
	backupBeforePublishHook = func(tmp, target string) {
		go func() {
			defer close(pollDone)
			deadline := time.Now().Add(300 * time.Millisecond)
			for time.Now().Before(deadline) {
				if data, err := os.ReadFile(dst); err == nil {
					sum := sha256.Sum256(data)
					mu.Lock()
					observed = append(observed, hex.EncodeToString(sum[:]))
					mu.Unlock()
				}
			}
		}()
	}
	defer func() { backupBeforePublishHook = nil }()

	if err := backupSQLite(src, dst); err != nil {
		t.Fatalf("backup: %v", err)
	}
	<-pollDone
	final := sha256File(t, dst)
	mu.Lock()
	defer mu.Unlock()
	for _, h := range observed {
		if h != final {
			t.Fatalf("a reader observed a non-final destination hash %s (final %s)", h, final)
		}
	}
}

func TestBackupNeverReplacesADestinationThatAppearsLate(t *testing.T) {
	dir := t.TempDir()
	src := backupFixture(t, dir, 100)
	dst := filepath.Join(dir, "backup.db")

	backupBeforePublishHook = func(tmp, target string) {
		if err := os.WriteFile(dst, []byte("intruder"), 0o600); err != nil {
			t.Fatalf("creating late destination: %v", err)
		}
	}
	defer func() { backupBeforePublishHook = nil }()

	if err := backupSQLite(src, dst); err == nil {
		t.Fatal("publication must fail when the destination appears concurrently")
	}
	data, err := os.ReadFile(dst)
	if err != nil || string(data) != "intruder" {
		t.Fatalf("the late destination must be untouched, got %q %v", data, err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "backup.db" && e.Name() != "source.db" {
			t.Fatalf("a failed publication left an artifact: %s", e.Name())
		}
	}
}

func TestBackupFailedVerificationPreventsPublication(t *testing.T) {
	dir := t.TempDir()
	src := backupFixture(t, dir, 50)
	dst := filepath.Join(dir, "backup.db")

	backupAfterStageHook = func(tmp string) {
		if err := os.WriteFile(tmp, []byte("corrupted after staging"), 0o600); err != nil {
			t.Fatalf("corrupting staged snapshot: %v", err)
		}
	}
	defer func() { backupAfterStageHook = nil }()

	if err := backupSQLite(src, dst); err == nil {
		t.Fatal("a corrupt staged snapshot must not be published")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatal("no destination may exist after a failed verification")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "source.db" {
			t.Fatalf("a failed verification left an artifact: %s", e.Name())
		}
	}
}

func TestBackupLeavesSourceUntouchedAndRestorable(t *testing.T) {
	dir := t.TempDir()
	src := backupFixture(t, dir, 500)
	dst := filepath.Join(dir, "backup.db")

	beforeHash := sha256File(t, src)
	var beforeRows int
	srcDB, err := sql.Open("sqlite3", src+"?_busy_timeout=30000")
	if err != nil {
		t.Fatal(err)
	}
	if err := srcDB.QueryRow(`SELECT COUNT(*) FROM clients`).Scan(&beforeRows); err != nil {
		srcDB.Close()
		t.Fatal(err)
	}
	srcDB.Close()

	if err := backupSQLite(src, dst); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if got := sha256File(t, src); got != beforeHash {
		t.Fatal("the source database was modified by the backup")
	}
	if err := verifySQLiteFile(dst); err != nil {
		t.Fatalf("published backup is not valid: %v", err)
	}
	restored, err := sql.Open("sqlite3", dst+"?_busy_timeout=30000")
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var afterRows int
	if err := restored.QueryRow(`SELECT COUNT(*) FROM clients`).Scan(&afterRows); err != nil {
		t.Fatal(err)
	}
	if afterRows != beforeRows {
		t.Fatalf("restored row count %d != source %d", afterRows, beforeRows)
	}
}
