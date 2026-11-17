package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// M7-E Phase 1.1: backup edge cases. Disposable databases only.

func TestBackupRefusesExistingAndKeepsCanonicalPaths(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "live.db")
	db, err := OpenDB(src)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Destination that already exists in any form is refused.
	existing := filepath.Join(dir, "existing.db")
	if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := backupSQLite(src, existing); err == nil {
		t.Fatal("an existing destination must be refused")
	}
	if data, _ := os.ReadFile(existing); string(data) != "keep" {
		t.Fatal("an existing destination must be unchanged")
	}

	// A symlinked source is resolved and backed up.
	link := filepath.Join(dir, "live-link.db")
	if err := os.Symlink(src, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	out := filepath.Join(dir, "from-link.db")
	if err := backupSQLite(link, out); err != nil {
		t.Fatalf("backup through a source symlink: %v", err)
	}
	if err := verifySQLiteFile(out); err != nil {
		t.Fatalf("backup through a symlink is invalid: %v", err)
	}
	if _, err := os.Stat(out + "-wal"); !os.IsNotExist(err) {
		t.Fatal("VACUUM INTO must produce a single self-contained file")
	}
}

func TestBackupConcurrentInvocations(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "live.db")
	db, err := OpenDB(src)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO clients (client_id, client_name, status, created_at, updated_at)
		VALUES ('client-concurrent', 'Concurrent', 'active', datetime('now'), datetime('now'))`); err != nil {
		t.Fatal(err)
	}

	// Different destinations: both succeed.
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = backupSQLite(src, filepath.Join(dir, "backup-"+string(rune('a'+i))+".db"))
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent backup %d failed: %v", i, err)
		}
	}

	// Same destination: exactly one publishes, the other refuses, and the loser
	// leaves no temporary file behind.
	same := filepath.Join(dir, "same.db")
	res := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res[i] = backupSQLite(src, same)
		}(i)
	}
	wg.Wait()
	okCount := 0
	for _, err := range res {
		if err == nil {
			okCount++
		}
	}
	if okCount != 1 {
		t.Fatalf("exactly one concurrent backup to the same path must win, got %d", okCount)
	}
	if err := verifySQLiteFile(same); err != nil {
		t.Fatalf("published backup is invalid: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temporary backup file left behind: %s", e.Name())
		}
	}
}

func TestBackupFailureLeavesNoPublishedFile(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "not-a-database.txt")
	if err := os.WriteFile(bad, []byte("this is not sqlite"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "backup.db")
	if err := backupSQLite(bad, dst); err == nil {
		t.Fatal("a malformed source must fail")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatal("a failed backup must not publish a file")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("a failed backup left a temporary file: %s", e.Name())
		}
	}
}
