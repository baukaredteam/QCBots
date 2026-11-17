package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// M7-E Phase 1.2: consistent, verified SQLite backup with atomic publication.
//
// VACUUM INTO writes a consistent snapshot under a private temporary name. The
// snapshot is flushed, verified, hashed, and only then published to the final
// name with a hard link. A hard link creates the destination atomically and
// fails if it already exists, so:
//   - a reader never sees a partial final file;
//   - an existing backup is never overwritten;
//   - concurrent publications to one name have exactly one winner;
//   - an interrupted process leaves at most a temporary file, never a partial
//     backup under the final name.
//
// Guarantees differ by platform and by failure mode; see the M7-E 1.2 document.
// Hard links are required for publication. Filesystems without hard links fail
// closed instead of falling back to a visible copy.

// Test seams. Production leaves these nil.
var (
	backupAfterStageHook    func(tmp string)
	backupBeforePublishHook func(tmp, dst string)
)

func backupSQLite(src, dst string) error {
	if strings.TrimSpace(src) == "" || strings.TrimSpace(dst) == "" {
		return fmt.Errorf("source and destination are required")
	}
	srcPath, err := canonicalExistingFile(src)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	dstDir, err := canonicalDir(filepath.Dir(dst))
	if err != nil {
		return fmt.Errorf("destination directory: %w", err)
	}
	dstPath := filepath.Join(dstDir, filepath.Base(dst))
	if strings.EqualFold(srcPath, dstPath) {
		return fmt.Errorf("source and destination are the same file")
	}
	if _, err := os.Lstat(dstPath); err == nil {
		return fmt.Errorf("refusing to overwrite an existing backup: %s", dstPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cannot inspect destination: %w", err)
	}

	srcDB, err := sql.Open("sqlite3", srcPath+"?_busy_timeout=30000")
	if err != nil {
		return fmt.Errorf("opening source: %w", err)
	}
	defer srcDB.Close()
	srcDB.SetMaxOpenConns(1)
	var check string
	if err := srcDB.QueryRow(`PRAGMA integrity_check`).Scan(&check); err != nil {
		return fmt.Errorf("source integrity check failed: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(check), "ok") {
		return fmt.Errorf("source database is not intact: %s", check)
	}

	tmp := filepath.Join(dstDir, fmt.Sprintf(".%s.tmp-%d-%d", filepath.Base(dst), os.Getpid(), time.Now().UnixNano()))
	// The temporary file (and any SQLite sidecars created while verifying it) is
	// ours alone; the final destination is never removed by cleanup.
	defer func() {
		for _, p := range []string{tmp, tmp + "-wal", tmp + "-shm", tmp + "-journal"} {
			_ = os.Remove(p)
		}
	}()

	if _, err := srcDB.Exec(`VACUUM INTO '` + strings.ReplaceAll(tmp, "'", "''") + `'`); err != nil {
		return fmt.Errorf("writing staged snapshot: %w", err)
	}
	if err := syncFile(tmp); err != nil {
		return fmt.Errorf("flushing staged snapshot: %w", err)
	}
	if backupAfterStageHook != nil {
		backupAfterStageHook(tmp)
	}
	if err := verifySQLiteFile(tmp); err != nil {
		return fmt.Errorf("staged snapshot verification: %w", err)
	}
	stagedHash, err := hashFileSHA256(tmp)
	if err != nil {
		return fmt.Errorf("hashing staged snapshot: %w", err)
	}
	if backupBeforePublishHook != nil {
		backupBeforePublishHook(tmp, dstPath)
	}

	if err := publishNoReplace(tmp, dstPath); err != nil {
		return err
	}
	finalHash, err := hashFileSHA256(dstPath)
	if err != nil {
		_ = os.Remove(dstPath) // we just created it; do not leave a broken backup
		return fmt.Errorf("reading published backup: %w", err)
	}
	if finalHash != stagedHash {
		_ = os.Remove(dstPath)
		return fmt.Errorf("published backup hash %s does not match the verified snapshot %s", finalHash, stagedHash)
	}
	if err := syncDir(dstDir); err != nil {
		return fmt.Errorf("backup published at %s but the directory could not be flushed: %w", dstPath, err)
	}
	return nil
}

// publishNoReplace creates dst as a hard link to the complete staged snapshot.
// It fails if dst exists and does not fall back to a visible copy.
func publishNoReplace(tmp, dst string) error {
	if err := os.Link(tmp, dst); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("refusing to overwrite an existing backup: %s", dst)
		}
		return fmt.Errorf("atomic no-replace publication requires hard-link support: %w", err)
	}
	return nil
}

// syncFile flushes the staged file contents before publication.
func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// syncDir persists the directory entry after the link on POSIX systems. Windows
// has no portable directory fsync; that limitation is documented, not hidden.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func hashFileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// verifySQLiteFile opens a database and checks integrity, schema and history.
func verifySQLiteFile(path string) error {
	db, err := sql.Open("sqlite3", path+"?_busy_timeout=30000")
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var check string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&check); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(check), "ok") {
		return fmt.Errorf("integrity check returned %q", check)
	}
	var tables int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table'`).Scan(&tables); err != nil {
		return err
	}
	if tables == 0 {
		return fmt.Errorf("backup contains no tables")
	}
	var versions int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&versions); err != nil {
		return fmt.Errorf("backup has no migration history: %w", err)
	}
	if versions == 0 {
		return fmt.Errorf("backup has an empty migration history")
	}
	return nil
}

// canonicalExistingFile resolves symlinks and requires a regular file.
func canonicalExistingFile(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("not resolvable: %w", err)
	}
	st, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file: %s", real)
	}
	return real, nil
}

// canonicalDir resolves a directory that must already exist.
func canonicalDir(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("not resolvable: %w", err)
	}
	st, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("not a directory: %s", real)
	}
	return real, nil
}
