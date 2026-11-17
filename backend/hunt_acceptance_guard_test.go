package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Phase 2B-4B release hardening: the acceptance seeder must never delete or
// overwrite an existing file, whatever it is called or contains.

func TestValidateAcceptanceDBPath(t *testing.T) {
	auth := t.TempDir()
	write := func(t *testing.T, path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	unchanged := func(t *testing.T, path, want string) {
		t.Helper()
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("pre-existing file disappeared: %v", err)
		}
		if string(got) != want {
			t.Fatalf("pre-existing file changed: %q", got)
		}
	}

	t.Run("valid new path", func(t *testing.T) {
		target := filepath.Join(auth, "new-acceptance.db")
		got, err := validateAcceptanceDBPath(target, auth)
		if err != nil {
			t.Fatalf("valid path rejected: %v", err)
		}
		if _, err := os.Stat(got); !os.IsNotExist(err) {
			t.Fatalf("validation must not create the file: %v", err)
		}
	})

	t.Run("existing sqlite database", func(t *testing.T) {
		target := filepath.Join(auth, "existing.db")
		write(t, target, "SQLite format 3\x00not really a database")
		if _, err := validateAcceptanceDBPath(target, auth); err == nil {
			t.Fatal("an existing database must be refused")
		}
		unchanged(t, target, "SQLite format 3\x00not really a database")
	})

	t.Run("empty file", func(t *testing.T) {
		target := filepath.Join(auth, "empty.db")
		write(t, target, "")
		if _, err := validateAcceptanceDBPath(target, auth); err == nil {
			t.Fatal("an empty file must be refused")
		}
		unchanged(t, target, "")
	})

	t.Run("malformed database", func(t *testing.T) {
		target := filepath.Join(auth, "garbage.db")
		write(t, target, "\x00\x01not a database at all")
		if _, err := validateAcceptanceDBPath(target, auth); err == nil {
			t.Fatal("a malformed database file must be refused")
		}
		unchanged(t, target, "\x00\x01not a database at all")
	})

	t.Run("alternate synthetic-looking filename", func(t *testing.T) {
		target := filepath.Join(auth, "synthetic-users.db")
		write(t, target, "keep me")
		if _, err := validateAcceptanceDBPath(target, auth); err == nil {
			t.Fatal("a file name must never prove that a database may be replaced")
		}
		unchanged(t, target, "keep me")
	})

	t.Run("symlink at target", func(t *testing.T) {
		victim := filepath.Join(auth, "victim.txt")
		write(t, victim, "do not touch")
		target := filepath.Join(auth, "link.db")
		if err := os.Symlink(victim, target); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := validateAcceptanceDBPath(target, auth); err == nil {
			t.Fatal("a symlink at the target path must be refused")
		}
		unchanged(t, victim, "do not touch")
		if fi, err := os.Lstat(target); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Fatal("the symlink must be left in place")
		}
	})

	t.Run("forbidden application directory", func(t *testing.T) {
		for _, dir := range []string{"..", "../storage", "../config"} {
			abs, err := filepath.Abs(dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := validateAcceptanceDBPath(filepath.Join(abs, "acceptance.db"), abs); err == nil {
				t.Fatalf("application directory %s must be refused", dir)
			}
		}
	})

	t.Run("outside the authorized directory", func(t *testing.T) {
		other := t.TempDir()
		if _, err := validateAcceptanceDBPath(filepath.Join(other, "x.db"), auth); err == nil {
			t.Fatal("a path outside the authorized directory must be refused")
		}
	})

	t.Run("authorized directory does not exist", func(t *testing.T) {
		if _, err := validateAcceptanceDBPath(filepath.Join(auth, "x.db"), filepath.Join(auth, "missing")); err == nil {
			t.Fatal("a missing authorized directory must be refused")
		}
	})

	t.Run("target is a directory", func(t *testing.T) {
		target := filepath.Join(auth, "adir")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := validateAcceptanceDBPath(target, auth); err == nil {
			t.Fatal("a directory at the target path must be refused")
		}
	})

	t.Run("production name inside temp", func(t *testing.T) {
		if _, err := validateAcceptanceDBPath(filepath.Join(auth, "workbench.db"), auth); err == nil {
			t.Fatal("the production database name must be refused anywhere")
		}
	})

	t.Run("empty target", func(t *testing.T) {
		if _, err := validateAcceptanceDBPath("", auth); err == nil {
			t.Fatal("an empty target must be refused")
		}
	})
}

func TestSeedHuntAcceptanceRefusesWithoutAuthorization(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "x.db")
	t.Setenv(acceptanceDirEnv, "")
	if err := seedHuntAcceptance(target); err == nil {
		t.Fatal("seeding without an authorized directory must fail")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("a refused run must not create a file")
	}
}

func TestSeedHuntAcceptancePreservesExistingFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "existing.db")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(acceptanceDirEnv, dir)
	if err := seedHuntAcceptance(target); err == nil {
		t.Fatal("seeding over an existing file must fail")
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "keep" {
		t.Fatalf("existing file was modified: %q %v", got, err)
	}
}
