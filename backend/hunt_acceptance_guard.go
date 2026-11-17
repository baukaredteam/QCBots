package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// validateAcceptanceDBPath is the only gate that allows the acceptance seeder to
// create a file. It never deletes or truncates anything: a path that already
// exists in any form (regular file, directory, symlink, broken symlink) is
// refused. Failures leave every pre-existing file untouched.
//
// Rules, in order:
//  1. the target path and the authorized directory are required;
//  2. the authorized directory must resolve, exist and be a directory;
//  3. it must be inside the OS temporary root and outside the application tree;
//  4. the target's parent must resolve and stay inside the authorized directory;
//  5. nothing may exist at the target path;
//  6. the canonical result must not be a production database path.
func validateAcceptanceDBPath(target, authorizedDir string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("acceptance database path is required")
	}
	if strings.TrimSpace(authorizedDir) == "" {
		return "", fmt.Errorf("an authorized temporary directory is required")
	}

	authAbs, err := filepath.Abs(authorizedDir)
	if err != nil {
		return "", fmt.Errorf("resolving authorized directory: %w", err)
	}
	authReal, err := filepath.EvalSymlinks(authAbs)
	if err != nil {
		return "", fmt.Errorf("authorized directory is not resolvable: %w", err)
	}
	st, err := os.Stat(authReal)
	if err != nil {
		return "", fmt.Errorf("stat authorized directory: %w", err)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("authorized path is not a directory: %s", authReal)
	}

	tempAbs, err := filepath.Abs(os.TempDir())
	if err != nil {
		return "", fmt.Errorf("resolving the OS temporary directory: %w", err)
	}
	tempReal, err := filepath.EvalSymlinks(tempAbs)
	if err != nil {
		return "", fmt.Errorf("the OS temporary directory is not resolvable: %w", err)
	}
	if !pathWithin(tempReal, authReal) {
		return "", fmt.Errorf("authorized directory must be inside the OS temporary directory")
	}
	// Defence in depth: never accept a directory inside the application tree,
	// whatever the environment says.
	for _, root := range []string{"..", "../storage", "../config"} {
		abs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		real, err := filepath.EvalSymlinks(abs)
		if err != nil {
			continue
		}
		if pathWithin(real, authReal) {
			return "", fmt.Errorf("authorized directory must not be inside the application tree")
		}
	}

	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return "", fmt.Errorf("resolving target path: %w", err)
	}
	parentReal, err := filepath.EvalSymlinks(filepath.Dir(targetAbs))
	if err != nil {
		return "", fmt.Errorf("target directory is not resolvable: %w", err)
	}
	if !pathWithin(authReal, parentReal) {
		return "", fmt.Errorf("acceptance database must be created inside the authorized directory")
	}
	final := filepath.Join(parentReal, filepath.Base(targetAbs))
	if !pathWithin(authReal, final) {
		return "", fmt.Errorf("acceptance database escapes the authorized directory")
	}

	// Anything at the target path is a refusal: file, empty file, directory,
	// symlink (including a broken one) or junction.
	if fi, err := os.Lstat(final); err == nil {
		return "", fmt.Errorf("refusing to overwrite an existing path (%s): %s", fi.Mode().Type(), final)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("cannot inspect the target path: %w", err)
	}
	if real, err := filepath.EvalSymlinks(final); err == nil {
		return "", fmt.Errorf("refusing to overwrite an existing path: %s", real)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("cannot inspect the target path: %w", err)
	}

	if strings.EqualFold(filepath.Base(final), "workbench.db") {
		return "", fmt.Errorf("refusing to use the production database name")
	}
	if def, err := filepath.Abs(filepath.Join("..", "storage", "workbench.db")); err == nil {
		if strings.EqualFold(filepath.Clean(final), filepath.Clean(def)) {
			return "", fmt.Errorf("refusing to use the production database path")
		}
	}
	return final, nil
}

// pathWithin reports whether p is root or a descendant of root, after cleaning.
func pathWithin(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return !filepath.IsAbs(rel)
}
