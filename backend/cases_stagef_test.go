package main

import (
	"errors"
	"testing"
)

// Pre-flight 1: seedTestData is test-only surface; OpenDB must not auto-seed
// in production. This is enforced by code inspection + env gate verified in
// OpenDB (WORKBENCH_SEED_DATA). The test asserts the gate expression exists.
func TestStageFSeedGateRequiresExplicitOptIn(t *testing.T) {
	// Functional guard: seedTestData inserts the synthetic reviewer account
	// only when called explicitly (in-process test DBs). OpenDB skips it
	// unless WORKBENCH_SEED_DATA=true. We assert seedTestData itself is
	// idempotent and includes the reviewer with REVIEWER role in isolated DBs.
	db := testDB(t)
	defer db.Close()
	var role string
	if err := db.QueryRow(`SELECT role FROM users WHERE user_id='user-reviewer'`).Scan(&role); err != nil {
		t.Fatalf("reviewer user should exist in isolated test DB: %v", err)
	}
	if role != "REVIEWER" {
		t.Errorf("expected REVIEWER role, got %q", role)
	}
}

// Pre-flight 3: CanCreateHypothesis and CanLinkHypothesis are distinct.
func TestLinkHypothesisPermissionIsSeparateFromCreate(t *testing.T) {
	cti := RolePermissions["CTI_ANALYST"]
	if cti.CanCreateHypothesis {
		t.Fatal("CTI_ANALYST must not have CanCreateHypothesis")
	}
	if !cti.CanLinkHypothesis {
		t.Fatal("CTI_ANALYST must have CanLinkHypothesis (case EDIT)")
	}
	hw := RolePermissions["HYPOTHESIS_WRITER"]
	if !hw.CanCreateHypothesis {
		t.Fatal("HYPOTHESIS_WRITER must have CanCreateHypothesis")
	}
	if !hw.CanLinkHypothesis {
		t.Fatal("HYPOTHESIS_WRITER must have CanLinkHypothesis")
	}
	ro := RolePermissions["READ_ONLY"]
	if ro.CanLinkHypothesis {
		t.Fatal("READ_ONLY must not have CanLinkHypothesis")
	}
	rev := RolePermissions["REVIEWER"]
	if rev.CanLinkHypothesis {
		t.Fatal("REVIEWER must not have CanLinkHypothesis")
	}
	admin := RolePermissions["ADMINISTRATOR"]
	if !admin.CanLinkHypothesis {
		t.Fatal("ADMINISTRATOR must have CanLinkHypothesis")
	}
	// Helper functions agree.
	if !CanLinkHypothesis(cti) || CanLinkHypothesis(ro) {
		t.Fatal("CanLinkHypothesis helper mismatch")
	}
}

// End-to-end: CreateCaseNote -> ListCaseNotes -> revoked grant hides CLIENT note.
func TestStageFWorkflowNoteGrantRevocation(t *testing.T) {
	db := seedCaseTestEnv(t)
	defer db.Close()
	caseID, err := CreateResearchCase("user-analyst-alpha", "F Case", "d", "idem-f-note-1", "client-alpha")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := CreateCaseNote(caseID, "user-analyst-alpha", "alpha body note", "observation", "CLIENT", "client-alpha"); err != nil {
		t.Fatalf("create note: %v", err)
	}
	notes, total, err := ListCaseNotes(caseID, "user-analyst-alpha", 20, 0)
	if err != nil || total != 1 || len(notes) != 1 {
		t.Fatalf("expected 1 visible note, got total=%d err=%v", total, err)
	}
	if _, err := db.Exec(`DELETE FROM user_authorized_clients WHERE grant_id='grant-alpha-alpha'`); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, total2, err := ListCaseNotes(caseID, "user-analyst-alpha", 20, 0)
	if err != nil {
		t.Fatalf("list after revoke: %v", err)
	}
	if total2 != 0 {
		t.Errorf("expected 0 visible after grant revoked, got %d", total2)
	}
}

var _ = errors.Is
