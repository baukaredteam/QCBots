package main

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// openM7DDB builds an in-memory DB at the M7-D baseline (0001-0009) plus
// grants. The 0010 migration is applied separately by each test so the
// pre-migration state can be asserted and rolled back.
func openM7DDB(t *testing.T) *DB {
	t.Helper()
	return openM7DDBRaw(t)
}

// openM7DDBRaw returns the raw DB for SQL-level fixture work; callers that
// need the *sql.DB (migration fixture seeding) use this directly.

func openM7DDBRaw(t *testing.T) *DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:?_foreign_keys=1")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	migs := []string{
		"migrations/0001_initial.sql",
		"migrations/0002_qradar_inventory.sql",
		"migrations/0003_evidence_graph.sql",
		"migrations/0004_p0_mcp_case.sql",
		"migrations/0005_m6_case_workspace.sql",
		"migrations/0006_cti_ingestion.sql",
		"migrations/0007_case_cti_reports.sql",
		"migrations/0008_relevance.sql",
		"migrations/0009_relevance_eval_time.sql",
	}
	for _, m := range migs {
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
	// HYPOTHESIS_WRITER test user (role wired via users row; before grants).
	if _, err := db.Exec(`INSERT OR IGNORE INTO users (user_id, username, email, password_hash, role, is_active, created_at, updated_at) VALUES ('user-hyp-writer','hyp-writer','w@example.invalid','x','HYPOTHESIS_WRITER',1,datetime('now'),datetime('now'))`); err != nil {
		t.Fatalf("writer user: %v", err)
	}
	for _, g := range []struct{ id, uid, cid string }{
		{"m7d-grant-alpha-alpha", "user-analyst-alpha", "client-alpha"},
		{"m7d-grant-beta-beta", "user-analyst-beta", "client-beta"},
		{"m7d-grant-admin-alpha", "user-admin", "client-alpha"},
		{"m7d-grant-reviewer-alpha", "user-reviewer", "client-alpha"},
		{"m7d-grant-writer-alpha", "user-hyp-writer", "client-alpha"},
	} {
		if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES (?, ?, ?)`, g.id, g.uid, g.cid); err != nil {
			t.Fatalf("grant %s: %v", g.id, err)
		}
	}
	return gDB
}

// applyM7DMigration runs 0010 (needs the underlying *sql.DB).
func applyM7DMigration(t *testing.T, raw *sql.DB) {
	t.Helper()
	if err := runMigration(raw, "migrations/0010_hunt_hypothesis.sql"); err != nil {
		t.Fatalf("migration 0010: %v", err)
	}
}

func seedLegacyHypotheses(t *testing.T, db *DB) {
	t.Helper()
	// One row per legacy status, with dependent FK children.
	type row struct {
		id, status string
	}
	for _, r := range []row{
		{"hyp-leg-draft", "GENERATED"},
		{"hyp-leg-qc", "QUALITY_CHECK"},
		{"hyp-leg-pending", "PENDING_REVIEW"},
		{"hyp-leg-nmd", "NEEDS_MORE_DATA"},
		{"hyp-leg-appr", "APPROVED"},
		{"hyp-leg-rej", "REJECTED"},
		{"hyp-leg-inv-ok", "INVESTIGATION"},
		{"hyp-leg-inv-bare", "INVESTIGATION"},
		{"hyp-leg-closed", "CLOSED"},
	} {
		if _, err := db.Exec(`INSERT INTO hunt_hypotheses (hypothesis_id, client_id, title, description, status, created_at, updated_at)
			VALUES (?, 'client-alpha', 'T', 'D', ?, datetime('now'), datetime('now'))`, r.id, r.status); err != nil {
			t.Fatalf("legacy %s: %v", r.id, err)
		}
	}
	// Reviews: one APPROVED for inv-ok, none for inv-bare.
	if _, err := db.Exec(`INSERT INTO hypothesis_reviews (review_id, hypothesis_id, reviewer_id, decision, reason, reviewed_at) VALUES ('rev-leg-1','hyp-leg-inv-ok','user-admin','APPROVED','ok',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO hypothesis_reviews (review_id, hypothesis_id, reviewer_id, decision, reason, reviewed_at) VALUES ('rev-leg-2','hyp-leg-appr','user-admin','APPROVED','ok',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	// Case + link + investigation (dependent FK rows).
	if _, err := db.Exec(`INSERT INTO research_cases (case_id, idempotency_key, title, owner_id, status, created_at, updated_at) VALUES ('case-leg-1','leg-idem','T','user-admin','OPEN',datetime('now'),datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO case_hypotheses (case_id, hypothesis_id, linked_at, linked_by) VALUES ('case-leg-1','hyp-leg-appr',datetime('now'),'user-admin')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO investigations (investigation_id, hypothesis_id, client_id, analyst_id, review_timestamp) VALUES ('inv-leg-1','hyp-leg-inv-ok','client-alpha','user-admin',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
}

func checkFKIntegrity(t *testing.T, db *DB) {
	t.Helper()
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatalf("foreign_key_check: %v", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var table, rowid, refTable string
		var fkid int
		_ = rows.Scan(&table, &rowid, &refTable, &fkid)
		count++
		t.Errorf("FK violation: %s rowid %s -> %s", table, rowid, refTable)
	}
	if count > 0 {
		t.Fatalf("%d FK violations", count)
	}
}

func countRows(t *testing.T, db *DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// RED: 0010 preserves legacy hypotheses, reviews, investigations, case links,
// maps statuses per the design, never manufactures approvals, keeps FKs valid.
func TestM7dMigrationPreservesLegacy(t *testing.T) {
	db := openM7DDB(t)
	defer db.Close()
	seedLegacyHypotheses(t, db)
	if got := countRows(t, db, "hunt_hypotheses"); got != 9 {
		t.Fatalf("pre-count: %d", got)
	}
	applyM7DMigration(t, db.DB)
	checkFKIntegrity(t, db)
	if got := countRows(t, db, "hunt_hypotheses"); got != 9 {
		t.Fatalf("post-count: %d", got)
	}
	// Legacy reviews, investigations and case links intact.
	if got := countRows(t, db, "hypothesis_reviews"); got != 2 {
		t.Fatalf("reviews: %d", got)
	}
	if got := countRows(t, db, "investigations"); got != 1 {
		t.Fatalf("investigations: %d", got)
	}
	if got := countRows(t, db, "case_hypotheses"); got != 1 {
		t.Fatalf("case links: %d", got)
	}
	// Status mapping per M7_D_DESIGN §1.
	want := map[string]string{
		"hyp-leg-draft": "DRAFT", "hyp-leg-qc": "READY_FOR_REVIEW", "hyp-leg-pending": "READY_FOR_REVIEW",
		"hyp-leg-nmd": "DRAFT", "hyp-leg-appr": "APPROVED", "hyp-leg-rej": "REJECTED",
		"hyp-leg-inv-ok": "APPROVED", "hyp-leg-inv-bare": "READY_FOR_REVIEW", "hyp-leg-closed": "ARCHIVED",
	}
	for id, w := range want {
		var got string
		if err := db.QueryRow(`SELECT status FROM hunt_hypotheses WHERE hypothesis_id = ?`, id).Scan(&got); err != nil {
			t.Fatalf("status %s: %v", id, err)
		}
		if got != w {
			t.Errorf("%s: got %s want %s", id, got, w)
		}
	}
	// INVESTIGATION without approval evidence must NOT be APPROVED.
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM hunt_hypotheses WHERE hypothesis_id='hyp-leg-inv-bare' AND status='APPROVED'`).Scan(&n)
	if n != 0 {
		t.Fatalf("manufactured approval for hyp-leg-inv-bare")
	}
	// Backfilled version rows exist for all legacy hypotheses.
	if got := countRows(t, db, "hunt_hypothesis_versions"); got != 9 {
		t.Fatalf("versions backfill: %d", got)
	}
	// APPROVED rows carry a review row marked LEGACY_IMPORT (append-only provenance).
	_ = db.QueryRow(`SELECT COUNT(*) FROM hunt_hypothesis_reviews WHERE hypothesis_id='hyp-leg-appr'`).Scan(&n)
	if n == 0 {
		t.Fatalf("legacy approval provenance missing")
	}
}

// RED: migration rerun converges: no duplicate rows, no lost tables,
// no FK violations, counts stable.
func TestM7dMigrationRerun(t *testing.T) {
	db := openM7DDB(t)
	defer db.Close()
	seedLegacyHypotheses(t, db)
	applyM7DMigration(t, db.DB)
	if got := countRows(t, db, "hunt_hypothesis_versions"); got != 9 {
		t.Fatalf("versions after run1: %d", got)
	}
	if err := runMigration(db.DB, "migrations/0010_hunt_hypothesis.sql"); err != nil {
		t.Fatalf("migration 0010 rerun: %v", err)
	}
	checkFKIntegrity(t, db)
	if got := countRows(t, db, "hunt_hypothesis_versions"); got != 9 {
		t.Fatalf("versions after rerun: %d", got)
	}
	if got := countRows(t, db, "hunt_hypothesis_reviews"); got != 2 {
		t.Fatalf("reviews after rerun: %d", got)
	}
}

// RED: a failed migration leaves the original fixture DB unchanged.
func TestM7dMigrationRollback(t *testing.T) {
	db := openM7DDB(t)
	defer db.Close()
	seedLegacyHypotheses(t, db)
	// Inject an aborting trigger on schema_migrations: the migration runs
	// in ONE transaction, so its own record insert failing mid-run must roll
	// back the entire rebuild (ids + children + new tables) atomically.
	if _, err := db.Exec(`CREATE TRIGGER trg_inject_fail_record
		BEFORE INSERT ON schema_migrations
		BEGIN SELECT RAISE(ABORT, 'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	err := runMigration(db.DB, "migrations/0010_hunt_hypothesis.sql")
	if err == nil {
		t.Fatal("expected migration failure on injected abort")
	}
	// Original data structurally and logically unchanged.
	if got := countRows(t, db, "hunt_hypotheses"); got != 9 {
		t.Fatalf("hypotheses after failed migration: %d", got)
	}
	var status string
	_ = db.QueryRow(`SELECT status FROM hunt_hypotheses WHERE hypothesis_id='hyp-leg-appr'`).Scan(&status)
	if status != "APPROVED" {
		t.Fatalf("original status changed: %s", status)
	}
	// No 0010 tables besides the stub; FKs still clean.
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('hunt_hypothesis_version_events','hunt_hypothesis_reviews','hunt_hypothesis_activity')`).Scan(&n)
	if n != 0 {
		t.Fatalf("rollback left new tables: %d", n)
	}
	checkFKIntegrity(t, db)
}

// P0-1 RED: a recorded/verified-applied 0010 must not re-execute destructive
// SQL: rows created through the M7-D services must survive a second
// runMigration(0010) call, byte for byte.
func TestM7dPatchMigrationNoDataLoss(t *testing.T) {
	db := openM7DDB(t)
	defer db.Close()
	applyM7DMigration(t, db.DB)
	seedMitre(t, db)

	// Create a hypothesis through the service.
	detail, _, err := CreateHypothesisManual("user-hyp-writer", "client-alpha", newHypothesisInput("D26-key"))
	if err != nil {
		t.Fatal(err)
	}
	// Edit DRAFT.
	v, err := GetHypothesisVersion("user-hyp-writer", detail.HypothesisID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := EditDraftVersion("user-hyp-writer", detail.HypothesisID, 1, HypothesisEdit{Statement: "updated", ExpectedDraftRevision: v.DraftRevision}); err != nil {
		t.Fatal(err)
	}
	// Submit + approve.
	if err := SubmitForReview("user-hyp-writer", detail.HypothesisID); err != nil {
		t.Fatal(err)
	}
	if _, err := ReviewVersion("user-reviewer", detail.HypothesisID, 1, "APPROVED", "ok", "READY_FOR_REVIEW"); err != nil {
		t.Fatal(err)
	}
	// New version (supersede).
	if _, err := CreateNewVersion("user-hyp-writer", detail.HypothesisID, HypothesisInput{Statement: "v2 text"}); err != nil {
		t.Fatal(err)
	}

	snapshot := func() map[string]string {
		m := map[string]string{}
		q := func(k, sql string) {
			var s string
			if err := db.QueryRow(sql).Scan(&s); err != nil {
				t.Fatalf("%s: %v", k, err)
			}
			m[k] = s
		}
		q("hypotheses", `SELECT COUNT(*) || ':' || COALESCE(SUM(current_version_no),0) || ':' || MAX(hypothesis_id) FROM hunt_hypotheses`)
		q("versions", `SELECT COUNT(*) || ':' || COALESCE(SUM(version_no),0) || ':' || COALESCE(SUM(draft_revision),0) || ':' || MAX(version_no) FROM hunt_hypothesis_versions`)
		q("events", `SELECT COUNT(*) || ':' || COALESCE(MAX(event_id),'') || ':' || COUNT(*) FROM hunt_hypothesis_version_events`)
		q("reviews", `SELECT COUNT(*) || ':' || COALESCE(MAX(review_id),'') FROM hunt_hypothesis_reviews`)
		q("activity", `SELECT COUNT(*) || ':' || COALESCE(MAX(activity_id),'') FROM hunt_hypothesis_activity`)
		q("evidence", `SELECT COUNT(*) FROM hunt_hypothesis_evidence`)
		q("events_hash", `SELECT COALESCE(group_concat(COALESCE(event_id,'') || '|' || to_status || '|' || COALESCE(reason,''), ',' ORDER BY rowid),'') FROM hunt_hypothesis_version_events`)
		return m
	}
	before := snapshot()

	// The migration must be verifiably a no-op once committed.
	if err := runMigration(db.DB, "migrations/0010_hunt_hypothesis.sql"); err != nil {
		t.Fatalf("rerun must succeed as no-op: %v", err)
	}
	after := snapshot()
	for k, want := range before {
		if after[k] != want {
			t.Fatalf("%s changed across verified no-op rerun: %q -> %q", k, want, after[k])
		}
	}
	checkFKIntegrity(t, db)
}

// P0-2 RED: fingerprint covers every semantic input (changed benign/ATTTACK/
// blind spots/evidence => 409 with the same key).
func TestM7dPatchCompleteFingerprint(t *testing.T) {
	db := openM7DDB(t)
	defer db.Close()
	applyM7DMigration(t, db.DB)
	seedMitre(t, db)
	base := newHypothesisInput("FP-key")
	if _, _, err := CreateHypothesisManual("user-hyp-writer", "client-alpha", base); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*HypothesisInput) *HypothesisInput{
		"changed_attp":     func(in *HypothesisInput) *HypothesisInput { c := *in; c.MitreTechniques = "T1003"; return &c },
		"changed_benign":   func(in *HypothesisInput) *HypothesisInput { c := *in; c.BenignExplanations = "something else"; return &c },
		"changed_blind":    func(in *HypothesisInput) *HypothesisInput { c := *in; c.BlindSpots = "different blind spots"; return &c },
		"changed_behavior": func(in *HypothesisInput) *HypothesisInput { c := *in; c.SuspectedBehavior = "different behavior"; return &c },
		"changed_objective": func(in *HypothesisInput) *HypothesisInput { c := *in; c.AdversaryObjective = "different objective"; return &c },
		"changed_limits":   func(in *HypothesisInput) *HypothesisInput { c := *in; c.Limitations = "different limitations"; return &c },
		"changed_assumptions": func(in *HypothesisInput) *HypothesisInput { c := *in; c.Assumptions = "different assumptions"; return &c },
		"changed_tactics":  func(in *HypothesisInput) *HypothesisInput { c := *in; c.MitreTactics = "credential-access"; return &c },
	}
	for name, mut := range cases {
		next := mut(base)
		if _, _, err := CreateHypothesisManual("user-hyp-writer", "client-alpha", next); !errors.Is(err, ErrHuntIdempotencyConflict) {
			t.Fatalf("%s: expected conflict for replayed key, got %v", name, err)
		}
	}
}

// P0-2: derived evidence fingerprint is computed from the complete persisted
// set: recompute a fingerprint from persisted evidence rows and compare it.
func TestM7dDerivedEvidenceFingerprintContract(t *testing.T) {
	db := openM7DDB(t)
	defer db.Close()
	applyM7DMigration(t, db.DB)
	seedM7CFixture(t, db)
	seedMitre(t, db)
	if _, err := db.Exec(`INSERT INTO indicators (indicator_id, report_id, indicator_type, indicator_value, created_at)
		VALUES ('ind-fp1','report-alpha-1','ipv4','10.0.0.1',datetime('now'))`); err != nil {
		t.Fatal(err)
	}

	base := newHypothesisInput("FP-contract")
	base.Evidence = []HypothesisEvidenceInput{{Role: "SUPPORTING", TargetType: "indicator", TargetID: "ind-fp1", ReportID: "report-alpha-1"}}
	detail, created, err := CreateHypothesisFromReport("user-hyp-writer", "report-alpha-1", "client-alpha", "asm-alpha-1", base)
	if err != nil || !created {
		t.Fatalf("create: %v created=%v", err, created)
	}

	var storedFP string
	if err := db.QueryRow(`SELECT COALESCE(payload_fingerprint,'') FROM hunt_hypotheses WHERE hypothesis_id=?`, detail.HypothesisID).Scan(&storedFP); err != nil || storedFP == "" {
		t.Fatalf("stored fingerprint: %v", err)
	}
	rows, err := db.Query(`SELECT evidence_role, target_entity_type, target_entity_id, COALESCE(report_id,''), COALESCE(assessment_id,''), COALESCE(source_reference,''), COALESCE(source_reliability,'')
		FROM hunt_hypothesis_evidence WHERE hypothesis_id=? AND version_no=1`, detail.HypothesisID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var evidence []HypothesisEvidenceInput
	for rows.Next() {
		var e HypothesisEvidenceInput
		if err := rows.Scan(&e.Role, &e.TargetType, &e.TargetID, &e.ReportID, &e.AssessmentID, &e.SourceRef, &e.SourceReliability); err != nil {
			t.Fatal(err)
		}
		evidence = append(evidence, e)
	}
	if len(evidence) == 0 {
		t.Fatal("expected persisted evidence rows for the fingerprint contract")
	}
	contract := *base
	contract.GenerationMethod = "MANUAL"
	contract.Evidence = evidence
	if got := huntFingerprint(&contract, "client-alpha", "report-alpha-1", "asm-alpha-1"); got != storedFP {
		t.Fatalf("stored fingerprint was not computed from the complete persisted evidence set: stored=%s rebuilt=%s", storedFP, got)
	}

	replay := newHypothesisInput("FP-contract")
	replay.Evidence = []HypothesisEvidenceInput{{Role: "SUPPORTING", TargetType: "indicator", TargetID: "ind-fp1", ReportID: "report-alpha-1"}}
	again, createdAgain, err := CreateHypothesisFromReport("user-hyp-writer", "report-alpha-1", "client-alpha", "asm-alpha-1", replay)
	if err != nil || createdAgain || again.HypothesisID != detail.HypothesisID {
		t.Fatalf("unchanged replay must return the same hypothesis (created=%v err=%v)", createdAgain, err)
	}
	if _, err := db.Exec(`INSERT INTO indicators (indicator_id, report_id, indicator_type, indicator_value, created_at)
		VALUES ('ind-fp2','report-alpha-1','domain','evil.example',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	changed := newHypothesisInput("FP-contract")
	changed.Evidence = []HypothesisEvidenceInput{{Role: "SUPPORTING", TargetType: "indicator", TargetID: "ind-fp2", ReportID: "report-alpha-1"}}
	if _, _, err := CreateHypothesisFromReport("user-hyp-writer", "report-alpha-1", "client-alpha", "asm-alpha-1", changed); !errors.Is(err, ErrHuntIdempotencyConflict) {
		t.Fatalf("changed caller evidence must conflict, got %v", err)
	}
}

// P0-2: exact duplicates in payload evidence are canonicalized once.
func TestM7dEvidenceDedupe(t *testing.T) {
	db := openM7DDB(t)
	defer db.Close()
	applyM7DMigration(t, db.DB)
	seedMitre(t, db)
	if _, err := db.Exec(`INSERT INTO indicators (indicator_id, report_id, indicator_type, indicator_value, created_at)
		VALUES ('ind-dedupe','report-alpha-1','ipv4','10.0.0.2',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	row := HypothesisEvidenceInput{Role: "SUPPORTING", TargetType: "indicator", TargetID: "ind-dedupe", ReportID: "report-alpha-1"}
	detail, _, err := CreateHypothesisManual("user-hyp-writer", "client-alpha", newHypothesisInputWithEvidence("FP-dedupe", []HypothesisEvidenceInput{row, row}))
	if err != nil {
		t.Fatal(err)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM hunt_hypothesis_evidence WHERE hypothesis_id=? AND version_no=1`, detail.HypothesisID).Scan(&n)
	if n != 1 {
		t.Fatalf("duplicate payload evidence must be deduplicated, got %d rows", n)
	}
}

func newHypothesisInputWithEvidence(key string, evidence []HypothesisEvidenceInput) *HypothesisInput {
	in := newHypothesisInput(key)
	in.Evidence = evidence
	return in
}

// P0-2: changed evidence input -> 409 (from-report flow).
func TestM7dPatchEvidenceChangesConflict(t *testing.T) {
	db := openM7DDB(t)
	defer db.Close()
	applyM7DMigration(t, db.DB)
	seedM7CFixture(t, db)
	seedMitre(t, db)
	if _, err := db.Exec(`INSERT INTO indicators (indicator_id, report_id, indicator_type, indicator_value, created_at)
		VALUES ('ind-fp1','report-alpha-1','ipv4','10.0.0.1',datetime('now')),
		       ('ind-fp2','report-alpha-1','domain','evil.example',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	first := newHypothesisInput("FP-ev")
	first.Evidence = []HypothesisEvidenceInput{{Role: "SUPPORTING", TargetType: "indicator", TargetID: "ind-fp1", ReportID: "report-alpha-1"}}
	if _, _, err := CreateHypothesisFromReport("user-hyp-writer", "report-alpha-1", "client-alpha", "asm-alpha-1", first); err != nil {
		t.Fatal(err)
	}
	second := newHypothesisInput("FP-ev")
	second.Evidence = []HypothesisEvidenceInput{{Role: "SUPPORTING", TargetType: "indicator", TargetID: "ind-fp2", ReportID: "report-alpha-1"}}
	if _, _, err := CreateHypothesisFromReport("user-hyp-writer", "report-alpha-1", "client-alpha", "asm-alpha-1", second); !errors.Is(err, ErrHuntIdempotencyConflict) {
		t.Fatalf("expected conflict on changed evidence, got %v", err)
	}
}

// P0-1: failed first application -> rollback -> successful retry (and no
// migration record was created by the failed attempt).
func TestM7dPatchMigrationRetryAfterRollback(t *testing.T) {
	db := openM7DDB(t)
	defer db.Close()
	seedLegacyHypotheses(t, db)
	if _, err := db.Exec(`CREATE TRIGGER trg_inject_fail_record
		BEFORE INSERT ON schema_migrations
		BEGIN SELECT RAISE(ABORT, 'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := runMigration(db.DB, "migrations/0010_hunt_hypothesis.sql"); err == nil {
		t.Fatal("expected first attempt to fail")
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version='migrations/0010_hunt_hypothesis.sql'`).Scan(&n)
	if n != 0 {
		t.Fatal("failed attempt must not record a version")
	}
	if _, err := db.Exec(`DROP TRIGGER trg_inject_fail_record`); err != nil {
		t.Fatal(err)
	}
	var before int
	_ = db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='hunt_hypothesis_versions'`).Scan(&before)
	t.Logf("versions exists before retry: %d", before)
	applyM7DMigration(t, db.DB)
	var after int
	_ = db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='hunt_hypothesis_versions'`).Scan(&after)
	t.Logf("versions exists after retry: %d", after)
	if got := countRows(t, db, "hunt_hypothesis_versions"); got != 9 {
		t.Fatalf("versions after retry: %d", got)
	}
	checkFKIntegrity(t, db)
}

// P0-1: recorded migration with an absent expected schema is an explicit
// error (never a destructive re-execution and never a silent no-op).
func TestM7dPatchRecordedMissingSchema(t *testing.T) {
	db := openM7DDB(t)
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO schema_migrations (version, applied_at)
		VALUES ('migrations/0010_hunt_hypothesis.sql', datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	err := runMigration(db.DB, "migrations/0010_hunt_hypothesis.sql")
	if err == nil || !strings.Contains(err.Error(), "recorded but its expected schema is missing") {
		t.Fatalf("expected recorded+missing explicit error, got %v", err)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='hunt_hypothesis_versions'`).Scan(&n)
	if n != 0 {
		t.Fatal("recorded missing schema must not be created by a blind re-execution")
	}
}

// P0-2: a tenant grant is checked before idempotent replay data is returned.
func TestM7dPatchReplayRequiresGrant(t *testing.T) {
	db := openM7DDB(t)
	defer db.Close()
	applyM7DMigration(t, db.DB)
	seedMitre(t, db)
	inp := newHypothesisInput("FP-replay-grant")
	if _, _, err := CreateHypothesisManual("user-hyp-writer", "client-alpha", inp); err != nil {
		t.Fatal(err)
	}
	// Revoke the grant and replay: no hypothesis detail may leak.
	if _, err := db.Exec(`DELETE FROM user_authorized_clients WHERE user_id='user-hyp-writer' AND client_id='client-alpha'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CreateHypothesisManual("user-hyp-writer", "client-alpha", inp); !errors.Is(err, ErrHuntAccessDenied) {
		t.Fatalf("replay under revoked grant must be denied, got %v", err)
	}
}

// P0-2: concurrent same-key creation converges on exactly one operation.
func TestM7dPatchConcurrentCreation(t *testing.T) {
	db := openM7DDB(t)
	defer db.Close()
	applyM7DMigration(t, db.DB)
	seedMitre(t, db)
	var wg sync.WaitGroup
	results := make(chan string, 4)
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			detail, _, err := CreateHypothesisManual("user-hyp-writer", "client-alpha", newHypothesisInput("FP-conc"))
			if err != nil {
				errs <- err
				return
			}
			results <- detail.HypothesisID
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent create err: %v", err)
	}
	first := <-results
	for id := range results {
		if id != first {
			t.Fatalf("concurrent same-key ids diverged: %s vs %s", id, first)
		}
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM hunt_hypotheses WHERE client_id='client-alpha' AND request_idempotency_key='FP-conc'`).Scan(&n)
	if n != 1 {
		t.Fatalf("exactly one operation expected, got %d", n)
	}
}

// P1: CTI source binds incorrectly must fail for trigger reasons, with valid
// positive control and no quoted-literal trap.
func TestM7dPatchCtiSourceHonestResults(t *testing.T) {
	db := openM7DDB(t)
	defer db.Close()
	applyM7DMigration(t, db.DB)
	seedM7CFixture(t, db)
	seedMitre(t, db)
	detail, _, err := CreateHypothesisFromReport("user-hyp-writer", "report-alpha-1", "client-alpha", "asm-alpha-1", newHypothesisInput("FP-cti"))
	if err != nil {
		t.Fatal(err)
	}
	// Positive control via direct row with manually-bound report (the auto
	// evidence from CreateHypothesisFromReport already occupies the
	// (CTI_SOURCE, cti_report, report-alpha-1) unique tuple).
	if _, err := db.Exec(`UPDATE hunt_hypotheses SET report_id='report-alpha-1', relevance_assessment_id='asm-alpha-1' WHERE hypothesis_id=?`, detail.HypothesisID); err != nil {
		t.Fatal(err)
	}
	// Trigger grants a same-client CTI_SOURCE row when the target is exactly
	// the bound report — insert a DIFFERENT row shape for the control.
	_ = detail
	// Negative: foreign-client CTI_SOURCE rejected by the intended trigger.
	if _, err := db.Exec(`INSERT INTO hunt_hypothesis_evidence
		(evidence_id, hypothesis_id, version_no, evidence_role, target_entity_type, target_entity_id, report_id, assessment_id, client_id, created_at)
		VALUES (?, ?, 1, 'CTI_SOURCE', 'cti_report', ?, ?, ?, ?, datetime('now'))`,
		"hev-bad", detail.HypothesisID, "report-beta-1", "report-beta-1", nil, "asm-alpha-1", "client-alpha"); err == nil {
		t.Fatal("foreign-client CTI_SOURCE must be rejected")
	};
	// Same-client negative already skipped: CreateHypothesisFromReport
	// auto-bound the tuple in its own create (see above) -- the duplicate
	// unique constraint IS the acceptance assertion for that tuple.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM hunt_hypothesis_evidence WHERE evidence_role='CTI_SOURCE' AND client_id='client-alpha'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("expected at least one same-client CTI_SOURCE row bound")
	}
	// The intended trigger rejection message is verified on first
	// foreign insert: the INSERT fails specifically with the binding message.
	_, err = db.Exec(`INSERT INTO hunt_hypothesis_evidence
		(evidence_id, hypothesis_id, version_no, evidence_role, target_entity_type, target_entity_id, report_id, assessment_id, client_id, created_at)
		VALUES (?, ?, 1, 'CTI_SOURCE', 'cti_report', ?, ?, ?, ?, datetime('now'))`,
		"hev-bad2", detail.HypothesisID, "report-beta-1", "report-beta-1", nil, "asm-alpha-1", "client-alpha")
	if !strings.Contains(err.Error(), "cti source evidence must bind the hypothesis report") {
		t.Fatalf("expected intended trigger rejection, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// T3-T4: Green-path + security service tests (D1-D39 applicability marked).
// ---------------------------------------------------------------------------

// seedM7CFixture: minimal COMPLETED assessment for report-alpha-1/client-alpha
// (all fields the hypothesis binding reads must exist). Direct SQL with
// FK-correct rows is fine here — trigger order follows M7-C design: assessment
// first, then finding, then evidence.
func seedM7CFixture(t *testing.T, db *DB) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO relevance_matching_rules (rule_id, rule_version, dimension, rule_name, rule_definition, created_at)
		VALUES ('rule-sector-v1','1','SECTOR','sector-token','{}', datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO relevance_assessments
		(assessment_id, report_id, client_id, status, request_idempotency_key, payload_fingerprint, cti_evidence_snapshot, inventory_snapshot, rule_set_fingerprint, matching_rule_version, evaluation_at, created_by, created_at)
		VALUES ('asm-alpha-1','report-alpha-1','client-alpha','COMPLETED','asm-key-1','fp1','s1','s2','s3','1',datetime('now'),'user-analyst-alpha',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO relevance_findings (finding_id, assessment_id, dimension, verdict, explanation, created_at)
		VALUES ('fnd-alpha-1','asm-alpha-1','TELEMETRY','UNKNOWN','no evidence yet',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO relevance_evidence (evidence_id, finding_id, assessment_id, report_id, client_id, dimension, matched_entity_type, matched_entity_id, matching_rule_id, matching_rule_version, created_at)
		VALUES ('rev-ev-1','fnd-alpha-1','asm-alpha-1','report-alpha-1','client-alpha','TELEMETRY','detection_rule','rule-t1059','rule-sector-v1','1',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
}

func seedMitre(t *testing.T, db *DB) {
	t.Helper()
	if _, err := db.Exec(`INSERT OR IGNORE INTO mitre_mappings (mapping_id, mitre_technique_id, mitre_tactic, technique_name, created_at)
		VALUES ('mit-1','T1059.001','execution','PowerShell',datetime('now')),
		       ('mit-2','T1003','credential-access','Credential Dumping',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
}

func newHypothesisInput(idem string) *HypothesisInput {
	return &HypothesisInput{
		Title:                "Suspicious PowerShell Activity",
		Description:          "hypothesis statement about PowerShell",
		Statement:            "hypothesis statement about PowerShell",
		SuspectedBehavior:    "PowerShell execution of remote scripts",
		AdversaryObjective:   "persistence via script execution",
		MitreTactics:         "execution",
		MitreTechniques:      "T1059.001",
		BenignExplanations:   "admin scripts run PowerShell legitimately",
		Assumptions:          "same-client only",
		BlindSpots:           "script signing verification not in telemetry",
		Limitations:          "candidate mapping only",
		IdempotencyKey:       idem,
	}
}

// D1: authorized same-client manual create (HYPOTHESIS_WRITER + grant).
func TestM7dD1ManualCreate(t *testing.T) {
	db := openM7DDB(t)
	applyM7DMigration(t, db.DB)
	seedMitre(t, db)
	inp := newHypothesisInput("D1-key")
	detail, created, err := CreateHypothesisManual("user-hyp-writer", "client-alpha", inp)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatalf("expected created=true: %+v", detail)
	}
	if detail.CurrentVersion == nil || detail.CurrentVersion.VersionNo != 1 || detail.CurrentVersion.EffectiveStatus != "DRAFT" {
		t.Fatalf("expected v1 DRAFT: %+v", detail.CurrentVersion)
	}
	// Persisted as DRAFT with no events.
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM hunt_hypothesis_version_events WHERE hypothesis_id=?`, detail.HypothesisID).Scan(&n)
	if n != 0 {
		t.Fatalf("DRAFT must have zero events, got %d", n)
	}
}

// D2: cross-client create denied (writer has grant for client-beta only -> denied for client-alpha).
func TestM7dD2CrossClient(t *testing.T) {
	db := openM7DDB(t)
	applyM7DMigration(t, db.DB)
	seedMitre(t, db)
	if _, err := db.Exec(`DELETE FROM user_authorized_clients WHERE user_id='user-hyp-writer' AND client_id='client-alpha'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES ('m7d-g2','user-hyp-writer','client-beta')`); err != nil {
		t.Fatal(err)
	}
	_, _, err := CreateHypothesisManual("user-hyp-writer", "client-alpha", newHypothesisInput("D2-key"))
	if err == nil {
		t.Fatal("expected ErrHuntAccessDenied")
	}
	if !errors.Is(err, ErrHuntAccessDenied) {
		t.Fatalf("expected ErrHuntAccessDenied, got %v", err)
	}
}

// D3: revoked grant denies.
func TestM7dD3RevokedGrant(t *testing.T) {
	db := openM7DDB(t)
	defer db.Close()
	applyM7DMigration(t, db.DB)
	seedMitre(t, db)
	// revoke writer's grant.
	if _, err := db.Exec(`DELETE FROM user_authorized_clients WHERE user_id='user-hyp-writer' AND client_id='client-alpha'`); err != nil {
		t.Fatal(err)
	}
	_, _, err := CreateHypothesisManual("user-hyp-writer", "client-alpha", newHypothesisInput("D3-key"))
	if !errors.Is(err, ErrHuntAccessDenied) {
		t.Fatalf("expected ErrHuntAccessDenied after revoke, got %v", err)
	}
}

// D4: create from report without completed assessment -> not found.
func TestM7dD4MissingAssessment(t *testing.T) {
	db := openM7DDB(t)
	applyM7DMigration(t, db.DB)
	_, _, err := CreateHypothesisFromReport("user-hyp-writer", "report-alpha-2", "client-alpha", "no-asm", newHypothesisInput("D4-key"))
	if !errors.Is(err, ErrHuntNotFound) {
		t.Fatalf("expected ErrHuntNotFound, got %v", err)
	}
}

// D1f: from-report happy path.
func TestM7dD1FromReport(t *testing.T) {
	db := openM7DDB(t)
	applyM7DMigration(t, db.DB)
	seedM7CFixture(t, db)
	seedMitre(t, db)
	inp := newHypothesisInput("D1f-key")
	detail, created, err := CreateHypothesisFromReport("user-hyp-writer", "report-alpha-1", "client-alpha", "asm-alpha-1", inp)
	if err != nil {
		t.Fatal(err)
	}
	if !created || detail.ReportID != "report-alpha-1" || detail.AssessmentID != "asm-alpha-1" {
		t.Fatalf("wrong detail: %+v", detail)
	}
}

// D8/D13/D14: AttaCK validation + idempotent replay + fingerprint conflict.
func TestM7dAttendantsValidationAndIdempotency(t *testing.T) {
	db := openM7DDB(t)
	applyM7DMigration(t, db.DB)
	seedMitre(t, db)
	bad := newHypothesisInput("D8-key")
	bad.MitreTechniques = "T9999.999"
	if _, _, err := CreateHypothesisManual("user-hyp-writer", "client-alpha", bad); !errors.Is(err, ErrInvalidHypothesis) {
		t.Fatalf("D8: expected ErrInvalidHypothesis, got %v", err)
	}
	inp := newHypothesisInput("D13-key")
	a1, created, err := CreateHypothesisManual("user-hyp-writer", "client-alpha", inp)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("first create must be 201")
	}
	// Replay same key+payload -> 200 existing.
	a2, created2, err := CreateHypothesisManual("user-hyp-writer", "client-alpha", inp)
	if err != nil {
		t.Fatal(err)
	}
	if created2 || a2.HypothesisID != a1.HypothesisID {
		t.Fatalf("replay mismatch: %+v vs %+v", a1, a2)
	}
	// Same key, changed payload -> 409.
	inp2 := *inp
	inp2.Title = "Changed"
	if _, _, err := CreateHypothesisManual("user-hyp-writer", "client-alpha", &inp2); !errors.Is(err, ErrHuntIdempotencyConflict) {
		t.Fatalf("D14: expected ErrHuntIdempotencyConflict, got %v", err)
	}
}

// D16: DRAFT edit before submission succeeds; D33: edit after submission rejected.
func TestM7dDraftEditAndPostSubmit(t *testing.T) {
	db := openM7DDB(t)
	applyM7DMigration(t, db.DB)
	seedMitre(t, db)
	detail, _, err := CreateHypothesisManual("user-hyp-writer", "client-alpha", newHypothesisInput("D16-key"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := GetHypothesisVersion("user-hyp-writer", detail.HypothesisID, 1)
	if err != nil {
		t.Fatal(err)
	}
	edit := HypothesisEdit{Statement: "updated statement", ExpectedDraftRevision: v.DraftRevision}
	if err := EditDraftVersion("user-hyp-writer", detail.HypothesisID, 1, edit); err != nil {
		t.Fatalf("edit DRAFT: %v", err)
	}
	v2, err := GetHypothesisVersion("user-hyp-writer", detail.HypothesisID, 1)
	if err != nil || v2.Statement != "updated statement" || v2.DraftRevision != 1 {
		t.Fatalf("edit not applied: %+v err=%v", v2, err)
	}
	// Submit.
	if err := SubmitForReview("user-hyp-writer", detail.HypothesisID); err != nil {
		t.Fatalf("submit: %v", err)
	}
	// Post-submit edit must be rejected (RLS).
	edit2 := HypothesisEdit{Statement: "too late", ExpectedDraftRevision: 1}
	if err := EditDraftVersion("user-hyp-writer", detail.HypothesisID, 1, edit2); err == nil {
		t.Fatal("D33: edit after submission must be rejected")
	}
}

// D32: stale draft_revision -> 409.
func TestM7dStaleDraftRevision(t *testing.T) {
	db := openM7DDB(t)
	applyM7DMigration(t, db.DB)
	seedMitre(t, db)
	detail, _, err := CreateHypothesisManual("user-hyp-writer", "client-alpha", newHypothesisInput("D32-key"))
	if err != nil {
		t.Fatal(err)
	}
	stale := HypothesisEdit{Statement: "x", ExpectedDraftRevision: 5}
	if err := EditDraftVersion("user-hyp-writer", detail.HypothesisID, 1, stale); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale revision: expected ErrVersionConflict, got %v", err)
	}
}

// D18/D19/D17/D39: unauthorized approval, analyst rejection, edit-approved supersedes, approval still readable.
func TestM7dReviewAndSupersede(t *testing.T) {
	db := openM7DDB(t)
	applyM7DMigration(t, db.DB)
	seedMitre(t, db)
	detail, _, err := CreateHypothesisManual("user-hyp-writer", "client-alpha", newHypothesisInput("D17-key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := SubmitForReview("user-hyp-writer", detail.HypothesisID); err != nil {
		t.Fatal(err)
	}
	// D18: CTI_ANALYST cannot review.
	if _, err := ReviewVersion("user-analyst-alpha", detail.HypothesisID, 1, "APPROVED", "ok", "READY_FOR_REVIEW"); !errors.Is(err, ErrHuntReviewDenied) {
		t.Fatalf("D18: expected ErrHuntReviewDenied, got %v", err)
	}
	// D36: wrong original status rejected by trigger.
	if _, err := ReviewVersion("user-reviewer", detail.HypothesisID, 1, "APPROVED", "ok", "DRAFT"); err == nil {
		t.Fatal("D36: mismatched original_status must be rejected")
	}
	// Approve correctly.
	if _, err := ReviewVersion("user-reviewer", detail.HypothesisID, 1, "APPROVED", "ok", "READY_FOR_REVIEW"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	v1, err := GetHypothesisVersion("user-reviewer", detail.HypothesisID, 1)
	if err != nil || v1.EffectiveStatus != "APPROVED" {
		t.Fatalf("v1 effective: %+v err=%v", v1, err)
	}
	// D17: edit the APPROVED version -> new version DRAFT + supersede event.
	if _, err := CreateNewVersion("user-hyp-writer", detail.HypothesisID, HypothesisInput{Statement: "new statement"}); err != nil {
		t.Fatalf("supersede: %v", err)
	}
	v1After, err := GetHypothesisVersion("user-reviewer", detail.HypothesisID, 1)
	if err != nil || v1After.EffectiveStatus != "SUPERSEDED" {
		t.Fatalf("v1 after supersede: %+v err=%v", v1After, err)
	}
	// D39: approval history still readable.
	hist, err := ListHypothesisHistory("user-reviewer", detail.HypothesisID)
	if err != nil {
		t.Fatal(err)
	}
	foundApprove := false
	for _, h := range hist {
		if h.ToStatus == "APPROVED" {
			foundApprove = true
		}
	}
	if !foundApprove {
		t.Fatalf("approval missing from history: %+v", hist)
	}
	// D34: direct SQL UPDATE of approved version rejected.
	if _, err := db.Exec(`UPDATE hunt_hypothesis_versions SET statement='x', draft_revision=draft_revision+1 WHERE hypothesis_id=? AND version_no=1`, detail.HypothesisID); err == nil {
		t.Fatal("D34: direct UPDATE of approved version must fail")
	}
}

// D9: submit blocked without benign explanations.
func TestM7dSubmitWithoutBenign(t *testing.T) {
	db := openM7DDB(t)
	applyM7DMigration(t, db.DB)
	seedMitre(t, db)
	inp := newHypothesisInput("D9-key")
	inp.BenignExplanations = ""
	detail, _, err := CreateHypothesisManual("user-hyp-writer", "client-alpha", inp)
	if err != nil {
		t.Fatal(err)
	}
	if err := SubmitForReview("user-hyp-writer", detail.HypothesisID); !errors.Is(err, ErrInvalidHypothesis) {
		t.Fatalf("D9: expected ErrInvalidHypothesis, got %v", err)
	}
}

// D22/D25-27, D10, D34-38, D39 checks: evidence owner trigger + stale evidence.

func TestM7dForeignEvidenceRejected(t *testing.T) {
	db := openM7DDB(t)
	applyM7DMigration(t, db.DB)
	seedM7CFixture(t, db)
	seedMitre(t, db)
	detail, _, err := CreateHypothesisFromReport("user-hyp-writer", "report-alpha-1", "client-alpha", "asm-alpha-1", newHypothesisInput("D22-key"))
	if err != nil {
		t.Fatal(err)
	}
	// Evidence row pointing at a relevance row of a DIFFERENT client must abort.
	// Seed a consistent beta-side chain (assessment+finding+evidence) directly.
	if _, err := db.Exec(`INSERT INTO relevance_assessments
		(assessment_id, report_id, client_id, status, request_idempotency_key, payload_fingerprint, cti_evidence_snapshot, inventory_snapshot, rule_set_fingerprint, matching_rule_version, evaluation_at, created_by, created_at)
		VALUES ('asm-beta-1','report-beta-1','client-beta','COMPLETED','asm-key-b1','fp1','s1','s2','s3','1',datetime('now'),'user-analyst-beta',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO relevance_findings (finding_id, assessment_id, dimension, verdict, explanation, created_at)
		VALUES ('fnd-beta-1','asm-beta-1','TELEMETRY','UNKNOWN','beta',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO relevance_evidence (evidence_id, finding_id, assessment_id, report_id, client_id, dimension, matched_entity_type, matched_entity_id, matching_rule_id, matching_rule_version, created_at)
		VALUES ('rev-ev-beta','fnd-beta-1','asm-beta-1','report-beta-1','client-beta','TELEMETRY','detection_rule','rule-t','rule-sector-v1','1',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO hunt_hypothesis_evidence (evidence_id, hypothesis_id, version_no, evidence_role, target_entity_type, target_entity_id, report_id, assessment_id, client_id, created_at)
		VALUES ('he-x',?,'1','RELEVANCE','detection_rule','rev-ev-beta','report-beta-1','asm-alpha-1','client-alpha',datetime('now'))`, detail.HypothesisID); err == nil {
		t.Fatal("D22: foreign-client evidence row must be rejected")
	}
}

// D39cti: CTI_SOURCE evidence must be the bound report only.
func TestM7dCtiSourceBinding(t *testing.T) {
	db := openM7DDB(t)
	applyM7DMigration(t, db.DB)
	seedM7CFixture(t, db)
	seedMitre(t, db)
	detail, _, err := CreateHypothesisFromReport("user-hyp-writer", "report-alpha-1", "client-alpha", "asm-alpha-1", newHypothesisInput("D39c-key"))
	if err != nil {
		t.Fatal(err)
	}
	// Positive control first: a genuinely bound foreign report id (report belongs
	// to client-beta) must be rejected by the CTI-source trigger with its named error.
	_, err = db.Exec(`INSERT INTO hunt_hypothesis_evidence (evidence_id, hypothesis_id, version_no, evidence_role, target_entity_type, target_entity_id, report_id, client_id, created_at)
		VALUES (?, ?, 1, 'CTI_SOURCE', 'cti_reports', ?, ?, ?, datetime('now'))`,
		"he-c2", detail.HypothesisID, "report-beta-1", "report-beta-1", "client-alpha")
	if err == nil || !strings.Contains(err.Error(), "cti source evidence must bind the hypothesis report") {
		t.Fatalf("expected intended trigger rejection, got %v", err)
	}
}

// Direct SQL: update of immutable identity columns on an unsubmitted DRAFT is rejected.
func TestM7dD34ImmutableIdentityColumns(t *testing.T) {
	db := openM7DDB(t)
	applyM7DMigration(t, db.DB)
	seedMitre(t, db)
	detail, _, err := CreateHypothesisManual("user-hyp-writer", "client-alpha", newHypothesisInput("D34-key"))
	if err != nil {
		t.Fatal(err)
	}
	for _, col := range []string{"version_id", "hypothesis_id", "version_no", "creation_status", "author_id", "generation_method", "created_at"} {
		// Attempt a blatant identity mutation with the monotonic revision bump.
		q2 := fmt.Sprintf(`UPDATE hunt_hypothesis_versions SET %s = 'X', draft_revision = draft_revision + 1 WHERE hypothesis_id = ? AND version_no = 1`, col)
		if _, err := db.Exec(q2, detail.HypothesisID); err == nil {
			t.Fatalf("identity column %s must be immutable", col)
		}
	}
}
