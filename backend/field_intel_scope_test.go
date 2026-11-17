package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// importInto uploads the same body into an explicitly chosen domain, reusing the
// given instance so cross-domain cases share a realistic console.
func importInto(t *testing.T, db *DB, instanceID, instanceName, domainName, body, sourceType, batchName string) (*QRadarImportBatch, error) {
	t.Helper()
	var inst *QRadarInstance
	if instanceID != "" {
		got, err := GetQRadarInstance(instanceID, "user-analyst-alpha")
		if err != nil {
			t.Fatalf("instance lookup: %v", err)
		}
		inst = got
	} else {
		created, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", instanceName, "qr.alpha.internal")
		if err != nil {
			// Unique per client+name: reuse the existing instance for this test.
			var id string
			if qerr := db.QueryRow(`SELECT instance_id FROM qradar_instances WHERE client_id='client-alpha' AND instance_name=?`, instanceName).Scan(&id); qerr != nil {
				t.Fatalf("instance: %v", err)
			}
			inst = &QRadarInstance{InstanceID: id}
		} else {
			inst = created
		}
	}
	dom, err := CreateQRadarDomain("user-analyst-alpha", inst.InstanceID, domainName, "production")
	if err != nil {
		var id string
		if qerr := db.QueryRow(`SELECT domain_id FROM qradar_domains WHERE instance_id=? AND domain_name=?`, inst.InstanceID, domainName).Scan(&id); qerr != nil {
			t.Fatalf("domain: %v", err)
		}
		dom = &QRadarDomain{DomainID: id}
	}
	// A domain is created UNASSIGNED; confirm it explicitly the way an operator
	// would before any client-scoped import.
	if b, berr := GetDomainBinding(dom.DomainID); berr == nil && b.VerificationStatus != "VERIFIED" {
		native := strconv.Itoa(1000 + int(atomic.AddInt32(&testNativeSeq, 1)))
		if _, uerr := UpdateDomainBinding("user-admin", dom.DomainID, DomainBindingUpdate{
			NativeQRadarDomainID: native, ClientID: "client-alpha", BindingKind: "CLIENT",
			Evidence: "synthetic test binding confirmed by administrator, ticket TEST-2",
			ExpectedRevision: b.Revision,
		}); uerr != nil {
			t.Fatalf("confirm binding: %v", uerr)
		}
	}
	return ProcessImportFile(memFile{bytes.NewReader([]byte(body))}, "sample.log",
		"user-analyst-alpha", "client-alpha", dom.DomainID, batchName, sourceType)
}

func TestImportIdentity_SameFileSameDomainIsIdempotent(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	first, err := upload(t, db, windowsFixture, "windows_kev")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ProcessImportFile(memFile{bytes.NewReader([]byte(windowsFixture))}, "sample.log",
		"user-analyst-alpha", "client-alpha", first.DomainID, "other name", "windows_kev")
	if err != nil {
		t.Fatal(err)
	}
	if second.BatchID != first.BatchID {
		t.Fatalf("replay into the same domain must be idempotent: %s vs %s", second.BatchID, first.BatchID)
	}
}

func TestImportIdentity_SameFileDifferentDomainIsDistinct(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	a, err := importInto(t, db, "", "QRadar-Prod", "Corporate", windowsFixture, "windows_kev", "Corporate import")
	if err != nil {
		t.Fatal(err)
	}
	b, err := importInto(t, db, "", "QRadar-Prod", "DMZ", windowsFixture, "windows_kev", "DMZ import")
	if err != nil {
		t.Fatal(err)
	}
	if a.BatchID == b.BatchID {
		t.Fatal("the same file imported into two domains must produce two batches")
	}
	if a.DomainID == b.DomainID {
		t.Fatal("test setup error: domains must differ")
	}
	// Each batch keeps its own rows bound to its own domain.
	ra, _ := ListQRadarImportRows(a.BatchID, "user-analyst-alpha")
	rb, _ := ListQRadarImportRows(b.BatchID, "user-analyst-alpha")
	if len(ra) != 1 || len(rb) != 1 {
		t.Fatalf("each domain batch must own its rows: %d / %d", len(ra), len(rb))
	}
}

func TestImportIdentity_SameFileDifferentSourceTypeIsDistinct(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	csvBody := "EventID,TaskName\n4624,Logon\n"
	a, err := importInto(t, db, "", "QRadar-Prod", "Corporate", csvBody, "csv", "as csv")
	if err != nil {
		t.Fatal(err)
	}
	b, err := importInto(t, db, "", "QRadar-Prod", "Corporate", csvBody, "txt", "as txt")
	if b != nil && a != nil && a.BatchID == b.BatchID {
		t.Fatal("different source type must not reuse a batch")
	}
	// txt is key=value only, so the CSV body is rejected there — but it must be
	// rejected on its own merits, not silently served as the CSV batch.
	if err == nil {
		t.Fatal("a CSV body declared as generic text must not be accepted as parsed data")
	}
}

func TestImportIdentity_DifferentClientsAreIsolated(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	a, err := upload(t, db, windowsFixture, "windows_kev")
	if err != nil {
		t.Fatal(err)
	}
	// beta owns its own instance/domain; same bytes must not collide.
	inst, _ := CreateQRadarInstance("user-analyst-beta", "client-beta", "QRadar-Beta", "qr.beta.internal")
	dom := mkDomain(t, db, "user-analyst-beta", inst.InstanceID, "Beta", "production")
	b, err := ProcessImportFile(memFile{bytes.NewReader([]byte(windowsFixture))}, "sample.log",
		"user-analyst-beta", "client-beta", dom.DomainID, "beta import", "windows_kev")
	if err != nil {
		t.Fatal(err)
	}
	if a.BatchID == b.BatchID {
		t.Fatal("batches must not be shared across clients")
	}
	if b.ClientID != "client-beta" {
		t.Fatalf("batch attributed to %s", b.ClientID)
	}
}

func TestImportIdentity_ConcurrentSubmissionsConverge(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	first, err := upload(t, db, windowsFixture, "windows_kev")
	if err != nil {
		t.Fatal(err)
	}
	// Sequential replay stands in for a second submission of the same file: the
	// unique identity index plus the pre-insert lookup must converge on one row.
	for i := 0; i < 3; i++ {
		b, err := ProcessImportFile(memFile{bytes.NewReader([]byte(windowsFixture))}, "dup.log",
			"user-analyst-alpha", "client-alpha", first.DomainID, "dup", "windows_kev")
		if err != nil {
			t.Fatalf("replay %d: %v", i, err)
		}
		if b.BatchID != first.BatchID {
			t.Fatalf("replay %d diverged: %s vs %s", i, b.BatchID, first.BatchID)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM qradar_import_batches WHERE client_id='client-alpha' AND file_hash=?`, first.FileHash).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected exactly one batch for the identity, got %d", n)
	}
	// The database itself must refuse a second row with the same identity.
	if _, err := db.Exec(`INSERT INTO qradar_import_batches
		(batch_id, client_id, domain_id, batch_name, source_type, file_hash, imported_by, processing_status)
		VALUES ('qib-forced-dup','client-alpha',?, 'dup','windows_kev',?, 'user-analyst-alpha','PENDING')`,
		first.DomainID, first.FileHash); err == nil {
		t.Fatal("unique identity index must reject a duplicate batch")
	}
}

func TestImportIdentity_RevokedGrantCannotReplay(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	first, err := upload(t, db, windowsFixture, "windows_kev")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM user_authorized_clients WHERE user_id='user-analyst-alpha' AND client_id='client-alpha'`); err != nil {
		t.Fatal(err)
	}
	_, err = ProcessImportFile(memFile{bytes.NewReader([]byte(windowsFixture))}, "sample.log",
		"user-analyst-alpha", "client-alpha", first.DomainID, "replay", "windows_kev")
	if !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("revoked grant must deny the replay before lookup, got %v", err)
	}
}

func TestImportIdentity_ObservationsStayBoundToDomain(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, _ := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr.alpha.internal")
	d1 := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	d2 := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "DMZ", "production")

	f1, err := CreateQRadarFieldDefinition("user-analyst-alpha", "client-alpha", d1.DomainID, "EventID", "system", "integer", "event_id", "4624", "event_id")
	if err != nil {
		t.Fatal(err)
	}
	f2, err := CreateQRadarFieldDefinition("user-analyst-alpha", "client-alpha", d2.DomainID, "EventID", "system", "integer", "event_id", "4624", "event_id")
	if err != nil {
		t.Fatal(err)
	}
	if f1.FieldID == f2.FieldID {
		t.Fatal("same field name in two domains must be two definitions")
	}
	o1, err := CreateQRadarFieldObservation("user-analyst-alpha", "client-alpha", d1.DomainID, f1.FieldID, true, false, false, "UNVERIFIED", "", "", "import A")
	if err != nil {
		t.Fatal(err)
	}
	// An observation for domain A cannot be smuggled onto domain B's field.
	if _, err := CreateQRadarFieldObservation("user-analyst-alpha", "client-alpha", d1.DomainID, f2.FieldID, true, false, false, "UNVERIFIED", "", "", "cross domain"); err == nil {
		t.Fatal("observation must not accept a field from another domain")
	}
	list1, _ := ListQRadarFieldObservations("user-analyst-alpha", "client-alpha", d1.DomainID)
	list2, _ := ListQRadarFieldObservations("user-analyst-alpha", "client-alpha", d2.DomainID)
	if len(list1) != 1 || len(list2) != 0 {
		t.Fatalf("observations leaked across domains: %d / %d (o1=%s)", len(list1), len(list2), o1.ObservationID)
	}
}

func TestRegistryWrite_RequiresImportCapability(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	// READ_ONLY has a grant but must not create registry rows.
	if _, err := CreateQRadarInstance("user-readonly", "client-alpha", "RO Instance", "x"); !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("READ_ONLY must not create an instance, got %v", err)
	}
	// HYPOTHESIS_WRITER has no implicit write right either.
	if _, err := CreateQRadarInstance("user-analyst-multi", "client-alpha", "Writer Instance", "x"); !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("HYPOTHESIS_WRITER must not create an instance, got %v", err)
	}
	// Analyst with a grant may.
	inst, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr.alpha.internal")
	if err != nil {
		t.Fatal(err)
	}
	dom := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	if _, err := CreateQRadarLogSourceType("user-reviewer", dom.DomainID, "WinEventLog"); !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("REVIEWER must not create inventory without the import capability, got %v", err)
	}
	if _, err := CreateQRadarFieldDefinition("user-readonly", "client-alpha", dom.DomainID, "X", "custom", "string", "", "", ""); !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("READ_ONLY must not create field definitions, got %v", err)
	}
	if _, err := CreateQRadarFieldObservation("user-readonly", "client-alpha", dom.DomainID, "qfd-x", true, false, false, "UNVERIFIED", "", "", ""); !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("READ_ONLY must not create observations, got %v", err)
	}
}

// TestMigrationUpgrade_From0011 proves the 0012-0014 upgrade is additive and
// non-destructive on a database that already holds Field Intelligence data.
func TestMigrationUpgrade_From0011(t *testing.T) {
	db := openSingleConnMemoryDB(t)
	defer db.Close()

	through0011 := []string{
		"migrations/0001_initial.sql",
		"migrations/0002_qradar_inventory.sql",
		"migrations/0003_evidence_graph.sql",
		"migrations/0004_p0_mcp_case.sql",
		"migrations/0005_m6_case_workspace.sql",
		"migrations/0006_cti_ingestion.sql",
		"migrations/0007_case_cti_reports.sql",
		"migrations/0008_relevance.sql",
		"migrations/0009_relevance_eval_time.sql",
		"migrations/0010_hunt_hypothesis.sql",
		"migrations/0011_field_intelligence.sql",
	}
	for _, m := range through0011 {
		if err := runMigration(db, m); err != nil {
			t.Fatalf("baseline %s: %v", m, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO clients (client_id, client_name, created_at) VALUES ('client-up','Upgrade Client',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users (user_id, username, email, password_hash, role, is_active, created_at, updated_at)
		VALUES ('user-up','up','up@example.invalid','x','CTI_ANALYST',1,datetime('now'),datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO qradar_instances (instance_id, client_id, instance_name) VALUES ('qi-up','client-up','QRadar-Up')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO qradar_domains (domain_id, instance_id, domain_name) VALUES ('qd-up','qi-up','Corporate')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO qradar_import_batches (batch_id, client_id, domain_id, batch_name, source_type, file_hash, imported_by, processing_status)
		VALUES ('qib-up','client-up','qd-up','legacy','csv','sha256:legacy','user-up','PENDING')`); err != nil {
		t.Fatal(err)
	}

	// Apply the forward migrations through the real runner.
	for _, m := range []string{
		"migrations/0012_field_intel_hardening.sql",
		"migrations/0013_field_intel_review_history.sql",
		"migrations/0014_import_identity_scope.sql",
		"migrations/0015_qradar_domain_bindings.sql",
		"migrations/0016_domain_binding_update_guards.sql",
		"migrations/0017_sigma_detection_ingestion.sql",
	} {
		if err := runMigration(db, m); err != nil {
			t.Fatalf("upgrade %s: %v", m, err)
		}
	}

	// Existing data preserved.
	var batchName, status string
	if err := db.QueryRow(`SELECT batch_name, processing_status FROM qradar_import_batches WHERE batch_id='qib-up'`).Scan(&batchName, &status); err != nil {
		t.Fatalf("legacy row lost: %v", err)
	}
	if batchName != "legacy" || status != "PENDING" {
		t.Fatalf("legacy row mutated: %s/%s", batchName, status)
	}
	// Added columns are present and defaulted.
	var parsedRows, redactedValues int
	if err := db.QueryRow(`SELECT parsed_rows, redacted_values FROM qradar_import_batches WHERE batch_id='qib-up'`).Scan(&parsedRows, &redactedValues); err != nil {
		t.Fatalf("0012 columns missing: %v", err)
	}
	if parsedRows != 0 || redactedValues != 0 {
		t.Fatalf("unexpected defaults: %d/%d", parsedRows, redactedValues)
	}
	// New identity index replaced the old one.
	var idx int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_qradar_import_batches_identity'`).Scan(&idx); err != nil || idx != 1 {
		t.Fatalf("identity index missing: %v %d", err, idx)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_qradar_import_batches_file_hash'`).Scan(&idx); err != nil || idx != 0 {
		t.Fatalf("old file_hash index still present: %v %d", err, idx)
	}
	// Tenant triggers still operational: a mismatched client/domain insert aborts.
	if _, err := db.Exec(`INSERT INTO qradar_import_batches (batch_id, client_id, domain_id, batch_name, source_type, file_hash, imported_by, processing_status)
		VALUES ('qib-bad','client-up','missing-domain','bad','csv','sha256:bad','user-up','PENDING')`); err == nil {
		t.Fatal("tenant trigger did not reject a foreign domain")
	}
	// 0015: legacy domains are backfilled as UNASSIGNED with inferred attribution
	// only, and their native id is not invented from the label.
	var kind, vstatus, inferred, native string
	if err := db.QueryRow(`SELECT binding_kind, verification_status, COALESCE(inferred_client_id, ''), COALESCE((SELECT native_qradar_domain_id FROM qradar_domains WHERE domain_id = 'qd-up'), '')
		FROM qradar_domain_bindings WHERE domain_id = 'qd-up'`).Scan(&kind, &vstatus, &inferred, &native); err != nil {
		t.Fatalf("backfill binding missing: %v", err)
	}
	if kind != "UNASSIGNED" || vstatus != "UNVERIFIED" {
		t.Fatalf("legacy domain must be UNASSIGNED/UNVERIFIED, got %s/%s", kind, vstatus)
	}
	if inferred != "client-up" {
		t.Fatalf("legacy attribution must be kept as inferred metadata, got %q", inferred)
	}
	if native != "" {
		t.Fatalf("native domain id must not be invented from domain_name, got %q", native)
	}
	// A batch for the unverified legacy domain is refused by the new trigger.
	if _, err := db.Exec(`INSERT INTO qradar_import_batches (batch_id, client_id, domain_id, batch_name, source_type, file_hash, imported_by, processing_status)
		VALUES ('qib-up2','client-up','qd-up','x','csv','sha256:up2','user-up','PENDING')`); err == nil {
		t.Fatal("unverified legacy domain must not accept tenant data")
	}
	// Binding history exists and is append-only.
	if _, err := db.Exec(`INSERT INTO qradar_domain_binding_history
		(history_id, binding_id, domain_id, instance_id, previous_kind, previous_status, new_kind, new_status, actor_id, evidence_reference, revision)
		VALUES ('qdbh-up','qdb-legacy-qd-up','qd-up','qi-up','UNASSIGNED','UNVERIFIED','UNASSIGNED','UNVERIFIED','user-up','upgrade check',1)`); err != nil {
		t.Fatalf("binding history unusable: %v", err)
	}
	if _, err := db.Exec(`UPDATE qradar_domain_binding_history SET evidence_reference='x'`); err == nil {
		t.Fatal("binding history must be append-only")
	}
	// Review history is usable and append-only.
	if _, err := db.Exec(`INSERT INTO qradar_import_reviews (review_id, batch_id, client_id, reviewer_id, decision, evidence, previous_status, new_status, created_at)
		VALUES ('qrv-up','qib-up','client-up','user-up','APPROVED','upgrade check','MAPPED','REVIEWED',datetime('now'))`); err != nil {
		t.Fatalf("0013 table unusable: %v", err)
	}
	if _, err := db.Exec(`UPDATE qradar_import_reviews SET evidence='x' WHERE review_id='qrv-up'`); err == nil {
		t.Fatal("review history must stay append-only after upgrade")
	}
	// Database integrity.
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	if rows.Next() {
		rows.Close()
		t.Fatal("foreign_key_check reported violations")
	}
	rows.Close()
	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("integrity_check=%q err=%v", integrity, err)
	}
	// Reruns are recorded no-ops, not re-executions.
	for _, m := range []string{
		"migrations/0012_field_intel_hardening.sql",
		"migrations/0013_field_intel_review_history.sql",
		"migrations/0014_import_identity_scope.sql",
	} {
		if err := runMigration(db, m); err != nil {
			t.Fatalf("rerun %s: %v", m, err)
		}
	}
}

// TestMigrationUpgrade_FailureRollsBack proves a failing migration leaves the
// database exactly as it was.
func TestMigrationUpgrade_FailureRollsBack(t *testing.T) {
	db := openSingleConnMemoryDB(t)
	defer db.Close()
	if err := runMigration(db, "migrations/0001_initial.sql"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO clients (client_id, client_name, created_at) VALUES ('client-rb','Rollback',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	bad := `CREATE TABLE qradar_probe (id TEXT PRIMARY KEY);
INSERT INTO qradar_probe (id) VALUES ('a');
SELECT * FROM table_that_does_not_exist;`
	probe := filepath.Join(t.TempDir(), "9999_rollback_probe.sql")
	if err := os.WriteFile(probe, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runMigration(db, probe); err == nil {
		t.Fatal("expected the probe migration to fail")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='qradar_probe'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("failed migration left a partial table behind")
	}
	var c int
	if err := db.QueryRow(`SELECT COUNT(*) FROM clients WHERE client_id='client-rb'`).Scan(&c); err != nil || c != 1 {
		t.Fatalf("pre-existing data damaged: %v %d", err, c)
	}
	var recorded int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version LIKE '%9999%'`).Scan(&recorded); err != nil && !strings.Contains(err.Error(), "no such table") {
		t.Fatal(err)
	}
	if recorded != 0 {
		t.Fatal("failed migration was recorded as applied")
	}
}
