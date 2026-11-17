package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// seedParsedBatch creates a MAPPED batch with one parsed row using the real
// importer, so every gate test works against a realistic record.
func seedParsedBatch(t *testing.T, db *DB) *QRadarImportBatch {
	t.Helper()
	b, err := upload(t, db, windowsFixture, "windows_kev")
	if err != nil {
		t.Fatalf("seed batch: %v", err)
	}
	if b.ProcessingStatus != "MAPPED" {
		t.Fatalf("seed batch status %s", b.ProcessingStatus)
	}
	return b
}

func TestGate_ImportCapabilityEnforcedInService(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, _ := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr.alpha.internal")
	dom := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")

	// READ_ONLY holds a client grant but no import capability.
	_, err := ProcessImportFile(memFile{bytes.NewReader([]byte(windowsFixture))}, "x.log",
		"user-readonly", "client-alpha", dom.DomainID, "ro import", "windows_kev")
	if !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("READ_ONLY import must be denied at service level, got %v", err)
	}
	// REVIEWER may review but not import.
	_, err = ProcessImportFile(memFile{bytes.NewReader([]byte(windowsFixture))}, "x.log",
		"user-reviewer", "client-alpha", dom.DomainID, "reviewer import", "windows_kev")
	if !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("REVIEWER import must be denied, got %v", err)
	}
	// ADMINISTRATOR without a grant for this client is still denied.
	_, err = ProcessImportFile(memFile{bytes.NewReader([]byte(windowsFixture))}, "x.log",
		"user-admin", "client-beta", "", "admin foreign", "windows_kev")
	if !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("ADMIN without grant must be denied, got %v", err)
	}
}

func TestGate_ReviewCapabilityEnforcedInService(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	b := seedParsedBatch(t, db)
	ev := "checked 1 row against ticket SOC-42"

	for _, uid := range []string{"user-analyst-alpha", "user-readonly"} {
		if _, err := ReviewQRadarImportBatch(uid, b.BatchID, "APPROVED", ev); !errors.Is(err, ErrFieldAccessDenied) {
			t.Fatalf("%s must not review, got %v", uid, err)
		}
		if _, err := PublishQRadarImportBatch(uid, b.BatchID); !errors.Is(err, ErrFieldAccessDenied) {
			t.Fatalf("%s must not publish, got %v", uid, err)
		}
	}
	if _, err := ReviewQRadarImportBatch("user-reviewer", b.BatchID, "APPROVED", ev); err != nil {
		t.Fatalf("reviewer review: %v", err)
	}
	if _, err := PublishQRadarImportBatch("user-reviewer", b.BatchID); err != nil {
		t.Fatalf("reviewer publish: %v", err)
	}
}

func TestGate_ForeignBatchDenied(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	b := seedParsedBatch(t, db)
	// reviewer has no grant on client-beta and this batch is client-alpha's
	if _, err := ReviewQRadarImportBatch("user-reviewer", b.BatchID, "APPROVED", "checked one row by hand"); err != nil {
		t.Fatalf("owner review should pass: %v", err)
	}
	// unknown batch id must look the same as a foreign one
	if _, err := ReviewQRadarImportBatch("user-reviewer", "qib-does-not-exist", "APPROVED", "checked one row by hand"); !errors.Is(err, ErrFieldInventoryNotFound) {
		t.Fatalf("unknown batch must be not-found, got %v", err)
	}
	if err := CreateQRadarImportFieldMap("user-reviewer", b.BatchID, "EventID", "eventid", "event_id", "high", "e", false); !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("reviewer without import capability must not write field maps, got %v", err)
	}
}

func TestGate_EvidenceMustBeMeaningful(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	b := seedParsedBatch(t, db)
	for _, ev := range []string{"", "  ", "ok", "approved", "LGTM", "n/a"} {
		if _, err := ReviewQRadarImportBatch("user-reviewer", b.BatchID, "APPROVED", ev); !errors.Is(err, ErrFieldImportInvalid) {
			t.Fatalf("evidence %q must be rejected, got %v", ev, err)
		}
	}
	if _, err := ReviewQRadarImportBatch("user-reviewer", b.BatchID, "APPROVED", "row 1 checked, ticket SOC-42"); err != nil {
		t.Fatalf("real evidence rejected: %v", err)
	}
}

func TestGate_RepeatReviewIdempotentAndConflict(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	b := seedParsedBatch(t, db)
	ev := "row 1 compared with ticket SOC-7"
	first, err := ReviewQRadarImportBatch("user-reviewer", b.BatchID, "APPROVED", ev)
	if err != nil {
		t.Fatal(err)
	}
	again, err := ReviewQRadarImportBatch("user-reviewer", b.BatchID, "APPROVED", ev)
	if err != nil || again.ProcessingStatus != first.ProcessingStatus {
		t.Fatalf("repeat approval must be idempotent: %v %v", again, err)
	}
	if _, err := ReviewQRadarImportBatch("user-reviewer", b.BatchID, "REJECTED", "changed my mind about SOC-7"); !errors.Is(err, ErrFieldConflict) {
		t.Fatalf("a later decision must conflict, got %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM qradar_import_reviews WHERE batch_id = ?`, b.BatchID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected exactly one history row, got %d", n)
	}
}

func TestGate_ReviewHistoryIsAppendOnly(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	b := seedParsedBatch(t, db)
	if _, err := ReviewQRadarImportBatch("user-reviewer", b.BatchID, "APPROVED", "row 1 reviewed for SOC-9"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE qradar_import_reviews SET evidence = 'rewritten' WHERE batch_id = ?`, b.BatchID); err == nil {
		t.Fatal("history rows must not be updatable")
	}
	if _, err := db.Exec(`DELETE FROM qradar_import_reviews WHERE batch_id = ?`, b.BatchID); err == nil {
		t.Fatal("history rows must not be deletable")
	}
}

func TestGate_AuditWrittenWithDecision(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	b := seedParsedBatch(t, db)
	if _, err := ReviewQRadarImportBatch("user-reviewer", b.BatchID, "APPROVED", "row 1 reviewed for SOC-11"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'IMPORT_REVIEW' AND resource = ?`, b.BatchID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected one audit row, got %d", n)
	}
}

func TestGate_MappingApprovalImmutable(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, _ := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr.alpha.internal")
	dom := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	m, err := CreateQRadarFieldMapping("user-analyst-alpha", "client-alpha", dom.DomainID, "EventCode", "event_id", "event_id", "Windows", "4624", "1", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApproveQRadarFieldMapping("user-reviewer", m.MappingID, "short"); !errors.Is(err, ErrFieldImportInvalid) {
		t.Fatalf("weak evidence must be rejected, got %v", err)
	}
	ev := "values compared with QRadar CEP export, ticket SOC-12"
	if _, err := ApproveQRadarFieldMapping("user-reviewer", m.MappingID, ev); err != nil {
		t.Fatal(err)
	}
	// Same reviewer, same mapping: idempotent, no second history row.
	if _, err := ApproveQRadarFieldMapping("user-reviewer", m.MappingID, ev); err != nil {
		t.Fatalf("repeat approval must be idempotent: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM qradar_mapping_reviews WHERE mapping_id = ?`, m.MappingID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected one mapping review row, got %d", n)
	}
	// A different reviewer must not silently replace the approval.
	if _, err := ApproveQRadarFieldMapping("user-admin", m.MappingID, "re-approving under my own name"); !errors.Is(err, ErrFieldConflict) {
		t.Fatalf("second reviewer must conflict, got %v", err)
	}
}

func TestGate_FieldMapRejectsInventedCEP(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	b := seedParsedBatch(t, db)
	if err := CreateQRadarImportFieldMap("user-analyst-alpha", b.BatchID, "EventID", "eventid", "not_a_real_cep", "high", "e", false); !errors.Is(err, ErrFieldImportInvalid) {
		t.Fatalf("invented CEP must be rejected, got %v", err)
	}
	if err := CreateQRadarImportFieldMap("user-analyst-alpha", b.BatchID, "  ", "eventid", "event_id", "high", "e", false); !errors.Is(err, ErrFieldImportInvalid) {
		t.Fatalf("empty raw field must be rejected, got %v", err)
	}
	if err := CreateQRadarImportFieldMap("user-analyst-alpha", b.BatchID, "EventID", "eventid", "event_id", "certain", "e", false); !errors.Is(err, ErrFieldImportInvalid) {
		t.Fatalf("unknown confidence must be rejected, got %v", err)
	}
}

// TestGate_ImporterIsOnlyWriter proves the redaction promise survives a hostile
// payload: whatever the caller sends, only redacted values are stored.
func TestGate_ImporterIsOnlyWriter(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	hostile := "EventID=4624 AccountName=root Password=p@ss TargetUserName=admin IpAddress=172.16.5.9 CommandLine=curl -H Authorization: Bearer abc123secret payload"
	b, err := upload(t, db, hostile, "windows_kev")
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	rows, err := ListQRadarImportRows(b.BatchID, "user-analyst-alpha")
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows: %v %d", err, len(rows))
	}
	blob := rows[0].ParsedJSON + rows[0].RawLine
	for _, secret := range []string{"root", "p@ss", "admin", "172.16.5.9", "abc123secret"} {
		if strings.Contains(blob, secret) {
			t.Fatalf("secret %q persisted: %s", secret, blob)
		}
	}
}

func TestGate_AdminNeedsGrantAndRevocationRevokes(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	b := seedParsedBatch(t, db)
	ev := "row 1 checked against ticket SOC-31"

	// ADMINISTRATOR with a grant may review.
	if _, err := ReviewQRadarImportBatch("user-admin", b.BatchID, "APPROVED", ev); err != nil {
		t.Fatalf("admin with grant should review: %v", err)
	}
	// Revoke the grant: the same call must now be denied even for admin.
	if _, err := db.Exec(`DELETE FROM user_authorized_clients WHERE user_id = 'user-admin' AND client_id = 'client-alpha'`); err != nil {
		t.Fatal(err)
	}
	if _, err := ReviewQRadarImportBatch("user-admin", b.BatchID, "APPROVED", ev); !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("revoked grant must deny admin, got %v", err)
	}
	if _, err := PublishQRadarImportBatch("user-admin", b.BatchID); !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("revoked grant must deny publish, got %v", err)
	}
}
