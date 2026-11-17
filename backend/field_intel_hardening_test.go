package main

import (
	"bytes"
	"strings"
	"testing"
)

// memFile adapts bytes to multipart.File for the importer under test.
type memFile struct{ *bytes.Reader }

func (memFile) Close() error { return nil }

func upload(t *testing.T, db *DB, body, sourceType string) (*QRadarImportBatch, error) {
	t.Helper()
	inst, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-"+sourceType, "qr.alpha.internal")
	if err != nil {
		t.Fatalf("instance: %v", err)
	}
	dom := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	return ProcessImportFile(memFile{bytes.NewReader([]byte(body))}, "sample.log", "user-analyst-alpha", "client-alpha", dom.DomainID, "Import "+sourceType, sourceType)
}

const windowsFixture = `MSWinEventLog  Security  1  Mon Jan 01 00:00:00 2026  4624  Windows Security  SYSTEM  User  N/A  host-01  EventID=4624 SourceName=Microsoft-Windows-Security-Auditing TaskName=Logon TaskContent=<EventData><Data Name="TargetUserName">j.doe</Data><Data Name="IpAddress">10.1.2.3</Data><Data Name="HomeDirectory">https://portal.example.org/x?a=1&token=SECRET-TOKEN</Data><Data Name="Password">Hunter2!</Data></EventData> AccountName=j.doe CommandLine=powershell -enc SENSITIVE`

func TestM7D_Phase2_WindowsParserAndRedaction(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	b, err := upload(t, db, windowsFixture, "windows_kev")
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if b.ProcessingStatus != "MAPPED" {
		t.Fatalf("expected MAPPED, got %s (errors=%q)", b.ProcessingStatus, b.ImportErrors)
	}
	rows, err := ListQRadarImportRows(b.BatchID, "user-analyst-alpha")
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows: %v %d", err, len(rows))
	}
	row := rows[0]
	for _, field := range []string{"EventID", "TaskName", "TaskContent.TargetUserName"} {
		if !strings.Contains(row.ParsedJSON, field) {
			t.Fatalf("parsed payload missing %s: %s", field, row.ParsedJSON)
		}
	}
	// No literal secret may survive in anything persisted.
	persisted := row.ParsedJSON + row.RawLine
	for _, secret := range []string{"j.doe", "10.1.2.3", "Hunter2!", "SECRET-TOKEN", "portal.example.org", "-enc SENSITIVE"} {
		if strings.Contains(persisted, secret) {
			t.Fatalf("unredacted value persisted: %q in %s", secret, persisted)
		}
	}
	if !strings.Contains(persisted, "[REDACTED") {
		t.Fatalf("expected redaction placeholders, got %s", persisted)
	}
}

func TestM7D_Phase2_IISWithFields(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	body := `#Software: Microsoft Internet Information Services 10.0
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status
2026-01-01 00:00:00 10.0.0.5 GET /admin/default.aspx q=1 443 CONTOSO\jdoe 203.0.113.9 Mozilla/5.0 200`
	b, err := upload(t, db, body, "iis")
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	rows, _ := ListQRadarImportRows(b.BatchID, "user-analyst-alpha")
	if len(rows) != 1 || !strings.Contains(rows[0].ParsedJSON, "cs-method") {
		t.Fatalf("expected parsed IIS row, got %+v", rows)
	}
	if strings.Contains(rows[0].ParsedJSON, "jdoe") || strings.Contains(rows[0].ParsedJSON, "Mozilla") {
		t.Fatalf("IIS identifiers not redacted: %s", rows[0].ParsedJSON)
	}
	// Candidate mappings must come from the header, not from guesswork.
	maps, _ := ListQRadarImportFieldMaps(b.BatchID, "user-analyst-alpha")
	found := false
	for _, m := range maps {
		if m.RawFieldName == "cs-method" && m.SuggestedCEPField == "http_method" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected cs-method -> http_method candidate, got %+v", maps)
	}
}

func TestM7D_Phase2_IISWithoutFieldsRejected(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	body := "2026-01-01 00:00:00 10.0.0.5 GET /x 443 user 203.0.113.9 agent 200"
	if _, err := upload(t, db, body, "iis"); err == nil {
		t.Fatal("expected rejection: IIS without #Fields must not be positionally mapped")
	}
	bs, _ := ListQRadarImportBatches("user-analyst-alpha", "client-alpha")
	if len(bs) != 1 || bs[0].ProcessingStatus != "FAILED" {
		t.Fatalf("expected FAILED batch, got %+v", bs)
	}
	rows, _ := ListQRadarImportRows(bs[0].BatchID, "user-analyst-alpha")
	if len(rows) != 0 {
		t.Fatalf("ambiguous import must persist no rows, got %d", len(rows))
	}
}

func TestM7D_Phase2_CSVDuplicateHeaderRejected(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	if _, err := upload(t, db, "a,a\n1,2\n", "csv"); err == nil {
		t.Fatal("expected rejection for duplicate CSV header")
	}
}

func TestM7D_Phase2_OversizedUploadRejected(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	huge := strings.Repeat("A=1 ", (maxImportBytes/4)+64)
	if _, err := upload(t, db, huge, "txt"); err == nil {
		t.Fatal("expected rejection of oversized upload")
	}
}

func TestM7D_Phase2_DuplicateUploadIdempotent(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	first, err := upload(t, db, windowsFixture, "windows_kev")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ProcessImportFile(memFile{bytes.NewReader([]byte(windowsFixture))}, "again.log",
		"user-analyst-alpha", "client-alpha", first.DomainID, "duplicate", "windows_kev")
	if err != nil {
		t.Fatal(err)
	}
	if second.BatchID != first.BatchID {
		t.Fatalf("duplicate upload created a second batch: %s vs %s", second.BatchID, first.BatchID)
	}
}

func TestM7D_Phase2_ImportRowCrossClientDenied(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	b, err := upload(t, db, windowsFixture, "windows_kev")
	if err != nil {
		t.Fatal(err)
	}
	if err := CreateQRadarImportFieldMap("user-analyst-beta", b.BatchID, "EventID", "eventid", "event_id", "high", "", false); err == nil {
		t.Fatal("beta must not write field maps into an alpha batch")
	}
	if _, err := ListQRadarImportRows(b.BatchID, "user-analyst-beta"); err == nil {
		t.Fatal("beta must not read an alpha batch")
	}
}

func TestM7D_Phase2_VerifiedRequiresAuthorizedEvidence(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, _ := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr.alpha.internal")
	dom := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	fd, err := CreateQRadarFieldDefinition("user-analyst-alpha", "client-alpha", dom.DomainID, "EventID", "system", "integer", "event_id", "4624", "event_id")
	if err != nil {
		t.Fatal(err)
	}
	// A plain analyst cannot self-declare VERIFIED.
	if _, err := CreateQRadarFieldObservation("user-analyst-alpha", "client-alpha", dom.DomainID, fd.FieldID, true, true, true, "VERIFIED", "2026-01-01T00:00:00Z", "user-analyst-alpha", "ticket-1"); err == nil {
		t.Fatal("analyst must not be able to set AQL_VERIFIED")
	}
	// Reviewer, but impersonating someone else or missing evidence: refused.
	if _, err := CreateQRadarFieldObservation("user-reviewer", "client-alpha", dom.DomainID, fd.FieldID, true, true, true, "VERIFIED", "2026-01-01T00:00:00Z", "user-analyst-alpha", "ticket-1"); err == nil {
		t.Fatal("reviewer must attest under their own identity")
	}
	if _, err := CreateQRadarFieldObservation("user-reviewer", "client-alpha", dom.DomainID, fd.FieldID, true, true, true, "VERIFIED", "2026-01-01T00:00:00Z", "user-reviewer", ""); err == nil {
		t.Fatal("verification without evidence must be refused")
	}
	// Proper manual attestation succeeds and stays marked as manual.
	o, err := CreateQRadarFieldObservation("user-reviewer", "client-alpha", dom.DomainID, fd.FieldID, true, true, true, "VERIFIED", "2026-01-01T00:00:00Z", "user-reviewer", "ticket-1: AQL SELECT event_id")
	if err != nil {
		t.Fatalf("expected authorized manual attestation, got %v", err)
	}
	if o.AQLVerificationStatus != "VERIFIED" || o.VerifiedBy != "user-reviewer" {
		t.Fatalf("unexpected observation: %+v", o)
	}
}

func TestM7D_Phase2_ReviewRequiresParsedRows(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, _ := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr.alpha.internal")
	dom := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	b, err := CreateQRadarImportBatch("user-analyst-alpha", "client-alpha", dom.DomainID, "empty", "csv", "sha256:empty")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReviewQRadarImportBatch("user-reviewer", b.BatchID, "APPROVED", ""); err == nil {
		t.Fatal("a batch with no parsed rows must not be reviewable")
	}
}

func TestM7D_Phase2_ApproveMappingRequiresReviewer(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, _ := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr.alpha.internal")
	dom := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	m, err := CreateQRadarFieldMapping("user-analyst-alpha", "client-alpha", dom.DomainID, "EventCode", "event_id", "event_id", "Windows", "4624", "1", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApproveQRadarFieldMapping("user-analyst-alpha", m.MappingID, "self"); err == nil {
		t.Fatal("analyst must not approve a mapping")
	}
	ok, err := ApproveQRadarFieldMapping("user-reviewer", m.MappingID, "ticket-9 reviewed values")
	if err != nil {
		t.Fatalf("reviewer approval: %v", err)
	}
	if ok.Origin != "manual" {
		t.Fatalf("approved mapping must leave candidate state, got origin=%s", ok.Origin)
	}
}
