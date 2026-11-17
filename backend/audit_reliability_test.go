package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// M7-E Phase 1.1: best-effort access logs must never fail silently; security
// decisions must roll back when their transactional audit row cannot be written.

func TestAuditAccessLogFailureIsObservableAndRecoverable(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	logger := NewAuditLogger(db)

	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)

	if _, err := db.Exec(`CREATE TRIGGER zz_block_audit BEFORE INSERT ON audit_log
		BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	before := auditWriteFailureCount()
	if err := logger.Log(AuditEvent{
		UserID: "user-admin", ClientID: "client-alpha",
		Action: "POST /api/v1/clients/client-alpha", Result: "error", CorrelationID: "corr-test",
	}); err == nil {
		t.Fatal("a failed audit insert must return an error")
	}
	if auditWriteFailureCount() != before+1 {
		t.Fatal("failed audit writes must be counted")
	}
	logged := buf.String()
	if !strings.Contains(logged, "audit write failed") {
		t.Fatalf("failure must be reported, got %q", logged)
	}
	if strings.Contains(logged, "client-alpha") || strings.Contains(logged, "user-admin") {
		t.Fatalf("failure log leaked identifiers: %q", logged)
	}

	// Recovery: removing the fault makes the next write succeed and stops the
	// counter from moving.
	if _, err := db.Exec(`DROP TRIGGER zz_block_audit`); err != nil {
		t.Fatal(err)
	}
	after := auditWriteFailureCount()
	if err := logger.Log(AuditEvent{UserID: "user-admin", Action: "TEST", Result: "success"}); err != nil {
		t.Fatalf("audit must recover: %v", err)
	}
	if auditWriteFailureCount() != after {
		t.Fatal("a successful write must not increment the failure counter")
	}
}

func TestAuditUnavailableDatabaseReturnsError(t *testing.T) {
	db := openM7DFI_DB(t)
	logger := NewAuditLogger(db)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := logger.Log(AuditEvent{UserID: "user-admin", Action: "TEST", Result: "success"}); err == nil {
		t.Fatal("a closed database must produce an audit error")
	}
}

func TestAccessLogFailureDoesNotFailTheRequest(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER zz_block_audit BEFORE INSERT ON audit_log
		BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)

	before := auditWriteFailureCount()
	h := NewAuditMiddleware(db, false).Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest("GET", "/api/v1/clients", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("access-log failure must not change the response, got %d", w.Code)
	}
	if auditWriteFailureCount() != before+1 {
		t.Fatal("access-log failure must be counted")
	}
	if !strings.Contains(buf.String(), "audit write failed") {
		t.Fatal("access-log failure must be reported")
	}
}

// A security decision whose transactional audit row cannot be written must not
// commit. Mapping approval is representative of the class.
func TestMappingApprovalRollsBackWhenAuditFails(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	_, dom := readySigmaDomain(t, db)
	m, err := CreateQRadarFieldMapping("user-admin", "client-alpha", dom.DomainID,
		"CommandLine", "command_line", "command_line", "Microsoft Windows Security Event Log", "4624", "1", "manual")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER zz_block_audit BEFORE INSERT ON audit_log
		BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := ApproveQRadarFieldMapping("user-admin", m.MappingID, "CEP export compared, ticket M7E-1"); err == nil {
		t.Fatal("approval must fail when its audit row cannot be written")
	}
	var approved string
	if err := db.QueryRow(`SELECT COALESCE(approved_by,'') FROM qradar_field_mappings WHERE mapping_id = ?`, m.MappingID).
		Scan(&approved); err != nil {
		t.Fatal(err)
	}
	if approved != "" {
		t.Fatalf("mapping approval must be rolled back, approved_by=%q", approved)
	}
}
