package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func openM7DFI_DB(t *testing.T) *DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:?_journal_mode=WAL&_foreign_keys=1")
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
		"migrations/0010_hunt_hypothesis.sql",
		"migrations/0011_field_intelligence.sql",
		"migrations/0012_field_intel_hardening.sql",
		"migrations/0013_field_intel_review_history.sql",
		"migrations/0014_import_identity_scope.sql",
		"migrations/0015_qradar_domain_bindings.sql",
		"migrations/0016_domain_binding_update_guards.sql",
		"migrations/0017_sigma_detection_ingestion.sql",
		"migrations/0018_detection_translations.sql",
		"migrations/0019_hunt_plans.sql",
		"migrations/0020_hunt_plan_item_integrity.sql",
		"migrations/0021_hunt_plan_item_binding_owner.sql",
		"migrations/0022_manual_inventory_provenance.sql",
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
	if _, err := db.Exec(`INSERT OR IGNORE INTO users (user_id, username, email, password_hash, role, is_active, created_at, updated_at) VALUES ('user-readonly','readonly','ro@example.invalid','x','READ_ONLY',1,datetime('now'),datetime('now'))`); err != nil {
		t.Fatalf("readonly user: %v", err)
	}
	for _, g := range []struct{ id, uid, cid string }{
		{"m7dfi-grant-alpha-alpha", "user-analyst-alpha", "client-alpha"},
		{"m7dfi-grant-ro-alpha", "user-readonly", "client-alpha"},
		{"m7dfi-grant-beta-beta", "user-analyst-beta", "client-beta"},
		{"m7dfi-grant-admin-alpha", "user-admin", "client-alpha"},
		{"m7dfi-grant-reviewer-alpha", "user-reviewer", "client-alpha"},
	} {
		if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES (?, ?, ?)`, g.id, g.uid, g.cid); err != nil {
			t.Fatalf("grant %s: %v", g.id, err)
		}
	}
	return gDB
}

func TestM7D_Phase2_CreateInstance(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr-prod.alpha.internal")
	if err != nil {
		t.Fatal(err)
	}
	if inst.InstanceName != "QRadar-Prod" {
		t.Fatalf("unexpected instance: %+v", inst)
	}
	got, err := GetQRadarInstance(inst.InstanceID, "user-analyst-alpha")
	if err != nil {
		t.Fatal(err)
	}
	if got.InstanceID != inst.InstanceID {
		t.Fatal("instance not retrievable")
	}
	list, err := ListQRadarInstances("user-analyst-alpha", "client-alpha")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(list))
	}
}

func TestM7D_Phase2_CreateDomain(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr-prod.alpha.internal")
	if err != nil {
		t.Fatal(err)
	}
	dom := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	if dom.DomainName != "Corporate" {
		t.Fatalf("unexpected domain: %+v", dom)
	}
	doms, err := ListQRadarDomains("user-analyst-alpha", inst.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(doms) != 1 {
		t.Fatalf("expected 1 domain, got %d", len(doms))
	}
}

func TestM7D_Phase2_CreateLogSourceType(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr-prod.alpha.internal")
	if err != nil {
		t.Fatal(err)
	}
	dom := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	lst, err := CreateQRadarLogSourceType("user-analyst-alpha", dom.DomainID, "WinEventLog")
	if err != nil {
		t.Fatal(err)
	}
	if lst.TypeName != "WinEventLog" {
		t.Fatalf("unexpected log source type: %+v", lst)
	}
	lsts, err := ListQRadarLogSourceTypes("user-analyst-alpha", dom.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	if len(lsts) != 1 {
		t.Fatalf("expected 1 log source type, got %d", len(lsts))
	}
}

func TestM7D_Phase2_CreateLogSource(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr-prod.alpha.internal")
	if err != nil {
		t.Fatal(err)
	}
	dom := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	lst, err := CreateQRadarLogSourceType("user-analyst-alpha", dom.DomainID, "WinEventLog")
	if err != nil {
		t.Fatal(err)
	}
	ls, err := CreateQRadarLogSource("user-analyst-alpha", lst.LogSourceTypeID, "CONNECTED", "sysmon-forwarder")
	if err != nil {
		t.Fatal(err)
	}
	if ls.Status != "CONNECTED" {
		t.Fatalf("unexpected log source: %+v", ls)
	}
	lss, err := ListQRadarLogSources("user-analyst-alpha", lst.LogSourceTypeID)
	if err != nil {
		t.Fatal(err)
	}
	if len(lss) != 1 {
		t.Fatalf("expected 1 log source, got %d", len(lss))
	}
}

func TestM7D_Phase2_CreateQRadarQID(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr-prod.alpha.internal")
	if err != nil {
		t.Fatal(err)
	}
	dom := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	lst, err := CreateQRadarLogSourceType("user-analyst-alpha", dom.DomainID, "WinEventLog")
	if err != nil {
		t.Fatal(err)
	}
	ls, err := CreateQRadarLogSource("user-analyst-alpha", lst.LogSourceTypeID, "CONNECTED", "sysmon-forwarder")
	if err != nil {
		t.Fatal(err)
	}
	qid, err := CreateQRadarQID("user-analyst-alpha", ls.LogSourceID, "4698", "4698")
	if err != nil {
		t.Fatal(err)
	}
	if qid.EventName != "4698" {
		t.Fatalf("unexpected QRadar QID: %+v", qid)
	}
	qids, err := ListQRadarQIDs("user-analyst-alpha", ls.LogSourceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(qids) != 1 {
		t.Fatalf("expected 1 QRadar QID, got %d", len(qids))
	}
}

func TestM7D_Phase2_FieldDefinition(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr-prod.alpha.internal")
	if err != nil {
		t.Fatal(err)
	}
	dom := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	fd, err := CreateQRadarFieldDefinition("user-analyst-alpha", "client-alpha", dom.DomainID, "EventID", "system", "integer", "event_id", "4698", "event_id")
	if err != nil {
		t.Fatal(err)
	}
	if fd.FieldName != "EventID" {
		t.Fatalf("unexpected field definition: %+v", fd)
	}
	fds, err := ListQRadarFieldDefinitions("user-analyst-alpha", "client-alpha", dom.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	if len(fds) != 1 {
		t.Fatalf("expected 1 field definition, got %d", len(fds))
	}
}

func TestM7D_Phase2_FieldMapping(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr-prod.alpha.internal")
	if err != nil {
		t.Fatal(err)
	}
	dom := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	fm, err := CreateQRadarFieldMapping("user-analyst-alpha", "client-alpha", dom.DomainID, "EventCode", "event_id", "event_id", "Windows Security", "4698", "1", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if fm.RawSourceField != "EventCode" || fm.TargetCEPField != "event_id" {
		t.Fatalf("unexpected field mapping: %+v", fm)
	}
	fms, err := ListQRadarFieldMappings("user-analyst-alpha", "client-alpha", dom.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	if len(fms) != 1 {
		t.Fatalf("expected 1 field mapping, got %d", len(fms))
	}
}

func TestM7D_Phase2_FieldObservation(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr-prod.alpha.internal")
	if err != nil {
		t.Fatal(err)
	}
	dom := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	fd, err := CreateQRadarFieldDefinition("user-analyst-alpha", "client-alpha", dom.DomainID, "EventID", "system", "integer", "event_id", "4698", "event_id")
	if err != nil {
		t.Fatal(err)
	}
	fo, err := CreateQRadarFieldObservation("user-analyst-alpha", "client-alpha", dom.DomainID, fd.FieldID, true, true, true, "UNVERIFIED", "2026-01-01T00:00:00Z", "user-analyst-alpha", "raw_event_001")
	if err != nil {
		t.Fatal(err)
	}
	if fo.FieldID != fd.FieldID {
		t.Fatalf("unexpected field observation: %+v", fo)
	}
	fos, err := ListQRadarFieldObservations("user-analyst-alpha", "client-alpha", dom.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	if len(fos) != 1 {
		t.Fatalf("expected 1 field observation, got %d", len(fos))
	}
}

func TestM7D_Phase2_ImportBatch(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr-prod.alpha.internal")
	if err != nil {
		t.Fatal(err)
	}
	dom := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	b, err := CreateQRadarImportBatch("user-analyst-alpha", "client-alpha", dom.DomainID, "Weekly Import 2026-01", "csv", "sha256:abc123")
	if err != nil {
		t.Fatal(err)
	}
	if b.ProcessingStatus != "PENDING" {
		t.Fatalf("unexpected import batch: %+v", b)
	}
	bs, err := ListQRadarImportBatches("user-analyst-alpha", "client-alpha")
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) != 1 {
		t.Fatalf("expected 1 import batch, got %d", len(bs))
	}
}

func TestM7D_Phase2_ImportRow(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr-prod.alpha.internal")
	if err != nil {
		t.Fatal(err)
	}
	dom := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	// Rows can only be produced by the importer, never inserted by a caller.
	imported, err := upload(t, db, "EventID=4698 src_ip=10.0.0.1", "windows_kev")
	if err != nil {
		t.Fatal(err)
	}
	// A batch created directly stays empty until content is imported.
	if _, err := CreateQRadarImportBatch("user-analyst-alpha", "client-alpha", dom.DomainID, "Weekly Import 2026-01", "csv", "sha256:abc123"); err != nil {
		t.Fatal(err)
	}
	rows, err := ListQRadarImportRows(imported.BatchID, "user-analyst-alpha")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 import row, got %d", len(rows))
	}
}

func TestM7D_Phase2_ImportFieldMap(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr-prod.alpha.internal")
	if err != nil {
		t.Fatal(err)
	}
	dom := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	b, err := CreateQRadarImportBatch("user-analyst-alpha", "client-alpha", dom.DomainID, "Weekly Import 2026-01", "csv", "sha256:abc123")
	if err != nil {
		t.Fatal(err)
	}
	if err := CreateQRadarImportFieldMap("user-analyst-alpha", b.BatchID, "EventCode", "event_id", "event_id", "high", "observed integer", false); err != nil {
		t.Fatal(err)
	}
	fms, err := ListQRadarImportFieldMaps(b.BatchID, "user-analyst-alpha")
	if err != nil {
		t.Fatal(err)
	}
	if len(fms) != 1 {
		t.Fatalf("expected 1 field map, got %d", len(fms))
	}
}

func TestM7D_Phase2_PublishBatch(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr-prod.alpha.internal")
	if err != nil {
		t.Fatal(err)
	}
	dom := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	b, err := CreateQRadarImportBatch("user-analyst-alpha", "client-alpha", dom.DomainID, "Weekly Import 2026-01", "csv", "sha256:abc123")
	if err != nil {
		t.Fatal(err)
	}
	// Cannot publish PENDING batch
	if _, err := PublishQRadarImportBatch("user-analyst-alpha", b.BatchID); err == nil {
		t.Fatal("expected error when publishing PENDING batch")
	}
	// Simulate a parsed batch, then run the real review -> publish flow.
	if _, err := db.Exec(`UPDATE qradar_import_batches SET processing_status = 'MAPPED', parsed_rows = 1 WHERE batch_id = ?`, b.BatchID); err != nil {
		t.Fatal(err)
	}
	// Publish before review must fail.
	if _, err := PublishQRadarImportBatch("user-reviewer", b.BatchID); err == nil {
		t.Fatal("expected error when publishing an unreviewed batch")
	}
	if _, err := ReviewQRadarImportBatch("user-reviewer", b.BatchID, "APPROVED", "synthetic review"); err != nil {
		t.Fatal(err)
	}
	pub, err := PublishQRadarImportBatch("user-reviewer", b.BatchID)
	if err != nil {
		t.Fatal(err)
	}
	if pub.ProcessingStatus != "PUBLISHED" {
		t.Fatalf("expected PUBLISHED status, got %s", pub.ProcessingStatus)
	}
	// Second publish must not silently succeed again.
	if _, err := PublishQRadarImportBatch("user-reviewer", b.BatchID); err == nil {
		t.Fatal("expected error on duplicate publish")
	}
}

func TestM7D_Phase2_CrossClientDenied(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	_, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr-prod.alpha.internal")
	if err != nil {
		t.Fatal(err)
	}
	// Beta user should not be able to see alpha's instances
	if _, err := ListQRadarInstances("user-analyst-beta", "client-alpha"); err == nil {
		t.Fatal("expected access denied for beta user on alpha client")
	}
}

func TestM7D_Phase2_RevokedGrantDenied(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	_, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr-prod.alpha.internal")
	if err != nil {
		t.Fatal(err)
	}
	// Revoke grant
	if _, err := db.Exec(`DELETE FROM user_authorized_clients WHERE user_id='user-analyst-alpha' AND client_id='client-alpha'`); err != nil {
		t.Fatal(err)
	}
	if _, err := ListQRadarInstances("user-analyst-alpha", "client-alpha"); err == nil {
		t.Fatal("expected access denied after grant revocation")
	}
}

func TestM7D_Phase2_HTTPRoutes(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/qradar/instances", applyMiddleware(http.HandlerFunc(handleListQRadarInstances), requireAuth, requirePermission(CanViewCTI), auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/instances", applyMiddleware(http.HandlerFunc(handleCreateQRadarInstance), requireAuth, requirePermission(CanViewCTI), auditWrap, csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/domains", applyMiddleware(http.HandlerFunc(handleListQRadarDomains), requireAuth, requirePermission(CanViewCTI), auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/domains", applyMiddleware(http.HandlerFunc(handleCreateQRadarDomain), requireAuth, requirePermission(CanViewCTI), auditWrap, csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/log-source-types", applyMiddleware(http.HandlerFunc(handleListQRadarLogSourceTypes), requireAuth, requirePermission(CanViewCTI), auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/log-source-types", applyMiddleware(http.HandlerFunc(handleCreateQRadarLogSourceType), requireAuth, requirePermission(CanViewCTI), auditWrap, csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/log-sources", applyMiddleware(http.HandlerFunc(handleListQRadarLogSources), requireAuth, requirePermission(CanViewCTI), auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/log-sources", applyMiddleware(http.HandlerFunc(handleCreateQRadarLogSource), requireAuth, requirePermission(CanViewCTI), auditWrap, csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/qids", applyMiddleware(http.HandlerFunc(handleListQRadarQIDs), requireAuth, requirePermission(CanViewCTI), auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/qids", applyMiddleware(http.HandlerFunc(handleCreateQRadarQID), requireAuth, requirePermission(CanViewCTI), auditWrap, csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/field-definitions", applyMiddleware(http.HandlerFunc(handleListQRadarFieldDefinitions), requireAuth, requirePermission(CanViewCTI), auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/field-definitions", applyMiddleware(http.HandlerFunc(handleCreateQRadarFieldDefinition), requireAuth, requirePermission(CanViewCTI), auditWrap, csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/field-mappings", applyMiddleware(http.HandlerFunc(handleListQRadarFieldMappings), requireAuth, requirePermission(CanViewCTI), auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/field-mappings", applyMiddleware(http.HandlerFunc(handleCreateQRadarFieldMapping), requireAuth, requirePermission(CanViewCTI), auditWrap, csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/field-observations", applyMiddleware(http.HandlerFunc(handleListQRadarFieldObservations), requireAuth, requirePermission(CanViewCTI), auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/field-observations", applyMiddleware(http.HandlerFunc(handleCreateQRadarFieldObservation), requireAuth, requirePermission(CanViewCTI), auditWrap, csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/import-batches", applyMiddleware(http.HandlerFunc(handleListQRadarImportBatches), requireAuth, requirePermission(CanViewCTI), auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/import-batches", applyMiddleware(http.HandlerFunc(handleCreateQRadarImportBatch), requireAuth, requirePermission(CanViewCTI), auditWrap, csrfWrap))
	mux.HandleFunc("POST /api/v1/qradar/import-batches/{batch_id}/publish", applyMiddleware(http.HandlerFunc(handlePublishQRadarImportBatch), requireAuth, requirePermission(CanViewCTI), auditWrap, csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/import-rows", applyMiddleware(http.HandlerFunc(handleListQRadarImportRows), requireAuth, requirePermission(CanViewCTI), auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/import-field-maps", applyMiddleware(http.HandlerFunc(handleCreateQRadarImportFieldMap), requireAuth, requirePermission(CanViewCTI), auditWrap, csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/import-field-maps", applyMiddleware(http.HandlerFunc(handleListQRadarImportFieldMaps), requireAuth, requirePermission(CanViewCTI), auditWrap))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	sess, err := db.CreateSession("user-analyst-alpha", "client-alpha")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	do := func(method, path, body string, csrf bool) int {
		var rdr *strings.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		} else {
			rdr = strings.NewReader("")
		}
		req, _ := http.NewRequest(method, srv.URL+path, rdr)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: sess.SessionID})
		if csrf {
			req.Header.Set("Origin", "http://localhost:5173")
			req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "tok-1"})
			req.Header.Set("X-CSRF-Token", "tok-1")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	// 401 unauthenticated
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/qradar/instances", nil)
	resp, _ := client.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth: %d", resp.StatusCode)
	}
	// Create instance
	if code := do("POST", "/api/v1/qradar/instances", `{"client_id":"client-alpha","instance_name":"QRadar-Prod","host":"qr-prod.alpha.internal"}`, true); code != http.StatusCreated {
		t.Fatalf("create instance: %d", code)
	}
	// List instances
	if code := do("GET", "/api/v1/qradar/instances?client_id=client-alpha", "", false); code != http.StatusOK {
		t.Fatalf("list instances: %d", code)
	}
}

// Helper: decode JSON response into struct
func decodeJSONResp(resp *http.Response, v interface{}) error {
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}
