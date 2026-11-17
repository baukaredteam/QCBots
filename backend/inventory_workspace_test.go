package main

import (
	"errors"
	"strings"
	"testing"
)

// M7-F Phase 1: manual inventory import, provenance and completeness.

func inventoryDomain(t *testing.T, db *DB) *QRadarDomain {
	t.Helper()
	rule, dom := readySigmaDomain(t, db)
	_ = rule
	// readySigmaDomain also creates an attested EventID mapping.
	return dom
}

func importReq(dom *QRadarDomain, kind, content string) InventoryImportRequest {
	return InventoryImportRequest{
		ClientID: "client-alpha", DomainID: dom.DomainID, Kind: kind, Format: "csv",
		Content: content, DeclaredSource: "operator export ticket M7F-1",
	}
}

func TestInventoryImportPreviewDoesNotPersist(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	dom := inventoryDomain(t, db)
	before := countMappings(t)

	content := "raw_source_field,target_cep_field,semantic_alias,applicable_dsm,applicable_event,mapping_version\n" +
		"CommandLine,command_line,cmd,Microsoft Windows Security Event Log,4624,1\n"
	preview, err := previewInventoryImport("user-admin", importReq(dom, "field_mappings", content))
	if err != nil {
		t.Fatal(err)
	}
	if preview.Summary["create"] != 1 {
		t.Fatalf("expected one create, got %+v", preview.Summary)
	}
	if countMappings(t) != before {
		t.Fatal("preview must not write inventory")
	}
}

func countMappings(t *testing.T) int {
	t.Helper()
	var n int
	if err := globalDB.QueryRow(`SELECT COUNT(*) FROM qradar_field_mappings`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestInventoryImportCommitIsIdempotent(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	dom := inventoryDomain(t, db)
	req := importReq(dom, "field_mappings",
		"raw_source_field,target_cep_field,semantic_alias,applicable_dsm,applicable_event,mapping_version\n"+
			"CommandLine,command_line,cmd,Microsoft Windows Security Event Log,4624,1\n")

	p1, err := commitInventoryImport("user-admin", withConfirm(req))
	if err != nil {
		t.Fatalf("first commit: %v", err)
	}
	if p1.Summary["created"] != 1 {
		t.Fatalf("expected one created mapping, got %+v", p1.Summary)
	}
	var category, enteredBy, approvedBy string
	var revision int
	if err := db.QueryRow(`SELECT source_category, COALESCE(entered_by,''), COALESCE(approved_by,''), revision
		FROM qradar_field_mappings WHERE raw_source_field='CommandLine'`).Scan(&category, &enteredBy, &approvedBy, &revision); err != nil {
		t.Fatal(err)
	}
	if category != "IMPORTED_UNVERIFIED" || enteredBy != "user-admin" || approvedBy != "" || revision != 1 {
		t.Fatalf("bad provenance: %s %s %s %d", category, enteredBy, approvedBy, revision)
	}
	var revRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM qradar_inventory_revisions
		WHERE entity_type='field_mapping' AND source_category='IMPORTED_UNVERIFIED'`).Scan(&revRows); err != nil {
		t.Fatal(err)
	}
	if revRows == 0 {
		t.Fatal("import must record an immutable revision")
	}

	p2, err := commitInventoryImport("user-admin", withConfirm(req))
	if err != nil {
		t.Fatalf("re-import must be idempotent: %v", err)
	}
	if p2.Summary["created"] != 0 || p2.Summary["duplicate"] != 1 {
		t.Fatalf("expected a duplicate-only re-import, got %+v", p2.Summary)
	}
	if countMappings(t) != 1+1 { // EventID from the fixture + CommandLine
		t.Fatalf("unexpected mapping count: %d", countMappings(t))
	}
}

func withConfirm(req InventoryImportRequest) InventoryImportRequest {
	req.Confirm = true
	return req
}

func TestInventoryImportRequiresScopeAndGrant(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	dom := inventoryDomain(t, db)
	content := "raw_source_field,target_cep_field,semantic_alias,applicable_dsm,applicable_event,mapping_version\nImage,image,,,\n,1\n"

	// A user of another client cannot preview or commit against Alpha.
	if _, err := previewInventoryImport("user-analyst-beta", importReq(dom, "field_mappings", content)); !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("cross-client preview must be denied, got %v", err)
	}
	if _, err := commitInventoryImport("user-analyst-beta", withConfirm(importReq(dom, "field_mappings", content))); !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("cross-client commit must be denied, got %v", err)
	}

	// An unassigned domain is not importable.
	inst, err := CreateQRadarInstance("user-admin", "client-alpha", "Unassigned Console", "qr2.internal")
	if err != nil {
		t.Fatal(err)
	}
	unassigned, err := CreateQRadarDomain("user-admin", inst.InstanceID, "Unassigned", "production")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := previewInventoryImport("user-admin", importReq(unassigned, "field_mappings", content)); err == nil {
		t.Fatal("an unassigned domain must not accept imports")
	}
}

func TestInventoryImportValidationAndBounds(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	dom := inventoryDomain(t, db)

	cases := map[string]InventoryImportRequest{
		"unknown column": {ClientID: "client-alpha", DomainID: dom.DomainID, Kind: "field_mappings", Format: "csv",
			Content: "raw_source_field,target_cep_field,nope\nEventID,event_id,x\n"},
		"missing required": {ClientID: "client-alpha", DomainID: dom.DomainID, Kind: "field_mappings", Format: "csv",
			Content: "raw_source_field,target_cep_field\n,\n"},
		"invalid json": {ClientID: "client-alpha", DomainID: dom.DomainID, Kind: "field_mappings", Format: "json",
			Content: `[{"raw_source_field":`},
		"unknown field": {ClientID: "client-alpha", DomainID: dom.DomainID, Kind: "field_mappings", Format: "json",
			Content: `[{"raw_source_field":"a","target_cep_field":"b","secret":"x"}]`},
	}
	for name, req := range cases {
		if _, err := previewInventoryImport("user-admin", req); !errors.Is(err, ErrFieldImportInvalid) {
			t.Fatalf("%s must be rejected, got %v", name, err)
		}
	}
	oversize := importReq(dom, "field_mappings", "raw_source_field,target_cep_field\n"+strings.Repeat("a,b\n", 120000))
	if _, err := previewInventoryImport("user-admin", oversize); !errors.Is(err, ErrFieldImportInvalid) {
		t.Fatalf("oversized import must be rejected, got %v", err)
	}
}

func TestInventoryImportConflictDoesNotRewriteApprovedMapping(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	dom := inventoryDomain(t, db)

	// The fixture approved EventID -> event_id. A different CEP is a conflict.
	content := "raw_source_field,target_cep_field,semantic_alias,applicable_dsm,applicable_event,mapping_version\n" +
		"EventID,event_id_other,,Microsoft Windows Security Event Log,4624,1\n"
	preview, err := previewInventoryImport("user-admin", importReq(dom, "field_mappings", content))
	if err != nil {
		t.Fatal(err)
	}
	if preview.Summary["conflict"] != 1 {
		t.Fatalf("expected a conflict, got %+v", preview.Summary)
	}
	if _, err := commitInventoryImport("user-admin", withConfirm(importReq(dom, "field_mappings", content))); !errors.Is(err, ErrFieldConflict) {
		t.Fatalf("conflicting commit must be refused, got %v", err)
	}
	var cep string
	if err := db.QueryRow(`SELECT target_cep_field FROM qradar_field_mappings
		WHERE raw_source_field='EventID' AND COALESCE(approved_by,'') <> ''`).Scan(&cep); err != nil {
		t.Fatal(err)
	}
	if cep != "event_id" {
		t.Fatalf("approved mapping was rewritten: %s", cep)
	}
}

func TestInventoryImportRollsBackAtomically(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	dom := inventoryDomain(t, db)
	content := "field_name,field_origin,data_type,cep_identifier,supported_event_scope,aql_field_expression\n" +
		"FieldOne,raw_only,keyword,field_one,,field_one\n" +
		"FieldTwo,raw_only,keyword,field_two,,field_two\n"
	if _, err := db.Exec(`CREATE TRIGGER zz_block_second BEFORE INSERT ON qradar_field_definitions
		WHEN NEW.field_name = 'FieldTwo' BEGIN SELECT RAISE(ABORT, 'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := commitInventoryImport("user-admin", withConfirm(importReq(dom, "field_definitions", content))); err == nil {
		t.Fatal("the injected failure must abort the import")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM qradar_field_definitions WHERE field_name IN ('FieldOne','FieldTwo')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("partial import survived rollback: %d", n)
	}
}

func TestInventoryImportNeverChangesBinding(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	dom := inventoryDomain(t, db)
	before, err := GetDomainBinding(dom.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	content := "type_name\nNew DSM Type\n"
	if _, err := commitInventoryImport("user-admin", withConfirm(importReq(dom, "log_source_types", content))); err != nil {
		t.Fatalf("commit: %v", err)
	}
	after, err := GetDomainBinding(dom.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	if before.VerificationStatus != after.VerificationStatus || before.Revision != after.Revision ||
		before.NativeQRadarDomainID != after.NativeQRadarDomainID {
		t.Fatalf("import changed the domain binding: %+v -> %+v", before, after)
	}
}

func TestInventoryCompletenessReport(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	_ = inventoryDomain(t, db)
	report, err := InventoryCompletenessReport("user-admin", "client-alpha")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Domains) == 0 {
		t.Fatal("expected the verified Alpha domain")
	}
	seen := map[string]string{}
	for _, area := range report.Domains[0].Areas {
		seen[area.Entity] = area.Status
	}
	if seen["domain_binding"] != "MANUALLY_ENTERED" {
		t.Fatalf("binding evidence status = %q", seen["domain_binding"])
	}
	if seen["field_mappings"] != "APPROVED_MAPPING" {
		t.Fatalf("mapping evidence status = %q", seen["field_mappings"])
	}
	if seen["field_attestation"] != "AQL_MANUALLY_ATTESTED" {
		t.Fatalf("attestation status = %q", seen["field_attestation"])
	}
	if _, ok := seen["no_such_area"]; ok {
		t.Fatal("unexpected area")
	}
	if _, err := InventoryCompletenessReport("user-analyst-beta", "client-alpha"); !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("cross-client completeness must be denied, got %v", err)
	}
}

func TestInventoryRevisionsAreImmutable(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	dom := inventoryDomain(t, db)
	var revID, enteredBy string
	if err := db.QueryRow(`SELECT revision_id, COALESCE(entered_by,'') FROM qradar_inventory_revisions
		WHERE entity_type='log_source_type' AND domain_id=? ORDER BY entered_at LIMIT 1`, dom.DomainID).Scan(&revID, &enteredBy); err != nil {
		t.Fatal(err)
	}
	if enteredBy != "user-admin" {
		t.Fatalf("revision must preserve entered_by, got %q", enteredBy)
	}
	if _, err := db.Exec(`UPDATE qradar_inventory_revisions SET source_reference='rewritten' WHERE revision_id=?`, revID); err == nil {
		t.Fatal("revisions must be immutable")
	}
	if _, err := db.Exec(`DELETE FROM qradar_inventory_revisions WHERE revision_id=?`, revID); err == nil {
		t.Fatal("revisions must not be deletable")
	}
}

func TestInventoryImportUsesTheDomainOwnersIdentity(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	alpha := inventoryDomain(t, db)

	if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id)
		VALUES ('m7f-admin-beta', 'user-admin', 'client-beta')`); err != nil {
		t.Fatal(err)
	}
	inst, err := CreateQRadarInstance("user-admin", "client-beta", "Beta Console", "qr.beta.internal")
	if err != nil {
		t.Fatal(err)
	}
	beta, err := CreateQRadarDomain("user-admin", inst.InstanceID, "Beta Domain", "production")
	if err != nil {
		t.Fatal(err)
	}
	rev := 1
	if b, err := GetDomainBinding(beta.DomainID); err == nil {
		rev = b.Revision
	}
	if _, err := UpdateDomainBinding("user-admin", beta.DomainID, DomainBindingUpdate{
		NativeQRadarDomainID: "8", ClientID: "client-beta", BindingKind: "CLIENT",
		Evidence: "native id confirmed, ticket M7F-2", ExpectedRevision: rev,
	}); err != nil {
		t.Fatal(err)
	}

	content := "raw_source_field,target_cep_field,semantic_alias,applicable_dsm,applicable_event,mapping_version\n" +
		"Image,image,,,,\n"
	for _, dom := range []*QRadarDomain{alpha, beta} {
		b, err := GetDomainBinding(dom.DomainID)
		if err != nil {
			t.Fatal(err)
		}
		owner := b.ClientID
		req := InventoryImportRequest{ClientID: owner, DomainID: dom.DomainID, Kind: "field_mappings",
			Format: "csv", Content: content, DeclaredSource: "same export, ticket M7F-2", Confirm: true}
		if _, err := commitInventoryImport("user-admin", req); err != nil {
			t.Fatalf("import into %s: %v", owner, err)
		}
	}
	rows, err := db.Query(`SELECT client_id, mapping_id FROM qradar_field_mappings WHERE raw_source_field='Image' ORDER BY client_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var clients, ids []string
	for rows.Next() {
		var c, id string
		if err := rows.Scan(&c, &id); err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
		ids = append(ids, id)
	}
	if len(clients) != 2 || clients[0] != "client-alpha" || clients[1] != "client-beta" {
		t.Fatalf("same import must land in each domain owner: %v", clients)
	}
	if ids[0] == ids[1] {
		t.Fatal("domain imports must have separate identities")
	}
}
