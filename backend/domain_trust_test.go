package main

import (
	"bytes"
	"errors"
	"testing"
)

// P0 trust-boundary tests for Phase 2A.1:
//  1. a new domain is UNASSIGNED/UNVERIFIED and carries no native id;
//  2. no client-scoped operation works before confirmation;
//  3. confirmation requires a real native QRadar domain id and evidence;
//  4. revoking verification blocks access immediately;
//  5. database UPDATEs cannot bypass the invariants.

// 1-2
func TestTrust_NewDomainIsUnassigned(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr.alpha.internal")
	if err != nil {
		t.Fatal(err)
	}
	d, err := CreateQRadarDomain("user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	if err != nil {
		t.Fatal(err)
	}
	b, err := GetDomainBinding(d.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	if b.BindingKind != "UNASSIGNED" || b.VerificationStatus != "UNVERIFIED" {
		t.Fatalf("a new domain must be UNASSIGNED/UNVERIFIED, got %s/%s", b.BindingKind, b.VerificationStatus)
	}
	if b.ClientID != "" {
		t.Fatalf("a new domain must not be client-owned, got %q", b.ClientID)
	}
	if b.InferredClientID != "client-alpha" {
		t.Fatalf("creator client may be kept as reconciliation metadata, got %q", b.InferredClientID)
	}
	if b.NativeQRadarDomainID != "" || b.NativeIDStatus != "UNVERIFIED" {
		t.Fatalf("a new domain must not carry a native id, got %q/%s", b.NativeQRadarDomainID, b.NativeIDStatus)
	}
	// The creator still sees it (so they can hand it to an administrator), but it
	// is not usable as client data.
	if _, err := ClientOfDomain(d.DomainID); !errors.Is(err, ErrDomainNotAssigned) {
		t.Fatalf("unconfirmed domain must not resolve to a client, got %v", err)
	}
}

// 3-4
func TestTrust_NoClientOperationsBeforeConfirmation(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr.alpha.internal")
	if err != nil {
		t.Fatal(err)
	}
	d, err := CreateQRadarDomain("user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProcessImportFile(memFile{bytes.NewReader([]byte(windowsFixture))}, "x.log",
		"user-analyst-alpha", "client-alpha", d.DomainID, "early import", "windows_kev"); !errors.Is(err, ErrDomainNotAssigned) {
		t.Fatalf("import into an unverified domain must be refused, got %v", err)
	}
	if _, err := CreateQRadarFieldDefinition("user-analyst-alpha", "client-alpha", d.DomainID, "EventID", "system", "integer", "event_id", "", ""); !errors.Is(err, ErrDomainNotAssigned) {
		t.Fatalf("field definition on an unverified domain must be refused, got %v", err)
	}
	if _, err := CreateQRadarLogSourceType("user-analyst-alpha", d.DomainID, "WinEventLog"); !errors.Is(err, ErrDomainNotAssigned) {
		t.Fatalf("log source type on an unverified domain must be refused, got %v", err)
	}
	if _, err := ListQRadarFieldDefinitions("user-analyst-alpha", "client-alpha", d.DomainID); !errors.Is(err, ErrDomainNotAssigned) {
		t.Fatalf("client-scoped read on an unverified domain must be refused, got %v", err)
	}
}

// 5
func TestTrust_ConfirmationRequiresNativeDomainID(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, _ := CreateQRadarInstance("user-admin", "client-alpha", "QRadar-Prod", "qr.alpha.internal")
	d, _ := CreateQRadarDomain("user-admin", inst.InstanceID, "Corporate", "production")
	if _, err := UpdateDomainBinding("user-admin", d.DomainID, DomainBindingUpdate{
		ClientID: "client-alpha", BindingKind: "CLIENT",
		Evidence: "trying to confirm without any native id", ExpectedRevision: 1,
	}); !errors.Is(err, ErrNativeDomainIDBad) {
		t.Fatalf("CLIENT confirmation without a native id must fail, got %v", err)
	}
	// Still unassigned afterwards.
	b, _ := GetDomainBinding(d.DomainID)
	if b.BindingKind != "UNASSIGNED" || b.VerificationStatus != "UNVERIFIED" {
		t.Fatalf("failed confirmation must not change the binding, got %s/%s", b.BindingKind, b.VerificationStatus)
	}
}

// 6
func TestTrust_InvalidNativeDomainIDRejected(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, _ := CreateQRadarInstance("user-admin", "client-alpha", "QRadar-Prod", "qr.alpha.internal")
	d, _ := CreateQRadarDomain("user-admin", inst.InstanceID, "Corporate", "production")
	for _, bad := range []string{"corporate", "-1", "5a", "99999999999999", "  ", "0x05"} {
		if _, err := UpdateDomainBinding("user-admin", d.DomainID, DomainBindingUpdate{
			NativeQRadarDomainID: bad, ClientID: "client-alpha", BindingKind: "CLIENT",
			Evidence: "invalid native id attempt, ticket TEST-3", ExpectedRevision: 1,
		}); !errors.Is(err, ErrNativeDomainIDBad) && !errors.Is(err, ErrFieldImportInvalid) {
			t.Fatalf("native id %q must be rejected, got %v", bad, err)
		}
	}
}

// 7-8
func TestTrust_AccessOnlyAfterConfirmation(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, _ := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr.alpha.internal")
	d, _ := CreateQRadarDomain("user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	if _, err := ClientOfDomain(d.DomainID); !errors.Is(err, ErrDomainNotAssigned) {
		t.Fatalf("expected no ownership before confirmation: %v", err)
	}
	if _, err := UpdateDomainBinding("user-admin", d.DomainID, DomainBindingUpdate{
		NativeQRadarDomainID: "7", ClientID: "client-alpha", BindingKind: "CLIENT",
		Evidence: "QRadar export: domain 7 = Corporate, ticket TEST-4", ExpectedRevision: 1,
	}); err != nil {
		t.Fatalf("valid confirmation failed: %v", err)
	}
	if _, err := ClientOfDomain(d.DomainID); err != nil {
		t.Fatalf("confirmed domain must resolve: %v", err)
	}
	if _, err := CreateQRadarLogSourceType("user-analyst-alpha", d.DomainID, "WinEventLog"); err != nil {
		t.Fatalf("client write after confirmation: %v", err)
	}
}

// 9
func TestTrust_RevokingVerificationBlocksImmediately(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, _ := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr.alpha.internal")
	d, _ := CreateQRadarDomain("user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	if _, err := UpdateDomainBinding("user-admin", d.DomainID, DomainBindingUpdate{
		NativeQRadarDomainID: "11", ClientID: "client-alpha", BindingKind: "CLIENT",
		Evidence: "QRadar export: domain 11 = Corporate, ticket TEST-5", ExpectedRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateQRadarLogSourceType("user-analyst-alpha", d.DomainID, "Before"); err != nil {
		t.Fatalf("access before revocation should work: %v", err)
	}
	// Revoke: UNASSIGNED keeps the native id but ends the ownership claim.
	b, _ := GetDomainBinding(d.DomainID)
	if _, err := UpdateDomainBinding("user-admin", d.DomainID, DomainBindingUpdate{
		BindingKind: "UNASSIGNED", Evidence: "ownership withdrawn pending contract review, ticket TEST-6",
		ExpectedRevision: b.Revision,
	}); err != nil {
		t.Fatalf("revocation failed: %v", err)
	}
	if _, err := ClientOfDomain(d.DomainID); !errors.Is(err, ErrDomainNotAssigned) {
		t.Fatalf("revoked domain must not resolve, got %v", err)
	}
	if _, err := ListQRadarLogSourceTypes("user-analyst-alpha", d.DomainID); !errors.Is(err, ErrDomainNotAssigned) {
		t.Fatalf("client read after revocation must fail, got %v", err)
	}
	if _, err := ProcessImportFile(memFile{bytes.NewReader([]byte(windowsFixture))}, "x.log",
		"user-analyst-alpha", "client-alpha", d.DomainID, "post revocation", "windows_kev"); !errors.Is(err, ErrDomainNotAssigned) {
		t.Fatalf("import after revocation must fail, got %v", err)
	}
}

// 10
func TestTrust_RebindingNeverTransfersBatches(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, _ := CreateQRadarInstance("user-admin", "client-alpha", "QRadar-Shared", "qr.shared.internal")
	// grants for admin on both clients so the fixtures stay usable
	for _, c := range []string{"client-alpha", "client-beta"} {
		if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES (?,?,?)`, "g-admin-"+c, "user-admin", c); err != nil {
			t.Fatal(err)
		}
	}
	d, _ := CreateQRadarDomain("user-admin", inst.InstanceID, "Corporate", "production")
	if _, err := UpdateDomainBinding("user-admin", d.DomainID, DomainBindingUpdate{
		NativeQRadarDomainID: "5", ClientID: "client-alpha", BindingKind: "CLIENT",
		Evidence: "QRadar export: domain 5 = Corporate, ticket TEST-7", ExpectedRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	batch, err := ProcessImportFile(memFile{bytes.NewReader([]byte(windowsFixture))}, "x.log",
		"user-analyst-alpha", "client-alpha", d.DomainID, "alpha import", "windows_kev")
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	cur, _ := GetDomainBinding(d.DomainID)
	if _, err := UpdateDomainBinding("user-admin", d.DomainID, DomainBindingUpdate{
		NativeQRadarDomainID: "5", ClientID: "client-beta", BindingKind: "CLIENT",
		Evidence: "ownership transferred, ticket TEST-8", ExpectedRevision: cur.Revision,
	}); err != nil {
		t.Fatal(err)
	}
	// The batch keeps its original client and is not handed to the new owner.
	if _, err := GetQRadarImportBatch(batch.BatchID, "user-analyst-beta"); !errors.Is(err, ErrFieldConflict) {
		t.Fatalf("rebinding must surface an attribution conflict, got %v", err)
	}
	var owner string
	if err := db.QueryRow(`SELECT client_id FROM qradar_import_batches WHERE batch_id=?`, batch.BatchID).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner != "client-alpha" {
		t.Fatalf("historical attribution was rewritten: %s", owner)
	}
}

// 11
func TestTrust_DirectSQLCannotBypassBinding(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, _ := CreateQRadarInstance("user-admin", "client-alpha", "QRadar-Prod", "qr.alpha.internal")
	d, _ := CreateQRadarDomain("user-admin", inst.InstanceID, "Corporate", "production")

	// Cannot flip an unverified binding to VERIFIED CLIENT by hand: no native id.
	if _, err := db.Exec(`UPDATE qradar_domain_bindings
		SET client_id='client-alpha', binding_kind='CLIENT', verification_status='VERIFIED',
		    verified_by='user-admin', verified_at=datetime('now'), evidence_reference='direct sql attempt'
		WHERE domain_id=?`, d.DomainID); err == nil {
		t.Fatal("direct SQL must not create a verified client binding without a verified native id")
	}
	// Cannot mark a binding verified without evidence.
	if _, err := db.Exec(`UPDATE qradar_domain_bindings SET verification_status='VERIFIED', verified_by='user-admin', verified_at=datetime('now') WHERE domain_id=?`, d.DomainID); err == nil {
		t.Fatal("direct SQL must not verify a binding without evidence")
	}
	// Cannot move a binding to another domain.
	if _, err := db.Exec(`UPDATE qradar_domain_bindings SET domain_id='qd-other' WHERE domain_id=?`, d.DomainID); err == nil {
		t.Fatal("binding domain identity must be immutable")
	}
	// Cannot declare a client binding with a null client.
	if _, err := db.Exec(`UPDATE qradar_domain_bindings SET binding_kind='CLIENT', client_id=NULL WHERE domain_id=?`, d.DomainID); err == nil {
		t.Fatal("CLIENT binding without a client must be rejected")
	}
	// A verified native id cannot be inserted without provenance.
	if _, err := db.Exec(`INSERT INTO qradar_domains (domain_id, instance_id, domain_name, native_qradar_domain_id, native_id_status)
		VALUES ('qd-badnative', ?, 'Bad', '42', 'VERIFIED')`, inst.InstanceID); err == nil {
		t.Fatal("verified native id without a source must be rejected")
	}
	// After a legitimate confirmation, the native id cannot be cleared while the
	// client binding depends on it.
	if _, err := UpdateDomainBinding("user-admin", d.DomainID, DomainBindingUpdate{
		NativeQRadarDomainID: "21", ClientID: "client-alpha", BindingKind: "CLIENT",
		Evidence: "QRadar export: domain 21, ticket TEST-9", ExpectedRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE qradar_domains SET native_qradar_domain_id=NULL, native_id_status='UNVERIFIED' WHERE domain_id=?`, d.DomainID); err == nil {
		t.Fatal("native id used by a verified client binding must not be cleared")
	}
}

// A client binding cannot be verified from an id that exists but is unverified.
func TestTrust_UnverifiedNativeIDCannotBackABinding(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, _ := CreateQRadarInstance("user-admin", "client-alpha", "QRadar-Prod", "qr.alpha.internal")
	d, _ := CreateQRadarDomain("user-admin", inst.InstanceID, "Corporate", "production")
	// Attach an unverified id directly, then try to confirm with no id in the request.
	if _, err := db.Exec(`UPDATE qradar_domains SET native_qradar_domain_id='33', native_id_status='UNVERIFIED' WHERE domain_id=?`, d.DomainID); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateDomainBinding("user-admin", d.DomainID, DomainBindingUpdate{
		ClientID: "client-alpha", BindingKind: "CLIENT",
		Evidence: "confirming using an unverified stored id, ticket TEST-10", ExpectedRevision: 1,
	}); !errors.Is(err, ErrNativeDomainIDBad) {
		t.Fatalf("an unverified stored native id must not back a CLIENT binding, got %v", err)
	}
}
