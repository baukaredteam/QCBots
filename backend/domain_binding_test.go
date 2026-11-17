package main

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

// Phase 2A.1: one physical QRadar console, several native domains, several Atlas
// clients. Nothing here uses fabricated native ids beyond clearly synthetic ones.

type sharedConsole struct {
	db       *DB
	instance *QRadarInstance
	domA     *QRadarDomain // client-alpha
	domB     *QRadarDomain // client-beta after rebinding
}

func newSharedConsole(t *testing.T) *sharedConsole {
	t.Helper()
	db := openM7DFI_DB(t)
	// The admin creates the console. Instance ownership is legacy metadata only;
	// it never grants access to a domain.
	if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES ('grant-admin-alpha','user-admin','client-alpha')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES ('grant-admin-beta','user-admin','client-beta')`); err != nil {
		t.Fatal(err)
	}
	inst, err := CreateQRadarInstance("user-admin", "client-alpha", "QRadar-Shared", "qr.shared.internal")
	if err != nil {
		t.Fatalf("instance: %v", err)
	}
	// Domain 5 for client-alpha. Creation leaves it UNASSIGNED; the administrator
	// confirms ownership explicitly with a native id and evidence.
	domA, err := CreateQRadarDomain("user-analyst-alpha", inst.InstanceID, "Corporate", "production")
	if err != nil {
		t.Fatalf("domain A: %v", err)
	}
	if _, err := UpdateDomainBinding("user-admin", domA.DomainID, DomainBindingUpdate{
		NativeQRadarDomainID: "5", ClientID: "client-alpha", BindingKind: "CLIENT",
		Evidence: "QRadar API export: domain 5 = Corporate, ticket SOC-099", ExpectedRevision: 1,
	}); err != nil {
		t.Fatalf("bind A: %v", err)
	}
	// Domain 8 for client-beta, confirmed the same way.
	domB, err := CreateQRadarDomain("user-admin", inst.InstanceID, "Beta Payloads", "production")
	if err != nil {
		t.Fatalf("domain B: %v", err)
	}
	if _, err := UpdateDomainBinding("user-admin", domB.DomainID, DomainBindingUpdate{
		NativeQRadarDomainID: "8", ClientID: "client-beta", BindingKind: "CLIENT",
		Evidence: "QRadar API export: domain 8 = Beta Payloads, ticket SOC-100", ExpectedRevision: 1,
	}); err != nil {
		t.Fatalf("bind B: %v", err)
	}
	return &sharedConsole{db: db, instance: inst, domA: domA, domB: domB}
}

func seedDomainData(t *testing.T, db *DB, domainID, clientID, actorID string) (fieldID string) {
	t.Helper()
	if _, err := CreateQRadarLogSourceType(actorID, domainID, "WinEventLog-"+domainID); err != nil {
		t.Fatalf("log source type: %v", err)
	}
	fd, err := CreateQRadarFieldDefinition(actorID, clientID, domainID, "EventID", "system", "integer", "event_id", "4624", "event_id")
	if err != nil {
		t.Fatalf("field def: %v", err)
	}
	return fd.FieldID
}

// 1-5: two clients, two domains, no cross reading.
func TestPhase21_TwoClientsTwoDomains(t *testing.T) {
	sc := newSharedConsole(t)
	defer sc.db.Close()
	fieldA := seedDomainData(t, sc.db, sc.domA.DomainID, "client-alpha", "user-analyst-alpha")
	_ = fieldA
	if _, err := CreateQRadarLogSourceType("user-admin", sc.domB.DomainID, "WinEventLogB"); err != nil {
		t.Fatalf("beta data: %v", err)
	}

	// Client alpha sees its own domain only.
	domsA, err := ListQRadarDomains("user-analyst-alpha", sc.instance.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(domsA) != 1 || domsA[0].DomainID != sc.domA.DomainID {
		t.Fatalf("alpha must see exactly its own domain, got %+v", domsA)
	}
	domsB, err := ListQRadarDomains("user-analyst-beta", sc.instance.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(domsB) != 1 || domsB[0].DomainID != sc.domB.DomainID {
		t.Fatalf("beta must see exactly its own domain, got %+v", domsB)
	}
	// Alpha cannot list beta's domain entities.
	if _, err := ListQRadarLogSourceTypes("user-analyst-alpha", sc.domB.DomainID); !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("alpha must not read beta log source types, got %v", err)
	}
	if _, err := ListQRadarFieldDefinitions("user-analyst-alpha", "client-beta", sc.domB.DomainID); err == nil {
		t.Fatal("alpha must not read beta field definitions")
	}
	// Claiming beta's client id on alpha's domain is an integrity conflict.
	if _, err := ListQRadarFieldDefinitions("user-analyst-beta", "client-beta", sc.domA.DomainID); !errors.Is(err, ErrFieldConflict) {
		t.Fatalf("client/domain mismatch must conflict, got %v", err)
	}
}

// 6: one user with both grants is scoped by the argument, not by reach.
func TestPhase21_UserWithBothGrantsIsScoped(t *testing.T) {
	sc := newSharedConsole(t)
	defer sc.db.Close()
	if _, err := sc.db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES ('grant-multi-beta','user-analyst-multi','client-beta')`); err != nil {
		t.Fatal(err)
	}
	if _, err := sc.db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES ('grant-multi-alpha','user-analyst-multi','client-alpha')`); err != nil {
		t.Fatal(err)
	}
	if _, err := sc.db.Exec(`UPDATE users SET role='CTI_ANALYST' WHERE user_id='user-analyst-multi'`); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateQRadarLogSourceType("user-analyst-multi", sc.domA.DomainID, "A-Source"); err != nil {
		t.Fatalf("alpha scope: %v", err)
	}
	if _, err := CreateQRadarLogSourceType("user-analyst-multi", sc.domB.DomainID, "B-Source"); err != nil {
		t.Fatalf("beta scope: %v", err)
	}
	// Reading beta's domain while claiming alpha is refused.
	if _, err := ListQRadarFieldDefinitions("user-analyst-multi", "client-alpha", sc.domB.DomainID); !errors.Is(err, ErrFieldConflict) {
		t.Fatalf("mismatched claim must conflict, got %v", err)
	}
}

// 7: administrator without a client grant cannot read client telemetry.
func TestPhase21_AdminNeedsGrantForTelemetry(t *testing.T) {
	sc := newSharedConsole(t)
	defer sc.db.Close()
	if _, err := sc.db.Exec(`DELETE FROM user_authorized_clients WHERE user_id='user-admin'`); err != nil {
		t.Fatal(err)
	}
	// Admin holds no client grant now, so client telemetry is closed to them.
	if _, err := ListQRadarLogSourceTypes("user-admin", sc.domB.DomainID); !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("admin without grant must be denied telemetry, got %v", err)
	}
	// But reconciliation (binding metadata) remains available.
	if _, err := ListDomainBindings("user-admin", sc.instance.InstanceID); err != nil {
		t.Fatalf("admin must still manage bindings: %v", err)
	}
}

// 8-10: unassigned, shared and missing bindings deny by default.
func TestPhase21_UnassignedSharedMissingDeny(t *testing.T) {
	sc := newSharedConsole(t)
	defer sc.db.Close()
	// Unassign B.
	if _, err := UpdateDomainBinding("user-admin", sc.domB.DomainID, DomainBindingUpdate{
		BindingKind: "UNASSIGNED", Evidence: "domain ownership under review, ticket SOC-101", ExpectedRevision: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ListQRadarLogSourceTypes("user-analyst-beta", sc.domB.DomainID); !errors.Is(err, ErrDomainNotAssigned) {
		t.Fatalf("unassigned domain must deny, got %v", err)
	}
	if _, err := CreateQRadarLogSourceType("user-admin", sc.domB.DomainID, "Hidden"); !errors.Is(err, ErrDomainNotAssigned) {
		t.Fatalf("unassigned domain must deny writes, got %v", err)
	}
	// Shared.
	if _, err := UpdateDomainBinding("user-admin", sc.domB.DomainID, DomainBindingUpdate{
		BindingKind: "SHARED", Evidence: "global reference domain, ticket SOC-102", ExpectedRevision: 3,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ListQRadarLogSourceTypes("user-admin", sc.domB.DomainID); !errors.Is(err, ErrDomainNotAssigned) {
		t.Fatalf("shared domain must deny client-scoped access, got %v", err)
	}
	// Missing binding: a domain inserted directly without a binding row.
	if _, err := sc.db.Exec(`INSERT INTO qradar_domains (domain_id, instance_id, domain_name, domain_type) VALUES ('qd-orphan','` + sc.instance.InstanceID + `','Orphan','production')`); err != nil {
		t.Fatal(err)
	}
	if _, err := ListQRadarLogSourceTypes("user-admin", "qd-orphan"); !errors.Is(err, ErrDomainBindingMissing) {
		t.Fatalf("missing binding must deny, got %v", err)
	}
}

// 11-13: native id validation and uniqueness.
func TestPhase21_NativeDomainIDRules(t *testing.T) {
	sc := newSharedConsole(t)
	defer sc.db.Close()
	// Bad format.
	rev := func(id string) int {
		b, err := GetDomainBinding(id)
		if err != nil {
			t.Fatal(err)
		}
		return b.Revision
	}
	if _, err := UpdateDomainBinding("user-admin", sc.domA.DomainID, DomainBindingUpdate{
		NativeQRadarDomainID: "corporate", ClientID: "client-alpha", BindingKind: "CLIENT",
		Evidence: "trying to use a label as a native id", ExpectedRevision: rev(sc.domA.DomainID),
	}); !errors.Is(err, ErrNativeDomainIDBad) {
		t.Fatalf("a label must not be accepted as native id, got %v", err)
	}
	// Duplicate on the same instance: domA is being given 8, which domB holds.
	if _, err := UpdateDomainBinding("user-admin", sc.domA.DomainID, DomainBindingUpdate{
		NativeQRadarDomainID: "8", ClientID: "client-alpha", BindingKind: "CLIENT",
		Evidence: "duplicate native id attempt, ticket SOC-103", ExpectedRevision: rev(sc.domA.DomainID),
	}); !errors.Is(err, ErrNativeDomainIDBad) {
		t.Fatalf("duplicate native id on one instance must be rejected, got %v", err)
	}
	// Same native id on a different instance is allowed.
	other, err := CreateQRadarInstance("user-admin", "client-alpha", "QRadar-Second", "qr.second.internal")
	if err != nil {
		t.Fatal(err)
	}
	domC, err := CreateQRadarDomain("user-admin", other.InstanceID, "Other Corporate", "production")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateDomainBinding("user-admin", domC.DomainID, DomainBindingUpdate{
		NativeQRadarDomainID: "8", ClientID: "client-alpha", BindingKind: "CLIENT",
		Evidence: "second console also has domain 8, ticket SOC-104", ExpectedRevision: rev(domC.DomainID),
	}); err != nil {
		t.Fatalf("same native id on another instance must be allowed: %v", err)
	}
}

// 14: revoked grant denies immediately.
func TestPhase21_RevokedGrantDenies(t *testing.T) {
	sc := newSharedConsole(t)
	defer sc.db.Close()
	if _, err := ListQRadarLogSourceTypes("user-analyst-alpha", sc.domA.DomainID); err != nil {
		t.Fatalf("expected access before revocation: %v", err)
	}
	if _, err := sc.db.Exec(`DELETE FROM user_authorized_clients WHERE user_id='user-analyst-alpha' AND client_id='client-alpha'`); err != nil {
		t.Fatal(err)
	}
	if _, err := ListQRadarLogSourceTypes("user-analyst-alpha", sc.domA.DomainID); !errors.Is(err, ErrFieldAccessDenied) {
		t.Fatalf("revoked grant must deny, got %v", err)
	}
}

// 15-16: historical attribution is frozen; cross-client references are refused.
func TestPhase21_HistoricalBatchAndCrossReferences(t *testing.T) {
	sc := newSharedConsole(t)
	defer sc.db.Close()
	batch, err := ProcessImportFile(memFile{bytes.NewReader([]byte(windowsFixture))}, "x.log",
		"user-analyst-alpha", "client-alpha", sc.domA.DomainID, "alpha import", "windows_kev")
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	// Rebind the domain to beta.
	if _, err := UpdateDomainBinding("user-admin", sc.domA.DomainID, DomainBindingUpdate{
		NativeQRadarDomainID: "5", ClientID: "client-beta", BindingKind: "CLIENT",
		ExpectedRevision: 2, Evidence: "ownership transferred after contract change, ticket SOC-105",
	}); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	// Alpha no longer owns the domain; the historical batch is not disclosed.
	if _, err := GetQRadarImportBatch(batch.BatchID, "user-analyst-alpha"); err == nil {
		t.Fatal("alpha must lose access to a domain it no longer owns")
	}
	// Beta now owns the domain but must not inherit alpha's batch as its evidence.
	if _, err := GetQRadarImportBatch(batch.BatchID, "user-analyst-beta"); !errors.Is(err, ErrFieldConflict) {
		t.Fatalf("historical attribution mismatch must surface as a conflict, got %v", err)
	}
	// The batch row itself is untouched.
	var owner string
	if err := sc.db.QueryRow(`SELECT client_id FROM qradar_import_batches WHERE batch_id=?`, batch.BatchID).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner != "client-alpha" {
		t.Fatalf("historical attribution was rewritten: %s", owner)
	}
	// A field definition from beta's earlier domain cannot be referenced by alpha's.
	if _, err := CreateQRadarFieldObservation("user-analyst-alpha", "client-alpha", sc.domA.DomainID, "qfd-foreign", true, false, false, "UNVERIFIED", "", "", ""); err == nil {
		t.Fatal("cross-domain field reference must be refused")
	}
	// Mapping into a client/domain that disagrees with the binding is refused.
	if _, err := CreateQRadarFieldMapping("user-analyst-beta", "client-alpha", sc.domA.DomainID, "X", "event_id", "", "", "", "1", "auto"); !errors.Is(err, ErrFieldConflict) {
		t.Fatalf("cross-client mapping must conflict, got %v", err)
	}
}

// 17: import idempotency stays domain-scoped after the binding work.
func TestPhase21_ImportIdentityStillDomainScoped(t *testing.T) {
	sc := newSharedConsole(t)
	defer sc.db.Close()
	a, err := ProcessImportFile(memFile{bytes.NewReader([]byte(windowsFixture))}, "x.log",
		"user-analyst-alpha", "client-alpha", sc.domA.DomainID, "a1", "windows_kev")
	if err != nil {
		t.Fatal(err)
	}
	again, err := ProcessImportFile(memFile{bytes.NewReader([]byte(windowsFixture))}, "x.log",
		"user-analyst-alpha", "client-alpha", sc.domA.DomainID, "a2", "windows_kev")
	if err != nil || again.BatchID != a.BatchID {
		t.Fatalf("same domain replay must be idempotent: %v", err)
	}
	b, err := ProcessImportFile(memFile{bytes.NewReader([]byte(windowsFixture))}, "x.log",
		"user-analyst-beta", "client-beta", sc.domB.DomainID, "b1", "windows_kev")
	if err != nil {
		t.Fatal(err)
	}
	if b.BatchID == a.BatchID {
		t.Fatal("different domains must not share a batch")
	}
}

// 18: reassignment keeps an immutable history.
func TestPhase21_ReassignmentHistoryImmutable(t *testing.T) {
	sc := newSharedConsole(t)
	defer sc.db.Close()
	hist, err := ListDomainBindingHistory("user-admin", sc.domB.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 || hist[len(hist)-1].NewClient != "client-beta" {
		t.Fatalf("expected the rebinding to be recorded, got %+v", hist)
	}
	if _, err := sc.db.Exec(`UPDATE qradar_domain_binding_history SET evidence_reference='rewritten'`); err == nil {
		t.Fatal("binding history must be append-only")
	}
	// The binding row keeps the actor identity from the session, not the request.
	var actor string
	if err := sc.db.QueryRow(`SELECT verified_by FROM qradar_domain_bindings WHERE domain_id=?`, sc.domB.DomainID).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	if actor != "user-admin" {
		t.Fatalf("binding actor must be the session user, got %s", actor)
	}
}

// 19: concurrent confirmations cannot both win.
func TestPhase21_ConcurrentBindingConfirmation(t *testing.T) {
	sc := newSharedConsole(t)
	defer sc.db.Close()
	dom, err := CreateQRadarDomain("user-admin", sc.instance.InstanceID, "Racy", "production")
	if err != nil {
		t.Fatal(err)
	}
	before, err := GetDomainBinding(dom.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = UpdateDomainBinding("user-admin", dom.DomainID, DomainBindingUpdate{
				NativeQRadarDomainID: "9", ClientID: "client-alpha", BindingKind: "CLIENT",
				ExpectedRevision: before.Revision,
				Evidence:         "concurrent confirmation attempt, ticket SOC-106",
			})
		}(i)
	}
	wg.Wait()
	ok, conflict := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrDomainBindingOwned):
			conflict++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatalf("expected exactly one winner and one conflict, got ok=%d conflict=%d", ok, conflict)
	}
}

// 20: direct SQL cannot bypass the binding, and the import identity is enforced
// by the database as well as the service.
func TestPhase21_DatabaseEnforcement(t *testing.T) {
	sc := newSharedConsole(t)
	defer sc.db.Close()
	// A batch row claiming a client that the binding does not confirm is refused.
	if _, err := sc.db.Exec(`INSERT INTO qradar_import_batches
		(batch_id, client_id, domain_id, batch_name, source_type, file_hash, imported_by, processing_status)
		VALUES ('qib-forged','client-beta',?, 'forged','windows_kev','sha256:forged','user-admin','PENDING')`,
		sc.domA.DomainID); err == nil {
		t.Fatal("trigger must reject a batch whose client does not match the binding")
	}
	// Field definitions likewise.
	if _, err := sc.db.Exec(`INSERT INTO qradar_field_definitions
		(field_id, client_id, domain_id, field_name, field_origin)
		VALUES ('qfd-forged','client-beta',?, 'Forged','system')`, sc.domA.DomainID); err == nil {
		t.Fatal("trigger must reject a field definition whose client does not match the binding")
	}
}
