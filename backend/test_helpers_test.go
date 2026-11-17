package main

import (
	"strconv"
	"sync/atomic"
	"testing"
)

// mkDomain creates a domain and then explicitly confirms its binding as an
// administrator. Domain creation alone never grants ownership: a fresh domain is
// UNASSIGNED/UNVERIFIED until a native QRadar domain id and a client are
// confirmed with evidence.
var testNativeSeq int32

func clientForTestUser(userID string) string {
	switch userID {
	case "user-analyst-beta":
		return "client-beta"
	default:
		return "client-alpha"
	}
}

func mkDomain(t *testing.T, db *DB, userID, instanceID, name, domainType string) *QRadarDomain {
	t.Helper()
	d, err := CreateQRadarDomain(userID, instanceID, name, domainType)
	if err != nil {
		t.Fatalf("create domain %s: %v", name, err)
	}
	// A freshly created domain must not be client-owned.
	b, err := GetDomainBinding(d.DomainID)
	if err != nil {
		t.Fatalf("binding after create: %v", err)
	}
	if b.BindingKind != "UNASSIGNED" || b.VerificationStatus != "UNVERIFIED" {
		t.Fatalf("a new domain must be UNASSIGNED/UNVERIFIED, got %+v", b)
	}
	native := strconv.Itoa(int(atomic.AddInt32(&testNativeSeq, 1)))
	if _, err := UpdateDomainBinding("user-admin", d.DomainID, DomainBindingUpdate{
		NativeQRadarDomainID: native,
		ClientID:             clientForTestUser(userID),
		BindingKind:          "CLIENT",
		Evidence:             "synthetic test binding confirmed by administrator, ticket TEST-1",
		ExpectedRevision:     b.Revision,
	}); err != nil {
		t.Fatalf("confirm binding %s: %v", name, err)
	}
	return d
}
