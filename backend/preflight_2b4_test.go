package main

import (
	"context"
	"errors"
	"testing"
)

// M7-D Phase 2B-4A preflight: regression tests for the five validation gaps
// closed before Hunt Plans were built.

func TestPreflight_INRequiresFieldOperand(t *testing.T) {
	// A constant on the left of IN is always true or always false and can be
	// used to smuggle a predicate past the rule body.
	for _, q := range []string{
		`SELECT * FROM events WHERE 1 IN (1, 2)`,
		`SELECT * FROM events WHERE 'a' NOT IN ('b')`,
	} {
		if _, err := TenantScopedAQL(q, "5", 7); !errors.Is(err, ErrAQLInvalid) {
			t.Fatalf("constant IN operand must be refused: %s", q)
		}
	}
	// A real field expression is still accepted.
	if _, err := TenantScopedAQL(`SELECT * FROM events WHERE "Event ID" NOT IN (4625, 4688)`, "5", 7); err != nil {
		t.Fatalf("field IN must be accepted: %v", err)
	}
}

func TestPreflight_ConflictingWorkerWindowRejected(t *testing.T) {
	if _, err := TenantScopedAQL(`SELECT * FROM events WHERE "Event ID"=4624 LAST 30 DAYS`, "5", 7); !errors.Is(err, ErrAQLInvalid) {
		t.Fatalf("a conflicting worker window must be refused, got %v", err)
	}
	v, err := TenantScopedAQL(`SELECT * FROM events WHERE "Event ID"=4624 LAST 7 DAYS`, "5", 7)
	if err != nil {
		t.Fatalf("a matching worker window must be accepted: %v", err)
	}
	if v.AQL != `SELECT * FROM events WHERE domainid=5 AND ("Event ID" = 4624) LAST 7 DAYS` {
		t.Fatalf("unexpected canonical statement: %s", v.AQL)
	}
}

// The readiness resolver and the revalidation path must choose the newest
// mapping by numeric version, so "10" beats "9" (string order would invert it).
func TestPreflight_MappingVersionOrderIsNumeric(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	rule, dom := readySigmaDomain(t, db)
	for _, v := range []string{"9", "10"} {
		if _, err := CreateQRadarFieldMapping("user-admin", "client-alpha", dom.DomainID,
			"EventID", "event_id", "event_id", "Microsoft Windows Security Event Log", "4624", v, "manual"); err != nil {
			t.Fatalf("mapping v%s: %v", v, err)
		}
	}
	sc, err := AnalyzeDetectionScope("user-analyst-alpha", "client-alpha", rule.RuleID)
	if err != nil {
		t.Fatal(err)
	}
	var got string
	for _, f := range sc.Domains[0].Fields {
		if f.Field == "EventID" {
			got = f.MappingVersion
		}
	}
	if got != "10" {
		t.Fatalf("readiness must select mapping version 10, got %q", got)
	}
}

// A CEP target changed while the worker runs must abort persistence.
func TestPreflight_CEPMutationDuringConversionIsStale(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	rule, dom := readySigmaDomain(t, db)
	err := runTranslationWhile(t, rule, dom.DomainID, func() {
		if _, uerr := db.Exec(`UPDATE qradar_field_mappings SET target_cep_field='different_cep' WHERE domain_id=?`, dom.DomainID); uerr != nil {
			t.Fatalf("mutate: %v", uerr)
		}
	})
	if !errors.Is(err, ErrTranslationStale) {
		t.Fatalf("a changed CEP target must abort persistence, got %v", err)
	}
}

// A valid draft produced with a scope-bound field list is still accepted.
func TestPreflight_ValidDraftStillSupported(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	rule, dom := readySigmaDomain(t, db)
	stubWorker(t, func(req sigmaWorkerRequest) (sigmaWorkerResponse, string) {
		return sigmaWorkerResponse{
			Status:          "OK",
			AQL:             `SELECT * FROM events WHERE "Event ID"=4624`,
			ConvertedFields: []string{"EventID"},
		}, ""
	})
	tr, err := CreateDetectionTranslation(context.Background(), "user-admin", rule.RuleID, TranslationRequest{
		ClientID: "client-alpha", DomainID: dom.DomainID, Mode: "VERIFIED_FIELDS_ONLY", TimeWindowDays: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tr.Status != ReadinessReady {
		t.Fatalf("valid draft must remain supported, got %s (%+v)", tr.Status, tr.Diagnostics)
	}
}
