package main

import "testing"

// The plan UI must use the hypothesis version the API reports, never a guessed
// constant. This asserts the list endpoint exposes it.
func TestListAvailableHypothesesReturnsCurrentVersion(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	detail, _, err := CreateHypothesisManual("user-admin", "client-alpha", &HypothesisInput{
		Title:     "Version exposure fixture",
		Statement: "the list endpoint must expose the current version",
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, total, err := ListAvailableHypotheses("user-admin", "client-alpha", 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total == 0 {
		t.Fatal("expected at least one hypothesis")
	}
	var found bool
	for _, h := range rows {
		if h.HypothesisID != detail.HypothesisID {
			continue
		}
		found = true
		if h.CurrentVersion != detail.CurrentVersion.VersionNo {
			t.Fatalf("current_version_no = %d, want %d", h.CurrentVersion, detail.CurrentVersion.VersionNo)
		}
		if h.CurrentVersion <= 0 {
			t.Fatal("a hypothesis must report a positive current version")
		}
	}
	if !found {
		t.Fatal("created hypothesis missing from the list")
	}
}
