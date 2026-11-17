package main

import (
	"bytes"
	"sync"
	"testing"
)

// TestImportIdentity_TrulyConcurrentSubmissions replaces the earlier sequential
// "concurrent" test. Many goroutines submit the same bytes into the same domain
// through the real importer; exactly one batch must exist and every caller must
// receive that batch (or a deterministic conflict-free equivalent), never a
// half-written PENDING batch.
func TestImportIdentity_TrulyConcurrentSubmissions(t *testing.T) {
	db := openM7DFI_DB(t)
	defer db.Close()
	inst, err := CreateQRadarInstance("user-analyst-alpha", "client-alpha", "QRadar-Prod", "qr.alpha.internal")
	if err != nil {
		t.Fatal(err)
	}
	dom := mkDomain(t, db, "user-analyst-alpha", inst.InstanceID, "Corporate", "production")

	const workers = 6
	var wg sync.WaitGroup
	ids := make([]string, workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			b, err := ProcessImportFile(memFile{bytes.NewReader([]byte(windowsFixture))}, "same.log",
				"user-analyst-alpha", "client-alpha", dom.DomainID, "concurrent", "windows_kev")
			if err != nil {
				errs[i] = err
				return
			}
			ids[i] = b.BatchID
		}(i)
	}
	wg.Wait()

	winner := ""
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d failed: %v", i, err)
		}
		if ids[i] == "" {
			t.Fatalf("worker %d returned no batch", i)
		}
		if winner == "" {
			winner = ids[i]
		} else if ids[i] != winner {
			t.Fatalf("concurrent submissions diverged: %s vs %s", ids[i], winner)
		}
	}

	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM qradar_import_batches WHERE client_id='client-alpha' AND domain_id=?`, dom.DomainID).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("expected exactly one batch for the identity, got %d", total)
	}
	// No caller may be handed a batch that never finished processing.
	b, err := GetQRadarImportBatch(winner, "user-analyst-alpha")
	if err != nil {
		t.Fatal(err)
	}
	if b.ProcessingStatus != "MAPPED" {
		t.Fatalf("converged batch must be fully processed, got %s", b.ProcessingStatus)
	}
	var rows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM qradar_import_rows WHERE batch_id=?`, winner).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("expected one row for the single import, got %d", rows)
	}
}
