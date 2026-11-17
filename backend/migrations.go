package main

import (
	"database/sql"
	"fmt"
	"os"
)

// M7-E Phase 1: the deployment migration path.
//
// The HTTP server intentionally does not migrate on startup (project convention:
// migrations are explicit). `workbench migrate <db>` applies every versioned
// file in order; runMigration records each version in the same transaction, so a
// failure leaves both the schema and schema_migrations unchanged for that file.

var migrationFiles = []string{
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

func applyAllMigrations(db *sql.DB) error {
	for _, path := range migrationFiles {
		if err := runMigration(db, path); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	return nil
}

func runMigrateCommand(dbPath string) error {
	db, err := OpenDB(dbPath)
	if err != nil {
		return fmt.Errorf("opening %s: %w", dbPath, err)
	}
	defer db.Close()
	if err := applyAllMigrations(db.DB); err != nil {
		return err
	}
	var version string
	_ = db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version)
	fmt.Printf("migrations applied to %s (last recorded: %s)\n", dbPath, version)
	return nil
}

// requireTestSeederEnv gates the synthetic-fixture commands. A documentation
// string and a filename are not proof of a test environment; the operator must
// opt in explicitly.
func requireTestSeederEnv() error {
	if os.Getenv("SENTINEL_ENABLE_TEST_SEEDERS") != "1" {
		return fmt.Errorf("refusing to create synthetic users: set SENTINEL_ENABLE_TEST_SEEDERS=1 and use a disposable database")
	}
	return nil
}
