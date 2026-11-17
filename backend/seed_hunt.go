package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// M7-D Phase 2B-4B: disposable acceptance database.
//
// Builds the full schema (0001-0021) plus synthetic fixtures for browser
// acceptance: two clients sharing one console, verified native domains 5 and 8,
// one READY draft, one unsupported detection, one stale draft, a DRAFT plan and
// an IN_REVIEW plan. Nothing here calls QRadar or executes AQL.
//
// Safety: the target must be a file that does not exist, inside the directory
// named by SENTINEL_ACCEPTANCE_DIR, which itself must be a canonical temporary
// directory outside the repository. Nothing is ever deleted or overwritten.
const acceptanceDirEnv = "SENTINEL_ACCEPTANCE_DIR"

func seedHuntAcceptance(dbPath string) error {
	authorized := strings.TrimSpace(os.Getenv(acceptanceDirEnv))
	if authorized == "" {
		return fmt.Errorf("refusing to seed: set %s to an authorized temporary directory", acceptanceDirEnv)
	}
	final, err := validateAcceptanceDBPath(dbPath, authorized)
	if err != nil {
		return err
	}
	// O_EXCL is the last line of defence: even if validation raced, an existing
	// file (including an empty one) is never opened or truncated.
	f, err := os.OpenFile(final, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("refusing to create acceptance database: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing new acceptance database: %w", err)
	}
	dbPath = final

	db, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=1&_busy_timeout=30000&_journal_mode=WAL")
	if err != nil {
		return fmt.Errorf("opening db: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	migrations := []string{
		"migrations/0001_initial.sql", "migrations/0002_qradar_inventory.sql",
		"migrations/0003_evidence_graph.sql", "migrations/0004_p0_mcp_case.sql",
		"migrations/0005_m6_case_workspace.sql", "migrations/0006_cti_ingestion.sql",
		"migrations/0007_case_cti_reports.sql", "migrations/0008_relevance.sql",
		"migrations/0009_relevance_eval_time.sql", "migrations/0010_hunt_hypothesis.sql",
		"migrations/0011_field_intelligence.sql", "migrations/0012_field_intel_hardening.sql",
		"migrations/0013_field_intel_review_history.sql", "migrations/0014_import_identity_scope.sql",
		"migrations/0015_qradar_domain_bindings.sql", "migrations/0016_domain_binding_update_guards.sql",
		"migrations/0017_sigma_detection_ingestion.sql", "migrations/0018_detection_translations.sql",
		"migrations/0019_hunt_plans.sql", "migrations/0020_hunt_plan_item_integrity.sql",
		"migrations/0021_hunt_plan_item_binding_owner.sql",
		"migrations/0022_manual_inventory_provenance.sql",
	}
	for _, m := range migrations {
		if err := runMigration(db, m); err != nil {
			return fmt.Errorf("migration %s: %w", m, err)
		}
	}
	if err := createM1Tables(db); err != nil {
		return err
	}
	if err := seedTestData(db); err != nil {
		return err
	}

	globalDB = &DB{db}
	ctiArtifactDir = filepath.Join(filepath.Dir(dbPath), "hunt-acceptance-artifacts")
	_ = os.MkdirAll(ctiArtifactDir, 0o755)
	globalAuditLogger = NewAuditLogger(&DB{db})
	globalCSRFValidator = NewCSRFValidator([]string{"http://localhost:18081"}, false)
	globalConfig = &Config{ServerPort: "18081", Origin: "http://localhost:18081"}

	grants := []struct{ id, uid, cid string }{
		{"seed-grant-aa", "user-analyst-alpha", "client-alpha"},
		{"seed-grant-bb", "user-analyst-beta", "client-beta"},
		{"seed-grant-writer-a", "user-analyst-multi", "client-alpha"},
		{"seed-grant-admin-a", "user-admin", "client-alpha"},
		{"seed-grant-admin-b", "user-admin", "client-beta"},
		{"seed-grant-rev-a", "user-reviewer", "client-alpha"},
	}
	for _, g := range grants {
		if _, err := db.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES (?, ?, ?)`, g.id, g.uid, g.cid); err != nil {
			return fmt.Errorf("grant %s: %w", g.id, err)
		}
	}

	inst, err := CreateQRadarInstance("user-admin", "client-alpha", "Shared QRadar Console", "qradar.lab.internal")
	if err != nil {
		return fmt.Errorf("instance: %w", err)
	}
	domA, err := CreateQRadarDomain("user-admin", inst.InstanceID, "Alpha Corporate", "production")
	if err != nil {
		return fmt.Errorf("domain alpha: %w", err)
	}
	alphaBindRev := 1
	if b, err := GetDomainBinding(domA.DomainID); err == nil {
		alphaBindRev = b.Revision
	}
	if _, err := UpdateDomainBinding("user-admin", domA.DomainID, DomainBindingUpdate{
		NativeQRadarDomainID: "5", ClientID: "client-alpha", BindingKind: "CLIENT",
		Evidence: "Native domain id confirmed on console export, seed ticket A-1",
		ExpectedRevision: alphaBindRev,
	}); err != nil {
		return fmt.Errorf("bind alpha: %w", err)
	}
	betaBindRev := 1
	domB, err := CreateQRadarDomain("user-admin", inst.InstanceID, "Beta Finance", "production")
	if err != nil {
		return fmt.Errorf("domain beta: %w", err)
	}
	if b, err := GetDomainBinding(domB.DomainID); err == nil {
		betaBindRev = b.Revision
	}
	if _, err := UpdateDomainBinding("user-admin", domB.DomainID, DomainBindingUpdate{
		NativeQRadarDomainID: "8", ClientID: "client-beta", BindingKind: "CLIENT",
		Evidence: "Native domain id confirmed on console export, seed ticket B-1",
		ExpectedRevision: betaBindRev,
	}); err != nil {
		return fmt.Errorf("bind beta: %w", err)
	}

	// Telemetry: one DSM and attested fields per domain.
	alphaEvent, alphaImage, err := seedTelemetry("client-alpha", domA.DomainID, true)
	if err != nil {
		return fmt.Errorf("alpha telemetry: %w", err)
	}
	if _, _, err := seedTelemetry("client-beta", domB.DomainID, false); err != nil {
		return fmt.Errorf("beta telemetry: %w", err)
	}

	readyYAML := `title: Windows Logon Success
id: 44444444-4444-4444-4444-444444444444
status: test
description: Synthetic fixture detection for a successful Windows logon.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
  condition: selection
level: low
tags:
  - attack.execution
  - attack.t1078
`
	unsupportedYAML := `title: PowerShell Burst (aggregation)
id: 55555555-5555-5555-5555-555555555555
status: test
description: Synthetic fixture using an aggregation the IBM backend cannot convert.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
  condition: selection | count() > 5
level: medium
`
	staleYAML := `title: Suspicious Image Path
id: 66666666-6666-6666-6666-666666666666
status: test
description: Synthetic fixture scoped to the Image field, later superseded by a mapping change.
logsource:
  product: windows
  service: security
detection:
  selection:
    Image: 'C:\Windows\System32\cmd.exe'
  condition: selection
level: medium
`
	readyRule, err := IngestSigmaRule("user-admin", "client-alpha", "", "windows-logon.yml", readyYAML)
	if err != nil {
		return fmt.Errorf("ready rule: %w", err)
	}
	unsupportedRule, err := IngestSigmaRule("user-admin", "client-alpha", "", "powershell-burst.yml", unsupportedYAML)
	if err != nil {
		return fmt.Errorf("unsupported rule: %w", err)
	}
	staleRule, err := IngestSigmaRule("user-admin", "client-alpha", "", "image-path.yml", staleYAML)
	if err != nil {
		return fmt.Errorf("stale rule: %w", err)
	}
	// Safety fixture: markup in a title/description must render as text, never
	// as HTML.
	htmlYAML := `title: HTML Fixture <img src=x onerror=alert(1)>
id: 77777777-7777-7777-7777-777777777777
status: test
description: Contains <script>alert(1)</script> and must be displayed as text.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
  condition: selection
level: low
`
	if _, err := IngestSigmaRule("user-admin", "client-alpha", "", "html-fixture.yml", htmlYAML); err != nil {
		return fmt.Errorf("html fixture rule: %w", err)
	}

	alphaBinding, err := GetDomainBinding(domA.DomainID)
	if err != nil {
		return err
	}
	dsm := "Microsoft Windows Security Event Log"
	readyTr, err := seedTranslation(readyRule, "client-alpha", inst.InstanceID, domA.DomainID, "5",
		alphaBinding.Revision, "READY_FOR_REVIEW", `SELECT * FROM events WHERE "Event ID"=4624`, dsm,
		[]TranslationMapping{{Field: "EventID", CEPField: "event_id", MappingID: alphaEvent.MappingID,
			MappingVersion: alphaEvent.MappingVersion, ApprovedBy: "user-admin", State: FieldStateAttested}},
		[]string{"synthetic acceptance fixture"}, nil, "")
	if err != nil {
		return fmt.Errorf("ready translation: %w", err)
	}
	if _, err := seedTranslation(unsupportedRule, "client-alpha", inst.InstanceID, domA.DomainID, "5",
		alphaBinding.Revision, "UNSUPPORTED", "", dsm,
		[]TranslationMapping{{Field: "EventID", CEPField: "event_id", MappingID: alphaEvent.MappingID,
			MappingVersion: alphaEvent.MappingVersion, ApprovedBy: "user-admin", State: FieldStateAttested}},
		[]string{"the original Sigma detection is preserved unchanged"}, []string{"aggregation | count() > 5"}, "aggregation is not supported by the IBM backend"); err != nil {
		return fmt.Errorf("unsupported translation: %w", err)
	}
	staleTr, err := seedTranslation(staleRule, "client-alpha", inst.InstanceID, domA.DomainID, "5",
		alphaBinding.Revision, "READY_FOR_REVIEW", `SELECT * FROM events WHERE Image='C:\Windows\System32\cmd.exe'`, dsm,
		[]TranslationMapping{{Field: "Image", CEPField: "image", MappingID: alphaImage.MappingID,
			MappingVersion: alphaImage.MappingVersion, ApprovedBy: "user-admin", State: FieldStateAttested}},
		[]string{"synthetic stale fixture"}, nil, "")
	if err != nil {
		return fmt.Errorf("stale translation: %w", err)
	}

	hyp, _, err := CreateHypothesisManual("user-admin", "client-alpha", &HypothesisInput{
		Title:       "Synthetic logon hunt",
		Description: "Acceptance fixture hypothesis.",
		Statement:   "Investigate successful logons from unusual sources.",
	})
	if err != nil {
		return fmt.Errorf("hypothesis: %w", err)
	}

	// DRAFT plan for the analyst flow.
	if _, err := CreateHuntPlan("user-admin", CreateHuntPlanRequest{
		ClientID: "client-alpha", HypothesisID: hyp.HypothesisID, HypothesisVersion: 1,
		Title: "Alpha – analyst draft",
	}); err != nil {
		return fmt.Errorf("draft plan: %w", err)
	}

	// IN_REVIEW plan carrying the later-stale draft.
	reviewPlan, err := CreateHuntPlan("user-admin", CreateHuntPlanRequest{
		ClientID: "client-alpha", HypothesisID: hyp.HypothesisID, HypothesisVersion: 1,
		Title: "Alpha – stale evidence review",
	})
	if err != nil {
		return fmt.Errorf("review plan: %w", err)
	}
	if _, err := AddHuntPlanItem("user-admin", reviewPlan.PlanID, staleTr); err != nil {
		return fmt.Errorf("attach stale draft: %w", err)
	}
	if _, err := SubmitHuntPlan("user-admin", reviewPlan.PlanID); err != nil {
		return fmt.Errorf("submit review plan: %w", err)
	}
	// A newer Image mapping appears after submission: the plan is now stale.
	if _, err := CreateQRadarFieldMapping("user-admin", "client-alpha", domA.DomainID,
		"Image", "image", "image", dsm, "", "2", "manual"); err != nil {
		return fmt.Errorf("supersede image mapping: %w", err)
	}

	fmt.Printf("seeded acceptance database %s\n", dbPath)
	fmt.Printf("  ready translation:       %s\n", readyTr)
	fmt.Printf("  draft plan:              %s\n", "Alpha – analyst draft")
	fmt.Printf("  in-review (stale) plan:  %s\n", reviewPlan.PlanID)
	return nil
}

type seedMap struct {
	MappingID      string
	MappingVersion string
}

// seedTelemetry creates the DSM, an approved+attested EventID mapping, and (for
// alpha) an Image mapping. Returns the two mapping references.
func seedTelemetry(clientID, domainID string, withImage bool) (seedMap, seedMap, error) {
	dsm := "Microsoft Windows Security Event Log"
	if _, err := CreateQRadarLogSourceType("user-admin", domainID, dsm); err != nil {
		return seedMap{}, seedMap{}, err
	}
	eventMap, err := CreateQRadarFieldMapping("user-admin", clientID, domainID,
		"EventID", "event_id", "event_id", dsm, "4624", "1", "auto")
	if err != nil {
		return seedMap{}, seedMap{}, err
	}
	if _, err := ApproveQRadarFieldMapping("user-admin", eventMap.MappingID, "CONFIRMED: CEP export compared, seed ticket C-1"); err != nil {
		return seedMap{}, seedMap{}, err
	}
	fd, err := CreateQRadarFieldDefinition("user-admin", clientID, domainID,
		"EventID", "system", "integer", "event_id", "4624", "event_id")
	if err != nil {
		return seedMap{}, seedMap{}, err
	}
	if _, err := CreateQRadarFieldObservation("user-admin", clientID, domainID, fd.FieldID,
		true, true, true, "VERIFIED", time.Now().UTC().Format(time.RFC3339), "user-admin", "AQL event_id returns the value, seed ticket C-1"); err != nil {
		return seedMap{}, seedMap{}, err
	}
	out := seedMap{MappingID: eventMap.MappingID, MappingVersion: eventMap.MappingVersion}
	if !withImage {
		return out, seedMap{}, nil
	}
	imageMap, err := CreateQRadarFieldMapping("user-admin", clientID, domainID,
		"Image", "image", "image", dsm, "", "1", "auto")
	if err != nil {
		return seedMap{}, seedMap{}, err
	}
	if _, err := ApproveQRadarFieldMapping("user-admin", imageMap.MappingID, "CONFIRMED: CEP export compared, seed ticket C-2"); err != nil {
		return seedMap{}, seedMap{}, err
	}
	imgFD, err := CreateQRadarFieldDefinition("user-admin", clientID, domainID,
		"Image", "system", "keyword", "image", "", "image")
	if err != nil {
		return seedMap{}, seedMap{}, err
	}
	if _, err := CreateQRadarFieldObservation("user-admin", clientID, domainID, imgFD.FieldID,
		true, true, true, "VERIFIED", time.Now().UTC().Format(time.RFC3339), "user-admin", "AQL image returns the value, seed ticket C-2"); err != nil {
		return seedMap{}, seedMap{}, err
	}
	return out, seedMap{MappingID: imageMap.MappingID, MappingVersion: imageMap.MappingVersion}, nil
}

// seedTranslation stores a synthetic immutable draft. It uses the real AQL
// scoping builder so the tenant predicate is the production one.
func seedTranslation(rule *SigmaRule, clientID, instanceID, domainID, native string, bindingRev int,
	status, workerAQL, dsm string, mappings []TranslationMapping, notes, unsupported []string, workerErr string) (string, error) {

	aql, hash := "", ""
	if workerAQL != "" {
		v, err := TenantScopedAQL(workerAQL, native, 7)
		if err != nil {
			return "", err
		}
		aql = v.AQL
		s := sha256.Sum256([]byte(aql))
		hash = hex.EncodeToString(s[:])
	}
	diag := TranslationDiagnostics{
		ScopeStatus: status, DSMVerified: dsm != "", PrimaryDSM: dsm,
		ConvertedFields: []string{}, Notes: notes, UnsupportedConditions: unsupported,
		WorkerError: workerErr, Executed: false,
		Isolation: WorkerIsolation{InterpreterIsolated: true, MinimalEnv: true, FixedWorkdir: true,
			TimeoutEnforced: true, OutputCapped: true, TreeKill: "BEST_EFFORT",
			NetworkSandbox: false, FilesystemSandbox: false},
	}
	snap, _ := json.Marshal(mappings)
	diagJSON, _ := json.Marshal(diag)
	id := newID("dtr")
	_, err := globalDB.Exec(`INSERT INTO detection_translations
		(translation_id, rule_id, client_id, instance_id, domain_id, native_qradar_domain_id, binding_revision,
		 conversion_mode, status, aql_draft, aql_sha256, time_window_days, mapping_snapshot, diagnostics,
		 worker_version, backend_version, pysigma_version, sigma_rule_hash, sigma_rule_version,
		 validation_status, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'VERIFIED_FIELDS_ONLY', ?, ?, ?, 7, ?, ?, 'seed', '0.3.2', '0.11.23', ?, ?, 'PRELIMINARY', 'user-admin', datetime('now'))`,
		id, rule.RuleID, clientID, instanceID, domainID, native, bindingRev,
		status, aql, hash, string(snap), string(diagJSON), rule.YAMLSHA256, rule.Version)
	if err != nil {
		return "", err
	}
	return id, nil
}

