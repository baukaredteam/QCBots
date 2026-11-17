package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// M7-D Phase 2B-3: client-aware Sigma -> QRadar AQL draft generation.
//
// A draft is created only for a verified domain binding of the selected client.
// It records exactly which mappings were used, which were not, what the worker
// reported, and the versions of everything involved. Drafts are immutable and are
// never described as executed.

type TranslationMapping struct {
	Field          string `json:"field"`
	CEPField       string `json:"cep_field,omitempty"`
	MappingID      string `json:"mapping_id,omitempty"`
	MappingVersion string `json:"mapping_version,omitempty"`
	ApprovedBy     string `json:"approved_by,omitempty"`
	State          string `json:"state"`
}

type TranslationDiagnostics struct {
	ScopeStatus           string   `json:"scope_status"`
	DSMVerified           bool     `json:"dsm_verified"`
	PrimaryDSM            string   `json:"primary_dsm,omitempty"`
	ConvertedFields       []string `json:"converted_fields,omitempty"`
	UnmappedFields        []string `json:"unmapped_fields,omitempty"`
	UnsupportedConditions []string `json:"unsupported_conditions,omitempty"`
	Warnings              []string `json:"warnings,omitempty"`
	Notes                 []string `json:"notes,omitempty"`
	WorkerError           string   `json:"worker_error,omitempty"`
	WorkerScriptSHA256    string   `json:"worker_script_sha256,omitempty"`
	Isolation             WorkerIsolation `json:"isolation"`
	Executed              bool     `json:"executed"` // always false: nothing runs
}

// WorkerIsolation states exactly what is and is not enforced around the local
// Python worker. Nothing here is a sandbox; it is a bounded subprocess.
type WorkerIsolation struct {
	InterpreterIsolated bool   `json:"interpreter_isolated"` // python -I -B
	MinimalEnv          bool   `json:"minimal_env"`
	FixedWorkdir        bool   `json:"fixed_workdir"`
	TimeoutEnforced     bool   `json:"timeout_enforced"`
	OutputCapped        bool   `json:"output_capped"`
	TreeKill            string `json:"tree_kill"`          // BEST_EFFORT
	NetworkSandbox      bool   `json:"network_sandbox"`    // false: no OS-level egress block
	FilesystemSandbox   bool   `json:"filesystem_sandbox"` // false: no OS-level FS confinement
}

type DetectionTranslation struct {
	TranslationID    string                 `json:"translation_id"`
	RuleID           string                 `json:"rule_id"`
	ClientID         string                 `json:"client_id"`
	InstanceID       string                 `json:"instance_id"`
	DomainID         string                 `json:"domain_id"`
	NativeDomainID   string                 `json:"native_qradar_domain_id"`
	BindingRevision  int                    `json:"binding_revision"`
	Mode             string                 `json:"conversion_mode"`
	Status           string                 `json:"status"`
	AQLDraft         string                 `json:"aql_draft,omitempty"`
	AQLSHA256        string                 `json:"aql_sha256,omitempty"`
	TimeWindowDays   int                    `json:"time_window_days"`
	Mappings         []TranslationMapping   `json:"mappings"`
	Diagnostics      TranslationDiagnostics `json:"diagnostics"`
	WorkerVersion    string                 `json:"worker_version,omitempty"`
	BackendVersion   string                 `json:"backend_version,omitempty"`
	PySigmaVersion   string                 `json:"pysigma_version,omitempty"`
	SigmaRuleHash    string                 `json:"sigma_rule_hash"`
	SigmaRuleVersion int                    `json:"sigma_rule_version"`
	ValidationStatus string                 `json:"validation_status"`
	CreatedBy        string                 `json:"created_by"`
	CreatedAt        string                 `json:"created_at"`
	Stale            bool                   `json:"stale"`
	StaleReasons     []string               `json:"stale_reasons,omitempty"`
}

type TranslationRequest struct {
	ClientID       string `json:"client_id"`
	DomainID       string `json:"domain_id"`
	Mode           string `json:"conversion_mode"`
	TimeWindowDays int    `json:"time_window_days"`
}

// CreateDetectionTranslation converts one rule for one verified domain.
func CreateDetectionTranslation(ctx context.Context, userID, ruleID string, req TranslationRequest) (*DetectionTranslation, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if err := requireFieldCapability(userID, CanGenerateAQL); err != nil {
		return nil, err
	}
	rule, err := GetSigmaRule(ruleID, userID)
	if err != nil {
		return nil, err
	}
	if req.ClientID == "" || rule.ClientID != req.ClientID {
		return nil, ErrFieldAccessDenied
	}
	if req.Mode == "" {
		req.Mode = "VERIFIED_FIELDS_ONLY"
	}
	switch req.Mode {
	case "VERIFIED_FIELDS_ONLY", "REVIEW_REQUIRED_FIELDS":
	case "PAYLOAD_FALLBACK":
		return nil, fmt.Errorf("%w: payload fallback is not enabled", ErrFieldImportInvalid)
	default:
		return nil, fmt.Errorf("%w: unknown conversion mode", ErrFieldImportInvalid)
	}
	if req.TimeWindowDays == 0 {
		req.TimeWindowDays = 7
	}
	if req.TimeWindowDays < 1 || req.TimeWindowDays > 90 {
		return nil, fmt.Errorf("%w: time window must be 1..90 days", ErrFieldImportInvalid)
	}

	scope, err := AnalyzeDetectionScope(userID, req.ClientID, ruleID)
	if err != nil {
		return nil, err
	}
	domain, ok := scopeDomain(scope, req.DomainID)
	if !ok {
		// Either the domain is not this client's, or its binding is not verified.
		return nil, ErrDomainNotAssigned
	}

	diag := TranslationDiagnostics{
		ScopeStatus: domain.Status,
		DSMVerified: domain.DSMVerified,
		PrimaryDSM:  domain.PrimaryDSM,
		Executed:    false,
		Isolation: WorkerIsolation{
			InterpreterIsolated: true,
			MinimalEnv:          true,
			FixedWorkdir:        true,
			TimeoutEnforced:     true,
			OutputCapped:        true,
			TreeKill:            "BEST_EFFORT",
			NetworkSandbox:      false,
			FilesystemSandbox:   false,
		},
	}
	var mappings []TranslationMapping

	// Refuse before conversion when the evidence policy is not met. This is a
	// real, recorded outcome, not a silent skip.
	if req.Mode == "VERIFIED_FIELDS_ONLY" {
		if !domain.DSMVerified || len(rule.Fields) == 0 || domain.Status != ReadinessReady {
			diag.Notes = append(diag.Notes,
				"conversion refused: VERIFIED_FIELDS_ONLY requires a catalogue-verified DSM and attested fields")
			return persistTranslation(userID, rule, domain, req, "", "", diag, nil, ReadinessNeedsVerification, nil)
		}
	}

	fieldMap := map[string]string{}
	for _, f := range domain.Fields {
		if f.CEPField == "" {
			continue
		}
		if req.Mode == "VERIFIED_FIELDS_ONLY" && f.State != FieldStateAttested {
			continue
		}
		fieldMap[f.Field] = f.CEPField
		mappings = append(mappings, TranslationMapping{
			Field: f.Field, CEPField: f.CEPField, MappingID: f.MappingID,
			MappingVersion: f.MappingVersion, ApprovedBy: f.ApprovedBy, State: f.State,
		})
		if f.State != FieldStateAttested {
			diag.Warnings = append(diag.Warnings, "field "+f.Field+" is used without AQL attestation ("+f.State+")")
		}
	}

	resp, werr := CallSigmaWorker(ctx, rule.YAML, rule.YAMLSHA256, fieldMap, req.Mode)
	if werr != nil {
		if errors.Is(werr, ErrWorkerUnavailable) {
			diag.WorkerError = "worker unavailable"
			diag.Notes = append(diag.Notes, "the Sigma worker is not configured; no AQL was generated")
			return persistTranslation(userID, rule, domain, req, "", "", diag, mappings, ReadinessBlocked, nil)
		}
		diag.WorkerError = truncate(werr.Error(), 300)
		diag.Notes = append(diag.Notes, "worker protocol failure; no AQL was generated")
		return persistTranslation(userID, rule, domain, req, "", "", diag, mappings, ReadinessBlocked, nil)
	}
	diag.WorkerScriptSHA256 = resp.WorkerScriptSHA256
	diag.ConvertedFields = resp.ConvertedFields
	diag.UnmappedFields = resp.UnmappedFields
	diag.UnsupportedConditions = resp.UnsupportedConditions
	diag.Warnings = append(diag.Warnings, resp.Warnings...)

	if resp.Status != "OK" {
		status := ReadinessUnsupported
		if resp.Status == "PARSE_ERROR" {
			status = ReadinessUnsupported
		}
		if resp.Status == "ERROR" && resp.ErrorCode != "" {
			diag.WorkerError = resp.ErrorCode
		}
		diag.Notes = append(diag.Notes, "worker returned "+resp.Status)
		return persistTranslation(userID, rule, domain, req, "", "", diag, mappings, status,
			&workerVersions{Worker: resp.WorkerVersion, Backend: resp.BackendVersion, PySigma: resp.PySigmaVersion})
	}

	scoped, aerr := TenantScopedAQL(resp.AQL, domain.NativeDomainID, req.TimeWindowDays)
	if aerr != nil {
		diag.WorkerError = aerr.Error()
		diag.Notes = append(diag.Notes, "generated AQL failed validation and was not stored")
		return persistTranslation(userID, rule, domain, req, "", "", diag, mappings, ReadinessBlocked,
			&workerVersions{Worker: resp.WorkerVersion, Backend: resp.BackendVersion, PySigma: resp.PySigmaVersion})
	}

	status := ReadinessNeedsVerification
	if domain.Status == ReadinessReady && req.Mode == "VERIFIED_FIELDS_ONLY" {
		status = ReadinessReady
	}
	if len(resp.UnmappedFields) > 0 {
		status = ReadinessNeedsVerification
	}
	return persistTranslation(userID, rule, domain, req, scoped.AQL, scopeValidationStatus(resp, domain),
		diag, mappings, status,
		&workerVersions{Worker: resp.WorkerVersion, Backend: resp.BackendVersion, PySigma: resp.PySigmaVersion})
}

func scopeValidationStatus(resp *sigmaWorkerResponse, domain DetectionDomainScope) string {
	if resp.Status == "OK" {
		return "PY_SIGMA_PARSED"
	}
	return "PRELIMINARY"
}

type workerVersions struct {
	Worker, Backend, PySigma string
}

func scopeDomain(scope *DetectionScope, domainID string) (DetectionDomainScope, bool) {
	for _, d := range scope.Domains {
		if d.DomainID == domainID {
			return d, true
		}
	}
	return DetectionDomainScope{}, false
}

func persistTranslation(userID string, rule *SigmaRule, domain DetectionDomainScope, req TranslationRequest,
	aql, validation string, diag TranslationDiagnostics, mappings []TranslationMapping,
	status string, versions *workerVersions) (*DetectionTranslation, error) {

	if mappings == nil {
		mappings = []TranslationMapping{}
	}
	snap, _ := json.Marshal(mappings)
	diagJSON, _ := json.Marshal(diag)
	aqlHash := ""
	if aql != "" {
		s := sha256.Sum256([]byte(aql))
		aqlHash = hex.EncodeToString(s[:])
	}
	tx, err := globalDB.Begin()
	if err != nil {
		return nil, err
	}
	// The worker ran outside this transaction, so everything it depended on is
	// re-checked here, atomically with the insert. A revoked grant, a rebound
	// domain, a changed mapping or a withdrawn approval aborts the write — no
	// READY draft is persisted on stale evidence.
	if err := revalidateTranslationTx(tx, userID, rule, domain, mappings); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	id := newID("dtr")
	var wv, bv, pv string
	if versions != nil {
		wv, bv, pv = versions.Worker, versions.Backend, versions.PySigma
	}
	if _, err := tx.Exec(`INSERT INTO detection_translations
		(translation_id, rule_id, client_id, instance_id, domain_id, native_qradar_domain_id, binding_revision,
		 conversion_mode, status, aql_draft, aql_sha256, time_window_days, mapping_snapshot, diagnostics,
		 worker_version, backend_version, pysigma_version, sigma_rule_hash, sigma_rule_version,
		 validation_status, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		id, rule.RuleID, rule.ClientID, domain.InstanceID, domain.DomainID, domain.NativeDomainID, domain.BindingRevision,
		req.Mode, status, aql, aqlHash, req.TimeWindowDays, string(snap), string(diagJSON),
		wv, bv, pv, rule.YAMLSHA256, rule.Version, validation, userID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := auditInTx(tx, userID, rule.ClientID, "DETECTION_TRANSLATE", id, status); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return GetDetectionTranslation(id, userID)
}

func GetDetectionTranslation(translationID, userID string) (*DetectionTranslation, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	t, err := loadTranslation(`WHERE t.translation_id = ?`, translationID)
	if err != nil {
		return nil, err
	}
	if !hasClientGrant(userID, t.ClientID) {
		return nil, ErrFieldAccessDenied
	}
	computeStaleness(t)
	return t, nil
}

func ListDetectionTranslations(userID, ruleID string) ([]DetectionTranslation, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	rule, err := GetSigmaRule(ruleID, userID)
	if err != nil {
		return nil, err
	}
	rows, err := globalDB.Query(`SELECT translation_id FROM detection_translations WHERE rule_id = ? AND client_id = ? ORDER BY created_at DESC`,
		ruleID, rule.ClientID)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	out := make([]DetectionTranslation, 0, len(ids))
	for _, id := range ids {
		t, err := loadTranslation(`WHERE t.translation_id = ?`, id)
		if err != nil {
			return nil, err
		}
		if !hasClientGrant(userID, t.ClientID) {
			continue
		}
		computeStaleness(t)
		out = append(out, *t)
	}
	return out, nil
}

func loadTranslation(where string, args ...interface{}) (*DetectionTranslation, error) {
	var t DetectionTranslation
	var snap, diag string
	err := globalDB.QueryRow(`SELECT t.translation_id, t.rule_id, t.client_id, t.instance_id, t.domain_id,
			t.native_qradar_domain_id, t.binding_revision, t.conversion_mode, t.status, t.aql_draft, t.aql_sha256,
			t.time_window_days, t.mapping_snapshot, t.diagnostics, t.worker_version, t.backend_version,
			t.pysigma_version, t.sigma_rule_hash, t.sigma_rule_version, t.validation_status, t.created_by, t.created_at
		FROM detection_translations t `+where, args...).
		Scan(&t.TranslationID, &t.RuleID, &t.ClientID, &t.InstanceID, &t.DomainID,
			&t.NativeDomainID, &t.BindingRevision, &t.Mode, &t.Status, &t.AQLDraft, &t.AQLSHA256,
			&t.TimeWindowDays, &snap, &diag, &t.WorkerVersion, &t.BackendVersion,
			&t.PySigmaVersion, &t.SigmaRuleHash, &t.SigmaRuleVersion, &t.ValidationStatus, &t.CreatedBy, &t.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrFieldInventoryNotFound
		}
		return nil, err
	}
	_ = json.Unmarshal([]byte(snap), &t.Mappings)
	_ = json.Unmarshal([]byte(diag), &t.Diagnostics)
	if t.Mappings == nil {
		t.Mappings = []TranslationMapping{}
	}
	return &t, nil
}

// computeStaleness derives staleness at read time from the stored provenance. A
// draft is never mutated; it is only marked as no longer trustworthy.
func computeStaleness(t *DetectionTranslation) {
	t.Stale = false
	t.StaleReasons = nil
	b, err := GetDomainBinding(t.DomainID)
	if err != nil {
		t.Stale = true
		t.StaleReasons = append(t.StaleReasons, "domain binding is no longer readable")
		return
	}
	if b.Revision != t.BindingRevision {
		t.Stale = true
		t.StaleReasons = append(t.StaleReasons, fmt.Sprintf("binding revision changed (%d → %d)", t.BindingRevision, b.Revision))
	}
	if b.BindingKind != "CLIENT" || b.VerificationStatus != "VERIFIED" || b.ClientID != t.ClientID {
		t.Stale = true
		t.StaleReasons = append(t.StaleReasons, "domain is no longer verified for this client")
	}
	rule, err := loadSigmaRule(t.RuleID)
	if err != nil {
		t.Stale = true
		t.StaleReasons = append(t.StaleReasons, "source rule is no longer readable")
		return
	}
	if rule.Version != t.SigmaRuleVersion || rule.YAMLSHA256 != t.SigmaRuleHash {
		t.Stale = true
		t.StaleReasons = append(t.StaleReasons, "source rule version changed")
	}
	for _, m := range t.Mappings {
		if m.Field == "" {
			continue
		}
		// The draft used a specific mapping version. It is stale if that row
		// disappeared, or if a newer applicable mapping now exists for the field.
		var currentID, currentVersion string
		err := globalDB.QueryRow(`SELECT mapping_id, mapping_version FROM qradar_field_mappings
			WHERE client_id = ? AND domain_id = ? AND LOWER(raw_source_field) = LOWER(?)
			ORDER BY CAST(mapping_version AS INTEGER) DESC, created_at DESC LIMIT 1`,
			t.ClientID, t.DomainID, m.Field).Scan(&currentID, &currentVersion)
		if err != nil {
			t.Stale = true
			t.StaleReasons = append(t.StaleReasons, "mapping for "+m.Field+" disappeared")
			continue
		}
		if m.MappingID != "" && currentID != m.MappingID {
			t.Stale = true
			t.StaleReasons = append(t.StaleReasons, "a newer mapping exists for "+m.Field)
			continue
		}
		if m.MappingVersion != "" && currentVersion != m.MappingVersion {
			t.Stale = true
			t.StaleReasons = append(t.StaleReasons, "mapping version for "+m.Field+" changed")
		}
	}
	_ = strings.TrimSpace
}
