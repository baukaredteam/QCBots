package main

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// M7-D Phase 2B-2 (corrected): resolve what a selected client actually has for a
// Sigma rule.
//
// Readiness is evidence, not a claim: it never asserts QRadar DSM equivalence
// beyond the curated catalogue, never treats a token match as verified, and never
// turns a database error into "MISSING". A lookup failure fails the analysis.

const (
	ReadinessReady             = "READY_FOR_REVIEW"
	ReadinessNeedsVerification = "NEEDS_FIELD_VERIFICATION"
	ReadinessTelemetryUnknown  = "TELEMETRY_UNKNOWN"
	ReadinessUnsupported       = "UNSUPPORTED"
	ReadinessBlocked           = "BLOCKED"

	FieldStateAttested      = "AQL_MANUALLY_ATTESTED"
	FieldStateApproved      = "MAPPING_APPROVED"
	FieldStateCEPDisplayed  = "CEP_DISPLAYED"
	FieldStateRawObserved   = "RAW_OBSERVED"
	FieldStateUnverified    = "UNVERIFIED"
	FieldStateMissing       = "MISSING"
	FieldStateUnsupported   = "UNSUPPORTED"
	FieldStateConflict      = "CONFLICTING_MAPPINGS"
	FieldStateTypeMismatch  = "TYPE_MISMATCH"
	FieldStateScopeMismatch = "SCOPE_MISMATCH"

	CandidateToken = "CANDIDATE"       // name-token match only
	CandidateDSM   = "CATALOGUE_MATCH" // curated catalogue match AND present in inventory
)

// ErrFieldAnalysisUnavailable means the registry could not be read. The caller
// must fail closed: an unreadable registry is not "no telemetry".
var ErrFieldAnalysisUnavailable = errors.New("FIELD_ANALYSIS_UNAVAILABLE")

type FieldReadiness struct {
	Field          string `json:"field"`
	State          string `json:"state"`
	CEPField       string `json:"cep_field,omitempty"`
	MappingID      string `json:"mapping_id,omitempty"`
	MappingVersion string `json:"mapping_version,omitempty"`
	FieldID        string `json:"field_id,omitempty"`
	Observation    string `json:"observation,omitempty"`
	Evidence       string `json:"evidence,omitempty"`
	ApprovedBy     string `json:"approved_by,omitempty"`
	Detail         string `json:"detail,omitempty"`
}

type LogSourceCandidate struct {
	LogSourceTypeID string `json:"log_source_type_id"`
	TypeName        string `json:"type_name"`
	Match           string `json:"match"`
	LogSourceID     string `json:"log_source_id,omitempty"`
	Status          string `json:"status,omitempty"`
}

type DetectionDomainScope struct {
	InstanceID      string               `json:"instance_id"`
	DomainID        string               `json:"domain_id"`
	NativeDomainID  string               `json:"native_qradar_domain_id"`
	DomainName      string               `json:"domain_name"`
	BindingRevision int                  `json:"binding_revision"`
	Status          string               `json:"status"`
	DSMVerified     bool                 `json:"dsm_verified"`
	PrimaryDSM      string               `json:"primary_dsm,omitempty"`
	LogSources      []LogSourceCandidate `json:"log_sources"`
	Fields          []FieldReadiness     `json:"fields"`
}

type DetectionScope struct {
	RuleID             string                 `json:"rule_id"`
	ClientID           string                 `json:"client_id"`
	Status             string                 `json:"status"`
	Domains            []DetectionDomainScope `json:"domains"`
	Notes              []string               `json:"notes"`
	Modifiers          []string               `json:"modifiers"`
	Fields             []string               `json:"fields"`
	CatalogueVersion   string                 `json:"logsource_catalogue_version"`
	ValidationStatus   string                 `json:"validation_status"`
}

// AnalyzeDetectionScope builds the readiness picture for one rule and client.
func AnalyzeDetectionScope(userID, clientID, ruleID string) (*DetectionScope, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	rule, err := GetSigmaRule(ruleID, userID)
	if err != nil {
		return nil, err
	}
	if rule.ClientID != clientID {
		return nil, ErrFieldAccessDenied
	}

	scope := &DetectionScope{
		RuleID: rule.RuleID, ClientID: clientID,
		Modifiers: rule.Modifiers, Fields: rule.Fields,
		CatalogueVersion: sigmaLogsourceCatalogueVersion,
		ValidationStatus: "PRELIMINARY",
	}
	if len(rule.Fields) == 0 {
		scope.Notes = append(scope.Notes, "the rule exposes no extractable fields: readiness cannot be established from field evidence")
	}

	type domRow struct {
		instanceID, domainID, nativeID, name string
		revision                             int
	}
	var domains []domRow
	rows, err := globalDB.Query(`SELECT b.instance_id, b.domain_id, d.native_qradar_domain_id, d.domain_name, b.revision
		FROM qradar_domain_bindings b
		JOIN qradar_domains d ON d.domain_id = b.domain_id
		WHERE b.client_id = ?
		  AND b.binding_kind = 'CLIENT'
		  AND b.verification_status = 'VERIFIED'
		  AND b.verified_by IS NOT NULL AND b.verified_at IS NOT NULL AND b.evidence_reference IS NOT NULL
		  AND d.native_qradar_domain_id IS NOT NULL AND TRIM(d.native_qradar_domain_id) <> ''
		  AND d.native_id_status = 'VERIFIED'
		ORDER BY d.domain_name`, clientID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFieldAnalysisUnavailable, err)
	}
	for rows.Next() {
		var d domRow
		if err := rows.Scan(&d.instanceID, &d.domainID, &d.nativeID, &d.name, &d.revision); err != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: %v", ErrFieldAnalysisUnavailable, err)
		}
		domains = append(domains, d)
	}
	rows.Close()
	if len(domains) == 0 {
		scope.Status = ReadinessBlocked
		scope.Notes = append(scope.Notes, "no verified client domain binding: confirm a native QRadar domain id before translating")
		return scope, nil
	}

	eventToken := sigmaEventToken(rule)
	worst := ReadinessReady
	for _, d := range domains {
		ds := DetectionDomainScope{
			InstanceID: d.instanceID, DomainID: d.domainID, NativeDomainID: d.nativeID,
			DomainName: d.name, BindingRevision: d.revision,
		}
		candidates, err := matchLogSources(d.domainID, rule)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFieldAnalysisUnavailable, err)
		}
		ds.LogSources = candidates
		ds.PrimaryDSM, ds.DSMVerified = primaryDSM(candidates)
		ds.Fields, err = fieldReadiness(clientID, d.domainID, rule.Fields, mappingScope{DSM: ds.PrimaryDSM, Event: eventToken})
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFieldAnalysisUnavailable, err)
		}
		ds.Status = domainStatus(ds)
		if severity(ds.Status) > severity(worst) {
			worst = ds.Status
		}
		scope.Domains = append(scope.Domains, ds)
	}
	scope.Status = worst
	if eventToken != "" {
		scope.Notes = append(scope.Notes, "event scope derived from the rule's event-id value ("+eventToken+"); it is a Sigma value, not a QRadar Event Name or QID")
	} else {
		scope.Notes = append(scope.Notes, "no event identity could be derived: event-scoped mappings are not applied")
	}
	if len(rule.Modifiers) > 0 {
		scope.Notes = append(scope.Notes, "modifiers present ("+strings.Join(rule.Modifiers, ", ")+"); conversion support is decided in Phase 2B-3 and unsupported ones must block translation")
	}
	return scope, nil
}

// sigmaEventToken extracts a single scalar value from an event-id-like selection
// field. It is used only to decide whether an event-scoped mapping applies.
func sigmaEventToken(rule *SigmaRule) string {
	parsed, err := parseSigma([]byte(rule.YAML))
	if err != nil {
		return ""
	}
	eventFields := map[string]bool{"eventid": true, "eventcode": true, "event_id": true}
	for name, value := range parsed.Doc.Detection {
		if name == "condition" || name == "timeframe" {
			continue
		}
		m, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		for k, v := range m {
			base := k
			if i := strings.Index(k, "|"); i >= 0 {
				base = k[:i]
			}
			if !eventFields[normalizeFieldName(base)] {
				continue
			}
			switch tv := v.(type) {
			case int:
				return fmt.Sprintf("%d", tv)
			case int64:
				return fmt.Sprintf("%d", tv)
			case string:
				if strings.TrimSpace(tv) != "" {
					return strings.TrimSpace(tv)
				}
			case []interface{}:
				if len(tv) == 1 {
					if s, ok := tv[0].(string); ok {
						return s
					}
				}
			}
		}
	}
	return ""
}

func severity(status string) int {
	switch status {
	case ReadinessReady:
		return 0
	case ReadinessNeedsVerification:
		return 1
	case ReadinessTelemetryUnknown:
		return 2
	case ReadinessUnsupported:
		return 3
	case ReadinessBlocked:
		return 4
	}
	return 1
}

// primaryDSM picks the strongest candidate and reports whether the curated
// catalogue matched a DSM that actually exists in this client's inventory.
func primaryDSM(cands []LogSourceCandidate) (string, bool) {
	for _, c := range cands {
		if c.Match == CandidateDSM {
			return c.TypeName, true
		}
	}
	if len(cands) > 0 {
		return cands[0].TypeName, false
	}
	return "", false
}

// matchLogSources proposes candidates. A candidate is CATALOGUE_MATCH only when
// the curated catalogue names a DSM and that DSM exists in the domain inventory;
// otherwise it stays a name-token CANDIDATE.
func matchLogSources(domainID string, rule *SigmaRule) ([]LogSourceCandidate, error) {
	rows, err := globalDB.Query(`SELECT t.log_source_type_id, t.type_name,
			COALESCE((SELECT l.log_source_id FROM qradar_log_sources l WHERE l.log_source_type_id = t.log_source_type_id ORDER BY l.created_at LIMIT 1),''),
			COALESCE((SELECT l.status FROM qradar_log_sources l WHERE l.log_source_type_id = t.log_source_type_id ORDER BY l.created_at LIMIT 1),'')
		FROM qradar_log_source_types t WHERE t.domain_id = ? ORDER BY t.type_name`, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tokens := logsourceTokens(rule)
	dsms := catalogueDSMs(rule)
	var out []LogSourceCandidate
	for rows.Next() {
		var id, name, lsID, status string
		if err := rows.Scan(&id, &name, &lsID, &status); err != nil {
			return nil, err
		}
		lower := strings.ToLower(name)
		matched := false
		for _, t := range tokens {
			if strings.Contains(lower, t) {
				matched = true
				break
			}
		}
		catalogue := false
		for _, dsm := range dsms {
			if strings.EqualFold(strings.TrimSpace(dsm), strings.TrimSpace(name)) {
				catalogue = true
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		match := CandidateToken
		if catalogue {
			match = CandidateDSM
		}
		out = append(out, LogSourceCandidate{
			LogSourceTypeID: id, TypeName: name, Match: match,
			LogSourceID: lsID, Status: status,
		})
	}
	return out, rows.Err()
}

// logsourceTokens converts Sigma logsource metadata into search tokens. Hints
// only: they never establish DSM equivalence.
func logsourceTokens(rule *SigmaRule) []string {
	var tokens []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			tokens = append(tokens, s)
		}
	}
	switch strings.ToLower(rule.LogsourceProduct) {
	case "windows":
		add("windows")
	case "linux":
		add("linux")
	case "macos":
		add("macos")
	}
	switch strings.ToLower(rule.LogsourceService) {
	case "security":
		add("security")
	case "sysmon":
		add("sysmon")
	case "iis", "webserver":
		add("iis")
	case "powershell":
		add("powershell")
	}
	switch strings.ToLower(rule.LogsourceCategory) {
	case "webserver":
		add("iis")
	case "process_creation":
		add("windows")
		add("sysmon")
	case "dns":
		add("dns")
	}
	return tokens
}

type mappingScope struct {
	DSM   string
	Event string
}

// fieldReadiness resolves each Sigma field inside the selected DSM/event scope.
// A registry read error aborts the analysis instead of being reported as a
// missing field.
func fieldReadiness(clientID, domainID string, fields []string, sc mappingScope) ([]FieldReadiness, error) {
	out := make([]FieldReadiness, 0, len(fields))
	for _, f := range fields {
		fr, err := oneFieldReadiness(clientID, domainID, f, sc)
		if err != nil {
			return nil, err
		}
		out = append(out, fr)
	}
	return out, nil
}

func oneFieldReadiness(clientID, domainID, field string, sc mappingScope) (FieldReadiness, error) {
	fr := FieldReadiness{Field: field}

	type mapRow struct {
		id, cep, version, origin, approvedBy, dsm, event string
	}
	rows, err := globalDB.Query(`SELECT mapping_id, target_cep_field, mapping_version, origin, COALESCE(approved_by,''),
			COALESCE(applicable_dsm,''), COALESCE(applicable_event,'')
		FROM qradar_field_mappings
		WHERE client_id = ? AND domain_id = ? AND LOWER(raw_source_field) = LOWER(?)
		ORDER BY CAST(mapping_version AS INTEGER) DESC, created_at DESC`, clientID, domainID, field)
	if err != nil {
		return fr, err
	}
	var all []mapRow
	for rows.Next() {
		var m mapRow
		if err := rows.Scan(&m.id, &m.cep, &m.version, &m.origin, &m.approvedBy, &m.dsm, &m.event); err != nil {
			rows.Close()
			return fr, err
		}
		all = append(all, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fr, err
	}

	// Scope filter: a mapping bound to a different DSM, or to an event we cannot
	// establish, is not applicable. It is reported, never silently ignored.
	// Fail closed: an unknown selected DSM never matches a DSM-scoped mapping.
	var applicable []mapRow
	scopeRejected := 0
	for _, m := range all {
		if m.dsm != "" {
			if sc.DSM == "" || !strings.EqualFold(strings.TrimSpace(m.dsm), strings.TrimSpace(sc.DSM)) {
				scopeRejected++
				continue
			}
		}
		if m.event != "" {
			if sc.Event == "" || !strings.EqualFold(strings.TrimSpace(m.event), strings.TrimSpace(sc.Event)) {
				scopeRejected++
				continue
			}
		}
		applicable = append(applicable, m)
	}

	targets := map[string]bool{}
	approvedCount := 0
	approvedByID := ""
	for _, m := range applicable {
		targets[m.cep] = true
		if m.approvedBy != "" {
			approvedCount++
			approvedByID = m.approvedBy
		}
	}
	fr.ApprovedBy = approvedByID
	if len(targets) > 1 || approvedCount > 1 {
		fr.State = FieldStateConflict
		fr.Detail = "more than one applicable target or approved mapping for this raw field"
		return fr, nil
	}
	if len(applicable) > 0 {
		fr.CEPField = applicable[0].cep
		fr.MappingID = applicable[0].id
		fr.MappingVersion = applicable[0].version
	} else if scopeRejected > 0 {
		fr.State = FieldStateScopeMismatch
		fr.Detail = fmt.Sprintf("%d mapping(s) exist but are bound to a different DSM or event", scopeRejected)
		return fr, nil
	}

	var fieldID, dataType, obsStatus, obsEvidence string
	if fr.CEPField != "" {
		err := globalDB.QueryRow(`SELECT field_id, COALESCE(data_type,'') FROM qradar_field_definitions
			WHERE client_id = ? AND domain_id = ? AND (cep_identifier = ? OR LOWER(field_name) = LOWER(?))
			ORDER BY created_at LIMIT 1`, clientID, domainID, fr.CEPField, field).Scan(&fieldID, &dataType)
		if err != nil && err != sql.ErrNoRows {
			return fr, err
		}
	}
	if fieldID != "" {
		fr.FieldID = fieldID
		var n int
		if err := globalDB.QueryRow(`SELECT COUNT(*) FROM qradar_field_observations
			WHERE client_id = ? AND domain_id = ? AND field_id = ? AND aql_verification_status = 'VERIFIED'`,
			clientID, domainID, fieldID).Scan(&n); err != nil {
			return fr, err
		}
		if n > 0 {
			_ = globalDB.QueryRow(`SELECT aql_verification_status, COALESCE(evidence_reference,'') FROM qradar_field_observations
				WHERE client_id = ? AND domain_id = ? AND field_id = ? AND aql_verification_status = 'VERIFIED'
				ORDER BY created_at DESC LIMIT 1`, clientID, domainID, fieldID).Scan(&obsStatus, &obsEvidence)
			fr.Observation = obsStatus
			fr.Evidence = obsEvidence
			if approvedCount == 1 {
				fr.State = FieldStateAttested
				return fr, nil
			}
			fr.State = FieldStateCEPDisplayed
			fr.Detail = "AQL attested but no approved mapping"
			return fr, nil
		}
		var displayed int
		if err := globalDB.QueryRow(`SELECT COUNT(*) FROM qradar_field_observations
			WHERE client_id = ? AND domain_id = ? AND field_id = ? AND qradar_property_displayed = 1`,
			clientID, domainID, fieldID).Scan(&displayed); err != nil {
			return fr, err
		}
		if approvedCount == 1 {
			fr.State = FieldStateApproved
			fr.Detail = "mapping approved; AQL not attested"
			return fr, nil
		}
		if displayed > 0 {
			fr.State = FieldStateCEPDisplayed
			fr.Detail = "CEP displayed in QRadar, no approved mapping or attestation"
			return fr, nil
		}
		if len(applicable) > 0 {
			fr.State = FieldStateUnverified
			fr.Detail = "mapping exists but is not approved"
			return fr, nil
		}
		fr.State = FieldStateRawObserved
		fr.Detail = "field definition exists without an approved mapping"
		return fr, nil
	}
	if len(applicable) > 0 {
		if approvedCount == 1 {
			fr.State = FieldStateApproved
			fr.Detail = "mapping approved; no field definition or observation recorded"
			return fr, nil
		}
		fr.State = FieldStateUnverified
		fr.Detail = "mapping exists but is not approved"
		return fr, nil
	}
	fr.State = FieldStateMissing
	fr.Detail = "no applicable mapping for this field in this client domain"
	return fr, nil
}

// domainStatus collapses the evidence into one status. READY needs a
// catalogue-verified DSM, at least one field, and every field attested.
func domainStatus(d DetectionDomainScope) string {
	if len(d.LogSources) == 0 {
		return ReadinessTelemetryUnknown
	}
	if !d.DSMVerified {
		return ReadinessTelemetryUnknown
	}
	if len(d.Fields) == 0 {
		return ReadinessNeedsVerification
	}
	worst := ReadinessReady
	for _, f := range d.Fields {
		switch f.State {
		case FieldStateAttested:
		case FieldStateUnsupported:
			if severity(ReadinessUnsupported) > severity(worst) {
				worst = ReadinessUnsupported
			}
		default:
			if severity(ReadinessNeedsVerification) > severity(worst) {
				worst = ReadinessNeedsVerification
			}
		}
	}
	return worst
}
