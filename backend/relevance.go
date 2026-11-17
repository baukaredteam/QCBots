package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// M7-C: Client Relevance Engine (same-client-only, explainable, no scores).

var ErrRelevanceNotFound = errors.New("RELEVANCE_NOT_FOUND")

type RelevanceEvidence struct {
	EvidenceID             string `json:"evidence_id"`
	MatchedEntityType      string `json:"matched_entity_type"`
	MatchedEntityID        string `json:"matched_entity_id"`
	SourceReference        string `json:"source_reference,omitempty"`
	SourceReliability      string `json:"source_reliability,omitempty"`
	InventoryEvidence      string `json:"inventory_evidence,omitempty"`
	MatchingRuleID         string `json:"matching_rule_id"`
	MatchingRuleVersion    string `json:"matching_rule_version"`
}

type RelevanceFinding struct {
	FindingID   string              `json:"finding_id"`
	Dimension   string              `json:"dimension"`
	Verdict     string              `json:"verdict"`
	Explanation string              `json:"explanation"`
	Unknowns    []string            `json:"unknowns,omitempty"`
	Limitations []string            `json:"limitations,omitempty"`
	Evidence    []RelevanceEvidence `json:"evidence,omitempty"`
}

type RelevanceAssessment struct {
	AssessmentID         string                 `json:"assessment_id"`
	ReportID             string                 `json:"report_id"`
	ClientID             string                 `json:"client_id"`
	Status               string                 `json:"status"`
	ErrorCode            string                 `json:"error_code,omitempty"`
	CTIEvidenceSnapshot  string                 `json:"cti_evidence_snapshot"`
	InventorySnapshot    string                 `json:"inventory_snapshot"`
	RuleSetFingerprint   string                 `json:"rule_set_fingerprint"`
	MatchingRuleVersion  string                 `json:"matching_rule_version"`
	EvaluationAt         string                 `json:"evaluation_at,omitempty"`
	CTIEvidenceDocument  string                 `json:"cti_evidence_document,omitempty"`
	InventoryDocument    string                 `json:"inventory_document,omitempty"`
	Findings             []RelevanceFinding     `json:"findings,omitempty"`
	Reviews              []map[string]interface{} `json:"reviews,omitempty"`
}

// Seed default matching rules (versioned, idempotent).
func ensureRelevanceRules() error {
	defs := []struct{ id, dim, name, def string }{
		{"rule-sector-v1", "SECTOR", "sector-token", `{"mode":"token","source":"sectors.sector_name"}`},
		{"rule-tech-v1", "TECHNOLOGY", "tech-token", `{"mode":"token","source":"client_technologies"}`},
		{"rule-telemetry-v1", "TELEMETRY", "telemetry-path", `{"mode":"path","staleness_days":7}`},
	}
	for _, d := range defs {
		_, err := globalDB.Exec(`INSERT OR IGNORE INTO relevance_matching_rules (rule_id, rule_version, dimension, rule_name, rule_definition, created_at) VALUES (?, '1', ?, ?, ?, datetime('now'))`, d.id, d.dim, d.name, d.def)
		if err != nil {
			return err
		}
	}
	return nil
}

func snapshotHash(v interface{}) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// AssessRelevance runs one attempt (always a new row; idempotency replay handled by caller).
func AssessRelevance(userID, reportID, clientID, idemKey string) (*RelevanceAssessment, bool, error) {
	if err := requireM7Schema(); err != nil {
		return nil, false, err
	}
	// Same-client rule: report's tenant must equal requested client.
	report, err := globalDB.GetCTIReport(reportID)
	if err != nil {
		return nil, false, err
	}
	if report == nil {
		return nil, false, ErrReportNotFound
	}
	if report.ClientID != clientID {
		return nil, false, ErrReportAccessDenied
	}
	if !hasClientGrant(userID, clientID) {
		return nil, false, ErrReportAccessDenied
	}
	if err := requireMutation(userID); err != nil {
		return nil, false, err
	}
	if err := ensureRelevanceRules(); err != nil {
		return nil, false, err
	}
	// Build snapshots (source rows only, stable ordering). Documents are persisted
	// beside fingerprints so historical assessments stay reconstructable.
	ctiSnap, invSnap, ruleFP, ruleVer, ctiDoc, invDoc, ruleDoc, err := buildRelevanceSnapshots(reportID, clientID)
	if err != nil {
		return nil, false, err
	}
	fingerprint := snapshotHash(map[string]interface{}{
		"report_id": reportID, "client_id": clientID,
		"cti": ctiSnap, "inv": invSnap, "rules": ruleFP,
	})
	// Idempotent replay: same client+key -> existing operation (check fingerprint).
	if idemKey != "" {
		var priorID, priorFP string
		rowErr := globalDB.QueryRow(`SELECT assessment_id, COALESCE(payload_fingerprint,'') FROM relevance_assessments WHERE client_id = ? AND request_idempotency_key = ? LIMIT 1`, clientID, idemKey).Scan(&priorID, &priorFP)
		if rowErr == nil {
			if priorFP != "" && priorFP != fingerprint {
				return nil, false, ErrRelevanceIdempotencyConflict
			}
			existing, err := GetRelevanceAssessment(priorID)
			if err != nil {
				return nil, false, err
			}
			return existing, false, nil
		}
	}
	assessmentID := newID("assessment")
	// The evaluation reference time is pinned once, at attempt creation, and
	// persisted. TELEMETRY staleness is judged against it, never against the
	// clock at read time, so historical findings are not reinterpreted.
	evalAt := time.Now().UTC()
	evalAtStr := evalAt.Format(time.RFC3339)
	tx, err := globalDB.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	nkey := sql.NullString{}
	if idemKey != "" {
		nkey = sql.NullString{String: idemKey, Valid: true}
	}
	// Idempotency race: another request may have inserted the same key.
	if _, err := tx.Exec(`INSERT INTO relevance_assessments (assessment_id, report_id, client_id, status, request_idempotency_key, payload_fingerprint, cti_evidence_snapshot, inventory_snapshot, rule_set_fingerprint, matching_rule_version, evaluation_at, created_by, created_at)
		VALUES (?, ?, ?, 'PENDING', ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		assessmentID, reportID, clientID, nkey, fingerprint, ctiSnap, invSnap, ruleFP, ruleVer, evalAtStr, userID); err != nil {
		if isUniqueConstraintError(err) && idemKey != "" {
			// Concurrent winner: rollback, re-read, return existing (or 409 on mismatch).
			tx.Rollback()
			var priorID, priorFP string
			if err2 := globalDB.QueryRow(`SELECT assessment_id, COALESCE(payload_fingerprint,'') FROM relevance_assessments WHERE client_id = ? AND request_idempotency_key = ? LIMIT 1`, clientID, idemKey).Scan(&priorID, &priorFP); err2 == nil {
				if priorFP != "" && priorFP != fingerprint {
					return nil, false, ErrRelevanceIdempotencyConflict
				}
				existing, err := GetRelevanceAssessment(priorID)
				if err != nil {
					return nil, false, err
				}
				return existing, false, nil
			}
		}
		return nil, false, fmt.Errorf("creating assessment: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO relevance_snapshots (assessment_id, cti_evidence_document, inventory_document, rule_set_document, created_at) VALUES (?, ?, ?, ?, datetime('now'))`, assessmentID, ctiDoc, invDoc, ruleDoc); err != nil {
		return nil, false, fmt.Errorf("storing snapshots: %w", err)
	}
	// Findings/evidence live in a savepoint: any compute or persistence
	// failure rolls them ALL back while keeping the assessment + canonical
	// snapshots, which are then persisted as FAILED.
	if _, err := tx.Exec(`SAVEPOINT relevance_work`); err != nil {
		return nil, false, fmt.Errorf("savepoint: %w", err)
	}
	failAttempt := func(code string) (*RelevanceAssessment, bool, error) {
		if _, err := tx.Exec(`ROLLBACK TO SAVEPOINT relevance_work`); err != nil {
			return nil, false, fmt.Errorf("rolling back partial findings: %w", err)
		}
		if _, err := tx.Exec(`RELEASE SAVEPOINT relevance_work`); err != nil {
			return nil, false, fmt.Errorf("releasing savepoint: %w", err)
		}
		if _, err := tx.Exec(`UPDATE relevance_assessments SET status = 'FAILED', error_code = ? WHERE assessment_id = ?`, code, assessmentID); err != nil {
			return nil, false, fmt.Errorf("persisting FAILED attempt: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return nil, false, fmt.Errorf("committing FAILED attempt: %w", err)
		}
		return &RelevanceAssessment{AssessmentID: assessmentID, ReportID: reportID, ClientID: clientID, Status: "FAILED", ErrorCode: code, CTIEvidenceSnapshot: ctiSnap, InventorySnapshot: invSnap, RuleSetFingerprint: ruleFP, MatchingRuleVersion: ruleVer, EvaluationAt: evalAtStr, CTIEvidenceDocument: ctiDoc, InventoryDocument: invDoc}, true, nil
	}
	findings, err := computeRelevanceFindings(tx, report, clientID, evalAt)
	if err != nil {
		return failAttempt("compute_error")
	}
	for _, f := range findings {
		findingID := newID("finding")
		if _, err := tx.Exec(`INSERT INTO relevance_findings (finding_id, assessment_id, dimension, verdict, explanation, unknowns, limitations, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
			findingID, assessmentID, f.Dimension, f.Verdict, f.Explanation, jsonOrNull(f.Unknowns), jsonOrNull(f.Limitations)); err != nil {
			// Persisting failure must not roll back the FAILED attempt itself.
			return failAttempt("persist_error")
		}
		for _, e := range f.Evidence {
			evID := newID("evidence")
			if _, err := tx.Exec(`INSERT INTO relevance_evidence (evidence_id, finding_id, assessment_id, report_id, client_id, dimension, matched_entity_type, matched_entity_id, source_reference, source_reliability, inventory_evidence, matching_rule_id, matching_rule_version, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
				evID, findingID, assessmentID, reportID, clientID, f.Dimension, e.MatchedEntityType, e.MatchedEntityID, e.SourceReference, e.SourceReliability, e.InventoryEvidence, e.MatchingRuleID, e.MatchingRuleVersion); err != nil {
				return failAttempt("persist_error")
			}
		}
	}
	if _, err := tx.Exec(`RELEASE SAVEPOINT relevance_work`); err != nil {
		return failAttempt("persist_error")
	}
	if _, err := tx.Exec(`UPDATE relevance_assessments SET status = 'COMPLETED' WHERE assessment_id = ?`, assessmentID); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	out, err := GetRelevanceAssessment(assessmentID)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func jsonOrNull(v []string) interface{} {
	if len(v) == 0 {
		return nil
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func buildRelevanceSnapshots(reportID, clientID string) (ctiSnap, invSnap, ruleFP, ruleVer, ctiDoc, invDoc, ruleDoc string, err error) {
	// CTI evidence snapshot: source rows only, sorted by ID.
	type ind struct{ ID, Type, Value, Norm, Rule, Ref string }
	inds := []ind{}
	rows, err := globalDB.Query(`SELECT indicator_id, indicator_type, indicator_value, COALESCE(normalized_value,''), COALESCE(normalization_rule,''), COALESCE(source_reference,'') FROM indicators WHERE report_id = ? ORDER BY indicator_id`, reportID)
	if err != nil {
		return "", "", "", "", "", "", "", err
	}
	for rows.Next() {
		var i ind
		_ = rows.Scan(&i.ID, &i.Type, &i.Value, &i.Norm, &i.Rule, &i.Ref)
		inds = append(inds, i)
	}
	rows.Close()
	type tech struct{ ID, Mitre, Tactic, Name string }
	techs := []tech{}
	rows, err = globalDB.Query(`SELECT technique_id, COALESCE(mitre_technique_id,''), COALESCE(mitre_tactic,''), COALESCE(technique_name,'') FROM techniques WHERE report_id = ? ORDER BY technique_id`, reportID)
	if err != nil {
		return "", "", "", "", "", "", "", err
	}
	for rows.Next() {
		var x tech
		_ = rows.Scan(&x.ID, &x.Mitre, &x.Tactic, &x.Name)
		techs = append(techs, x)
	}
	rows.Close()
	type cve struct{ ID, Text string }
	cves := []cve{}
	rows, err = globalDB.Query(`SELECT cve_id, cve_id_text FROM cves WHERE report_id = ? ORDER BY cve_id`, reportID)
	if err != nil {
		return "", "", "", "", "", "", "", err
	}
	for rows.Next() {
		var x cve
		_ = rows.Scan(&x.ID, &x.Text)
		cves = append(cves, x)
	}
	rows.Close()
	type mal struct{ ID, Name, Family, Type string }
	mals := []mal{}
	rows, err = globalDB.Query(`SELECT malware_id, COALESCE(malware_name,''), COALESCE(family,''), COALESCE(type,'') FROM malware WHERE report_id = ? ORDER BY malware_id`, reportID)
	if err != nil {
		return "", "", "", "", "", "", "", err
	}
	for rows.Next() {
		var x mal
		_ = rows.Scan(&x.ID, &x.Name, &x.Family, &x.Type)
		mals = append(mals, x)
	}
	rows.Close()
	// SECTOR matching reads the report title; it is part of the fingerprint.
	title := ""
	if err := globalDB.QueryRow(`SELECT COALESCE(title,'') FROM cti_reports WHERE report_id = ?`, reportID).Scan(&title); err != nil {
		return "", "", "", "", "", "", "", err
	}

	// Inventory snapshot.
	type sector struct{ ID, Name string }
	sectors := []sector{}
	rows, err = globalDB.Query(`SELECT s.sector_id, s.sector_name FROM client_sector_mapping m JOIN sectors s ON s.sector_id = m.sector_id WHERE m.client_id = ? ORDER BY s.sector_id`, clientID)
	if err != nil {
		return "", "", "", "", "", "", "", err
	}
	for rows.Next() {
		var x sector
		_ = rows.Scan(&x.ID, &x.Name)
		sectors = append(sectors, x)
	}
	rows.Close()
	type technology struct{ ID, Name, Category, Version string }
	techs2 := []technology{}
	rows, err = globalDB.Query(`SELECT tech_id, technology_name, COALESCE(category,''), COALESCE(version,'') FROM client_technologies WHERE client_id = ? ORDER BY tech_id`, clientID)
	if err != nil {
		return "", "", "", "", "", "", "", err
	}
	for rows.Next() {
		var x technology
		_ = rows.Scan(&x.ID, &x.Name, &x.Category, &x.Version)
		techs2 = append(techs2, x)
	}
	rows.Close()
	type tele struct{ ID, SourceType, Status, LastEvent, Checked, FieldAvail string }
	teles := []tele{}
	rows, err = globalDB.Query(`SELECT status_id, log_source_type_id, connection_status, COALESCE(last_event_timestamp,''), COALESCE(last_checked_at,''), COALESCE(field_availability,'') FROM client_log_source_status WHERE client_id = ? ORDER BY status_id`, clientID)
	if err != nil {
		return "", "", "", "", "", "", "", err
	}
	for rows.Next() {
		var x tele
		_ = rows.Scan(&x.ID, &x.SourceType, &x.Status, &x.LastEvent, &x.Checked, &x.FieldAvail)
		teles = append(teles, x)
	}
	rows.Close()

	// Rule-set fingerprint: every mutable source row that influences
	// computation (not merely rule ID/version labels).
	type rr struct{ ID, Ver, Dim, Name, Def string }
	ruleRows, err := globalDB.Query(`SELECT rule_id, rule_version, dimension, rule_name, rule_definition FROM relevance_matching_rules ORDER BY rule_id, rule_version`)
	if err != nil {
		return "", "", "", "", "", "", "", err
	}
	var rulePairs []rr
	for ruleRows.Next() {
		var x rr
		_ = ruleRows.Scan(&x.ID, &x.Ver, &x.Dim, &x.Name, &x.Def)
		rulePairs = append(rulePairs, x)
	}
	ruleRows.Close()
	sort.Slice(rulePairs, func(i, j int) bool { return rulePairs[i].ID+rulePairs[i].Ver < rulePairs[j].ID+rulePairs[j].Ver })
	type detRule struct{ ID, Mitre, Sources string }
	detRules := []detRule{}
	ruleRows, err = globalDB.Query(`SELECT rule_id, COALESCE(mitre_techniques,''), COALESCE(required_log_sources,'') FROM detection_rules ORDER BY rule_id`)
	if err != nil {
		return "", "", "", "", "", "", "", err
	}
	for ruleRows.Next() {
		var x detRule
		_ = ruleRows.Scan(&x.ID, &x.Mitre, &x.Sources)
		detRules = append(detRules, x)
	}
	ruleRows.Close()
	type reqRow struct{ RuleID, FieldID string; Required bool }
	reqRows := []reqRow{}
	ruleRows, err = globalDB.Query(`SELECT rule_id, field_id, is_required FROM rule_field_requirements ORDER BY rule_id, field_id`)
	if err != nil {
		return "", "", "", "", "", "", "", err
	}
	for ruleRows.Next() {
		var x reqRow
		var req int
		_ = ruleRows.Scan(&x.RuleID, &x.FieldID, &req)
		x.Required = req != 0
		reqRows = append(reqRows, x)
	}
	ruleRows.Close()
	type glField struct{ ID, Name string; Active bool }
	glFields := []glField{}
	ruleRows, err = globalDB.Query(`SELECT field_id, COALESCE(field_name,''), is_active FROM global_fields ORDER BY field_id`)
	if err != nil {
		return "", "", "", "", "", "", "", err
	}
	for ruleRows.Next() {
		var x glField
		var act int
		_ = ruleRows.Scan(&x.ID, &x.Name, &act)
		x.Active = act != 0
		glFields = append(glFields, x)
	}
	ruleRows.Close()
	ruleVer = "1"
	if len(rulePairs) > 0 {
		ruleVer = rulePairs[0].Ver
	}
	ctiMap := map[string]interface{}{"report_id": reportID, "title": title, "indicators": inds, "techniques": techs, "cves": cves, "malware": mals}
	invMap := map[string]interface{}{"client_id": clientID, "sectors": sectors, "technologies": techs2, "telemetry": teles}
	ruleMap := map[string]interface{}{"matching_rules": rulePairs, "detection_rules": detRules, "field_requirements": reqRows, "global_fields": glFields}
	ruleFP = snapshotHash(ruleMap)
	ctiSnap = snapshotHash(ctiMap)
	invSnap = snapshotHash(invMap)
	ctiDocJSON, _ := json.Marshal(ctiMap)
	invDocJSON, _ := json.Marshal(invMap)
	ruleDocJSON, _ := json.Marshal(ruleMap)
	return ctiSnap, invSnap, ruleFP, ruleVer, string(ctiDocJSON), string(invDocJSON), string(ruleDocJSON), nil
}

var ErrRelevanceIdempotencyConflict = errors.New("RELEVANCE_IDEMPOTENCY_CONFLICT")

// GetRelevanceAssessment returns one assessment with findings+evidence+reviews.
func GetRelevanceAssessment(assessmentID string) (*RelevanceAssessment, error) {
	a := &RelevanceAssessment{AssessmentID: assessmentID}
	err := globalDB.QueryRow(`SELECT assessment_id, report_id, client_id, status, COALESCE(error_code,''), cti_evidence_snapshot, inventory_snapshot, rule_set_fingerprint, matching_rule_version FROM relevance_assessments WHERE assessment_id = ?`, assessmentID).
		Scan(&a.AssessmentID, &a.ReportID, &a.ClientID, &a.Status, &a.ErrorCode, &a.CTIEvidenceSnapshot, &a.InventorySnapshot, &a.RuleSetFingerprint, &a.MatchingRuleVersion)
	if err != nil {
		return nil, err
	}
	// Best-effort: present after migration 0009, empty on older schemas.
	_ = globalDB.QueryRow(`SELECT COALESCE(evaluation_at,'') FROM relevance_assessments WHERE assessment_id = ?`, assessmentID).Scan(&a.EvaluationAt)
	_ = globalDB.QueryRow(`SELECT COALESCE(cti_evidence_document,''), COALESCE(inventory_document,'') FROM relevance_snapshots WHERE assessment_id = ?`, assessmentID).Scan(&a.CTIEvidenceDocument, &a.InventoryDocument)
	frows, err := globalDB.Query(`SELECT finding_id, dimension, verdict, explanation, COALESCE(unknowns,''), COALESCE(limitations,'') FROM relevance_findings WHERE assessment_id = ? ORDER BY dimension`, assessmentID)
	if err != nil {
		return nil, err
	}
	defer frows.Close()
	for frows.Next() {
		var f RelevanceFinding
		var un, lim string
		if err := frows.Scan(&f.FindingID, &f.Dimension, &f.Verdict, &f.Explanation, &un, &lim); err != nil {
			return nil, err
		}
		if un != "" {
			_ = json.Unmarshal([]byte(un), &f.Unknowns)
		}
		if lim != "" {
			_ = json.Unmarshal([]byte(lim), &f.Limitations)
		}
		a.Findings = append(a.Findings, f)
	}
	if err := frows.Err(); err != nil {
		return nil, err
	}
	for i := range a.Findings {
		erows, err := globalDB.Query(`SELECT evidence_id, matched_entity_type, matched_entity_id, COALESCE(source_reference,''), COALESCE(source_reliability,''), COALESCE(inventory_evidence,''), matching_rule_id, matching_rule_version FROM relevance_evidence WHERE finding_id = ? ORDER BY evidence_id`, a.Findings[i].FindingID)
		if err != nil {
			return nil, err
		}
		for erows.Next() {
			var e RelevanceEvidence
			if err := erows.Scan(&e.EvidenceID, &e.MatchedEntityType, &e.MatchedEntityID, &e.SourceReference, &e.SourceReliability, &e.InventoryEvidence, &e.MatchingRuleID, &e.MatchingRuleVersion); err != nil {
				erows.Close()
				return nil, err
			}
			a.Findings[i].Evidence = append(a.Findings[i].Evidence, e)
		}
		erows.Close()
	}
	rrows, err := globalDB.Query(`SELECT review_id, dimension, original_verdict, override_verdict, reason, reviewed_at FROM relevance_reviews WHERE assessment_id = ? ORDER BY reviewed_at, review_id`, assessmentID)
	if err == nil {
		defer rrows.Close()
		for rrows.Next() {
			var id, dim, ov, ovr, reason, at string
			if err := rrows.Scan(&id, &dim, &ov, &ovr, &reason, &at); err == nil {
				a.Reviews = append(a.Reviews, map[string]interface{}{
					"review_id": id, "dimension": dim, "original_verdict": ov,
					"override_verdict": ovr, "reason": reason, "reviewed_at": at,
				})
			}
		}
	}
	return a, nil
}

// LatestCompletedAssessment returns the newest COMPLETED assessment for (report, client).
func LatestCompletedAssessment(reportID, clientID string) (*RelevanceAssessment, error) {
	var id string
	err := globalDB.QueryRow(`SELECT assessment_id FROM relevance_assessments WHERE report_id = ? AND client_id = ? AND status = 'COMPLETED' ORDER BY created_at DESC, rowid DESC LIMIT 1`, reportID, clientID).Scan(&id)
	if err != nil {
		return nil, err
	}
	return GetRelevanceAssessment(id)
}
