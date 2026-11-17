package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// M7-D Phase 1: versioned threat-hunting hypothesis domain.
// Whatever the caller writes, the version lifecycle flows through
// hunt_hypothesis_version_events; version rows are never rewritten once an
// event exists on them. Approval always binds (hypothesis_id, version_no).

var (
	ErrHuntNotFound        = errors.New("HUNT_NOT_FOUND")
	ErrHuntAccessDenied    = errors.New("HUNT_ACCESS_DENIED")
	ErrHuntReviewDenied    = errors.New("HUNT_REVIEW_DENIED")
	ErrInvalidHypothesis   = errors.New("INVALID_HYPOTHESIS")
	ErrVersionConflict     = errors.New("VERSION_CONFLICT")
	ErrHuntInvalidTransition = errors.New("HUNT_INVALID_TRANSITION")
	ErrHuntIdempotencyConflict = errors.New("HUNT_IDEMPOTENCY_CONFLICT")
)

// requireM7DSchema gates M7-D service calls until 0010 is present.
func requireM7DSchema() error {
	if err := requireM6Schema(); err != nil {
		return err
	}
	var n int
	if err := globalDB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='hunt_hypothesis_versions'`).Scan(&n); err != nil || n == 0 {
		return ErrSchemaNotReady
	}
	return nil
}

type HypothesisInput struct {
	Title                string
	Description          string
	Statement            string
	SuspectedBehavior    string
	AdversaryObjective   string
	MitreTactics         string
	MitreTechniques      string
	BenignExplanations   string
	Assumptions          string
	BlindSpots           string
	Limitations          string
	GenerationMethod     string
	IdempotencyKey       string
	Evidence             []HypothesisEvidenceInput
}

type HypothesisEvidenceInput struct {
	Role              string `json:"role"`
	TargetType        string `json:"target_entity_type"`
	TargetID          string `json:"target_entity_id"`
	ReportID          string `json:"report_id"`
	AssessmentID      string `json:"assessment_id"`
	SourceRef         string `json:"source_reference"`
	SourceReliability string `json:"source_reliability"`
}

type hypothesisEvidence = HypothesisEvidenceInput

type HypothesisVersion struct {
	VersionID       string
	VersionNo       int
	CreationStatus  string
	EffectiveStatus string
	DraftRevision   int
	Statement       string
	Suspected       string
	Objective       string
	Tactics         string
	Techniques      string
	Benign          string
	Assumptions     string
	BlindSpots      string
	Limitations     string
	AuthorID        string
	GenerationMethod string
	CreatedAt       string
}

type HypothesisDetail struct {
	HypothesisID     string
	ClientID         string
	Title            string
	Description      string
	ReportID         string
	AssessmentID     string
	GenerationMethod string
	AuthorID         string
	CurrentVersionNo int
	CurrentVersion   *HypothesisVersion
	CreatedAt        string
	UpdatedAt        string
}

type HypothesisEvent struct {
	EventID      string
	HypothesisID string
	VersionNo    int
	FromStatus   string
	ToStatus     string
	ActorID      string
	Reason       string
	CreatedAt    string
}

type HuntReviewResult struct {
	ReviewID       string
	HypothesisID   string
	VersionNo      int
	ReviewerID     string
	Decision       string
	Reason         string
	OriginalStatus string
	ReviewedAt     string
}

type HypothesisEdit struct {
	Statement             string
	Suspected             string
	Objective             string
	Tactics               string
	Techniques            string
	Benign                string
	Assumptions           string
	BlindSpots            string
	Limitations           string
	ExpectedDraftRevision int
}

type huntEvidenceTuple struct {
	Role              string `json:"role"`
	TargetType        string `json:"target_type"`
	TargetID          string `json:"target_id"`
	ReportID          string `json:"report_id"`
	AssessmentID      string `json:"assessment_id"`
	SourceReference   string `json:"source_reference"`
	SourceReliability string `json:"source_reliability"`
}

func canonicalHypothesisEvidenceTuples(evidence []HypothesisEvidenceInput) []huntEvidenceTuple {
	out := make([]huntEvidenceTuple, 0, len(evidence))
	seen := map[string]struct{}{}
	for _, e := range evidence {
		tuple := huntEvidenceTuple{
			Role: e.Role, TargetType: e.TargetType, TargetID: e.TargetID,
			ReportID: e.ReportID, AssessmentID: e.AssessmentID,
			SourceReference: e.SourceRef, SourceReliability: e.SourceReliability,
		}
		b, _ := json.Marshal(tuple)
		key := string(b)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, tuple)
	}
	sort.Slice(out, func(i, j int) bool {
		left, _ := json.Marshal(out[i])
		right, _ := json.Marshal(out[j])
		return string(left) < string(right)
	})
	if out == nil {
		out = []huntEvidenceTuple{}
	}
	return out
}

func deduplicateHypothesisEvidence(evidence []HypothesisEvidenceInput) []HypothesisEvidenceInput {
	if len(evidence) == 0 {
		return evidence
	}
	out := make([]HypothesisEvidenceInput, 0, len(evidence))
	seen := map[string]struct{}{}
	for _, e := range evidence {
		tuple := huntEvidenceTuple{
			Role: e.Role, TargetType: e.TargetType, TargetID: e.TargetID,
			ReportID: e.ReportID, AssessmentID: e.AssessmentID,
			SourceReference: e.SourceRef, SourceReliability: e.SourceReliability,
		}
		b, _ := json.Marshal(tuple)
		key := string(b)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, e)
	}
	return out
}

func huntFingerprint(in *HypothesisInput, clientID, reportID, assessmentID string) string {
	// P0-2 canonical payload contract: every semantic input that affects
	// hypothesis creation is hashed; generated ids/timestamps are excluded.
	// evidence bindings (including derived CTI_SOURCE + RELEVANCE rows) are
	// canonicalized as structured JSON tuples before hashing.
	evidence := canonicalHypothesisEvidenceTuples(in.Evidence)
	return snapshotHash(map[string]interface{}{
		"client":     clientID,
		"report":     reportID,
		"assessment": assessmentID,
		"title":      in.Title,
		"desc":       in.Description,
		"statement":  in.Statement,
		"suspected":  in.SuspectedBehavior,
		"objective":  in.AdversaryObjective,
		"tactics":    in.MitreTactics,
		"techniques": in.MitreTechniques,
		"benign":     in.BenignExplanations,
		"assumptions": in.Assumptions,
		"blind":      in.BlindSpots,
		"limitations": in.Limitations,
		"method":     in.GenerationMethod,
		"evidence":   evidence,
	})
}

func huntRequireWrite(userID, clientID string) error {
	if !hasClientGrant(userID, clientID) {
		return ErrHuntAccessDenied
	}
	role, err := globalDB.GetUserRole(userID)
	if err != nil {
		return fmt.Errorf("getting user role: %w", err)
	}
	rp, ok := GetPermission(role)
	if !ok || !rp.CanCreateHypothesis {
		return ErrDraftPermissionDenied
	}
	return nil
}

func huntValidateMitre(techniques string) error {
	if strings.TrimSpace(techniques) == "" {
		return nil
	}
	toks := strings.FieldsFunc(techniques, func(r rune) bool { return r == ' ' || r == ',' || r == ';' })
	for _, tok := range toks {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		var n int
		if err := globalDB.QueryRow(`SELECT COUNT(*) FROM mitre_mappings WHERE mitre_technique_id = ?`, tok).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return ErrInvalidHypothesis
		}
	}
	return nil
}

func huntValidateContent(in *HypothesisInput) error {
	if strings.TrimSpace(in.Title) == "" {
		return ErrInvalidHypothesis
	}
	return huntValidateMitre(in.MitreTechniques)
}

func huntEvidenceCountsForCTITarget(e HypothesisEvidenceInput, clientID string) (int, error) {
	table, column := "", ""
	switch e.TargetType {
	case "indicator":
		table, column = "indicators", "indicator_id"
	case "technique":
		table, column = "techniques", "technique_id"
	case "cve":
		table, column = "cves", "cve_id"
	case "malware":
		table, column = "malware", "malware_id"
	case "claim":
		table, column = "cti_claims", "claim_id"
	case "threat_actor":
		table, column = "threat_actors", "actor_id"
	case "campaign":
		table, column = "campaigns", "campaign_id"
	default:
		return 0, ErrInvalidHypothesis
	}
	q := fmt.Sprintf(`SELECT COUNT(*) FROM %s x JOIN cti_reports r ON r.report_id = x.report_id WHERE x.%s = ? AND r.client_id = ?`, table, column)
	var n int
	if err := globalDB.QueryRow(q, e.TargetID, clientID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func huntValidateEvidenceRows(evid []HypothesisEvidenceInput, clientID string) error {
	for _, e := range evid {
		switch e.Role {
		case "SUPPORTING", "CONTRADICTING":
			n, err := huntEvidenceCountsForCTITarget(e, clientID)
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrInvalidHypothesis
			}
		case "CTI_SOURCE":
			if e.TargetType != "cti_reports" && e.TargetType != "cti_report" {
				return ErrInvalidHypothesis
			}
			var reportClient string
			if err := globalDB.QueryRow(`SELECT client_id FROM cti_reports WHERE report_id = ?`, e.TargetID).Scan(&reportClient); err != nil {
				return ErrInvalidHypothesis
			}
			if reportClient != clientID || (e.ReportID != "" && e.ReportID != e.TargetID) {
				return ErrInvalidHypothesis
			}
		case "RELEVANCE":
			if e.AssessmentID == "" {
				return ErrInvalidHypothesis
			}
			var n int
			if err := globalDB.QueryRow(`SELECT COUNT(*) FROM relevance_evidence re
				JOIN relevance_assessments a ON a.assessment_id = re.assessment_id
				WHERE re.evidence_id = ? AND a.client_id = ?
				  AND (? = '' OR re.report_id = ?)
				  AND (? = '' OR re.assessment_id = ?)`,
				e.TargetID, clientID, e.ReportID, e.ReportID, e.AssessmentID, e.AssessmentID).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				return ErrInvalidHypothesis
			}
		case "INVESTIGATION", "LEGACY":
			// Phase 1 does not accept external evidence bindings; those roles
			// arrive through Phase 2 ingest paths, not direct create input.
			return ErrInvalidHypothesis
		default:
			return ErrInvalidHypothesis
		}
	}
	return nil
}

func getHypothesisClientM7D(hypID string) (string, string, int, error) {
	var clientID, authorID string
	var current int
	err := globalDB.QueryRow(
		`SELECT client_id, COALESCE(author_id,''), current_version_no FROM hunt_hypotheses WHERE hypothesis_id = ?`, hypID).
		Scan(&clientID, &authorID, &current)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", 0, ErrHuntNotFound
		}
		return "", "", 0, err
	}
	return clientID, authorID, current, nil
}

func huntRequireWriteExisting(userID, hypID string) (clientID, authorID string, current int, err error) {
	clientID, authorID, current, err = getHypothesisClientM7D(hypID)
	if err != nil {
		return "", "", 0, err
	}
	if !hasClientGrant(userID, clientID) {
		return "", "", 0, ErrHuntAccessDenied
	}
	role, err := globalDB.GetUserRole(userID)
	if err != nil {
		return "", "", 0, fmt.Errorf("getting user role: %w", err)
	}
	rp, ok := GetPermission(role)
	if !ok || !rp.CanCreateHypothesis {
		return "", "", 0, ErrDraftPermissionDenied
	}
	return clientID, authorID, current, nil
}

func insertHuntVersion(tx *sql.Tx, hypID string, versionNo int, in *HypothesisInput, authorID, genMethod string) error {
	verID := newID("hver")
	if _, err := tx.Exec(`INSERT INTO hunt_hypothesis_versions (
		version_id, hypothesis_id, version_no, creation_status, draft_revision,
		statement, suspected_behavior, adversary_objective, mitre_tactics,
		mitre_techniques, benign_explanations, assumptions, blind_spots,
		limitations, author_id, generation_method, created_at)
		VALUES (?, ?, ?, 'DRAFT', 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		verID, hypID, versionNo, in.Statement, in.SuspectedBehavior, in.AdversaryObjective,
		in.MitreTactics, in.MitreTechniques, in.BenignExplanations, in.Assumptions,
		in.BlindSpots, in.Limitations, authorID, genMethod); err != nil {
		return err
	}
	return nil
}

func replayOrInsertHypothesis(userID, clientID string, in *HypothesisInput, reportID, assessmentID, payloadFP string) (*HypothesisDetail, bool, error) {
	// Idempotent replay lookup.
	if in.IdempotencyKey != "" {
		var priorID, priorFP string
		rowErr := globalDB.QueryRow(`SELECT hypothesis_id, COALESCE(payload_fingerprint,'')
			FROM hunt_hypotheses WHERE client_id = ? AND request_idempotency_key = ? LIMIT 1`,
			clientID, in.IdempotencyKey).Scan(&priorID, &priorFP)
		if rowErr == nil {
			if priorFP != "" && priorFP != payloadFP {
				return nil, false, ErrHuntIdempotencyConflict
			}
			existing, err := GetHypothesisDetail(priorID, userID)
			if err != nil {
				return nil, false, err
			}
			return existing, false, nil
		}
	}
	hypID := newID("hunt")
	nkey := sql.NullString{}
	if in.IdempotencyKey != "" {
		nkey = sql.NullString{String: in.IdempotencyKey, Valid: true}
	}
	tx, err := globalDB.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO hunt_hypotheses
		(hypothesis_id, client_id, title, description, status, report_id,
		 relevance_assessment_id, author_id, generation_method,
		 current_version_no, request_idempotency_key, payload_fingerprint,
		 created_at, updated_at)
		VALUES (?, ?, ?, ?, 'DRAFT', ?, ?, ?, ?, 1, ?, ?, datetime('now'), datetime('now'))`,
		hypID, clientID, in.Title, in.Description, sqlNullStr(reportID), sqlNullStr(assessmentID), userID,
		in.GenerationMethod, nkey, payloadFP); err != nil {
		if isUniqueConstraintError(err) && in.IdempotencyKey != "" {
			tx.Rollback()
			var priorID, priorFP string
			if err2 := globalDB.QueryRow(`SELECT hypothesis_id, COALESCE(payload_fingerprint,'')
				FROM hunt_hypotheses WHERE client_id = ? AND request_idempotency_key = ? LIMIT 1`,
				clientID, in.IdempotencyKey).Scan(&priorID, &priorFP); err2 == nil {
				if priorFP != "" && priorFP != payloadFP {
					return nil, false, ErrHuntIdempotencyConflict
				}
				existing, err := GetHypothesisDetail(priorID, userID)
				if err != nil {
					return nil, false, err
				}
				return existing, false, nil
			}
		}
		return nil, false, fmt.Errorf("creating hypothesis: %w", err)
	}
	if err := insertHuntVersion(tx, hypID, 1, in, userID, in.GenerationMethod); err != nil {
		return nil, false, err
	}
	if err := bindEvidence(tx, in, hypID, clientID, reportID); err != nil {
		return nil, false, fmt.Errorf("binding evidence: %w", err)
	}
	actID := newID("hactivity")
	if _, err := tx.Exec(`INSERT INTO hunt_hypothesis_activity (activity_id, hypothesis_id, version_no, user_id, action, client_id, created_at)
		VALUES (?, ?, 1, ?, 'draft_created', ?, datetime('now'))`, actID, hypID, userID, clientID); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	detail, err := GetHypothesisDetail(hypID, userID)
	return detail, true, err
}

func bindEvidence(tx *sql.Tx, in *HypothesisInput, hypID, clientID, reportID string) error {
	for _, e := range in.Evidence {
		evID := newID("hev")
		assessmentID := sql.NullString{}
		if e.AssessmentID != "" {
			assessmentID = sql.NullString{String: e.AssessmentID, Valid: true}
		}
		if _, err := tx.Exec(`INSERT INTO hunt_hypothesis_evidence
			(evidence_id, hypothesis_id, version_no, evidence_role, target_entity_type, target_entity_id,
			 report_id, assessment_id, source_reference, source_reliability, client_id, created_at)
			VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
			evID, hypID, e.Role, e.TargetType, e.TargetID,
			sqlNullStr(e.ReportID), assessmentID, e.SourceRef, e.SourceReliability, clientID); err != nil {
			return err
		}
	}
	return nil
}

func CreateHypothesisManual(userID, clientID string, in *HypothesisInput) (*HypothesisDetail, bool, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, false, err
	}
	if err := huntValidateContent(in); err != nil {
		return nil, false, err
	}
	if err := huntValidateEvidenceRows(in.Evidence, clientID); err != nil {
		return nil, false, err
	}
	if err := huntRequireWrite(userID, clientID); err != nil {
		return nil, false, err
	}
	if in.GenerationMethod == "" {
		in.GenerationMethod = "MANUAL"
	}
	in.Evidence = deduplicateHypothesisEvidence(in.Evidence)
	fp := huntFingerprint(in, clientID, "", "")
	return replayOrInsertHypothesis(userID, clientID, in, "", "", fp)
}

func CreateHypothesisFromReport(userID, reportID, clientID, assessmentID string, in *HypothesisInput) (*HypothesisDetail, bool, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, false, err
	}
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
	role, err := globalDB.GetUserRole(userID)
	if err != nil {
		return nil, false, err
	}
	rp, ok := GetPermission(role)
	if !ok || !rp.CanCreateHypothesis {
		return nil, false, ErrDraftPermissionDenied
	}
	a, err := GetRelevanceAssessment(assessmentID)
	if err != nil {
		return nil, false, ErrHuntNotFound
	}
	if a.Status != "COMPLETED" || a.ReportID != reportID || a.ClientID != clientID {
		return nil, false, ErrInvalidHypothesis
	}
	if err := huntValidateContent(in); err != nil {
		return nil, false, err
	}
	if err := huntValidateEvidenceRows(in.Evidence, clientID); err != nil {
		return nil, false, err
	}
	if in.GenerationMethod == "" {
		in.GenerationMethod = "MANUAL"
	}
	// evidence rows: CTI_SOURCE for the report + RELEVANCE rows for the
	// assessment's finding evidence, plus caller-supplied bindings.
	var evid []HypothesisEvidenceInput
	evid = append(evid, HypothesisEvidenceInput{Role: "CTI_SOURCE", TargetType: "cti_report", TargetID: reportID, ReportID: reportID})
	for _, f := range a.Findings {
		for _, e := range f.Evidence {
			evid = append(evid, HypothesisEvidenceInput{Role: "RELEVANCE", TargetType: e.MatchedEntityType,
				TargetID: e.EvidenceID, ReportID: reportID, AssessmentID: assessmentID,
				SourceRef: e.SourceReference, SourceReliability: e.SourceReliability})
		}
	}
	evid = append(evid, in.Evidence...)
	// Fingerprint only now that the complete semantic evidence set is known;
	// immutable assessment identity is included and derived evidence is
	// deliberately part of the idempotency contract.
	in.Evidence = deduplicateHypothesisEvidence(evid)
	fp := huntFingerprint(in, clientID, reportID, assessmentID)
	return replayOrInsertHypothesis(userID, clientID, in, reportID, assessmentID, fp)
}

func GetHypothesisDetail(hypID, userID string) (*HypothesisDetail, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	var d HypothesisDetail
	var rep, asm sql.NullString
	err := globalDB.QueryRow(`SELECT hypothesis_id, client_id, title, description,
		COALESCE(report_id,''), COALESCE(relevance_assessment_id,''),
		COALESCE(generation_method,''), COALESCE(author_id,''), current_version_no, created_at, updated_at
		FROM hunt_hypotheses WHERE hypothesis_id = ?`, hypID).
		Scan(&d.HypothesisID, &d.ClientID, &d.Title, &d.Description, &rep, &asm,
			&d.GenerationMethod, &d.AuthorID, &d.CurrentVersionNo, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrHuntNotFound
		}
		return nil, err
	}
	if !hasClientGrant(userID, d.ClientID) {
		return nil, ErrHuntAccessDenied
	}
	v, err := GetHypothesisVersion(userID, hypID, d.CurrentVersionNo)
	if err != nil {
		return nil, err
	}
	d.CurrentVersion = v
	d.ReportID = rep.String
	d.AssessmentID = asm.String
	return &d, nil
}

func GetHypothesisVersion(userID, hypID string, versionNo int) (*HypothesisVersion, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	clientID, _, _, err := getHypothesisClientM7D(hypID)
	if err != nil {
		return nil, err
	}
	if !hasClientGrant(userID, clientID) {
		return nil, ErrHuntAccessDenied
	}
	var v HypothesisVersion
	v.VersionNo = versionNo
	err = globalDB.QueryRow(`SELECT v.version_id, v.creation_status, COALESCE(s.effective_status,''), v.draft_revision,
		v.statement, v.suspected_behavior, v.adversary_objective, v.mitre_tactics, v.mitre_techniques,
		v.benign_explanations, v.assumptions, v.blind_spots, v.limitations,
		COALESCE(v.author_id,''), COALESCE(v.generation_method,''), v.created_at
		FROM hunt_hypothesis_versions v
		LEFT JOIN v_hunt_hypothesis_version_state s ON s.hypothesis_id = v.hypothesis_id AND s.version_no = v.version_no
		WHERE v.hypothesis_id = ? AND v.version_no = ?`, hypID, versionNo).
		Scan(&v.VersionID, &v.CreationStatus, &v.EffectiveStatus, &v.DraftRevision,
			&v.Statement, &v.Suspected, &v.Objective, &v.Tactics, &v.Techniques,
			&v.Benign, &v.Assumptions, &v.BlindSpots, &v.Limitations, &v.AuthorID, &v.GenerationMethod, &v.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrHuntNotFound
		}
		return nil, err
	}
	return &v, nil
}

func EditDraftVersion(userID, hypID string, versionNo int, edit HypothesisEdit) error {
	if err := requireM7DSchema(); err != nil {
		return err
	}
	clientID, authorID, current, err := huntRequireWriteExisting(userID, hypID)
	if err != nil {
		return err
	}
	role, _ := globalDB.GetUserRole(userID)
	rp, _ := GetPermission(role)
	if rp.Role != "ADMINISTRATOR" && authorID != userID {
		return ErrHuntAccessDenied
	}
	if versionNo != current {
		return ErrHuntInvalidTransition
	}
	res, err := globalDB.Exec(`UPDATE hunt_hypothesis_versions SET
		statement = CASE WHEN ? <> '' THEN ? ELSE statement END,
		suspected_behavior = CASE WHEN ? <> '' THEN ? ELSE suspected_behavior END,
		adversary_objective = CASE WHEN ? <> '' THEN ? ELSE adversary_objective END,
		mitre_tactics = CASE WHEN ? <> '' THEN ? ELSE mitre_tactics END,
		mitre_techniques = CASE WHEN ? <> '' THEN ? ELSE mitre_techniques END,
		benign_explanations = CASE WHEN ? <> '' THEN ? ELSE benign_explanations END,
		assumptions = CASE WHEN ? <> '' THEN ? ELSE assumptions END,
		blind_spots = CASE WHEN ? <> '' THEN ? ELSE blind_spots END,
		limitations = CASE WHEN ? <> '' THEN ? ELSE limitations END,
		draft_revision = draft_revision + 1
		WHERE hypothesis_id = ? AND version_no = ? AND draft_revision = ?`,
		edit.Statement, edit.Statement,
		edit.Suspected, edit.Suspected,
		edit.Objective, edit.Objective,
		edit.Tactics, edit.Tactics,
		edit.Techniques, edit.Techniques,
		edit.Benign, edit.Benign,
		edit.Assumptions, edit.Assumptions,
		edit.BlindSpots, edit.BlindSpots,
		edit.Limitations, edit.Limitations,
		hypID, versionNo, edit.ExpectedDraftRevision)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrVersionConflict
	}
	_ = clientID
	return nil
}

func SubmitForReview(userID, hypID string) error {
	if err := requireM7DSchema(); err != nil {
		return err
	}
	clientID, authorID, current, err := huntRequireWriteExisting(userID, hypID)
	if err != nil {
		return err
	}
	role, _ := globalDB.GetUserRole(userID)
	rp, _ := GetPermission(role)
	if rp.Role != "ADMINISTRATOR" && authorID != userID {
		return ErrHuntAccessDenied
	}
	v, err := GetHypothesisVersion(userID, hypID, current)
	if err != nil {
		return err
	}
	if v.EffectiveStatus != "DRAFT" {
		return ErrHuntInvalidTransition
	}
	if strings.TrimSpace(v.Benign) == "" {
		return ErrInvalidHypothesis
	}
	tx, err := globalDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := insertHuntEvent(tx, hypID, current, "DRAFT", "READY_FOR_REVIEW", userID, "submitted"); err != nil {
		return err
	}
	actID := newID("hactivity")
	if _, err := tx.Exec(`INSERT INTO hunt_hypothesis_activity (activity_id, hypothesis_id, version_no, user_id, action, client_id, created_at)
		VALUES (?, ?, ?, ?, 'submitted', ?, datetime('now'))`, actID, hypID, current, userID, clientID); err != nil {
		return err
	}
	return tx.Commit()
}

func insertHuntEvent(tx *sql.Tx, hypID string, versionNo int, from, to, actor, reason string) error {
	eventID := newID("hevent")
	_, err := tx.Exec(`INSERT INTO hunt_hypothesis_version_events
		(event_id, hypothesis_id, version_no, from_status, to_status, actor_id, reason, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		eventID, hypID, versionNo, from, to, actor, reason)
	return err
}

func ReviewVersion(userID, hypID string, versionNo int, decision, reason, originalStatus string) (*HuntReviewResult, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	clientID, _, current, err := getHypothesisClientM7D(hypID)
	if err != nil {
		return nil, err
	}
	if !hasClientGrant(userID, clientID) {
		return nil, ErrHuntAccessDenied
	}
	role, err := globalDB.GetUserRole(userID)
	if err != nil {
		return nil, fmt.Errorf("getting user role: %w", err)
	}
	rp, ok := GetPermission(role)
	if !ok || !rp.CanReviewHypothesis {
		return nil, ErrHuntReviewDenied
	}
	if versionNo != current {
		return nil, ErrHuntInvalidTransition
	}
	v, err := GetHypothesisVersion(userID, hypID, versionNo)
	if err != nil {
		return nil, err
	}
	if v.EffectiveStatus != "READY_FOR_REVIEW" || v.EffectiveStatus != originalStatus {
		return nil, ErrHuntInvalidTransition
	}
	to := map[string]string{"APPROVED": "APPROVED", "REJECTED": "REJECTED", "NEEDS_MORE_DATA": "DRAFT"}[decision]
	if to == "" {
		return nil, ErrInvalidHypothesis
	}
	reviewID := newID("hreview")
	tx, err := globalDB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Review row first (trigger validates original_status against effective).
	if _, err := tx.Exec(`INSERT INTO hunt_hypothesis_reviews
		(review_id, hypothesis_id, version_no, reviewer_id, decision, reason, original_status, reviewed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		reviewID, hypID, versionNo, userID, decision, reason, originalStatus); err != nil {
		return nil, fmt.Errorf("recording review: %w", err)
	}
	if err := insertHuntEvent(tx, hypID, versionNo, "READY_FOR_REVIEW", to, userID, reason); err != nil {
		return nil, err
	}
	actID := newID("hactivity")
	reviewAction := map[string]string{"APPROVED": "approved", "REJECTED": "rejected", "NEEDS_MORE_DATA": "returned_for_more_data"}[decision]
	if _, err := tx.Exec(`INSERT INTO hunt_hypothesis_activity (activity_id, hypothesis_id, version_no, user_id, action, client_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
		actID, hypID, versionNo, userID, reviewAction, clientID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &HuntReviewResult{
		ReviewID: reviewID, HypothesisID: hypID, VersionNo: versionNo,
		ReviewerID: userID, Decision: decision, Reason: reason, OriginalStatus: originalStatus,
		ReviewedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// CreateNewVersion clones the current APPROVED version into a new DRAFT and
// supersedes the old one atomically (new row first, then supersede event).
func CreateNewVersion(userID, hypID string, edit HypothesisInput) (*HypothesisVersion, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	clientID, authorID, current, err := huntRequireWriteExisting(userID, hypID)
	if err != nil {
		return nil, err
	}
	role, _ := globalDB.GetUserRole(userID)
	rp, _ := GetPermission(role)
	if rp.Role != "ADMINISTRATOR" && authorID != userID {
		return nil, ErrHuntAccessDenied
	}
	cur, err := GetHypothesisVersion(userID, hypID, current)
	if err != nil {
		return nil, err
	}
	if cur.EffectiveStatus != "APPROVED" {
		return nil, ErrHuntInvalidTransition
	}
	if strings.TrimSpace(edit.Statement) == "" {
		edit.Statement = cur.Statement
	}
	if edit.SuspectedBehavior == "" {
		edit.SuspectedBehavior = cur.Suspected
	}
	if edit.AdversaryObjective == "" {
		edit.AdversaryObjective = cur.Objective
	}
	if edit.MitreTactics == "" {
		edit.MitreTactics = cur.Tactics
	}
	if edit.MitreTechniques == "" {
		edit.MitreTechniques = cur.Techniques
	}
	if edit.BenignExplanations == "" {
		edit.BenignExplanations = cur.Benign
	}
	if edit.Assumptions == "" {
		edit.Assumptions = cur.Assumptions
	}
	if edit.BlindSpots == "" {
		edit.BlindSpots = cur.BlindSpots
	}
	if edit.Limitations == "" {
		edit.Limitations = cur.Limitations
	}
	merged := edit
	tx, err := globalDB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// New version FIRST so the supersede trigger sees it.
	if err := insertHuntVersion(tx, hypID, current+1, &merged, userID, "MANUAL"); err != nil {
		return nil, err
	}
	if err := insertHuntEvent(tx, hypID, current, "APPROVED", "SUPERSEDED", userID, "edited by author"); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE hunt_hypotheses SET current_version_no = ?, updated_at = datetime('now') WHERE hypothesis_id = ?`, current+1, hypID); err != nil {
		return nil, err
	}
	actID := newID("hactivity")
	if _, err := tx.Exec(`INSERT INTO hunt_hypothesis_activity (activity_id, hypothesis_id, version_no, user_id, action, client_id, created_at)
		VALUES (?, ?, ?, ?, 'version_created', ?, datetime('now'))`, actID, hypID, current+1, userID, clientID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return GetHypothesisVersion(userID, hypID, current+1)
}

func ListHypothesisHistory(userID, hypID string) ([]HypothesisEvent, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	clientID, _, _, err := getHypothesisClientM7D(hypID)
	if err != nil {
		return nil, err
	}
	if !hasClientGrant(userID, clientID) {
		return nil, ErrHuntAccessDenied
	}
	rows, err := globalDB.Query(`SELECT event_id, hypothesis_id, version_no, from_status, to_status, actor_id, COALESCE(reason,''), created_at
		FROM hunt_hypothesis_version_events WHERE hypothesis_id = ? ORDER BY rowid`, hypID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HypothesisEvent
	for rows.Next() {
		var e HypothesisEvent
		if err := rows.Scan(&e.EventID, &e.HypothesisID, &e.VersionNo, &e.FromStatus, &e.ToStatus, &e.ActorID, &e.Reason, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

var _ = json.Marshal
