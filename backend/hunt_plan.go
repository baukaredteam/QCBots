package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// M7-D Phase 2B-4A: Hunt Plans.
//
// A plan bundles one hypothesis version with reviewed AQL drafts for one client.
// It is created as DRAFT, submitted for review, and then approved or rejected by
// an authorised reviewer. Approved plans are immutable; a change creates a new
// version. Nothing here executes AQL or claims QRadar verification.

var (
	ErrHuntPlanNotFound    = errors.New("HUNT_PLAN_NOT_FOUND")
	ErrHuntPlanInvalid     = errors.New("HUNT_PLAN_INVALID")
	ErrHuntPlanAccessDenied = errors.New("HUNT_PLAN_ACCESS_DENIED")
	ErrHuntPlanConflict    = errors.New("HUNT_PLAN_CONFLICT")
	// ErrHuntPlanEvidenceUnavailable: the row a decision depends on is gone or
	// unreadable, which is not the same as stale.
	ErrHuntPlanEvidenceUnavailable = errors.New("HUNT_PLAN_EVIDENCE_UNAVAILABLE")
)

// Evidence states are derived from the evidence itself, never from the identity
// of whoever attached it.
const (
	EvidenceStateOK          = "OK"
	EvidenceStateStale       = "STALE_EVIDENCE"
	EvidenceStateUnavailable = "EVIDENCE_UNAVAILABLE"
)

type HuntPlanItem struct {
	TranslationID           string `json:"translation_id"`
	DomainID                string `json:"domain_id"`
	NativeQRadarDomainID    string `json:"native_qradar_domain_id"`
	TranslationStatus       string `json:"translation_status"`
	AQLSHA256               string `json:"aql_sha256,omitempty"`
	AddedBy                 string `json:"added_by"`
	AddedAt                 string `json:"added_at"`
	EvidenceState           string `json:"evidence_state"`
	Stale                   bool   `json:"stale"`
	StaleReasons            []string `json:"stale_reasons,omitempty"`
}

type HuntPlan struct {
	PlanID            string         `json:"plan_id"`
	LogicalID         string         `json:"logical_id"`
	Version           int            `json:"version"`
	ClientID          string         `json:"client_id"`
	HypothesisID      string         `json:"hypothesis_id"`
	HypothesisVersion int            `json:"hypothesis_version"`
	ReportID          string         `json:"report_id,omitempty"`
	Title             string         `json:"title"`
	Status            string         `json:"status"`
	SupersedesPlanID  string         `json:"supersedes_plan_id,omitempty"`
	CreatedBy         string         `json:"created_by"`
	CreatedAt         string         `json:"created_at"`
	SubmittedBy       string         `json:"submitted_by,omitempty"`
	SubmittedAt       string         `json:"submitted_at,omitempty"`
	ReviewedBy        string         `json:"reviewed_by,omitempty"`
	ReviewedAt        string         `json:"reviewed_at,omitempty"`
	ReviewEvidence    string         `json:"review_evidence,omitempty"`
	ReviewNote        string         `json:"review_note,omitempty"`
	Items             []HuntPlanItem `json:"items"`
}

type CreateHuntPlanRequest struct {
	ClientID          string `json:"client_id"`
	HypothesisID      string `json:"hypothesis_id"`
	HypothesisVersion int    `json:"hypothesis_version"`
	ReportID          string `json:"report_id"`
	Title             string `json:"title"`
}

func CreateHuntPlan(userID string, req CreateHuntPlanRequest) (*HuntPlan, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if err := requireFieldCapability(userID, CanCreateHypothesis); err != nil {
		return nil, ErrHuntPlanAccessDenied
	}
	if req.ClientID == "" || req.HypothesisID == "" || strings.TrimSpace(req.Title) == "" {
		return nil, fmt.Errorf("%w: client_id, hypothesis_id and title are required", ErrHuntPlanInvalid)
	}
	if !hasClientGrant(userID, req.ClientID) {
		return nil, ErrHuntPlanAccessDenied
	}
	if req.HypothesisVersion <= 0 {
		req.HypothesisVersion = 1
	}
	var hypClient string
	var currentVersion int
	if err := globalDB.QueryRow(`SELECT client_id, current_version_no FROM hunt_hypotheses WHERE hypothesis_id = ?`, req.HypothesisID).
		Scan(&hypClient, &currentVersion); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrHuntPlanNotFound
		}
		return nil, err
	}
	if hypClient != req.ClientID {
		return nil, ErrHuntPlanAccessDenied
	}
	var exists int
	if err := globalDB.QueryRow(`SELECT COUNT(*) FROM hunt_hypothesis_versions WHERE hypothesis_id = ? AND version_no = ?`,
		req.HypothesisID, req.HypothesisVersion).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, fmt.Errorf("%w: hypothesis version does not exist", ErrHuntPlanInvalid)
	}
	if req.ReportID != "" {
		var reportClient string
		if err := globalDB.QueryRow(`SELECT client_id FROM cti_reports WHERE report_id = ?`, req.ReportID).Scan(&reportClient); err != nil {
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("%w: source report not found", ErrHuntPlanInvalid)
			}
			return nil, err
		}
		if reportClient != req.ClientID {
			return nil, ErrHuntPlanAccessDenied
		}
	}

	planID := newID("hp")
	logicalID := newID("hpl")
	tx, err := globalDB.Begin()
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`INSERT INTO hunt_plan_versions
		(plan_id, logical_id, version, client_id, hypothesis_id, hypothesis_version, report_id, title, status, created_by, created_at)
		VALUES (?, ?, 1, ?, ?, ?, ?, ?, 'DRAFT', ?, datetime('now'))`,
		planID, logicalID, req.ClientID, req.HypothesisID, req.HypothesisVersion, nullableString(req.ReportID),
		strings.TrimSpace(req.Title), userID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := auditInTx(tx, userID, req.ClientID, "HUNT_PLAN_CREATE", planID, "DRAFT"); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return GetHuntPlan(planID, userID)
}

func GetHuntPlan(planID, userID string) (*HuntPlan, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	plan, err := loadHuntPlan(planID)
	if err != nil {
		return nil, err
	}
	if !hasClientGrant(userID, plan.ClientID) {
		return nil, ErrHuntPlanAccessDenied
	}
	items, err := loadHuntPlanItems(planID, plan.ClientID)
	if err != nil {
		return nil, err
	}
	plan.Items = items
	return plan, nil
}

func ListHuntPlans(userID, clientID string) ([]HuntPlan, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if !hasClientGrant(userID, clientID) {
		return nil, ErrHuntPlanAccessDenied
	}
	rows, err := globalDB.Query(`SELECT plan_id FROM hunt_plan_versions WHERE client_id = ? ORDER BY created_at DESC`, clientID)
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
	out := make([]HuntPlan, 0, len(ids))
	for _, id := range ids {
		p, err := GetHuntPlan(id, userID)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, nil
}

func loadHuntPlan(planID string) (*HuntPlan, error) {
	var p HuntPlan
	var report, supersedes, submittedBy, submittedAt, reviewedBy, reviewedAt, evidence, note sql.NullString
	err := globalDB.QueryRow(`SELECT plan_id, logical_id, version, client_id, hypothesis_id, hypothesis_version,
			report_id, title, status, supersedes_plan_id, created_by, created_at,
			submitted_by, submitted_at, reviewed_by, reviewed_at, review_evidence, review_note
		FROM hunt_plan_versions WHERE plan_id = ?`, planID).
		Scan(&p.PlanID, &p.LogicalID, &p.Version, &p.ClientID, &p.HypothesisID, &p.HypothesisVersion,
			&report, &p.Title, &p.Status, &supersedes, &p.CreatedBy, &p.CreatedAt,
			&submittedBy, &submittedAt, &reviewedBy, &reviewedAt, &evidence, &note)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrHuntPlanNotFound
		}
		return nil, err
	}
	p.ReportID = report.String
	p.SupersedesPlanID = supersedes.String
	p.SubmittedBy = submittedBy.String
	p.SubmittedAt = submittedAt.String
	p.ReviewedBy = reviewedBy.String
	p.ReviewedAt = reviewedAt.String
	p.ReviewEvidence = evidence.String
	p.ReviewNote = note.String
	return &p, nil
}

func loadHuntPlanItems(planID, planClientID string) ([]HuntPlanItem, error) {
	rows, err := globalDB.Query(`SELECT i.translation_id, i.domain_id, i.native_qradar_domain_id, i.added_by, i.added_at,
			t.status, t.aql_sha256
		FROM hunt_plan_version_items i JOIN detection_translations t ON t.translation_id = i.translation_id
		WHERE i.plan_id = ? ORDER BY i.added_at`, planID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HuntPlanItem
	for rows.Next() {
		var it HuntPlanItem
		if err := rows.Scan(&it.TranslationID, &it.DomainID, &it.NativeQRadarDomainID, &it.AddedBy, &it.AddedAt,
			&it.TranslationStatus, &it.AQLSHA256); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Staleness is derived from the evidence, not from the author's grants. The
	// viewer was already authorised for this client by the caller.
	for i := range out {
		state, reasons := translationEvidenceState(out[i].TranslationID, planClientID)
		out[i].EvidenceState = state
		out[i].Stale = state != EvidenceStateOK
		out[i].StaleReasons = reasons
	}
	return out, nil
}

// translationEvidenceState classifies one attached draft. ACCESS_DENIED is never
// produced here: authorization belongs to the plan, so a historical author's
// lost grant cannot make evidence look stale.
func translationEvidenceState(translationID, expectedClientID string) (string, []string) {
	tr, err := loadTranslation(`WHERE t.translation_id = ?`, translationID)
	if err != nil {
		return EvidenceStateUnavailable, []string{"translation evidence is no longer readable"}
	}
	if expectedClientID != "" && tr.ClientID != expectedClientID {
		return EvidenceStateUnavailable, []string{"translation belongs to a different client"}
	}
	computeStaleness(tr)
	if tr.Stale {
		return EvidenceStateStale, tr.StaleReasons
	}
	return EvidenceStateOK, nil
}

// AddHuntPlanItem attaches one reviewed draft to a DRAFT plan.
func AddHuntPlanItem(userID, planID, translationID string) (*HuntPlan, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	plan, err := loadHuntPlan(planID)
	if err != nil {
		return nil, err
	}
	if !hasClientGrant(userID, plan.ClientID) {
		return nil, ErrHuntPlanAccessDenied
	}
	if err := requireFieldCapability(userID, CanCreateHypothesis); err != nil {
		return nil, ErrHuntPlanAccessDenied
	}
	if plan.Status != "DRAFT" {
		return nil, fmt.Errorf("%w: items can only be added to a DRAFT plan", ErrHuntPlanConflict)
	}

	tx, err := globalDB.Begin()
	if err != nil {
		return nil, err
	}
	// Re-check plan state and the draft's evidence inside the transaction: the
	// plan could have moved and the evidence could have changed meanwhile.
	if err := assertPlanDraftTx(tx, planID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	domainID, nativeID, err := assertItemEvidenceTx(tx, plan.ClientID, translationID)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if _, err := tx.Exec(`INSERT INTO hunt_plan_version_items (plan_id, translation_id, domain_id, native_qradar_domain_id, added_by, added_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'))`,
		planID, translationID, domainID, nativeID, userID); err != nil {
		_ = tx.Rollback()
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return nil, fmt.Errorf("%w: translation already attached", ErrHuntPlanConflict)
		}
		return nil, err
	}
	if err := auditInTx(tx, userID, plan.ClientID, "HUNT_PLAN_ADD_ITEM", planID, translationID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return GetHuntPlan(planID, userID)
}

// assertItemEvidenceTx proves, inside the transaction, that a draft may become a
// plan item: same client, READY, a real AQL draft, a current verified binding,
// the pinned rule version, and a mapping snapshot that is still the newest
// applicable one. It returns the domain and native id the item must store.
func assertItemEvidenceTx(tx *sql.Tx, planClientID, translationID string) (string, string, error) {
	var trClient, trDomain, trNative, trStatus, trAQL, trBindingRev, snap, diag, ruleID, ruleHash string
	var trRuleVersion int
	err := tx.QueryRow(`SELECT client_id, domain_id, native_qradar_domain_id, status, aql_sha256,
			CAST(binding_revision AS TEXT), mapping_snapshot, diagnostics, rule_id, sigma_rule_version, sigma_rule_hash
		FROM detection_translations WHERE translation_id = ?`, translationID).
		Scan(&trClient, &trDomain, &trNative, &trStatus, &trAQL, &trBindingRev, &snap, &diag, &ruleID, &trRuleVersion, &ruleHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", fmt.Errorf("%w: translation %s does not exist", ErrHuntPlanEvidenceUnavailable, translationID)
		}
		return "", "", err
	}
	if trClient != planClientID {
		return "", "", ErrHuntPlanAccessDenied
	}
	if trStatus != ReadinessReady || trAQL == "" {
		return "", "", fmt.Errorf("%w: %s is %s and is not a reviewed AQL draft", ErrHuntPlanConflict, translationID, trStatus)
	}

	var bindClient, kind, bindStatus, native, nativeStatus string
	var revision int
	if err := tx.QueryRow(`SELECT COALESCE(b.client_id,''), b.binding_kind, b.verification_status, b.revision,
			COALESCE(d.native_qradar_domain_id,''), COALESCE(d.native_id_status,'UNVERIFIED')
		FROM qradar_domain_bindings b JOIN qradar_domains d ON d.domain_id = b.domain_id
		WHERE b.domain_id = ?`, trDomain).
		Scan(&bindClient, &kind, &bindStatus, &revision, &native, &nativeStatus); err != nil {
		return "", "", fmt.Errorf("%w: domain binding for %s is gone", ErrHuntPlanEvidenceUnavailable, translationID)
	}
	if bindClient != planClientID || kind != "CLIENT" || bindStatus != "VERIFIED" || nativeStatus != "VERIFIED" || native == "" {
		return "", "", fmt.Errorf("%w: domain is not currently verified for this client", ErrHuntPlanConflict)
	}
	if native != trNative || fmt.Sprintf("%d", revision) != trBindingRev {
		return "", "", fmt.Errorf("%w: domain binding changed since the draft was made", ErrHuntPlanConflict)
	}

	var curVersion int
	var curHash, yaml string
	if err := tx.QueryRow(`SELECT version, yaml_sha256, yaml_text FROM sigma_detection_rules WHERE rule_id = ?`, ruleID).
		Scan(&curVersion, &curHash, &yaml); err != nil {
		return "", "", fmt.Errorf("%w: source rule for %s is gone", ErrHuntPlanEvidenceUnavailable, translationID)
	}
	if curVersion != trRuleVersion || curHash != ruleHash {
		return "", "", fmt.Errorf("%w: source rule changed since the draft was made", ErrHuntPlanConflict)
	}

	var diags TranslationDiagnostics
	_ = json.Unmarshal([]byte(diag), &diags)
	if err := verifyMappingSnapshotTx(tx, snap, trClient, trDomain, diags.PrimaryDSM, sigmaEventToken(&SigmaRule{YAML: yaml})); err != nil {
		return "", "", err
	}
	return trDomain, trNative, nil
}

func assertPlanDraftTx(tx *sql.Tx, planID string) error {
	var status string
	if err := tx.QueryRow(`SELECT status FROM hunt_plan_versions WHERE plan_id = ?`, planID).Scan(&status); err != nil {
		if err == sql.ErrNoRows {
			return ErrHuntPlanNotFound
		}
		return err
	}
	if status != "DRAFT" {
		return fmt.Errorf("%w: plan is %s", ErrHuntPlanConflict, status)
	}
	return nil
}

// SubmitHuntPlan moves DRAFT → IN_REVIEW after checking the attached drafts.
func SubmitHuntPlan(userID, planID string) (*HuntPlan, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	plan, err := loadHuntPlan(planID)
	if err != nil {
		return nil, err
	}
	if !hasClientGrant(userID, plan.ClientID) {
		return nil, ErrHuntPlanAccessDenied
	}
	if err := requireFieldCapability(userID, CanCreateHypothesis); err != nil {
		return nil, ErrHuntPlanAccessDenied
	}
	items, err := loadHuntPlanItems(planID, plan.ClientID)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("%w: a plan needs at least one reviewed translation", ErrHuntPlanInvalid)
	}
	for _, it := range items {
		switch it.EvidenceState {
		case EvidenceStateOK:
		case EvidenceStateStale:
			return nil, fmt.Errorf("%w: %s is stale", ErrHuntPlanConflict, it.TranslationID)
		case EvidenceStateUnavailable:
			return nil, fmt.Errorf("%w: %s is no longer readable", ErrHuntPlanEvidenceUnavailable, it.TranslationID)
		default:
			return nil, fmt.Errorf("%w: %s has an unknown evidence state", ErrHuntPlanConflict, it.TranslationID)
		}
		if it.TranslationStatus != ReadinessReady {
			return nil, fmt.Errorf("%w: %s is %s, not READY_FOR_REVIEW", ErrHuntPlanConflict, it.TranslationID, it.TranslationStatus)
		}
	}
	tx, err := globalDB.Begin()
	if err != nil {
		return nil, err
	}
	res, err := tx.Exec(`UPDATE hunt_plan_versions SET status = 'IN_REVIEW', submitted_by = ?, submitted_at = datetime('now')
		WHERE plan_id = ? AND status = 'DRAFT'`, userID, planID)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_ = tx.Rollback()
		return nil, fmt.Errorf("%w: plan is not DRAFT", ErrHuntPlanConflict)
	}
	if err := auditInTx(tx, userID, plan.ClientID, "HUNT_PLAN_SUBMIT", planID, "IN_REVIEW"); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return GetHuntPlan(planID, userID)
}

// ReviewHuntPlan approves or rejects an IN_REVIEW plan. Every fact the decision
// asserts is checked inside the decision transaction: the reviewer's role, the
// live client grant, plan ownership, plan state, and — for an approval — the
// freshness of the evidence.
func ReviewHuntPlan(userID, planID, decision, evidence, note string) (*HuntPlan, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	decision = strings.ToUpper(strings.TrimSpace(decision))
	if decision != "APPROVED" && decision != "REJECTED" {
		return nil, fmt.Errorf("%w: decision must be APPROVED or REJECTED", ErrHuntPlanInvalid)
	}
	plan, err := loadHuntPlan(planID)
	if err != nil {
		return nil, err
	}
	// Fast, non-authoritative rejection of a caller without any grant. The
	// authoritative checks run below, inside the transaction.
	if !hasClientGrant(userID, plan.ClientID) {
		return nil, ErrHuntPlanAccessDenied
	}

	tx, err := globalDB.Begin()
	if err != nil {
		return nil, err
	}
	clientID, err := reviewAuthTx(tx, userID, planID)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if clientID != plan.ClientID {
		_ = tx.Rollback()
		return nil, ErrHuntPlanAccessDenied
	}
	// Evidence is validated only after authorization, so an unauthorized caller
	// learns nothing about the review policy.
	ev, err := reviewEvidence(evidence)
	if err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("%w: approval evidence is required", ErrHuntPlanInvalid)
	}
	if err := revalidateHuntPlanTx(tx, plan, decision); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	res, err := tx.Exec(`UPDATE hunt_plan_versions
		SET status = ?, reviewed_by = ?, reviewed_at = datetime('now'), review_evidence = ?, review_note = ?
		WHERE plan_id = ? AND status = 'IN_REVIEW'`,
		decision, userID, ev, strings.TrimSpace(note), planID)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_ = tx.Rollback()
		return nil, fmt.Errorf("%w: plan is no longer IN_REVIEW", ErrHuntPlanConflict)
	}
	if err := auditInTx(tx, userID, clientID, "HUNT_PLAN_REVIEW", planID, decision); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return GetHuntPlan(planID, userID)
}

// reviewAuthTx re-reads the plan and the reviewer's rights inside the decision
// transaction, returning the plan's client. It refuses a plan that is not
// IN_REVIEW and never trusts a role or grant observed before the transaction.
func reviewAuthTx(tx *sql.Tx, userID, planID string) (string, error) {
	var clientID, status string
	err := tx.QueryRow(`SELECT client_id, status FROM hunt_plan_versions WHERE plan_id = ?`, planID).
		Scan(&clientID, &status)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", ErrHuntPlanNotFound
		}
		return "", err
	}
	rp, ok := GetPermissionOfTx(tx, userID)
	if !ok || !CanReviewHypothesis(rp) {
		return "", ErrHuntPlanAccessDenied
	}
	var grants int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM user_authorized_clients WHERE user_id = ? AND client_id = ?`,
		userID, clientID).Scan(&grants); err != nil {
		return "", err
	}
	if grants == 0 {
		return "", ErrHuntPlanAccessDenied
	}
	if status != "IN_REVIEW" {
		return "", fmt.Errorf("%w: plan is %s", ErrHuntPlanConflict, status)
	}
	return clientID, nil
}

// CreateHuntPlanVersion forks a rejected or approved plan into a new DRAFT.
func CreateHuntPlanVersion(userID, planID string) (*HuntPlan, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	plan, err := loadHuntPlan(planID)
	if err != nil {
		return nil, err
	}
	if !hasClientGrant(userID, plan.ClientID) {
		return nil, ErrHuntPlanAccessDenied
	}
	if err := requireFieldCapability(userID, CanCreateHypothesis); err != nil {
		return nil, ErrHuntPlanAccessDenied
	}
	if plan.Status == "DRAFT" || plan.Status == "IN_REVIEW" {
		return nil, fmt.Errorf("%w: only a decided plan can be versioned", ErrHuntPlanConflict)
	}
	items, err := loadHuntPlanItems(planID, plan.ClientID)
	if err != nil {
		return nil, err
	}
	var nextVersion int
	if err := globalDB.QueryRow(`SELECT COALESCE(MAX(version),0)+1 FROM hunt_plan_versions WHERE logical_id = ?`, plan.LogicalID).Scan(&nextVersion); err != nil {
		return nil, err
	}
	newIDv := newID("hp")
	tx, err := globalDB.Begin()
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`INSERT INTO hunt_plan_versions
		(plan_id, logical_id, version, client_id, hypothesis_id, hypothesis_version, report_id, title, status, supersedes_plan_id, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'DRAFT', ?, ?, datetime('now'))`,
		newIDv, plan.LogicalID, nextVersion, plan.ClientID, plan.HypothesisID, plan.HypothesisVersion,
		nullableString(plan.ReportID), plan.Title, planID, userID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	for _, it := range items {
		if it.EvidenceState != EvidenceStateOK {
			continue // never copy evidence that no longer holds
		}
		if _, err := tx.Exec(`INSERT INTO hunt_plan_version_items (plan_id, translation_id, domain_id, native_qradar_domain_id, added_by, added_at)
			VALUES (?, ?, ?, ?, ?, datetime('now'))`,
			newIDv, it.TranslationID, it.DomainID, it.NativeQRadarDomainID, userID); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
	}
	if err := auditInTx(tx, userID, plan.ClientID, "HUNT_PLAN_VERSION", newIDv, planID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return GetHuntPlan(newIDv, userID)
}

// revalidateHuntPlanTx re-checks every approval fact inside the decision
// transaction: binding identity/revision, translation status, and the mapping
// evidence each draft was built from.
func revalidateHuntPlanTx(tx *sql.Tx, plan *HuntPlan, decision string) error {
	if decision != "APPROVED" {
		return nil // rejection does not assert that evidence is current
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM hunt_plan_version_items WHERE plan_id = ?`, plan.PlanID).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("%w: a plan needs at least one translation", ErrHuntPlanInvalid)
	}
	rows, err := tx.Query(`SELECT i.translation_id, i.domain_id, i.native_qradar_domain_id
		FROM hunt_plan_version_items i WHERE i.plan_id = ?`, plan.PlanID)
	if err != nil {
		return err
	}
	type item struct{ trID, domainID, native string }
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.trID, &it.domainID, &it.native); err != nil {
			rows.Close()
			return err
		}
		items = append(items, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, it := range items {
		var clientID, kind, status, verifiedBy, native, nativeStatus string
		var rev int
		if err := tx.QueryRow(`SELECT b.client_id, b.binding_kind, b.verification_status, COALESCE(b.verified_by,''),
				b.revision, d.native_qradar_domain_id, d.native_id_status
			FROM qradar_domain_bindings b JOIN qradar_domains d ON d.domain_id = b.domain_id
			WHERE b.domain_id = ?`, it.domainID).
			Scan(&clientID, &kind, &status, &verifiedBy, &rev, &native, &nativeStatus); err != nil {
			return fmt.Errorf("%w: domain binding for %s is gone", ErrHuntPlanEvidenceUnavailable, it.trID)
		}
		if clientID != plan.ClientID || kind != "CLIENT" || status != "VERIFIED" || verifiedBy == "" ||
			native != it.native || nativeStatus != "VERIFIED" {
			return fmt.Errorf("%w: domain ownership changed for %s", ErrHuntPlanConflict, it.trID)
		}
		var trStatus, trBindingRev string
		var trClient, trDomain, trNative, snap, diag, trRuleID, trRuleHash, trAQL string
		var trRuleVersion int
		if err := tx.QueryRow(`SELECT client_id, domain_id, status, CAST(binding_revision AS TEXT),
				native_qradar_domain_id, mapping_snapshot, diagnostics, rule_id, sigma_rule_version,
				sigma_rule_hash, aql_sha256
			FROM detection_translations WHERE translation_id = ?`, it.trID).
			Scan(&trClient, &trDomain, &trStatus, &trBindingRev, &trNative, &snap, &diag,
				&trRuleID, &trRuleVersion, &trRuleHash, &trAQL); err != nil {
			return fmt.Errorf("%w: translation %s is gone", ErrHuntPlanEvidenceUnavailable, it.trID)
		}
		if trClient != plan.ClientID || trDomain != it.domainID {
			return fmt.Errorf("%w: translation %s belongs to another client or domain", ErrHuntPlanConflict, it.trID)
		}
		if trStatus != ReadinessReady {
			return fmt.Errorf("%w: %s is %s, not READY_FOR_REVIEW", ErrHuntPlanConflict, it.trID, trStatus)
		}
		if trAQL == "" {
			return fmt.Errorf("%w: %s has no AQL draft", ErrHuntPlanConflict, it.trID)
		}
		// The source detection version is part of the evidence. A rule edited
		// after the draft was made invalidates the draft.
		var ruleVersion int
		var ruleHash, yaml string
		if err := tx.QueryRow(`SELECT version, yaml_sha256, yaml_text FROM sigma_detection_rules WHERE rule_id = ?`, trRuleID).
			Scan(&ruleVersion, &ruleHash, &yaml); err != nil {
			return fmt.Errorf("%w: source rule for %s is gone", ErrHuntPlanEvidenceUnavailable, it.trID)
		}
		if ruleVersion != trRuleVersion || ruleHash != trRuleHash {
			return fmt.Errorf("%w: source rule changed for %s", ErrHuntPlanConflict, it.trID)
		}
		if trNative != native {
			return fmt.Errorf("%w: native domain id changed for %s", ErrHuntPlanConflict, it.trID)
		}
		if trBindingRev != fmt.Sprintf("%d", rev) {
			return fmt.Errorf("%w: binding revision changed for %s", ErrHuntPlanConflict, it.trID)
		}
		var diags TranslationDiagnostics
		_ = json.Unmarshal([]byte(diag), &diags)
		if err := verifyMappingSnapshotTx(tx, snap, plan.ClientID, it.domainID,
			diags.PrimaryDSM, sigmaEventToken(&SigmaRule{YAML: yaml})); err != nil {
			return err
		}
	}
	return nil
}

// verifyMappingSnapshotTx proves that every mapping in a stored snapshot is still
// the newest applicable mapping for the draft's scope. Selection is identical to
// readiness and translation revalidation: newest numeric version among rows whose
// DSM and event scope match, with an unknown scope never matching a scoped row.
func verifyMappingSnapshotTx(tx *sql.Tx, snapshot, clientID, domainID, dsm, event string) error {
	var mappings []TranslationMapping
	if err := json.Unmarshal([]byte(snapshot), &mappings); err != nil {
		return fmt.Errorf("%w: unreadable mapping snapshot", ErrHuntPlanConflict)
	}
	for _, m := range mappings {
		if m.MappingID == "" {
			continue
		}
		var id, version, cep, approvedBy, curDSM, curEvent string
		err := tx.QueryRow(`SELECT mapping_id, mapping_version, target_cep_field, COALESCE(approved_by,''),
				COALESCE(applicable_dsm,''), COALESCE(applicable_event,'')
			FROM qradar_field_mappings
			WHERE client_id = ? AND domain_id = ? AND LOWER(raw_source_field) = LOWER(?)
			  AND (COALESCE(applicable_dsm,'') = '' OR LOWER(TRIM(applicable_dsm)) = LOWER(TRIM(?)))
			  AND (COALESCE(applicable_event,'') = '' OR LOWER(TRIM(applicable_event)) = LOWER(TRIM(?)))
			ORDER BY CAST(mapping_version AS INTEGER) DESC, created_at DESC LIMIT 1`,
			clientID, domainID, m.Field, dsm, event).
			Scan(&id, &version, &cep, &approvedBy, &curDSM, &curEvent)
		if err != nil {
			return fmt.Errorf("%w: no applicable mapping remains for %s", ErrHuntPlanConflict, m.Field)
		}
		if id != m.MappingID {
			return fmt.Errorf("%w: a newer applicable mapping superseded %s", ErrHuntPlanConflict, m.Field)
		}
		if version != m.MappingVersion || cep != m.CEPField {
			return fmt.Errorf("%w: mapping %s changed", ErrHuntPlanConflict, m.MappingID)
		}
		if m.ApprovedBy != "" && approvedBy == "" {
			return fmt.Errorf("%w: approval for %s was withdrawn", ErrHuntPlanConflict, m.MappingID)
		}
		// Explicit scope check: the query already fails closed, but a mismatch is
		// reported as such instead of looking like a disappeared mapping.
		if curDSM != "" && (dsm == "" || !strings.EqualFold(strings.TrimSpace(curDSM), strings.TrimSpace(dsm))) {
			return fmt.Errorf("%w: mapping %s is out of DSM scope", ErrHuntPlanConflict, m.MappingID)
		}
		if curEvent != "" && (event == "" || !strings.EqualFold(strings.TrimSpace(curEvent), strings.TrimSpace(event))) {
			return fmt.Errorf("%w: mapping %s is out of event scope", ErrHuntPlanConflict, m.MappingID)
		}
		// Two approved applicable mappings for one raw field is ambiguous.
		var approvedCount int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM qradar_field_mappings
			WHERE client_id = ? AND domain_id = ? AND LOWER(raw_source_field) = LOWER(?)
			  AND COALESCE(approved_by,'') <> ''
			  AND (COALESCE(applicable_dsm,'') = '' OR LOWER(TRIM(applicable_dsm)) = LOWER(TRIM(?)))
			  AND (COALESCE(applicable_event,'') = '' OR LOWER(TRIM(applicable_event)) = LOWER(TRIM(?)))`,
			clientID, domainID, m.Field, dsm, event).Scan(&approvedCount); err != nil {
			return err
		}
		if approvedCount > 1 {
			return fmt.Errorf("%w: conflicting approved mappings for %s", ErrHuntPlanConflict, m.Field)
		}
		attested, err := fieldAttestedTx(tx, clientID, domainID, m.CEPField, m.Field)
		if err != nil {
			return err
		}
		if !attested {
			return fmt.Errorf("%w: AQL attestation for %s was withdrawn", ErrHuntPlanConflict, m.Field)
		}
	}
	return nil
}

// fieldAttestedTx mirrors the readiness resolver's attestation rule: a field
// definition matching the CEP identifier (or the raw field name) with at least
// one VERIFIED AQL observation.
func fieldAttestedTx(tx *sql.Tx, clientID, domainID, cep, rawField string) (bool, error) {
	var fieldID string
	err := tx.QueryRow(`SELECT field_id FROM qradar_field_definitions
		WHERE client_id = ? AND domain_id = ? AND (cep_identifier = ? OR LOWER(field_name) = LOWER(?))
		ORDER BY created_at LIMIT 1`, clientID, domainID, cep, rawField).Scan(&fieldID)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM qradar_field_observations
		WHERE client_id = ? AND domain_id = ? AND field_id = ? AND aql_verification_status = 'VERIFIED'`,
		clientID, domainID, fieldID).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// planHash is available for provenance display without claiming verification.
func planHash(plan *HuntPlan) string {
	sum := sha256.Sum256([]byte(plan.PlanID + "|" + fmt.Sprintf("%d", plan.Version) + "|" + plan.Status))
	return hex.EncodeToString(sum[:])
}
