package main

import (
	"database/sql"
	"fmt"
)

// revalidateTranslationTx re-checks every fact the draft depends on, inside the
// transaction that persists it. Any drift — a revoked grant, a rebound domain, a
// changed native id, a new mapping version, a withdrawn approval — aborts with
// ErrTranslationStale and nothing is written.
func revalidateTranslationTx(tx *sql.Tx, userID string, rule *SigmaRule, domain DetectionDomainScope, mappings []TranslationMapping) error {
	// 1. Capability and client grant still hold.
	rp, ok := GetPermissionOfTx(tx, userID)
	if !ok || !CanGenerateAQL(rp) {
		return fmt.Errorf("%w: capability withdrawn", ErrTranslationStale)
	}
	var grants int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM user_authorized_clients WHERE user_id = ? AND client_id = ?`,
		userID, rule.ClientID).Scan(&grants); err != nil {
		return err
	}
	if grants == 0 {
		return fmt.Errorf("%w: client grant withdrawn", ErrTranslationStale)
	}

	// 2. The domain still belongs to the same client through a verified binding,
	//    with the same native id and revision that the analysis used.
	var client, kind, status, verifiedBy, verifiedAt, evidence, nativeID, nativeStatus string
	var revision int
	err := tx.QueryRow(`SELECT COALESCE(b.client_id,''), b.binding_kind, b.verification_status,
			COALESCE(b.verified_by,''), COALESCE(b.verified_at,''), COALESCE(b.evidence_reference,''),
			b.revision, COALESCE(d.native_qradar_domain_id,''), COALESCE(d.native_id_status,'UNVERIFIED')
		FROM qradar_domain_bindings b JOIN qradar_domains d ON d.domain_id = b.domain_id
		WHERE b.domain_id = ?`, domain.DomainID).
		Scan(&client, &kind, &status, &verifiedBy, &verifiedAt, &evidence, &revision, &nativeID, &nativeStatus)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: domain binding disappeared", ErrTranslationStale)
		}
		return err
	}
	switch {
	case client != rule.ClientID:
		return fmt.Errorf("%w: domain reassigned", ErrTranslationStale)
	case kind != "CLIENT" || status != "VERIFIED":
		return fmt.Errorf("%w: binding is no longer a verified client binding", ErrTranslationStale)
	case verifiedBy == "" || verifiedAt == "" || evidence == "":
		return fmt.Errorf("%w: binding evidence removed", ErrTranslationStale)
	case nativeID != domain.NativeDomainID:
		return fmt.Errorf("%w: native domain id changed", ErrTranslationStale)
	case nativeStatus != "VERIFIED":
		return fmt.Errorf("%w: native domain id is no longer verified", ErrTranslationStale)
	case revision != domain.BindingRevision:
		return fmt.Errorf("%w: binding revision changed (%d → %d)", ErrTranslationStale, domain.BindingRevision, revision)
	}

	// 3. Every mapping in the snapshot is still the current applicable one, still
	//    approved where it was approved, still targets the same CEP expression and
	//    is still in scope. The selection rule must be identical to the readiness
	//    resolver: newest numeric version among scope-applicable rows.
	eventToken := sigmaEventToken(rule)
	for _, m := range mappings {
		if m.Field == "" {
			continue
		}
		var id, version, cep, approvedBy string
		err := tx.QueryRow(`SELECT mapping_id, mapping_version, target_cep_field, COALESCE(approved_by,'')
			FROM qradar_field_mappings
			WHERE client_id = ? AND domain_id = ? AND LOWER(raw_source_field) = LOWER(?)
			  AND (COALESCE(applicable_dsm,'') = '' OR LOWER(TRIM(applicable_dsm)) = LOWER(TRIM(?)))
			  AND (COALESCE(applicable_event,'') = '' OR LOWER(TRIM(applicable_event)) = LOWER(TRIM(?)))
			ORDER BY CAST(mapping_version AS INTEGER) DESC, created_at DESC LIMIT 1`,
			rule.ClientID, domain.DomainID, m.Field, domain.PrimaryDSM, eventToken).
			Scan(&id, &version, &cep, &approvedBy)
		if err != nil {
			return fmt.Errorf("%w: applicable mapping for %s disappeared", ErrTranslationStale, m.Field)
		}
		if m.MappingID != "" && id != m.MappingID {
			return fmt.Errorf("%w: a newer applicable mapping exists for %s", ErrTranslationStale, m.Field)
		}
		if m.MappingVersion != "" && version != m.MappingVersion {
			return fmt.Errorf("%w: mapping version for %s changed", ErrTranslationStale, m.Field)
		}
		if m.CEPField != "" && cep != m.CEPField {
			return fmt.Errorf("%w: target CEP expression for %s changed", ErrTranslationStale, m.Field)
		}
		if m.ApprovedBy != "" && approvedBy == "" {
			return fmt.Errorf("%w: approval for %s was withdrawn", ErrTranslationStale, m.Field)
		}
		// Two approved applicable mappings for one raw field is ambiguous, exactly
		// as the readiness resolver reports CONFLICTING_MAPPINGS.
		var approvedCount int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM qradar_field_mappings
			WHERE client_id = ? AND domain_id = ? AND LOWER(raw_source_field) = LOWER(?)
			  AND COALESCE(approved_by,'') <> ''
			  AND (COALESCE(applicable_dsm,'') = '' OR LOWER(TRIM(applicable_dsm)) = LOWER(TRIM(?)))
			  AND (COALESCE(applicable_event,'') = '' OR LOWER(TRIM(applicable_event)) = LOWER(TRIM(?)))`,
			rule.ClientID, domain.DomainID, m.Field, domain.PrimaryDSM, eventToken).Scan(&approvedCount); err != nil {
			return err
		}
		if approvedCount > 1 {
			return fmt.Errorf("%w: conflicting approved mappings for %s", ErrTranslationStale, m.Field)
		}
	}
	return nil
}

// GetPermissionOfTx resolves a role inside a transaction without opening a second
// connection (which would deadlock on a single-connection SQLite pool).
func GetPermissionOfTx(tx *sql.Tx, userID string) (RolePermission, bool) {
	var role string
	if err := tx.QueryRow(`SELECT role FROM users WHERE user_id = ?`, userID).Scan(&role); err != nil {
		return RolePermission{}, false
	}
	return GetPermission(role)
}
