package main

import (
	"database/sql"
	"errors"
	"regexp"
	"strings"
)

// M7-D Phase 2A.1: a QRadar domain belongs to an Atlas client through an
// explicit, verified binding — never through the instance's legacy owner and
// never through the domain label.
//
// Resolution contract:
//
//	(instance_id, domain_id) -> native domain id -> active VERIFIED binding -> client_id
//
// Access is denied unless the binding is CLIENT + VERIFIED and the caller holds
// a grant for that client. SHARED and UNASSIGNED deny client-scoped operations.

var (
	ErrDomainBindingMissing = errors.New("DOMAIN_BINDING_MISSING")
	ErrDomainNotAssigned    = errors.New("DOMAIN_NOT_ASSIGNED")
	ErrDomainBindingOwned   = errors.New("DOMAIN_BINDING_CONFLICT")
	ErrNativeDomainIDBad    = errors.New("NATIVE_DOMAIN_ID_INVALID")
)

var reNativeDomainID = regexp.MustCompile(`^[0-9]{1,10}$`)

type QRadarDomainBinding struct {
	BindingID              string `json:"binding_id"`
	DomainID               string `json:"domain_id"`
	InstanceID             string `json:"instance_id"`
	DomainName             string `json:"domain_name,omitempty"`
	NativeQRadarDomainID   string `json:"native_qradar_domain_id,omitempty"`
	NativeIDStatus         string `json:"native_id_status"`
	ClientID               string `json:"client_id,omitempty"`
	BindingKind            string `json:"binding_kind"`
	VerificationStatus     string `json:"verification_status"`
	InferredClientID       string `json:"inferred_client_id,omitempty"`
	VerifiedBy             string `json:"verified_by,omitempty"`
	VerifiedAt             string `json:"verified_at,omitempty"`
	EvidenceReference      string `json:"evidence_reference,omitempty"`
	Revision               int    `json:"revision"`
	CreatedAt              string `json:"created_at"`
	UpdatedAt              string `json:"updated_at"`
}

type DomainBindingHistoryEntry struct {
	HistoryID   string `json:"history_id"`
	DomainID    string `json:"domain_id"`
	NativeID    string `json:"native_qradar_domain_id,omitempty"`
	PrevKind    string `json:"previous_kind"`
	PrevClient  string `json:"previous_client_id,omitempty"`
	PrevStatus  string `json:"previous_status"`
	NewKind     string `json:"new_kind"`
	NewClient   string `json:"new_client_id,omitempty"`
	NewStatus   string `json:"new_status"`
	ActorID     string `json:"actor_id"`
	Evidence    string `json:"evidence_reference"`
	Revision    int    `json:"revision"`
	CreatedAt   string `json:"created_at"`
}

type domainBindingRow struct {
	binding   QRadarDomainBinding
	domainID  string
	clientID  string
	kind      string
	status    string
}

// GetDomainBinding reads the binding and the domain's native identity.
func GetDomainBinding(domainID string) (*QRadarDomainBinding, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	var b QRadarDomainBinding
	var clientID, verifiedBy, verifiedAt, evidence, nativeID sql.NullString
	err := globalDB.QueryRow(`SELECT b.binding_id, b.domain_id, b.instance_id, b.client_id, b.binding_kind,
			b.verification_status, COALESCE(b.inferred_client_id,''), b.verified_by, b.verified_at,
			b.evidence_reference, b.revision, b.created_at, b.updated_at,
			COALESCE(d.domain_name,''), COALESCE(d.native_qradar_domain_id,''), COALESCE(d.native_id_status,'UNVERIFIED')
		FROM qradar_domain_bindings b JOIN qradar_domains d ON d.domain_id = b.domain_id
		WHERE b.domain_id = ?`, domainID).
		Scan(&b.BindingID, &b.DomainID, &b.InstanceID, &clientID, &b.BindingKind, &b.VerificationStatus,
			&b.InferredClientID, &verifiedBy, &verifiedAt, &evidence, &b.Revision, &b.CreatedAt, &b.UpdatedAt,
			&b.DomainName, &nativeID, &b.NativeIDStatus)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrDomainBindingMissing
		}
		return nil, err
	}
	b.ClientID = clientID.String
	b.VerifiedBy = verifiedBy.String
	b.VerifiedAt = verifiedAt.String
	b.EvidenceReference = evidence.String
	b.NativeQRadarDomainID = nativeID.String
	return &b, nil
}

// ClientOfDomain is the single authoritative ownership resolver. It enforces
// the FULL trust invariant, not just the binding flags: a client owns a domain
// only when the binding is a verified CLIENT binding AND the domain carries a
// verified native QRadar domain id with recorded provenance.
func ClientOfDomain(domainID string) (string, error) {
	b, err := GetDomainBinding(domainID)
	if err != nil {
		return "", err
	}
	if b.BindingKind != "CLIENT" || b.VerificationStatus != "VERIFIED" || b.ClientID == "" {
		return "", ErrDomainNotAssigned
	}
	if b.VerifiedBy == "" || b.VerifiedAt == "" || b.EvidenceReference == "" {
		return "", ErrDomainNotAssigned
	}
	if b.NativeIDStatus != "VERIFIED" || b.NativeQRadarDomainID == "" {
		return "", ErrDomainNotAssigned
	}
	return b.ClientID, nil
}

// requireDomainAccess resolves the owner, rejects any mismatch with the caller's
// claim, then enforces capability and client grant. This is the only place a
// domain-scoped operation may obtain a client id.
func requireDomainAccess(userID, domainID, claimedClientID string, check PermissionCheck) (string, error) {
	if err := requireM7DSchema(); err != nil {
		return "", err
	}
	clientID, err := ClientOfDomain(domainID)
	if err != nil {
		return "", err
	}
	if claimedClientID != "" && claimedClientID != clientID {
		// The caller is claiming ownership that the registry does not confirm.
		return "", ErrFieldConflict
	}
	if check != nil {
		if err := requireFieldCapability(userID, check); err != nil {
			return "", err
		}
	}
	if !hasClientGrant(userID, clientID) {
		return "", ErrFieldAccessDenied
	}
	return clientID, nil
}

// domainOfLogSourceType / domainOfLogSource / domainOfQID resolve the domain a
// nested entity belongs to, so binding checks apply to nested writes too.
func domainOfLogSourceType(id string) (string, error) {
	var domainID string
	if err := globalDB.QueryRow(`SELECT domain_id FROM qradar_log_source_types WHERE log_source_type_id = ?`, id).Scan(&domainID); err != nil {
		if err == sql.ErrNoRows {
			return "", ErrFieldInventoryNotFound
		}
		return "", err
	}
	return domainID, nil
}

func domainOfLogSource(id string) (string, error) {
	var domainID string
	err := globalDB.QueryRow(`SELECT t.domain_id FROM qradar_log_sources s
		JOIN qradar_log_source_types t ON t.log_source_type_id = s.log_source_type_id
		WHERE s.log_source_id = ?`, id).Scan(&domainID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", ErrFieldInventoryNotFound
		}
		return "", err
	}
	return domainID, nil
}

func domainOfQID(id string) (string, error) {
	var domainID string
	err := globalDB.QueryRow(`SELECT t.domain_id FROM qradar_qids q
		JOIN qradar_log_sources s ON s.log_source_id = q.log_source_id
		JOIN qradar_log_source_types t ON t.log_source_type_id = s.log_source_type_id
		WHERE q.qid = ?`, id).Scan(&domainID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", ErrFieldInventoryNotFound
		}
		return "", err
	}
	return domainID, nil
}

// CreateDomainBinding records that a domain exists and is NOT yet owned. A newly
// created domain is UNASSIGNED/UNVERIFIED: creating a row is not evidence of
// ownership, and no client is inferred from the creating user. The creator's
// client is kept as reconciliation metadata only.
func CreateDomainBinding(tx *sql.Tx, domainID, instanceID, inferredClientID, actorID string) error {
	_, err := tx.Exec(`INSERT INTO qradar_domain_bindings
		(binding_id, domain_id, instance_id, client_id, binding_kind, verification_status,
		 inferred_client_id, revision, created_at, updated_at)
		VALUES (?, ?, ?, NULL, 'UNASSIGNED', 'UNVERIFIED', ?, 1, datetime('now'), datetime('now'))`,
		newID("qdb"), domainID, instanceID, nullableString(inferredClientID))
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO qradar_domain_binding_history
		(history_id, binding_id, domain_id, instance_id, native_qradar_domain_id,
		 previous_kind, previous_client_id, previous_status,
		 new_kind, new_client_id, new_status, actor_id, evidence_reference, revision, created_at)
		SELECT ?, b.binding_id, b.domain_id, b.instance_id, NULL,
		       'UNASSIGNED', NULL, 'UNVERIFIED', 'UNASSIGNED', NULL, 'UNVERIFIED', ?, ?, 1, datetime('now')
		FROM qradar_domain_bindings b WHERE b.domain_id = ?`,
		newID("qdbh"), actorID, "domain created; binding unverified pending native domain id", domainID)
	return err
}

// ListDomainBindings returns bindings for one instance. Callers with the binding
// management capability see every domain (including unassigned ones, which is
// what makes reconciliation possible). Everyone else sees only verified CLIENT
// bindings for clients they are granted.
func ListDomainBindings(userID, instanceID string) ([]QRadarDomainBinding, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	rp, ok := GetPermission(userRoleOf(userID))
	canManage := ok && CanManageQRadarBindings(rp)
	granted := authorizedClientsSet(userID)

	rows, err := globalDB.Query(`SELECT b.binding_id, b.domain_id, b.instance_id, COALESCE(b.client_id,''), b.binding_kind,
			b.verification_status, COALESCE(b.inferred_client_id,''), COALESCE(b.verified_by,''), COALESCE(b.verified_at,''),
			COALESCE(b.evidence_reference,''), b.revision, b.created_at, b.updated_at,
			COALESCE(d.domain_name,''), COALESCE(d.native_qradar_domain_id,''), COALESCE(d.native_id_status,'UNVERIFIED')
		FROM qradar_domain_bindings b JOIN qradar_domains d ON d.domain_id = b.domain_id
		WHERE b.instance_id = ? ORDER BY d.domain_name`, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QRadarDomainBinding
	for rows.Next() {
		var b QRadarDomainBinding
		if err := rows.Scan(&b.BindingID, &b.DomainID, &b.InstanceID, &b.ClientID, &b.BindingKind,
			&b.VerificationStatus, &b.InferredClientID, &b.VerifiedBy, &b.VerifiedAt,
			&b.EvidenceReference, &b.Revision, &b.CreatedAt, &b.UpdatedAt,
			&b.DomainName, &b.NativeQRadarDomainID, &b.NativeIDStatus); err != nil {
			return nil, err
		}
		if !canManage {
			if b.BindingKind != "CLIENT" || b.VerificationStatus != "VERIFIED" || !granted[b.ClientID] {
				continue
			}
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

type DomainBindingUpdate struct {
	NativeQRadarDomainID string `json:"native_qradar_domain_id"`
	ClientID             string `json:"client_id"`
	BindingKind          string `json:"binding_kind"`
	Evidence             string `json:"evidence"`
	ExpectedRevision     int    `json:"expected_revision"`
}

// UpdateDomainBinding is the privileged reconciliation operation. It requires
// the administrator binding capability, real evidence, an actor identity taken
// from the session (never from the request), and an expected revision so two
// administrators cannot silently overwrite each other.
func UpdateDomainBinding(userID, domainID string, req DomainBindingUpdate) (*QRadarDomainBinding, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	rp, ok := GetPermission(userRoleOf(userID))
	if !ok || !CanManageQRadarBindings(rp) {
		return nil, ErrFieldAccessDenied
	}
	evidence, err := reviewEvidence(req.Evidence)
	if err != nil {
		return nil, err
	}
	kind := strings.ToUpper(strings.TrimSpace(req.BindingKind))
	clientID := strings.TrimSpace(req.ClientID)
	switch kind {
	case "CLIENT":
		if clientID == "" {
			return nil, ErrFieldImportInvalid
		}
		var exists int
		if err := globalDB.QueryRow(`SELECT COUNT(*) FROM clients WHERE client_id = ?`, clientID).Scan(&exists); err != nil {
			return nil, err
		}
		if exists == 0 {
			return nil, ErrFieldInventoryNotFound
		}
	case "SHARED", "UNASSIGNED":
		if clientID != "" {
			return nil, ErrFieldImportInvalid
		}
	default:
		return nil, ErrFieldImportInvalid
	}
	native := strings.TrimSpace(req.NativeQRadarDomainID)
	if native != "" && !reNativeDomainID.MatchString(native) {
		return nil, ErrNativeDomainIDBad
	}

	current, err := GetDomainBinding(domainID)
	if err != nil {
		return nil, err
	}
	// Optimistic concurrency is mandatory: a caller that has not read the current
	// binding cannot confirm or revoke it blind.
	if req.ExpectedRevision <= 0 || req.ExpectedRevision != current.Revision {
		return nil, ErrDomainBindingOwned
	}
	// A CLIENT binding may only become VERIFIED when the domain carries a real,
	// verified native QRadar domain id. Accepting it from this request is fine;
	// accepting whatever is already stored requires that it is itself verified.
	if kind == "CLIENT" {
		if native == "" {
			if current.NativeIDStatus != "VERIFIED" || current.NativeQRadarDomainID == "" {
				// Never promote a binding on the strength of an empty or unverified id.
				return nil, ErrNativeDomainIDBad
			}
		}
	}

	tx, err := globalDB.Begin()
	if err != nil {
		return nil, err
	}
	if native != "" {
		if _, err := tx.Exec(`UPDATE qradar_domains
			SET native_qradar_domain_id = ?, native_id_status = 'VERIFIED', native_id_source = 'ADMIN_CONFIRMED'
			WHERE domain_id = ?`, native, domainID); err != nil {
			_ = tx.Rollback()
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				return nil, ErrNativeDomainIDBad
			}
			return nil, err
		}
	}
	res, err := tx.Exec(`UPDATE qradar_domain_bindings
		SET client_id = ?, binding_kind = ?, verification_status = 'VERIFIED',
		    verified_by = ?, verified_at = datetime('now'), evidence_reference = ?,
		    revision = revision + 1, updated_at = datetime('now')
		WHERE domain_id = ? AND revision = ?`,
		nullableString(clientID), kind, userID, evidence, domainID, current.Revision)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_ = tx.Rollback()
		return nil, ErrDomainBindingOwned // concurrent confirmation won
	}
	if _, err := tx.Exec(`INSERT INTO qradar_domain_binding_history
		(history_id, binding_id, domain_id, instance_id, native_qradar_domain_id,
		 previous_kind, previous_client_id, previous_status,
		 new_kind, new_client_id, new_status, actor_id, evidence_reference, revision, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'VERIFIED', ?, ?, ?, datetime('now'))`,
		newID("qdbh"), current.BindingID, domainID, current.InstanceID, nullableString(native),
		current.BindingKind, nullableString(current.ClientID), current.VerificationStatus,
		kind, nullableString(clientID), userID, evidence, current.Revision+1); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := auditInTx(tx, userID, clientID, "DOMAIN_BINDING_UPDATE", domainID, kind); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return GetDomainBinding(domainID)
}

func ListDomainBindingHistory(userID, domainID string) ([]DomainBindingHistoryEntry, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	rp, ok := GetPermission(userRoleOf(userID))
	canManage := ok && CanManageQRadarBindings(rp)
	if !canManage {
		if _, err := requireDomainAccess(userID, domainID, "", nil); err != nil {
			return nil, err
		}
	}
	rows, err := globalDB.Query(`SELECT history_id, domain_id, COALESCE(native_qradar_domain_id,''),
			previous_kind, COALESCE(previous_client_id,''), previous_status,
			new_kind, COALESCE(new_client_id,''), new_status,
			actor_id, evidence_reference, revision, created_at
		FROM qradar_domain_binding_history WHERE domain_id = ? ORDER BY created_at, revision`, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DomainBindingHistoryEntry
	for rows.Next() {
		var h DomainBindingHistoryEntry
		if err := rows.Scan(&h.HistoryID, &h.DomainID, &h.NativeID, &h.PrevKind, &h.PrevClient, &h.PrevStatus,
			&h.NewKind, &h.NewClient, &h.NewStatus, &h.ActorID, &h.Evidence, &h.Revision, &h.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func nullableString(s string) interface{} {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}
