package main

import (
	"database/sql"
	"errors"
	"strings"
)

// M7-D Phase 2: Client Threat Hunting Field Intelligence Registry.
// Additive only: no existing tables are modified. All tables are
// tenant-scoped (client_id enforced by DB triggers). Never mutates
// M6/M7-A/M7-B/M7-C records. Never connects to QRadar; imports are
// purely synthetic file ingestion.

var (
	ErrFieldInventoryNotFound = errors.New("FIELD_INTEL_NOT_FOUND")
	ErrFieldAccessDenied      = errors.New("FIELD_INTEL_ACCESS_DENIED")
	ErrFieldImportInvalid     = errors.New("FIELD_IMPORT_INVALID")
	ErrFieldImportRedacted    = errors.New("FIELD_IMPORT_REDACTION_REQUIRED")
	// ErrFieldVerificationDenied: AQL_VERIFIED was requested without reviewer
	// rights, without the reviewer's own identity, or without evidence.
	ErrFieldVerificationDenied = errors.New("FIELD_VERIFICATION_DENIED")
	// ErrFieldConflict: an approval decision would replace an earlier one.
	ErrFieldConflict = errors.New("FIELD_INTEL_CONFLICT")
	// ErrTranslationStale: the evidence a draft was built on changed before it
	// could be persisted.
	ErrTranslationStale = errors.New("TRANSLATION_STALE_SCOPE")
)

// ---------- types ----------

type QRadarInstance struct {
	InstanceID   string `json:"instance_id"`
	ClientID     string `json:"client_id"`
	InstanceName string `json:"instance_name"`
	Host         string `json:"host,omitempty"`
	CreatedAt    string `json:"created_at"`
}

type QRadarDomain struct {
	DomainID    string `json:"domain_id"`
	InstanceID  string `json:"instance_id"`
	DomainName  string `json:"domain_name"`
	DomainType  string `json:"domain_type,omitempty"`
	CreatedAt   string `json:"created_at"`
	// Binding view (Phase 2A.1). A domain is useful only together with its
	// ownership decision, so these travel with it.
	NativeQRadarDomainID string `json:"native_qradar_domain_id,omitempty"`
	NativeIDStatus       string `json:"native_id_status,omitempty"`
	ClientID             string `json:"client_id,omitempty"`
	BindingKind          string `json:"binding_kind,omitempty"`
	VerificationStatus   string `json:"verification_status,omitempty"`
}

type QRadarLogSourceType struct {
	LogSourceTypeID string `json:"log_source_type_id"`
	DomainID        string `json:"domain_id"`
	TypeName        string `json:"type_name"`
	CreatedAt       string `json:"created_at"`
}

type QRadarLogSource struct {
	LogSourceID     string `json:"log_source_id"`
	LogSourceTypeID string `json:"log_source_type_id"`
	Status          string `json:"status"`
	FirstSeen       string `json:"first_seen,omitempty"`
	LastSeen        string `json:"last_seen,omitempty"`
	DataProvenance  string `json:"data_provenance,omitempty"`
	CreatedAt       string `json:"created_at"`
}

type QRadarQID struct {
	QID             string `json:"qid"`
	LogSourceID     string `json:"log_source_id"`
	EventName       string `json:"event_name"`
	NativeEventID   string `json:"native_event_id,omitempty"`
	CreatedAt       string `json:"created_at"`
}

type QRadarFieldDefinition struct {
	FieldID            string `json:"field_id"`
	ClientID           string `json:"client_id"`
	DomainID           string `json:"domain_id"`
	FieldName          string `json:"field_name"`
	FieldOrigin        string `json:"field_origin"`
	DataType           string `json:"data_type,omitempty"`
	CEPIdentifier      string `json:"cep_identifier,omitempty"`
	SupportedEventScope string `json:"supported_event_scope,omitempty"`
	AQLFieldExpression string `json:"aql_field_expression,omitempty"`
	CreatedAt          string `json:"created_at"`
}

type QRadarFieldMapping struct {
	MappingID          string `json:"mapping_id"`
	ClientID           string `json:"client_id"`
	DomainID           string `json:"domain_id"`
	RawSourceField     string `json:"raw_source_field"`
	TargetCEPField     string `json:"target_cep_field"`
	SemanticAlias      string `json:"semantic_alias,omitempty"`
	ApplicableDSM      string `json:"applicable_dsm,omitempty"`
	ApplicableEvent    string `json:"applicable_event,omitempty"`
	MappingVersion     string `json:"mapping_version"`
	Origin             string `json:"origin"`
	CreatedAt          string `json:"created_at"`
}

type QRadarFieldObservation struct {
	ObservationID          string `json:"observation_id"`
	ClientID               string `json:"client_id"`
	DomainID               string `json:"domain_id"`
	FieldID                string `json:"field_id"`
	FieldPresentInRaw      bool   `json:"field_present_in_raw"`
	QRadarPropertyDisplayed bool  `json:"qradar_property_displayed"`
	ExtractedValuePresent   bool  `json:"extracted_value_present"`
	AQLVerificationStatus  string `json:"aql_verification_status"`
	VerificationTimestamp  string `json:"verification_timestamp,omitempty"`
	VerifiedBy             string `json:"verified_by,omitempty"`
	EvidenceReference      string `json:"evidence_reference,omitempty"`
	CreatedAt              string `json:"created_at"`
}

type QRadarImportBatch struct {
	BatchID          string `json:"batch_id"`
	ClientID         string `json:"client_id"`
	DomainID         string `json:"domain_id"`
	BatchName        string `json:"batch_name"`
	SourceType       string `json:"source_type"`
	FileHash         string `json:"file_hash"`
	ImportedBy       string `json:"imported_by"`
	ProcessingStatus string `json:"processing_status"`
	RedactionResult  string `json:"redaction_result,omitempty"`
	ParseWarnings    string `json:"parse_warnings,omitempty"`
	ImportErrors     string `json:"import_errors,omitempty"`
	ParserVersion    string `json:"parser_version,omitempty"`
	RedactionVersion string `json:"redaction_version,omitempty"`
	ParsedRows       int    `json:"parsed_rows"`
	RejectedRows     int    `json:"rejected_rows"`
	RedactedValues   int    `json:"redacted_values"`
	ReviewedBy       string `json:"reviewed_by,omitempty"`
	ReviewedStatus   string `json:"reviewed_status,omitempty"`
	CreatedAt        string `json:"created_at"`
	PublishedAt      string `json:"published_at,omitempty"`
}

type QRadarImportRow struct {
	RowID      string `json:"row_id"`
	BatchID    string `json:"batch_id"`
	RowNumber  int    `json:"row_number"`
	RawLine    string `json:"raw_line,omitempty"`
	ParsedJSON string `json:"parsed_json,omitempty"`
	ParseError string `json:"parse_error,omitempty"`
	CreatedAt  string `json:"created_at"`
}

type QRadarImportFieldMap struct {
	MapID             string `json:"map_id"`
	BatchID           string `json:"batch_id"`
	RawFieldName      string `json:"raw_field_name"`
	NormalizedFieldName string `json:"normalized_field_name,omitempty"`
	SuggestedCEPField string `json:"suggested_cep_field,omitempty"`
	MappingConfidence string `json:"mapping_confidence,omitempty"`
	Ambiguous         bool   `json:"ambiguous"`
	Evidence          string `json:"evidence,omitempty"`
	CreatedAt         string `json:"created_at"`
}

// ---------- instance ----------

func CreateQRadarInstance(userID, clientID, instanceName, host string) (*QRadarInstance, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if err := requireFieldCapability(userID, CanImportFieldIntel); err != nil {
		return nil, err
	}
	if !hasClientGrant(userID, clientID) {
		return nil, ErrFieldAccessDenied
	}
	instanceID := newID("qi")
	_, err := globalDB.Exec(`INSERT INTO qradar_instances (instance_id, client_id, instance_name, host, created_at, source_category, entered_by, entered_at, revision)
		VALUES (?, ?, ?, ?, datetime('now'), 'MANUAL', ?, datetime('now'), 1)`,
		instanceID, clientID, instanceName, host, userID)
	if err != nil {
		return nil, err
	}
	return GetQRadarInstance(instanceID, userID)
}

func GetQRadarInstance(instanceID, userID string) (*QRadarInstance, error) {
	var inst QRadarInstance
	var clientID string
	err := globalDB.QueryRow(`SELECT instance_id, client_id, instance_name, host, created_at FROM qradar_instances WHERE instance_id = ?`, instanceID).
		Scan(&inst.InstanceID, &clientID, &inst.InstanceName, &inst.Host, &inst.CreatedAt)
	inst.ClientID = clientID
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrFieldInventoryNotFound
		}
		return nil, err
	}
	if !hasClientGrant(userID, clientID) {
		return nil, ErrFieldAccessDenied
	}
	return &inst, nil
}

func ListQRadarInstances(userID, clientID string) ([]QRadarInstance, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if !hasClientGrant(userID, clientID) {
		return nil, ErrFieldAccessDenied
	}
	// A client sees an instance if it owns it (legacy dedicated console) or if at
	// least one domain on it is verified-bound to this client (shared console).
	// Instance ownership alone never grants access to any domain's data.
	rows, err := globalDB.Query(`SELECT DISTINCT i.instance_id, i.client_id, i.instance_name, i.host, i.created_at
		FROM qradar_instances i
		WHERE i.client_id = ?
		   OR EXISTS (SELECT 1 FROM qradar_domain_bindings b
		              WHERE b.instance_id = i.instance_id
		                AND b.binding_kind = 'CLIENT'
		                AND b.verification_status = 'VERIFIED'
		                AND b.client_id = ?)
		ORDER BY i.instance_name`, clientID, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QRadarInstance
	for rows.Next() {
		var inst QRadarInstance
		if err := rows.Scan(&inst.InstanceID, &inst.ClientID, &inst.InstanceName, &inst.Host, &inst.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, inst)
	}
	return out, rows.Err()
}

// ---------- domain ----------

func CreateQRadarDomain(userID, instanceID, domainName, domainType string) (*QRadarDomain, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if err := requireFieldCapability(userID, CanImportFieldIntel); err != nil {
		return nil, err
	}
	// The instance's legacy owner gates *creation* (who may add a domain to this
	// console); it never grants access to the domain itself — that comes from the
	// binding created below.
	var clientID string
	err := globalDB.QueryRow(`SELECT client_id FROM qradar_instances WHERE instance_id = ?`, instanceID).Scan(&clientID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrFieldInventoryNotFound
		}
		return nil, err
	}
	if !hasClientGrant(userID, clientID) {
		return nil, ErrFieldAccessDenied
	}
	domainID := newID("qd")
	tx, err := globalDB.Begin()
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`INSERT INTO qradar_domains (domain_id, instance_id, domain_name, domain_type, created_at, source_category, entered_by, entered_at, revision)
		VALUES (?, ?, ?, ?, datetime('now'), 'MANUAL', ?, datetime('now'), 1)`, domainID, instanceID, domainName, domainType, userID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := CreateDomainBinding(tx, domainID, instanceID, clientID, userID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	// The creator gets the new domain back even though it is not yet owned:
	// ownership requires explicit confirmation, but the caller must be able to
	// see what they just created (it is UNASSIGNED and carries no client data).
	d := &QRadarDomain{
		DomainID:           domainID,
		InstanceID:         instanceID,
		DomainName:         domainName,
		DomainType:         domainType,
		BindingKind:        "UNASSIGNED",
		VerificationStatus: "UNVERIFIED",
		NativeIDStatus:     "UNVERIFIED",
	}
	if b, berr := GetDomainBinding(domainID); berr == nil {
		d.CreatedAt = b.CreatedAt
		d.NativeQRadarDomainID = b.NativeQRadarDomainID
		d.NativeIDStatus = b.NativeIDStatus
		d.BindingKind = b.BindingKind
		d.VerificationStatus = b.VerificationStatus
		d.ClientID = b.ClientID
	}
	return d, nil
}

func GetQRadarDomain(domainID, userID string) (*QRadarDomain, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	var d QRadarDomain
	err := globalDB.QueryRow(`SELECT domain_id, instance_id, domain_name, COALESCE(domain_type,''), created_at
		FROM qradar_domains WHERE domain_id = ?`, domainID).
		Scan(&d.DomainID, &d.InstanceID, &d.DomainName, &d.DomainType, &d.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrFieldInventoryNotFound
		}
		return nil, err
	}
	b, berr := GetDomainBinding(domainID)
	if berr != nil {
		return nil, berr
	}
	d.NativeQRadarDomainID = b.NativeQRadarDomainID
	d.NativeIDStatus = b.NativeIDStatus
	d.BindingKind = b.BindingKind
	d.VerificationStatus = b.VerificationStatus
	d.ClientID = b.ClientID
	// Unassigned/shared domains are visible only to a binding administrator, and
	// only so they can be reconciled. Verified CLIENT domains follow the grant.
	if b.BindingKind != "CLIENT" || b.VerificationStatus != "VERIFIED" {
		if !canManageBindings(userID) {
			return nil, ErrDomainNotAssigned
		}
		return &d, nil
	}
	if !hasClientGrant(userID, b.ClientID) {
		return nil, ErrFieldAccessDenied
	}
	return &d, nil
}

func ListQRadarDomains(userID, instanceID string) ([]QRadarDomain, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	var exists int
	if err := globalDB.QueryRow(`SELECT COUNT(*) FROM qradar_instances WHERE instance_id = ?`, instanceID).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, ErrFieldInventoryNotFound
	}
	// Resolve capability and grants before opening the result set: a one-connection
	// pool cannot serve a nested query while rows are still being iterated.
	manage := canManageBindings(userID)
	granted := authorizedClientsSet(userID)
	rows, err := globalDB.Query(`SELECT d.domain_id, d.instance_id, d.domain_name, COALESCE(d.domain_type,''), d.created_at,
			COALESCE(b.client_id,''), b.binding_kind, b.verification_status,
			COALESCE(d.native_qradar_domain_id,''), COALESCE(d.native_id_status,'UNVERIFIED')
		FROM qradar_domains d JOIN qradar_domain_bindings b ON b.domain_id = d.domain_id
		WHERE d.instance_id = ? ORDER BY d.domain_name`, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QRadarDomain
	for rows.Next() {
		var d QRadarDomain
		if err := rows.Scan(&d.DomainID, &d.InstanceID, &d.DomainName, &d.DomainType, &d.CreatedAt,
			&d.ClientID, &d.BindingKind, &d.VerificationStatus, &d.NativeQRadarDomainID, &d.NativeIDStatus); err != nil {
			return nil, err
		}
		if d.BindingKind == "CLIENT" && d.VerificationStatus == "VERIFIED" {
			if granted[d.ClientID] {
				out = append(out, d)
			}
			continue
		}
		if manage {
			out = append(out, d)
		}
	}
	return out, rows.Err()
}

// authorizedClientsSet loads the caller's grants once, for loops that must not
// issue nested queries.
func authorizedClientsSet(userID string) map[string]bool {
	out := map[string]bool{}
	clients, err := GetUserAuthorizedClientsFromDB(userID)
	if err != nil {
		return out
	}
	for _, c := range clients {
		out[c] = true
	}
	return out
}

// ---------- log source type ----------

func CreateQRadarLogSourceType(userID, domainID, typeName string) (*QRadarLogSourceType, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if err := requireFieldCapability(userID, CanImportFieldIntel); err != nil {
		return nil, err
	}
	if _, derr := requireDomainAccess(userID, domainID, "", nil); derr != nil {
		return nil, derr
	}
	typeID := newID("qlst")
	_, err := globalDB.Exec(`INSERT INTO qradar_log_source_types (log_source_type_id, domain_id, type_name, created_at, source_category, entered_by, entered_at, revision)
		VALUES (?, ?, ?, datetime('now'), 'MANUAL', ?, datetime('now'), 1)`, typeID, domainID, typeName, userID)
	if err != nil {
		return nil, err
	}
	return GetQRadarLogSourceType(typeID, userID)
}

func GetQRadarLogSourceType(typeID, userID string) (*QRadarLogSourceType, error) {
	var t QRadarLogSourceType
	err := globalDB.QueryRow(`SELECT log_source_type_id, domain_id, type_name, created_at
		FROM qradar_log_source_types WHERE log_source_type_id = ?`, typeID).
		Scan(&t.LogSourceTypeID, &t.DomainID, &t.TypeName, &t.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrFieldInventoryNotFound
		}
		return nil, err
	}
	if _, err := requireDomainAccess(userID, t.DomainID, "", nil); err != nil {
		return nil, err
	}
	return &t, nil
}

func ListQRadarLogSourceTypes(userID, domainID string) ([]QRadarLogSourceType, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if _, err := requireDomainAccess(userID, domainID, "", nil); err != nil {
		return nil, err
	}
	rows, err := globalDB.Query(`SELECT log_source_type_id, domain_id, type_name, created_at FROM qradar_log_source_types WHERE domain_id = ? ORDER BY type_name`, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QRadarLogSourceType
	for rows.Next() {
		var t QRadarLogSourceType
		if err := rows.Scan(&t.LogSourceTypeID, &t.DomainID, &t.TypeName, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ---------- log source ----------

func CreateQRadarLogSource(userID, logSourceTypeID, status, dataProvenance string) (*QRadarLogSource, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if err := requireFieldCapability(userID, CanImportFieldIntel); err != nil {
		return nil, err
	}
	domID, err := domainOfLogSourceType(logSourceTypeID)
	if err != nil {
		return nil, err
	}
	if _, err := requireDomainAccess(userID, domID, "", nil); err != nil {
		return nil, err
	}
	lsID := newID("qls")
	_, err = globalDB.Exec(`INSERT INTO qradar_log_sources (log_source_id, log_source_type_id, status, first_seen, last_seen, data_provenance, created_at, source_category, entered_by, entered_at, revision)
		VALUES (?, ?, ?, NULL, NULL, ?, datetime('now'), 'MANUAL', ?, datetime('now'), 1)`, lsID, logSourceTypeID, status, dataProvenance, userID)
	if err != nil {
		return nil, err
	}
	return GetQRadarLogSource(lsID, userID)
}

func GetQRadarLogSource(logSourceID, userID string) (*QRadarLogSource, error) {
	var ls QRadarLogSource
	err := globalDB.QueryRow(`SELECT log_source_id, log_source_type_id, status, COALESCE(first_seen,''), COALESCE(last_seen,''), COALESCE(data_provenance,''), created_at
		FROM qradar_log_sources WHERE log_source_id = ?`, logSourceID).
		Scan(&ls.LogSourceID, &ls.LogSourceTypeID, &ls.Status, &ls.FirstSeen, &ls.LastSeen, &ls.DataProvenance, &ls.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrFieldInventoryNotFound
		}
		return nil, err
	}
	domID, err := domainOfLogSource(logSourceID)
	if err != nil {
		return nil, err
	}
	if _, err := requireDomainAccess(userID, domID, "", nil); err != nil {
		return nil, err
	}
	return &ls, nil
}

func ListQRadarLogSources(userID, logSourceTypeID string) ([]QRadarLogSource, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	domID, err := domainOfLogSourceType(logSourceTypeID)
	if err != nil {
		return nil, err
	}
	if _, err := requireDomainAccess(userID, domID, "", nil); err != nil {
		return nil, err
	}
	rows, err := globalDB.Query(`SELECT l.log_source_id, l.log_source_type_id, l.status, COALESCE(l.first_seen,''), COALESCE(l.last_seen,''), COALESCE(l.data_provenance,''), l.created_at
		FROM qradar_log_sources l WHERE l.log_source_type_id = ? ORDER BY l.log_source_id`, logSourceTypeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QRadarLogSource
	for rows.Next() {
		var ls QRadarLogSource
		if err := rows.Scan(&ls.LogSourceID, &ls.LogSourceTypeID, &ls.Status, &ls.FirstSeen, &ls.LastSeen, &ls.DataProvenance, &ls.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, ls)
	}
	return out, rows.Err()
}

// ---------- QRadar QID ----------

func CreateQRadarQID(userID, logSourceID, eventName, nativeEventID string) (*QRadarQID, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if err := requireFieldCapability(userID, CanImportFieldIntel); err != nil {
		return nil, err
	}
	domID, err := domainOfLogSource(logSourceID)
	if err != nil {
		return nil, err
	}
	if _, err := requireDomainAccess(userID, domID, "", nil); err != nil {
		return nil, err
	}
	qid := newID("qid")
	_, err = globalDB.Exec(`INSERT INTO qradar_qids (qid, log_source_id, event_name, native_event_id, created_at, source_category, entered_by, entered_at, revision)
		VALUES (?, ?, ?, ?, datetime('now'), 'MANUAL', ?, datetime('now'), 1)`, qid, logSourceID, eventName, nativeEventID, userID)
	if err != nil {
		return nil, err
	}
	return GetQRadarQID(qid, userID)
}

func GetQRadarQID(qid, userID string) (*QRadarQID, error) {
	var q QRadarQID
	err := globalDB.QueryRow(`SELECT qid, log_source_id, event_name, COALESCE(native_event_id,''), created_at
		FROM qradar_qids WHERE qid = ?`, qid).
		Scan(&q.QID, &q.LogSourceID, &q.EventName, &q.NativeEventID, &q.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrFieldInventoryNotFound
		}
		return nil, err
	}
	domID, err := domainOfQID(qid)
	if err != nil {
		return nil, err
	}
	if _, err := requireDomainAccess(userID, domID, "", nil); err != nil {
		return nil, err
	}
	return &q, nil
}

func ListQRadarQIDs(userID, logSourceID string) ([]QRadarQID, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	domID, err := domainOfLogSource(logSourceID)
	if err != nil {
		return nil, err
	}
	if _, err := requireDomainAccess(userID, domID, "", nil); err != nil {
		return nil, err
	}
	rows, err := globalDB.Query(`SELECT q.qid, q.log_source_id, q.event_name, COALESCE(q.native_event_id,''), q.created_at
		FROM qradar_qids q WHERE q.log_source_id = ? ORDER BY q.event_name`, logSourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QRadarQID
	for rows.Next() {
		var q QRadarQID
		if err := rows.Scan(&q.QID, &q.LogSourceID, &q.EventName, &q.NativeEventID, &q.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// ---------- field definitions ----------

func CreateQRadarFieldDefinition(userID, clientID, domainID, fieldName, fieldOrigin, dataType, cepIdentifier, supportedEventScope, aqlFieldExpression string) (*QRadarFieldDefinition, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if err := requireFieldCapability(userID, CanImportFieldIntel); err != nil {
		return nil, err
	}
	if _, err := requireDomainAccess(userID, domainID, clientID, nil); err != nil {
		return nil, err
	}
	fieldID := newID("qfd")
	_, err := globalDB.Exec(`INSERT INTO qradar_field_definitions
		(field_id, client_id, domain_id, field_name, field_origin, data_type, cep_identifier, supported_event_scope, aql_field_expression, created_at, source_category, entered_by, entered_at, revision)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), 'MANUAL', ?, datetime('now'), 1)`,
		fieldID, clientID, domainID, fieldName, fieldOrigin, dataType, cepIdentifier, supportedEventScope, aqlFieldExpression, userID)
	if err != nil {
		return nil, err
	}
	return GetQRadarFieldDefinition(fieldID, userID)
}

func GetQRadarFieldDefinition(fieldID, userID string) (*QRadarFieldDefinition, error) {
	var f QRadarFieldDefinition
	err := globalDB.QueryRow(`SELECT f.field_id, f.client_id, f.domain_id, f.field_name, f.field_origin, COALESCE(f.data_type,''), COALESCE(f.cep_identifier,''), COALESCE(f.supported_event_scope,''), COALESCE(f.aql_field_expression,''), f.created_at
		FROM qradar_field_definitions f WHERE f.field_id = ?`, fieldID).
		Scan(&f.FieldID, &f.ClientID, &f.DomainID, &f.FieldName, &f.FieldOrigin, &f.DataType, &f.CEPIdentifier, &f.SupportedEventScope, &f.AQLFieldExpression, &f.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrFieldInventoryNotFound
		}
		return nil, err
	}
	if _, err := requireDomainAccess(userID, f.DomainID, f.ClientID, nil); err != nil {
		return nil, err
	}
	return &f, nil
}

func ListQRadarFieldDefinitions(userID, clientID, domainID string) ([]QRadarFieldDefinition, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if _, err := requireDomainAccess(userID, domainID, clientID, nil); err != nil {
		return nil, err
	}
	rows, err := globalDB.Query(`SELECT field_id, client_id, domain_id, field_name, field_origin, COALESCE(data_type,''), COALESCE(cep_identifier,''), COALESCE(supported_event_scope,''), COALESCE(aql_field_expression,''), created_at
		FROM qradar_field_definitions WHERE client_id = ? AND domain_id = ? ORDER BY field_name`, clientID, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QRadarFieldDefinition
	for rows.Next() {
		var f QRadarFieldDefinition
		if err := rows.Scan(&f.FieldID, &f.ClientID, &f.DomainID, &f.FieldName, &f.FieldOrigin, &f.DataType, &f.CEPIdentifier, &f.SupportedEventScope, &f.AQLFieldExpression, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ---------- field mappings ----------

func CreateQRadarFieldMapping(userID, clientID, domainID, rawSourceField, targetCEPField, semanticAlias, applicableDSM, applicableEvent, mappingVersion, origin string) (*QRadarFieldMapping, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if err := requireFieldCapability(userID, CanImportFieldIntel); err != nil {
		return nil, err
	}
	if _, err := requireDomainAccess(userID, domainID, clientID, nil); err != nil {
		return nil, err
	}
	mappingID := newID("qfm")
	_, err := globalDB.Exec(`INSERT INTO qradar_field_mappings
		(mapping_id, client_id, domain_id, raw_source_field, target_cep_field, semantic_alias, applicable_dsm, applicable_event, mapping_version, origin, created_at, source_category, entered_by, entered_at, revision)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), 'MANUAL', ?, datetime('now'), 1)`,
		mappingID, clientID, domainID, rawSourceField, targetCEPField, semanticAlias, applicableDSM, applicableEvent, mappingVersion, origin, userID)
	if err != nil {
		return nil, err
	}
	return GetQRadarFieldMapping(mappingID, userID)
}

func GetQRadarFieldMapping(mappingID, userID string) (*QRadarFieldMapping, error) {
	var m QRadarFieldMapping
	err := globalDB.QueryRow(`SELECT m.mapping_id, m.client_id, m.domain_id, m.raw_source_field, m.target_cep_field, COALESCE(m.semantic_alias,''), COALESCE(m.applicable_dsm,''), COALESCE(m.applicable_event,''), m.mapping_version, m.origin, m.created_at
		FROM qradar_field_mappings m WHERE m.mapping_id = ?`, mappingID).
		Scan(&m.MappingID, &m.ClientID, &m.DomainID, &m.RawSourceField, &m.TargetCEPField, &m.SemanticAlias, &m.ApplicableDSM, &m.ApplicableEvent, &m.MappingVersion, &m.Origin, &m.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrFieldInventoryNotFound
		}
		return nil, err
	}
	if _, err := requireDomainAccess(userID, m.DomainID, m.ClientID, nil); err != nil {
		return nil, err
	}
	return &m, nil
}

func ListQRadarFieldMappings(userID, clientID, domainID string) ([]QRadarFieldMapping, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if _, err := requireDomainAccess(userID, domainID, clientID, nil); err != nil {
		return nil, err
	}
	rows, err := globalDB.Query(`SELECT mapping_id, client_id, domain_id, raw_source_field, target_cep_field, COALESCE(semantic_alias,''), COALESCE(applicable_dsm,''), COALESCE(applicable_event,''), mapping_version, origin, created_at
		FROM qradar_field_mappings WHERE client_id = ? AND domain_id = ? ORDER BY raw_source_field`, clientID, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QRadarFieldMapping
	for rows.Next() {
		var m QRadarFieldMapping
		if err := rows.Scan(&m.MappingID, &m.ClientID, &m.DomainID, &m.RawSourceField, &m.TargetCEPField, &m.SemanticAlias, &m.ApplicableDSM, &m.ApplicableEvent, &m.MappingVersion, &m.Origin, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---------- field observations ----------

func CreateQRadarFieldObservation(userID, clientID, domainID, fieldID string, fieldPresentInRaw, qradarPropertyDisplayed, extractedValuePresent bool, aqlVerificationStatus, verificationTimestamp, verifiedBy, evidenceReference string) (*QRadarFieldObservation, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	// Recording an observation is an inventory write (import capability). A
	// reviewer may also record one, because a VERIFIED row is their attestation.
	rp, ok := GetPermission(userRoleOf(userID))
	if !ok || !(CanImportFieldIntel(rp) || CanReviewFieldIntel(rp)) {
		return nil, ErrFieldAccessDenied
	}
	if _, err := requireDomainAccess(userID, domainID, clientID, nil); err != nil {
		return nil, err
	}
	observationID := newID("qfo")
	aqlVerificationStatus = strings.ToUpper(strings.TrimSpace(aqlVerificationStatus))
	if aqlVerificationStatus == "" {
		aqlVerificationStatus = "UNVERIFIED"
	}
	switch aqlVerificationStatus {
	case "UNVERIFIED", "UNVERIFIABLE":
		// no attestation claims; nothing extra required
	case "VERIFIED":
		// A client-supplied "VERIFIED" string is not evidence. Verification
		// requires the reviewer capability, the reviewer's own identity, a
		// timestamp and a non-empty evidence reference.
		rp, ok := GetPermission(userRoleOf(userID))
		if !ok || !CanReviewFieldIntel(rp) {
			return nil, ErrFieldVerificationDenied
		}
		if strings.TrimSpace(verifiedBy) != userID {
			return nil, ErrFieldVerificationDenied
		}
		if strings.TrimSpace(evidenceReference) == "" || strings.TrimSpace(verificationTimestamp) == "" {
			return nil, ErrFieldVerificationDenied
		}
	default:
		return nil, ErrFieldImportInvalid
	}
	// Empty strings must be NULL: verified_by is a foreign key, and '' is not a
	// user id.
	var verifiedByArg, tsArg, evArg interface{}
	if strings.TrimSpace(verifiedBy) != "" {
		verifiedByArg = strings.TrimSpace(verifiedBy)
	}
	if strings.TrimSpace(verificationTimestamp) != "" {
		tsArg = strings.TrimSpace(verificationTimestamp)
	}
	if strings.TrimSpace(evidenceReference) != "" {
		evArg = strings.TrimSpace(evidenceReference)
	}
	_, err := globalDB.Exec(`INSERT INTO qradar_field_observations
		(observation_id, client_id, domain_id, field_id, field_present_in_raw, qradar_property_displayed, extracted_value_present, aql_verification_status, verification_timestamp, verified_by, evidence_reference, created_at, source_category, entered_by, entered_at, revision)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), 'MANUAL', ?, datetime('now'), 1)`,
		observationID, clientID, domainID, fieldID, boolToInt(fieldPresentInRaw), boolToInt(qradarPropertyDisplayed), boolToInt(extractedValuePresent), aqlVerificationStatus, tsArg, verifiedByArg, evArg, userID)
	if err != nil {
		return nil, err
	}
	return GetQRadarFieldObservation(observationID, userID)
}

func GetQRadarFieldObservation(observationID, userID string) (*QRadarFieldObservation, error) {
	var o QRadarFieldObservation
	var clientID string
	err := globalDB.QueryRow(`SELECT o.observation_id, o.client_id, o.domain_id, o.field_id, o.field_present_in_raw, o.qradar_property_displayed, o.extracted_value_present, o.aql_verification_status, COALESCE(o.verification_timestamp,''), COALESCE(o.verified_by,''), COALESCE(o.evidence_reference,''), o.created_at
		FROM qradar_field_observations o WHERE o.observation_id = ?`, observationID).
		Scan(&o.ObservationID, &clientID, &o.DomainID, &o.FieldID, &o.FieldPresentInRaw, &o.QRadarPropertyDisplayed, &o.ExtractedValuePresent, &o.AQLVerificationStatus, &o.VerificationTimestamp, &o.VerifiedBy, &o.EvidenceReference, &o.CreatedAt)
	o.ClientID = clientID
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrFieldInventoryNotFound
		}
		return nil, err
	}
	if _, err := requireDomainAccess(userID, o.DomainID, o.ClientID, nil); err != nil {
		return nil, err
	}
	return &o, nil
}

func ListQRadarFieldObservations(userID, clientID, domainID string) ([]QRadarFieldObservation, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if _, err := requireDomainAccess(userID, domainID, clientID, nil); err != nil {
		return nil, err
	}
	rows, err := globalDB.Query(`SELECT o.observation_id, o.client_id, o.domain_id, o.field_id, o.field_present_in_raw, o.qradar_property_displayed, o.extracted_value_present, o.aql_verification_status, COALESCE(o.verification_timestamp,''), COALESCE(o.verified_by,''), COALESCE(o.evidence_reference,''), o.created_at
		FROM qradar_field_observations o WHERE o.client_id = ? AND o.domain_id = ? ORDER BY o.created_at`, clientID, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QRadarFieldObservation
	for rows.Next() {
		var o QRadarFieldObservation
		if err := rows.Scan(&o.ObservationID, &o.ClientID, &o.DomainID, &o.FieldID, &o.FieldPresentInRaw, &o.QRadarPropertyDisplayed, &o.ExtractedValuePresent, &o.AQLVerificationStatus, &o.VerificationTimestamp, &o.VerifiedBy, &o.EvidenceReference, &o.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ---------- import batches ----------

func CreateQRadarImportBatch(userID, clientID, domainID, batchName, sourceType, fileHash string) (*QRadarImportBatch, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if err := requireFieldCapability(userID, CanImportFieldIntel); err != nil {
		return nil, err
	}
	if _, err := requireDomainAccess(userID, domainID, clientID, nil); err != nil {
		return nil, err
	}
	batchID := newID("qib")
	_, err := globalDB.Exec(`INSERT INTO qradar_import_batches
		(batch_id, client_id, domain_id, batch_name, source_type, file_hash, imported_by, processing_status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', datetime('now'))`,
		batchID, clientID, domainID, batchName, sourceType, fileHash, userID)
	if err != nil {
		return nil, err
	}
	return GetQRadarImportBatch(batchID, userID)
}

func GetQRadarImportBatch(batchID, userID string) (*QRadarImportBatch, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	// Ownership is checked by batchClient, which also refuses a batch whose
	// historical client disagrees with the domain's current binding.
	if _, err := batchClient(userID, batchID); err != nil {
		return nil, err
	}
	var b QRadarImportBatch
	err := globalDB.QueryRow(`SELECT b.batch_id, b.client_id, b.domain_id, b.batch_name, b.source_type, b.file_hash, b.imported_by, b.processing_status, COALESCE(b.redaction_result,''), COALESCE(b.parse_warnings,''), COALESCE(b.import_errors,''), b.created_at, COALESCE(b.published_at,''), COALESCE(b.parser_version,''), COALESCE(b.redaction_version,''), COALESCE(b.parsed_rows,0), COALESCE(b.rejected_rows,0), COALESCE(b.redacted_values,0), COALESCE(b.reviewed_by,''), COALESCE(b.reviewed_status,'')
		FROM qradar_import_batches b WHERE b.batch_id = ?`, batchID).
		Scan(&b.BatchID, &b.ClientID, &b.DomainID, &b.BatchName, &b.SourceType, &b.FileHash, &b.ImportedBy, &b.ProcessingStatus, &b.RedactionResult, &b.ParseWarnings, &b.ImportErrors, &b.CreatedAt, &b.PublishedAt, &b.ParserVersion, &b.RedactionVersion, &b.ParsedRows, &b.RejectedRows, &b.RedactedValues, &b.ReviewedBy, &b.ReviewedStatus)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrFieldInventoryNotFound
		}
		return nil, err
	}
	return &b, nil
}

func ListQRadarImportBatches(userID, clientID string) ([]QRadarImportBatch, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if !hasClientGrant(userID, clientID) {
		return nil, ErrFieldAccessDenied
	}
	rows, err := globalDB.Query(`SELECT b.batch_id, b.client_id, b.domain_id, b.batch_name, b.source_type, b.file_hash, b.imported_by, b.processing_status, COALESCE(b.redaction_result,''), COALESCE(b.parse_warnings,''), COALESCE(b.import_errors,''), b.created_at, COALESCE(b.published_at,''), COALESCE(b.parser_version,''), COALESCE(b.redaction_version,''), COALESCE(b.parsed_rows,0), COALESCE(b.rejected_rows,0), COALESCE(b.redacted_values,0), COALESCE(b.reviewed_by,''), COALESCE(b.reviewed_status,'')
		FROM qradar_import_batches b WHERE b.client_id = ? ORDER BY b.created_at DESC`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QRadarImportBatch
	for rows.Next() {
		var b QRadarImportBatch
		if err := rows.Scan(&b.BatchID, &b.ClientID, &b.DomainID, &b.BatchName, &b.SourceType, &b.FileHash, &b.ImportedBy, &b.ProcessingStatus, &b.RedactionResult, &b.ParseWarnings, &b.ImportErrors, &b.CreatedAt, &b.PublishedAt, &b.ParserVersion, &b.RedactionVersion, &b.ParsedRows, &b.RejectedRows, &b.RedactedValues, &b.ReviewedBy, &b.ReviewedStatus); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}


// userRoleOf resolves the stored role of a user. It is used only for capability
// checks that are not derivable from the session alone.
func userRoleOf(userID string) string {
	var role string
	if err := globalDB.QueryRow(`SELECT role FROM users WHERE user_id = ?`, userID).Scan(&role); err != nil {
		return ""
	}
	return role
}
