package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"sort"
	"strings"
)
// ---------- import rows ----------

const (
	maxImportBytes = 4 << 20 // 4 MiB per file
	maxImportRows  = 2000
)

var importSourceTypes = map[string]bool{
	"csv": true, "json": true, "jsonl": true, "txt": true,
	"custom_export": true, "windows_kev": true, "iis": true,
}

// batchClient resolves the owning client of a batch, verifies the caller may
// see it, and refuses any batch whose historical attribution disagrees with the
// domain's current binding. A reassigned domain must never hand a client another
// client's import.
func batchClient(userID, batchID string) (string, error) {
	var clientID, domainID string
	err := globalDB.QueryRow(`SELECT client_id, domain_id FROM qradar_import_batches WHERE batch_id = ?`, batchID).Scan(&clientID, &domainID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", ErrFieldInventoryNotFound
		}
		return "", err
	}
	boundClient, berr := ClientOfDomain(domainID)
	if berr != nil {
		// Missing or unverified binding: the batch is not usable as current
		// client evidence, and nothing about it may be disclosed.
		return "", ErrDomainNotAssigned
	}
	if boundClient != clientID {
		// Historical attribution and current binding disagree. Report the
		// integrity conflict; never rewrite or re-attribute the batch.
		return "", ErrFieldConflict
	}
	if !hasClientGrant(userID, clientID) {
		return "", ErrFieldAccessDenied
	}
	return clientID, nil
}

// Row payloads are written only by insertImportRowTx inside the import
// transaction. A caller-supplied text writer would let any caller store
// unredacted client data and defeat the redaction guarantee, so none exists.

func ListQRadarImportRows(batchID, userID string) ([]QRadarImportRow, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if _, err := batchClient(userID, batchID); err != nil {
		return nil, err
	}
	rows, err := globalDB.Query(`SELECT row_id, batch_id, row_number, COALESCE(redacted_line,''), COALESCE(parsed_json,''), COALESCE(parse_error,''), created_at
		FROM qradar_import_rows WHERE batch_id = ? ORDER BY row_number`, batchID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QRadarImportRow
	for rows.Next() {
		var r QRadarImportRow
		if err := rows.Scan(&r.RowID, &r.BatchID, &r.RowNumber, &r.RawLine, &r.ParsedJSON, &r.ParseError, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---------- import field map ----------

func CreateQRadarImportFieldMap(userID, batchID, rawFieldName, normalizedFieldName, suggestedCEPField, mappingConfidence, evidence string, ambiguous bool) error {
	if err := requireM7DSchema(); err != nil {
		return err
	}
	if err := requireFieldCapability(userID, CanImportFieldIntel); err != nil {
		return err
	}
	if _, err := batchClient(userID, batchID); err != nil {
		return err
	}
	rawFieldName = strings.TrimSpace(rawFieldName)
	if rawFieldName == "" || len(rawFieldName) > 128 {
		return ErrFieldImportInvalid
	}
	// Only a CEP field the catalogue knows may be suggested; anything else
	// would be an invented mapping.
	suggestedCEPField = strings.TrimSpace(suggestedCEPField)
	if suggestedCEPField != "" && !cepCatalogueHas(suggestedCEPField) {
		return ErrFieldImportInvalid
	}
	switch mappingConfidence {
	case "", "high", "medium", "low":
	default:
		return ErrFieldImportInvalid
	}
	mapID := newID("qifm")
	_, err := globalDB.Exec(`INSERT INTO qradar_import_field_map
		(map_id, batch_id, raw_field_name, normalized_field_name, suggested_cep_field, mapping_confidence, ambiguous, evidence, parser_version, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		mapID, batchID, rawFieldName, normalizeFieldName(normalizedFieldName), suggestedCEPField, mappingConfidence, boolToInt(ambiguous), evidence, fieldMappingVersion)
	return err
}

// cepCatalogueHas reports whether a target is a known CEP field.
func cepCatalogueHas(name string) bool {
	for _, spec := range cepCatalogue {
		if spec.Name == name {
			return true
		}
	}
	return false
}

func ListQRadarImportFieldMaps(batchID, userID string) ([]QRadarImportFieldMap, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if _, err := batchClient(userID, batchID); err != nil {
		return nil, err
	}
	rows, err := globalDB.Query(`SELECT map_id, batch_id, raw_field_name, COALESCE(normalized_field_name,''), COALESCE(suggested_cep_field,''), COALESCE(mapping_confidence,''), COALESCE(ambiguous,0), COALESCE(evidence,''), created_at
		FROM qradar_import_field_map WHERE batch_id = ? ORDER BY raw_field_name`, batchID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QRadarImportFieldMap
	for rows.Next() {
		var m QRadarImportFieldMap
		var amb int
		if err := rows.Scan(&m.MapID, &m.BatchID, &m.RawFieldName, &m.NormalizedFieldName, &m.SuggestedCEPField, &m.MappingConfidence, &amb, &m.Evidence, &m.CreatedAt); err != nil {
			return nil, err
		}
		m.Ambiguous = amb == 1
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---------- review / publish ----------

// reviewEvidence rejects empty and generic "evidence": an approval must say
// something a later auditor can act on.
func reviewEvidence(evidence string) (string, error) {
	e := strings.TrimSpace(evidence)
	if len(e) < 12 {
		return "", ErrFieldImportInvalid
	}
	switch strings.ToLower(strings.ReplaceAll(e, " ", "")) {
	case "ok", "okay", "yes", "no", "none", "n/a", "na", "test", "approved", "reviewed", "looksgood", "lgtm":
		return "", ErrFieldImportInvalid
	}
	return e, nil
}

// auditInTx writes the audit row inside the caller's transaction: a decision and
// its audit entry commit together or not at all. An audit failure therefore
// aborts the decision instead of silently losing it.
func auditInTx(tx *sql.Tx, userID, clientID, action, resource, result string) error {
	var client interface{} = clientID
	if clientID == "" {
		client = nil
	}
	_, err := tx.Exec(`INSERT INTO audit_log (event_id, user_id, agent_id, client_id, action, resource, timestamp, result, source_ip, correlation_id)
		VALUES (?, ?, NULL, ?, ?, ?, datetime('now'), ?, NULL, ?)`,
		newID("aud"), userID, client, action, resource, result, generateCorrelationID())
	return err
}

// ReviewQRadarImportBatch records a reviewer decision plus an append-only
// history row. Rules:
//   - capability and client grant are enforced here, not only in middleware;
//   - the batch must have parsed rows and be in MAPPED state;
//   - repeating the same decision is idempotent;
//   - a different decision after review conflicts (earlier approvals stand).
func ReviewQRadarImportBatch(userID, batchID, decision, evidence string) (*QRadarImportBatch, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if err := requireFieldCapability(userID, CanReviewFieldIntel); err != nil {
		return nil, err
	}
	clientID, err := batchClient(userID, batchID)
	if err != nil {
		return nil, err
	}
	decision = strings.ToUpper(strings.TrimSpace(decision))
	if decision != "APPROVED" && decision != "REJECTED" {
		return nil, ErrFieldImportInvalid
	}
	e, err := reviewEvidence(evidence)
	if err != nil {
		return nil, err
	}

	var status, reviewedStatus string
	var parsedRows int
	if err := globalDB.QueryRow(`SELECT processing_status, COALESCE(reviewed_status,''), COALESCE(parsed_rows,0)
		FROM qradar_import_batches WHERE batch_id = ?`, batchID).Scan(&status, &reviewedStatus, &parsedRows); err != nil {
		return nil, err
	}
	if parsedRows <= 0 {
		return nil, ErrFieldImportInvalid
	}
	switch status {
	case "MAPPED":
		// first decision
	case "REVIEWED", "REJECTED":
		if reviewedStatus == decision {
			return GetQRadarImportBatch(batchID, userID) // idempotent repeat
		}
		return nil, ErrFieldConflict // never silently replace an earlier decision
	default:
		return nil, ErrFieldImportInvalid
	}

	newStatus := "REJECTED"
	if decision == "APPROVED" {
		newStatus = "REVIEWED"
	}
	tx, err := globalDB.Begin()
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`INSERT INTO qradar_import_reviews
		(review_id, batch_id, client_id, reviewer_id, decision, evidence, previous_status, new_status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		newID("qrv"), batchID, clientID, userID, decision, e, status, newStatus); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	res, err := tx.Exec(`UPDATE qradar_import_batches
		SET processing_status = ?, reviewed_by = ?, reviewed_at = datetime('now'), reviewed_status = ?
		WHERE batch_id = ? AND processing_status = 'MAPPED'`,
		newStatus, userID, decision, batchID)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_ = tx.Rollback()
		return nil, ErrFieldConflict
	}
	if err := auditInTx(tx, userID, clientID, "IMPORT_REVIEW", batchID, decision); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return GetQRadarImportBatch(batchID, userID)
}

// PublishQRadarImportBatch publishes an approved batch. Guard and history are in
// one transaction, so two concurrent publishes cannot both win.
func PublishQRadarImportBatch(userID, batchID string) (*QRadarImportBatch, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if err := requireFieldCapability(userID, CanReviewFieldIntel); err != nil {
		return nil, err
	}
	clientID, err := batchClient(userID, batchID)
	if err != nil {
		return nil, err
	}
	tx, err := globalDB.Begin()
	if err != nil {
		return nil, err
	}
	res, err := tx.Exec(`UPDATE qradar_import_batches
		SET processing_status = 'PUBLISHED', published_at = datetime('now')
		WHERE batch_id = ? AND processing_status = 'REVIEWED' AND reviewed_status = 'APPROVED' AND COALESCE(parsed_rows,0) > 0`,
		batchID)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_ = tx.Rollback()
		return nil, ErrFieldImportInvalid
	}
	if _, err := tx.Exec(`INSERT INTO qradar_import_reviews
		(review_id, batch_id, client_id, reviewer_id, decision, evidence, previous_status, new_status, created_at)
		VALUES (?, ?, ?, ?, 'PUBLISHED', ?, 'REVIEWED', 'PUBLISHED', datetime('now'))`,
		newID("qrv"), batchID, clientID, userID, "publish after approved review"); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := auditInTx(tx, userID, clientID, "IMPORT_PUBLISH", batchID, "PUBLISHED"); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return GetQRadarImportBatch(batchID, userID)
}

// ---------- file hashing ----------

func hashFileData(data []byte) (string, error) {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// ProcessImportFile ingests a telemetry export safely:
//
//	validate -> parse -> redact -> persist redacted -> derive candidates -> MAPPED
//
// The unredacted payload never reaches SQLite, the log, or an error message.
// Rows are written in one transaction, so an interrupted import leaves a FAILED
// batch with no half-written rows.
func ProcessImportFile(file multipart.File, filename string, userID, clientID, domainID, batchName, sourceType string) (*QRadarImportBatch, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if err := requireFieldCapability(userID, CanImportFieldIntel); err != nil {
		return nil, err
	}
	if !hasClientGrant(userID, clientID) {
		return nil, ErrFieldAccessDenied
	}
	if !importSourceTypes[sourceType] {
		return nil, fmt.Errorf("%w: unsupported source type", ErrFieldImportInvalid)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxImportBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading upload: %w", err)
	}
	if len(data) > maxImportBytes {
		return nil, fmt.Errorf("%w: file exceeds %d bytes", ErrFieldImportInvalid, maxImportBytes)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("%w: empty file", ErrFieldImportInvalid)
	}
	sum := sha256.Sum256(data)
	fileHash := hex.EncodeToString(sum[:])

	// Idempotent duplicate detection uses the canonical import identity:
	// (client_id, domain_id, source_type, file_hash). The same bytes imported
	// into a different domain, or parsed as a different source type, are a
	// different operation and must not reuse this batch.
	var existingBatchID string
	if err := globalDB.QueryRow(`SELECT batch_id FROM qradar_import_batches
		WHERE client_id = ? AND domain_id = ? AND source_type = ? AND file_hash = ?`,
		clientID, domainID, sourceType, fileHash).Scan(&existingBatchID); err == nil {
		return GetQRadarImportBatch(existingBatchID, userID)
	}

	batch, err := CreateQRadarImportBatch(userID, clientID, domainID, batchName, sourceType, fileHash)
	if err != nil {
		// Two concurrent submissions of the same identity: the unique index lets
		// exactly one insert win, and the loser converges on the winner's batch.
		var raced string
		if qerr := globalDB.QueryRow(`SELECT batch_id FROM qradar_import_batches
			WHERE client_id = ? AND domain_id = ? AND source_type = ? AND file_hash = ?`,
			clientID, domainID, sourceType, fileHash).Scan(&raced); qerr == nil {
			return GetQRadarImportBatch(raced, userID)
		}
		return nil, err
	}

	res := parseImport(sourceType, data)
	if res.Ambiguous && len(res.Rows) == 0 {
		msg := "import rejected: " + strings.Join(res.Warnings, "; ")
		_, _ = globalDB.Exec(`UPDATE qradar_import_batches SET processing_status = 'FAILED', import_errors = ?, parser_version = ? WHERE batch_id = ?`,
			msg, res.Parser, batch.BatchID)
		return nil, fmt.Errorf("%w: %s", ErrFieldImportInvalid, msg)
	}

	tx, err := globalDB.Begin()
	if err != nil {
		return nil, err
	}
	parsed, rejected, redactedTotal := 0, 0, 0
	observed := map[string]map[string]int{}

	for i, row := range res.Rows {
		if i >= maxImportRows {
			rejected++
			continue
		}
		if row.Error != "" {
			rejected++
			if _, err := tx.Exec(`INSERT INTO qradar_import_rows
				(row_id, batch_id, row_number, raw_line, parsed_json, parse_error, redacted_line, created_at)
				VALUES (?, ?, ?, NULL, NULL, ?, NULL, datetime('now'))`,
				newID("qir"), batch.BatchID, i+1, row.Error); err != nil {
				_ = tx.Rollback()
				failBatch(batch.BatchID, "row insert failed")
				return nil, err
			}
			continue
		}
		safeFields, st := redactPairs(row.Fields)
		redactedTotal += st.Values
		for k, t := range row.Types {
			if observed[k] == nil {
				observed[k] = map[string]int{}
			}
			observed[k][t]++
		}
		payload, err := json.Marshal(safeFields)
		if err != nil {
			_ = tx.Rollback()
			failBatch(batch.BatchID, "encoding failed")
			return nil, err
		}
		names, err := json.Marshal(sortedKeys(row.Fields))
		if err != nil {
			_ = tx.Rollback()
			failBatch(batch.BatchID, "encoding failed")
			return nil, err
		}
		types, err := json.Marshal(row.Types)
		if err != nil {
			_ = tx.Rollback()
			failBatch(batch.BatchID, "encoding failed")
			return nil, err
		}
		redactedLine := renderRedactedLine(safeFields)
		if _, err := tx.Exec(`INSERT INTO qradar_import_rows
			(row_id, batch_id, row_number, raw_line, parsed_json, parse_error, redacted_line, field_names, field_types, created_at)
			VALUES (?, ?, ?, NULL, ?, NULL, ?, ?, ?, datetime('now'))`,
			newID("qir"), batch.BatchID, i+1, string(payload), redactedLine, string(names), string(types)); err != nil {
			_ = tx.Rollback()
			failBatch(batch.BatchID, "row insert failed")
			return nil, err
		}
		parsed++
	}

	if parsed == 0 {
		_ = tx.Rollback()
		msg := "import rejected: no parseable rows"
		if len(res.Warnings) > 0 {
			msg += " — " + strings.Join(res.Warnings, "; ")
		}
		failBatch(batch.BatchID, msg)
		return nil, fmt.Errorf("%w: %s", ErrFieldImportInvalid, msg)
	}

	candidates := buildCandidates(observed)
	for _, c := range candidates {
		if _, err := tx.Exec(`INSERT INTO qradar_import_field_map
			(map_id, batch_id, raw_field_name, normalized_field_name, suggested_cep_field, mapping_confidence, ambiguous, evidence, parser_version, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
			newID("qifm"), batch.BatchID, c.RawField, c.Normalized, c.CEP, c.Confidence, boolToInt(c.Ambiguous), c.Evidence, fieldMappingVersion); err != nil {
			_ = tx.Rollback()
			failBatch(batch.BatchID, "candidate mapping insert failed")
			return nil, err
		}
	}

	warnings := strings.Join(res.Warnings, "; ")
	status := "MAPPED"
	if _, err := tx.Exec(`UPDATE qradar_import_batches
		SET processing_status = ?, parser_version = ?, redaction_version = ?,
		    parsed_rows = ?, rejected_rows = ?, redacted_values = ?, parse_warnings = ?, import_errors = NULL
		WHERE batch_id = ?`,
		status, res.Parser, fieldRedactionVersion, parsed, rejected, redactedTotal, warnings, batch.BatchID); err != nil {
		_ = tx.Rollback()
		failBatch(batch.BatchID, "batch update failed")
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		failBatch(batch.BatchID, "commit failed")
		return nil, err
	}
	_ = filename
	return GetQRadarImportBatch(batch.BatchID, userID)
}

// clientIDOwningBatch is a best-effort lookup for audit context; it never
// overrides the authorisation performed by batchClient.
func clientIDOwningBatch(batchID string) string {
	var clientID string
	if err := globalDB.QueryRow(`SELECT client_id FROM qradar_import_batches WHERE batch_id = ?`, batchID).Scan(&clientID); err != nil {
		return ""
	}
	return clientID
}

// failBatch records a terminal failure without leaking payload details.
func failBatch(batchID, reason string) {
	_, _ = globalDB.Exec(`UPDATE qradar_import_batches SET processing_status = 'FAILED', import_errors = ? WHERE batch_id = ?`, reason, batchID)
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// renderRedactedLine rebuilds a readable, redacted representation for review.
func renderRedactedLine(fields map[string]string) string {
	keys := sortedKeys(fields)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteString(" | ")
		}
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(fields[k])
	}
	return b.String()
}

// ApproveQRadarFieldMapping turns a candidate mapping into an approved one.
// Approval is auditable, versioned and never performed implicitly by an import.
func ApproveQRadarFieldMapping(userID, mappingID, evidence string) (*QRadarFieldMapping, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if err := requireFieldCapability(userID, CanReviewFieldIntel); err != nil {
		return nil, err
	}
	e, err := reviewEvidence(evidence)
	if err != nil {
		return nil, err
	}
	var clientID, version, approvedBy string
	if err := globalDB.QueryRow(`SELECT client_id, mapping_version, COALESCE(approved_by,'') FROM qradar_field_mappings WHERE mapping_id = ?`, mappingID).
		Scan(&clientID, &version, &approvedBy); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrFieldInventoryNotFound
		}
		return nil, err
	}
	if !hasClientGrant(userID, clientID) {
		return nil, ErrFieldAccessDenied
	}
	// An approved mapping is immutable: a repeat by the same reviewer is
	// idempotent, anything else is a conflict rather than an overwrite.
	if approvedBy != "" {
		if approvedBy == userID {
			return GetQRadarFieldMapping(mappingID, userID)
		}
		return nil, ErrFieldConflict
	}
	tx, err := globalDB.Begin()
	if err != nil {
		return nil, err
	}
	res, err := tx.Exec(`UPDATE qradar_field_mappings
		SET origin = 'manual', approved_by = ?, approved_at = datetime('now'),
		    verification_mode = 'MANUAL_ATTESTED', evidence_reference = ?
		WHERE mapping_id = ? AND COALESCE(approved_by,'') = ''`, userID, e, mappingID)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_ = tx.Rollback()
		return nil, ErrFieldConflict
	}
	if _, err := tx.Exec(`INSERT INTO qradar_mapping_reviews
		(review_id, mapping_id, client_id, reviewer_id, decision, evidence, mapping_version, created_at)
		VALUES (?, ?, ?, ?, 'APPROVED', ?, ?, datetime('now'))`,
		newID("qmr"), mappingID, clientID, userID, e, version); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := auditInTx(tx, userID, clientID, "MAPPING_APPROVE", mappingID, "APPROVED"); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return GetQRadarFieldMapping(mappingID, userID)
}
