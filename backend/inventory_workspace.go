package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// M7-F Phase 1: manual inventory workspace.
//
// Structured metadata import and completeness diagnostics over the existing
// QRadar inventory tables. Nothing here verifies a binding, approves a mapping,
// attests a field, contacts QRadar or executes AQL.

const (
	inventoryImportMaxBytes = 512 << 10
	inventoryImportMaxRows  = 2000
)

type inventoryKind struct {
	Columns  []string
	Required []string
}

var inventoryKinds = map[string]inventoryKind{
	"log_source_types": {Columns: []string{"type_name"}, Required: []string{"type_name"}},
	"log_sources":      {Columns: []string{"type_name", "status", "data_provenance"}, Required: []string{"type_name"}},
	"qids":             {Columns: []string{"type_name", "event_name", "native_event_id"}, Required: []string{"event_name"}},
	"field_definitions": {Columns: []string{"field_name", "field_origin", "data_type", "cep_identifier",
		"supported_event_scope", "aql_field_expression"}, Required: []string{"field_name"}},
	"field_mappings": {Columns: []string{"raw_source_field", "target_cep_field", "semantic_alias",
		"applicable_dsm", "applicable_event", "mapping_version"}, Required: []string{"raw_source_field", "target_cep_field"}},
}

var inventoryKindOrder = []string{"log_source_types", "log_sources", "qids", "field_definitions", "field_mappings"}

type InventoryImportRequest struct {
	ClientID       string `json:"client_id"`
	DomainID       string `json:"domain_id"`
	Kind           string `json:"kind"`
	Format         string `json:"format"`
	Content        string `json:"content"`
	DeclaredSource string `json:"declared_source"`
	DryRun         bool   `json:"dry_run"`
	Confirm        bool   `json:"confirm"`
}

type InventoryImportRow struct {
	Line    int               `json:"line"`
	Status  string            `json:"status"`
	Message string            `json:"message,omitempty"`
	Fields  map[string]string `json:"fields"`
}

type InventoryImportPreview struct {
	Kind           string              `json:"kind"`
	Format         string              `json:"format"`
	ClientID       string              `json:"client_id"`
	DomainID       string              `json:"domain_id"`
	DeclaredSource string              `json:"declared_source"`
	DryRun         bool                `json:"dry_run"`
	Rows           []InventoryImportRow `json:"rows"`
	Summary        map[string]int      `json:"summary"`
	Conflicts      []string            `json:"conflicts"`
	Notes          []string            `json:"notes"`
	ExistingRows   int                 `json:"existing_rows"`
	ContentSHA256  string              `json:"content_sha256"`
}

type rowQueryer interface {
	QueryRow(query string, args ...interface{}) *sql.Row
}

// requireInventoryScope resolves the target domain through the existing binding
// and grant rules. Import never establishes ownership.
func requireInventoryScope(userID, clientID, domainID string) error {
	if strings.TrimSpace(clientID) == "" || strings.TrimSpace(domainID) == "" {
		return fmt.Errorf("%w: client_id and domain_id are required", ErrFieldImportInvalid)
	}
	if _, err := requireDomainAccess(userID, domainID, clientID, CanImportFieldIntel); err != nil {
		return err
	}
	return nil
}

func previewInventoryImport(userID string, req InventoryImportRequest) (*InventoryImportPreview, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if err := requireFieldCapability(userID, CanImportFieldIntel); err != nil {
		return nil, ErrFieldAccessDenied
	}
	if err := requireInventoryScope(userID, req.ClientID, req.DomainID); err != nil {
		return nil, err
	}
	return buildInventoryPreview(globalDB, req)
}

func buildInventoryPreview(q rowQueryer, req InventoryImportRequest) (*InventoryImportPreview, error) {
	kind, ok := inventoryKinds[strings.ToLower(strings.TrimSpace(req.Kind))]
	if !ok {
		return nil, fmt.Errorf("%w: unsupported inventory kind", ErrFieldImportInvalid)
	}
	format := strings.ToLower(strings.TrimSpace(req.Format))
	if format != "csv" && format != "json" {
		return nil, fmt.Errorf("%w: format must be csv or json", ErrFieldImportInvalid)
	}
	if len(req.Content) > inventoryImportMaxBytes {
		return nil, fmt.Errorf("%w: content exceeds %d bytes", ErrFieldImportInvalid, inventoryImportMaxBytes)
	}
	rows, err := parseInventoryRows(kind, format, req.Content)
	if err != nil {
		return nil, err
	}
	if len(rows) > inventoryImportMaxRows {
		return nil, fmt.Errorf("%w: more than %d rows", ErrFieldImportInvalid, inventoryImportMaxRows)
	}

	sum := sha256.Sum256([]byte(req.Content))
	p := &InventoryImportPreview{
		Kind: strings.ToLower(strings.TrimSpace(req.Kind)), Format: format,
		ClientID: req.ClientID, DomainID: req.DomainID, DeclaredSource: strings.TrimSpace(req.DeclaredSource),
		DryRun: req.DryRun, Summary: map[string]int{}, ContentSHA256: hex.EncodeToString(sum[:]),
	}
	p.Notes = append(p.Notes,
		"Imported metadata is marked IMPORTED_UNVERIFIED; it never confirms a binding, approves a mapping or attests a field.",
		"Rows absent from this file are not evidence of deletion in QRadar.")

	seen := map[string]int{}
	for i := range rows {
		row := &rows[i]
		key := importNaturalKey(p.Kind, row.Fields)
		if prev, dup := seen[key]; dup {
			row.Status = "DUPLICATE"
			row.Message = fmt.Sprintf("duplicate of line %d in this file", prev)
			p.Summary["duplicate"]++
			p.Rows = append(p.Rows, *row)
			continue
		}
		seen[key] = row.Line
		status, message := classifyInventoryRow(q, p.Kind, req.ClientID, req.DomainID, row.Fields)
		row.Status = status
		row.Message = message
		switch status {
		case "CREATE":
			p.Summary["create"]++
		case "DUPLICATE":
			p.Summary["duplicate"]++
		case "CONFLICT":
			p.Summary["conflict"]++
			p.Conflicts = append(p.Conflicts, fmt.Sprintf("line %d: %s", row.Line, message))
		default:
			status = "ERROR"
			row.Status = "ERROR"
			p.Summary["error"]++
		}
		p.Rows = append(p.Rows, *row)
	}
	p.Summary["rows"] = len(rows)
	p.ExistingRows, _ = countInventoryRows(q, p.Kind, req.ClientID, req.DomainID)
	return p, nil
}

func parseInventoryRows(kind inventoryKind, format, content string) ([]InventoryImportRow, error) {
	content = strings.TrimPrefix(content, "\ufeff")
	if strings.TrimSpace(content) == "" {
		return nil, fmt.Errorf("%w: empty content", ErrFieldImportInvalid)
	}
	switch format {
	case "csv":
		r := csv.NewReader(strings.NewReader(content))
		r.FieldsPerRecord = len(kind.Columns)
		records, err := r.ReadAll()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFieldImportInvalid, err)
		}
		if len(records) < 2 {
			return nil, fmt.Errorf("%w: a header and at least one row are required", ErrFieldImportInvalid)
		}
		header := records[0]
		want := map[string]bool{}
		for _, c := range kind.Columns {
			want[c] = true
		}
		got := map[string]bool{}
		for i, h := range header {
			h = strings.ToLower(strings.TrimSpace(h))
			if !want[h] {
				return nil, fmt.Errorf("%w: unknown column %q", ErrFieldImportInvalid, header[i])
			}
			if got[h] {
				return nil, fmt.Errorf("%w: duplicate column %q", ErrFieldImportInvalid, h)
			}
			got[h] = true
			header[i] = h
		}
		for _, c := range kind.Required {
			if !got[c] {
				return nil, fmt.Errorf("%w: missing column %q", ErrFieldImportInvalid, c)
			}
		}
		var out []InventoryImportRow
		for i, rec := range records[1:] {
			fields := map[string]string{}
			for j, h := range header {
				fields[h] = strings.TrimSpace(rec[j])
			}
			row := InventoryImportRow{Line: i + 2, Fields: fields}
			if msg := validateInventoryFields(kind, fields); msg != "" {
				row.Status, row.Message = "ERROR", msg
			}
			out = append(out, row)
		}
		return out, nil
	case "json":
		var docs []map[string]interface{}
		dec := json.NewDecoder(strings.NewReader(content))
		dec.UseNumber()
		if err := dec.Decode(&docs); err != nil {
			return nil, fmt.Errorf("%w: invalid JSON array", ErrFieldImportInvalid)
		}
		if len(docs) == 0 {
			return nil, fmt.Errorf("%w: JSON array is empty", ErrFieldImportInvalid)
		}
		allowed := map[string]bool{}
		for _, c := range kind.Columns {
			allowed[c] = true
		}
		var out []InventoryImportRow
		for i, doc := range docs {
			fields := map[string]string{}
			for k, v := range doc {
				key := strings.ToLower(strings.TrimSpace(k))
				if !allowed[key] {
					return nil, fmt.Errorf("%w: unknown field %q", ErrFieldImportInvalid, k)
				}
				fields[key] = strings.TrimSpace(fmt.Sprintf("%v", v))
			}
			row := InventoryImportRow{Line: i + 1, Fields: fields}
			if msg := validateInventoryFields(kind, fields); msg != "" {
				row.Status, row.Message = "ERROR", msg
			}
			out = append(out, row)
		}
		return out, nil
	}
	return nil, fmt.Errorf("%w: unsupported format", ErrFieldImportInvalid)
}

func validateInventoryFields(kind inventoryKind, fields map[string]string) string {
	for _, req := range kind.Required {
		if strings.TrimSpace(fields[req]) == "" {
			return "missing required value " + req
		}
	}
	if v := fields["field_origin"]; v != "" {
		switch v {
		case "system", "normalized", "custom", "raw_only":
		default:
			return "field_origin must be system, normalized, custom or raw_only"
		}
	}
	if v := fields["status"]; v != "" {
		switch v {
		case "CONNECTED", "DISCONNECTED", "NO_RECENT_EVENTS", "UNKNOWN":
		default:
			return "status must be CONNECTED, DISCONNECTED, NO_RECENT_EVENTS or UNKNOWN"
		}
	}
	return ""
}

func importNaturalKey(kind string, f map[string]string) string {
	switch kind {
	case "log_source_types":
		return strings.ToLower(f["type_name"])
	case "log_sources":
		return strings.ToLower(f["type_name"] + "|" + f["data_provenance"])
	case "qids":
		return strings.ToLower(f["type_name"] + "|" + f["event_name"])
	case "field_definitions":
		return strings.ToLower(f["field_name"])
	case "field_mappings":
		v := f["mapping_version"]
		if v == "" {
			v = "1"
		}
		return strings.ToLower(f["raw_source_field"] + "|" + f["target_cep_field"] + "|" + v)
	}
	return ""
}

// classifyInventoryRow compares one row with the current inventory inside the
// caller's query scope (database for preview, transaction for commit).
func classifyInventoryRow(q rowQueryer, kind, clientID, domainID string, f map[string]string) (string, string) {
	switch kind {
	case "log_source_types":
		var n int
		if err := q.QueryRow(`SELECT COUNT(*) FROM qradar_log_source_types WHERE domain_id = ? AND LOWER(type_name) = LOWER(?)`,
			domainID, f["type_name"]).Scan(&n); err != nil {
			return "ERROR", "registry read failed"
		}
		if n > 0 {
			return "DUPLICATE", "log source type already exists"
		}
		return "CREATE", ""

	case "log_sources":
		var typeID string
		err := q.QueryRow(`SELECT log_source_type_id FROM qradar_log_source_types WHERE domain_id = ? AND LOWER(type_name) = LOWER(?)`,
			domainID, f["type_name"]).Scan(&typeID)
		if err == sql.ErrNoRows {
			return "ERROR", "no log source type named " + f["type_name"]
		}
		if err != nil {
			return "ERROR", "registry read failed"
		}
		var status string
		err = q.QueryRow(`SELECT status FROM qradar_log_sources
			WHERE log_source_type_id = ? AND LOWER(COALESCE(data_provenance,'')) = LOWER(?)`, typeID, f["data_provenance"]).Scan(&status)
		if err == sql.ErrNoRows {
			return "CREATE", ""
		}
		if err != nil {
			return "ERROR", "registry read failed"
		}
		want := strings.TrimSpace(f["status"])
		if want == "" {
			want = "UNKNOWN"
		}
		if !strings.EqualFold(status, want) {
			return "CONFLICT", "log source exists with status " + status + ", file says " + want
		}
		return "DUPLICATE", "log source already exists"

	case "qids":
		var logSourceID string
		err := q.QueryRow(`SELECT s.log_source_id FROM qradar_log_sources s
			JOIN qradar_log_source_types t ON t.log_source_type_id = s.log_source_type_id
			WHERE t.domain_id = ? AND LOWER(t.type_name) = LOWER(?) ORDER BY s.created_at LIMIT 1`,
			domainID, f["type_name"]).Scan(&logSourceID)
		if err == sql.ErrNoRows {
			return "ERROR", "no log source for type " + f["type_name"]
		}
		if err != nil {
			return "ERROR", "registry read failed"
		}
		var native string
		err = q.QueryRow(`SELECT COALESCE(native_event_id,'') FROM qradar_qids WHERE log_source_id = ? AND LOWER(event_name) = LOWER(?)`,
			logSourceID, f["event_name"]).Scan(&native)
		if err == sql.ErrNoRows {
			return "CREATE", ""
		}
		if err != nil {
			return "ERROR", "registry read failed"
		}
		if !strings.EqualFold(strings.TrimSpace(native), strings.TrimSpace(f["native_event_id"])) {
			return "CONFLICT", "QID already exists with native event id " + native
		}
		return "DUPLICATE", "QID already exists"

	case "field_definitions":
		var origin, dataType, cep, expr string
		err := q.QueryRow(`SELECT field_origin, COALESCE(data_type,''), COALESCE(cep_identifier,''), COALESCE(aql_field_expression,'')
			FROM qradar_field_definitions WHERE client_id = ? AND domain_id = ? AND LOWER(field_name) = LOWER(?)`,
			clientID, domainID, f["field_name"]).Scan(&origin, &dataType, &cep, &expr)
		if err == sql.ErrNoRows {
			return "CREATE", ""
		}
		if err != nil {
			return "ERROR", "registry read failed"
		}
		wantOrigin := f["field_origin"]
		if wantOrigin == "" {
			wantOrigin = "raw_only"
		}
		if !strings.EqualFold(origin, wantOrigin) || dataType != f["data_type"] ||
			cep != f["cep_identifier"] || expr != f["aql_field_expression"] {
			return "CONFLICT", "field definition exists with different attributes"
		}
		return "DUPLICATE", "field definition already exists"

	case "field_mappings":
		version := f["mapping_version"]
		if version == "" {
			version = "1"
		}
		var cep string
		err := q.QueryRow(`SELECT target_cep_field FROM qradar_field_mappings
			WHERE client_id = ? AND domain_id = ? AND LOWER(raw_source_field) = LOWER(?) AND mapping_version = ?`,
			clientID, domainID, f["raw_source_field"], version).Scan(&cep)
		if err == nil {
			if strings.EqualFold(cep, f["target_cep_field"]) {
				return "DUPLICATE", "mapping already exists"
			}
			return "CONFLICT", "same mapping version already targets " + cep
		}
		if err != sql.ErrNoRows {
			return "ERROR", "registry read failed"
		}
		// An approved mapping with a different CEP for the same raw field would be
		// ambiguous evidence; refuse to layer another target on it.
		var approvedCEP string
		err = q.QueryRow(`SELECT target_cep_field FROM qradar_field_mappings
			WHERE client_id = ? AND domain_id = ? AND LOWER(raw_source_field) = LOWER(?)
			  AND COALESCE(approved_by,'') <> '' ORDER BY created_at DESC LIMIT 1`,
			clientID, domainID, f["raw_source_field"]).Scan(&approvedCEP)
		if err == nil && !strings.EqualFold(approvedCEP, f["target_cep_field"]) {
			return "CONFLICT", "an approved mapping already targets " + approvedCEP
		}
		if err != nil && err != sql.ErrNoRows {
			return "ERROR", "registry read failed"
		}
		return "CREATE", ""
	}
	return "ERROR", "unsupported kind"
}

func countInventoryRows(q rowQueryer, kind, clientID, domainID string) (int, error) {
	var n int
	var err error
	switch kind {
	case "log_source_types":
		err = q.QueryRow(`SELECT COUNT(*) FROM qradar_log_source_types WHERE domain_id = ?`, domainID).Scan(&n)
	case "log_sources":
		err = q.QueryRow(`SELECT COUNT(*) FROM qradar_log_sources s JOIN qradar_log_source_types t
			ON t.log_source_type_id = s.log_source_type_id WHERE t.domain_id = ?`, domainID).Scan(&n)
	case "qids":
		err = q.QueryRow(`SELECT COUNT(*) FROM qradar_qids q JOIN qradar_log_sources s ON s.log_source_id = q.log_source_id
			JOIN qradar_log_source_types t ON t.log_source_type_id = s.log_source_type_id WHERE t.domain_id = ?`, domainID).Scan(&n)
	case "field_definitions":
		err = q.QueryRow(`SELECT COUNT(*) FROM qradar_field_definitions WHERE client_id = ? AND domain_id = ?`, clientID, domainID).Scan(&n)
	case "field_mappings":
		err = q.QueryRow(`SELECT COUNT(*) FROM qradar_field_mappings WHERE client_id = ? AND domain_id = ?`, clientID, domainID).Scan(&n)
	}
	return n, err
}

// commitInventoryImport re-validates inside the transaction and inserts only
// CREATE rows. Exact duplicates are skipped, conflicts refuse the whole import.
func commitInventoryImport(userID string, req InventoryImportRequest) (*InventoryImportPreview, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if err := requireFieldCapability(userID, CanImportFieldIntel); err != nil {
		return nil, ErrFieldAccessDenied
	}
	if !req.Confirm {
		return nil, fmt.Errorf("%w: explicit confirmation is required", ErrFieldImportInvalid)
	}
	if err := requireInventoryScope(userID, req.ClientID, req.DomainID); err != nil {
		return nil, err
	}
	tx, err := globalDB.Begin()
	if err != nil {
		return nil, err
	}
	preview, err := buildInventoryPreview(tx, req)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if preview.Summary["conflict"] > 0 || preview.Summary["error"] > 0 {
		_ = tx.Rollback()
		return preview, fmt.Errorf("%w: import has conflicts or errors; nothing was written", ErrFieldConflict)
	}
	created := 0
	for _, row := range preview.Rows {
		if row.Status != "CREATE" {
			continue
		}
		if err := insertInventoryRow(tx, userID, req, preview.ContentSHA256, row.Fields); err != nil {
			_ = tx.Rollback()
			return nil, fmt.Errorf("%w: %v", ErrFieldImportInvalid, err)
		}
		created++
	}
	if err := auditInTx(tx, userID, req.ClientID, "INVENTORY_IMPORT", req.DomainID,
		fmt.Sprintf("%s created=%d", preview.Kind, created)); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	preview.Summary["created"] = created
	return preview, nil
}

func importSourceReference(req InventoryImportRequest, contentHash string) string {
	source := strings.TrimSpace(req.DeclaredSource)
	if source == "" {
		source = "operator export"
	}
	return source + " | sha256:" + contentHash
}

func insertInventoryRow(tx *sql.Tx, userID string, req InventoryImportRequest, contentHash string, f map[string]string) error {
	ref := importSourceReference(req, contentHash)
	version := f["mapping_version"]
	if version == "" {
		version = "1"
	}
	switch strings.ToLower(req.Kind) {
	case "log_source_types":
		_, err := tx.Exec(`INSERT INTO qradar_log_source_types
			(log_source_type_id, domain_id, type_name, created_at, source_category, source_reference, entered_by, entered_at, revision)
			VALUES (?, ?, ?, datetime('now'), 'IMPORTED_UNVERIFIED', ?, ?, datetime('now'), 1)`,
			newID("qlst"), req.DomainID, f["type_name"], ref, userID)
		return err
	case "log_sources":
		status := f["status"]
		if status == "" {
			status = "UNKNOWN"
		}
		_, err := tx.Exec(`INSERT INTO qradar_log_sources
			(log_source_id, log_source_type_id, status, data_provenance, created_at, source_category, source_reference, entered_by, entered_at, revision)
			SELECT ?, log_source_type_id, ?, ?, datetime('now'), 'IMPORTED_UNVERIFIED', ?, ?, datetime('now'), 1
			FROM qradar_log_source_types WHERE domain_id = ? AND LOWER(type_name) = LOWER(?)`,
			newID("qls"), status, f["data_provenance"], ref, userID, req.DomainID, f["type_name"])
		return err
	case "qids":
		_, err := tx.Exec(`INSERT INTO qradar_qids
			(qid, log_source_id, event_name, native_event_id, created_at, source_category, source_reference, entered_by, entered_at, revision)
			SELECT ?, s.log_source_id, ?, ?, datetime('now'), 'IMPORTED_UNVERIFIED', ?, ?, datetime('now'), 1
			FROM qradar_log_sources s JOIN qradar_log_source_types t ON t.log_source_type_id = s.log_source_type_id
			WHERE t.domain_id = ? AND LOWER(t.type_name) = LOWER(?) ORDER BY s.created_at LIMIT 1`,
			newID("qid"), f["event_name"], f["native_event_id"], ref, userID, req.DomainID, f["type_name"])
		return err
	case "field_definitions":
		origin := f["field_origin"]
		if origin == "" {
			origin = "raw_only"
		}
		_, err := tx.Exec(`INSERT INTO qradar_field_definitions
			(field_id, client_id, domain_id, field_name, field_origin, data_type, cep_identifier,
			 supported_event_scope, aql_field_expression, created_at, source_category, source_reference, entered_by, entered_at, revision)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), 'IMPORTED_UNVERIFIED', ?, ?, datetime('now'), 1)`,
			newID("qfd"), req.ClientID, req.DomainID, f["field_name"], origin, f["data_type"],
			f["cep_identifier"], f["supported_event_scope"], f["aql_field_expression"], ref, userID)
		return err
	case "field_mappings":
		_, err := tx.Exec(`INSERT INTO qradar_field_mappings
			(mapping_id, client_id, domain_id, raw_source_field, target_cep_field, semantic_alias,
			 applicable_dsm, applicable_event, mapping_version, origin, created_at,
			 source_category, source_reference, entered_by, entered_at, revision)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'imported', datetime('now'),
			 'IMPORTED_UNVERIFIED', ?, ?, datetime('now'), 1)`,
			newID("qfm"), req.ClientID, req.DomainID, f["raw_source_field"], f["target_cep_field"],
			f["semantic_alias"], f["applicable_dsm"], f["applicable_event"], version, ref, userID)
		return err
	}
	return fmt.Errorf("unsupported kind")
}

// InventoryImportTemplate returns a CSV template with a header and one example.
func InventoryImportTemplate(kind string) (string, error) {
	k, ok := inventoryKinds[strings.ToLower(strings.TrimSpace(kind))]
	if !ok {
		return "", fmt.Errorf("%w: unsupported inventory kind", ErrFieldImportInvalid)
	}
	example := map[string]map[string]string{
		"log_source_types":  {},
		"log_sources":       {"status": "UNKNOWN"},
		"qids":              {},
		"field_definitions": {"field_origin": "raw_only"},
		"field_mappings":    {"mapping_version": "1"},
	}
	row := make([]string, len(k.Columns))
	for i, c := range k.Columns {
		if v, ok := example[strings.ToLower(kind)][c]; ok {
			row[i] = v
		} else if strings.Contains(c, "name") || c == "raw_source_field" || c == "target_cep_field" {
			row[i] = "example_" + c
		}
	}
	var b strings.Builder
	w := csv.NewWriter(&b)
	_ = w.Write(k.Columns)
	_ = w.Write(row)
	w.Flush()
	return b.String(), nil
}

// InventoryCompleteness reports which manual evidence exists. It is not a
// coverage score and does not imply live telemetry.
type InventoryArea struct {
	Entity string `json:"entity"`
	Status string `json:"status"`
	Count  int    `json:"count"`
	Detail string `json:"detail,omitempty"`
}

type InventoryDomainCompleteness struct {
	DomainID        string          `json:"domain_id"`
	DomainName      string          `json:"domain_name"`
	InstanceID      string          `json:"instance_id"`
	ClientID        string          `json:"client_id"`
	NativeDomainID  string          `json:"native_qradar_domain_id,omitempty"`
	BindingStatus   string          `json:"binding_status"`
	BindingRevision int             `json:"binding_revision"`
	Areas           []InventoryArea `json:"areas"`
}

type InventoryCompleteness struct {
	ClientID string                       `json:"client_id"`
	Domains  []InventoryDomainCompleteness `json:"domains"`
	Notes    []string                     `json:"notes"`
}

func InventoryCompletenessReport(userID, clientID string) (*InventoryCompleteness, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if !hasClientGrant(userID, clientID) {
		return nil, ErrFieldAccessDenied
	}
	rows, err := globalDB.Query(`SELECT b.domain_id, d.domain_name, b.instance_id,
			COALESCE(d.native_qradar_domain_id,''), b.verification_status, b.revision
		FROM qradar_domain_bindings b JOIN qradar_domains d ON d.domain_id = b.domain_id
		WHERE b.client_id = ? AND b.binding_kind = 'CLIENT'
		ORDER BY d.domain_name`, clientID)
	if err != nil {
		return nil, err
	}
	type dom struct {
		id, name, instance, native, verified string
		revision                             int
	}
	var doms []dom
	for rows.Next() {
		var d dom
		if err := rows.Scan(&d.id, &d.name, &d.instance, &d.native, &d.verified, &d.revision); err != nil {
			rows.Close()
			return nil, err
		}
		doms = append(doms, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := &InventoryCompleteness{ClientID: clientID}
	out.Notes = append(out.Notes,
		"Quantities describe manually entered evidence, not live QRadar telemetry or detection coverage.",
		"An unverified binding or native Domain ID blocks readiness regardless of imported metadata.")
	for _, d := range doms {
		dc := InventoryDomainCompleteness{
			DomainID: d.id, DomainName: d.name, InstanceID: d.instance, ClientID: clientID,
			NativeDomainID: d.native, BindingStatus: d.verified, BindingRevision: d.revision,
		}
		dc.Areas = inventoryAreas(clientID, d.id, d.verified, d.native)
		out.Domains = append(out.Domains, dc)
	}
	sort.Slice(out.Domains, func(i, j int) bool { return out.Domains[i].DomainName < out.Domains[j].DomainName })
	return out, nil
}

func inventoryAreas(clientID, domainID, bindingStatus, nativeID string) []InventoryArea {
	var areas []InventoryArea
	bind := InventoryArea{Entity: "domain_binding", Status: "MISSING", Detail: "binding is not verified"}
	if bindingStatus == "VERIFIED" {
		bind = InventoryArea{Entity: "domain_binding", Status: "MANUALLY_ENTERED", Count: 1, Detail: "verified by a human reviewer"}
	}
	areas = append(areas, bind)
	native := InventoryArea{Entity: "native_domain_id", Status: "MISSING", Detail: "native Domain ID is not verified"}
	if nativeID != "" {
		native = InventoryArea{Entity: "native_domain_id", Status: "MANUALLY_ENTERED", Count: 1, Detail: nativeID}
	}
	areas = append(areas, native)

	count := func(q string, args ...interface{}) int {
		var n int
		_ = globalDB.QueryRow(q, args...).Scan(&n)
		return n
	}
	imported := func(q string, args ...interface{}) int {
		var n int
		_ = globalDB.QueryRow(q, args...).Scan(&n)
		return n
	}
	areaFor := func(entity, totalQ, importedQ string, args ...interface{}) InventoryArea {
		total := count(totalQ, args...)
		imp := imported(importedQ, args...)
		switch {
		case total == 0:
			return InventoryArea{Entity: entity, Status: "MISSING", Count: 0, Detail: "no manual entries"}
		case imp > 0:
			return InventoryArea{Entity: entity, Status: "IMPORTED_UNVERIFIED", Count: total, Detail: fmt.Sprintf("%d imported, not reviewed", imp)}
		default:
			return InventoryArea{Entity: entity, Status: "MANUALLY_ENTERED", Count: total}
		}
	}
	areas = append(areas,
		areaFor("log_source_types",
			`SELECT COUNT(*) FROM qradar_log_source_types WHERE domain_id = ?`,
			`SELECT COUNT(*) FROM qradar_log_source_types WHERE domain_id = ? AND source_category = 'IMPORTED_UNVERIFIED'`, domainID),
		areaFor("log_sources",
			`SELECT COUNT(*) FROM qradar_log_sources s JOIN qradar_log_source_types t ON t.log_source_type_id = s.log_source_type_id WHERE t.domain_id = ?`,
			`SELECT COUNT(*) FROM qradar_log_sources s JOIN qradar_log_source_types t ON t.log_source_type_id = s.log_source_type_id WHERE t.domain_id = ? AND s.source_category = 'IMPORTED_UNVERIFIED'`, domainID),
		areaFor("qids",
			`SELECT COUNT(*) FROM qradar_qids q JOIN qradar_log_sources s ON s.log_source_id = q.log_source_id
			 JOIN qradar_log_source_types t ON t.log_source_type_id = s.log_source_type_id WHERE t.domain_id = ?`,
			`SELECT COUNT(*) FROM qradar_qids q JOIN qradar_log_sources s ON s.log_source_id = q.log_source_id
			 JOIN qradar_log_source_types t ON t.log_source_type_id = s.log_source_type_id WHERE t.domain_id = ? AND q.source_category = 'IMPORTED_UNVERIFIED'`, domainID),
		areaFor("field_definitions",
			`SELECT COUNT(*) FROM qradar_field_definitions WHERE client_id = ? AND domain_id = ?`,
			`SELECT COUNT(*) FROM qradar_field_definitions WHERE client_id = ? AND domain_id = ? AND source_category = 'IMPORTED_UNVERIFIED'`, clientID, domainID),
	)

	// Mapping evidence: approved, conflicting or stale.
	var totalMappings, approvedMappings, importedMappings, ambiguous, stale int
	_ = globalDB.QueryRow(`SELECT COUNT(*) FROM qradar_field_mappings WHERE client_id = ? AND domain_id = ?`, clientID, domainID).Scan(&totalMappings)
	_ = globalDB.QueryRow(`SELECT COUNT(*) FROM qradar_field_mappings WHERE client_id = ? AND domain_id = ? AND COALESCE(approved_by,'') <> ''`, clientID, domainID).Scan(&approvedMappings)
	_ = globalDB.QueryRow(`SELECT COUNT(*) FROM qradar_field_mappings WHERE client_id = ? AND domain_id = ? AND source_category = 'IMPORTED_UNVERIFIED' AND COALESCE(approved_by,'') = ''`, clientID, domainID).Scan(&importedMappings)
	_ = globalDB.QueryRow(`SELECT COUNT(*) FROM (
		SELECT raw_source_field FROM qradar_field_mappings
		WHERE client_id = ? AND domain_id = ? AND COALESCE(approved_by,'') <> ''
		GROUP BY LOWER(raw_source_field) HAVING COUNT(DISTINCT target_cep_field) > 1)`, clientID, domainID).Scan(&ambiguous)
	_ = globalDB.QueryRow(`SELECT COUNT(*) FROM qradar_field_mappings m
		WHERE m.client_id = ? AND m.domain_id = ? AND COALESCE(m.approved_by,'') <> ''
		  AND EXISTS (SELECT 1 FROM qradar_field_mappings n
		              WHERE n.client_id = m.client_id AND n.domain_id = m.domain_id
		                AND LOWER(n.raw_source_field) = LOWER(m.raw_source_field)
		                AND CAST(n.mapping_version AS INTEGER) > CAST(m.mapping_version AS INTEGER))`,
		clientID, domainID).Scan(&stale)
	switch {
	case totalMappings == 0:
		areas = append(areas, InventoryArea{Entity: "field_mappings", Status: "MISSING", Detail: "no candidate mappings"})
	case ambiguous > 0:
		areas = append(areas, InventoryArea{Entity: "field_mappings", Status: "CONFLICTING", Count: totalMappings, Detail: "multiple approved CEP targets for one raw field"})
	case stale > 0:
		areas = append(areas, InventoryArea{Entity: "field_mappings", Status: "STALE", Count: totalMappings, Detail: "an approved mapping is superseded by a newer version"})
	case approvedMappings > 0 && importedMappings == 0:
		areas = append(areas, InventoryArea{Entity: "field_mappings", Status: "APPROVED_MAPPING", Count: approvedMappings})
	default:
		areas = append(areas, InventoryArea{Entity: "field_mappings", Status: "IMPORTED_UNVERIFIED", Count: importedMappings, Detail: "candidate mappings await review"})
	}

	var attested int
	_ = globalDB.QueryRow(`SELECT COUNT(*) FROM qradar_field_observations
		WHERE client_id = ? AND domain_id = ? AND aql_verification_status = 'VERIFIED'`, clientID, domainID).Scan(&attested)
	if attested > 0 {
		areas = append(areas, InventoryArea{Entity: "field_attestation", Status: "AQL_MANUALLY_ATTESTED", Count: attested})
	} else {
		areas = append(areas, InventoryArea{Entity: "field_attestation", Status: "MISSING", Detail: "no reviewer-attested AQL field evidence"})
	}
	return areas
}
