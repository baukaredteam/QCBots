package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// --- YAML struct definitions ---

type RuleYAML struct {
	RuleID                  string              `yaml:"rule_id"`
	RuleName                string              `yaml:"rule_name"`
	Enabled                 bool                `yaml:"enabled"`
	CreatedDate             string              `yaml:"created_date"`
	ModifiedDate            string              `yaml:"modified_date"`
	EventCount30d           int                 `yaml:"event_count_30d"`
	OffenseCount30d         int                 `yaml:"offense_count_30d"`
	LogSource               string              `yaml:"log_source"`
	Criticality             string              `yaml:"criticality"`
	MitreTechniques         []string            `yaml:"mitre_techniques"`
	SysmonRequired          bool                `yaml:"sysmon_required"`
	FullRuleLogic           string              `yaml:"full_rule_logic"`
	BuildingBlocks          []BuildingBlockYAML `yaml:"building_blocks"`
	EffectiveDetectionLogic string              `yaml:"effective_detection_logic"`
	BBChainSummary          string              `yaml:"bb_chain_summary"`
	CustomFields            []FieldYAML         `yaml:"custom_fields"`
	ReferenceSetsUsed       []string            `yaml:"reference_sets_used"`
}

type BuildingBlockYAML struct {
	BBID          string   `yaml:"bb_id" json:"bb_id"`
	BBName        string   `yaml:"bb_name" json:"bb_name"`
	Level         int      `yaml:"level" json:"level"`
	Category      string   `yaml:"category" json:"category"`
	DependsOnBB   []string `yaml:"depends_on_bb" json:"depends_on_bb"`
	OwnConditions string   `yaml:"own_conditions" json:"own_conditions"`
	FullBBLogic   string   `yaml:"full_bb_logic" json:"full_bb_logic"`
	Notes         string   `yaml:"notes" json:"notes"`
}

type FieldYAML struct {
	Name             string   `yaml:"name" json:"name"`
	InternalName     string   `yaml:"internal_name" json:"internal_name"`
	DisplayName      string   `yaml:"display_name" json:"display_name"`
	DataType         string   `yaml:"data_type" json:"data_type"`
	LogSources       []string `yaml:"log_sources" json:"log_sources"`
	Availability     string   `yaml:"availability" json:"availability"`
	AdversaryControl string   `yaml:"adversary_control" json:"adversary_control"`
	UsedInEvents     []string `yaml:"used_in_events" json:"used_in_events"`
	EventIDContext   string   `yaml:"event_id_context" json:"event_id_context"`
	Notes            string   `yaml:"notes" json:"notes"`
}

// --- QRadar DB structs ---

type QRadarRule struct {
	RuleID                  string              `json:"rule_id"`
	RuleName                string              `json:"rule_name"`
	Enabled                 bool                `json:"enabled"`
	CreatedDate             string              `json:"created_date"`
	ModifiedDate            string              `json:"modified_date"`
	EventCount30d           int                 `json:"event_count_30d"`
	OffenseCount30d         int                 `json:"offense_count_30d"`
	LogSource               string              `json:"log_source"`
	Criticality             string              `json:"criticality"`
	MitreTechniques         []string            `json:"mitre_techniques"`
	SysmonRequired          bool                `json:"sysmon_required"`
	FullRuleLogic           string              `json:"full_rule_logic"`
	EffectiveDetectionLogic string              `json:"effective_detection_logic"`
	BBChainSummary          string              `json:"bb_chain_summary"`
	CustomFields            []FieldYAML         `json:"custom_fields"`
	ReferenceSetsUsed       []string            `json:"reference_sets_used"`
	BuildingBlocks          []BuildingBlockYAML `json:"building_blocks"`
}

// --- Schema ensure ---

func ensureQRadarSchema(db *DB) error {
	return ensureQRadarSchemaSQL(db.DB)
}

func ensureQRadarSchemaSQL(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS detection_rules (
			rule_id TEXT PRIMARY KEY,
			rule_name TEXT NOT NULL,
			rule_description TEXT,
			rule_type TEXT,
			mitre_tactics TEXT,
			mitre_techniques TEXT,
			required_fields TEXT,
			required_log_sources TEXT,
			rule_status TEXT,
			rule_version TEXT,
			last_updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			criticality TEXT,
			log_source TEXT,
			enabled INTEGER NOT NULL DEFAULT 0,
			sysmon_required INTEGER NOT NULL DEFAULT 0,
			full_rule_logic TEXT,
			effective_detection_logic TEXT,
			bb_chain_summary TEXT,
			custom_fields TEXT,
			building_blocks TEXT,
			reference_sets_used TEXT,
			event_count_30d INTEGER NOT NULL DEFAULT 0,
			offense_count_30d INTEGER NOT NULL DEFAULT 0,
			created_date TEXT,
			modified_date TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS building_blocks (
			bb_id TEXT PRIMARY KEY,
			bb_name TEXT NOT NULL,
			level INTEGER,
			category TEXT,
			depends_on_bb TEXT,
			own_conditions TEXT,
			full_bb_logic TEXT,
			adversary_control TEXT,
			availability TEXT,
			sysmon_required INTEGER NOT NULL DEFAULT 0,
			notes TEXT,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS rule_building_blocks (
			rule_id TEXT NOT NULL REFERENCES detection_rules(rule_id),
			bb_id TEXT NOT NULL REFERENCES building_blocks(bb_id),
			PRIMARY KEY (rule_id, bb_id)
		)`,
		`CREATE TABLE IF NOT EXISTS global_fields (
			field_id TEXT PRIMARY KEY,
			field_name TEXT NOT NULL,
			field_type TEXT NOT NULL,
			field_description TEXT,
			source_type TEXT,
			normalized_name TEXT,
			aliases TEXT,
			is_active INTEGER NOT NULL DEFAULT 1,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			availability TEXT,
			log_sources TEXT,
			adversary_control TEXT,
			display_name TEXT,
			used_in_events TEXT
		)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("creating qradar table: %w", err)
		}
	}
	// Ensure columns on pre-existing tables
	cols := []struct{ table, column, def string }{
		{"detection_rules", "criticality", "TEXT"},
		{"detection_rules", "log_source", "TEXT"},
		{"detection_rules", "enabled", "INTEGER NOT NULL DEFAULT 0"},
		{"detection_rules", "sysmon_required", "INTEGER NOT NULL DEFAULT 0"},
		{"detection_rules", "full_rule_logic", "TEXT"},
		{"detection_rules", "effective_detection_logic", "TEXT"},
		{"detection_rules", "bb_chain_summary", "TEXT"},
		{"detection_rules", "custom_fields", "TEXT"},
		{"detection_rules", "building_blocks", "TEXT"},
		{"detection_rules", "reference_sets_used", "TEXT"},
		{"detection_rules", "event_count_30d", "INTEGER NOT NULL DEFAULT 0"},
		{"detection_rules", "offense_count_30d", "INTEGER NOT NULL DEFAULT 0"},
		{"detection_rules", "created_date", "TEXT"},
		{"detection_rules", "modified_date", "TEXT"},
		{"global_fields", "availability", "TEXT"},
		{"global_fields", "log_sources", "TEXT"},
		{"global_fields", "adversary_control", "TEXT"},
		{"global_fields", "display_name", "TEXT"},
		{"global_fields", "used_in_events", "TEXT"},
		{"building_blocks", "adversary_control", "TEXT"},
		{"building_blocks", "availability", "TEXT"},
		{"building_blocks", "sysmon_required", "INTEGER NOT NULL DEFAULT 0"},
		{"building_blocks", "log_sources", "TEXT"},
	}
	for _, c := range cols {
		if err := ensureColumnSQL(db, c.table, c.column, c.def); err != nil {
			return err
		}
	}
	return nil
}

// ensureColumnSQL adds column if missing. Single PRAGMA query, closed before any
// Exec — critical under SetMaxOpenConns(1). No ALTER TABLE on check failure.

// qradarColumnDefs is the single registry table -> column -> expected SQL definition.
// ensureColumnSQL validates (table, column, def) against this registry and rejects
// wrong pairs and wrong types instead of building ALTER TABLE from caller strings.
//
// Technical debt (not refactored here): column-ensuring pairs are listed twice —
// in ensureQRadarSchemaSQL's cols table and in qradarColumnDefs below. They must
// stay in sync; the registry is the validation source of truth.
var qradarColumnDefs = map[string]map[string]string{
	"detection_rules": {
		"criticality": "TEXT", "log_source": "TEXT",
		"enabled": "INTEGER NOT NULL DEFAULT 0", "sysmon_required": "INTEGER NOT NULL DEFAULT 0",
		"full_rule_logic": "TEXT", "effective_detection_logic": "TEXT",
		"bb_chain_summary": "TEXT", "custom_fields": "TEXT",
		"building_blocks": "TEXT", "reference_sets_used": "TEXT",
		"event_count_30d": "INTEGER NOT NULL DEFAULT 0", "offense_count_30d": "INTEGER NOT NULL DEFAULT 0",
		"created_date": "TEXT", "modified_date": "TEXT",
	},
	"global_fields": {
		"availability": "TEXT", "log_sources": "TEXT",
		"adversary_control": "TEXT", "display_name": "TEXT",
		"used_in_events": "TEXT",
	},
	"building_blocks": {
		"adversary_control": "TEXT", "availability": "TEXT",
		"sysmon_required": "INTEGER NOT NULL DEFAULT 0", "log_sources": "TEXT",
	},
}

func ensureColumnSQL(db *sql.DB, table, column, def string) error {
	cols, ok := qradarColumnDefs[table]
	if !ok {
		return fmt.Errorf("ensureColumnSQL: invalid table %q", table)
	}
	wantDef, ok := cols[column]
	if !ok {
		return fmt.Errorf("ensureColumnSQL: column %q not registered for table %q", column, table)
	}
	if def != wantDef {
		return fmt.Errorf("ensureColumnSQL: wrong definition for %s.%s: got %q, want %q", table, column, def, wantDef)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return fmt.Errorf("ensureColumnSQL check %s.%s: %w", table, column, err)
	}
	exists := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return fmt.Errorf("ensureColumnSQL scan %s.%s: %w", table, column, err)
		}
		if name == column {
			exists = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("ensureColumnSQL rows %s.%s: %w", table, column, err)
	}
	// Close BEFORE any Exec: required with MaxOpenConns(1).
	if err := rows.Close(); err != nil {
		return fmt.Errorf("ensureColumnSQL close %s.%s: %w", table, column, err)
	}
	if exists {
		return nil
	}
	if _, err := db.ExecContext(ctx, "ALTER TABLE "+table+" ADD COLUMN "+column+" "+def); err != nil {
		// Concurrent ensure* calls can race to the same ALTER on MaxOpenConns(1).
		// Column now exists -> idempotent success.
		if strings.Contains(err.Error(), "duplicate column") {
			var n int
			if err2 := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?", table, column).Scan(&n); err2 == nil && n >= 1 {
				return nil
			}
		}
		return fmt.Errorf("ensureColumnSQL alter %s.%s: %w", table, column, err)
	}
	return nil
}

// --- Importers ---

func ImportQRadarRules(db *DB, filePath string) error {
	if err := ensureQRadarSchema(db); err != nil {
		return err
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading rules file: %w", err)
	}
	var doc struct {
		Rules []RuleYAML `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parsing rules yaml: %w", err)
	}
	for _, r := range doc.Rules {
		mitreJSON, _ := json.Marshal(r.MitreTechniques)
		customJSON, _ := json.Marshal(r.CustomFields)
		bbJSON, _ := json.Marshal(r.BuildingBlocks)
		refJSON, _ := json.Marshal(r.ReferenceSetsUsed)
		status := "disabled"
		if r.Enabled {
			status = "enabled"
		}
		version := r.ModifiedDate
		if version == "" {
			version = r.CreatedDate
		}
		lastUpdated := r.ModifiedDate
		if lastUpdated == "" {
			lastUpdated = r.CreatedDate
		}
		if lastUpdated == "" {
			lastUpdated = "CURRENT_TIMESTAMP"
		}
		_, err := db.Exec(`INSERT INTO detection_rules (
			rule_id, rule_name, rule_description, rule_type, mitre_tactics, mitre_techniques,
			required_fields, required_log_sources, rule_status, rule_version, last_updated,
			criticality, log_source, enabled, sysmon_required, full_rule_logic,
			effective_detection_logic, bb_chain_summary, custom_fields, building_blocks,
			reference_sets_used, event_count_30d, offense_count_30d, created_date, modified_date
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(rule_id) DO UPDATE SET
			rule_name=excluded.rule_name,
			rule_description=excluded.rule_description,
			mitre_techniques=excluded.mitre_techniques,
			rule_status=excluded.rule_status,
			rule_version=excluded.rule_version,
			last_updated=excluded.last_updated,
			criticality=excluded.criticality,
			log_source=excluded.log_source,
			enabled=excluded.enabled,
			sysmon_required=excluded.sysmon_required,
			full_rule_logic=excluded.full_rule_logic,
			effective_detection_logic=excluded.effective_detection_logic,
			bb_chain_summary=excluded.bb_chain_summary,
			custom_fields=excluded.custom_fields,
			building_blocks=excluded.building_blocks,
			reference_sets_used=excluded.reference_sets_used,
			event_count_30d=excluded.event_count_30d,
			offense_count_30d=excluded.offense_count_30d,
			created_date=excluded.created_date,
			modified_date=excluded.modified_date`,
			r.RuleID, r.RuleName, r.BBChainSummary, "detection_rule",
			"", string(mitreJSON), string(customJSON), r.LogSource, status, version, lastUpdated,
			r.Criticality, r.LogSource, boolToInt(r.Enabled), boolToInt(r.SysmonRequired), r.FullRuleLogic,
			r.EffectiveDetectionLogic, r.BBChainSummary, string(customJSON), string(bbJSON),
			string(refJSON), r.EventCount30d, r.OffenseCount30d, r.CreatedDate, r.ModifiedDate)
		if err != nil {
			return fmt.Errorf("inserting rule %s: %w", r.RuleID, err)
		}
		// upsert building blocks
		for _, bb := range r.BuildingBlocks {
			if err := upsertBuildingBlock(db, bb); err != nil {
				return err
			}
			db.Exec(`INSERT OR IGNORE INTO rule_building_blocks (rule_id, bb_id) VALUES (?, ?)`, r.RuleID, bb.BBID)
		}
	}
	return nil
}

func ImportSharedBBs(db *DB, filePath string) error {
	if err := ensureQRadarSchema(db); err != nil {
		return err
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading shared bbs file: %w", err)
	}
	var doc struct {
		SharedBuildingBlocks []BuildingBlockYAML `yaml:"shared_building_blocks"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parsing shared bbs yaml: %w", err)
	}
	for _, bb := range doc.SharedBuildingBlocks {
		if err := upsertBuildingBlock(db, bb); err != nil {
			return err
		}
	}
	return nil
}

func ImportCustomFields(db *DB, filePath string) error {
	if err := ensureQRadarSchema(db); err != nil {
		return err
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading fields file: %w", err)
	}
	var doc struct {
		CustomFields []FieldYAML `yaml:"custom_fields"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parsing fields yaml: %w", err)
	}
	for _, f := range doc.CustomFields {
		logSourcesJSON, _ := json.Marshal(f.LogSources)
		usedEventsJSON, _ := json.Marshal(f.UsedInEvents)
		fieldID := f.Name
		if f.InternalName != "" {
			fieldID = f.InternalName
		}
		sourceType := ""
		if len(f.LogSources) > 0 {
			sourceType = f.LogSources[0]
		}
		_, err := db.Exec(`INSERT INTO global_fields (
			field_id, field_name, field_type, field_description, source_type, normalized_name, aliases,
			is_active, availability, log_sources, adversary_control, display_name, used_in_events
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(field_id) DO UPDATE SET
			field_name=excluded.field_name,
			field_type=excluded.field_type,
			field_description=excluded.field_description,
			source_type=excluded.source_type,
			normalized_name=excluded.normalized_name,
			aliases=excluded.aliases,
			is_active=excluded.is_active,
			availability=excluded.availability,
			log_sources=excluded.log_sources,
			adversary_control=excluded.adversary_control,
			display_name=excluded.display_name,
			used_in_events=excluded.used_in_events`,
			fieldID, f.Name, defaultStr(f.DataType, "string"), f.Notes, sourceType, f.InternalName, f.DisplayName,
			1, f.Availability, string(logSourcesJSON), f.AdversaryControl, f.DisplayName, string(usedEventsJSON))
		if err != nil {
			return fmt.Errorf("inserting field %s: %w", f.Name, err)
		}
	}
	return nil
}

func upsertBuildingBlock(db *DB, bb BuildingBlockYAML) error {
	depsJSON, _ := json.Marshal(bb.DependsOnBB)
	_, err := db.Exec(`INSERT INTO building_blocks (
		bb_id, bb_name, level, category, depends_on_bb, own_conditions, full_bb_logic, notes
	) VALUES (?,?,?,?,?,?,?,?)
	ON CONFLICT(bb_id) DO UPDATE SET
		bb_name=excluded.bb_name,
		level=excluded.level,
		category=excluded.category,
		depends_on_bb=excluded.depends_on_bb,
		own_conditions=excluded.own_conditions,
		full_bb_logic=excluded.full_bb_logic,
		notes=excluded.notes,
		updated_at=CURRENT_TIMESTAMP`,
		bb.BBID, bb.BBName, bb.Level, bb.Category, string(depsJSON), bb.OwnConditions, bb.FullBBLogic, bb.Notes)
	if err != nil {
		return fmt.Errorf("inserting building block %s: %w", bb.BBID, err)
	}
	return nil
}

// --- DB list/get helpers ---

func (db *DB) ListQRadarRules(criticality, logSource, mitreTechnique string) ([]QRadarRule, error) {
	if err := ensureQRadarSchema(db); err != nil {
		return nil, err
	}
	query := `SELECT rule_id, rule_name, enabled, created_date, modified_date, event_count_30d, offense_count_30d, log_source, criticality, mitre_techniques, sysmon_required, full_rule_logic, effective_detection_logic, bb_chain_summary, custom_fields, building_blocks, reference_sets_used FROM detection_rules WHERE 1=1`
	args := []interface{}{}
	if criticality != "" {
		query += " AND criticality = ?"
		args = append(args, criticality)
	}
	if logSource != "" {
		query += " AND log_source = ?"
		args = append(args, logSource)
	}
	if mitreTechnique != "" {
		query += " AND mitre_techniques LIKE ?"
		args = append(args, "%"+mitreTechnique+"%")
	}
	query += " ORDER BY rule_name"
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []QRadarRule
	for rows.Next() {
		var r QRadarRule
		var enabled, sysmon int
		var mitre, custom, bb, ref sql.NullString
		var logSrc, crit, created, modified sql.NullString
		var fullLogic, effLogic, bbChain sql.NullString
		var eventCount, offenseCount sql.NullInt64
		if err := rows.Scan(&r.RuleID, &r.RuleName, &enabled, &created, &modified,
			&eventCount, &offenseCount, &logSrc, &crit, &mitre, &sysmon, &fullLogic,
			&effLogic, &bbChain, &custom, &bb, &ref); err != nil {
			return nil, err
		}
		r.Enabled = enabled == 1
		r.SysmonRequired = sysmon == 1
		if created.Valid {
			r.CreatedDate = created.String
		}
		if modified.Valid {
			r.ModifiedDate = modified.String
		}
		if eventCount.Valid {
			r.EventCount30d = int(eventCount.Int64)
		}
		if offenseCount.Valid {
			r.OffenseCount30d = int(offenseCount.Int64)
		}
		if logSrc.Valid {
			r.LogSource = logSrc.String
		}
		if crit.Valid {
			r.Criticality = crit.String
		}
		if mitre.Valid && mitre.String != "" {
			json.Unmarshal([]byte(mitre.String), &r.MitreTechniques)
		}
		if fullLogic.Valid {
			r.FullRuleLogic = fullLogic.String
		}
		if effLogic.Valid {
			r.EffectiveDetectionLogic = effLogic.String
		}
		if bbChain.Valid {
			r.BBChainSummary = bbChain.String
		}
		if custom.Valid && custom.String != "" {
			json.Unmarshal([]byte(custom.String), &r.CustomFields)
		}
		if bb.Valid && bb.String != "" {
			json.Unmarshal([]byte(bb.String), &r.BuildingBlocks)
		}
		if ref.Valid && ref.String != "" {
			json.Unmarshal([]byte(ref.String), &r.ReferenceSetsUsed)
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func (db *DB) GetQRadarRule(ruleID string) (*QRadarRule, error) {
	rules, err := db.ListQRadarRules("", "", "")
	if err != nil {
		return nil, err
	}
	for i := range rules {
		if rules[i].RuleID == ruleID {
			return &rules[i], nil
		}
	}
	// fallback direct query
	if err := ensureQRadarSchema(db); err != nil {
		return nil, err
	}
	row := db.QueryRow(`SELECT rule_id, rule_name, enabled, created_date, modified_date, event_count_30d, offense_count_30d, log_source, criticality, mitre_techniques, sysmon_required, full_rule_logic, effective_detection_logic, bb_chain_summary, custom_fields, building_blocks, reference_sets_used FROM detection_rules WHERE rule_id = ?`, ruleID)
	var r QRadarRule
	var enabled, sysmon int
	var mitre, custom, bb, ref sql.NullString
	var logSrc, crit, created, modified sql.NullString
	var fullLogic, effLogic, bbChain sql.NullString
	var eventCount, offenseCount sql.NullInt64
	if err := row.Scan(&r.RuleID, &r.RuleName, &enabled, &created, &modified,
		&eventCount, &offenseCount, &logSrc, &crit, &mitre, &sysmon, &fullLogic,
		&effLogic, &bbChain, &custom, &bb, &ref); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	r.Enabled = enabled == 1
	r.SysmonRequired = sysmon == 1
	if created.Valid {
		r.CreatedDate = created.String
	}
	if modified.Valid {
		r.ModifiedDate = modified.String
	}
	if eventCount.Valid {
		r.EventCount30d = int(eventCount.Int64)
	}
	if offenseCount.Valid {
		r.OffenseCount30d = int(offenseCount.Int64)
	}
	if logSrc.Valid {
		r.LogSource = logSrc.String
	}
	if crit.Valid {
		r.Criticality = crit.String
	}
	if mitre.Valid && mitre.String != "" {
		json.Unmarshal([]byte(mitre.String), &r.MitreTechniques)
	}
	if fullLogic.Valid {
		r.FullRuleLogic = fullLogic.String
	}
	if effLogic.Valid {
		r.EffectiveDetectionLogic = effLogic.String
	}
	if bbChain.Valid {
		r.BBChainSummary = bbChain.String
	}
	if custom.Valid && custom.String != "" {
		json.Unmarshal([]byte(custom.String), &r.CustomFields)
	}
	if bb.Valid && bb.String != "" {
		json.Unmarshal([]byte(bb.String), &r.BuildingBlocks)
	}
	if ref.Valid && ref.String != "" {
		json.Unmarshal([]byte(ref.String), &r.ReferenceSetsUsed)
	}
	return &r, nil
}

func (db *DB) ListQRadarFields(availability, logSource string) ([]GlobalField, error) {
	if err := ensureQRadarSchema(db); err != nil {
		return nil, err
	}
	query := `SELECT field_id, field_name, field_type, field_description, source_type, normalized_name, aliases, is_active, created_at, availability, log_sources, adversary_control, display_name, used_in_events FROM global_fields WHERE 1=1`
	args := []interface{}{}
	if availability != "" {
		query += " AND availability = ?"
		args = append(args, availability)
	}
	if logSource != "" {
		query += " AND log_sources LIKE ?"
		args = append(args, "%"+logSource+"%")
	}
	query += " ORDER BY field_name"
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var fields []GlobalField
	for rows.Next() {
		var f GlobalField
		var isActive int
		var avail, logSrc, adv, disp, used sql.NullString
		if err := rows.Scan(&f.FieldID, &f.FieldName, &f.FieldType, &f.FieldDescription, &f.SourceType, &f.NormalizedName, &f.Aliases, &isActive, &f.CreatedAt, &avail, &logSrc, &adv, &disp, &used); err != nil {
			return nil, err
		}
		f.IsActive = isActive == 1
		if avail.Valid {
			f.Availability = avail.String
		}
		if logSrc.Valid {
			f.LogSources = logSrc.String
		}
		if adv.Valid {
			f.AdversaryControl = adv.String
		}
		if disp.Valid {
			f.DisplayName = disp.String
		}
		if used.Valid {
			f.UsedInEvents = used.String
		}
		fields = append(fields, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return fields, nil
}

// --- helpers ---

func defaultStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
