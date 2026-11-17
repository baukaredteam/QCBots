package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps sql.DB with application-specific helpers.
type DB struct {
	*sql.DB
}

// migrationSchemaExpectation lists schema markers a recorded migration must
// have fully left behind. The markers are the CONTRACT the database grew to
// after that migration; a recorded path with missing markers used to mean a
// partial/corrupted application and is now an explicit error, never a
// silent re-execution.
type migrationSchemaExpectation struct {
	name string // object name
}

var migrationAppliedExpectations = map[string][]migrationSchemaExpectation{
	"migrations/0010_hunt_hypothesis.sql": {
		{"hunt_hypothesis_versions"},
		{"hunt_hypothesis_version_events"},
		{"hunt_hypothesis_reviews"},
		{"hunt_hypothesis_evidence"},
		{"hunt_hypotheses"},
	},
}

// migrationSchemaMarkersArePresent reports whether every required marker
// object exists (table, view, trigger, or index) in sqlite_master.
func migrationSchemaMarkersArePresent(db *sql.DB, markers []migrationSchemaExpectation) bool {
	for _, m := range markers {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = ?`, m.name).Scan(&n); err != nil {
			return false
		}
		if n == 0 {
			return false
		}
	}
	return true
}

// OpenDB opens the SQLite database and runs migrations.
// Test seeding is gated behind WORKBENCH_SEED_DATA=true and never runs
// against the production/working DB by default.
func OpenDB(dbPath string) (*DB, error) {
	// Ensure storage directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating storage dir: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=1&_busy_timeout=30000&_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Verify connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}
	// Serialize all DB access through a single connection to avoid SQLite locking issues on Windows
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// Run schema migration
	if err := runMigration(db, "migrations/0001_initial.sql"); err != nil {
		db.Close()
		return nil, fmt.Errorf("running migration: %w", err)
	}

	// Run QRadar inventory migration
	if err := runMigration(db, "migrations/0002_qradar_inventory.sql"); err != nil {
		db.Close()
		return nil, fmt.Errorf("running migration 0002: %w", err)
	}

	// Create additional M1 tables
	if err := createM1Tables(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating M1 tables: %w", err)
	}

	// Seed test data only when explicitly requested (isolated test DBs).
	// The synthetic REVIEWER account must not appear in production SQLite.
	if os.Getenv("WORKBENCH_SEED_DATA") == "true" {
		if err := requireTestSeederEnv(); err != nil {
			db.Close()
			return nil, fmt.Errorf("refusing to seed synthetic users into a database: %w", err)
		}
		if err := seedTestData(db); err != nil {
			db.Close()
			return nil, fmt.Errorf("seeding test data: %w", err)
		}
	}
	return &DB{db}, nil
}

// runMigration executes a SQL migration file, trying multiple possible locations.
// All statements in a migration file are executed in a single transaction along
// with recording the migration in schema_migrations, ensuring atomicity.
// Statements are split on semicolons, but semicolons inside BEGIN...END blocks
// (e.g., trigger bodies) are preserved.
func runMigration(db *sql.DB, path string) error {
	origPath := path
	candidatePaths := []string{
		path,
		filepath.Join("..", path),
		filepath.Join("..", "..", path),
		"/tmp/" + path,
		"C:/temp/" + path,
	}
	var lastErr error
	for _, p := range candidatePaths {
		_, err := os.Stat(p)
		if err == nil {
			path = p
			lastErr = nil
			break
		}
		lastErr = err
	}
	if lastErr != nil {
		return fmt.Errorf("migration file not found in any candidate path: %v", lastErr)
	}

	// Verified no-op once committed: a recorded + fully-schema-present
	// migration executes no SQL. A recorded migration whose expected schema
	// is missing is an explicit error (never a destructive re-execution, and
	// never silently treated as applied). Failed first attempts roll back
	// and record nothing, so the check below only fires for committed state.
	var recorded int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'schema_migrations'`).Scan(&recorded); err != nil {
		return err
	}
	if recorded > 0 {
		var applied int
		if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, origPath).Scan(&applied); err == nil {
			if applied > 0 {
				if markers := migrationAppliedExpectations[origPath]; len(markers) > 0 && !migrationSchemaMarkersArePresent(db, markers) {
					return fmt.Errorf("migration %s is recorded but its expected schema is missing", origPath)
				}
				return nil
			}
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading migration: %w", err)
	}

	statements := splitSQLStatements(string(data));

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" || strings.HasPrefix(strings.ToUpper(stmt), "PRAGMA") {
			continue
		}
		if _, err := tx.Exec(stmt); err != nil {
			// Idempotent ALTER TABLE on re-run: a duplicate-column error is
			// only acceptable when the column actually exists in the schema.
			// This prevents hiding unexpected duplicates by masking real
			// failures with the same message.
			if strings.Contains(err.Error(), "duplicate column name") {
				if ok, cerr := columnExistsTx(tx, stmt); cerr == nil && ok {
					continue
				}
			}
			tx.Rollback()
			return fmt.Errorf("executing statement %q: %w", stmt[:min(80, len(stmt))], err)
		}
	}

	// Record migration in schema_migrations table within the same transaction.
	// Store the original logical path (not the resolved filesystem candidate)
	// so version identity is stable across working directories.
	_, err = tx.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at)
		VALUES (?, datetime('now'))`, origPath)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("recording migration: %w", err)
	}

	return tx.Commit()
}

// columnExistsTx reports whether the column referenced by an
// "ALTER TABLE <table> ADD COLUMN <col> ..." statement already exists.
// Used to verify that a duplicate-column error is a genuine idempotent
// re-run rather than an unexpected failure.
func columnExistsTx(tx *sql.Tx, stmt string) (bool, error) {
	m := regexp.MustCompile(`(?i)ALTER\s+TABLE\s+([A-Za-z_][A-Za-z0-9_]*)\s+ADD\s+COLUMN\s+([A-Za-z_][A-Za-z0-9_]*)`).FindStringSubmatch(strings.TrimSpace(stmt))
	if m == nil {
		return false, fmt.Errorf("not an ALTER TABLE ADD COLUMN statement")
	}
	table, col := m[1], m[2]
	rows, err := tx.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if strings.EqualFold(name, col) {
			return true, nil
		}
	}
	return false, rows.Err()
}

// splitSQLStatements splits a SQL script into individual statements on semicolons,
// but preserves semicolons inside BEGIN...END blocks (trigger bodies), string
// literals and comments. Comments are kept within the statement buffer; keywords
// are matched on word boundaries only.
func splitSQLStatements(sql string) []string {
	var statements []string
	var cur strings.Builder
	depth := 0
	word := strings.Builder{}
	flushWord := func() {
		w := strings.ToLower(word.String())
		if w == "begin" {
			depth++
		} else if w == "end" && depth > 0 {
			depth--
		}
		word.Reset()
	}

	n := len(sql)
	for i := 0; i < n; i++ {
		ch := sql[i]

		// Line comment.
		if ch == '-' && i+1 < n && sql[i+1] == '-' {
			flushWord()
			for ; i < n && sql[i] != '\n'; i++ {
				cur.WriteByte(sql[i])
			}
			cur.WriteByte('\n')
			continue
		}
		// Block comment.
		if ch == '/' && i+1 < n && sql[i+1] == '*' {
			flushWord()
			cur.WriteString("/*")
			i += 2
			for i+1 < n && !(sql[i] == '*' && sql[i+1] == '/') {
				cur.WriteByte(sql[i])
				i++
			}
			cur.WriteString("*/")
			i++
			continue
		}
		// Single-quoted string literal; '' is an escaped quote.
		if ch == '\'' {
			flushWord()
			cur.WriteByte(ch)
			i++
			for i < n {
				cur.WriteByte(sql[i])
				if sql[i] == '\'' {
					if i+1 < n && sql[i+1] == '\'' {
						cur.WriteByte(sql[i+1])
						i += 2
						continue
					}
					break
				}
				i++
			}
			continue
		}
		// Double-quoted identifier/literal.
		if ch == '"' {
			flushWord()
			cur.WriteByte(ch)
			i++
			for i < n {
				cur.WriteByte(sql[i])
				if sql[i] == '"' {
					break
				}
				i++
			}
			continue
		}

		cur.WriteByte(ch)

		// Track words for BEGIN/END at word boundaries (non-alnum/_ delimiters).
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' {
			word.WriteByte(ch)
		} else {
			flushWord()
		}

		if ch == ';' && depth == 0 {
			statements = append(statements, cur.String())
			cur.Reset()
		}
	}
	flushWord()

	if strings.TrimSpace(cur.String()) != "" {
		statements = append(statements, cur.String())
	}

	return statements
}

// createM1Tables creates the sessions and schema_migrations tables needed for M1.
func createM1Tables(db *sql.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS sessions (
			session_id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(user_id),
			client_id TEXT NOT NULL REFERENCES clients(client_id),
			expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_accessed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("creating table: %w", err)
		}
	}
	return nil
}

// seedTestData inserts fictional test users and clients for M1 development.
func seedTestData(db *sql.DB) error {
	// Insert test clients (idempotent)
	clients := []struct {
		id, name, sector, status string
	}{
		{"client-alpha", "Alpha Corp", "ENERGY", "active"},
		{"client-beta", "Beta Corp", "FINANCE", "active"},
	}
	for _, c := range clients {
		res, err := db.Exec(`INSERT OR IGNORE INTO clients (client_id, client_name, status, created_at, updated_at)
			VALUES (?, ?, ?, datetime('now'), datetime('now'))`, c.id, c.name, c.status)
		if err != nil {
			return fmt.Errorf("inserting client %s: %w", c.id, err)
		}
		rowsAffected, _ := res.RowsAffected()
		log.Printf("seedTestData: inserted client %s (rows_affected=%d)", c.id, rowsAffected)
	}

	// Hash passwords using the real hashPassword function.
	// Passwords are read from environment variables with fallback defaults for development.
	pwAlpha, err := hashPassword(getEnv("WB_TEST_PASS_ALPHA", "alpha-pass-2026"))
	if err != nil {
		return fmt.Errorf("hashing alpha password: %w", err)
	}
	pwBeta, err := hashPassword(getEnv("WB_TEST_PASS_BETA", "beta-pass-2026"))
	if err != nil {
		return fmt.Errorf("hashing beta password: %w", err)
	}
	pwMulti, err := hashPassword(getEnv("WB_TEST_PASS_MULTI", "multi-pass-2026"))
	if err != nil {
		return fmt.Errorf("hashing multi password: %w", err)
	}

	// Insert test users (idempotent)
	pwAdmin, err := hashPassword(getEnv("WB_TEST_PASS_ADMIN", "admin-pass-2026"))
	if err != nil {
		return fmt.Errorf("hashing admin password: %w", err)
	}
	pwReviewer, err := hashPassword(getEnv("WB_TEST_PASS_REVIEWER", "reviewer-pass-2026"))
	if err != nil {
		return fmt.Errorf("hashing reviewer password: %w", err)
	}
	users := []struct {
		id, username, email, passwordHash, role string
	}{
		{"user-analyst-alpha", "analyst-alpha", "analyst-alpha@example.org", pwAlpha, "CTI_ANALYST"},
		{"user-analyst-beta", "analyst-beta", "analyst-beta@example.org", pwBeta, "CTI_ANALYST"},
		{"user-analyst-multi", "analyst-multi", "analyst-multi@example.org", pwMulti, "HYPOTHESIS_WRITER"},
		{"user-admin", "admin", "admin-workbench@example.org", pwAdmin, "ADMINISTRATOR"},
		{"user-reviewer", "reviewer", "reviewer@example.org", pwReviewer, "REVIEWER"},
	}
	for _, u := range users {
		res, err := db.Exec(`INSERT OR IGNORE INTO users (user_id, username, email, password_hash, role, is_active, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, 1, datetime('now'), datetime('now'))`, u.id, u.username, u.email, u.passwordHash, u.role)
		if err != nil {
			return fmt.Errorf("inserting user %s: %w", u.username, err)
		}
		rowsAffected, _ := res.RowsAffected()
		log.Printf("seedTestData: inserted user %s (rows_affected=%d)", u.username, rowsAffected)
	}

	// Verify users were inserted
	var userCount int
	db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&userCount)
	log.Printf("seedTestData: %d users in database", userCount)

	// Insert sample CTI reports for each tenant
	reports := []struct {
		id, clientID, title, status, checksum string
	}{
		{"report-alpha-1", "client-alpha", "APT29 Campaign Targeting Energy Sector", "ANALYZED", "sha256:alpha1"},
		{"report-alpha-2", "client-alpha", "Lazarus Group IOC Report Q3 2026", "APPROVED", "sha256:alpha2"},
		{"report-beta-1", "client-beta", "Fin7 Banking Trojan Analysis", "ANALYZED", "sha256:beta1"},
	}
	for _, r := range reports {
		res, err := db.Exec(`INSERT OR IGNORE INTO cti_reports (report_id, client_id, title, status, original_content_ref, checksum, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`,
			r.id, r.clientID, r.title, r.status, r.id+".pdf", r.checksum)
		if err != nil {
			return fmt.Errorf("inserting report %s: %w", r.id, err)
		}
		rowsAffected, _ := res.RowsAffected()
		log.Printf("seedTestData: inserted report %s (rows_affected=%d)", r.id, rowsAffected)
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Close closes the database connection.
func (d *DB) Close() error {
	return d.DB.Close()
}

// --- Phase 2: Inventory Database Operations ---

type Client struct {
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
	Status     string `json:"status"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

type Sector struct {
	SectorID    string `json:"sector_id"`
	SectorName  string `json:"sector_name"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
}

type GlobalField struct {
	FieldID          string `json:"field_id"`
	FieldName        string `json:"field_name"`
	FieldType        string `json:"field_type"`
	FieldDescription string `json:"field_description"`
	SourceType       string `json:"source_type"`
	NormalizedName   string `json:"normalized_name"`
	Aliases          string `json:"aliases"`
	Availability     string `json:"availability"`
	LogSources       string `json:"log_sources"`
	AdversaryControl string `json:"adversary_control"`
	UsedInEvents     string `json:"used_in_events"`
	DisplayName      string `json:"display_name"`
	IsActive         bool   `json:"is_active"`
	CreatedAt        string `json:"created_at"`
}

type DetectionRule struct {
	RuleID                  string `json:"rule_id"`
	RuleName                string `json:"rule_name"`
	RuleDescription         string `json:"rule_description"`
	RuleType                string `json:"rule_type"`
	MitreTactics            string `json:"mitre_tactics"`
	MitreTechniques         string `json:"mitre_techniques"`
	RequiredFields          string `json:"required_fields"`
	RequiredLogSources      string `json:"required_log_sources"`
	RuleStatus              string `json:"rule_status"`
	RuleVersion             string `json:"rule_version"`
	LastUpdated             string `json:"last_updated"`
	Enabled                 bool   `json:"enabled"`
	CreatedDate             string `json:"created_date"`
	ModifiedDate            string `json:"modified_date"`
	EventCount30d           int    `json:"event_count_30d"`
	OffenseCount30d         int    `json:"offense_count_30d"`
	LogSource               string `json:"log_source"`
	Criticality             string `json:"criticality"`
	SysmonRequired          bool   `json:"sysmon_required"`
	FullRuleLogic           string `json:"full_rule_logic"`
	EffectiveDetectionLogic string `json:"effective_detection_logic"`
	BBChainSummary          string `json:"bb_chain_summary"`
	CustomFields            string `json:"custom_fields"`
	ReferenceSetsUsed       string `json:"reference_sets_used"`
	BuildingBlocks          string `json:"building_blocks"`
}

type BuildingBlock struct {
	BbID             string `json:"bb_id"`
	BbName           string `json:"bb_name"`
	Level            int    `json:"level"`
	Category         string `json:"category"`
	DependsOnBB      string `json:"depends_on_bb"`
	OwnConditions    string `json:"own_conditions"`
	FullBBLogic      string `json:"full_bb_logic"`
	AdversaryControl string `json:"adversary_control"`
	Availability     string `json:"availability"`
	SysmonRequired   bool   `json:"sysmon_required"`
	Notes            string `json:"notes"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

type ClientTelemetryStatus struct {
	StatusID           string `json:"status_id"`
	ClientID           string `json:"client_id"`
	LogSourceTypeID    string `json:"log_source_type_id"`
	ConnectionStatus   string `json:"connection_status"`
	LastEventTimestamp string `json:"last_event_timestamp"`
	EventVolumeStatus  string `json:"event_volume_status"`
	FieldAvailability  string `json:"field_availability"`
	LastCheckedAt      string `json:"last_checked_at"`
}

// ListClients returns clients the user is authorized to access.
func (db *DB) ListClients(userID string) ([]Client, error) {
	authorized, err := db.GetUserAuthorizedClients(userID)
	if err != nil {
		return nil, err
	}
	if len(authorized) == 0 {
		return nil, nil
	}

	// Build query for authorized clients only
	placeholders := make([]string, len(authorized))
	args := make([]interface{}, len(authorized))
	for i, c := range authorized {
		placeholders[i] = "?"
		args[i] = c
	}

	query := `SELECT client_id, client_name, status, created_at, updated_at FROM clients WHERE client_id IN (` + strings.Join(placeholders, ",") + `) ORDER BY client_name`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []Client
	for rows.Next() {
		var c Client
		if err := rows.Scan(&c.ClientID, &c.ClientName, &c.Status, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, nil
}

// CreateClient creates a new client (ADMIN only).
func (db *DB) CreateClient(clientID, clientName, status string) error {
	_, err := db.Exec(`INSERT INTO clients (client_id, client_name, status, created_at, updated_at)
		VALUES (?, ?, ?, datetime('now'), datetime('now'))`,
		clientID, clientName, status)
	return err
}

// ListSectors returns all sectors.
func (db *DB) ListSectors() ([]Sector, error) {
	rows, err := db.Query(`SELECT sector_id, sector_name, description, created_at FROM sectors ORDER BY sector_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sectors []Sector
	for rows.Next() {
		var s Sector
		if err := rows.Scan(&s.SectorID, &s.SectorName, &s.Description, &s.CreatedAt); err != nil {
			return nil, err
		}
		sectors = append(sectors, s)
	}
	return sectors, nil
}

// ListGlobalFields returns all active global QRadar fields.
func (db *DB) ListGlobalFields() ([]GlobalField, error) {
	rows, err := db.Query(`SELECT field_id, field_name, field_type, field_description, source_type, normalized_name, aliases, availability, log_sources, adversary_control, used_in_events, display_name, is_active, created_at FROM global_fields WHERE is_active = 1 ORDER BY field_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var fields []GlobalField
	for rows.Next() {
		var f GlobalField
		var isActive int
		var availability, logSources, adversaryControl, usedInEvents, displayName sql.NullString
		if err := rows.Scan(&f.FieldID, &f.FieldName, &f.FieldType, &f.FieldDescription, &f.SourceType, &f.NormalizedName, &f.Aliases, &availability, &logSources, &adversaryControl, &usedInEvents, &displayName, &isActive, &f.CreatedAt); err != nil {
			return nil, err
		}
		f.Availability = availability.String
		f.LogSources = logSources.String
		f.AdversaryControl = adversaryControl.String
		f.UsedInEvents = usedInEvents.String
		f.DisplayName = displayName.String
		f.IsActive = isActive == 1
		fields = append(fields, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return fields, nil
}

// ListDetectionRules returns all detection rules.
func (db *DB) ListDetectionRules() ([]DetectionRule, error) {
	rows, err := db.Query(`SELECT rule_id, rule_name, rule_description, rule_type, mitre_tactics, mitre_techniques, required_fields, required_log_sources, rule_status, rule_version, last_updated, enabled, created_date, modified_date, event_count_30d, offense_count_30d, log_source, criticality, sysmon_required, full_rule_logic, effective_detection_logic, bb_chain_summary, custom_fields, reference_sets_used, building_blocks FROM detection_rules ORDER BY rule_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []DetectionRule
	for rows.Next() {
		var r DetectionRule
		var enabled, eventCount, offenseCount, sysmon sql.NullInt64
		var createdDate, modifiedDate, logSource, criticality, fullRuleLogic, effectiveDetectionLogic, bbChainSummary, customFields, referenceSetsUsed, buildingBlocks sql.NullString
		if err := rows.Scan(&r.RuleID, &r.RuleName, &r.RuleDescription, &r.RuleType, &r.MitreTactics, &r.MitreTechniques, &r.RequiredFields, &r.RequiredLogSources, &r.RuleStatus, &r.RuleVersion, &r.LastUpdated, &enabled, &createdDate, &modifiedDate, &eventCount, &offenseCount, &logSource, &criticality, &sysmon, &fullRuleLogic, &effectiveDetectionLogic, &bbChainSummary, &customFields, &referenceSetsUsed, &buildingBlocks); err != nil {
			return nil, err
		}
		r.Enabled = enabled.Valid && enabled.Int64 != 0
		r.CreatedDate = createdDate.String
		r.ModifiedDate = modifiedDate.String
		if eventCount.Valid {
			r.EventCount30d = int(eventCount.Int64)
		}
		if offenseCount.Valid {
			r.OffenseCount30d = int(offenseCount.Int64)
		}
		r.LogSource = logSource.String
		r.Criticality = criticality.String
		r.SysmonRequired = sysmon.Valid && sysmon.Int64 != 0
		r.FullRuleLogic = fullRuleLogic.String
		r.EffectiveDetectionLogic = effectiveDetectionLogic.String
		r.BBChainSummary = bbChainSummary.String
		r.CustomFields = customFields.String
		r.ReferenceSetsUsed = referenceSetsUsed.String
		r.BuildingBlocks = buildingBlocks.String
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

// ListBuildingBlocks returns all building blocks.
func (db *DB) ListBuildingBlocks() ([]BuildingBlock, error) {
	rows, err := db.Query(`SELECT bb_id, bb_name, level, category, depends_on_bb, own_conditions, full_bb_logic, adversary_control, availability, sysmon_required, notes, created_at, updated_at FROM building_blocks ORDER BY bb_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var blocks []BuildingBlock
	for rows.Next() {
		var b BuildingBlock
		var level sql.NullInt64
		var dependsOn, ownCond, fullLogic, advCtrl, avail, notes, updated sql.NullString
		var sysmon sql.NullInt64
		if err := rows.Scan(&b.BbID, &b.BbName, &level, &b.Category, &dependsOn, &ownCond, &fullLogic, &advCtrl, &avail, &sysmon, &notes, &b.CreatedAt, &updated); err != nil {
			return nil, err
		}
		if level.Valid {
			b.Level = int(level.Int64)
		}
		b.DependsOnBB = dependsOn.String
		b.OwnConditions = ownCond.String
		b.FullBBLogic = fullLogic.String
		b.AdversaryControl = advCtrl.String
		b.Availability = avail.String
		b.SysmonRequired = sysmon.Valid && sysmon.Int64 != 0
		b.Notes = notes.String
		b.UpdatedAt = updated.String
		blocks = append(blocks, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return blocks, nil
}

// GetBuildingBlock returns a building block by id.
func (db *DB) GetBuildingBlock(bbID string) (*BuildingBlock, error) {
	row := db.QueryRow(`SELECT bb_id, bb_name, level, category, depends_on_bb, own_conditions, full_bb_logic, adversary_control, availability, sysmon_required, notes, created_at, updated_at FROM building_blocks WHERE bb_id = ?`, bbID)
	var b BuildingBlock
	var level sql.NullInt64
	var dependsOn, ownCond, fullLogic, advCtrl, avail, notes, updated sql.NullString
	var sysmon sql.NullInt64
	err := row.Scan(&b.BbID, &b.BbName, &level, &b.Category, &dependsOn, &ownCond, &fullLogic, &advCtrl, &avail, &sysmon, &notes, &b.CreatedAt, &updated)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if level.Valid {
		b.Level = int(level.Int64)
	}
	b.DependsOnBB = dependsOn.String
	b.OwnConditions = ownCond.String
	b.FullBBLogic = fullLogic.String
	b.AdversaryControl = advCtrl.String
	b.Availability = avail.String
	b.SysmonRequired = sysmon.Valid && sysmon.Int64 != 0
	b.Notes = notes.String
	b.UpdatedAt = updated.String
	return &b, nil
}

// GetRuleBuildingBlocks returns building blocks associated with a rule.
func (db *DB) GetRuleBuildingBlocks(ruleID string) ([]BuildingBlock, error) {
	rows, err := db.Query(`SELECT b.bb_id, b.bb_name, b.level, b.category, b.depends_on_bb, b.own_conditions, b.full_bb_logic, b.adversary_control, b.availability, b.sysmon_required, b.notes, b.created_at, b.updated_at FROM building_blocks b JOIN rule_building_blocks rbb ON b.bb_id = rbb.bb_id WHERE rbb.rule_id = ? ORDER BY b.bb_id`, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var blocks []BuildingBlock
	for rows.Next() {
		var b BuildingBlock
		var level sql.NullInt64
		var dependsOn, ownCond, fullLogic, advCtrl, avail, notes, updated sql.NullString
		var sysmon sql.NullInt64
		if err := rows.Scan(&b.BbID, &b.BbName, &level, &b.Category, &dependsOn, &ownCond, &fullLogic, &advCtrl, &avail, &sysmon, &notes, &b.CreatedAt, &updated); err != nil {
			return nil, err
		}
		if level.Valid {
			b.Level = int(level.Int64)
		}
		b.DependsOnBB = dependsOn.String
		b.OwnConditions = ownCond.String
		b.FullBBLogic = fullLogic.String
		b.AdversaryControl = advCtrl.String
		b.Availability = avail.String
		b.SysmonRequired = sysmon.Valid && sysmon.Int64 != 0
		b.Notes = notes.String
		b.UpdatedAt = updated.String
		blocks = append(blocks, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return blocks, nil
}

// ListClientTelemetry returns client telemetry status for a given client.
func (db *DB) ListClientTelemetry(clientID string) ([]ClientTelemetryStatus, error) {
	rows, err := db.Query(`SELECT status_id, client_id, log_source_type_id, connection_status, last_event_timestamp, event_volume_status, field_availability, last_checked_at FROM client_log_source_status WHERE client_id = ? ORDER BY log_source_type_id`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var statuses []ClientTelemetryStatus
	for rows.Next() {
		var s ClientTelemetryStatus
		if err := rows.Scan(&s.StatusID, &s.ClientID, &s.LogSourceTypeID, &s.ConnectionStatus, &s.LastEventTimestamp, &s.EventVolumeStatus, &s.FieldAvailability, &s.LastCheckedAt); err != nil {
			return nil, err
		}
		statuses = append(statuses, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return statuses, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CreateGlobalField creates a global field.
func (db *DB) CreateGlobalField(args ...interface{}) error {
	var f GlobalField
	if len(args) == 1 {
		switch v := args[0].(type) {
		case GlobalField:
			f = v
		case *GlobalField:
			if v != nil {
				f = *v
			}
		}
	} else {
		getStr := func(i int) string {
			if i < len(args) {
				if s, ok := args[i].(string); ok {
					return s
				}
			}
			return ""
		}
		f.FieldID = getStr(0)
		f.FieldName = getStr(1)
		f.FieldType = getStr(2)
		f.FieldDescription = getStr(3)
		f.SourceType = getStr(4)
		f.NormalizedName = getStr(5)
		f.Aliases = getStr(6)
		f.Availability = getStr(7)
		f.AdversaryControl = getStr(8)
		f.UsedInEvents = getStr(9)
		f.DisplayName = getStr(10)
		if len(args) > 11 {
			switch v := args[11].(type) {
			case bool:
				f.IsActive = v
			case int:
				f.IsActive = v == 1
			}
		}
	}
	_, err := db.Exec(`INSERT INTO global_fields (field_id, field_name, field_type, field_description, source_type, normalized_name, aliases, availability, adversary_control, used_in_events, display_name, is_active, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, datetime('now')))`,
		f.FieldID, f.FieldName, f.FieldType, f.FieldDescription, f.SourceType, f.NormalizedName, f.Aliases, f.Availability, f.AdversaryControl, f.UsedInEvents, f.DisplayName, boolToInt(f.IsActive), func() interface{} {
			if f.CreatedAt == "" {
				return nil
			}
			return f.CreatedAt
		}())
	return err
}

// CreateDetectionRule creates a detection rule.
func (db *DB) CreateDetectionRule(args ...interface{}) error {
	var r DetectionRule
	if len(args) == 1 {
		switch v := args[0].(type) {
		case DetectionRule:
			r = v
		case *DetectionRule:
			if v != nil {
				r = *v
			}
		}
	} else {
		getStr := func(i int) string {
			if i < len(args) {
				if s, ok := args[i].(string); ok {
					return s
				}
			}
			return ""
		}
		r.RuleID = getStr(0)
		r.RuleName = getStr(1)
		r.RuleDescription = getStr(2)
		r.RuleType = getStr(3)
		r.MitreTactics = getStr(4)
		r.MitreTechniques = getStr(5)
		r.RequiredFields = getStr(6)
		r.RequiredLogSources = getStr(7)
		r.RuleStatus = getStr(8)
		r.RuleVersion = getStr(9)
	}
	_, err := db.Exec(`INSERT INTO detection_rules (rule_id, rule_name, rule_description, rule_type, mitre_tactics, mitre_techniques, required_fields, required_log_sources, rule_status, rule_version, last_updated, enabled, created_date, modified_date, event_count_30d, offense_count_30d, log_source, criticality, sysmon_required, full_rule_logic, effective_detection_logic, bb_chain_summary, custom_fields, reference_sets_used, building_blocks)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.RuleID, r.RuleName, r.RuleDescription, r.RuleType, r.MitreTactics, r.MitreTechniques, r.RequiredFields, r.RequiredLogSources, r.RuleStatus, r.RuleVersion,
		boolToInt(r.Enabled), r.CreatedDate, r.ModifiedDate, r.EventCount30d, r.OffenseCount30d, r.LogSource, r.Criticality, boolToInt(r.SysmonRequired), r.FullRuleLogic, r.EffectiveDetectionLogic, r.BBChainSummary, r.CustomFields, r.ReferenceSetsUsed, r.BuildingBlocks)
	return err
}

// CreateBuildingBlock creates a building block.
func (db *DB) CreateBuildingBlock(args ...interface{}) error {
	var b BuildingBlock
	if len(args) == 1 {
		switch v := args[0].(type) {
		case BuildingBlock:
			b = v
		case *BuildingBlock:
			if v != nil {
				b = *v
			}
		}
	} else {
		getStr := func(i int) string {
			if i < len(args) {
				if s, ok := args[i].(string); ok {
					return s
				}
			}
			return ""
		}
		b.BbID = getStr(0)
		b.BbName = getStr(1)
		if len(args) > 2 {
			switch v := args[2].(type) {
			case int:
				b.Level = v
			}
		}
		b.Category = getStr(3)
	}
	_, err := db.Exec(`INSERT INTO building_blocks (bb_id, bb_name, level, category, depends_on_bb, own_conditions, full_bb_logic, adversary_control, availability, sysmon_required, notes, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`,
		b.BbID, b.BbName, b.Level, b.Category, b.DependsOnBB, b.OwnConditions, b.FullBBLogic, b.AdversaryControl, b.Availability, boolToInt(b.SysmonRequired), b.Notes)
	return err
}
