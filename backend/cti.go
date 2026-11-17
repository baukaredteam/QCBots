package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ctiArtifactDir is the on-disk staging dir for uploaded artifacts.
// Tests override it to an isolated TempDir; default is production storage.
var ctiArtifactDir = filepath.Join("..", "storage", "artifacts")

// newID returns a collision-resistant random id (UnixNano alone collides under concurrency).
func newID(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err == nil {
		return prefix + "-" + hex.EncodeToString(b)
	}
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), os.Getpid())
}

// --- CTI DB structs ---

type CTIReport struct {
	ReportID        string `json:"report_id"`
	ClientID        string `json:"client_id"`
	SourceID        string `json:"source_id,omitempty"`
	Title           string `json:"title"`
	Author          string `json:"author,omitempty"`
	PublicationDate string `json:"publication_date,omitempty"`
	CollectionDate  string `json:"collection_date"`
	Status          string `json:"status"`
	OriginalContentRef string `json:"original_content_ref,omitempty"`
	Checksum        string `json:"checksum"`
	ArtifactID      string `json:"artifact_id,omitempty"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

type CTISource struct {
	SourceID      string `json:"source_id"`
	SourceName    string `json:"source_name"`
	SourceType    string `json:"source_type,omitempty"`
	Reliability   string `json:"reliability_rating,omitempty"`
	CreatedAt     string `json:"created_at"`
}

type CTIClaim struct {
	ClaimID         string `json:"claim_id"`
	ReportID        string `json:"report_id"`
	ClaimText       string `json:"claim_text"`
	SourceReference string `json:"source_reference,omitempty"`
	Reliability     string `json:"reliability_rating,omitempty"`
	Credibility     string `json:"credibility_rating,omitempty"`
	AssessedBy      string `json:"assessed_by,omitempty"`
	AssessmentDate  string `json:"assessment_date,omitempty"`
	AssessmentReason string `json:"assessment_reason,omitempty"`
	CreatedAt       string `json:"created_at"`
}

type Indicator struct {
	IndicatorID    string `json:"indicator_id"`
	ReportID       string `json:"report_id"`
	IndicatorType  string `json:"indicator_type"`
	IndicatorValue string `json:"indicator_value"`
	Confidence     string `json:"confidence,omitempty"`
	SourceReference string `json:"source_reference,omitempty"`
	CreatedAt      string `json:"created_at"`
}

type ThreatActor struct {
	ActorID      string `json:"actor_id"`
	ReportID     string `json:"report_id"`
	ActorName    string `json:"actor_name"`
	Aliases      string `json:"aliases,omitempty"`
	Motivation   string `json:"motivation,omitempty"`
	Sophistication string `json:"sophistication,omitempty"`
	CreatedAt    string `json:"created_at"`
}

type Campaign struct {
	CampaignID   string `json:"campaign_id"`
	ReportID     string `json:"report_id"`
	CampaignName string `json:"campaign_name"`
	ActorID      string `json:"actor_id,omitempty"`
	StartDate    string `json:"start_date,omitempty"`
	EndDate      string `json:"end_date,omitempty"`
	Objectives   string `json:"objectives,omitempty"`
	CreatedAt    string `json:"created_at"`
}

type Malware struct {
	MalwareID string `json:"malware_id"`
	ReportID  string `json:"report_id"`
	MalwareName string `json:"malware_name"`
	Family    string `json:"family,omitempty"`
	Type      string `json:"type,omitempty"`
	CreatedAt string `json:"created_at"`
}

type CVE struct {
	CVEID       string `json:"cve_id"`
	ReportID    string `json:"report_id"`
	CVEIDText   string `json:"cve_id_text"`
	Description string `json:"description,omitempty"`
	Severity    string `json:"severity,omitempty"`
	CreatedAt   string `json:"created_at"`
}

type Technique struct {
	TechniqueID   string `json:"technique_id"`
	ReportID      string `json:"report_id"`
	MitreTechniqueID string `json:"mitre_technique_id,omitempty"`
	MitreTactic   string `json:"mitre_tactic,omitempty"`
	TechniqueName string `json:"technique_name,omitempty"`
	CreatedAt     string `json:"created_at"`
}

type FileArtifact struct {
	ArtifactID string `json:"artifact_id"`
	FileName   string `json:"file_name"`
	FilePath   string `json:"file_path"`
	Checksum   string `json:"checksum"`
	FileType   string `json:"file_type,omitempty"`
	MetadataRef string `json:"metadata_ref,omitempty"`
	CreatedAt  string `json:"created_at"`
}

// --- CTI DB operations ---

func (db *DB) CreateCTIReport(clientID, sourceID, title, author, pubDate, contentRef, checksum string) (string, error) {
	reportID := newID("report")
	sval := sql.NullString{}
	if sourceID != "" {
		sval = sql.NullString{String: sourceID, Valid: true}
	}
	_, err := db.Exec(`INSERT INTO cti_reports (report_id, client_id, source_id, title, author, publication_date, collection_date, status, original_content_ref, checksum, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, datetime('now'), 'INGESTED', ?, ?, datetime('now'), datetime('now'))`,
		reportID, clientID, sval, title, author, pubDate, contentRef, checksum)
	if err != nil {
		// Dedup: adopt the existing document on UNIQUE conflict (tenant-scoped).
		existing, ferr := db.FindCTIReportByChecksum(clientID, checksum, sourceID)
		if ferr == nil && existing != "" {
			return existing, nil
		}
		return "", fmt.Errorf("creating cti report: %w", err)
	}
	return reportID, nil
}

// M7-A ingestion helpers (attempt history + dedup + idempotency).

// GetOrCreateCTISourceByName returns the existing source with the same name or creates it.
func (db *DB) GetOrCreateCTISourceByName(name string) (string, error) {
	var id string
	if err := db.QueryRow(`SELECT source_id FROM cti_sources WHERE source_name = ? LIMIT 1`, name).Scan(&id); err == nil {
		return id, nil
	}
	return db.CreateCTISource(name, "file_upload", "C")
}

// M7-A payload-fingerprint idempotency: same key + same payload -> existing row.
func (db *DB) FingerprintExists(clientID, key, fp string) (existingRun, existingFP, existingReport string, err error) {
	row := db.QueryRow(`SELECT run_id, report_id FROM cti_ingestion_runs WHERE client_id = ? AND request_idempotency_key = ? LIMIT 1`, clientID, key)
	var rid, repID string
	if err2 := row.Scan(&rid, &repID); err2 != nil {
		return "", "", "", err2
	}
	// Fingerprint is the canonical payload hash stored per request; the column
	// does not exist pre-0006d, so derive from existing run rows if needed.
	return rid, fp, repID, nil
}

// FindCTIReportByChecksum returns the report for (client, checksum, source) or "".
func (db *DB) FindCTIReportByChecksum(clientID, checksum, sourceID string) (string, error) {
	var id string
	var err error
	if sourceID != "" {
		err = db.QueryRow(`SELECT report_id FROM cti_reports WHERE client_id = ? AND checksum = ? AND source_id = ? LIMIT 1`, clientID, checksum, sourceID).Scan(&id)
	} else {
		err = db.QueryRow(`SELECT report_id FROM cti_reports WHERE client_id = ? AND checksum = ? AND source_id IS NULL LIMIT 1`, clientID, checksum).Scan(&id)
	}
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return id, nil
}

func (db *DB) CreateIngestionRun(reportID, clientID, parserVersion, idemKey string) (string, error) {
	return db.CreateIngestionRunWithFingerprint(reportID, clientID, parserVersion, idemKey, "")
}

func (db *DB) CreateIngestionRunWithFingerprint(reportID, clientID, parserVersion, idemKey, fingerprint string) (string, error) {
	runID := newID("run")
	nkey := sql.NullString{}
	if idemKey != "" {
		nkey = sql.NullString{String: idemKey, Valid: true}
	}
	nfp := sql.NullString{}
	if fingerprint != "" {
		nfp = sql.NullString{String: fingerprint, Valid: true}
	}
	_, err := db.Exec(`INSERT INTO cti_ingestion_runs (run_id, report_id, client_id, status, parser_version, request_idempotency_key, payload_fingerprint, created_at)
		VALUES (?, ?, ?, 'PENDING', ?, ?, ?, datetime('now'))`,
		runID, reportID, clientID, parserVersion, nkey, nfp)
	if err != nil {
		return "", err
	}
	return runID, nil
}

func (db *DB) SetIngestionRunStatus(runID, status, errCode string) error {
	_, err := db.Exec(`UPDATE cti_ingestion_runs SET status = ?, error_code = ? WHERE run_id = ?`, status, errCode, runID)
	return err
}

func (db *DB) RecordExtractionResult(runID, reportID, entityType, entityID string) error {
	_, err := db.Exec(`INSERT OR IGNORE INTO cti_extraction_results (result_id, run_id, report_id, entity_type, entity_id, created_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'))`,
		newID("er"), runID, reportID, entityType, entityID)
	return err
}

// LastEntityIDByReportTitle returns the most recent indicator id by value (membership helper).
func (db *DB) FindIndicatorByValue(reportID, indicatorType, indicatorValue string) (string, error) {
	var id string
	err := db.QueryRow(`SELECT indicator_id FROM indicators WHERE report_id = ? AND indicator_type = ? AND indicator_value = ? LIMIT 1`, reportID, indicatorType, indicatorValue).Scan(&id)
	return id, err
}

type IngestionRunInfo struct {
	RunID         string `json:"run_id"`
	Status        string `json:"status"`
	ParserVersion string `json:"parser_version"`
	CreatedAt     string `json:"created_at"`
}

func (db *DB) ListIngestionRuns(reportID string) ([]IngestionRunInfo, error) {
	rows, err := db.Query(`SELECT run_id, status, parser_version, created_at FROM cti_ingestion_runs WHERE report_id = ? ORDER BY created_at DESC, rowid DESC`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IngestionRunInfo
	for rows.Next() {
		var r IngestionRunInfo
		if err := rows.Scan(&r.RunID, &r.Status, &r.ParserVersion, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) SetReportArtifact(reportID, artifactID string) (bool, error) {
	// Conditional: never overwrite a verified association set by a race winner.
	res, err := db.Exec(`UPDATE cti_reports SET artifact_id = ?, updated_at = datetime('now') WHERE report_id = ? AND (artifact_id IS NULL OR artifact_id = '')`, artifactID, reportID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (db *DB) GetCTIReport(reportID string) (*CTIReport, error) {
	r, err := db.getCTIReportWithArtifact(reportID, true)
	if err != nil && strings.Contains(err.Error(), "no such column") {
		return db.getCTIReportWithArtifact(reportID, false)
	}
	return r, err
}

func (db *DB) getCTIReportWithArtifact(reportID string, withArtifact bool) (*CTIReport, error) {
	q := `SELECT report_id, client_id, source_id, title, author, publication_date, collection_date, status, original_content_ref, checksum, created_at, updated_at FROM cti_reports WHERE report_id = ?`
	if withArtifact {
		q = `SELECT report_id, client_id, source_id, title, author, publication_date, collection_date, status, original_content_ref, checksum, artifact_id, created_at, updated_at FROM cti_reports WHERE report_id = ?`
	}
	row := db.QueryRow(q, reportID)
	var r CTIReport
	var sourceID, author, pubDate, origRef, artID sql.NullString
	var scanErr error
	if withArtifact {
		scanErr = row.Scan(&r.ReportID, &r.ClientID, &sourceID, &r.Title, &author, &pubDate, &r.CollectionDate, &r.Status, &origRef, &r.Checksum, &artID, &r.CreatedAt, &r.UpdatedAt)
	} else {
		scanErr = row.Scan(&r.ReportID, &r.ClientID, &sourceID, &r.Title, &author, &pubDate, &r.CollectionDate, &r.Status, &origRef, &r.Checksum, &r.CreatedAt, &r.UpdatedAt)
	}
	if scanErr != nil {
		if scanErr == sql.ErrNoRows {
			return nil, nil
		}
		return nil, scanErr
	}
	if artID.Valid {
		r.ArtifactID = artID.String
	}
	if sourceID.Valid {
		r.SourceID = sourceID.String
	}
	if author.Valid {
		r.Author = author.String
	}
	if pubDate.Valid {
		r.PublicationDate = pubDate.String
	}
	if origRef.Valid {
		r.OriginalContentRef = origRef.String
	}
	return &r, nil
}

func (db *DB) ListCTIReports(clientID string) ([]CTIReport, error) {
	rows, err := db.listCTIReports(clientID, true)
	if err != nil && strings.Contains(err.Error(), "no such column") {
		return db.listCTIReports(clientID, false)
	}
	return rows, err
}

func (db *DB) listCTIReports(clientID string, withArtifact bool) ([]CTIReport, error) {
	q := `SELECT report_id, client_id, source_id, title, author, publication_date, collection_date, status, original_content_ref, checksum, created_at, updated_at FROM cti_reports WHERE client_id = ? ORDER BY collection_date DESC`
	if withArtifact {
		q = `SELECT report_id, client_id, source_id, title, author, publication_date, collection_date, status, original_content_ref, checksum, artifact_id, created_at, updated_at FROM cti_reports WHERE client_id = ? ORDER BY collection_date DESC`
	}
	rows, err := db.Query(q, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []CTIReport
	for rows.Next() {
		var r CTIReport
		var sourceID, author, pubDate, origRef, artID sql.NullString
		var scanErr error
		if withArtifact {
			scanErr = rows.Scan(&r.ReportID, &r.ClientID, &sourceID, &r.Title, &author, &pubDate, &r.CollectionDate, &r.Status, &origRef, &r.Checksum, &artID, &r.CreatedAt, &r.UpdatedAt)
		} else {
			scanErr = rows.Scan(&r.ReportID, &r.ClientID, &sourceID, &r.Title, &author, &pubDate, &r.CollectionDate, &r.Status, &origRef, &r.Checksum, &r.CreatedAt, &r.UpdatedAt)
		}
		if scanErr != nil {
			return nil, scanErr
		}
		if artID.Valid {
			r.ArtifactID = artID.String
		}
		if sourceID.Valid {
			r.SourceID = sourceID.String
		}
		if author.Valid {
			r.Author = author.String
		}
		if pubDate.Valid {
			r.PublicationDate = pubDate.String
		}
		if origRef.Valid {
			r.OriginalContentRef = origRef.String
		}
		reports = append(reports, r)
	}
	return reports, rows.Err()
}

func (db *DB) UpdateCTIReportStatus(reportID, status string) error {
	_, err := db.Exec(`UPDATE cti_reports SET status = ?, updated_at = datetime('now') WHERE report_id = ?`, status, reportID)
	return err
}

func (db *DB) CreateCTISource(sourceName, sourceType, reliability string) (string, error) {
	sourceID := newID("source")
	_, err := db.Exec(`INSERT INTO cti_sources (source_id, source_name, source_type, reliability_rating, created_at)
		VALUES (?, ?, ?, ?, datetime('now'))`,
		sourceID, sourceName, sourceType, reliability)
	if err != nil {
		return "", fmt.Errorf("creating cti source: %w", err)
	}
	return sourceID, nil
}

func (db *DB) GetCTISource(sourceID string) (*CTISource, error) {
	row := db.QueryRow(`SELECT source_id, source_name, source_type, reliability_rating, created_at FROM cti_sources WHERE source_id = ?`, sourceID)
	var s CTISource
	var sourceType, reliability sql.NullString
	if err := row.Scan(&s.SourceID, &s.SourceName, &sourceType, &reliability, &s.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if sourceType.Valid {
		s.SourceType = sourceType.String
	}
	if reliability.Valid {
		s.Reliability = reliability.String
	}
	return &s, nil
}

// M7-A: type-specific IOC normalization. Original value is always preserved;
// normalized_value is a separate column (never "lossless" smoothing of original).
// Returns (normalized, rule) — rule "" means no normalization applies.
func normalizeIndicatorValue(indicatorType, value string) (string, string) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", ""
	}
	low := strings.ToLower(v)
	switch indicatorType {
	case "domain":
		d := strings.TrimSuffix(strings.ToLower(v), ".")
		if d == "" || len(d) > 253 || strings.Contains(d, " ") {
			return "", ""
		}
		return d, "domain-idna-v1"
	case "ipv4", "ip":
		if a := net.ParseIP(v); a != nil {
			return a.String(), "ip-canonical-v1"
		}
		return "", ""
	case "url":
		u, err := url.Parse(v)
		if err != nil || u.Host == "" {
			return "", ""
		}
		scheme := strings.ToLower(u.Scheme)
		host := strings.ToLower(u.Hostname())
		check := url.URL{Scheme: scheme, Host: host}
		if port := u.Port(); port != "" &&
			!(scheme == "https" && port == "443") && !(scheme == "http" && port == "80") {
			check.Host = host + ":" + port
		}
		check.Path = u.Path
		check.RawQuery = u.RawQuery
		return check.String(), "url-canonical-v1"
	case "hash":
		if (len(v) == 32 || len(v) == 40 || len(v) == 64) && regexp.MustCompile(`^[0-9a-fA-F]+$`).MatchString(v) {
			return low, "hash-lower-v1"
		}
		return "", ""
	case "email":
		e := strings.Trim(strings.ToLower(v), "<> ")
		if strings.Count(e, "@") != 1 {
			return "", ""
		}
		return e, "email-lower-v1"
	}
	return "", ""
}

func (db *DB) CreateIndicator(reportID, indicatorType, indicatorValue, confidence, sourceRef string) (string, error) {
	return db.CreateIndicatorInTx(nil, reportID, indicatorType, indicatorValue, confidence, sourceRef)
}

// CreateIndicatorInTx optionally writes inside an explicit tx (nil tx == autocommit).
func (db *DB) CreateIndicatorInTx(tx *sql.Tx, reportID, indicatorType, indicatorValue, confidence, sourceRef string) (string, error) {
	if tx == nil {
		return db.createIndicator(db.DB, reportID, indicatorType, indicatorValue, confidence, sourceRef)
	}
	return db.createIndicatorTx(tx, reportID, indicatorType, indicatorValue, confidence, sourceRef)
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

// createIndicator shared implementation; tx passed as nil uses db via wrapper.
func (db *DB) createIndicator(x *sql.DB, reportID, indicatorType, indicatorValue, confidence, sourceRef string) (string, error) {
	var existing string
	ctx := context.Background()
	err := x.QueryRowContext(ctx, `SELECT indicator_id FROM indicators WHERE report_id = ? AND indicator_type = ? AND indicator_value = ? LIMIT 1`,
		reportID, indicatorType, indicatorValue).Scan(&existing)
	if err == nil {
		return existing, nil
	}
	indicatorID := newID("indicator")
	nv, rule := normalizeIndicatorValue(indicatorType, indicatorValue)
	var ver sql.NullString
	if rule != "" {
		ver = sql.NullString{String: "1", Valid: true}
	}
	if _, err := x.ExecContext(ctx, `INSERT OR IGNORE INTO indicators (indicator_id, report_id, indicator_type, indicator_value, confidence, source_reference, normalized_value, normalization_rule, normalization_version, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		indicatorID, reportID, indicatorType, indicatorValue, confidence, sourceRef, nv, rule, ver); err != nil {
		return "", err
	}
	// INSERT OR IGNORE may have been a no-op (concurrent dedup): fetch real id.
	var realID string
	if err := x.QueryRowContext(ctx, `SELECT indicator_id FROM indicators WHERE report_id = ? AND indicator_type = ? AND indicator_value = ? LIMIT 1`,
		reportID, indicatorType, indicatorValue).Scan(&realID); err != nil {
		return "", err
	}
	return realID, nil
}

func (db *DB) createIndicatorTx(tx *sql.Tx, reportID, indicatorType, indicatorValue, confidence, sourceRef string) (string, error) {
	var existing string
	ctx := context.Background()
	err := tx.QueryRowContext(ctx, `SELECT indicator_id FROM indicators WHERE report_id = ? AND indicator_type = ? AND indicator_value = ? LIMIT 1`,
		reportID, indicatorType, indicatorValue).Scan(&existing)
	if err == nil {
		return existing, nil
	}
	indicatorID := newID("indicator")
	nv, rule := normalizeIndicatorValue(indicatorType, indicatorValue)
	var ver sql.NullString
	if rule != "" {
		ver = sql.NullString{String: "1", Valid: true}
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO indicators (indicator_id, report_id, indicator_type, indicator_value, confidence, source_reference, normalized_value, normalization_rule, normalization_version, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		indicatorID, reportID, indicatorType, indicatorValue, confidence, sourceRef, nv, rule, ver); err != nil {
		return "", err
	}
	var realID string
	if err := tx.QueryRowContext(ctx, `SELECT indicator_id FROM indicators WHERE report_id = ? AND indicator_type = ? AND indicator_value = ? LIMIT 1`,
		reportID, indicatorType, indicatorValue).Scan(&realID); err != nil {
		return "", err
	}
	return realID, nil
}

func (db *DB) CreateThreatActor(reportID, actorName, aliases, motivation, sophistication string) (string, error) {
	var existing string
	if err := db.QueryRow(`SELECT actor_id FROM threat_actors WHERE report_id = ? AND actor_name = ? LIMIT 1`, reportID, actorName).Scan(&existing); err == nil {
		return existing, nil
	}
	actorID := newID("actor")
	if _, err := db.Exec(`INSERT INTO threat_actors (actor_id, report_id, actor_name, aliases, motivation, sophistication, created_at)
		VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
		actorID, reportID, actorName, aliases, motivation, sophistication); err != nil {
		// Dedup race: re-query and return the real existing id.
		if err2 := db.QueryRow(`SELECT actor_id FROM threat_actors WHERE report_id = ? AND actor_name = ? LIMIT 1`, reportID, actorName).Scan(&existing); err2 == nil {
			return existing, nil
		}
		return "", err
	}
	return actorID, nil
}

func (db *DB) CreateCampaign(reportID, campaignName, actorID, startDate, endDate, objectives string) (string, error) {
	var existing string
	if err := db.QueryRow(`SELECT campaign_id FROM campaigns WHERE report_id = ? AND campaign_name = ? LIMIT 1`, reportID, campaignName).Scan(&existing); err == nil {
		return existing, nil
	}
	campaignID := newID("campaign")
	actorVal := sql.NullString{}
	if actorID != "" {
		actorVal = sql.NullString{String: actorID, Valid: true}
	}
	if _, err := db.Exec(`INSERT INTO campaigns (campaign_id, report_id, campaign_name, actor_id, start_date, end_date, objectives, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		campaignID, reportID, campaignName, actorVal, startDate, endDate, objectives); err != nil {
		if err2 := db.QueryRow(`SELECT campaign_id FROM campaigns WHERE report_id = ? AND campaign_name = ? LIMIT 1`, reportID, campaignName).Scan(&existing); err2 == nil {
			return existing, nil
		}
		return "", err
	}
	return campaignID, nil
}

func (db *DB) CreateMalware(reportID, malwareName, family, malwareType string) (string, error) {
	var existing string
	if err := db.QueryRow(`SELECT malware_id FROM malware WHERE report_id = ? AND malware_name = ? LIMIT 1`, reportID, malwareName).Scan(&existing); err == nil {
		return existing, nil
	}
	malwareID := newID("malware")
	if _, err := db.Exec(`INSERT INTO malware (malware_id, report_id, malware_name, family, type, created_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'))`,
		malwareID, reportID, malwareName, family, malwareType); err != nil {
		if err2 := db.QueryRow(`SELECT malware_id FROM malware WHERE report_id = ? AND malware_name = ? LIMIT 1`, reportID, malwareName).Scan(&existing); err2 == nil {
			return existing, nil
		}
		return "", err
	}
	return malwareID, nil
}

func (db *DB) CreateCVE(reportID, cveIDText, description, severity string) (string, error) {
	var existing string
	if err := db.QueryRow(`SELECT cve_id FROM cves WHERE report_id = ? AND cve_id_text = ? LIMIT 1`, reportID, cveIDText).Scan(&existing); err == nil {
		return existing, nil
	}
	cveID := newID("cve")
	if _, err := db.Exec(`INSERT INTO cves (cve_id, report_id, cve_id_text, description, severity, created_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'))`,
		cveID, reportID, cveIDText, description, severity); err != nil {
		if err2 := db.QueryRow(`SELECT cve_id FROM cves WHERE report_id = ? AND cve_id_text = ? LIMIT 1`, reportID, cveIDText).Scan(&existing); err2 == nil {
			return existing, nil
		}
		return "", err
	}
	return cveID, nil
}

func (db *DB) CreateTechnique(reportID, mitreTechniqueID, mitreTactic, techniqueName string) (string, error) {
	var existing string
	if err := db.QueryRow(`SELECT technique_id FROM techniques WHERE report_id = ? AND mitre_technique_id = ? AND technique_name = ? LIMIT 1`, reportID, mitreTechniqueID, techniqueName).Scan(&existing); err == nil {
		return existing, nil
	}
	techniqueID := newID("technique")
	if _, err := db.Exec(`INSERT INTO techniques (technique_id, report_id, mitre_technique_id, mitre_tactic, technique_name, created_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'))`,
		techniqueID, reportID, mitreTechniqueID, mitreTactic, techniqueName); err != nil {
		if err2 := db.QueryRow(`SELECT technique_id FROM techniques WHERE report_id = ? AND mitre_technique_id = ? AND technique_name = ? LIMIT 1`, reportID, mitreTechniqueID, techniqueName).Scan(&existing); err2 == nil {
			return existing, nil
		}
		return "", err
	}
	return techniqueID, nil
}

func (db *DB) CreateCTIClaim(reportID, claimText, sourceRef, reliability, credibility string) (string, error) {
	var existing string
	if err := db.QueryRow(`SELECT claim_id FROM cti_claims WHERE report_id = ? AND claim_text = ? LIMIT 1`, reportID, claimText).Scan(&existing); err == nil {
		return existing, nil
	}
	claimID := newID("claim")
	rel := sql.NullString{}
	if reliability != "" {
		rel = sql.NullString{String: reliability, Valid: true}
	}
	cred := sql.NullString{}
	if credibility != "" {
		cred = sql.NullString{String: credibility, Valid: true}
	}
	if _, err := db.Exec(`INSERT INTO cti_claims (claim_id, report_id, claim_text, source_reference, reliability_rating, credibility_rating, created_at)
		VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
		claimID, reportID, claimText, sourceRef, rel, cred); err != nil {
		if err2 := db.QueryRow(`SELECT claim_id FROM cti_claims WHERE report_id = ? AND claim_text = ? LIMIT 1`, reportID, claimText).Scan(&existing); err2 == nil {
			return existing, nil
		}
		return "", err
	}
	return claimID, nil
}

func (db *DB) RecordExtractionResultTx(tx *sql.Tx, runID, reportID, entityType, entityID string) error {
	resultID := newID("er")
	_, err := tx.Exec(`INSERT INTO cti_extraction_results (result_id, run_id, report_id, entity_type, entity_id, created_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'))`, resultID, runID, reportID, entityType, entityID)
	return err
}

// createAndRecordTx wraps one entity creation + its membership insert in a single transaction.
func (db *DB) createAndRecordTx(runID, reportID, entityType string, create func(*sql.Tx) (string, error)) (string, error) {
	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	id, err := create(tx)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", fmt.Errorf("entity id empty")
	}
	if err := db.RecordExtractionResultTx(tx, runID, reportID, entityType, id); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return id, nil
}

// Run-aware entity creation: transactional when runID != "", legacy autocommit otherwise.
func (db *DB) createIndicatorRun(runID, reportID, indType, indValue, confidence, sourceRef string) (string, error) {
	if runID == "" {
		return db.CreateIndicator(reportID, indType, indValue, confidence, sourceRef)
	}
	return db.createAndRecordTx(runID, reportID, "indicator", func(tx *sql.Tx) (string, error) {
		return db.createIndicatorTx(tx, reportID, indType, indValue, confidence, sourceRef)
	})
}

func (db *DB) createTechniqueRun(runID, reportID, mitreID, tactic, name string) (string, error) {
	if runID == "" {
		return db.CreateTechnique(reportID, mitreID, tactic, name)
	}
	return db.createAndRecordTx(runID, reportID, "technique", func(tx *sql.Tx) (string, error) {
		return db.CreateTechniqueTx(tx, reportID, mitreID, tactic, name)
	})
}

func (db *DB) createCVERun(runID, reportID, cveText, desc, sev string) (string, error) {
	if runID == "" {
		return db.CreateCVE(reportID, cveText, desc, sev)
	}
	return db.createAndRecordTx(runID, reportID, "cve", func(tx *sql.Tx) (string, error) {
		return db.CreateCVETx(tx, reportID, cveText, desc, sev)
	})
}

func (db *DB) createThreatActorRun(runID, reportID, name, aliases, motivation, sophistication string) (string, error) {
	if runID == "" {
		return db.CreateThreatActor(reportID, name, aliases, motivation, sophistication)
	}
	return db.createAndRecordTx(runID, reportID, "threat_actor", func(tx *sql.Tx) (string, error) {
		return db.CreateThreatActorTx(tx, reportID, name, aliases, motivation, sophistication)
	})
}

func (db *DB) createCampaignRun(runID, reportID, name, actorID, startDate, endDate, objectives string) (string, error) {
	if runID == "" {
		return db.CreateCampaign(reportID, name, actorID, startDate, endDate, objectives)
	}
	return db.createAndRecordTx(runID, reportID, "campaign", func(tx *sql.Tx) (string, error) {
		return db.CreateCampaignTx(tx, reportID, name, actorID, startDate, endDate, objectives)
	})
}

func (db *DB) createMalwareRun(runID, reportID, name, family, malwareType string) (string, error) {
	if runID == "" {
		return db.CreateMalware(reportID, name, family, malwareType)
	}
	return db.createAndRecordTx(runID, reportID, "malware", func(tx *sql.Tx) (string, error) {
		return db.CreateMalwareTx(tx, reportID, name, family, malwareType)
	})
}

func (db *DB) createClaimRun(runID, reportID, text, sourceRef, reliability, credibility string) (string, error) {
	if runID == "" {
		return db.CreateCTIClaim(reportID, text, sourceRef, reliability, credibility)
	}
	return db.createAndRecordTx(runID, reportID, "claim", func(tx *sql.Tx) (string, error) {
		return db.CreateCTIClaimTx(tx, reportID, text, sourceRef, reliability, credibility)
	})
}

func (db *DB) CreateThreatActorTx(tx *sql.Tx, reportID, actorName, aliases, motivation, sophistication string) (string, error) {
	ctx := context.Background()
	var existing string
	if err := tx.QueryRowContext(ctx, `SELECT actor_id FROM threat_actors WHERE report_id = ? AND actor_name = ? LIMIT 1`, reportID, actorName).Scan(&existing); err == nil {
		return existing, nil
	}
	id := newID("actor")
	if _, err := tx.ExecContext(ctx, `INSERT INTO threat_actors (actor_id, report_id, actor_name, aliases, motivation, sophistication, created_at) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`, id, reportID, actorName, aliases, motivation, sophistication); err != nil {
		if err2 := tx.QueryRowContext(ctx, `SELECT actor_id FROM threat_actors WHERE report_id = ? AND actor_name = ? LIMIT 1`, reportID, actorName).Scan(&existing); err2 == nil {
			return existing, nil
		}
		return "", err
	}
	return id, nil
}

func (db *DB) CreateCampaignTx(tx *sql.Tx, reportID, campaignName, actorID, startDate, endDate, objectives string) (string, error) {
	ctx := context.Background()
	var existing string
	if err := tx.QueryRowContext(ctx, `SELECT campaign_id FROM campaigns WHERE report_id = ? AND campaign_name = ? LIMIT 1`, reportID, campaignName).Scan(&existing); err == nil {
		return existing, nil
	}
	id := newID("campaign")
	actorVal := sql.NullString{}
	if actorID != "" {
		actorVal = sql.NullString{String: actorID, Valid: true}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO campaigns (campaign_id, report_id, campaign_name, actor_id, start_date, end_date, objectives, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`, id, reportID, campaignName, actorVal, startDate, endDate, objectives); err != nil {
		if err2 := tx.QueryRowContext(ctx, `SELECT campaign_id FROM campaigns WHERE report_id = ? AND campaign_name = ? LIMIT 1`, reportID, campaignName).Scan(&existing); err2 == nil {
			return existing, nil
		}
		return "", err
	}
	return id, nil
}

func (db *DB) CreateMalwareTx(tx *sql.Tx, reportID, malwareName, family, malwareType string) (string, error) {
	ctx := context.Background()
	var existing string
	if err := tx.QueryRowContext(ctx, `SELECT malware_id FROM malware WHERE report_id = ? AND malware_name = ? LIMIT 1`, reportID, malwareName).Scan(&existing); err == nil {
		return existing, nil
	}
	id := newID("malware")
	if _, err := tx.ExecContext(ctx, `INSERT INTO malware (malware_id, report_id, malware_name, family, type, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))`, id, reportID, malwareName, family, malwareType); err != nil {
		if err2 := tx.QueryRowContext(ctx, `SELECT malware_id FROM malware WHERE report_id = ? AND malware_name = ? LIMIT 1`, reportID, malwareName).Scan(&existing); err2 == nil {
			return existing, nil
		}
		return "", err
	}
	return id, nil
}

func (db *DB) CreateCVETx(tx *sql.Tx, reportID, cveIDText, description, severity string) (string, error) {
	ctx := context.Background()
	var existing string
	if err := tx.QueryRowContext(ctx, `SELECT cve_id FROM cves WHERE report_id = ? AND cve_id_text = ? LIMIT 1`, reportID, cveIDText).Scan(&existing); err == nil {
		return existing, nil
	}
	id := newID("cve")
	if _, err := tx.ExecContext(ctx, `INSERT INTO cves (cve_id, report_id, cve_id_text, description, severity, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))`, id, reportID, cveIDText, description, severity); err != nil {
		if err2 := tx.QueryRowContext(ctx, `SELECT cve_id FROM cves WHERE report_id = ? AND cve_id_text = ? LIMIT 1`, reportID, cveIDText).Scan(&existing); err2 == nil {
			return existing, nil
		}
		return "", err
	}
	return id, nil
}

func (db *DB) CreateTechniqueTx(tx *sql.Tx, reportID, mitreTechniqueID, mitreTactic, techniqueName string) (string, error) {
	ctx := context.Background()
	var existing string
	if err := tx.QueryRowContext(ctx, `SELECT technique_id FROM techniques WHERE report_id = ? AND mitre_technique_id = ? AND technique_name = ? LIMIT 1`, reportID, mitreTechniqueID, techniqueName).Scan(&existing); err == nil {
		return existing, nil
	}
	id := newID("technique")
	if _, err := tx.ExecContext(ctx, `INSERT INTO techniques (technique_id, report_id, mitre_technique_id, mitre_tactic, technique_name, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))`, id, reportID, mitreTechniqueID, mitreTactic, techniqueName); err != nil {
		if err2 := tx.QueryRowContext(ctx, `SELECT technique_id FROM techniques WHERE report_id = ? AND mitre_technique_id = ? AND technique_name = ? LIMIT 1`, reportID, mitreTechniqueID, techniqueName).Scan(&existing); err2 == nil {
			return existing, nil
		}
		return "", err
	}
	return id, nil
}

func (db *DB) CreateCTIClaimTx(tx *sql.Tx, reportID, claimText, sourceRef, reliability, credibility string) (string, error) {
	ctx := context.Background()
	var existing string
	if err := tx.QueryRowContext(ctx, `SELECT claim_id FROM cti_claims WHERE report_id = ? AND claim_text = ? LIMIT 1`, reportID, claimText).Scan(&existing); err == nil {
		return existing, nil
	}
	id := newID("claim")
	rel := sql.NullString{}
	if reliability != "" {
		rel = sql.NullString{String: reliability, Valid: true}
	}
	cred := sql.NullString{}
	if credibility != "" {
		cred = sql.NullString{String: credibility, Valid: true}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO cti_claims (claim_id, report_id, claim_text, source_reference, reliability_rating, credibility_rating, created_at) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`, id, reportID, claimText, sourceRef, rel, cred); err != nil {
		if err2 := tx.QueryRowContext(ctx, `SELECT claim_id FROM cti_claims WHERE report_id = ? AND claim_text = ? LIMIT 1`, reportID, claimText).Scan(&existing); err2 == nil {
			return existing, nil
		}
		return "", err
	}
	return id, nil
}

func (db *DB) GetCTIReportIndicators(reportID string) ([]Indicator, error) {
	rows, err := db.Query(`SELECT indicator_id, report_id, indicator_type, indicator_value, confidence, source_reference, created_at FROM indicators WHERE report_id = ? ORDER BY created_at DESC`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var indicators []Indicator
	for rows.Next() {
		var i Indicator
		var conf, srcRef sql.NullString
		if err := rows.Scan(&i.IndicatorID, &i.ReportID, &i.IndicatorType, &i.IndicatorValue, &conf, &srcRef, &i.CreatedAt); err != nil {
			return nil, err
		}
		if conf.Valid {
			i.Confidence = conf.String
		}
		if srcRef.Valid {
			i.SourceReference = srcRef.String
		}
		indicators = append(indicators, i)
	}
	return indicators, nil
}

func (db *DB) GetCTIReportThreatActors(reportID string) ([]ThreatActor, error) {
	rows, err := db.Query(`SELECT actor_id, report_id, actor_name, aliases, motivation, sophistication, created_at FROM threat_actors WHERE report_id = ? ORDER BY created_at DESC`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var actors []ThreatActor
	for rows.Next() {
		var a ThreatActor
		var aliases, motivation, sophistication sql.NullString
		if err := rows.Scan(&a.ActorID, &a.ReportID, &a.ActorName, &aliases, &motivation, &sophistication, &a.CreatedAt); err != nil {
			return nil, err
		}
		if aliases.Valid {
			a.Aliases = aliases.String
		}
		if motivation.Valid {
			a.Motivation = motivation.String
		}
		if sophistication.Valid {
			a.Sophistication = sophistication.String
		}
		actors = append(actors, a)
	}
	return actors, nil
}

func (db *DB) GetCTIReportCampaigns(reportID string) ([]Campaign, error) {
	rows, err := db.Query(`SELECT campaign_id, report_id, campaign_name, actor_id, start_date, end_date, objectives, created_at FROM campaigns WHERE report_id = ? ORDER BY created_at DESC`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var campaigns []Campaign
	for rows.Next() {
		var c Campaign
		var actorID, startDate, endDate, objectives sql.NullString
		if err := rows.Scan(&c.CampaignID, &c.ReportID, &c.CampaignName, &actorID, &startDate, &endDate, &objectives, &c.CreatedAt); err != nil {
			return nil, err
		}
		if actorID.Valid {
			c.ActorID = actorID.String
		}
		if startDate.Valid {
			c.StartDate = startDate.String
		}
		if endDate.Valid {
			c.EndDate = endDate.String
		}
		if objectives.Valid {
			c.Objectives = objectives.String
		}
		campaigns = append(campaigns, c)
	}
	return campaigns, nil
}

func (db *DB) GetCTIReportMalware(reportID string) ([]Malware, error) {
	rows, err := db.Query(`SELECT malware_id, report_id, malware_name, family, type, created_at FROM malware WHERE report_id = ? ORDER BY created_at DESC`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var malware []Malware
	for rows.Next() {
		var m Malware
		var family, mType sql.NullString
		if err := rows.Scan(&m.MalwareID, &m.ReportID, &m.MalwareName, &family, &mType, &m.CreatedAt); err != nil {
			return nil, err
		}
		if family.Valid {
			m.Family = family.String
		}
		if mType.Valid {
			m.Type = mType.String
		}
		malware = append(malware, m)
	}
	return malware, nil
}

func (db *DB) GetCTIReportCVEs(reportID string) ([]CVE, error) {
	rows, err := db.Query(`SELECT cve_id, report_id, cve_id_text, description, severity, created_at FROM cves WHERE report_id = ? ORDER BY created_at DESC`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cves []CVE
	for rows.Next() {
		var c CVE
		var desc, sev sql.NullString
		if err := rows.Scan(&c.CVEID, &c.ReportID, &c.CVEIDText, &desc, &sev, &c.CreatedAt); err != nil {
			return nil, err
		}
		if desc.Valid {
			c.Description = desc.String
		}
		if sev.Valid {
			c.Severity = sev.String
		}
		cves = append(cves, c)
	}
	return cves, nil
}

func (db *DB) GetCTIReportTechniques(reportID string) ([]Technique, error) {
	rows, err := db.Query(`SELECT technique_id, report_id, mitre_technique_id, mitre_tactic, technique_name, created_at FROM techniques WHERE report_id = ? ORDER BY created_at DESC`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var techniques []Technique
	for rows.Next() {
		var t Technique
		var mitreID, tactic, name sql.NullString
		if err := rows.Scan(&t.TechniqueID, &t.ReportID, &mitreID, &tactic, &name, &t.CreatedAt); err != nil {
			return nil, err
		}
		if mitreID.Valid {
			t.MitreTechniqueID = mitreID.String
		}
		if tactic.Valid {
			t.MitreTactic = tactic.String
		}
		if name.Valid {
			t.TechniqueName = name.String
		}
		techniques = append(techniques, t)
	}
	return techniques, nil
}

func (db *DB) GetCTIReportClaims(reportID string) ([]CTIClaim, error) {
	rows, err := db.Query(`SELECT claim_id, report_id, claim_text, source_reference, reliability_rating, credibility_rating, assessed_by, assessment_date, assessment_reason, created_at FROM cti_claims WHERE report_id = ? ORDER BY created_at DESC`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var claims []CTIClaim
	for rows.Next() {
		var c CTIClaim
		var srcRef, reliability, credibility, assessedBy, assessDate, reason sql.NullString
		if err := rows.Scan(&c.ClaimID, &c.ReportID, &c.ClaimText, &srcRef, &reliability, &credibility, &assessedBy, &assessDate, &reason, &c.CreatedAt); err != nil {
			return nil, err
		}
		if srcRef.Valid {
			c.SourceReference = srcRef.String
		}
		if reliability.Valid {
			c.Reliability = reliability.String
		}
		if credibility.Valid {
			c.Credibility = credibility.String
		}
		if assessedBy.Valid {
			c.AssessedBy = assessedBy.String
		}
		if assessDate.Valid {
			c.AssessmentDate = assessDate.String
		}
		if reason.Valid {
			c.AssessmentReason = reason.String
		}
		claims = append(claims, c)
	}
	return claims, nil
}

// --- CTI Import Handler ---

func handleCTIImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	// Hard request-size limit (32 MB multipart, including overhead).
	r.Body = http.MaxBytesReader(w, r.Body, 33<<20)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid multipart form")
		return
	}

	clientID := r.FormValue("client_id")
	if clientID == "" {
		clientID = session.ClientID
	}
	// Mutation permission (in addition to route middleware).
	if role, err := globalDB.GetUserRole(session.UserID); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "user not found")
		return
	} else if rp, ok := GetPermission(role); !ok || !rp.CanCreateCTI {
		writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}
	if clientID == "" || !CanAccessClient(session.UserID, clientID) {
		writeJSONError(w, http.StatusForbidden, "TENANT_ISOLATION_VIOLATION", "not authorized for this client")
		return
	}

	sourceName := r.FormValue("source_name")
	if sourceName == "" {
		sourceName = "CTI Import"
	}

	file, fh, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "no file uploaded")
		return
	}
	defer file.Close()

	// Sanitize filename and validate supported types before any write.
	safeName := filepath.Base(fh.Filename)
	if safeName == "." || safeName == ".." || strings.TrimSpace(safeName) == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid filename")
		return
	}
	ext := strings.ToLower(filepath.Ext(safeName))
	if ext != ".json" && ext != ".html" && ext != ".htm" {
		writeJSONError(w, http.StatusUnsupportedMediaType, "UNSUPPORTED_FILE_TYPE", "only .json/.html files are supported")
		return
	}

	// Read file content and compute checksum
	data, err := io.ReadAll(file)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to read file")
		return
	}
	checksum := sha256Sum(data)

	idemKey := r.FormValue("idempotency_key")
	// Payload fingerprint over the logical operation: tenant, content, source name.
	fpRaw := clientID + "|" + sha256Sum(data) + "|" + r.FormValue("source_name") + "|" + safeName
	fp := sha256Sum([]byte(fpRaw))

	// HTTP idempotency — BEFORE any filesystem/CTI write:
	// same client+key: same fingerprint -> existing run; different -> 409.
	if idemKey != "" {
		var priorRun, priorReport, priorFP string
		rowErr := globalDB.QueryRow(`SELECT run_id, report_id, COALESCE(payload_fingerprint, '') FROM cti_ingestion_runs WHERE client_id = ? AND request_idempotency_key = ? LIMIT 1`, clientID, idemKey).Scan(&priorRun, &priorReport, &priorFP)
		if rowErr == nil {
			if priorFP != "" && priorFP != fp {
				writeJSONError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "same idempotency key with different payload")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"report_id": priorReport, "run_id": priorRun, "status": "EXISTING"})
			return
		}
	}

	// Store file artifact — safe path confined to storageDir.
	artifactID := newID("artifact")
	storageDir := ctiArtifactDir
	os.MkdirAll(storageDir, 0755)
	filePath := filepath.Join(storageDir, artifactID+"_"+safeName)
	if rel, err := filepath.Rel(storageDir, filePath); err != nil || strings.HasPrefix(rel, "..") {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid artifact path")
		return
	}
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to store file")
		return
	}
	_, err = globalDB.Exec(`INSERT INTO file_artifacts (artifact_id, file_name, file_path, checksum, file_type, metadata_ref, created_at)
		VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
		artifactID, safeName, filePath, checksum, ext, sourceName)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to record artifact")
		return
	}

	// Reuse existing source by name (dedup identity includes source).
	sourceID, err := globalDB.GetOrCreateCTISourceByName(sourceName)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create source")
		return
	}

	// Document dedup: (client_id, checksum, source) — unique indexes guarantee this.
	title := strings.TrimSuffix(safeName, filepath.Ext(safeName))
	reportID, err := globalDB.FindCTIReportByChecksum(clientID, checksum, sourceID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check dedup")
		return
	}
	// Cleanup helper: remove staged artifact when this request loses the idempotency race.
	cleanupStagedArtifact := func() {
		_, _ = globalDB.Exec(`DELETE FROM file_artifacts WHERE artifact_id = ?`, artifactID)
		_ = os.Remove(filePath)
	}
	// Atomic idempotency conflict handling: if run insert fails UNIQUE,
	// re-read by key and map to EXISTING (same fingerprint) or 409 (different).
	resolveIdemConflict := func() bool {
		if idemKey == "" {
			return false
		}
		var priorRun, priorReport, priorFP string
		if err := globalDB.QueryRow(`SELECT run_id, report_id, COALESCE(payload_fingerprint, '') FROM cti_ingestion_runs WHERE client_id = ? AND request_idempotency_key = ? LIMIT 1`, clientID, idemKey).Scan(&priorRun, &priorReport, &priorFP); err == nil {
			if priorFP != "" && priorFP != fp {
				writeJSONError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "same idempotency key with different payload")
				return true
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"report_id": priorReport, "run_id": priorRun, "status": "EXISTING"})
			return true
		}
		return false
	}
	var runID string
	var extracted map[string]int
	importStatus := "INGESTED"
	analysisStatus := ""
	var analysisErr string
	if reportID == "" {
		reportID, err = globalDB.CreateCTIReport(clientID, sourceID, title, session.UserID, "", safeName, checksum)
		if err != nil {
			cleanupStagedArtifact()
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create report")
			return
		}
		// Dedup race: if another request already linked its artifact to this
		// report, keep the winner's association — never overwrite verified provenance.
		if set, err := globalDB.SetReportArtifact(reportID, artifactID); err != nil {
			cleanupStagedArtifact()
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to link artifact")
			return
		} else if !set {
			cleanupStagedArtifact()
		}
		if runID, err = globalDB.CreateIngestionRunWithFingerprint(reportID, clientID, "1", idemKey, fp); err != nil {
			cleanupStagedArtifact()
			if resolveIdemConflict() {
				return
			}
			writeJSONError(w, http.StatusConflict, "CONFLICT", "idempotency or dedup conflict")
			return
		}
		if err := globalDB.SetIngestionRunStatus(runID, "ANALYZING", ""); err != nil {
			_ = globalDB.SetIngestionRunStatus(runID, "FAILED", "status_update_error")
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to start analysis run")
			return
		}
		contentType := detectContentType(data, safeName)
		if contentType == "json" {
			extracted, err = extractFromJSONWithRun(globalDB, reportID, runID, data)
		} else if contentType == "html" {
			extracted, err = extractFromHTMLWithRun(globalDB, reportID, runID, data)
		} else {
			extracted = map[string]int{}
			err = nil
		}
		if err != nil {
			if serr := globalDB.SetIngestionRunStatus(runID, "FAILED", "extraction_error"); serr != nil {
				writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to record extraction failure")
				return
			}
			analysisStatus = "FAILED"
			analysisErr = "extraction_error"
		} else {
			if serr := globalDB.SetIngestionRunStatus(runID, "ANALYZED", ""); serr != nil {
				_ = globalDB.SetIngestionRunStatus(runID, "FAILED", "finalization_error")
				writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to finalize run")
				return
			}
			if serr := globalDB.UpdateCTIReportStatusIfNotAnalyzed(reportID); serr != nil {
				writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to finalize report status")
				return
			}
			analysisStatus = "ANALYZED"
		}
		if extracted == nil {
			extracted = map[string]int{}
		}
	} else {
		// Existing document: record a fresh attempt (parser retry semantics).
		// Artifact policy: never overwrite verified provenance of an existing report.
		// The newly staged artifact is removed; the report keeps its original artifact_id.
		_, _ = globalDB.Exec(`DELETE FROM file_artifacts WHERE artifact_id = ?`, artifactID)
		_ = os.Remove(filePath)
		artifactID = ""
		runID, err = globalDB.CreateIngestionRunWithFingerprint(reportID, clientID, "1", idemKey, fp)
		if err != nil {
			if resolveIdemConflict() {
				return
			}
			writeJSONError(w, http.StatusConflict, "CONFLICT", "idempotency conflict")
			return
		}
		if err := globalDB.SetIngestionRunStatus(runID, "ANALYZING", ""); err != nil {
			_ = globalDB.SetIngestionRunStatus(runID, "FAILED", "status_update_error")
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to start analysis run")
			return
		}
		contentType := detectContentType(data, safeName)
		if contentType == "json" {
			extracted, err = extractFromJSONWithRun(globalDB, reportID, runID, data)
		} else if contentType == "html" {
			extracted, err = extractFromHTMLWithRun(globalDB, reportID, runID, data)
		} else {
			extracted = map[string]int{}
			err = nil
		}
		if err != nil {
			if serr := globalDB.SetIngestionRunStatus(runID, "FAILED", "extraction_error"); serr != nil {
				writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to record extraction failure")
				return
			}
			analysisStatus = "FAILED"
			analysisErr = "extraction_error"
		} else {
			if serr := globalDB.SetIngestionRunStatus(runID, "ANALYZED", ""); serr != nil {
				_ = globalDB.SetIngestionRunStatus(runID, "FAILED", "finalization_error")
				writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to finalize run")
				return
			}
			if serr := globalDB.UpdateCTIReportStatusIfNotAnalyzed(reportID); serr != nil {
				writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to finalize report status")
				return
			}
			analysisStatus = "ANALYZED"
		}
		if extracted == nil {
			extracted = map[string]int{}
		}
	}

	// Persisted report status is the source of truth (never fabricated).
	persistedStatus := ""
	if r, err := globalDB.GetCTIReport(reportID); err == nil && r != nil {
		persistedStatus = r.Status
	}
	auditResult := "success"
	if analysisStatus == "FAILED" {
		auditResult = "partial_failure"
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: clientID,
		Action:   "cti.import",
		Resource: "/api/v1/cti/import",
		Result:   auditResult,
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	resp := map[string]interface{}{
		"report_id":        reportID,
		"run_id":           runID,
		"import_status":    importStatus,
		"analysis_status":  analysisStatus,
		"persisted_status": persistedStatus,
		"checksum":         checksum,
		"artifact_id":      artifactID,
		"extracted":        extracted,
	}
	if analysisErr != "" {
		resp["error_code"] = analysisErr
	}
	json.NewEncoder(w).Encode(resp)
}

// --- CTI Report Detail Handler ---

func handleCTIReportDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	reportID := r.PathValue("report_id")
	report, err := globalDB.GetCTIReport(reportID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get report")
		return
	}
	if report == nil {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "report not found")
		return
	}

	if !CanAccessClient(session.UserID, report.ClientID) {
		writeJSONError(w, http.StatusForbidden, "TENANT_ISOLATION_VIOLATION", "not authorized for this client")
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: report.ClientID,
		Action:   "cti.report.read",
		Resource: "/api/v1/cti/reports/" + reportID,
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(report)
}

// --- CTI Analyze Handler ---

func handleCTIAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	reportID := r.PathValue("report_id")
	report, err := globalDB.GetCTIReport(reportID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get report")
		return
	}
	if report == nil {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "report not found")
		return
	}

	if !CanAccessClient(session.UserID, report.ClientID) {
		writeJSONError(w, http.StatusForbidden, "TENANT_ISOLATION_VIOLATION", "not authorized for this client")
		return
	}

	// Mutation permission (in addition to route middleware): only CanCreateCTI may analyze.
	if role, err := globalDB.GetUserRole(session.UserID); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "user not found")
		return
	} else if rp, ok := GetPermission(role); !ok || !rp.CanCreateCTI {
		writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}

	// Explicit report->artifact association (never metadata_ref/filename lookup).
	if report.ArtifactID == "" {
		runID, _ := globalDB.CreateIngestionRun(reportID, report.ClientID, "1", "")
		if runID != "" {
			_ = globalDB.SetIngestionRunStatus(runID, "FAILED", "artifact_missing")
		}
		writeJSONError(w, http.StatusUnprocessableEntity, "ARTIFACT_MISSING", "report has no associated artifact")
		return
	}
	artifactPath := ""
	var storedChecksum string
	err = globalDB.QueryRow(`SELECT file_path, checksum FROM file_artifacts WHERE artifact_id = ? LIMIT 1`, report.ArtifactID).Scan(&artifactPath, &storedChecksum)
	if err != nil {
		runID, _ := globalDB.CreateIngestionRun(reportID, report.ClientID, "1", "")
		if runID != "" {
			_ = globalDB.SetIngestionRunStatus(runID, "FAILED", "artifact_missing")
		}
		writeJSONError(w, http.StatusUnprocessableEntity, "ARTIFACT_MISSING", "associated artifact not found")
		return
	}

	runID, err := globalDB.CreateIngestionRun(reportID, report.ClientID, "1", "")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create analysis run")
		return
	}
	_ = globalDB.SetIngestionRunStatus(runID, "ANALYZING", "")

	counts := map[string]int{}
	data, err := os.ReadFile(artifactPath)
	if err != nil {
		_ = globalDB.SetIngestionRunStatus(runID, "FAILED", "artifact_unreadable")
		writeJSONError(w, http.StatusUnprocessableEntity, "ARTIFACT_UNREADABLE", "artifact file unreadable")
		return
	}
	// Verify checksum against artifact bytes before analysis.
	if sha256Sum(data) != storedChecksum || (report.Checksum != "" && sha256Sum(data) != report.Checksum) {
		_ = globalDB.SetIngestionRunStatus(runID, "FAILED", "checksum_mismatch")
		writeJSONError(w, http.StatusUnprocessableEntity, "CHECKSUM_MISMATCH", "artifact checksum mismatch")
		return
	}
	contentType := detectContentType(data, report.OriginalContentRef)
	if contentType == "json" {
		counts, err = extractFromJSONWithRun(globalDB, reportID, runID, data)
	} else if contentType == "html" {
		counts, err = extractFromHTMLWithRun(globalDB, reportID, runID, data)
	} else {
		counts = map[string]int{}
		err = nil
	}
	if err != nil {
		_ = globalDB.SetIngestionRunStatus(runID, "FAILED", "extraction_error")
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "extraction failed: "+err.Error())
		return
	}

	if err := globalDB.SetIngestionRunStatus(runID, "ANALYZED", ""); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to finalize run")
		return
	}
	if err := globalDB.UpdateCTIReportStatusIfNotAnalyzed(reportID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update status")
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: report.ClientID,
		Action:   "cti.analyze",
		Resource: "/api/v1/cti/reports/" + reportID + "/analyze",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"report_id": reportID,
		"status":    "ANALYZED",
		"extracted": counts,
	})
}

// --- Provenance handler (M7-A) ---

func handleCTIProvenance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	reportID := r.PathValue("report_id")
	report, err := globalDB.GetCTIReport(reportID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get report")
		return
	}
	if report == nil {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "report not found")
		return
	}
	if !CanAccessClient(session.UserID, report.ClientID) {
		writeJSONError(w, http.StatusForbidden, "TENANT_ISOLATION_VIOLATION", "not authorized for this client")
		return
	}
	// Source facts
	var sourceID, sourceName, sourceType, sourceReliability string
	if report.SourceID != "" {
		if src, err := globalDB.GetCTISource(report.SourceID); err == nil && src != nil {
			sourceID, sourceName, sourceType, sourceReliability = src.SourceID, src.SourceName, src.SourceType, src.Reliability
		}
	}
	// Artifact facts via explicit report->artifact association (never metadata_ref).
	// Legacy reports without artifact_id -> honest UNKNOWN, never claimed verified.
	var artID, artChecksum, artPath string
	checksumVerified := ""
	checksumState := "UNKNOWN"
	if report.ArtifactID != "" {
		if err := globalDB.QueryRow(`SELECT artifact_id, checksum, file_path FROM file_artifacts WHERE artifact_id = ? LIMIT 1`, report.ArtifactID).Scan(&artID, &artChecksum, &artPath); err == nil {
			checksumState = "MISMATCH"
			checksumVerified = "false"
			if data, err2 := os.ReadFile(artPath); err2 == nil {
				if sha256Sum(data) == artChecksum && (report.Checksum == "" || sha256Sum(data) == report.Checksum) {
					checksumState = "OK"
					checksumVerified = "true"
				}
			}
		}
	}
	// Ingestion run summary (legacy reports have none — null, never faked)
	var ingestion interface{} = nil
	if runs, err := globalDB.ListIngestionRuns(reportID); err == nil && len(runs) > 0 {
		latest := runs[0]
		ingestion = map[string]interface{}{
			"run_id": latest.RunID, "status": latest.Status,
			"parser_version": latest.ParserVersion, "created_at": latest.CreatedAt,
			"attempt_count": len(runs),
		}
	}
	// counts
	cnt := func(q string) int {
		var n int
		_ = globalDB.QueryRow(q, reportID).Scan(&n)
		return n
	}
	entities := map[string]int{
		"indicators": cnt(`SELECT COUNT(*) FROM indicators WHERE report_id = ?`),
		"techniques": cnt(`SELECT COUNT(*) FROM techniques WHERE report_id = ?`),
		"cves":       cnt(`SELECT COUNT(*) FROM cves WHERE report_id = ?`),
		"claims":     cnt(`SELECT COUNT(*) FROM cti_claims WHERE report_id = ?`),
		"threat_actors": cnt(`SELECT COUNT(*) FROM threat_actors WHERE report_id = ?`),
		"campaigns":  cnt(`SELECT COUNT(*) FROM campaigns WHERE report_id = ?`),
		"malware":    cnt(`SELECT COUNT(*) FROM malware WHERE report_id = ?`),
	}
	// confidence separation (never averaged, null when unverified)
	conf := func(v string) map[string]interface{} {
		if v == "" {
			return map[string]interface{}{"value": nil, "verified": false}
		}
		return map[string]interface{}{"value": v, "verified": true}
	}
	claimConf := func(v string) map[string]interface{} { return conf(v) }
	globalAuditLogger.Log(AuditEvent{
		UserID: session.UserID, ClientID: report.ClientID,
		Action: "cti.provenance.read", Resource: "/api/v1/cti/reports/" + reportID + "/provenance",
		Result: "success", SourceIP: r.RemoteAddr,
	})
	ocheck := map[string]interface{}{"source_reliability": conf(sourceReliability), "extraction_confidence": claimConf(""), "claim_confidence": claimConf("")}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"report_id": reportID, "client_id": report.ClientID,
		"source": map[string]interface{}{"source_id": sourceID, "source_name": sourceName, "source_type": sourceType, "source_reliability": sourceReliability},
		"artifact": map[string]interface{}{"artifact_id": artID, "checksum": artChecksum, "original_content_ref": report.OriginalContentRef, "checksum_verified": checksumVerified == "true", "checksum_state": checksumState},
		"ingestion": ingestion,
		"entities":  entities,
		"confidence": ocheck,
		"analysis_state": report.Status,
	})
}

func handleCTIIOCs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	reportID := r.PathValue("report_id")
	report, err := globalDB.GetCTIReport(reportID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get report")
		return
	}
	if report == nil {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "report not found")
		return
	}

	if !CanAccessClient(session.UserID, report.ClientID) {
		writeJSONError(w, http.StatusForbidden, "TENANT_ISOLATION_VIOLATION", "not authorized for this client")
		return
	}

	indicators, err := globalDB.GetCTIReportIndicators(reportID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list IOCs")
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: report.ClientID,
		Action:   "cti.iocs.read",
		Resource: "/api/v1/cti/reports/" + reportID + "/iocs",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"report_id": reportID,
		"iocs":      indicators,
		"count":     len(indicators),
	})
}

// --- TTPs handler ---

func handleCTITTPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	reportID := r.PathValue("report_id")
	report, err := globalDB.GetCTIReport(reportID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get report")
		return
	}
	if report == nil {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "report not found")
		return
	}

	if !CanAccessClient(session.UserID, report.ClientID) {
		writeJSONError(w, http.StatusForbidden, "TENANT_ISOLATION_VIOLATION", "not authorized for this client")
		return
	}

	techniques, err := globalDB.GetCTIReportTechniques(reportID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list TTPs")
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: report.ClientID,
		Action:   "cti.ttps.read",
		Resource: "/api/v1/cti/reports/" + reportID + "/ttps",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"report_id": reportID,
		"ttps":      techniques,
		"count":     len(techniques),
	})
}

// --- CVEs handler ---

func handleCTICVEs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	reportID := r.PathValue("report_id")
	report, err := globalDB.GetCTIReport(reportID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get report")
		return
	}
	if report == nil {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "report not found")
		return
	}

	if !CanAccessClient(session.UserID, report.ClientID) {
		writeJSONError(w, http.StatusForbidden, "TENANT_ISOLATION_VIOLATION", "not authorized for this client")
		return
	}

	cves, err := globalDB.GetCTIReportCVEs(reportID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list CVEs")
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: report.ClientID,
		Action:   "cti.cves.read",
		Resource: "/api/v1/cti/reports/" + reportID + "/cves",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"report_id": reportID,
		"cves":      cves,
		"count":     len(cves),
	})
}

// --- Evidence handler ---

func handleCTIEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	reportID := r.PathValue("report_id")
	report, err := globalDB.GetCTIReport(reportID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get report")
		return
	}
	if report == nil {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "report not found")
		return
	}

	if !CanAccessClient(session.UserID, report.ClientID) {
		writeJSONError(w, http.StatusForbidden, "TENANT_ISOLATION_VIOLATION", "not authorized for this client")
		return
	}

	claims, err := globalDB.GetCTIReportClaims(reportID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list evidence")
		return
	}

	threatActors, err := globalDB.GetCTIReportThreatActors(reportID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list threat actors")
		return
	}

	campaigns, err := globalDB.GetCTIReportCampaigns(reportID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list campaigns")
		return
	}

	malware, err := globalDB.GetCTIReportMalware(reportID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list malware")
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: report.ClientID,
		Action:   "cti.evidence.read",
		Resource: "/api/v1/cti/reports/" + reportID + "/evidence",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"report_id":   reportID,
		"claims":      claims,
		"threat_actors": threatActors,
		"campaigns":   campaigns,
		"malware":     malware,
		"counts": map[string]int{
			"claims":       len(claims),
			"threat_actors": len(threatActors),
			"campaigns":    len(campaigns),
			"malware":      len(malware),
		},
	})
}

// --- Extraction helpers ---

func sha256Sum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func detectContentType(data []byte, filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == ".json" {
		return "json"
	}
	if ext == ".html" || ext == ".htm" {
		return "html"
	}
	// Try to detect by content
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return "json"
	}
	if strings.HasPrefix(strings.ToLower(trimmed), "<!DOCTYPE") || strings.HasPrefix(strings.ToLower(trimmed), "<html") {
		return "html"
	}
	return "unknown"
}

var (
	ipv4Regex      = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	domainRegex    = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)
	sha256Regex    = regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)
	sha1Regex      = regexp.MustCompile(`\b[0-9a-fA-F]{40}\b`)
	md5Regex       = regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`)
	urlRegex       = regexp.MustCompile(`https?://[^\s<>"')]+`)
	emailRegex     = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	cveRegex       = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	mitreRegex     = regexp.MustCompile(`T\d{4}\.\d{3}`)
)

// M7-A: extraction attempt wrapper — creates a run, extracts with membership
// recording inside one transaction per entity kind, and finalizes ANALYZED.
// On any extraction or membership failure: FAILED with error_code, no fabricated counts.
func extractWithRun(db *DB, reportID, clientID string, data []byte, contentType, idemKey string) (map[string]int, string, error) {
	runID, err := db.CreateIngestionRunWithFingerprint(reportID, clientID, "1", idemKey, "")
	if err != nil {
		return nil, "", err
	}
	_ = db.SetIngestionRunStatus(runID, "ANALYZING", "")
	var counts map[string]int
	if contentType == "json" {
		counts, err = extractFromJSONWithRun(db, reportID, runID, data)
	} else if contentType == "html" {
		counts, err = extractFromHTMLWithRun(db, reportID, runID, data)
	} else {
		counts = map[string]int{}
		err = nil
	}
	if err != nil {
		_ = db.SetIngestionRunStatus(runID, "FAILED", "extraction_error")
		return nil, runID, err
	}
	if cerr := db.SetIngestionRunStatus(runID, "ANALYZED", ""); cerr != nil {
		_ = db.SetIngestionRunStatus(runID, "FAILED", "finalization_error")
		return nil, runID, cerr
	}
	_ = db.UpdateCTIReportStatusIfNotAnalyzed(reportID)
	return counts, runID, nil
}

// UpdateCTIReportStatusIfNotAnalyzed moves INGESTED -> ANALYZED (forward only).
func (db *DB) UpdateCTIReportStatusIfNotAnalyzed(reportID string) error {
	_, err := db.Exec(`UPDATE cti_reports SET status = 'ANALYZED', updated_at = datetime('now') WHERE report_id = ? AND status IN ('INGESTED','NEW','ANALYSIS_PENDING')`, reportID)
	return err
}

func extractFromJSON(db *DB, reportID string, data []byte) (map[string]int, error) {
	return extractFromJSONWithRun(db, reportID, "", data)
}

func extractFromJSONWithRun(db *DB, reportID, runID string, data []byte) (map[string]int, error) {
	var doc struct {
		Title           string   `json:"title"`
		Indicators      []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"indicators"`
		Techniques    []string `json:"techniques"`
		CVEs          []string `json:"cves"`
		ThreatActors  []struct {
			Name    string `json:"name"`
			Aliases string `json:"aliases"`
		} `json:"threat_actors"`
		Campaigns     []struct {
			Name string `json:"name"`
		} `json:"campaigns"`
		Malware       []struct {
			Name string `json:"name"`
			Family string `json:"family"`
		} `json:"malware"`
		Claims        []struct {
			Text string `json:"text"`
		} `json:"claims"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	counts := map[string]int{}
	var errs []string
	for _, ind := range doc.Indicators {
		if _, err := db.createIndicatorRun(runID, reportID, ind.Type, ind.Value, "", ""); err != nil {
			errs = append(errs, "create indicator: "+err.Error())
			continue
		}
		counts["iocs"]++
	}

	for _, t := range doc.Techniques {
		mitreID := ""
		if mitreRegex.MatchString(t) {
			mitreID = t
		}
		if _, err := db.createTechniqueRun(runID, reportID, mitreID, "", t); err != nil {
			errs = append(errs, "create technique: "+err.Error())
			continue
		}
		counts["ttps"]++
	}

	for _, c := range doc.CVEs {
		if _, err := db.createCVERun(runID, reportID, c, "", ""); err != nil {
			errs = append(errs, "create cve: "+err.Error())
			continue
		}
		counts["cves"]++
	}

	for _, ta := range doc.ThreatActors {
		if _, err := db.createThreatActorRun(runID, reportID, ta.Name, ta.Aliases, "", ""); err != nil {
			errs = append(errs, "create threat actor: "+err.Error())
			continue
		}
		counts["threat_actors"]++
	}

	for _, c := range doc.Campaigns {
		if _, err := db.createCampaignRun(runID, reportID, c.Name, "", "", "", ""); err != nil {
			errs = append(errs, "create campaign: "+err.Error())
			continue
		}
		counts["campaigns"]++
	}

	for _, m := range doc.Malware {
		if _, err := db.createMalwareRun(runID, reportID, m.Name, m.Family, ""); err != nil {
			errs = append(errs, "create malware: "+err.Error())
			continue
		}
		counts["malware"]++
	}

	for _, cl := range doc.Claims {
		if _, err := db.createClaimRun(runID, reportID, cl.Text, "", "", ""); err != nil {
			errs = append(errs, "create claim: "+err.Error())
			continue
		}
		counts["claims"]++
	}
	if len(errs) > 0 {
		return counts, fmt.Errorf("extraction failures: %s", strings.Join(errs, "; "))
	}

	return counts, nil
}

func extractFromHTML(db *DB, reportID string, data []byte) (map[string]int, error) {
	return extractFromHTMLWithRun(db, reportID, "", data)
}

func extractFromHTMLWithRun(db *DB, reportID, runID string, data []byte) (map[string]int, error) {
	text := string(data)
	// Strip HTML tags roughly
	re := regexp.MustCompile(`<[^>]*>`)
	text = re.ReplaceAllString(text, " ")
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")

	counts := map[string]int{}
	var errs []string

	// Extract IPs
	ips := ipv4Regex.FindAllString(text, -1)
	seen := map[string]bool{}
	for _, ip := range ips {
		if !seen[ip] {
			seen[ip] = true
			if _, err := db.createIndicatorRun(runID, reportID, "ipv4", ip, "", ""); err != nil {
				errs = append(errs, "create indicator: "+err.Error())
			} else {
				counts["iocs"]++
			}
		}
	}

	// Extract domains
	domains := domainRegex.FindAllString(text, -1)
	for _, d := range domains {
		if !seen[d] {
			seen[d] = true
			if _, err := db.createIndicatorRun(runID, reportID, "domain", d, "", ""); err != nil {
				errs = append(errs, "create indicator: "+err.Error())
			} else {
				counts["iocs"]++
			}
		}
	}

	// Extract URLs
	urls := urlRegex.FindAllString(text, -1)
	for _, u := range urls {
		if !seen[u] {
			seen[u] = true
			if _, err := db.createIndicatorRun(runID, reportID, "url", u, "", ""); err != nil {
				errs = append(errs, "create indicator: "+err.Error())
			} else {
				counts["iocs"]++
			}
		}
	}

	// Extract emails
	emails := emailRegex.FindAllString(text, -1)
	for _, e := range emails {
		if !seen[e] {
			seen[e] = true
			if _, err := db.createIndicatorRun(runID, reportID, "email", e, "", ""); err != nil {
				errs = append(errs, "create indicator: "+err.Error())
			} else {
				counts["iocs"]++
			}
		}
	}

	// Extract hashes
	hashes := append(sha256Regex.FindAllString(text, -1), sha1Regex.FindAllString(text, -1)...)
	hashes = append(hashes, md5Regex.FindAllString(text, -1)...)
	for _, h := range hashes {
		if !seen[h] {
			seen[h] = true
			if _, err := db.createIndicatorRun(runID, reportID, "hash", h, "", ""); err != nil {
				errs = append(errs, "create indicator: "+err.Error())
			} else {
				counts["iocs"]++
			}
		}
	}

	// Extract CVEs
	cves := cveRegex.FindAllString(text, -1)
	for _, c := range cves {
		if _, err := db.createCVERun(runID, reportID, c, "", ""); err != nil {
			errs = append(errs, "create cve: "+err.Error())
		} else {
			counts["cves"]++
		}
	}

	// Extract MITRE techniques
	mitres := mitreRegex.FindAllString(text, -1)
	for _, m := range mitres {
		if _, err := db.createTechniqueRun(runID, reportID, m, "", ""); err != nil {
			errs = append(errs, "create technique: "+err.Error())
		} else {
			counts["ttps"]++
		}
	}
	if len(errs) > 0 {
		return counts, fmt.Errorf("extraction failures: %s", strings.Join(errs, "; "))
	}

	return counts, nil
}