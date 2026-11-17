package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"regexp"
	"strconv"

	"go.yaml.in/yaml/v3"
)

// M7-D Phase 2B-1: Sigma detection ingestion.
//
// Sigma documents are untrusted input. They are size-limited, parsed as data
// (never executed), validated, hashed and stored immutably. A changed document
// becomes a new version; nothing is overwritten.

const (
	maxSigmaBytes = 512 << 10 // 512 KiB
	maxSigmaTags  = 64
)

var (
	ErrSigmaInvalid = errors.New("SIGMA_INVALID")
)

type SigmaRule struct {
	RuleID             string   `json:"rule_id"`
	SourceID           string   `json:"source_id"`
	ClientID           string   `json:"client_id"`
	SourceKind         string   `json:"source_kind"`
	ReportID           string   `json:"report_id,omitempty"`
	Filename           string   `json:"filename"`
	SigmaRuleID        string   `json:"sigma_rule_id"`
	Version            int      `json:"version"`
	Title              string   `json:"title"`
	Status             string   `json:"status,omitempty"`
	Description        string   `json:"description,omitempty"`
	Author             string   `json:"author,omitempty"`
	Level              string   `json:"level,omitempty"`
	LogsourceProduct   string   `json:"logsource_product,omitempty"`
	LogsourceCategory  string   `json:"logsource_category,omitempty"`
	LogsourceService   string   `json:"logsource_service,omitempty"`
	Condition          string   `json:"condition"`
	Tags               []string `json:"tags"`
	Modifiers          []string `json:"modifiers"`
	Fields             []string `json:"fields"`
	YAML               string   `json:"yaml,omitempty"`
	YAMLSHA256         string   `json:"yaml_sha256"`
	ByteSize           int      `json:"byte_size"`
	CreatedBy          string   `json:"created_by"`
	// ValidationStatus is PRELIMINARY: the Go parser is a structural gate, not
	// authoritative Sigma validation. pySigma re-parses before conversion.
	ValidationStatus   string   `json:"validation_status"`
	CreatedAt          string   `json:"created_at"`
}

// sigmaDocument is the subset of the Sigma specification this project stores and
// understands. Unknown keys are kept out of the struct on purpose: the original
// YAML is preserved verbatim, so nothing is lost by not modelling it.
type sigmaDocument struct {
	ID          string                 `yaml:"id"`
	Title       string                 `yaml:"title"`
	Status      string                 `yaml:"status"`
	Description string                 `yaml:"description"`
	Author      string                 `yaml:"author"`
	Level       string                 `yaml:"level"`
	References  []string               `yaml:"references"`
	Tags        []string               `yaml:"tags"`
	FalsePos    []string               `yaml:"falsepositives"`
	Logsource   map[string]string      `yaml:"logsource"`
	Detection   map[string]interface{} `yaml:"detection"`
	LevelAlias  string                 `yaml:"-"`
}

// parsedSigma is the validated, normalised view of one document.
type parsedSigma struct {
	Doc        sigmaDocument
	Condition  string
	Fields     []string
	Modifiers  []string
	Selections int
}

// parseSigma validates the document and extracts what later phases need.
func parseSigma(raw []byte) (*parsedSigma, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty document", ErrSigmaInvalid)
	}
	if len(raw) > maxSigmaBytes {
		return nil, fmt.Errorf("%w: document exceeds %d bytes", ErrSigmaInvalid, maxSigmaBytes)
	}
	var doc sigmaDocument
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigmaInvalid, err)
	}
	if strings.TrimSpace(doc.ID) == "" {
		return nil, fmt.Errorf("%w: id is required", ErrSigmaInvalid)
	}
	if strings.TrimSpace(doc.Title) == "" {
		return nil, fmt.Errorf("%w: title is required", ErrSigmaInvalid)
	}
	if len(doc.Detection) == 0 {
		return nil, fmt.Errorf("%w: detection is required", ErrSigmaInvalid)
	}
	condRaw, ok := doc.Detection["condition"]
	if !ok {
		return nil, fmt.Errorf("%w: detection.condition is required", ErrSigmaInvalid)
	}
	cond, ok := condRaw.(string)
	if !ok || strings.TrimSpace(cond) == "" {
		return nil, fmt.Errorf("%w: detection.condition must be a non-empty string", ErrSigmaInvalid)
	}

	fields, modifiers, selections, err := walkSelections(doc.Detection)
	if err != nil {
		return nil, err
	}
	if selections == 0 {
		return nil, fmt.Errorf("%w: detection has no selections", ErrSigmaInvalid)
	}
	if err := validateCondition(cond, doc.Detection); err != nil {
		return nil, err
	}
	return &parsedSigma{Doc: doc, Condition: cond, Fields: fields, Modifiers: modifiers, Selections: selections}, nil
}

// walkSelections collects field names and modifiers from every selection.
// A field with modifiers is reported by its base name; each modifier is also
// recorded so unsupported constructs can be refused later instead of silently
// dropped.
func walkSelections(detection map[string]interface{}) (fields, modifiers []string, selections int, err error) {
	seenF := map[string]bool{}
	seenM := map[string]bool{}
	for name, value := range detection {
		if name == "condition" || name == "timeframe" {
			continue
		}
		selections++
		var collect func(interface{}) error
		collect = func(sel interface{}) error {
			switch v := sel.(type) {
			case map[string]interface{}:
				for k, val := range v {
					base := k
					if i := strings.Index(k, "|"); i >= 0 {
						base = k[:i]
						for _, m := range strings.Split(k[i+1:], "|") {
							m = strings.TrimSpace(m)
							if m != "" && !seenM[m] {
								seenM[m] = true
								modifiers = append(modifiers, m)
							}
						}
					}
					if base != "" && !seenF[base] {
						seenF[base] = true
						fields = append(fields, base)
					}
					// Nested maps/lists inside a selection are valid Sigma
					// structures; they are preserved in YAML and not expanded here.
					_ = val
				}
			case []interface{}:
				for _, item := range v {
					if err := collect(item); err != nil {
						return err
					}
				}
			case string:
				// bare selection reference; validated by validateCondition
			default:
			}
			return nil
		}
		if err := collect(value); err != nil {
			return nil, nil, 0, err
		}
	}
	return fields, modifiers, selections, nil
}

// validateCondition performs PRELIMINARY structural validation only. It refuses
// conditions that reference selections which do not exist, but it is not
// authoritative Sigma semantics: the pySigma worker re-parses every rule before
// conversion, and only that result may be called parse-valid.
func validateCondition(cond string, detection map[string]interface{}) error {
	exists := map[string]bool{}
	for k := range detection {
		exists[k] = true
	}
	// Aggregation suffixes (| count(...), | near ...) are removed before the
	// reference scan; their semantics are decided by pySigma, not here.
	cleaned := regexpAggSuffix.ReplaceAllString(cond, " ")
	tokens := strings.Fields(strings.NewReplacer("(", " ( ", ")", " ) ", "|", " | ", ",", " , ").Replace(cleaned))
	if len(tokens) == 0 {
		return fmt.Errorf("%w: empty condition", ErrSigmaInvalid)
	}
	keywords := map[string]bool{
		"and": true, "or": true, "not": true, "of": true, "them": true, "all": true, "any": true,
		"|": true, ",": true,
	}
	for i, tok := range tokens {
		lower := strings.ToLower(tok)
		if keywords[lower] || tok == "(" || tok == ")" {
			continue
		}
		if _, err := strconv.Atoi(tok); err == nil {
			continue // "1 of them"
		}
		// Wildcard selection references: "selection*" / "filter_*".
		if strings.HasSuffix(tok, "*") {
			prefix := strings.TrimSuffix(tok, "*")
			found := false
			for name := range exists {
				if strings.HasPrefix(name, prefix) && name != "condition" && name != "timeframe" {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%w: condition references selection pattern %q with no match", ErrSigmaInvalid, tok)
			}
			continue
		}
		// A pipe separator introduced by the replacer may leave an empty token.
		if tok == "" {
			continue
		}
		// Allow a leading aggregation expression such as "count(selection)".
		if i > 0 && tokens[i-1] == "{" {
			continue
		}
		if !exists[tok] {
			return fmt.Errorf("%w: condition references unknown selection %q", ErrSigmaInvalid, tok)
		}
	}
	return nil
}

var regexpAggSuffix = regexp.MustCompile(`\|[^|]*$`)

// IngestSigmaRule stores a new immutable Sigma rule version.
func IngestSigmaRule(userID, clientID, reportID, filename, yamlText string) (*SigmaRule, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if err := requireFieldCapability(userID, CanManageDetections); err != nil {
		return nil, err
	}
	if !hasClientGrant(userID, clientID) {
		return nil, ErrFieldAccessDenied
	}
	if reportID != "" {
		var reportClient string
		err := globalDB.QueryRow(`SELECT client_id FROM cti_reports WHERE report_id = ?`, reportID).Scan(&reportClient)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("%w: source report not found", ErrSigmaInvalid)
			}
			return nil, err
		}
		if reportClient != clientID {
			return nil, ErrFieldAccessDenied
		}
	}

	raw := []byte(yamlText)
	parsed, err := parseSigma(raw)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])

	// Same client + same bytes is the same evidence: reuse it.
	var existing string
	if err := globalDB.QueryRow(`SELECT rule_id FROM sigma_detection_rules WHERE client_id = ? AND yaml_sha256 = ?`, clientID, hash).Scan(&existing); err == nil {
		return GetSigmaRule(existing, userID)
	}

	sourceKind := "MANUAL_UPLOAD"
	if reportID != "" {
		sourceKind = "CTI_REPORT_ATTACHMENT"
	}
	var version int
	if err := globalDB.QueryRow(`SELECT COALESCE(MAX(version),0)+1 FROM sigma_detection_rules WHERE client_id = ? AND sigma_rule_id = ?`, clientID, parsed.Doc.ID).Scan(&version); err != nil {
		return nil, err
	}

	tx, err := globalDB.Begin()
	if err != nil {
		return nil, err
	}
	sourceID := newID("dsrc")
	ruleID := newID("drule")
	tags, _ := json.Marshal(limitStrings(parsed.Doc.Tags, maxSigmaTags))
	mods, _ := json.Marshal(parsed.Modifiers)
	flds, _ := json.Marshal(parsed.Fields)
	if _, err := tx.Exec(`INSERT INTO sigma_detection_sources
		(source_id, client_id, source_kind, report_id, filename, yaml_sha256, byte_size, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		sourceID, clientID, sourceKind, nullableString(reportID), filename, hash, len(raw), userID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if _, err := tx.Exec(`INSERT INTO sigma_detection_rules
		(rule_id, source_id, client_id, sigma_rule_id, version, title, status, description, author, level,
		 logsource_product, logsource_category, logsource_service, condition_expr,
		 tags_json, modifiers_json, fields_json, yaml_text, yaml_sha256, byte_size, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		ruleID, sourceID, clientID, parsed.Doc.ID, version, parsed.Doc.Title, parsed.Doc.Status,
		parsed.Doc.Description, parsed.Doc.Author, parsed.Doc.Level,
		parsed.Doc.Logsource["product"], parsed.Doc.Logsource["category"], parsed.Doc.Logsource["service"],
		parsed.Condition, string(tags), string(mods), string(flds), string(raw), hash, len(raw), userID); err != nil {
		_ = tx.Rollback()
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			// A concurrent ingest of identical bytes won; converge on it.
			var raced string
			if qerr := globalDB.QueryRow(`SELECT rule_id FROM sigma_detection_rules WHERE client_id = ? AND yaml_sha256 = ?`, clientID, hash).Scan(&raced); qerr == nil {
				return GetSigmaRule(raced, userID)
			}
		}
		return nil, err
	}
	if err := auditInTx(tx, userID, clientID, "SIGMA_INGEST", ruleID, fmt.Sprintf("v%d", version)); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return GetSigmaRule(ruleID, userID)
}

func limitStrings(in []string, max int) []string {
	if len(in) <= max {
		return in
	}
	return in[:max]
}

func GetSigmaRule(ruleID, userID string) (*SigmaRule, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	r, err := loadSigmaRule(ruleID)
	if err != nil {
		return nil, err
	}
	if !hasClientGrant(userID, r.ClientID) {
		return nil, ErrFieldAccessDenied
	}
	return r, nil
}

// loadSigmaRule reads a stored detection without authorising a caller. Used when
// the caller already holds rights over the owning client (staleness checks), so
// evidence is never judged through another person's grants.
func loadSigmaRule(ruleID string) (*SigmaRule, error) {
	var r SigmaRule
	var tags, mods, flds string
	err := globalDB.QueryRow(`SELECT r.rule_id, r.source_id, r.client_id, s.source_kind, COALESCE(s.report_id,''), s.filename,
			r.sigma_rule_id, r.version, r.title, COALESCE(r.status,''), COALESCE(r.description,''), COALESCE(r.author,''), COALESCE(r.level,''),
			COALESCE(r.logsource_product,''), COALESCE(r.logsource_category,''), COALESCE(r.logsource_service,''),
			r.condition_expr, r.tags_json, r.modifiers_json, r.fields_json, r.yaml_text, r.yaml_sha256, r.byte_size, r.created_by, r.created_at
		FROM sigma_detection_rules r JOIN sigma_detection_sources s ON s.source_id = r.source_id
		WHERE r.rule_id = ?`, ruleID).
		Scan(&r.RuleID, &r.SourceID, &r.ClientID, &r.SourceKind, &r.ReportID, &r.Filename,
			&r.SigmaRuleID, &r.Version, &r.Title, &r.Status, &r.Description, &r.Author, &r.Level,
			&r.LogsourceProduct, &r.LogsourceCategory, &r.LogsourceService,
			&r.Condition, &tags, &mods, &flds, &r.YAML, &r.YAMLSHA256, &r.ByteSize, &r.CreatedBy, &r.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrFieldInventoryNotFound
		}
		return nil, err
	}
	r.ValidationStatus = "PRELIMINARY"
	_ = json.Unmarshal([]byte(tags), &r.Tags)
	_ = json.Unmarshal([]byte(mods), &r.Modifiers)
	_ = json.Unmarshal([]byte(flds), &r.Fields)
	return &r, nil
}

func ListSigmaRules(userID, clientID string) ([]SigmaRule, error) {
	if err := requireM7DSchema(); err != nil {
		return nil, err
	}
	if !hasClientGrant(userID, clientID) {
		return nil, ErrFieldAccessDenied
	}
	rows, err := globalDB.Query(`SELECT rule_id FROM sigma_detection_rules WHERE client_id = ? ORDER BY created_at DESC`, clientID)
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
	out := make([]SigmaRule, 0, len(ids))
	for _, id := range ids {
		r, err := GetSigmaRule(id, userID)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, nil
}
