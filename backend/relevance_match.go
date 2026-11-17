package main

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// computeRelevanceFindings evaluates the three dimensions (MATCH/UNKNOWN + TELEMETRY NO_MATCH).
// Evidence is written by AssessRelevance (caller tx) via the returned findings.
// now is the pinned evaluation reference time: every staleness check in this
// run is judged against it, never against the clock at read time.
func computeRelevanceFindings(tx *sql.Tx, report *CTIReport, clientID string, now time.Time) ([]RelevanceFinding, error) {
	findings := []RelevanceFinding{
		{Dimension: "SECTOR", FindingID: newID("finding")},
		{Dimension: "TECHNOLOGY", FindingID: newID("finding")},
		{Dimension: "TELEMETRY", FindingID: newID("finding")},
	}

	// --- SECTOR (MATCH|UNKNOWN only; NO_MATCH disabled in v1) ---
	{
		var sectorIDs []string
		rows, err := tx.Query(`SELECT s.sector_id, s.sector_name FROM client_sector_mapping m JOIN sectors s ON s.sector_id=m.sector_id WHERE m.client_id = ? ORDER BY s.sector_id`, clientID)
		if err != nil {
			return nil, err
		}
		type sec struct{ ID, Name string }
		var clientSecs []sec
		for rows.Next() {
			var s sec
			_ = rows.Scan(&s.ID, &s.Name)
			clientSecs = append(clientSecs, s)
			sectorIDs = append(sectorIDs, s.Name)
		}
		rows.Close()
		// Report sector tokens from campaign/actor text + title (conservative exact token).
		var tokens []string
		_ = tx.QueryRow(`SELECT COALESCE(title,'') FROM cti_reports WHERE report_id = ?`, report.ReportID).Scan(new(string))
		title := ""
		_ = tx.QueryRow(`SELECT title FROM cti_reports WHERE report_id = ?`, report.ReportID).Scan(&title)
		for _, s := range sectorIDs {
			if s != "" && strings.Contains(strings.ToLower(title), strings.ToLower(s)) {
				tokens = append(tokens, s)
			}
		}
		f := &findings[0]
		if len(clientSecs) == 0 {
			f.Verdict = "UNKNOWN"
			f.Explanation = "Client sector inventory is unknown (no rows)."
			f.Unknowns = []string{"client sector inventory unknown"}
			f.Limitations = []string{"NO_MATCH disabled in v1: missing inventory is never contradiction"}
		} else if len(tokens) == 0 {
			f.Verdict = "UNKNOWN"
			f.Explanation = "No sector tokens extracted from report entities."
			f.Unknowns = []string{"report has no sector tokens"}
			f.Limitations = []string{"free-text token match only"}
		} else {
			f.Verdict = "MATCH"
			f.Explanation = "Report sector tokens match client sectors: " + strings.Join(tokens, ", ")
			inv, _ := json.Marshal(map[string]interface{}{"client_sectors": sectorIDs})
			f.Evidence = []RelevanceEvidence{
				{MatchedEntityType: "sector", MatchedEntityID: tokens[0], InventoryEvidence: string(inv), MatchingRuleID: "rule-sector-v1", MatchingRuleVersion: "1"},
			}
		}
	}

	// --- TECHNOLOGY (MATCH|UNKNOWN only in v1) ---
	{
		f := &findings[1]
		var techs []struct{ ID, Name, Category, Version string }
		rows, err := tx.Query(`SELECT tech_id, technology_name, COALESCE(category,''), COALESCE(version,'') FROM client_technologies WHERE client_id = ? ORDER BY tech_id`, clientID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var x struct{ ID, Name, Category, Version string }
			_ = rows.Scan(&x.ID, &x.Name, &x.Category, &x.Version)
			techs = append(techs, x)
		}
		rows.Close()
		var malFamilies []string
		mrows, err := tx.Query(`SELECT COALESCE(family,''), COALESCE(type,'') FROM malware WHERE report_id = ? ORDER BY malware_id`, report.ReportID)
		if err == nil {
			for mrows.Next() {
				var fam, typ string
				_ = mrows.Scan(&fam, &typ)
				if fam != "" {
					malFamilies = append(malFamilies, fam)
				}
				if typ != "" {
					malFamilies = append(malFamilies, typ)
				}
			}
			mrows.Close()
		}
		var matchedTech string
		for _, mf := range malFamilies {
			for _, tech := range techs {
				if strings.EqualFold(strings.TrimSpace(mf), strings.TrimSpace(tech.Name)) {
					matchedTech = tech.Name
				}
			}
		}
		if len(techs) == 0 {
			f.Verdict = "UNKNOWN"
			f.Explanation = "Client technology inventory is unknown (no rows)."
			f.Unknowns = []string{"client technology inventory unknown"}
			f.Limitations = []string{"NO_MATCH disabled in v1"}
		} else if matchedTech == "" {
			f.Verdict = "UNKNOWN"
			f.Explanation = "No versioned CVE/product rule matched client technologies (exact token only)."
			f.Unknowns = []string{"no matching CVE/product rule evidence"}
			f.Limitations = []string{"exact string equality only; no semver inference"}
		} else {
			f.Verdict = "MATCH"
			f.Explanation = "Malware family/type matched client technology: " + matchedTech
			inv, _ := json.Marshal(map[string]interface{}{"client_technologies": len(techs)})
			f.Evidence = []RelevanceEvidence{
				{MatchedEntityType: "technology", MatchedEntityID: matchedTech, InventoryEvidence: string(inv), MatchingRuleID: "rule-tech-v1", MatchingRuleVersion: "1"},
			}
		}
	}

	// --- TELEMETRY (MATCH / NO_MATCH / UNKNOWN) ---
	{
		f := &findings[2]
		// Candidate rules for report TTPs.
		type rule struct {
			ID, RequiredSources, Mitre string
		}
		var rules []rule
		rrows, err := tx.Query(`SELECT rule_id, COALESCE(required_log_sources,''), COALESCE(mitre_techniques,'') FROM detection_rules ORDER BY rule_id`)
		if err != nil {
			return nil, err
		}
		for rrows.Next() {
			var r rule
			_ = rrows.Scan(&r.ID, &r.RequiredSources, &r.Mitre)
			rules = append(rules, r)
		}
		rrows.Close()
		var mitreIDs []string
		trows, err := tx.Query(`SELECT COALESCE(mitre_technique_id,'') FROM techniques WHERE report_id = ? ORDER BY technique_id`, report.ReportID)
		if err != nil {
			return nil, err
		}
		for trows.Next() {
			var m string
			_ = trows.Scan(&m)
			if m != "" {
				mitreIDs = append(mitreIDs, m)
			}
		}
		trows.Close()
		// Client telemetry map (per-client rows only).
		type tele struct{ SourceType, Status, LastEvent, FieldAvail, LastChecked string }
		teleMap := map[string]tele{}
		teleRows, err := tx.Query(`SELECT log_source_type_id, connection_status, COALESCE(last_event_timestamp,''), COALESCE(field_availability,''), COALESCE(last_checked_at,'') FROM client_log_source_status WHERE client_id = ? ORDER BY status_id`, clientID)
		if err != nil {
			return nil, err
		}
		for teleRows.Next() {
			var x tele
			_ = teleRows.Scan(&x.SourceType, &x.Status, &x.LastEvent, &x.FieldAvail, &x.LastChecked)
			teleMap[x.SourceType] = x
		}
		teleRows.Close()

		candidateExists := false
		allUnavailable := true
		observableFound := false
		var obsRule, obsSource, obsAvail, obsChecked string
		var unknowns []string
		for _, m := range mitreIDs {
			for _, r := range rules {
				if !strings.Contains(r.Mitre, m) {
					continue
				}
				candidateExists = true
				src := strings.TrimSpace(r.RequiredSources)
				if src == "" {
					unknowns = append(unknowns, "rule "+r.ID+" has no required_log_sources")
					allUnavailable = false
					continue
				}
				tel, hasTele := teleMap[src]
				if !hasTele || tel.Status == "UNKNOWN" {
					unknowns = append(unknowns, "telemetry unknown/missing for "+src)
					allUnavailable = false
					continue
				}
				// Stale check: last_event within 7 days of the evaluation time.
				stale := true
				if tel.LastEvent != "" {
					if ts, err := time.Parse(time.RFC3339, tel.LastEvent); err == nil {
						stale = now.Sub(ts) > 7*24*time.Hour
					} else if ts, err := time.Parse("2006-01-02 15:04:05", tel.LastEvent); err == nil {
						stale = now.Sub(ts) > 7*24*time.Hour
					}
				}
				if tel.Status == "CONNECTED" && !stale {
					// Client-specific field verification (required for MATCH).
					// Global field existence alone never proves availability for THIS client:
					// the client's own telemetry row must show the required fields as
					// verified fresh (field_availability + last_checked_at).
					fieldsOK := true
					checkedStale := true
					if tel.LastChecked != "" {
						if ts, err := time.Parse(time.RFC3339, tel.LastChecked); err == nil {
							checkedStale = now.Sub(ts) > 7*24*time.Hour
						} else if ts, err := time.Parse("2006-01-02 15:04:05", tel.LastChecked); err == nil {
							checkedStale = now.Sub(ts) > 7*24*time.Hour
						}
					}
					if checkedStale {
						fieldsOK = false
						unknowns = append(unknowns, "field verification stale/unknown for "+src)
					}
					required := []string{}
					requiredNames := []string{}
					frows, err := tx.Query(`SELECT r.field_id, COALESCE(g.field_name,'') FROM rule_field_requirements r LEFT JOIN global_fields g ON g.field_id = r.field_id WHERE r.rule_id = ? AND r.is_required = 1 ORDER BY r.field_id`, r.ID)
					if err == nil {
						for frows.Next() {
							var fid, fname string
							_ = frows.Scan(&fid, &fname)
							required = append(required, fid)
							requiredNames = append(requiredNames, fname)
						}
						frows.Close()
						if len(required) == 0 {
							fieldsOK = false
							unknowns = append(unknowns, "required fields not verifiable for rule "+r.ID)
						} else {
							// Client-owned proof: the field must appear as an EXACT TOKEN
							// in this client's field_availability (partial names never count).
							tokens := fieldAvailTokens(tel.FieldAvail)
							for i, fid := range required {
								var n int
								_ = tx.QueryRow(`SELECT COUNT(*) FROM global_fields WHERE field_id = ? AND is_active = 1`, fid).Scan(&n)
								if n == 0 {
									fieldsOK = false
									unknowns = append(unknowns, "field "+fid+" not active for rule "+r.ID)
									break
								}
								lowerFid := strings.ToLower(fid)
								lowerName := strings.ToLower(requiredNames[i])
								if !tokens[lowerFid] && (lowerName == "" || !tokens[lowerName]) {
									fieldsOK = false
									unknowns = append(unknowns, "no client field evidence for "+fid+" on "+src)
									break
								}
							}
						}
					} else {
						fieldsOK = false
					}
					if fieldsOK {
						observableFound = true
						obsRule, obsSource = r.ID, src
						obsAvail, obsChecked = tel.FieldAvail, tel.LastChecked
						allUnavailable = false
					} else {
						unknowns = append(unknowns, "fields unverified for rule "+r.ID)
						allUnavailable = false
					}
				} else if stale {
					// Stale events: insufficient evidence, never proven-unavailable.
					unknowns = append(unknowns, "last event stale for "+src)
					allUnavailable = false
				}
			}
		}
		if observableFound {
			f.Verdict = "MATCH"
			f.Explanation = "Telemetry + required-field evidence supports investigation via rule " + obsRule + " (source " + obsSource + "). Candidate observable path only."
			inv, _ := json.Marshal(map[string]interface{}{"client_id": clientID, "log_source": obsSource, "rule": obsRule, "field_availability": obsAvail, "last_checked_at": obsChecked})
			f.Evidence = []RelevanceEvidence{
				{MatchedEntityType: "detection_rule", MatchedEntityID: obsRule, InventoryEvidence: string(inv), MatchingRuleID: "rule-telemetry-v1", MatchingRuleVersion: "1"},
				{MatchedEntityType: "log_source", MatchedEntityID: obsSource, InventoryEvidence: string(inv), MatchingRuleID: "rule-telemetry-v1", MatchingRuleVersion: "1"},
			}
			f.Limitations = []string{"candidate mapping only; operational use is not proven by inventory"}
		} else if candidateExists && allUnavailable {
			f.Verdict = "NO_MATCH"
			f.Explanation = "All applicable detection-rule paths are proven unavailable by client telemetry."
			f.Limitations = []string{"not observable does not imply not affected"}
		} else {
			f.Verdict = "UNKNOWN"
			f.Explanation = "Insufficient telemetry or mapping evidence."
			f.Unknowns = unknowns
			if len(unknowns) == 0 {
				f.Unknowns = []string{"no candidate rules or telemetry evidence"}
			}
			f.Limitations = []string{"missing rule/telemetry is never NO_MATCH"}
		}
	}
	return findings, nil
}

// fieldAvailTokens splits free-text field_availability into exact tokens.
// Token characters are identifier characters (letters, digits, '_' and '-');
// everything else is a boundary. A token matches a field only by exact
// (case-insensitive) equality — partial-name matches never count.
func fieldAvailTokens(s string) map[string]bool {
	out := map[string]bool{}
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out[strings.ToLower(cur.String())] = true
			cur.Reset()
		}
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			cur.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return out
}
