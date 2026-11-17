package main

import (
	"fmt"
	"sort"
	"strings"
)

// Candidate field mapping. A candidate is produced only when the observed value
// type is compatible with the target CEP field, and the raw name is a known
// alias for that CEP. Nothing here approves a mapping; approval is a separate,
// audited reviewer action.
const fieldMappingVersion = "map-1"

type cepSpec struct {
	Name    string
	Type    string
	Aliases []string
	DSMHint string
}

// Known CEP fields with their declared value type and accepted raw aliases.
// The list is intentionally small and explicit: unknown CEP fields never produce
// a candidate.
var cepCatalogue = []cepSpec{
	{Name: "event_id", Type: "integer", Aliases: []string{"eventid", "eventcode", "event_id", "signatureid"}},
	{Name: "task_name", Type: "string", Aliases: []string{"taskname", "task_name", "taskcategory"}},
	{Name: "proc_id", Type: "integer", Aliases: []string{"executionprocessid", "processid", "newprocessid", "proc_id"}},
	{Name: "parent_proc_id", Type: "integer", Aliases: []string{"creatorprocessid", "parentprocessid"}},
	{Name: "http_method", Type: "string", Aliases: []string{"cs-method", "http_method", "method"}},
	{Name: "url_path", Type: "string", Aliases: []string{"cs-uri-stem", "url_path", "uristem"}},
	{Name: "http_code", Type: "integer", Aliases: []string{"sc-status", "http_code", "statuscode"}},
	{Name: "src_ip", Type: "ip", Aliases: []string{"s-ip", "src_ip", "sourceip", "ipaddress"}},
	{Name: "dst_ip", Type: "ip", Aliases: []string{"c-ip", "dst_ip", "destinationip"}},
	{Name: "username", Type: "string", Aliases: []string{"cs-username", "targetusername", "subjectusername", "username"}},
}

type mappingCandidate struct {
	RawField    string
	Normalized  string
	CEP         string
	Confidence  string // high | medium | low
	Ambiguous   bool
	Evidence    string
	ObservedTyp string
}

func normalizeFieldName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	repl := strings.NewReplacer("_", "", "-", "", ".", "", "(", "", ")", "", " ", "")
	return repl.Replace(s)
}

// buildCandidates derives candidates from observed field->type evidence.
// observed maps a raw field name to the set of types seen for it. A field seen
// with conflicting types is downgraded to low confidence; the same CEP claimed
// by two different raw fields makes both ambiguous.
func buildCandidates(observed map[string]map[string]int) []mappingCandidate {
	type hit struct {
		raw  string
		spec cepSpec
		typ  string
	}
	var hits []hit
	byName := map[string]cepSpec{}
	for _, spec := range cepCatalogue {
		for _, a := range spec.Aliases {
			byName[normalizeFieldName(a)] = spec
		}
	}
	for raw, types := range observed {
		spec, ok := byName[normalizeFieldName(raw)]
		if !ok {
			continue
		}
		typ, compatible, conflict := pickType(types)
		if !compatible || spec.Type != typ {
			continue // observed values contradict the CEP type: no candidate
		}
		conf := "high"
		if conflict || spec.Type != typ {
			conf = "low"
		}
		if !strings.EqualFold(normalizeFieldName(raw), normalizeFieldName(spec.Name)) && conf == "high" {
			conf = "medium"
		}
		hits = append(hits, hit{raw: raw, spec: spec, typ: typ})
		_ = conf
	}
	claimed := map[string][]string{}
	for _, h := range hits {
		claimed[h.spec.Name] = append(claimed[h.spec.Name], h.raw)
	}
	out := make([]mappingCandidate, 0, len(hits))
	for _, h := range hits {
		c := mappingCandidate{
			RawField:    h.raw,
			Normalized:  normalizeFieldName(h.raw),
			CEP:         h.spec.Name,
			ObservedTyp: h.typ,
			Confidence:  "high",
		}
		if c.Normalized != normalizeFieldName(h.spec.Name) {
			c.Confidence = "medium"
		}
		if h.spec.Type != h.typ {
			c.Confidence = "low"
		}
		if len(claimed[h.spec.Name]) > 1 {
			c.Ambiguous = true
			c.Confidence = "low"
			c.Evidence = fmt.Sprintf("multiple raw fields claim %s (%s)", h.spec.Name, strings.Join(sortedCopy(claimed[h.spec.Name]), ", "))
		} else {
			c.Evidence = fmt.Sprintf("observed %s value on %s; type matches %s", h.typ, h.raw, h.spec.Type)
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RawField < out[j].RawField })
	return out
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// pickType returns the dominant compatible type. compatible=false means the
// observed values contradict the CEP type, so no candidate may be proposed.
func pickType(types map[string]int) (string, bool, bool) {
	conflict := len(types) > 1
	best, bestN := "", -1
	for t, n := range types {
		if n > bestN {
			best, bestN = t, n
		}
	}
	switch best {
	case "integer", "ip", "string", "timestamp":
		return best, true, conflict
	default:
		return best, false, conflict
	}
}

// observedFromRows accumulates field name -> type -> count from parsed rows.
func observedFromRows(rows []parsedRow) map[string]map[string]int {
	out := map[string]map[string]int{}
	for _, r := range rows {
		if r.Fields == nil {
			continue
		}
		for k, t := range r.Types {
			if out[k] == nil {
				out[k] = map[string]int{}
			}
			out[k][t]++
		}
	}
	return out
}
