package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// Deterministic parsers for imported telemetry. Parsing happens in memory only;
// the caller redacts the parsed values before anything is persisted.
const fieldParserVersion = "parse-1"

type parsedRow struct {
	Fields map[string]string
	Types  map[string]string
	Error  string
}

type parseResult struct {
	Parser    string
	Rows      []parsedRow
	Warnings  []string
	Ambiguous bool
}

var reKV = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_\-]{0,63})=("([^"]*)"|\S+)`)
var reXMLData = regexp.MustCompile(`(?is)<Data\s+Name="([^"]{1,64})"\s*>(.*?)</Data>`)

// inferType gives coarse, honest type evidence: integer, ip, timestamp, string.
func inferType(v string) string {
	t := strings.TrimSpace(v)
	if t == "" {
		return "unknown"
	}
	if _, err := strconv.ParseInt(t, 10, 64); err == nil {
		return "integer"
	}
	if isIPv4Literal(t) {
		return "ip"
	}
	if strings.Contains(t, "T") && strings.Contains(t, ":") && (strings.HasSuffix(t, "Z") || strings.Contains(t, "+")) {
		return "timestamp"
	}
	return "string"
}

func isIPv4Literal(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

func typesOf(fields map[string]string) map[string]string {
	out := make(map[string]string, len(fields))
	for k, v := range fields {
		out[k] = inferType(v)
	}
	return out
}

// parseImport dispatches on the declared source type, then verifies that the
// content actually matches. A mismatch is reported, never guessed.
func parseImport(sourceType string, data []byte) parseResult {
	switch sourceType {
	case "windows_kev", "txt", "custom_export":
		if r := parseWindows(data); len(r.Rows) > 0 {
			return r
		}
		return parseGeneric(data)
	case "iis":
		return parseIIS(data)
	case "csv":
		return parseCSV(data)
	case "json", "jsonl":
		return parseJSON(sourceType, data)
	default:
		return parseResult{Parser: fieldParserVersion, Warnings: []string{"unsupported source type declared"}, Ambiguous: true}
	}
}

func parseKeyValues(line string) map[string]string {
	fields := map[string]string{}
	for _, m := range reKV.FindAllStringSubmatch(line, -1) {
		v := m[2]
		if strings.HasPrefix(v, `"`) {
			v = strings.Trim(v, `"`)
		}
		fields[m[1]] = v
	}
	return fields
}

// parseWindows handles Windows Security events: a syslog prefix followed by
// space-delimited Key=Value pairs, optionally with a TaskContent XML body.
func parseWindows(data []byte) parseResult {
	res := parseResult{Parser: fieldParserVersion + "/windows"}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Parse Key=Value only from the prefix before any nested XML body:
		// scanning inside the XML would fabricate keys from attribute pairs.
		kvPart := line
		if i := strings.Index(line, "<"); i >= 0 {
			kvPart = line[:i]
		}
		fields := parseKeyValues(kvPart)
		for _, m := range reXMLData.FindAllStringSubmatch(line, -1) {
			fields["TaskContent."+m[1]] = strings.TrimSpace(stripTags(m[2]))
		}
		if strings.Contains(line, "<") {
			fields["TaskContent"] = "[XML]"
		}
		if len(fields) < 2 {
			res.Rows = append(res.Rows, parsedRow{Error: "windows: no Key=Value pairs recognised"})
			continue
		}
		if _, ok := fields["EventID"]; !ok {
			res.Warnings = append(res.Warnings, "windows: row without EventID")
		}
		res.Rows = append(res.Rows, parsedRow{Fields: fields, Types: typesOf(fields)})
	}
	if len(res.Rows) == 0 {
		res.Ambiguous = true
	}
	return res
}

func stripTags(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch r {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

// parseIIS requires the authoritative #Fields header. Without it positional
// mapping would be an invention, so the batch is marked ambiguous instead.
func parseIIS(data []byte) parseResult {
	res := parseResult{Parser: fieldParserVersion + "/iis"}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var header []string
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "#Fields:") {
			header = strings.Fields(strings.TrimSpace(strings.TrimPrefix(t, "#Fields:")))
			continue
		}
		if strings.HasPrefix(t, "#") {
			continue
		}
		if len(header) == 0 {
			res.Ambiguous = true
			res.Rows = append(res.Rows, parsedRow{Error: "iis: no #Fields header — positional mapping refused"})
			continue
		}
		vals := strings.Fields(t)
		if len(vals) != len(header) {
			res.Rows = append(res.Rows, parsedRow{Error: "iis: field count mismatch"})
			continue
		}
		fields := make(map[string]string, len(header))
		for i, name := range header {
			fields[name] = vals[i]
		}
		res.Rows = append(res.Rows, parsedRow{Fields: fields, Types: typesOf(fields)})
	}
	if len(header) == 0 {
		res.Ambiguous = true
		res.Warnings = append(res.Warnings, "iis: file has no #Fields header")
	}
	return res
}

func parseCSV(data []byte) parseResult {
	res := parseResult{Parser: fieldParserVersion + "/csv"}
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = 0
	r.LazyQuotes = true
	records, err := r.ReadAll()
	if err != nil || len(records) == 0 {
		res.Ambiguous = true
		res.Warnings = append(res.Warnings, "csv: unreadable or empty")
		return res
	}
	header := records[0]
	seen := map[string]bool{}
	for _, h := range header {
		if strings.TrimSpace(h) == "" || seen[h] {
			res.Ambiguous = true
			res.Warnings = append(res.Warnings, "csv: empty or duplicate header")
			return res
		}
		seen[h] = true
	}
	for _, rec := range records[1:] {
		if len(rec) != len(header) {
			res.Rows = append(res.Rows, parsedRow{Error: "csv: column count mismatch"})
			continue
		}
		fields := make(map[string]string, len(header))
		for i, h := range header {
			fields[h] = rec[i]
		}
		res.Rows = append(res.Rows, parsedRow{Fields: fields, Types: typesOf(fields)})
	}
	return res
}

func parseJSON(sourceType string, data []byte) parseResult {
	res := parseResult{Parser: fieldParserVersion + "/" + sourceType}
	var objs []map[string]interface{}
	if sourceType == "jsonl" {
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var o map[string]interface{}
			if err := json.Unmarshal([]byte(line), &o); err != nil {
				res.Rows = append(res.Rows, parsedRow{Error: "jsonl: invalid object"})
				continue
			}
			objs = append(objs, o)
		}
	} else {
		var single map[string]interface{}
		if err := json.Unmarshal(data, &single); err == nil {
			objs = append(objs, single)
		} else {
			var arr []map[string]interface{}
			if err := json.Unmarshal(data, &arr); err != nil {
				res.Ambiguous = true
				res.Warnings = append(res.Warnings, "json: not an object or array of objects")
				return res
			}
			objs = arr
		}
	}
	for _, o := range objs {
		fields := make(map[string]string, len(o))
		for k, v := range o {
			switch t := v.(type) {
			case string:
				fields[k] = t
			case float64:
				fields[k] = strconv.FormatFloat(t, 'f', -1, 64)
			case bool:
				fields[k] = strconv.FormatBool(t)
			case nil:
				fields[k] = ""
			default:
				fields[k] = "[STRUCTURED_VALUE]"
			}
		}
		res.Rows = append(res.Rows, parsedRow{Fields: fields, Types: typesOf(fields)})
	}
	return res
}

// parseGeneric accepts only content that is clearly key=value; anything else is
// ambiguous rather than silently "parsed".
func parseGeneric(data []byte) parseResult {
	res := parseResult{Parser: fieldParserVersion + "/generic"}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := parseKeyValues(line)
		if len(fields) < 2 {
			res.Rows = append(res.Rows, parsedRow{Error: "generic: ambiguous format (expected Key=Value)"})
			continue
		}
		res.Rows = append(res.Rows, parsedRow{Fields: fields, Types: typesOf(fields)})
	}
	if len(res.Rows) == 0 {
		res.Ambiguous = true
	}
	return res
}
