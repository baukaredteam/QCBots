package main

// Curated, versioned Sigma-logsource -> QRadar DSM catalogue.
//
// This is NOT an automatic equivalence: a Sigma category and a QRadar devicetype
// are different taxonomies. The catalogue is a short, reviewed list; a match is
// still only a catalogue match, and it only counts as DSM-verified when the named
// DSM actually exists in the selected client's inventory.
const sigmaLogsourceCatalogueVersion = "logsource-catalogue-1"

type sigmaDSMEntry struct {
	Product  string
	Category string
	Service  string
	DSMs     []string
}

var sigmaDSMCatalogue = []sigmaDSMEntry{
	{Product: "windows", Service: "security", DSMs: []string{"Microsoft Windows Security Event Log"}},
	{Product: "windows", Service: "sysmon", DSMs: []string{"Microsoft Windows Sysmon"}},
	{Product: "windows", Category: "process_creation", DSMs: []string{"Microsoft Windows Security Event Log", "Microsoft Windows Sysmon"}},
	{Product: "windows", Category: "registry_event", DSMs: []string{"Microsoft Windows Sysmon"}},
	{Product: "windows", Service: "powershell", Category: "ps_script", DSMs: []string{"Microsoft Windows PowerShell"}},
	{Product: "microsoft", Service: "iis", Category: "webserver", DSMs: []string{"Microsoft IIS"}},
	{Product: "webserver", Category: "webserver", DSMs: []string{"Microsoft IIS", "Apache HTTP Server"}},
	{Product: "linux", DSMs: []string{"Linux OS", "Linux Server"}},
	{Product: "linux", Category: "process_creation", DSMs: []string{"Linux OS", "Linux Server"}},
}

// catalogueDSMs returns the reviewed DSM names for a rule's logsource, in
// catalogue order. An empty result means "no curated equivalence exists".
func catalogueDSMs(rule *SigmaRule) []string {
	p := lowerTrim(rule.LogsourceProduct)
	c := lowerTrim(rule.LogsourceCategory)
	s := lowerTrim(rule.LogsourceService)
	var out []string
	for _, e := range sigmaDSMCatalogue {
		if lowerTrim(e.Product) != "" && lowerTrim(e.Product) != p {
			continue
		}
		if lowerTrim(e.Category) != "" && lowerTrim(e.Category) != c {
			continue
		}
		if lowerTrim(e.Service) != "" && lowerTrim(e.Service) != s {
			continue
		}
		out = append(out, e.DSMs...)
	}
	return out
}

func lowerTrim(s string) string {
	out := make([]byte, 0, len(s))
	started := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if !started {
				continue
			}
			out = append(out, c)
			continue
		}
		started = true
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	for len(out) > 0 && (out[len(out)-1] == ' ' || out[len(out)-1] == '\t' || out[len(out)-1] == '\n' || out[len(out)-1] == '\r') {
		out = out[:len(out)-1]
	}
	return string(out)
}
