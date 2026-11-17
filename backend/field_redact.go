package main

import (
	"regexp"
	"strings"
)

// Redaction for imported telemetry. Everything here runs locally; nothing is
// sent anywhere. Patterns are deliberately conservative: when a value looks
// sensitive it is replaced, never stored and never logged.
//
// This is not an anonymisation guarantee. It removes the classes we can
// recognise deterministically; residual identifiability is possible and every
// batch still needs analyst review before publication.
const fieldRedactionVersion = "redact-1"

type redactStats struct {
	Values int
	Kinds  map[string]int
}

var (
	reEmail   = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	reIPv4    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reIPv6    = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b`)
	reURLHost = regexp.MustCompile(`(?i)\b(https?://)([^/\s?]+)`)
	reURLQ    = regexp.MustCompile(`(?i)\b(https?://[^\s?]+)\?[^\s]*`)
	reBearer  = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._\-+/=]{8,}`)
	reGUIDish = regexp.MustCompile(`\b[A-Za-z0-9_\-]{32,}\b`)
)

// Sensitive key names whose values are always replaced.
var sensitiveKeys = map[string]string{
	"password": "[REDACTED_PASSWORD]", "passwd": "[REDACTED_PASSWORD]", "pwd": "[REDACTED_PASSWORD]",
	"token": "[REDACTED_TOKEN]", "access_token": "[REDACTED_TOKEN]", "refresh_token": "[REDACTED_TOKEN]",
	"api_key": "[REDACTED_TOKEN]", "apikey": "[REDACTED_TOKEN]", "secret": "[REDACTED_SECRET]",
	"authorization": "[REDACTED_CREDENTIAL]", "cookie": "[REDACTED_COOKIE]", "session": "[REDACTED_SESSION]",
	"username": "[REDACTED_USER]", "user": "[REDACTED_USER]", "accountname": "[REDACTED_USER]",
	"targetusername": "[REDACTED_USER]", "subjectusername": "[REDACTED_USER]",
	"cs-username": "[REDACTED_USER]", "useragent": "[REDACTED_USER_AGENT]",
	"cs(user-agent)": "[REDACTED_USER_AGENT]",
	"commandline": "[REDACTED_CMDLINE]", "processcommandline": "[REDACTED_CMDLINE]",
	"hostname": "[REDACTED_HOST]", "computername": "[REDACTED_HOST]", "workstation": "[REDACTED_HOST]",
	// A nested XML body is never stored: its Data elements are extracted
	// separately, and the raw markup can carry arbitrary secrets.
	"taskcontent": "[REDACTED_XML]",
}

// sensitivePlaceholder resolves a value placeholder for a field name, matching
// both the full lower-cased name and its last dot-separated segment, so
// "TaskContent.Password" is treated like "Password".
func sensitivePlaceholder(key string) (string, bool) {
	k := strings.ToLower(strings.TrimSpace(key))
	if ph, ok := sensitiveKeys[k]; ok {
		return ph, true
	}
	if i := strings.LastIndex(k, "."); i >= 0 && i+1 < len(k) {
		if ph, ok := sensitiveKeys[k[i+1:]]; ok {
			return ph, true
		}
	}
	return "", false
}

// redactValue scrubs a single value.
func redactValue(key, value string, st *redactStats) string {
	if value == "" {
		return value
	}
	if ph, ok := sensitivePlaceholder(key); ok {
		st.bump(strings.Trim(ph, "[]"))
		return ph
	}
	out := value
	sub := func(re *regexp.Regexp, ph, kind string) {
		if re.MatchString(out) {
			n := len(re.FindAllString(out, -1))
			out = re.ReplaceAllString(out, ph)
			for i := 0; i < n; i++ {
				st.bump(kind)
			}
		}
	}
	if reURLQ.MatchString(out) {
		n := len(reURLQ.FindAllStringSubmatch(out, -1))
		out = reURLQ.ReplaceAllString(out, "$1?[REDACTED_QUERY]")
		for i := 0; i < n; i++ {
			st.bump("URL_QUERY")
		}
	}
	if reURLHost.MatchString(out) {
		n := len(reURLHost.FindAllStringSubmatch(out, -1))
		out = reURLHost.ReplaceAllString(out, "$1[REDACTED_HOST]")
		for i := 0; i < n; i++ {
			st.bump("URL_HOST")
		}
	}
	sub(reBearer, "$1 [REDACTED_CREDENTIAL]", "CREDENTIAL")
	sub(reEmail, "[REDACTED_EMAIL]", "EMAIL")
	sub(reIPv4, "[REDACTED_IP]", "IP")
	sub(reIPv6, "[REDACTED_IP]", "IP")
	// Long opaque identifiers: keep short hashes/event ids intact.
	if len(out) >= 32 {
		sub(reGUIDish, "[REDACTED_OPAQUE]", "OPAQUE")
	}
	return out
}

func (s *redactStats) bump(kind string) {
	s.Values++
	if s.Kinds == nil {
		s.Kinds = map[string]int{}
	}
	s.Kinds[kind]++
}

// redactPairs applies redaction to a parsed key/value row.
func redactPairs(fields map[string]string) (map[string]string, redactStats) {
	st := redactStats{}
	out := make(map[string]string, len(fields))
	for k, v := range fields {
		out[k] = redactValue(k, v, &st)
	}
	return out, st
}

// redactLine is the fallback for unparsed text: it keeps the shape of the line
// (structure, field names) while removing recognisable values.
func redactLine(line string) (string, redactStats) {
	st := redactStats{}
	out := redactValue("", line, &st)
	return out, st
}
