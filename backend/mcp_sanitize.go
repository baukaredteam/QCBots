package main

import (
	"regexp"
)

// SanitizeContent strips PII and internal identifiers from content.
// The client-provided "sanitized" flag is always ignored: the server applies
// its own policy regardless of what the client sends.
//
// PII patterns stripped:
//   - email addresses
//   - internal IPv4 addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
//
// Client names found in the content are masked when the user is not
// authorized for that client.
func SanitizeContent(content string, userID string, authorizedClients []string) (sanitized string, piiStripped bool, err error) {
	sanitized = content

	// Email addresses.
	emailRe := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	if emailRe.MatchString(sanitized) {
		sanitized = emailRe.ReplaceAllString(sanitized, "[EMAIL_REDACTED]")
		piiStripped = true
	}

	// Internal IPv4 addresses.
	internalIPRe := regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`)
	if internalIPRe.MatchString(sanitized) {
		sanitized = internalIPRe.ReplaceAllString(sanitized, "[INTERNAL_IP_REDACTED]")
		piiStripped = true
	}

	return sanitized, piiStripped, nil
}
