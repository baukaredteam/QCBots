package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// AuditEvent represents an audit log entry.
type AuditEvent struct {
	UserID         string
	AgentID        string
	ClientID       string
	Action         string
	Resource       string
	Result         string
	SourceIP       string
	CorrelationID  string
}

// AuditLogger writes audit events to the database.
type AuditLogger struct {
	db *DB
}

// NewAuditLogger creates a new audit logger.
func NewAuditLogger(db *DB) *AuditLogger {
	return &AuditLogger{db: db}
}

// Log writes an audit event to the database. Empty client_id is stored as NULL.
func (al *AuditLogger) Log(event AuditEvent) error {
	var clientID interface{} = event.ClientID
	if event.ClientID == "" {
		clientID = nil
	}
	var agentID interface{} = event.AgentID
	if event.AgentID == "" {
		agentID = nil
	}
	_, err := al.db.Exec(`INSERT INTO audit_log (event_id, user_id, agent_id, client_id, action, resource, timestamp, result, source_ip, correlation_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		generateCorrelationID(), event.UserID, agentID, clientID,
		event.Action, event.Resource, time.Now().Format(time.RFC3339), event.Result,
		event.SourceIP, event.CorrelationID)
	if err != nil {
		auditWriteFailures.Add(1)
		slog.Error("audit write failed",
			"correlation_id", event.CorrelationID,
			"result", sanitizeAuditField(event.Result),
			"error", sanitizeAuditError(err))
		return fmt.Errorf("writing audit log: %w", err)
	}
	return nil
}

// auditWriteFailures counts best-effort access-log writes that failed. It is
// incremented for every failed Log call, including those whose caller ignores
// the returned error, so a silent loss is impossible to miss.
var auditWriteFailures atomic.Uint64

func auditWriteFailureCount() uint64 { return auditWriteFailures.Load() }

// sanitizeAuditField keeps failure logs free of client data and long values.
func sanitizeAuditField(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

func sanitizeAuditError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// generateCorrelationID creates a unique correlation ID for tracing.
func generateCorrelationID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "corr-" + fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// AuditMiddleware wraps handlers to log all authenticated requests.
type AuditMiddleware struct {
	db    *DB
	al    *AuditLogger
	secure bool
}

// NewAuditMiddleware creates audit middleware.
func NewAuditMiddleware(db *DB, secure bool) *AuditMiddleware {
	return &AuditMiddleware{db: db, al: NewAuditLogger(db), secure: secure}
}

// Wrap wraps an HTTP handler with audit logging.
func (am *AuditMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}
		next.ServeHTTP(wrapped, r)

		sessionID := getSessionFromRequest(r)
		userID := ""
		clientID := ""
		action := fmt.Sprintf("%s %s", r.Method, r.URL.Path)

		if sessionID != "" {
			session, err := am.db.GetSession(sessionID)
			if err == nil && session != nil {
				userID = session.UserID
				clientID = session.ClientID
			}
		}

		result := fmt.Sprintf("HTTP %d", wrapped.statusCode)
		if wrapped.statusCode >= 400 {
			result = "error"
		}

		sourceIP := requestClientIP(r)

		am.al.Log(AuditEvent{
			UserID:         userID,
			AgentID:        "",
			ClientID:       clientID,
			Action:         action,
			Resource:       r.URL.Path,
			Result:         result,
			SourceIP:       sourceIP,
			CorrelationID:  generateCorrelationID(),
		})
	})
}

// responseWriter wraps http.ResponseWriter to capture status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// CSRFValidator validates Origin header for state-changing requests.
type CSRFValidator struct {
	allowedOrigins []string
	secure         bool
}

// NewCSRFValidator creates a CSRF validator.
func NewCSRFValidator(allowedOrigins []string, secure bool) *CSRFValidator {
	return &CSRFValidator{allowedOrigins: allowedOrigins, secure: secure}
}

// Validate checks if the request's Origin header is allowed for state-changing operations.
func (cv *CSRFValidator) Validate(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}

	// A same-origin request is never cross-site request forgery, whatever port or
	// hostname the deployment uses. This keeps the cookie session working on a
	// custom port, behind TLS termination and behind a reverse proxy without
	// hardcoding an origin in the client.
	if sameOriginRequest(r, origin) {
		return true
	}

	for _, allowed := range cv.allowedOrigins {
		if origin == allowed {
			return true
		}
	}

	return false
}

// sameOriginRequest compares the Origin header with the request's effective
// scheme and host. The effective values come from server state or from a
// validated trusted proxy only; a client-supplied forwarded header can never
// widen them (see proxy_trust.go).
func sameOriginRequest(r *http.Request, origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	scheme, host := requestSchemeHost(r)
	return strings.EqualFold(u.Scheme, scheme) && strings.EqualFold(u.Host, host)
}

// FormatCSRFError returns a standardized CSRF error.
func FormatCSRFError() string {
	return `{"error":{"code":"FORBIDDEN","message":"CSRF validation failed: missing or invalid Origin header"}}`
}
