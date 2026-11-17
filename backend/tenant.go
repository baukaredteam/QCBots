package main

import (
	"net/http"
	"strings"
)

// TenantContext holds the tenant-scoped information for a request.
type TenantContext struct {
	UserID     string
	ClientID   string
	Authorized bool
}

// TenantMiddleware ensures server-side tenant isolation for all client-scoped operations.
type TenantMiddleware struct {
	db *DB
}

// NewTenantMiddleware creates a new tenant isolation middleware.
func NewTenantMiddleware(db *DB) *TenantMiddleware {
	return &TenantMiddleware{db: db}
}

// RequireTenantAccess verifies the authenticated user is authorized for the requested client_id.
func (tm *TenantMiddleware) RequireTenantAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionID := getSessionFromRequest(r)
		if sessionID == "" {
			http.Error(w, `{"error":{"code":"AUTH_FAILED","message":"not authenticated"}}`, http.StatusUnauthorized)
			return
		}

		session, err := tm.db.GetSession(sessionID)
		if err != nil || session == nil {
			http.Error(w, `{"error":{"code":"AUTH_FAILED","message":"invalid or expired session"}}`, http.StatusUnauthorized)
			return
		}

		clientID := extractClientID(r)
		if clientID == "" {
			http.Error(w, `{"error":{"code":"VALIDATION_ERROR","message":"client_id required"}}`, http.StatusBadRequest)
			return
		}

		if !CanAccessClient(session.UserID, clientID) {
			http.Error(w, `{"error":{"code":"TENANT_ISOLATION_VIOLATION","message":"not authorized for this client"}}`, http.StatusForbidden)
			return
		}

		session.ClientID = clientID

		next.ServeHTTP(w, r)
	})
}

// extractClientID extracts client_id from URL path or X-Client-ID header.
func extractClientID(r *http.Request) string {
	path := r.URL.Path
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i, p := range parts {
		if p == "tenants" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	if h := r.Header.Get("X-Client-ID"); h != "" {
		return h
	}
	return ""
}

// TenantFromSession extracts tenant context from a session.
func TenantFromSession(session *Session) TenantContext {
	return TenantContext{
		UserID:     session.UserID,
		ClientID:   session.ClientID,
		Authorized: true,
	}
}

// FormatTenantError returns a standardized tenant isolation error.
func FormatTenantError() string {
	return `{"error":{"code":"TENANT_ISOLATION_VIOLATION","message":"client access denied"}}`
}
