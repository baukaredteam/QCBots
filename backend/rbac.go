package main

import (
	"fmt"
	"net/http"
)

// RolePermission defines what a role can do.
type RolePermission struct {
	Role                string
	CanViewCTI          bool
	CanCreateCTI        bool
	CanCreateArtifact   bool
	CanCreateBrain      bool
	CanCreateHypothesis bool
	CanGenerateAQL      bool
	CanViewReports      bool
	CanManageUsers      bool
	CanViewAudit        bool
	CanManageClients    bool
	CanReviewArtifact   bool
	CanReviewHypothesis bool
	CanLinkHypothesis   bool
	// Field-intel write and review are deliberately separate: importing raw
	// telemetry is not permission to approve mappings or publish a batch.
	CanImportFieldIntel bool
	CanReviewFieldIntel bool
	// CanManageQRadarBindings is the privileged reconciliation right: it may
	// confirm a domain's native id and bind it to a client. It never grants
	// access to client telemetry by itself.
	CanManageQRadarBindings bool
	// CanManageDetections allows ingesting Sigma detections (write), not
	// approving translations.
	CanManageDetections bool
}

// RolePermissions maps role names to their permissions.
var RolePermissions = map[string]RolePermission{
	"READ_ONLY": {
		Role:                "READ_ONLY",
		CanViewCTI:          true,
		CanCreateCTI:        false,
		CanCreateArtifact:   false,
		CanCreateBrain:      false,
		CanCreateHypothesis: false,
		CanGenerateAQL:      false,
		CanViewReports:      false,
		CanManageUsers:      false,
		CanViewAudit:        false,
	},
	"CTI_ANALYST": {
		Role:                "CTI_ANALYST",
		CanViewCTI:          true,
		CanCreateCTI:        true,
		CanCreateArtifact:   true,
		CanCreateBrain:      true,
		CanCreateHypothesis: false,
		CanGenerateAQL:      false,
		CanViewReports:      false,
		CanManageUsers:      false,
		CanViewAudit:        false,
		CanLinkHypothesis:   true,
		CanImportFieldIntel: true,
		CanManageDetections: true,
	},
	"HYPOTHESIS_WRITER": {
		Role:                "HYPOTHESIS_WRITER",
		CanViewCTI:          true,
		CanCreateCTI:        false,
		CanCreateArtifact:   false,
		CanCreateBrain:      false,
		CanCreateHypothesis: true,
		CanGenerateAQL:      true,
		CanViewReports:      false,
		CanManageUsers:      false,
		CanViewAudit:        false,
		CanLinkHypothesis:   true,
	},
	"REPORT_GENERATOR": {
		Role:                "REPORT_GENERATOR",
		CanViewCTI:          true,
		CanCreateCTI:        false,
		CanCreateArtifact:   false,
		CanCreateBrain:      false,
		CanCreateHypothesis: false,
		CanGenerateAQL:      false,
		CanViewReports:      true,
		CanManageUsers:      false,
		CanViewAudit:        false,
	},
	"ADMINISTRATOR": {
		Role:                "ADMINISTRATOR",
		CanViewCTI:          true,
		CanCreateCTI:        true,
		CanCreateArtifact:   true,
		CanCreateBrain:      true,
		CanCreateHypothesis: true,
		CanGenerateAQL:      true,
		CanViewReports:      true,
		CanManageUsers:      true,
		CanViewAudit:        true,
		CanManageClients:    true,
		CanReviewArtifact:   true,
		CanReviewHypothesis: true,
		CanLinkHypothesis:   true,
		CanImportFieldIntel: true,
		CanReviewFieldIntel: true,
		CanManageQRadarBindings: true,
		CanManageDetections: true,
	},
	// REVIEWER is the dedicated, narrowly-scoped human-reviewer role (M6).
	// It can view and review, but cannot create CTI, artifacts, hypotheses,
	// or manage users/clients. CTI_ANALYST explicitly has no REVIEW rights.
	"REVIEWER": {
		Role:                "REVIEWER",
		CanViewCTI:          true,
		CanCreateCTI:        false,
		CanCreateArtifact:   false,
		CanCreateBrain:      false,
		CanCreateHypothesis: false,
		CanGenerateAQL:      false,
		CanViewReports:      true,
		CanManageUsers:      false,
		CanViewAudit:        false,
		CanManageClients:    false,
		CanReviewArtifact:   true,
		CanReviewHypothesis: true,
		CanReviewFieldIntel: true,
	},
}

// GetPermission returns the permission set for a role.
func GetPermission(role string) (RolePermission, bool) {
	p, ok := RolePermissions[role]
	return p, ok
}

// RequireRole returns middleware that checks the user's role has the required permission.
type PermissionCheck func(rp RolePermission) bool

// RequirePermission creates middleware that checks a specific permission.
func RequirePermission(check PermissionCheck) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionID := getSessionFromRequest(r)
			if sessionID == "" {
				http.Error(w, `{"error":{"code":"AUTH_FAILED","message":"not authenticated"}}`, http.StatusUnauthorized)
				return
			}

			session, err := globalDB.GetSession(sessionID)
			if err != nil || session == nil {
				http.Error(w, `{"error":{"code":"AUTH_FAILED","message":"invalid or expired session"}}`, http.StatusUnauthorized)
				return
			}

			role, err := globalDB.GetUserRole(session.UserID)
			if err != nil {
				http.Error(w, `{"error":{"code":"AUTH_FAILED","message":"user not found"}}`, http.StatusUnauthorized)
				return
			}

			rp, ok := GetPermission(role)
			if !ok {
				http.Error(w, `{"error":{"code":"FORBIDDEN","message":"unknown role"}}`, http.StatusForbidden)
				return
			}

			if !check(rp) {
				http.Error(w, `{"error":{"code":"FORBIDDEN","message":"insufficient permissions"}}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CanViewCTI checks if the role can view CTI reports.
func CanViewCTI(rp RolePermission) bool {
	return rp.CanViewCTI
}

// CanCreateCTI checks if the role can create CTI reports.
func CanCreateCTI(rp RolePermission) bool {
	return rp.CanCreateCTI
}

// CanCreateHypothesis checks if the role can create hunt hypothesis drafts.
func CanCreateHypothesis(rp RolePermission) bool {
	return rp.CanCreateHypothesis
}

// CanViewAudit checks if the role can view audit logs.
func CanViewAudit(rp RolePermission) bool {
	return rp.CanViewAudit
}

// CanManageClients checks if the role can manage clients.
func CanManageClients(rp RolePermission) bool {
	return rp.CanManageClients
}

// IsAdministrator checks if the role is ADMINISTRATOR.
func IsAdministrator(rp RolePermission) bool {
	return rp.Role == "ADMINISTRATOR"
}

// requireFieldCapability enforces a field-intel capability inside the service
// layer, so direct callers and future MCP tools get the same answer as HTTP.
func requireFieldCapability(userID string, check PermissionCheck) error {
	rp, ok := GetPermission(userRoleOf(userID))
	if !ok || !check(rp) {
		return ErrFieldAccessDenied
	}
	return nil
}

// CanImportFieldIntel checks whether the role may upload telemetry and edit
// candidate field data. It does not permit approving or publishing.
func CanImportFieldIntel(rp RolePermission) bool { return rp.CanImportFieldIntel }

// CanReviewFieldIntel checks whether the role may review batches, approve
// candidate mappings and attest field verification.
func CanReviewFieldIntel(rp RolePermission) bool { return rp.CanReviewFieldIntel }

// CanReviewArtifact checks if the role has REVIEW permission for artifacts.
func CanReviewArtifact(rp RolePermission) bool {
	return rp.CanReviewArtifact
}

// CanReviewHypothesis checks if the role has REVIEW permission for hypotheses.
func CanReviewHypothesis(rp RolePermission) bool {
	return rp.CanReviewHypothesis
}

// CanCreateNote checks if the role may create analyst notes.
// Per M6 spec: all roles except READ_ONLY may create notes.
func CanCreateNote(rp RolePermission) bool {
	return rp.Role != "READ_ONLY"
}

// CanLinkHypothesis checks if the role may link an existing hypothesis to a case.
// Distinct from CanCreateHypothesis: creating a hypothesis draft is separate
// from linking an already-existing hypothesis.
func CanLinkHypothesis(rp RolePermission) bool {
	return rp.CanLinkHypothesis
}

// FormatPermissionError returns a standardized JSON error for permission denials.
func FormatPermissionError(code, message string) string {
	return fmt.Sprintf(`{"error":{"code":"%s","message":"%s"}}`, code, message)
}

// CanManageQRadarBindings reports whether the role may confirm domain bindings.
func CanManageQRadarBindings(rp RolePermission) bool { return rp.CanManageQRadarBindings }

// canManageBindings is the service-side shorthand used by the resolver.
func canManageBindings(userID string) bool {
	rp, ok := GetPermission(userRoleOf(userID))
	return ok && rp.CanManageQRadarBindings
}

// CanManageDetections reports whether the role may ingest Sigma detections.
func CanManageDetections(rp RolePermission) bool { return rp.CanManageDetections }

// CanGenerateAQL reports whether the role may generate AQL drafts.
func CanGenerateAQL(rp RolePermission) bool { return rp.CanGenerateAQL }
