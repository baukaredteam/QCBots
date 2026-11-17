package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"time"
)

// ErrAuthFailed is returned when MCP authentication fails.
var ErrAuthFailed = fmt.Errorf("AUTH_FAILED")

// ResolveMCPClientIdentity looks up the mcp_client_id in the mcp_client_identity
// table and returns the associated userID. This is identification only,
// NOT authentication — mcp_client_id is never used as a sole credential.
func ResolveMCPClientIdentity(mcpClientID string) (string, error) {
	if mcpClientID == "" {
		return "", fmt.Errorf("%w: mcp_client_id is required", ErrAuthFailed)
	}
	var userID string
	var revoked int
	var expiresAt sql.NullString
	err := globalDB.QueryRow(`
		SELECT user_id, revoked, expires_at
		FROM mcp_client_identity WHERE mcp_client_id = ?`, mcpClientID).
		Scan(&userID, &revoked, &expiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("%w: unknown or revoked mcp_client_id", ErrAuthFailed)
		}
		return "", fmt.Errorf("%w: resolving mcp_client_id: %w", ErrAuthFailed, err)
	}
	if revoked != 0 {
		return "", fmt.Errorf("%w: mcp_client_id revoked", ErrAuthFailed)
	}
	if expiresAt.Valid && expiresAt.String != "" {
		exp, parseErr := time.Parse(time.RFC3339, expiresAt.String)
		if parseErr == nil && time.Now().After(exp) {
			return "", fmt.Errorf("%w: mcp_client_id expired", ErrAuthFailed)
		}
	}
	return userID, nil
}

// ResolveMCPClientCredential looks up the credential verifier for a given
// client_id in the mcp_client_credential table. Returns the stored hash,
// the bound userID, and whether the credential is expired or revoked.
func ResolveMCPClientCredential(clientID string) (credentialHash, userID string, err error) {
	if clientID == "" {
		return "", "", fmt.Errorf("%w: client_id is required", ErrAuthFailed)
	}
	var expiresAt sql.NullString
	var revoked int
	err = globalDB.QueryRow(`
		SELECT credential_hash, user_id, expires_at, revoked
		FROM mcp_client_credential WHERE client_id = ?`,
		clientID).Scan(&credentialHash, &userID, &expiresAt, &revoked)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", fmt.Errorf("%w: no credential registered for client_id", ErrAuthFailed)
		}
		return "", "", fmt.Errorf("%w: resolving credential: %w", ErrAuthFailed, err)
	}
	if revoked != 0 {
		return "", "", fmt.Errorf("%w: credential revoked for client_id", ErrAuthFailed)
	}
	if expiresAt.Valid && expiresAt.String != "" {
		exp, parseErr := time.Parse(time.RFC3339, expiresAt.String)
		if parseErr == nil && time.Now().After(exp) {
			return "", "", fmt.Errorf("%w: credential expired for client_id", ErrAuthFailed)
		}
	}
	return credentialHash, userID, nil
}

// hashCredential returns the SHA-256 hex digest of the given credential.
// Only the hash is stored server-side; the plaintext secret is never persisted.
func hashCredential(credential string) string {
	sum := sha256.Sum256([]byte(credential))
	return hex.EncodeToString(sum[:])
}

// ValidateStdioCredential validates the client-provided credential against the
// MCP_CREDENTIAL environment variable. This is the server's shared credential
// loaded from the process environment — never compared against itself.
//
// This is the primary authentication mechanism for local stdio connections.
// The credential must be communicated out-of-band to the client (e.g., via
// secure configuration), never via CLI arguments or logs.
func ValidateStdioCredential(clientCredential string) error {
	expectedCredential := os.Getenv("MCP_CREDENTIAL")
	if expectedCredential == "" {
		return fmt.Errorf("%w: MCP_CREDENTIAL environment variable not set on server", ErrAuthFailed)
	}
	if subtle.ConstantTimeCompare([]byte(clientCredential), []byte(expectedCredential)) != 1 {
		return fmt.Errorf("%w: invalid credential", ErrAuthFailed)
	}
	return nil
}

// ValidateMCPClientCredential validates a client-provided credential against
// BOTH:
//   1. The MCP_CREDENTIAL environment variable (shared server credential)
//   2. The per-client credential hash in mcp_client_credential table
//
// Either validation path may succeed. The per-client hash binds the credential
// to a specific client_id and Workbench user, preventing client A's credential
// from being used with client B's identifier.
//
// Only the hash of the client-provided credential is compared against stored
// hashes — the plaintext secret is never persisted, logged, or returned.
func ValidateMCPClientCredential(clientID, clientCredential string) (userID string, err error) {
	if clientCredential == "" {
		return "", fmt.Errorf("%w: credential is required", ErrAuthFailed)
	}

	// Path 1: Validate against MCP_CREDENTIAL environment variable (shared credential).
	// This is the primary mechanism for local stdio connections.
	if envErr := ValidateStdioCredential(clientCredential); envErr == nil {
		// Env credential matches. Now resolve the client_id to a user.
		resolvedUserID, err := ResolveMCPClientIdentity(clientID)
		if err != nil {
			return "", err
		}
		return resolvedUserID, nil
	}

	// Path 2: Validate against per-client credential hash in the database.
	// This binds the credential to a specific client_id and user.
	storedHash, boundUserID, err := ResolveMCPClientCredential(clientID)
	if err != nil {
		return "", err
	}
	if hashCredential(clientCredential) != storedHash {
		return "", fmt.Errorf("%w: invalid credential for client_id", ErrAuthFailed)
	}
	return boundUserID, nil
}

// AuthenticateMCPCall performs combined authentication for an MCP tool call.
//
// Authentication rules:
//   1. mcp_credential is validated against MCP_CREDENTIAL env var (shared
//      server credential) OR against the per-client credential hash bound to
//      the specific client_id. This is the actual authentication.
//   2. mcp_client_id is resolved to userID via mcp_client_identity table —
//      identification only, NOT authentication.
//   3. The credential-bound user must match the identity-bound user (when
//      using per-client credential binding).
//   4. Expiry and revocation are checked per call.
//   5. Rights (role + client grants) are checked per call, never cached.
//
// mcp_client_id and mcp_credential come from the trusted server-side context
// established during MCP connection setup — never from untrusted HTTP
// parameters. user_id is NEVER accepted from tool arguments.
func AuthenticateMCPCall(mcpClientID, mcpCredential string) (userID, role string, authorizedClients []string, err error) {
	// Step 1: Validate the credential. This is the actual authentication.
	boundUserID, err := ValidateMCPClientCredential(mcpClientID, mcpCredential)
	if err != nil {
		return "", "", nil, err
	}

	// Step 2: mcp_client_id must resolve to a user (identification only).
	resolvedUserID, err := ResolveMCPClientIdentity(mcpClientID)
	if err != nil {
		return "", "", nil, err
	}

	// Step 3: The credential-bound user must match the identity-bound user.
	// This prevents using client A's credential with client B's identifier.
	if boundUserID != resolvedUserID {
		return "", "", nil, fmt.Errorf("%w: credential bound to different user than mcp_client_id", ErrAuthFailed)
	}

	userID = resolvedUserID

	// Step 4: Check RBAC role — per call, never cached.
	role, err = globalDB.GetUserRole(userID)
	if err != nil {
		return "", "", nil, fmt.Errorf("%w: user role lookup failed: %w", ErrAuthFailed, err)
	}
	if role == "" {
		return "", "", nil, fmt.Errorf("%w: unknown role for user", ErrAuthFailed)
	}

	// Step 5: Check client grants — per call, never cached.
	authorizedClients, err = globalDB.GetUserAuthorizedClients(userID)
	if err != nil {
		return "", "", nil, fmt.Errorf("%w: client grant lookup failed: %w", ErrAuthFailed, err)
	}

	return userID, role, authorizedClients, nil
}

// GetMCPClientCredentialEnv returns the MCP_CREDENTIAL environment variable.
// This is NOT used for actual authentication — only the mcp_client_credential
// table or ValidateStdioCredential are authoritative.
func GetMCPClientCredentialEnv() string {
	return os.Getenv("MCP_CREDENTIAL")
}