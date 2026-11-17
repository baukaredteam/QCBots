package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// sessionCache is an in-memory cache of active sessions, used to avoid
// SQLite locking issues on Windows when reads follow writes.
var sessionCache = &sessionCacheType{
	sessions: make(map[string]*Session),
}

// revokedSessions tracks session IDs that have been deleted/revoked in the
// database but may still reside in sessionCache. GetSession() consults this
// set to fail-closed on cached-but-revoked sessions.
var revokedSessions = make(map[string]struct{})
var revokedSessionsMu sync.RWMutex

func revokeSession(sessionID string) {
	revokedSessionsMu.Lock()
	revokedSessions[sessionID] = struct{}{}
	revokedSessionsMu.Unlock()
}

func isRevokedSession(sessionID string) bool {
	revokedSessionsMu.RLock()
	_, ok := revokedSessions[sessionID]
	revokedSessionsMu.RUnlock()
	return ok
}

type sessionCacheType struct {
	mu        sync.RWMutex
	sessions  map[string]*Session
}

func (sc *sessionCacheType) store(s *Session) {
	sc.mu.Lock()
	sc.sessions[s.SessionID] = s
	sc.mu.Unlock()
}

func (sc *sessionCacheType) load(sessionID string) *Session {
	sc.mu.RLock()
	s := sc.sessions[sessionID]
	sc.mu.RUnlock()
	return s
}

func (sc *sessionCacheType) delete(sessionID string) {
	sc.mu.Lock()
	delete(sc.sessions, sessionID)
	sc.mu.Unlock()
}

// pbkdf2Iterations is the number of PBKDF2 iterations for password hashing.
// 100,000 iterations provides reasonable security while remaining performant.
const pbkdf2Iterations = 100000
const pbkdf2SaltLen = 16
const pbkdf2KeyLen = 32

// hashPassword hashes a password using PBKDF2-HMAC-SHA256 with a random salt.
// This is significantly stronger than plain SHA-256 and suitable for password storage.
func hashPassword(password string) (string, error) {
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	key := pbkdf2Key([]byte(password), salt, pbkdf2Iterations, pbkdf2KeyLen)
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(key), nil
}

// verifyPassword checks a password against a PBKDF2 hash.
func verifyPassword(storedHash, password string) bool {
	parts := strings.Split(storedHash, ":")
	if len(parts) != 2 {
		return false
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}
	expectedKey, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	computedKey := pbkdf2Key([]byte(password), salt, pbkdf2Iterations, pbkdf2KeyLen)
	return hmac.Equal(computedKey, expectedKey)
}

// pbkdf2Key implements PBKDF2-HMAC-SHA256.
func pbkdf2Key(password, salt []byte, iterations, keyLen int) []byte {
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen

	key := make([]byte, keyLen)
	for block := 1; block <= numBlocks; block++ {
		// U1 = HMAC(password, salt || INT32_BE(block))
		blockBytes := make([]byte, 4)
		blockBytes[0] = byte(block >> 24)
		blockBytes[1] = byte(block >> 16)
		blockBytes[2] = byte(block >> 8)
		blockBytes[3] = byte(block)

		u1 := hmac.New(sha256.New, password)
		u1.Write(append(salt, blockBytes...))
		last := u1.Sum(nil)

		for i := 1; i < iterations; i++ {
			u1 = hmac.New(sha256.New, password)
			u1.Write(last)
			last = u1.Sum(nil)
			for j := 0; j < hashLen; j++ {
				key[(block-1)*hashLen+j] ^= last[j]
			}
		}
	}
	return key
}

// Session represents an authenticated user session.
type Session struct {
	SessionID    string
	UserID       string
	ClientID     string
	ExpiresAt    time.Time
	CreatedAt    time.Time
	LastAccessed time.Time
}

// AuthResult is the result of an authentication attempt.
type AuthResult struct {
	Success bool
	UserID  string
	Role    string
	Error   string
}

// generateSessionID creates a random session ID.
func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Authenticate validates username/password against the database.
func (db *DB) Authenticate(username, password string) (*AuthResult, error) {
	var userID, passwordHash, role string
	err := db.QueryRow(`SELECT user_id, password_hash, role FROM users WHERE username = ? AND is_active = 1`, username).
		Scan(&userID, &passwordHash, &role)
	if err != nil {
		if err == sql.ErrNoRows {
			return &AuthResult{Success: false, Error: "invalid credentials"}, nil
		}
		return nil, fmt.Errorf("querying user: %w", err)
	}

	if !verifyPassword(passwordHash, password) {
		return &AuthResult{Success: false, Error: "invalid credentials"}, nil
	}

	return &AuthResult{Success: true, UserID: userID, Role: role}, nil
}

// CreateSession creates a new session for a user bound to a specific client.
func (db *DB) CreateSession(userID, clientID string) (*Session, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	expiresAt := now.Add(8 * time.Hour)

	session := &Session{
		SessionID:   sessionID,
		UserID:      userID,
		ClientID:    clientID,
		ExpiresAt:   expiresAt,
		CreatedAt:   now,
		LastAccessed: now,
	}

	_, err = db.Exec(`INSERT INTO sessions (session_id, user_id, client_id, expires_at, created_at, last_accessed_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		session.SessionID, session.UserID, session.ClientID,
		session.ExpiresAt.Format(time.RFC3339), session.CreatedAt.Format(time.RFC3339),
		session.LastAccessed.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	// Cache in memory for fast, lock-free access
	sessionCache.store(session)

	return session, nil
}

// GetSession retrieves and validates a session by ID.
//
// The in-memory cache is checked first, but the expiry is verified before
// returning a cached session so that an expired session cannot be served
// from cache alone. Deleted/revoked sessions are removed from both cache
// and database.
func (db *DB) GetSession(sessionID string) (*Session, error) {
	// Check in-memory cache first (avoids SQLite locking issues),
	// but verify expiry and revocation before returning a cached session.
	if s := sessionCache.load(sessionID); s != nil {
		if time.Now().After(s.ExpiresAt) {
			sessionCache.delete(sessionID)
			db.Exec(`DELETE FROM sessions WHERE session_id = ?`, sessionID)
			return nil, nil
		}
		if isRevokedSession(sessionID) {
			sessionCache.delete(sessionID)
			return nil, nil
		}
		return s, nil
	}

	var s Session
	var expiresAt, createdAt, lastAccessed string
	err := db.QueryRow(`SELECT session_id, user_id, client_id, expires_at, created_at, last_accessed_at
		FROM sessions WHERE session_id = ?`, sessionID).
		Scan(&s.SessionID, &s.UserID, &s.ClientID, &expiresAt, &createdAt, &lastAccessed)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("querying session: %w", err)
	}

	s.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("parsing expires_at: %w", err)
	}
	s.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("parsing created_at: %w", err)
	}
	s.LastAccessed, err = time.Parse(time.RFC3339, lastAccessed)
	if err != nil {
		return nil, fmt.Errorf("parsing last_accessed_at: %w", err)
	}

	if time.Now().After(s.ExpiresAt) {
		db.Exec(`DELETE FROM sessions WHERE session_id = ?`, sessionID)
		sessionCache.delete(sessionID)
		return nil, nil
	}

	// Cache for future lookups (expiry will be re-checked on next read).
	sessionCache.store(&s)

	db.Exec(`UPDATE sessions SET last_accessed_at = datetime('now') WHERE session_id = ?`, sessionID)

	return &s, nil
}

// DeleteSession removes a session by ID.
func (db *DB) DeleteSession(sessionID string) error {
	sessionCache.delete(sessionID)
	revokeSession(sessionID)
	_, err := db.Exec(`DELETE FROM sessions WHERE session_id = ?`, sessionID)
	return err
}

// GetUserRole returns the role for a user.
func (db *DB) GetUserRole(userID string) (string, error) {
	var role string
	err := db.QueryRow(`SELECT role FROM users WHERE user_id = ? AND is_active = 1`, userID).Scan(&role)
	if err != nil {
		return "", err
	}
	return role, nil
}

// GetUserAuthorizedClients returns the client IDs a user is authorized for.
//
// Single source of truth: persistent user_authorized_clients table.
// The in-memory ClientAccessStore is retained for backward compatibility
// but is not consulted by new code.
func (db *DB) GetUserAuthorizedClients(userID string) ([]string, error) {
	rows, err := db.Query(`SELECT client_id FROM user_authorized_clients WHERE user_id = ?`, userID)
	if err != nil {
		return nil, fmt.Errorf("querying user authorized clients: %w", err)
	}
	defer rows.Close()

	var clients []string
	for rows.Next() {
		var clientID string
		if err := rows.Scan(&clientID); err != nil {
			return nil, fmt.Errorf("scanning client id: %w", err)
		}
		clients = append(clients, clientID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating client rows: %w", err)
	}
	return clients, nil
}

// CanAccessClient checks whether userID is authorized to access clientID
// via the persistent user_authorized_clients table.
//
// Fail-closed: any database error or missing grant results in false.
func (db *DB) CanAccessClient(userID, clientID string) bool {
	clients, err := db.GetUserAuthorizedClients(userID)
	if err != nil {
		return false
	}
	for _, c := range clients {
		if c == clientID {
			return true
		}
	}
	return false
}

// CanAccessClient is a package-level wrapper that uses the global database.
// It exists for backward compatibility; new code should call
// (*DB).CanAccessClient directly with an explicit *DB.
func CanAccessClient(userID, clientID string) bool {
	if globalDB == nil {
		return false
	}
	return globalDB.CanAccessClient(userID, clientID)
}

// getSessionFromRequest extracts the session ID from the Cookie header.
func getSessionFromRequest(r *http.Request) string {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return ""
	}
	return cookie.Value
}

// setSessionCookie sets the session_id cookie on the response.
// Secure flag is only set when isSecure=true (HTTPS production).
// SameSite=Lax allows cross-site top-level GET but blocks cross-site POST,
// which provides CSRF protection for state-changing operations.
func setSessionCookie(w http.ResponseWriter, sessionID string, secure bool) {
	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		MaxAge:   8 * 3600,
	}
	http.SetCookie(w, cookie)
}

// clearSessionCookie clears the session_id cookie.
func clearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
		MaxAge:   -1,
	}
	http.SetCookie(w, cookie)
}

// setCSRFCookie sets the CSRF token cookie (double-submit pattern).
func setCSRFCookie(w http.ResponseWriter, token string, secure bool) {
	cookie := &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		Path:     "/",
		HttpOnly: false, // Must be accessible by JS for double-submit
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		MaxAge:   8 * 3600,
	}
	http.SetCookie(w, cookie)
}

// clearCSRFCookie clears the CSRF token cookie.
func clearCSRFCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
		MaxAge:   -1,
	}
	http.SetCookie(w, cookie)
}

// generateCSRFToken creates a random CSRF token.
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// validateCSRFToken checks that the CSRF token in the header matches the cookie.
func validateCSRFToken(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}

	cookie, err := r.Cookie("csrf_token")
	if err != nil {
		return false
	}
	cookieToken := cookie.Value

	headerToken := r.Header.Get("X-CSRF-Token")
	if headerToken == "" {
		return false
	}

	return hmac.Equal([]byte(cookieToken), []byte(headerToken))
}
