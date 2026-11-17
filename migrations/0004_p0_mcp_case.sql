-- Migration 0004_p0_mcp_case.sql
-- P0: Secure MCP Gateway + Research Case MVP
-- Only new tables, no modifications to existing tables

PRAGMA foreign_keys = ON;

-- mcp_client_identity: MCP client -> user binding (identifier, NOT credential)
CREATE TABLE IF NOT EXISTS mcp_client_identity (
    mcp_client_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
);

-- mcp_client_credential: credential verifier bound to a specific client and user.
-- Stores only a SHA-256 hash of the credential, never the plaintext secret.
-- Each client_id has exactly one credential, preventing client A's credential
-- from being used with client B's identifier.
CREATE TABLE IF NOT EXISTS mcp_client_credential (
    client_id TEXT PRIMARY KEY REFERENCES mcp_client_identity(mcp_client_id),
    credential_hash TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(user_id),
    expires_at TEXT,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- user_authorized_clients: persistent multi-client grants
CREATE TABLE IF NOT EXISTS user_authorized_clients (
    grant_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id),
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    granted_by TEXT REFERENCES users(user_id),
    granted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT,
    UNIQUE(user_id, client_id)
);

-- research_cases: central case entity
CREATE TABLE IF NOT EXISTS research_cases (
    case_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT,
    owner_id TEXT NOT NULL REFERENCES users(user_id),
    status TEXT NOT NULL DEFAULT 'OPEN'
        CHECK (status IN ('OPEN','IN_PROGRESS','REVIEW','CLOSED','ARCHIVED')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at TEXT
);

-- case_authorized_participants: case-level access control
CREATE TABLE IF NOT EXISTS case_authorized_participants (
    grant_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES research_cases(case_id),
    user_id TEXT NOT NULL REFERENCES users(user_id),
    role_in_case TEXT NOT NULL DEFAULT 'VIEWER'
        CHECK (role_in_case IN ('OWNER','EDITOR','VIEWER')),
    granted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(case_id, user_id)
);

-- case_artifacts: external tool results, AQL drafts, evidence
CREATE TABLE IF NOT EXISTS case_artifacts (
    artifact_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES research_cases(case_id),
    visibility_scope TEXT NOT NULL DEFAULT 'CLIENT'
        CHECK (visibility_scope IN ('GLOBAL','CLIENT')),
    client_id TEXT REFERENCES clients(client_id),
    data_classification TEXT NOT NULL DEFAULT 'INTERNAL'
        CHECK (data_classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
    provenance_source TEXT NOT NULL,
    artifact_hash TEXT NOT NULL UNIQUE,
    sanitized_representation TEXT,
    raw_storage_ref TEXT,
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    review_status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (review_status IN ('PENDING','APPROVED','REJECTED'))
);
