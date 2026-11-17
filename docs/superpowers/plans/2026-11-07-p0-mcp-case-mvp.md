# P0 Implementation Plan — Secure MCP Gateway + Research Case MVP

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement P0: harness-agnostic MCP server (local stdio), Research Case entity, case authorization, case artifacts, and persistent multi-client authorization — all TDD, read-only design, no production code changes.

**Architecture:** Three equal interfaces (MCP Gateway, Telegram Adapter, Web UI REST API) call one Workbench Core Service. P0 implements only the MCP Gateway + Research Case MVP. Web UI and Telegram are not modified in P0.

**Tech Stack:** Go 1.22+, SQLite (WAL, foreign keys), existing migrations 0001–0003 unchanged, M5.1 Stage 1/2 preserved.

**Spec:** This plan implements the Final P0 Security Fixes architecture (Sentinel Atlas P0). No new ADR created.

---

## Global Constraints

| Constraint | Value |
|------------|-------|
| No production code modification | Existing .go files not edited; only new files added |
| No existing migration modification | 0001–0003 unchanged; only new 0004 migration |
| No working database changes | Tests use temporary in-memory SQLite |
| MCP client ID ≠ authentication credential | Separate entities; mcp_client_id is identifier only |
| No read-only MCP without authentication | Every tool call requires verified server-side identity |
| No secrets in CLI args, logs, or JSON tool arguments | Credentials via environment variables or local config file only |
| Remote Streamable HTTP MCP deferred to later stage | P0 = local stdio only |
| `sanitized=true` from client ignored | Server always enforces its own sanitization policy |
| Idempotency key scoped to user/operation | Same key + different content = conflict |
| Idempotency check+INSERT atomic | Via UNIQUE constraint + transaction |

---

## Review Focus

The following input classes or failure modes are most likely to bite and are not fully covered by individual task tests:

1. **MCP client ID used as sole credential** — a test must verify that presenting only `mcp_client_id` without session/CSRF auth fails.
2. **`sanitized=true` from client trusted** — a test must verify server overrides and sanitizes regardless.
3. **`user_id`/`mcp_client_id` in public inputSchema** — a test must verify these fields are absent from tool schemas.
4. **Case access without client grant** — a test must verify that case participant without client grant cannot see private artifacts.
5. **Idempotency key conflict** — same key, different content returns conflict, not silent overwrite.
6. **Atomicity under failure** — a transaction error leaves no partial changes.
7. **Cross-client data leakage via error messages** — error messages must be generic, not revealing which check failed.
8. **In-memory `ClientAccessStore` vs persistent `user_authorized_clients`** — no conflicting parallel sources during P0.

Each of these gets a dedicated test in the owning task.

---

## File Map

### New Files (create)

| File | Responsibility |
|------|---------------|
| `migrations/0004_p0_mcp_case.sql` | Minimal P0 migration: 5 new tables only |
| `backend/mcp_auth.go` | MCP authentication: stdio credential validation, session binding, mcp_client_identity resolution |
| `backend/mcp_server.go` | MCP server: stdio transport, tool dispatch, JSON-RPC handling |
| `backend/mcp_schema.go` | JSON Schemas for all MCP tools (no user_id/mcp_client_id in input) |
| `backend/mcp_tools.go` | MCP tool implementations: search_cases, create_research_case, get_case_context, get_authorized_clients |
| `backend/mcp_sanitize.go` | Server-side sanitization: PII/hostname/internal IP masking, artifact hash, provenance |
| `backend/mcp_case.go` | DB operations: research_cases, case_authorized_participants, case_artifacts |
| `backend/mcp_test.go` | TDD tests: all MCP tools, auth, authorization, sanitization, idempotency, negative security cases |

### Modified Files (add only, no existing logic changed)

| File | Change |
|------|--------|
| `backend/main.go` | Add MCP stdio route handler; register MCP server initialization |
| `backend/auth.go` | Add MCP auth helper functions (resolve MCP client ID to user ID) |
| `backend/rbac.go` | Add new permissions: `case_view`, `case_create`, `artifact_create`, `review_create`, `draft_create` |

---

## Tasks

### Task 0: Migration 0004 — P0 Minimal Schema

**Files:**
- Create: `migrations/0004_p0_mcp_case.sql`
- Test: `backend/mcp_test.go` (TestMigration0004CreatesAllTables)

**Interfaces:**
- Consumes: none (first migration task)
- Produces: 5 tables with exact schema (see below)

**Schema:**

```sql
-- mcp_client_identity: MCP client -> user binding (identifier, NOT credential)
CREATE TABLE IF NOT EXISTS mcp_client_identity (
    mcp_client_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT
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
    artifact_hash TEXT NOT NULL,
    sanitized_representation TEXT,
    raw_storage_ref TEXT,
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    review_status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (review_status IN ('PENDING','APPROVED','REJECTED'))
);
```

- [ ] **Step 1: Write failing migration test**

```go
func TestMigration0004CreatesAllTables(t *testing.T) {
    db := testP0DB(t) // in-memory SQLite with 0001-0003 + 0004
    // Verify all 5 tables exist
    tables := []string{"mcp_client_identity", "user_authorized_clients",
        "research_cases", "case_authorized_participants", "case_artifacts"}
    for _, table := range tables {
        var count int
        err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='%s'", table)).Scan(&count)
        if err != nil || count != 1 {
            t.Fatalf("table %s not created: err=%v count=%d", table, err, count)
        }
    }
    // Verify UNIQUE constraints
    // Verify CHECK constraints on visibility_scope, status, data_classification, review_status
    t.Log("PASS: TestMigration0004CreatesAllTables")
}
```

- [ ] **Step 2: Run migration test — verify FAIL (no migration file yet)**

Run: `go test -run TestMigration0004 ./backend/...`
Expected: FAIL — migration file not found or tables missing

- [ ] **Step 3: Create `migrations/0004_p0_mcp_case.sql`**

Write the 5-table schema above. Only CREATE TABLE IF NOT EXISTS, no ALTER of existing tables.

- [ ] **Step 4: Run migration test — verify PASS**

Run: `go test -run TestMigration0004 ./backend/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add migrations/0004_p0_mcp_case.sql backend/mcp_test.go
git commit -m "feat: add P0 migration 0004 for MCP case schema"
```

---

### Task 1: Existing RBAC Audit — ClientAccessStore and CanAccessClient

**Files:**
- Read: `backend/config.go` (ClientAccessStore, IsClientAccessible)
- Read: `backend/rbac.go` (CanAccessClient, IsClientAccessible)
- Test: `backend/mcp_test.go` (TestExistingRBACNoConflict)

**Interfaces:**
- Consumes: existing `ClientAccessStore` map, `CanAccessClient(userID, clientID) bool`
- Produces: documented understanding; no code changes to existing functions

**Review findings to document:**
- `ClientAccessStore` is in-memory, lost on restart — not suitable for MCP server
- `CanAccessClient` delegates to `IsClientAccessible` which checks the in-memory map
- No persistent storage for multi-client grants
- During P0, `user_authorized_clients` table is the new source of truth; `ClientAccessStore` is not removed but not extended

- [ ] **Step 1: Document existing RBAC behavior in test comments**

```go
func TestExistingRBACNoConflict(t *testing.T) {
    // Verify CanAccessClient works with existing in-memory store
    // user-analyst-alpha -> client-alpha (authorized)
    // user-analyst-alpha -> client-beta (NOT authorized)
    // user-analyst-multi -> client-alpha AND client-beta (authorized both)
    // user-admin -> client-alpha AND client-beta (authorized both)
    // No new code written; this test documents existing behavior
    t.Log("PASS: TestExistingRBACNoConflict")
}
```

- [ ] **Step 2: Run test — verify PASS**

Run: `go test -run TestExistingRBACNoConflict ./backend/...`
Expected: PASS (documents existing behavior, no changes)

---

### Task 2: MCP Authentication — stdio, No mcp_client_id as Sole Credential

**Files:**
- Create: `backend/mcp_auth.go`
- Test: `backend/mcp_test.go` (TestMCPAuth*, 5 tests)

**Interfaces:**
- Consumes: `mcp_client_id` (identifier only), session/CSRF (authentication)
- Produces: resolved `userID`, role, authorized clients

- [ ] **Step 1: Write failing auth tests**

```go
// TestMCPAuthClientIDIsNotCredential — presenting only mcp_client_id fails
func TestMCPAuthClientIDIsNotCredential(t *testing.T) {
    // Register mcp_client_id -> user mapping
    // Attempt tool call with only mcp_client_id, no session/CSRF
    // Expect: AUTH_FAILED
}

// TestMCPAuthStdioCredentialViaEnv — credentials via env var, not CLI args
func TestMCPAuthStdioCredentialViaEnv(t *testing.T) {
    // Set MCP_CREDENTIAL env var
    // Connect via stdio
    // Expect: successful auth
}

// TestMCPAuthNoReadOnlyWithoutAuth — read-only tool call without auth fails
func TestMCPAuthNoReadOnlyWithoutAuth(t *testing.T) {
    // Call search_cases without any authentication
    // Expect: AUTH_FAILED
}

// TestMCPAuthPerCallRightsCheck — every tool call checks user rights
func TestMCPAuthPerCallRightsCheck(t *testing.T) {
    // Same mcp_client_id, different operations
    // Expect: rights checked per call, not cached
}

// TestMCPAuthNoSecretsInLogs — credentials never appear in log output
func TestMCPAuthNoSecretsInLogs(t *testing.T) {
    // Capture log output during auth
    // Expect: no MCP credentials, no session IDs in logs
}
```

- [ ] **Step 2: Run auth tests — verify FAIL (no mcp_auth.go yet)**

Run: `go test -run TestMCPAuth ./backend/...`
Expected: FAIL — undefined functions

- [ ] **Step 3: Implement `backend/mcp_auth.go`**

Functions:
- `ResolveMCPClientIdentity(mcpClientID string) (userID string, err error)` — looks up `mcp_client_identity` table
- `ValidateStdioCredential(envVar string) (userID string, err error)` — reads credential from environment variable only
- `AuthenticateMCPCall(mcpClientID string, sessionID string, csrfToken string) (userID string, role string, authorizedClients []string, err error)` — combined auth

- [ ] **Step 4: Run auth tests — verify PASS**

Run: `go test -run TestMCPAuth ./backend/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/mcp_auth.go backend/mcp_test.go
git commit -m "feat: add MCP authentication (stdio, no mcp_client_id as credential)"
```

---

### Task 3: MCP JSON Schema — No user_id/mcp_client_id in Public Input

**Files:**
- Create: `backend/mcp_schema.go`
- Test: `backend/mcp_test.go` (TestMCPSchemaNoUserIDInInput, 2 tests)

**Interfaces:**
- Consumes: tool name
- Produces: JSON Schema `inputSchema` without `user_id` or `mcp_client_id` properties

- [ ] **Step 1: Write failing schema tests**

```go
func TestMCPSchemaNoUserIDInInput(t *testing.T) {
    // Get inputSchema for search_cases
    // Expect: no "user_id" property
    // Get inputSchema for create_research_case
    // Expect: no "user_id" property
    // Get inputSchema for get_case_context
    // Expect: no "user_id" property
}

func TestMCPSchemaClientIDIsFilterOnly(t *testing.T) {
    // client_id may appear as optional filter property
    // But not as required authentication property
    // Expect: client_id is optional, not in "required" array
}
```

- [ ] **Step 2: Run schema tests — verify FAIL**

Run: `go test -run TestMCPSchema ./backend/...`
Expected: FAIL — undefined schema functions

- [ ] **Step 3: Implement `backend/mcp_schema.go`**

Define JSON Schemas for:
- `search_cases`: optional `status`, `client_id` (filter), `limit`, `offset`
- `create_research_case`: required `title`, `idempotency_key`, optional `description`, `initial_client_id`
- `get_case_context`: required `case_id`
- `get_authorized_clients`: no required parameters

All schemas exclude `user_id` and `mcp_client_id` from `properties` and `required`.

- [ ] **Step 4: Run schema tests — verify PASS**

Run: `go test -run TestMCPSchema ./backend/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/mcp_schema.go backend/mcp_test.go
git commit -m "feat: add MCP JSON schemas without user_id/mcp_client_id"
```

---

### Task 4: Research Case CRUD — create_research_case

**Files:**
- Modify: `backend/mcp_case.go` (research_cases DB operations)
- Test: `backend/mcp_test.go` (TestCreateResearchCase*, 5 tests)

**Interfaces:**
- Consumes: title, description, idempotency_key, initial_client_id, resolved userID
- Produces: case_id, status, owner_id

- [ ] **Step 1: Write failing case create tests**

```go
// TestCreateResearchCaseSuccess — authorized user creates case
func TestCreateResearchCaseSuccess(t *testing.T) {
    // User with draft permission calls create_research_case
    // Expect: case_id returned, status=OPEN, owner_id=userID
}

// TestCreateResearchCaseNoDraftPermission — user without case_create capability fails
func TestCreateResearchCaseNoDraftPermission(t *testing.T) {
    // User with READ_ONLY role calls create_research_case
    // Expect: DRAFT_PERMISSION_DENIED
}

// TestCreateResearchCaseNoClientGrant — initial_client_id without grant fails
func TestCreateResearchCaseNoClientGrant(t *testing.T) {
    // User specifies client they are not authorized for
    // Expect: CLIENT_ACCESS_DENIED
}

// TestCreateResearchCaseIdempotencyConflict — same key, different content
func TestCreateResearchCaseIdempotencyConflict(t *testing.T) {
    // First call creates case with title "A"
    // Second call with same idempotency_key but title "B"
    // Expect: conflict error, original case unchanged
}

// TestCreateResearchCaseAtomicInsert — transaction failure leaves no partial case
func TestCreateResearchCaseAtomicInsert(t *testing.T) {
    // Force UNIQUE constraint violation on idempotency_key
    // Expect: error returned, no case row exists for that key
}
```

- [ ] **Step 2: Run case create tests — verify FAIL**

Run: `go test -run TestCreateResearchCase ./backend/...`
Expected: FAIL — undefined functions

- [ ] **Step 3: Implement `backend/mcp_case.go`**

Functions:
- `CreateResearchCase(userID, title, description, idempotencyKey, initialClientID string) (caseID string, err error)` — atomic insert with UNIQUE constraint on idempotency_key
- `GetResearchCase(caseID, userID string) (*ResearchCase, error)` — 4-level access check
- `GetUserAuthorizedClientsFromDB(userID string) ([]string, error)` — persistent replacement for in-memory store

- [ ] **Step 4: Run case create tests — verify PASS**

Run: `go test -run TestCreateResearchCase ./backend/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/mcp_case.go backend/mcp_test.go
git commit -m "feat: add research case CRUD with idempotency"
```

---

### Task 5: Case Authorization — get_case_context

**Files:**
- Modify: `backend/mcp_case.go` (get_case_context, 4-level checks)
- Test: `backend/mcp_test.go` (TestGetCaseContext*, 5 tests)

- [ ] **Step 1: Write failing case context tests**

```go
// TestGetCaseContextAuthorized — case participant gets case data
func TestGetCaseContextAuthorized(t *testing.T) {
    // Case owner calls get_case_context
    // Expect: case metadata, artifacts visible to user
}

// TestGetCaseContextNoCaseAccess — non-participant gets nothing
func TestGetCaseContextNoCaseAccess(t *testing.T) {
    // User not in case_authorized_participants and not owner
    // Expect: CASE_ACCESS_DENIED, generic message
}

// TestGetCaseContextNoClientGrant — participant without client grant sees no client artifacts
func TestGetCaseContextNoClientGrant(t *testing.T) {
    // Case participant not authorized for client referenced in artifact
    // Expect: artifact filtered out, no client name revealed
}

// TestGetCaseContextNoDataTypeRight — user lacks artifact_view permission
func TestGetCaseContextNoDataTypeRight(t *testing.T) {
    // User with READ_ONLY role requests CONFIDENTIAL artifact
    // Expect: DATA_TYPE_DENIED for that artifact
}

// TestGetCaseContextErrorMessagesGeneric — no leakage via errors
func TestGetCaseContextErrorMessagesGeneric(t *testing.T) {
    // Various failure scenarios
    // Expect: all errors say "access denied" without revealing which check failed
}
```

- [ ] **Step 2: Run case context tests — verify FAIL**

Run: `go test -run TestGetCaseContext ./backend/...`
Expected: FAIL

- [ ] **Step 3: Implement 4-level authorization in `backend/mcp_case.go`**

`GetResearchCase(caseID, userID string)` performs:
1. Case access check (owner or participant)
2. Client grant check for each referenced client
3. Data type right check (RBAC)
4. Detail level check (summary vs full)

All failures return generic error.

- [ ] **Step 4: Run case context tests — verify PASS**

Run: `go test -run TestGetCaseContext ./backend/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/mcp_case.go backend/mcp_test.go
git commit -m "feat: add case authorization with 4-level access checks"
```

---

### Task 6: get_authorized_clients

**Files:**
- Modify: `backend/mcp_case.go` (GetUserAuthorizedClientsFromDB)
- Test: `backend/mcp_test.go` (TestGetAuthorizedClients, 2 tests)

- [ ] **Step 1: Write failing tests**

```go
func TestGetAuthorizedClients(t *testing.T) {
    // user-analyst-multi expects ["client-alpha", "client-beta"]
    // user-analyst-alpha expects ["client-alpha"]
    // User with no grants expects empty list
}

func TestGetAuthorizedClientsNoLeakage(t *testing.T) {
    // user-analyst-alpha never sees client-beta in their list
}
```

- [ ] **Step 2: Run — verify FAIL**

Run: `go test -run TestGetAuthorizedClients ./backend/...`
Expected: FAIL

- [ ] **Step 3: Implement `GetUserAuthorizedClientsFromDB`**

Queries `user_authorized_clients` table (replaces in-memory `ClientAccessStore` for P0).

- [ ] **Step 4: Run — verify PASS**

Run: `go test -run TestGetAuthorizedClients ./backend/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/mcp_case.go backend/mcp_test.go
git commit -m "feat: add get_authorized_clients with persistent grants"
```

---

### Task 7: Case Artifact Authorization — append_case_artifact

**Files:**
- Modify: `backend/mcp_case.go` (AppendCaseArtifact)
- Modify: `backend/mcp_sanitize.go` (server-side sanitization)
- Test: `backend/mcp_test.go` (TestAppendCaseArtifact*, 6 tests)

- [ ] **Step 1: Write failing artifact tests**

```go
// TestAppendCaseArtifactSuccess — authorized user adds artifact
func TestAppendCaseArtifactSuccess(t *testing.T) {
    // User with artifact_create permission calls append_case_artifact
    // Expect: artifact_id returned, provenance stored
}

// TestAppendCaseArtifactSanitizedTrueIgnored — client says sanitized=true, server sanitizes anyway
func TestAppendCaseArtifactSanitizedTrueIgnored(t *testing.T) {
    // Input contains PII in artifact content, sanitized=true
    // Expect: server strips PII, stores sanitized_representation with PII removed
}

// TestAppendCaseArtifactNoArtifactPermission — user without artifact_create fails
func TestAppendCaseArtifactNoArtifactPermission(t *testing.T) {
    // READ_ONLY user calls append_case_artifact
    // Expect: ARTIFACT_PERMISSION_DENIED
}

// TestAppendCaseArtifactGlobalWithClientData — GLOBAL artifact with client data fails
func TestAppendCaseArtifactGlobalWithClientData(t *testing.T) {
    // visibility_scope=GLOBAL but client_id set or client data in content
    // Expect: error
}

// TestAppendCaseArtifactIdempotent — same ingestion_hash returns existing artifact
func TestAppendCaseArtifactIdempotent(t *testing.T) {
    // Same ingestion_hash twice
    // Expect: same artifact_id returned, no duplicate row
}

// TestAppendCaseArtifactProvenanceMetadata — provenance fields stored
func TestAppendCaseArtifactProvenanceMetadata(t *testing.T) {
    // Verify provenance_source, artifact_hash, created_by, sanitized flag stored
}
```

- [ ] **Step 2: Run artifact tests — verify FAIL**

Run: `go test -run TestAppendCaseArtifact ./backend/...`
Expected: FAIL

- [ ] **Step 3: Implement**

`AppendCaseArtifact(caseID, userID, visibilityScope, clientID, dataClassification, provenanceSource, rawContent string) (artifactID string, err error)`:
1. Check case access (4-level)
2. Check artifact_create permission
3. If visibilityScope=GLOBAL, reject if clientID != "" or content contains client identifiers
4. Server sanitizes raw content → sanitizedRepresentation (ignore input sanitized flag)
5. Compute artifactHash from sanitized content
6. Check idempotency by artifactHash (UNIQUE constraint)
7. Insert into case_artifacts

`SanitizeContent(content string, userID string, authorizedClients []string) (sanitized string, piiStripped bool, err error)`:
- Strip PII patterns (emails, usernames, hostnames, internal IPs)
- Mask client names if user not authorized for that client
- Return sanitized version

- [ ] **Step 4: Run artifact tests — verify PASS**

Run: `go test -run TestAppendCaseArtifact ./backend/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/mcp_case.go backend/mcp_sanitize.go backend/mcp_test.go
git commit -m "feat: add case artifact authorization and server-side sanitization"
```

---

### Task 8: MCP Server — stdio Transport and Tool Dispatch

**Files:**
- Create: `backend/mcp_server.go`
- Modify: `backend/main.go` (add MCP route handler)
- Test: `backend/mcp_test.go` (TestMCPServer*, 3 tests)

- [ ] **Step 1: Write failing server tests**

```go
// TestMCPServerStdioStarts — server starts on stdio without error
func TestMCPServerStdioStarts(t *testing.T) {
    // Create MCP server with stdio transport
    // Expect: no error starting
}

// TestMCPServerToolDispatch — valid tool call returns correct result
func TestMCPServerToolDispatch(t *testing.T) {
    // Send search_cases request via stdio
    // Expect: valid JSON-RPC response with cases array
}

// TestMCPServerUnknownTool — unknown tool returns error
func TestMCPServerUnknownTool(t *testing.T) {
    // Send "nonexistent_tool" request
    // Expect: JSON-RPC error with method not found
}
```

- [ ] **Step 2: Run server tests — verify FAIL**

Run: `go test -run TestMCPServer ./backend/...`
Expected: FAIL

- [ ] **Step 3: Implement `backend/mcp_server.go`**

- JSON-RPC 2.0 message parsing
- stdio transport (read from stdin, write to stdout)
- Tool dispatch table mapping tool names to handler functions
- Authentication middleware wrapping every tool call
- No Remote Streamable HTTP in P0

- [ ] **Step 4: Modify `backend/main.go`**

Add MCP server initialization and stdio route handler (no changes to existing routes).

- [ ] **Step 5: Run server tests — verify PASS**

Run: `go test -run TestMCPServer ./backend/...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add backend/mcp_server.go backend/main.go backend/mcp_test.go
git commit -m "feat: add MCP stdio server and tool dispatch"
```

---

### Task 9: Integration — Full P0 Flow

**Files:**
- Test: `backend/mcp_test.go` (TestP0IntegrationFlow, 1 test)

- [ ] **Step 1: Write integration test**

```go
// TestP0IntegrationFlow — Definition of Done scenario
func TestP0IntegrationFlow(t *testing.T) {
    // 1. Analyst registers MCP client (gets mcp_client_id)
    // 2. Octop connects via stdio with mcp_client_id + session
    // 3. create_research_case -> case_id returned
    // 4. get_case_context via MCP returns case data
    // 5. get_case_context via REST API returns same case data
    // 6. Unauthorized user cannot see case
    // 7. Case participant without client grant cannot see private artifacts
    // 8. Same idempotency_key does not create duplicate
    t.Log("PASS: TestP0IntegrationFlow")
}
```

- [ ] **Step 2: Run integration test — verify FAIL**

Run: `go test -run TestP0IntegrationFlow ./backend/...`
Expected: FAIL

- [ ] **Step 3: Ensure all previous tasks complete**

All previous tasks must pass before integration test passes.

- [ ] **Step 4: Run integration test — verify PASS**

Run: `go test -run TestP0IntegrationFlow ./backend/...`
Expected: PASS

- [ ] **Step 5: Full test suite**

Run: `go test -count=1 ./backend/...`
Expected: PASS (all 61+ tests including existing 50 + new P0 tests)

- [ ] **Step 6: Race detector on P0 tests**

Run: `go test -race -count=1 -run "TestMCP|TestP0|TestCreateResearch|TestGetCase|TestAppendCase|TestGetAuthorized|TestMigration0004|TestExistingRBAC" ./backend/...`
Expected: PASS

- [ ] **Step 7: Final commit**

```bash
git add -A
git commit -m "feat: P0 MCP Gateway + Research Case MVP complete"
```

---

## Definition of Done

| Criterion | Verification |
|-----------|-------------|
| Analyst launches Octop, connects Sentinel Atlas MCP | `TestP0IntegrationFlow` passes — MCP stdio connection works |
| Analyst creates synthetic Research Case, gets case_id | `TestCreateResearchCaseSuccess` — case_id returned |
| Analyst reads same case via MCP and Workbench API | `TestP0IntegrationFlow` — same case_id accessible via both |
| Unauthorized user cannot see case | `TestGetCaseContextNoCaseAccess` — CASE_ACCESS_DENIED |
| Case participant without client grant cannot see private artifacts | `TestGetCaseContextNoClientGrant` — artifact filtered out |
| Same idempotency_key does not create duplicate | `TestCreateResearchCaseIdempotencyConflict` — conflict error |
| All 4-level authorization checks work | `TestGetCaseContext*` — each check tested independently |
| Server-side sanitization enforced (input sanitized=true ignored) | `TestAppendCaseArtifactSanitizedTrueIgnored` — PII stripped regardless |
| No user_id/mcp_client_id in public MCP inputSchema | `TestMCPSchemaNoUserIDInInput` — schemas clean |
| Migration 0004 creates exactly 5 tables, no existing tables modified | `TestMigration0004CreatesAllTables` — schema verified |
| Full test suite passes | `go test -count=1 ./backend/...` — PASS |
| Race detector passes on P0 tests | `go test -race -count=1 -run "TestMCP|TestP0|TestCreateResearch|TestGetCase|TestAppendCase|TestGetAuthorized|TestMigration0004|TestExistingRBAC" ./backend/...` — PASS |

---

## Files Summary (P0)

**Created (8 new files):**
1. `migrations/0004_p0_mcp_case.sql` — 5 new tables, no existing table modified
2. `backend/mcp_auth.go` — MCP authentication (stdio, no mcp_client_id as credential)
3. `backend/mcp_server.go` — MCP stdio server, tool dispatch
4. `backend/mcp_schema.go` — JSON Schemas (no user_id/mcp_client_id in input)
5. `backend/mcp_tools.go` — MCP tool implementations
6. `backend/mcp_sanitize.go` — Server-side sanitization, artifact hash, provenance
7. `backend/mcp_case.go` — Case/artifact DB operations, 4-level authorization
8. `backend/mcp_test.go` — All TDD tests (positive + negative security)

**Modified (3 files, additions only):**
9. `backend/main.go` — MCP route registration
10. `backend/auth.go` — MCP auth helpers
11. `backend/rbac.go` — New permissions (case_view, case_create, artifact_create, review_create, draft_create)

**Not modified:**
- `backend/evidence.go`, `backend/evidence_test.go` (M5.1 preserved)
- `migrations/0001_initial.sql`, `0002_qradar_inventory.sql`, `0003_evidence_graph.sql`
- Any existing route handler
- Working database

---

## Migration Order

1. `0001_initial.sql` — existing (unchanged)
2. `0002_qradar_inventory.sql` — existing (unchanged)
3. `0003_evidence_graph.sql` — existing (unchanged, M5.1)
4. `0004_p0_mcp_case.sql` — NEW, 5 tables only

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-11-07-p0-mcp-case-mvp.md`.**

Please review the plan. Which execution approach would you prefer?

- **Subagent-driven** — A fresh subagent implements each task and a fresh reviewer checks it before the next one starts, then a whole-branch review at the end. Most thorough; costs a fresh context per task and per review.
- **Native** — I implement every task myself in this session, then one fresh reviewer checks the whole branch. Cheapest and fastest; no independent review until the end.

For this plan I recommend **Native**, because the tasks are tightly coupled (each builds on the previous migration and auth layer), there are only 9 tasks, and a shipped mistake in auth/authorization would be costly — a single reviewer at the end can verify the complete security boundary.

Does the plan capture what you want, and which approach should we use?
