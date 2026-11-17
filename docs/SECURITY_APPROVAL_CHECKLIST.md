# Security Approval Checklist — MSSP Intelligence Workbench

**Review type:** Read-only security decision preparation  
**Status:** Pre-Phase 1 gate — security approvals pending  
**Restrictions honored:** No passwords, tokens, or hashes exposed; no credential changes; no code modifications; read-only only

---

## 1. Decisions Requiring Human Approval

The following security decisions must be explicitly approved before Phase 1 implementation can proceed. No implementation of these items should begin without approval.

---

### Decision 1: Octop Credential Rotation and Removal of Temporary Credentials

**Context:** During Octop integration PoC exploration, the Octop admin password was reset via the `octop user passwd` CLI command. A temporary setup password file exists at `~/.octop/octop-login.txt`. The current password state is unknown to this review (read-only constraint prevented verification after rotation).

**Required approval:** Rotate the Octop admin password to a strong, randomly generated value; remove or securely store the temporary setup password file; ensure no temporary credentials remain in any project file, log, or documentation.

**Why approval is required:** Active credential exposure on a running container with network port 8088 exposed. Credential management is a security boundary decision.

**Files affected:** None in project (credential is outside project tree at `~/.octop/`)

**Do not expose:** No password values, tokens, or hashes appear in this document or any project file.

---

### Decision 2: Authentication Mechanism

**Context:** The backend (`backend/main.go`) currently has no authentication middleware. The specification requires server-side authorization on every endpoint. AGENTS.md mandates authentication + RBAC + tenant isolation.

**Required approval:** Approve the authentication mechanism (e.g., JWT bearer tokens, session-based auth, or other), token format, TTL, refresh strategy, and storage location for token secrets.

**Options to consider:**
- JWT bearer tokens with short TTL and refresh tokens
- Session-based authentication with server-side session store
- API key-based authentication for service accounts

**Why approval is required:** Authentication is the foundation of all security controls; mechanism selection affects every endpoint and integration.

**Files affected:** `backend/main.go` (no auth code exists); `config/model_providers.yaml` (empty API key fields)

---

### Decision 3: RBAC Roles and Permissions

**Context:** AGENTS.md and SECURITY_REQUIREMENTS.md define five permission profiles:
- READ_ONLY — Read all data, no writes
- CTI_ANALYST — Read + create CTI reports, IOCs, hypotheses (draft)
- HYPOTHESIS_WRITER — CTI_ANALYST + submit hypotheses for review
- REPORT_GENERATOR — Read + generate reports
- ADMINISTRATOR — Full access including user/client management

**Required approval:** Approve the five permission profiles and their exact capabilities; approve any additional roles; approve the role-permission mapping matrix.

**Why approval is required:** RBAC defines what each user and harness can do; incorrect permissions create security gaps or operational blockers.

**Files affected:** `SECURITY_REQUIREMENTS.md` (documents profiles); `config/harness_registry.yaml` (references permission_profile); `migrations/0001_initial.sql` (defines users table with role field)

---

### Decision 4: Tenant Isolation Enforcement

**Context:** The database schema (`migrations/0001_initial.sql`) correctly models tenant ownership with `client_id` FK on all client-owned tables. However, the backend has no code to enforce tenant isolation — no middleware, no query scoping, no middleware to verify `client_id` against authenticated user's authorized clients.

**Required approval:** Approve the tenant isolation enforcement strategy (middleware approach, query scoping method, MCP tool tenant checks, RAG tenant scoping, AI context tenant scoping).

**Why approval is required:** Tenant isolation is a core security requirement; frontend-only filtering is explicitly prohibited; server-side enforcement is mandatory.

**Files affected:** `backend/main.go` (no tenant isolation code); `SECURITY_REQUIREMENTS.md` (documents requirement); `migrations/0001_initial.sql` (schema supports it)

---

### Decision 5: Secrets Storage

**Context:** AGENTS.md prohibits secrets in source code or logs. `config/model_providers.yaml` has empty `api_key_required: true` fields with no values. No environment variable loading, secret store integration, or encrypted config exists in the backend.

**Required approval:** Approve the secrets storage mechanism (environment variables, secret store, encrypted config file, or other); approve which settings must come from environment vs. config files; approve the secret rotation policy.

**Options to consider:**
- Environment variables with .env file (not committed)
- Operating system secret store (Windows Credential Manager, etc.)
- Encrypted configuration file with key management
- HashiCorp Vault or similar (if approved infrastructure)

**Why approval is required:** Secret storage location and method is a security architecture decision affecting all integrations (Octop, LLM providers, QRadar, ThreadLinqs MCP).

**Files affected:** `config/model_providers.yaml` (empty API fields); `config/harness_registry.yaml` (empty endpoint fields); `backend/main.go` (no secret loading code)

---

### Decision 6: Network Egress Policy

**Context:** AGENTS.md and SECURITY_REQUIREMENTS.md mandate "default deny outbound unless explicitly approved." No code implements network restrictions. The backend has no outbound proxy, allowlist, or connection control.

**Required approval:** Approve the network egress allowlist (which domains/IPs are permitted); approve the enforcement mechanism (firewall rules, proxy, application-level allowlist); approve the process for adding new outbound destinations.

**Known destinations requiring evaluation:**
- `ghcr.nju.edu.cn` (Octop container registry — may be blocked by default deny)
- External LLM API endpoints (not yet selected)
- ThreadLinqs MCP service (not yet approved)
- Model download endpoints (not yet selected)

**Why approval is required:** Default deny outbound is a company security policy; exceptions require explicit approval.

**Files affected:** `SECURITY_REQUIREMENTS.md` (documents policy); `DEPLOYMENT_GUIDE.md` (references Docker); no code implements enforcement

---

### Decision 7: Local Model and External LLM Policy

**Context:** Section 4.3 of the specification states the specific LLM provider is not chosen. `config/model_providers.yaml` shows three providers all with `status: not_configured`. External LLM API use requires security policy approval. Client data must not be sent to external LLM without permission.

**Required approval:** Approve whether local LLM, external LLM API, or both are permitted; approve which external providers (if any) are allowed; approve whether client data can be sent to external LLMs; approve the model provider adapter implementation approach.

**Why approval is required:** External LLM use involves data leaving the network boundary; this is a data exfiltration risk requiring explicit security approval.

**Files affected:** `config/model_providers.yaml` (all providers `not_configured`); `AI_WORKFLOW_SPEC.md` (references model provider adapter)

---

### Decision 8: Harness Permissions and Data Access Boundaries

**Context:** The specification states AI Harness has NO direct database access — all interaction via permitted API or MCP tools. `config/harness_registry.yaml` lists Octop with `permission_profile: "READ_ONLY"` and `allowed_tools: ["read_only"]`. MCP tools must verify identity, permissions, client_id, operation type, and data volume limits.

**Required approval:** Approve the harness permission model (READ_ONLY vs. limited write for drafts); approve the MCP tool allowlist; approve data volume limits per tool; approve which harnesses can access which clients; approve data access boundaries for each integration type (REST, ACP, MCP, CLI/SDK).

**Why approval is required:** Harness data access boundaries prevent unauthorized data exposure and ensure AI systems cannot exceed their authorized scope.

**Files affected:** `config/harness_registry.yaml` (defines permissions per harness); `MULTI_HARNESS_SPEC.md` (documents adapter interface); `SECURITY_REQUIREMENTS.md` (documents harness layer security)

---

## 2. Security Findings Summary

| Severity | Finding | Reference | Approval Required |
|----------|---------|-----------|-------------------|
| CRITICAL | No authentication or authorization in backend | `backend/main.go` lines 57-108 | Decision 2 |
| CRITICAL | Temporary Octop credential exposed | `~/.octop/octop-login.txt`; password reset during PoC | Decision 1 |
| HIGH | No secrets management implemented | `config/model_providers.yaml` empty API fields | Decision 5 |
| HIGH | No audit logging middleware | `backend/main.go` (no audit code) | Implementation only |
| HIGH | No tenant isolation enforcement in code | `backend/main.go` (no tenant scoping) | Decision 4 |
| MEDIUM | Network egress restrictions not technically enforced | No allowlist or proxy in code | Decision 6 |
| MEDIUM | No LLM provider selected | `config/model_providers.yaml` all `not_configured` | Decision 7 |
| MEDIUM | Octop PoC is localhost-only, not production-verified | `INTEGRATION_FEASIBILITY.md` | Decision 1 (credentials) + Decision 8 (permissions) |

---

## 3. Approval Workflow

The user must review and approve each of the 8 decisions above before:

1. Any credential rotation is performed (Decision 1)
2. Any authentication code is written (Decision 2)
3. Any RBAC implementation begins (Decision 3)
4. Any tenant isolation code is written (Decision 4)
5. Any secrets are stored or loaded (Decision 5)
6. Any outbound network exception is configured (Decision 6)
7. Any external LLM integration is attempted (Decision 7)
8. Any harness adapter with data access is implemented (Decision 8)

---

## 4. Files Not Modified During This Investigation

No application code, database schemas, migrations, credentials, container configurations, or security settings were modified. All findings are read-only observations.

---

**Next step:** Wait for user explicit approval on each of the 8 security decisions before any corrections or implementation begins.