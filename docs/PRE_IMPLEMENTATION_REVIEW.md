# Pre-Implementation Architecture and Security Review — MSSP Intelligence Workbench

**Review type:** Read-only architecture and security review  
**Status:** Pre-Phase 1 gate review  
**Review scope:** All project files in `C:\Users\Бауыржан\Desktop\QC_Bots\`  
**Read-only:** No code, schema, credential, or configuration changes performed.

---

## 1. Executive Summary

The project has a well-structured set of planning artifacts (AGENTS.md, 15 supporting documents, agent configurations, config YAMLs, an initial database migration, and backend/frontend scaffolding). However, the project is **NOT READY FOR PHASE 1** because:

1. **The source-of-truth `TECHNICAL_SPECIFICATION.md` does not exist** in the project directory. Every document references it, but it is absent. All consistency claims against it are unverifiable.
2. **The backend is a scaffold only** — `main.go` contains a single health endpoint with no authentication, RBAC, tenant isolation, database layer, harness adapters, or API routes.
3. **The frontend is configuration only** — `package.json` lists dependencies but contains no React components, routes, or API client code.
4. **No tests exist** in `/tests/` — the directory is empty.
5. **Octop PoC is localhost-only** and does not constitute production readiness. Task submission via WebSocket was not tested.
6. **Temporary credentials remain** — an Octop admin password was reset during PoC exploration.

The documentation and planning layer is substantial (15 docs + AGENTS.md + 8 configs + 1 migration). The implementation layer is effectively absent. The project is ready for documentation review but not for implementation.

---

## 2. Verified Facts

| # | Fact | Evidence |
|---|------|----------|
| V1 | `TECHNICAL_SPECIFICATION.md` is absent from the project root | File glob found no match; directory listing confirms absence |
| V2 | `AGENTS.md` exists with 122 lines covering all required sections | Read file: lines 1-122 |
| V3 | 15 supporting documents exist in `/docs/` | Directory listing |
| V4 | 9 OpenCode agent configurations exist in `.agents/agents/` | Directory listing; all read |
| V5 | 8 YAML config files exist in `/config/` | Directory listing; all read |
| V6 | `migrations/0001_initial.sql` exists with 579 lines and full schema | Read file |
| V7 | `backend/go.mod` is minimal (module declaration + Go version only) | Read file: 3 lines |
| V8 | `backend/main.go` compiles successfully | `go build -o /dev/null .` exit 0 |
| V9 | `backend/main.go` implements only `/api/v1/health` | Read file: lines 57-108 |
| V10 | `frontend/package.json` lists dependencies but no source code exists | Read file; no `.tsx`, `.ts`, or component files in `/frontend/` |
| V11 | `/tests/` directory is empty | Directory listing |
| V12 | Octop container is running on `localhost:8088`, health verified | `docker ps`; `GET /api/health` → `{"ok":true,...}` |
| V13 | Octop JWT authentication verified working | `POST /api/auth/login` → 200 with JWT token |
| V14 | Octop agent listing verified working | `GET /api/agents` → 200 with agent `main` |
| V15 | Octop ACP runner configuration verified: OpenCode enabled | `GET /api/acp` → OpenCode runner enabled, trusted |
| V16 | Octop chat/WS task submission was NOT tested | Documented limitation in INTEGRATION_FEASIBILITY.md |
| V17 | Octop admin password was reset during PoC exploration | CLI `octop user passwd bauka --password "Workbench2026!"` succeeded |
| V18 | No `.git` directory exists in project root | Directory listing |

---

## 3. Architecture Issues

### A1: CRITICAL — Source-of-truth specification missing

**Reference:** All documents reference `TECHNICAL_SPECIFICATION.md`; file does not exist in project root.

**Why it matters:** Every agent config, document, and plan cites specific sections of `TECHNICAL_SPECIFICATION.md` (e.g., "Section 5.3", "Section 10.4", "Section 19", "Section 23"). Without the actual document, no one can verify that any document, config, or migration correctly implements the specification. This breaks traceability, which is a mandatory governance rule ("All implementation must be traceable to the specification").

**Recommended correction:** Obtain or recreate `TECHNICAL_SPECIFICATION.md` and place it at the project root. All downstream documents must then be re-checked against it.

**Human approval required:** Yes — this is the foundational requirements document; its content must be approved before any implementation.

---

### A2: HIGH — Backend is a scaffold, not an implementation

**Reference:** `backend/main.go` lines 57-108; `backend/go.mod` lines 1-3.

**Why it matters:** `main.go` implements only a single `/api/v1/health` endpoint. There is no:
- Authentication middleware
- RBAC authorization
- Tenant isolation enforcement
- Database connection layer (SQLite)
- Migration runner
- Harness adapter implementations
- API route registration beyond health
- Audit logging middleware
- Configuration loader

The `HarnessAdapter` interface and types are defined (lines 15-55) but never used. The server has no business logic.

**Recommended correction:** Treat `main.go` as a starting point, not a foundation. Phase 1 must build the full backend: auth, RBAC, tenant isolation, SQLite layer, migrations, API routes, audit logging, and the harness adapter interface implementation.

**Human approval required:** No (implementation decision), but the missing spec (A1) blocks validation.

---

### A3: HIGH — Frontend has no source code

**Reference:** `frontend/package.json` lines 1-31; no `.tsx`, `.ts`, or component files in `/frontend/`.

**Why it matters:** `package.json` declares React, TypeScript, Vite, Tailwind, React Router, Axios, but there are zero source files. No components, no routes, no API client, no state management.

**Recommended correction:** Phase 1 frontend work must create the full React application structure: Vite config, Tailwind config, main entry point, App component, routing, and API client.

**Human approval required:** No.

---

### A4: MEDIUM — No tests exist

**Reference:** `/tests/` directory is empty.

**Why it matters:** AGENTS.md and TESTING_STRATEGY.md require unit, integration, security, and acceptance tests for every module. No test files exist, so no verification of correctness is possible.

**Recommended correction:** Create test files alongside implementation in Phase 1 and beyond.

**Human approval required:** No.

---

### A5: MEDIUM — Database migration is unversioned relative to spec

**Reference:** `migrations/0001_initial.sql` line 1 ("Migration 0001: Initial schema").

**Why it matters:** The migration file exists and is comprehensive, but there is no migration tracking table (e.g., `schema_migrations`) and no migration runner in the backend. The `PRAGMA foreign_keys = ON` at line 5 is a session-level setting, not persistent — it must be re-applied on every connection.

**Recommended correction:** Add a `schema_migrations` tracking table and ensure the backend enables `foreign_keys=ON` and `journal_mode=WAL` on every database connection.

**Human approval required:** No.

---

### A6: MEDIUM — No OpenAPI spec file exists despite API documentation

**Reference:** `docs/API_SPECIFICATION.md` documents endpoints but no machine-readable `openapi.json` or `openapi.yaml` exists.

**Why it matters:** AGENTS.md requires "OpenAPI specification for all API endpoints." A markdown document is not machine-readable for code generation, client generation, or validation.

**Recommended correction:** Generate an OpenAPI 3.0 spec file (YAML or JSON) in `/docs/` or `/backend/` that matches the documented endpoints.

**Human approval required:** No.

---

### A7: LOW — Backend and Octop use different ports

**Reference:** `backend/main.go` line 81 (`:8080`); Octop runs on port 8088 (INTEGRATION_FEASIBILITY.md line 10).

**Why it matters:** Not a conflict (different ports), but CORS configuration will be needed for frontend-to-backend and backend-to-Octop communication. The backend `main.go` has no CORS middleware.

**Recommended correction:** Add CORS middleware to the backend HTTP server in Phase 1.

**Human approval required:** No.

---

### A8: INFORMATIONAL — `storage/` directory is empty

**Reference:** Directory listing shows `/storage` exists but contains no files.

**Why it matters:** `/storage` is intended for the SQLite database file and file artifacts. It must be created at runtime with appropriate permissions.

**Recommended correction:** Ensure backend creates `/storage` directory and SQLite file on startup if not present.

**Human approval required:** No.

---

## 4. Security Findings

### S1: CRITICAL — No authentication or authorization exists in the backend

**Reference:** `backend/main.go` lines 57-108 — no auth middleware, no RBAC, no tenant isolation.

**Why it matters:** The health endpoint is publicly accessible. AGENTS.md and SECURITY_REQUIREMENTS.md mandate server-side authorization on every endpoint, RBAC + tenant isolation, and no frontend-only filtering. The current backend enforces none of this.

**Recommended correction:** Implement authentication middleware (JWT or session-based), RBAC with the five permission profiles, and tenant-scoped query enforcement before any Phase 1 implementation is considered complete.

**Human approval required:** Yes — security architecture decisions require approval.

---

### S2: CRITICAL — Temporary Octop credential remains in the environment

**Reference:** Octop admin password was reset to `Workbench2026!` via `octop user passwd bauka --password "Workbench2026!"` during PoC exploration. The local `~/.octop/octop-login.txt` still contains `duETeBkMGwTz3kZ8` (the Docker container's setup password).

**Why it matters:** A known temporary password exists on a running container with network exposure on port 8088. This violates the "no secrets in source code or logs" rule and creates an active security exposure.

**Recommended correction:** Immediately rotate the Octop admin password to a strong, randomly generated value and store it only in the organization's secret management system. Do not record it in any project file. Restart the container if necessary to clear any cached credentials.

**Human approval required:** Yes — credential rotation on a running production-adjacent service requires approval.

---

### S3: HIGH — No secrets management strategy implemented

**Reference:** `backend/main.go` has no secret loading; `config/model_providers.yaml` has empty `api_endpoint` and `api_key_required: true` fields; `config/harness_registry.yaml` has empty endpoint fields.

**Why it matters:** AGENTS.md prohibits secrets in source code. No environment variable loading, secret store integration, or encrypted config exists. The YAML files contain placeholder empty strings that will need real values before any external integration works.

**Recommended correction:** Implement environment-variable-based secret loading (or a secret store) before Phase 1. Document which settings must come from environment vs. config files.

**Human approval required:** Yes — secret storage location and method require security approval.

---

### S4: HIGH — No audit logging middleware exists

**Reference:** `backend/main.go` lines 57-108 — no audit logging; `migrations/0001_initial.sql` defines `audit_log` table but no code writes to it.

**Why it matters:** SECURITY_REQUIREMENTS.md and AGENTS.md require audit logging for all significant actions with no secrets/tokens. The table exists but nothing populates it.

**Recommended correction:** Implement audit logging middleware in the backend that writes to the `audit_log` table for every authenticated request, excluding secrets and tokens.

**Human approval required:** No.

---

### S5: MEDIUM — Octop authentication not fully explored

**Reference:** INTEGRATION_FEASIBILITY.md lines 14-18 — JWT login works, but task submission, streaming, and cancellation endpoints were not tested.

**Why it matters:** The harness adapter for Octop cannot be implemented correctly without knowing the full API surface. The `octop acp` CLI provides stdio-based ACP, but the REST API task submission path is unverified.

**Recommended correction:** Complete Octop API exploration (task submission, execution, streaming, cancellation) before implementing the Octop harness adapter.

**Human approval required:** No (investigation), but results require approval before adapter implementation.

---

### S6: MEDIUM — Network egress restrictions not technically enforced

**Reference:** SECURITY_REQUIREMENTS.md lines 68-74 — default deny outbound policy documented but no code implements it.

**Why it matters:** The backend has no network allowlist, no outbound proxy, and no mechanism to block unauthorized external connections. The `default deny` policy is documentation only.

**Recommended correction:** Implement outbound network restrictions (allowlist) in Phase 1 or early Phase 2, before any external integration (ThreadLinqs MCP, LLM providers) is attempted.

**Human approval required:** Yes — network allowlist contents require security approval.

---

### S7: LOW — Octop container exposes local setup password file

**Reference:** `~/.octop/octop-login.txt` contains `duETeBkMGwTz3kZ8`.

**Why it matters:** This file was created by Octop's setup process and contains a password in plaintext on the local filesystem.

**Recommended correction:** Delete or rotate this file after credential rotation (S2).

**Human approval required:** Yes (tied to S2).

---

## 5. MSSP Domain-Model Findings

### M1: VERIFIED — QRadar fields are global and shared

**Reference:** `migrations/0001_initial.sql` lines 92-102 (`global_fields` table, no `client_id`); `docs/DATABASE_SCHEMA.md` lines 49-52.

**Status:** Correctly modeled. Global fields are not duplicated per client.

---

### M2: VERIFIED — QRadar detection rules are global and shared

**Reference:** `migrations/0001_initial.sql` lines 112-124 (`detection_rules` table, no `client_id`); `docs/DATABASE_SCHEMA.md` lines 57-63.

**Status:** Correctly modeled. Global rules are not duplicated per client.

---

### M3: VERIFIED — Client-specific telemetry tracked separately

**Reference:** `migrations/0001_initial.sql` lines 80-90 (`client_log_source_status` with `client_id` FK); `docs/DATABASE_SCHEMA.md` lines 44-47.

**Status:** Correctly modeled. Telemetry status is per-client, not global.

---

### M4: VERIFIED — Client-sector relevance represented explicitly

**Reference:** `migrations/0001_initial.sql` lines 56-61 (`client_sector_mapping` table); `docs/DATABASE_SCHEMA.md` lines 33-35.

**Status:** Correctly modeled. Many-to-many client-sector mapping exists.

---

### M5: VERIFIED — Evidence, CTI claims, hypotheses, and analyst verdicts are separate entities

**Reference:** `migrations/0001_initial.sql`:
- `cti_claims` (lines 168-179)
- `brain_evidence` (lines 314-321)
- `hypothesis_evidence` (lines 363-370)
- `investigation_evidence` (lines 395-401)
- `investigation_feedback` (lines 403-409)
- `hypothesis_reviews` (lines 372-379)

**Status:** Correctly modeled. Evidence and verdicts are separate from the claims/hypotheses they evaluate.

---

### M6: VERIFIED — FP/TP feedback is contextual, not global

**Reference:** `migrations/0001_initial.sql` lines 381-393 (`investigations` table with `final_verdict` CHECK constraint including `TRUE_POSITIVE`, `FALSE_POSITIVE`, etc.); `docs/DATABASE_SCHEMA.md` lines 169-173.

**Status:** Correctly modeled. Verdicts are tied to specific investigations, not to QRadar rules globally. SECURITY_REQUIREMENTS.md line 45 confirms "TP/FP verdict assertion" requires human approval.

---

### M7: VERIFIED — Tenant isolation applies to client-specific data

**Reference:** `migrations/0001_initial.sql` — all client-owned tables (`cti_reports`, `adversary_brains`, `hunt_hypotheses`, `investigations`, `ai_tasks`, `ai_executions`, etc.) include `client_id` FK. Global tables (`global_fields`, `detection_rules`, `mitre_mappings`, etc.) do not have `client_id`.

**Status:** Correctly modeled at schema level. However, the backend code does not enforce tenant isolation (see S1).

---

### M8: INFORMATIONAL — Admiralty assessment table exists but no enforcement

**Reference:** `migrations/0001_initial.sql` lines 239-249 (`admiralty_assessments`); `docs/ADVERSARY_BRAIN_SPEC.md` lines 69-78.

**Status:** Schema supports Admiralty ratings (A-F reliability, 1-6 credibility) per claim. No code enforces analyst confirmation of AI-proposed assessments.

---

## 6. Octop PoC Limitations

### O1: HIGH — PoC is localhost-only, not production-ready

**Reference:** INTEGRATION_FEASIBILITY.md lines 8-51; Octop running on `localhost:8088` via Docker.

**Why it matters:** Health check, JWT login, agent listing, and ACP configuration were verified on a local Docker container. This does not prove:
- Production network connectivity
- Authentication in a production Octop deployment
- Task submission via REST or WebSocket
- Streaming execution events
- Cancellation behavior
- Error handling and retry policies

**Recommended correction:** Treat Octop as "candidate harness, PoC in progress." Complete REST API task submission testing and production deployment review before marking Octop as verified for production use.

**Human approval required:** Yes — production Octop deployment requires infrastructure approval.

---

### O2: MEDIUM — Octop task submission not tested

**Reference:** INTEGRATION_FEASIBILITY.md line 47 — "Chat/WS task submission not tested in this PoC (requires WebSocket client)."

**Why it matters:** The harness adapter's `SubmitTask`, `GetExecution`, `StreamExecution`, and `CancelExecution` methods cannot be implemented correctly without knowing the exact Octop API for these operations.

**Recommended correction:** Explore Octop chat/task submission endpoints (likely WebSocket-based per source code review of `/app/src/octop/api/routers/chat/ws.py`) before implementing the Octop adapter.

**Human approval required:** No.

---

### O3: MEDIUM — Octop full API surface not documented

**Reference:** INTEGRATION_FEASIBILITY.md lines 32-41 — only 7 endpoints verified. Octop source code reveals many more (`/api/chat`, `/api/agents`, `/api/acp`, `/api/providers`, etc.) but their request/response schemas are unknown.

**Why it matters:** Without documented API schemas, the adapter implementation will be based on assumptions, violating the "do not invent endpoints" rule.

**Recommended correction:** Obtain Octop OpenAPI/Swagger documentation (currently `enable_api_docs: false`) or reverse-engineer the API from source code with careful documentation.

**Human approval required:** No.

---

### O4: LOW — Octop ACP runner wraps OpenCode

**Reference:** INTEGRATION_FEASIBILITY.md line 28 — Octop's `/api/acp` shows OpenCode runner enabled with command `opencode acp`.

**Why it matters:** Octop can delegate to OpenCode via ACP stdio. This means OpenCode integration is available *through* Octop, not as a standalone harness. This affects the multi-harness architecture — OpenCode may not need a separate adapter if accessed via Octop's ACP.

**Recommended correction:** Decide whether OpenCode should be a standalone harness adapter or accessed via Octop ACP. Document this decision.

**Human approval required:** Yes — architectural decision about harness integration approach.

---

## 7. Missing Implementation Requirements

| # | Missing Item | Required By | Reference |
|---|-------------|-------------|-----------|
| MI1 | `TECHNICAL_SPECIFICATION.md` at project root | All documents reference it | AGENTS.md line 43 |
| MI2 | Authentication middleware (JWT/session) | AGENTS.md security | AGENTS.md line 71 |
| MI3 | RBAC enforcement with 5 profiles | SECURITY_REQUIREMENTS.md lines 32-38 | SECURITY_REQUIREMENTS.md |
| MI4 | Tenant isolation enforcement (server-side) | AGENTS.md lines 79-84 | AGENTS.md |
| MI5 | SQLite database connection layer | AGENTS.md lines 62-67 | AGENTS.md |
| MI6 | Migration runner with tracking table | AGENTS.md line 67 | AGENTS.md |
| MI7 | API route registration (all endpoints in API_SPECIFICATION.md) | docs/API_SPECIFICATION.md | docs/API_SPECIFICATION.md |
| MI8 | Audit logging middleware | SECURITY_REQUIREMENTS.md lines 51-56 | SECURITY_REQUIREMENTS.md |
| MI9 | Configuration loader (YAML + env vars) | AGENTS.md line 59 | AGENTS.md |
| MI10 | CORS middleware | Architecture issue A7 | backend/main.go line 81 |
| MI11 | OpenAPI spec file (machine-readable) | AGENTS.md line 97 | AGENTS.md |
| MI12 | Frontend source code (React components, routes, API client) | UI_SPECIFICATION.md | docs/UI_SPECIFICATION.md |
| MI13 | Test files (unit, integration, security, acceptance) | TESTING_STRATEGY.md | docs/TESTING_STRATEGY.md |
| MI14 | Harness adapter implementations (Octop + at least one more) | MULTI_HARNESS_SPEC.md lines 10-21 | docs/MULTI_HARNESS_SPEC.md |
| MI15 | MCP server implementation | MULTI_HARNESS_SPEC.md Section 5.6 | docs/MULTI_HARNESS_SPEC.md |
| MI16 | Model provider adapters | AI_WORKFLOW_SPEC.md | docs/AI_WORKFLOW_SPEC.md |
| MI17 | Secrets management (env vars or secret store) | SECURITY_REQUIREMENTS.md lines 76-81 | SECURITY_REQUIREMENTS.md |

---

## 8. Contradictions Between Documents

| # | Contradiction | Documents Involved | Resolution Needed |
|---|-------------|-------------------|-------------------|
| C1 | `TECHNICAL_SPECIFICATION.md` is referenced by all documents but does not exist | AGENTS.md, all docs, all agent configs | Obtain/recreate the spec (A1) |
| C2 | `backend/main.go` serves on port 8080; Octop on 8088; no CORS configured | backend/main.go line 81; INTEGRATION_FEASIBILITY.md line 10 | Add CORS middleware (A7) |
| C3 | `migrations/0001_initial.sql` line 5 sets `PRAGMA foreign_keys = ON` (session-level) but no code ensures it on every connection | migrations/0001_initial.sql line 5; backend/main.go (no DB code) | Add persistent PRAGMA on every connection (A5) |
| C4 | `config/harness_registry.yaml` lists Octop `status: "running"` and `trust_level: "unverified"` but capabilities are claimed without PoC task submission testing | config/harness_registry.yaml lines 13-17; INTEGRATION_FEASIBILITY.md line 47 | Re-evaluate after full Octop API testing (O2) |
| C5 | `docs/API_SPECIFICATION.md` lists `/api/v1/admin/config` but no config loading code exists | docs/API_SPECIFICATION.md line 129; backend/main.go | Implement config loader (MI9) |

---

## 9. Critical Blockers

| # | Blocker | Severity | Why It Blocks Phase 1 |
|---|---------|----------|----------------------|
| B1 | `TECHNICAL_SPECIFICATION.md` missing | CRITICAL | Cannot verify any implementation against the source of truth |
| B2 | No authentication/authorization in backend | CRITICAL | Phase 1 includes Authentication and RBAC; nothing exists to build on |
| B3 | No database connection layer | CRITICAL | Phase 1 includes SQLite; no code connects to or manages the database |
| B4 | Temporary Octop credential exposed | CRITICAL | Active security exposure on running container |
| B5 | No secrets management | HIGH | External integrations cannot be configured without secret storage |
| B6 | No frontend source code | HIGH | Phase 1 includes frontend setup; zero source files exist |

---

## 10. Recommended Corrections

| # | Correction | Priority | Human Approval Required? |
|---|-----------|----------|--------------------------|
| RC1 | Obtain/recreate `TECHNICAL_SPECIFICATION.md` at project root | CRITICAL | Yes |
| RC2 | Rotate Octop admin password; remove `~/.octop/octop-login.txt` | CRITICAL | Yes |
| RC3 | Implement authentication middleware (JWT) in backend | CRITICAL | Yes (security architecture) |
| RC4 | Implement RBAC with 5 permission profiles | CRITICAL | Yes |
| RC5 | Implement tenant isolation enforcement (server-side) | CRITICAL | Yes |
| RC6 | Implement SQLite database connection layer with WAL + foreign keys | HIGH | No |
| RC7 | Implement migration runner with `schema_migrations` tracking table | HIGH | No |
| RC8 | Implement audit logging middleware | HIGH | No |
| RC9 | Implement secrets management (environment variables or secret store) | HIGH | Yes |
| RC10 | Implement CORS middleware | MEDIUM | No |
| RC11 | Generate machine-readable OpenAPI spec file | MEDIUM | No |
| RC12 | Complete Octop API exploration (task submission, streaming, cancellation) | MEDIUM | No |
| RC13 | Create frontend source code structure | HIGH | No |
| RC14 | Create test files (unit, integration, security) | HIGH | No |

---

## 11. Phase 1 Readiness Decision

**VERDICT: NOT READY FOR PHASE 1**

### Justification

Phase 1 (per IMPLEMENTATION_PLAN.md lines 5-14) requires: project structure, frontend, backend, SQLite database, authentication, RBAC, tenant model, audit logging, and configuration management.

**What exists:**
- Project structure (directories created) ✅
- Database migration schema (SQL file) ✅
- Documentation and planning artifacts ✅
- Agent configurations ✅
- Config YAML files ✅

**What does NOT exist:**
- Authentication (CRITICAL gap)
- RBAC (CRITICAL gap)
- Tenant isolation enforcement (CRITICAL gap)
- Database connection layer (CRITICAL gap)
- Audit logging middleware (CRITICAL gap)
- Frontend source code (CRITICAL gap)
- API routes beyond health (CRITICAL gap)
- Tests (HIGH gap)
- Source-of-truth specification (CRITICAL gap — cannot validate anything)

**Blocking findings:** B1, B2, B3, B4, B5, B6 (6 critical blockers). The `TECHNICAL_SPECIFICATION.md` absence (B1) is the foundational blocker — without it, no implementation can be verified against requirements.

### Conditions for Readiness

The project would be **READY WITH CONDITIONS** for Phase 1 if the following are completed first:

1. `TECHNICAL_SPECIFICATION.md` is obtained and placed at project root (RC1)
2. Octop temporary credential is rotated and removed (RC2)
3. A security architecture review approves the auth/RBAC/tenant isolation design (RC3-RC5, RC9)

After these conditions are met, Phase 1 implementation can begin with the remaining corrections (RC6-RC14) addressed during implementation.

---

**Review completed:** All project files read and analyzed.  
**Read-only:** No modifications made to code, schema, credentials, or configuration.  
**Next step:** Wait for user approval before making any corrections or beginning Phase 1 implementation.