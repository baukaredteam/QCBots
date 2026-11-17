# Integration Feasibility Matrix — MSSP Intelligence Workbench

Per TECHNICAL_SPECIFICATION.md Section 6 (PHASE F/G): every integration must pass PoC.
No fabricated endpoints, no unverified compatibility claims, no external system modifications.

## Verified Integrations

### 1. Tencent Octop — VERIFIED (POC PASSED)

**Deployment**: Docker container `octop`, image `ghcr.nju.edu.cn/tencentcloud/octop:latest` (v1.0.3b1-amd64), port 8088

**Health**: `GET http://localhost:8088/api/health` → `{"ok":true,"db":true,"users_loaded":1,"agents_running":1}`

**Authentication**:
- Endpoint: `POST /api/auth/login`
- Body: `{"username": "<user>", "password": "<pass>", "captcha_token": null}`
- Response: Bearer JWT token (TTL 86400s), token_type, expires_in, user profile
- Tested successfully with user `bauka` (admin role)

**Agent**:
- `GET /api/agents` returns agent `main` (state: running, kind: expert)
- Backend: `local_shell` with virtual_mode
- Memory: enabled
- No skills, no MCP servers, no knowledge bases (clean slate for Workbench integration)

**ACP (Agent Communication Protocol)**:
- `GET /api/acp` returns runner configurations
- OpenCode runner: ENABLED, command `opencode`, args `["acp"]`, trusted
- Other runners (Claude Code, Codex, Kimi, Cursor, Pi): configured but disabled
- Octop can run as ACP agent via `octop acp` CLI (stdio transport)

**API Endpoints Discovered**:
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| /api/health | GET | No | Health check |
| /api/auth/login | POST | No | JWT login |
| /api/auth/me | GET | Bearer | Current user profile |
| /api/agents | GET | Bearer | List agents |
| /api/acp | GET | Bearer | ACP runner configurations |
| /api/providers | GET | Bearer | LLM providers |
| /api/admin/overview | GET | Bearer | Admin overview |

**Limitations**:
- Full API not documented via OpenAPI (enable_api_docs: false)
- Chinese character encoding in agent names (display issue only)
- No A2A endpoint confirmed
- Chat/WS task submission not tested in this PoC (requires WebSocket client)

**Integration Method**: Native REST API + ACP (stdio)
**Status**: VERIFIED — suitable for Workbench harness adapter

---

## Not Verified Integrations

| Integration | Interface | Status | Reason |
|-------------|-----------|--------|--------|
| HarnessRouter | REST API (candidate) | NOT INSTALLED | Not present in environment |
| OpenCode | Local CLI | NOT VERIFIED | Installed in this session but no A2A endpoint confirmed; Octop ACP runner wraps OpenCode instead |
| Claude Code | Local CLI | NOT INSTALLED | No installation found |
| Codex | Local CLI | NOT INSTALLED | No installation found |
| DeepSeek Harness | External API | NOT VERIFIED | External network not approved by default |
| ThreadLinqs MCP | MCP transport | NOT VERIFIED | Subject to company security policy; default deny outbound |
| Local LLM | Local inference | NOT CONFIGURED | No model selected or installed |

---

## PoC Test Results Summary

| Integration | Health Check | Auth | Task Submission | ACP | Status |
|-------------|-------------|------|-----------------|-----|--------|
| Tencent Octop | PASSED | PASSED (JWT) | Not tested (WS) | PASSED (stdout) | VERIFIED |
| HarnessRouter | Not installed | N/A | N/A | N/A | NOT VERIFIED |
| OpenCode | Installed | N/A | N/A | Via Octop runner | NOT VERIFIED standalone |
| Claude Code | Not installed | N/A | N/A | Configured, disabled | NOT VERIFIED |
| Codex | Not installed | N/A | N/A | Configured, disabled | NOT VERIFIED |
| DeepSeek | Not reachable | N/A | N/A | N/A | NOT VERIFIED |
| ThreadLinqs MCP | Not reachable | N/A | N/A | N/A | NOT VERIFIED |
| Local LLM | Not configured | N/A | N/A | N/A | NOT VERIFIED |

---

## Default Network Policy

Deny outbound connections unless explicitly approved. This affects:
- External LLM APIs (OpenAI, DeepSeek, zenmux.ai)
- ThreadLinqs MCP (outbound to external service)
- Model download endpoints
- Container registries (ghcr.nju.edu.cn may be blocked)
- Harness package managers
- Telemetry and update endpoints
- External IOC enrichment services