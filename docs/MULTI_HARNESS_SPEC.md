# Multi-Harness Specification — MSSP Intelligence Workbench

## Objective

Support multiple AI Harness simultaneously with a unified management mechanism. Users can use different harnesses; the platform provides a single interface for task management.

Per TECHNICAL_SPECIFICATION.md Section 5: presence of a harness name in the spec does NOT confirm compatibility. Each integration must pass PoC.

## Harness Adapter Interface (Go)

```go
type HarnessAdapter interface {
    Name() string
    HealthCheck(ctx context.Context) error
    GetCapabilities(ctx context.Context) ([]Capability, error)
    SubmitTask(ctx context.Context, task HarnessTask) (Execution, error)
    GetExecution(ctx context.Context, executionID string) (Execution, error)
    StreamExecution(ctx context.Context, executionID string) (<-chan ExecutionEvent, error)
    CancelExecution(ctx context.Context, executionID string) error
}
```

This is the internal Workbench contract — NOT an assertion that all external harnesses provide the same methods. Each adapter converts the internal contract to the specific product's API.

## Integration Methods (in order of preference)

1. **HarnessRouter API** — unified layer candidate
2. **Native REST API** — product-specific REST endpoints
3. **A2A Protocol** — optional, additional mechanism (NOT mandatory)
4. **MCP Integration** — when harness acts as MCP client/server
5. **CLI/SDK Adapter** — for allowed local tools

## Supported Harnesses (candidate list, each requires PoC)

| Harness | Interface | Status | Notes |
|---------|-----------|--------|-------|
| Tencent Octop | Docker container, port 8088, REST + ACP (stdio) | Running locally | Health verified: `{"ok":true,"db":true}` |
| HarnessRouter | Candidate unified layer | NOT installed | Must pass PoC; not mandatory |
| OpenCode | Local agent | NOT verified | No confirmed A2A endpoint |
| Claude Code | Local agent | NOT verified | No confirmed A2A endpoint |
| Codex | Local agent | NOT verified | No confirmed A2A endpoint |
| DeepSeek Harness | External API | NOT verified | Network access may be restricted |
| Custom Harness | Adapter-based | Not implemented | Via adapter interface |

## HarnessRouter (Candidate Only)

HarnessRouter is a candidate for the unified harness management layer. Its tasks:
- Unified API
- Launch supported harnesses
- Session management
- Result retrieval
- Streaming
- Cancellation
- Error handling

Workbench interacts via its documented interface. HarnessRouter is NOT mandatory for business logic. If replaced, Workbench continues working.

## Agent Registry

Fields (per spec Section 5.7):

```text
agent_id, agent_name, harness_type, integration_type, endpoint,
version, status, capabilities, allowed_clients, allowed_tools,
permission_profile, trust_level, created_at, updated_at, last_seen_at
```

Functions: Register, Edit Configuration, Enable/Disable, Health Check, View Capabilities, View Execution History, View Permissions.

## Capability Registry

Each harness has permitted capabilities:

```text
CTI_ANALYSIS, IOC_EXTRACTION, IOC_PIVOTING, MITRE_MAPPING,
ADVERSARY_BRAIN_GENERATION, ACH_ANALYSIS, SECTOR_RELEVANCE,
HYPOTHESIS_GENERATION, DETECTION_COVERAGE, AQL_DRAFT_GENERATION,
REPORT_GENERATION
```

Task Router checks capabilities before sending a task.

## Task Routing Modes

- **AUTO** — Workbench selects suitable available harness
- **MANUAL** — analyst selects harness
- **USER_PREFERRED** — uses user's stored preference
- **WORKFLOW_DEFINED** — harness determined by process configuration

On error, fallback to alternative harness only with preserved context and security constraints. All attempts saved.

## Unified Task Contract (internal format)

Input:
```json
{
  "task_id": "task-001",
  "task_type": "CTI_ANALYSIS",
  "client_id": "client-001",
  "priority": "normal",
  "input": {},
  "expected_output": ["summary", "iocs", "ttps", "sources"],
  "human_review_required": true
}
```

Output:
```json
{
  "task_id": "task-001",
  "agent_id": "agent-001",
  "status": "completed",
  "result": {},
  "sources": [],
  "warnings": [],
  "errors": [],
  "execution_id": "execution-001"
}
```

## Execution Modes

- **Harness-managed**: Harness (e.g., Octop) coordinates subagents. Workbench receives status, results, telemetry.
- **Workbench-managed**: Workbench splits task into stages, routes between harnesses (next phase).

MVP: Harness-managed via one confirmed-compatible harness. Workbench-managed is a future phase.

## PoC Requirements

For each integration, document:
- Officially supported interface
- API or protocol
- Authentication requirements
- Required dependencies
- Network requirements
- Data transfer implications
- Version compatibility
- Limitations
- PoC test required

**Never** invent endpoints or claim compatibility without evidence.
**Never** modify external systems during checks.

## Octop Current Status

- Image: `ghcr.nju.edu.cn/tencentcloud/octop:latest` (v1.0.3b1-amd64)
- Container: `octop`, running on port 8088
- Health endpoint: `GET http://localhost:8088/api/health` → `{"ok":true,"started_at":...,"db":true,"users_loaded":1,"agents_running":1}`
- CLI: `~/.octop/venv/Scripts/octop.exe` with ACP (`octop acp`), agent lifecycle, provider management, plugin system
- Config: `~/.octop/config.json`, SQLite database (`octop.db`), bind host `localhost`, port 9000 (CLI), server port 8088 (Docker)
- Authentication required for API (`AUTH_FAILED` without token)
- License: MIT (per container labels)
- Source: https://github.com/TencentCloud/Octop