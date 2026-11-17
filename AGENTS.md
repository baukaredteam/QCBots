# MSSP Intelligence Workbench — Agent Operating Instructions

## Project Purpose

MSSP Intelligence Workbench is an on-premise AI-powered Cyber Threat Intelligence (CTI), Threat Hunting, and Detection Intelligence platform. It transforms fragmented threat intelligence into structured, evidence-based, client-relevant threat hunting hypotheses for MSSP SOC analysts.

Core mission: given a new CTI report, answer — which clients are affected, what can we already detect, what are the detection gaps, and which hunt hypotheses should the SOC investigate.

## Architecture Principles

1. On-premise first — no mandatory cloud dependency.
2. Multi-Harness architecture — adapter-based, no single harness is mandatory.
3. Provider-independent LLM architecture — model provider selected via configuration.
4. Human-in-the-Loop — analyst approval required for all write/trust decisions.
5. Evidence-Based Intelligence — every claim carries provenance and source reference.
6. Multi-Tenant Data Isolation — client data is isolated server-side; frontend filtering is insufficient.
7. Centralized Knowledge Management — the database is the source of truth.
8. Auditable AI Execution — every AI execution is logged with inputs, outputs, and model metadata.
9. Modular and Replaceable Components — HarnessRouter is a candidate, not a requirement.
10. Read-only QRadar integration in MVP — no automatic rule deployment or incident response.

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend | Go 1.22+, REST API, OpenAPI |
| Frontend | React + TypeScript, Vite, Tailwind CSS |
| MVP Database | SQLite (WAL mode, foreign keys enabled) |
| Production Database | PostgreSQL (+ pgvector optional) |
| CTI Feed | ThreadLinqs MCP (subject to security policy approval) |
| Harness Integration | Adapter-based (Go interface) |
| Harness Router | HarnessRouter (candidate, must pass PoC) |
| Existing Harness | Tencent Octop (Docker, port 8088, running locally) |
| Other Harnesses | OpenCode, Claude Code, Codex, DeepSeek — subject to PoC |
| Internal API | REST / OpenAPI |
| Tool Integration | MCP (Workbench provides secured MCP server) |
| Source Control | No mandatory Git |

## Directory Structure

/                    — Project root
  AGENTS.md          — This file
  TECHNICAL_SPECIFICATION.md — Detailed requirements (source of truth)
  /docs              — Supporting technical documentation
  /config            — YAML configuration files
  /migrations        — Database migrations
  /backend           — Go backend source
  /frontend          — React + TypeScript frontend
  /tests             — Unit, integration, acceptance tests
  /storage           — Persistent runtime directory (file artifacts, DB)
  /.agents           — OpenCode agent configurations

## Coding Conventions

- Go: standard library first, minimal dependencies, structured logging (slog), context propagation everywhere.
- TypeScript: strict mode, explicit types, no any, functional components with hooks.
- Error handling: explicit errors in Go, typed API errors with codes in frontend.
- All client-scoped queries must include client_id and be authorized server-side.
- No secrets in source code or logs; secrets via environment variables or secret store.
- File artifacts carry checksums, metadata, and database record references.

## Database Conventions

- Every table: primary key, foreign keys where applicable, indexes, created_at, updated_at.
- Client-owned tables include tenant ownership (client_id); global tables do not duplicate per client.
- SQLite WAL mode, foreign keys ON, transactional writes.
- Migrations are versioned SQL files; no auto-migration at runtime.

## Security Requirements

- Server-side authorization on every endpoint (RBAC + tenant isolation).
- MCP tools check identity, permissions, client_id, operation type, and data volume.
- Audit logging for all significant actions; no secrets or tokens in audit logs.
- AI Harness has NO direct database access — API or MCP only.
- Default network policy: deny outbound unless explicitly approved.
- Human Approval required for: hypothesis approval, TP/FP verdicts, trusted knowledge changes, rule library changes, report publication, any write/response operation.
- Permission profiles: READ_ONLY, CTI_ANALYST, HYPOTHESIS_WRITER, REPORT_GENERATOR, ADMINISTRATOR.

## Tenant Isolation Requirements

- Every client-scoped operation checks: user_id, role, client_id, permissions.
- Tenant-scoped database queries, MCP tools, RAG retrieval, and AI context.
- Global QRadar Fields and Detection Rules are shared; client telemetry status is per-client.
- No cross-tenant data access via API, MCP, or RAG.

## Testing Requirements

- Unit tests: DB operations, tenant authorization, data validation, CTI parsing, IOC normalization, sector mapping, coverage calculations, hypothesis validation, harness adapter contract.
- Integration tests: backend+DB, backend+HarnessRouter, backend+MCP, CTI ingestion, inventory import, multi-tenant access checks.
- Security tests: cross-tenant access, unauthorized MCP/API calls, secret leakage, prompt injection, untrusted document processing, unauthorized file access, outbound network restrictions.
- Acceptance test: full end-to-end scenario (import CTI → extract IOC/TTP/CVE → Adversary Brain → sector relevance → client matching → QRadar check → hypothesis → AQL draft → analyst review → investigation feedback).
- No fabricated test results.

## Documentation Requirements

- Every implemented module has: code, config, migrations, API docs, unit tests, integration tests, UI functionality, error handling, security validation, usage documentation.
- OpenAPI specification for all API endpoints.
- Integrations not passing PoC are marked NOT VERIFIED — never simulated.

## Prohibited Operations

- No Git as a mandatory part of workflow or deployment.
- No cloud deployment or external data transfer without approval.
- No direct database access by AI harnesses.
- No automatic QRadar changes or automatic incident response.
- No unapproved modification of trusted knowledge.
- No secrets in source code or logs.
- No fake integrations or fabricated test results.
- No Kubernetes for MVP.

## Definition of Done

For each module: implemented code + configuration + database migrations + API documentation + unit tests + integration tests + UI functionality + error handling + security validation + usage documentation. Integration must pass PoC or be marked NOT VERIFIED.

## Rules for Using Subagents

- Primary (orchestration) agent owns architecture, task decomposition, planning, and consistency.
- Subagents do not launch other subagents unless explicitly authorized.
- Primary agent coordinates file ownership to prevent conflicting parallel modifications.
- Every subagent task must reference the specification section it implements.
- Code reviewer is read-only; cannot modify files.
- QA engineer owns all test creation and execution.