# Project Architecture — MSSP Intelligence Workbench

## Logical Architecture

The platform consists of the following logical components (per TECHNICAL_SPECIFICATION.md Section 3.1):

1. Frontend Application — React + TypeScript UI
2. Backend API — Go REST API (central control component)
3. Authentication and Authorization — RBAC + tenant isolation
4. MSSP Tenant Management — clients, sectors, client-specific telemetry
5. CTI Ingestion Engine — PDF/HTML/JSON/STIX import, ThreadLinqs MCP
6. CTI Processing Engine — IOC/TTP/CVE extraction, normalization
7. Adversary Brain Engine — threat actor behavior modeling
8. Sector Relevance Engine — client-sector-threat relevance assessment
9. Hunt Hypothesis Engine — testable hypothesis generation
10. Detection Coverage Engine — QRadar rule mapping and gap analysis
11. Knowledge Management — centralized CTI knowledge base
12. AI Orchestration Layer — task creation, harness selection, execution control
13. Harness Integration Layer — adapter-based multi-harness support
14. MCP Integration Layer — secured Workbench MCP server
15. Model Provider Adapter — configurable LLM provider
16. Audit and Monitoring — execution logging, health checks
17. Reporting Engine — PDF/JSON/CSV/Markdown report generation

## Component Interaction

```
Frontend <-> Backend API <-> Database (SQLite MVP / PostgreSQL prod)
                                      |
                +---------------------+---------------------+
                |                     |                     |
         AI Orchestration       Harness Adapters       MCP Server
                |                     |                     |
         Execution History   Octop, HarnessRouter,   Secured Tools
         (read-only for      OpenCode, Claude Code,   (tenant-scoped)
          harnesses)         Codex, DeepSeek
```

## Key Design Decisions

| Area | Decision | Rationale |
|------|----------|-----------|
| Backend | Go (single binary, modular) | Spec Section 3.2; no microservices without need |
| MVP Database | SQLite WAL mode | Simple, file-based, persistent, no external DB dependency |
| Production DB | PostgreSQL (+ pgvector optional) | Scalability for production |
| Harness Integration | Adapter-based (Go interface) | Spec Section 5.3; each harness converts to internal contract |
| Harness Router | Candidate only (not mandatory) | Spec Section 5.2; replaceable without breaking Workbench |
| Model Provider | Configurable adapter | Spec Section 4.3; no hardcoded binding to one model |
| QRadar Access | Read-only in MVP | Spec Section 2.1, 24; no automatic changes |
| Source Control | No mandatory Git | Spec Section 2.1; local artifact versioning instead |
| Network | Default deny outbound | Spec Section 2.2; explicit approval for outbound |
| Vector DB | Not mandatory for MVP | Spec Section 3.2; full-text search sufficient initially |
| A2A Protocol | Optional | Spec Section 5.5; not required for every harness |

## Data Flow (Core Scenario)

1. CTI report imported (manual or ThreadLinqs MCP)
2. CTI normalized — IOC, TTP, CVE, threat actors extracted with provenance
3. Adversary Brain built — relationships, evidence, versioning
4. Admiralty assessment — source reliability + information credibility
5. Sector relevance — matched to MSSP clients with explanation
6. Detection coverage — QRadar rules checked, gaps identified
7. Hunt Hypothesis generated — required telemetry, fields, rules, AQL draft
8. Quality Gate — evidence, sources, client isolation verified
9. Analyst review — approve/reject/need more data
10. Investigation feedback — TP/FP/inconclusive recorded

## Integration Points

- **ThreadLinqs MCP**: CTI feed source (subject to security policy)
- **HarnessRouter**: Unified harness management (candidate, PoC required)
- **Tencent Octop**: Running locally on port 8088 (Docker, health verified)
- **OpenCode / Claude Code / Codex / DeepSeek**: Subject to individual PoC
- **MCP Server**: Workbench-provided, tenant-scoped tools only
- **QRadar**: Read-only inventory import (Excel/CSV/JSON), no live connection

## Unverified Assumptions

- ThreadLinqs MCP transport and authentication mechanism not yet verified
- HarnessRouter API interface not yet confirmed
- OpenCode/Claude Code/Codex/DeepSeek harness integration methods not yet verified
- Local LLM model provider not yet selected
- QRadar field/rule inventory format not yet confirmed