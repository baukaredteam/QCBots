# Implementation Plan — MSSP Intelligence Workbench

## MVP Phases (per TECHNICAL_SPECIFICATION.md Section 23)

### Phase 1 — Foundation
- Project structure
- Frontend (React + TypeScript + Vite)
- Backend (Go REST API)
- SQLite database (WAL mode, foreign keys)
- Authentication
- RBAC
- Tenant model
- Audit logging
- Configuration management

### Phase 2 — Inventory
- Clients
- Sectors
- Global QRadar Fields
- Global QRadar Rules
- Log Source Types
- Client Telemetry Status
- Excel/CSV Import

### Phase 3 — CTI
- ThreadLinqs MCP integration (subject to company security policy)
- Manual PDF/HTML/JSON import
- CTI normalization
- IOC extraction
- TTP extraction
- MITRE mapping
- Provenance
- Admiralty assessment

### Phase 4 — Multi-Harness Foundation
- Harness Adapter Interface
- Agent Registry
- Capability Registry
- HarnessRouter adapter (candidate)
- Execution History
- Task Routing
- Health Checks
- MVP: at least one harness confirmed working
- Second harness: PoC for interchangeability

### Phase 5 — Adversary Brain
- Brain creation
- TTP relationships
- IOC relationships
- Evidence references
- Versioning
- Basic ACH
- Analyst review

### Phase 6 — Sector Relevance
- Sector mapping
- Client mapping
- Technology relevance
- Threat relevance assessment
- Explanation and evidence

### Phase 7 — Hunt Hypotheses
- Hypothesis generation
- Required telemetry
- QRadar fields
- Detection rules
- Coverage status
- Quality Gate
- Analyst review
- AQL draft generation

### Phase 8 — Reporting
- Dashboard
- CTI Report
- Sector Relevance Report
- Adversary Brain Report
- Hunt Hypothesis Report
- Detection Coverage Report

## Definition of Done (per module)

- Implemented code
- Configuration
- Database migrations
- API documentation
- Unit tests
- Integration tests
- UI functionality
- Error handling
- Security validation
- Usage documentation

Integrations not passing PoC: marked NOT VERIFIED, never simulated.

## Execution Rules

- Do not implement entire system in one large change
- Work sequentially through phases
- Study existing source and environment before starting
- Do not overwrite configurations without analysis
- Do not invent third-party APIs
- Use official documentation and real API schemas
- Separate confirmed capabilities from unverified integrations
- No unnecessary dependencies
- No cloud services without approval
- No internal data sent externally
- No real QRadar operations
- No fake data in production database
- Create unit and integration tests
- Document every implemented module
- Maintain compatibility with current components
- No global setting changes without agreement
- Functionality not complete just because UI displays