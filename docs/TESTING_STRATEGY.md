# Testing Strategy — MSSP Intelligence Workbench

## Unit Tests

- Database operations (CRUD, transactions, migrations)
- Tenant authorization (RBAC + client_id checks)
- Data validation (input schemas, field types)
- CTI parsing (PDF, HTML, JSON import)
- IOC normalization (deduplication, formatting)
- Sector mapping (client-to-sector relationships)
- Coverage calculations (COVERED/PARTIAL/NOT_COVERED/UNKNOWN)
- Hypothesis validation (structure, quality gate)
- Harness adapter contract (interface compliance)

## Integration Tests

- Backend + Database (SQLite WAL mode)
- Backend + HarnessRouter (adapter interface)
- Backend + MCP (tenant-scoped tool calls)
- CTI ingestion (import → normalize → extract)
- Inventory import (Excel/CSV → database)
- Multi-tenant access checks (cross-tenant isolation)

## Security Tests

- Cross-tenant access attempts (API + MCP)
- Unauthorized MCP tool calls
- Unauthorized API calls
- Secret leakage (source code, logs, audit)
- Prompt injection handling
- Untrusted document processing
- Unauthorized file access
- Outbound network restrictions (default deny)

## Acceptance Test Scenario

1. Import CTI report
2. Extract IOC, TTP, CVE
3. Create Adversary Brain
4. Assess sources (Admiralty)
5. Determine target sector
6. Find matching MSSP clients
7. Check QRadar Inventory
8. Check telemetry availability
9. Create Hunt Hypothesis
10. Generate AQL Draft
11. Conduct Analyst Review
12. Save investigation feedback

All results reproducible from saved source materials, workflow versions, and evidence references.

## Test Requirements

- No fabricated test results
- Every completed task includes relevant tests
- Tests traceable to specification sections
- QA engineer owns all test creation and execution
- Code reviewer verifies test quality (read-only)