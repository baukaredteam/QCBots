# Recommended First Implementation Tasks — MSSP Intelligence Workbench

These are the first tasks to start after approval, following the MVP phase order from IMPLEMENTATION_PLAN.md.

## Immediate (Before Phase 1)

1. **Resolve Octop authentication** — Obtain Octop admin token/credentials; explore full API (not just health endpoint). Owner: ai-integration-engineer.
2. **Get QRadar export** — Obtain real QRadar field and rule export (Excel/CSV/JSON) to replace placeholder config data. Owner: backend-engineer + security-engineer.
3. **Confirm network allowlist** — Get explicit approval for any required outbound connections (model downloads, container registries, external APIs). Owner: security-engineer.
4. **Confirm deployment machine** — Verify SQLite is acceptable for MVP, confirm `/storage` directory, verify Docker availability. Owner: primary-orchestrator.

## Phase 1 — Foundation

5. **Backend project setup** — Go module, main.go with health endpoint, structured logging, config loading. Owner: backend-engineer.
6. **SQLite database initialization** — Run migration 0001_initial.sql, verify WAL mode and foreign keys. Owner: backend-engineer.
7. **Authentication middleware** — Basic auth with RBAC, tenant isolation enforcement. Owner: security-engineer + backend-engineer.
8. **Audit logging** — Audit log table and middleware to record all significant actions. Owner: security-engineer.
9. **Frontend project setup** — React + TypeScript + Vite + Tailwind, basic shell with main menu routing. Owner: frontend-engineer.
10. **Configuration loader** — YAML config loading for clients, sectors, harness registry, model providers. Owner: backend-engineer.

## Phase 2 — Inventory

11. **Clients/sectors CRUD** — API endpoints and UI for managing MSSP clients and sectors. Owner: backend-engineer + frontend-engineer.
12. **QRadar fields/rules** — Import from real QRadar export, store in global tables. Owner: backend-engineer.
13. **Client telemetry status** — Table and UI for per-client log source status. Owner: backend-engineer.
14. **Excel/CSV import** — Import UI with column mapping, duplicate detection, error display, confirm/cancel. Owner: frontend-engineer + backend-engineer.

## Phase 3 — CTI

15. **Manual CTI import** — PDF/HTML/JSON file upload with checksum and provenance. Owner: cti-engineer + backend-engineer.
16. **CTI normalization** — Extract title, source, author, dates, threat actors, campaigns. Owner: cti-engineer.
17. **IOC/TTP/CVE extraction** — Indicator extraction with source references. Owner: cti-engineer.
18. **MITRE mapping** — Map extracted techniques to MITRE ATT&CK. Owner: cti-engineer.
19. **Admiralty assessment** — Source reliability (A-F) and credibility (1-6) with analyst confirmation. Owner: cti-engineer.

## Phase 4 — Multi-Harness

20. **Harness adapter interface** — Go interface (Name, HealthCheck, SubmitTask, GetExecution, StreamExecution, CancelExecution). Owner: ai-integration-engineer.
21. **Octop adapter** — Implement adapter for local Octop instance (requires auth resolved first). Owner: ai-integration-engineer.
22. **Agent registry** — Register harnesses, health check, view capabilities. Owner: ai-integration-engineer + frontend-engineer.
23. **Execution history** — Store and display AI execution records. Owner: backend-engineer.

## Task Order Recommendation

Start with tasks 1-4 (immediate), then Phase 1 tasks 5-10, then Phase 2 tasks 11-14. Each task must include:
- Implementation code
- Unit tests
- Integration tests
- Documentation
- Security validation
- Code reviewer sign-off (read-only review)