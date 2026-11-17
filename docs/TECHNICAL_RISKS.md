# Technical Risks — MSSP Intelligence Workbench

## Identified Technical Risks

### R1: Octop Authentication Barrier (HIGH)
Octop API requires authentication (AUTH_FAILED without bearer token). The health endpoint is accessible, but full API exploration requires credentials. No API documentation found beyond the health check.
- **Mitigation**: Obtain Octop credentials/admin token; explore CLI `octop admin` and `octop user` commands; document auth flow
- **Impact**: Cannot verify Octop task submission/execution without auth

### R2: HarnessRouter Not Installed (HIGH)
HarnessRouter is a candidate unified layer but is not installed locally. Its API interface is not confirmed.
- **Mitigation**: Build Workbench with adapter interface that does not depend on HarnessRouter; treat HarnessRouter as optional
- **Impact**: Cannot test unified harness management until HarnessRouter is available

### R3: No Confirmed A2A Endpoints (MEDIUM)
OpenCode, Claude Code, Codex do not have confirmed A2A protocol endpoints. A2A is optional per spec but not verified for any harness.
- **Mitigation**: Use native REST/CLI adapters instead of A2A; mark A2A as NOT VERIFIED
- **Impact**: A2A-based inter-agent communication not available for MVP

### R4: ThreadLinqs MCP Subject to Security Policy (HIGH)
ThreadLinqs integration requires company security policy approval. Default policy denies outbound connections. Cannot send raw client logs to external MCP.
- **Mitigation**: Use manual CTI import as primary source; defer ThreadLyncs until policy approval
- **Impact**: Automated CTI feed not available in MVP

### R5: No LLM Provider Selected (HIGH)
Specific LLM provider not chosen. Local LLM vs external API not decided. Model provider adapter must be configurable.
- **Mitigation**: Implement adapter pattern; configure provider via YAML; support local LLM and OpenAI-compatible
- **Impact**: AI workflows cannot run until model provider is configured

### R6: QRadar Inventory Format Unconfirmed (MEDIUM)
QRadar field names, rule formats, and import format (Excel/CSV/JSON) not confirmed with QRadar admin. Config files contain placeholder data.
- **Mitigation**: Obtain real QRadar export; validate field names against actual deployment
- **Impact**: Detection coverage analysis cannot use real QRadar data

### R7: No Git Mandatory (MEDIUM)
Company prohibits mandatory Git. Local artifact versioning and config versioning must be implemented without Git.
- **Mitigation**: Implement checksum-based artifact versioning, configuration journal, export/import YAML/JSON
- **Impact**: No standard source control; custom versioning needed

### R8: Network Restrictions (MEDIUM)
Default deny outbound may block model downloads, container registries, external APIs.
- **Mitigation**: Pre-download required containers; use local models; explicit allowlist for approved outbound
- **Impact**: Some integrations may not work without network exceptions

### R9: SQLite vs PostgreSQL Migration (LOW)
MVP uses SQLite; production uses PostgreSQL. Schema migration path needed.
- **Mitigation**: Keep SQL portable; use standard SQL; test PostgreSQL compatibility
- **Impact**: Future production migration effort

### R10: Human-in-the-Loop Complexity (MEDIUM)
All write/trust decisions require analyst approval. This adds complexity to AI workflows.
- **Mitigation**: Build approval workflow from the start; queue-based review system
- **Impact**: Slower automated processing; more UI work

## Risk Mitigation Summary

| Risk | Severity | Likelihood | Mitigation | Owner |
|------|----------|------------|------------|-------|
| R1 Octop Auth | HIGH | High | Get credentials, explore CLI | AI Integration |
| R2 HarnessRouter missing | HIGH | High | Optional adapter, not mandatory | Architecture |
| R3 No A2A endpoints | MEDIUM | High | Use REST/CLI adapters | AI Integration |
| R4 ThreadLinqs policy | HIGH | Medium | Manual import first | Security |
| R5 No LLM provider | HIGH | High | Adapter pattern, configurable | AI Integration |
| R6 QRadar format | MEDIUM | Medium | Get real export | Backend |
| R7 No Git | MEDIUM | High | Checksum versioning | Backend |
| R8 Network restrictions | MEDIUM | High | Local models, allowlist | Security |
| R9 SQLite→PostgreSQL | LOW | Medium | Portable SQL | Backend |
| R10 Human-in-loop | MEDIUM | High | Approval workflow from start | Frontend/Backend |