# Unresolved Questions — MSSP Intelligence Workbench

## Integration Questions

1. **Octop authentication**: What are the credentials/admin token for the local Octop instance? How does the auth flow work (login endpoint, token TTL, refresh)?
2. **Octop full API**: Beyond `/api/health`, what endpoints does Octop expose for task submission, execution, streaming, cancellation? Is there OpenAPI/Swagger docs?
3. **HarnessRouter availability**: Is HarnessRouter available internally? What is its documented API interface?
4. **OpenCode/Claude Code/Codex integration**: Do these products provide A2A endpoints? What is their officially supported integration method?
5. **DeepSeek Harness**: Is external network access to DeepSeek API permitted? What are the API endpoints and auth requirements?
6. **ThreadLinqs MCP**: Has the company security policy approved ThreadLinqs integration? What MCP transport (stdio/HTTP) and auth does ThreadLinqs support?
7. **Local LLM**: Which local model should be used? What hardware (GPU/CPU) is available for inference?

## Data Questions

8. **QRadar field names**: What are the real QRadar field names and IDs in the existing deployment? Config files currently contain placeholder data.
9. **QRadar rule export format**: Can QRadar rules be exported as Excel/CSV/JSON? What is the exact column structure?
10. **QRadar telemetry**: How is client telemetry status obtained? Is there a QRadar API for log source status?
11. **CTI report format**: What formats are incoming CTI reports in (PDF, HTML, JSON, STIX)? Sample files needed for parser development.

## Infrastructure Questions

12. **Database choice for MVP**: Confirm SQLite is acceptable for MVP, or is PostgreSQL required from the start?
13. **File storage location**: Confirm `/storage` is the appropriate persistent directory on the deployment machine.
14. **Network allowlist**: Which outbound domains/IPs are explicitly approved (if any)?
15. **Docker availability**: Can Docker containers run on the deployment machine? Is `ghcr.nju.edu.cn` registry accessible?

## Security Questions

16. **Secret storage**: Where should secrets (API keys, Octop token) be stored? Environment variables, secret store, or encrypted config?
17. **Session management**: What session/token format should the backend use for authentication?
18. **Audit log retention**: How long should audit logs be retained? Is there a retention policy?

## Scope Questions

19. **MVP phase boundary**: Which phases are strictly MVP vs. post-MVP? Confirm Phase 1-8 scope.
20. **Python modules**: Are Python analytical modules permitted alongside Go backend? If so, which modules?

## Process Questions

21. **Approval workflow**: Who approves implementation milestones? Is there a sign-off process between phases?
22. **Documentation review**: Who reviews supporting technical documents for accuracy?