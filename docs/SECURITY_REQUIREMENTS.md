# Security Requirements — MSSP Intelligence Workbench

## Security Layers (per spec Section 19)

### Model Layer
- Safety instructions
- Structured output
- Prompt separation
- Explicit uncertainty
- No unsupported claims

### Harness Layer
- Sandbox
- Tool allowlist
- Restricted filesystem
- Restricted credentials
- Execution timeout
- Controlled network access

### Workbench Control Layer
- Authentication
- Authorization (RBAC)
- Tenant isolation
- MCP permissions
- Audit logging
- Human Approval
- Data classification
- Policy enforcement

## Permission Profiles

| Profile | Capabilities |
|---------|-------------|
| READ_ONLY | Read all data, no writes |
| CTI_ANALYST | Read + create CTI reports, IOCs, hypotheses (draft) |
| HYPOTHESIS_WRITER | CTI_ANALYST + submit hypotheses for review |
| REPORT_GENERATOR | Read + generate reports |
| ADMINISTRATOR | Full access including user/client management |

MVP: AI Harness gets READ_ONLY + limited draft creation via Workbench API.

## Human Approval Required For

- Hunt Hypothesis approval
- TP/FP verdict assertion
- Trusted Adversary Brain changes
- Global Detection Library changes
- Official analytical report publication
- Any future write/response operation

## Audit Logging

Fields: event_id, user_id, agent_id, harness_id, client_id, action,
resource, timestamp, result, source_ip, correlation_id

**Never** record secrets or tokens in audit logs.

## Tenant Isolation

Every client-scoped operation checks: user_id, role, client_id, permissions.
- Server-side authorization (never frontend-only)
- Tenant-scoped database queries
- Tenant-scoped MCP tools
- Tenant-scoped RAG retrieval
- Tenant-scoped AI context
- Audit logging for all actions

## Network Restrictions

- Default policy: deny outbound unless explicitly approved
- All external connections explicitly controllable and disableable
- ThreadLinqs MCP, external LLM API, model downloads, container registries,
  harness package managers, telemetry, IOC enrichment — all require approval
- Local deployment does not guarantee no data exfiltration

## Secrets Management

- No secrets in source code
- No secrets in logs
- No secrets in audit logs
- Secrets via environment variables or secret store

## AI Harness Database Access

**Prohibited**: AI Harness has NO direct database access.
All interaction via permitted API or MCP tools.

## QRadar Actions

- Read-only in MVP
- No automatic rule deployment
- No automatic incident response
- No automatic endpoint isolation
- No automatic firewall changes

## Security Tests Required

- Cross-tenant access attempts
- Unauthorized MCP tool calls
- Unauthorized API calls
- Secret leakage
- Prompt injection handling
- Untrusted document processing
- Unauthorized file access
- Outbound network restrictions