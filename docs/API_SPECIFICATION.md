# API Specification — MSSP Intelligence Workbench

All APIs documented via OpenAPI. Base path: `/api/v1`. All endpoints enforce authentication, RBAC, and tenant isolation. Error responses use a unified error schema with `code`, `message`, and `details`.

## Common Headers

- `Authorization: Bearer <token>`
- `X-Client-ID: <client_id>` (for client-scoped operations)
- `Content-Type: application/json`

## Unified Error Schema

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable message",
    "details": {}
  }
}
```

Common codes: `AUTH_FAILED`, `UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`, `VALIDATION_ERROR`, `TENANT_ISOLATION_VIOLATION`, `HARNESS_ERROR`, `MCP_ERROR`, `INTERNAL_ERROR`

---

## Clients

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/clients` | List clients (tenant-scoped) |
| POST | `/api/v1/clients` | Create client (ADMIN only) |
| GET | `/api/v1/clients/{id}` | Get client details |
| PUT | `/api/v1/clients/{id}` | Update client (ADMIN only) |

## Sectors

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/sectors` | List sectors |
| POST | `/api/v1/sectors` | Create sector (ADMIN only) |
| GET | `/api/v1/sectors/{id}` | Get sector details |

## CTI

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/cti/reports` | List CTI reports (tenant-scoped) |
| POST | `/api/v1/cti/import` | Import CTI report (PDF/HTML/JSON) |
| GET | `/api/v1/cti/reports/{id}` | Get report details |
| POST | `/api/v1/cti/reports/{id}/analyze` | Start CTI analysis |
| GET | `/api/v1/cti/reports/{id}/iocs` | Get extracted IOCs |
| GET | `/api/v1/cti/reports/{id}/ttps` | Get extracted TTPs |
| GET | `/api/v1/cti/reports/{id}/evidence` | Get evidence and provenance |

## Adversary Brains

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/adversary-brains` | List brains (tenant-scoped) |
| POST | `/api/v1/adversary-brains` | Create brain |
| GET | `/api/v1/adversary-brains/{id}` | Get brain details |
| GET | `/api/v1/adversary-brains/{id}/versions` | List versions |
| GET | `/api/v1/adversary-brains/{id}/relationships` | Get relationships |
| POST | `/api/v1/adversary-brains/{id}/review` | Analyst review |

## Hunt Hypotheses

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/hypotheses` | List hypotheses (tenant-scoped) |
| POST | `/api/v1/hypotheses` | Create hypothesis |
| GET | `/api/v1/hypotheses/{id}` | Get hypothesis details |
| POST | `/api/v1/hypotheses/{id}/review` | Review (approve/reject/need more data) |
| POST | `/api/v1/hypotheses/{id}/investigate` | Start investigation |
| GET | `/api/v1/hypotheses/{id}/aql` | Get AQL draft |
| POST | `/api/v1/hypotheses/{id}/aql` | Generate AQL draft |

## Detection Coverage

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/detection/coverage` | List coverage matrix |
| POST | `/api/v1/detection/coverage/analyze` | Run coverage analysis |
| GET | `/api/v1/detection/coverage/gaps` | List detection gaps |

## QRadar Inventory

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/inventory/fields` | List global fields |
| GET | `/api/v1/inventory/rules` | List detection rules |
| POST | `/api/v1/inventory/import` | Import Excel/CSV/JSON inventory |
| GET | `/api/v1/inventory/import/{id}` | Get import job status |
| GET | `/api/v1/inventory/mappings` | List rule-field mappings |
| GET | `/api/v1/inventory/mitre` | List MITRE mappings |
| GET | `/api/v1/inventory/telemetry` | List client telemetry status |

## Harness

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/harness` | List registered harnesses |
| POST | `/api/v1/harness` | Register harness |
| GET | `/api/v1/harness/{id}` | Get harness details |
| POST | `/api/v1/harness/{id}/health` | Health check |
| POST | `/api/v1/harness/{id}/execute` | Submit task |
| GET | `/api/v1/executions/{id}` | Get execution status |
| POST | `/api/v1/executions/{id}/cancel` | Cancel execution |
| GET | `/api/v1/executions` | List execution history |

## Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/reports` | List reports |
| POST | `/api/v1/reports/generate` | Generate report |
| GET | `/api/v1/reports/{id}` | Get report |
| GET | `/api/v1/reports/{id}/download` | Download (PDF/JSON/CSV/MD) |

## Administration

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/admin/audit` | Query audit log |
| GET | `/api/v1/admin/users` | List users |
| POST | `/api/v1/admin/users` | Create user |
| GET | `/api/v1/admin/health` | System health check |
| GET | `/api/v1/admin/config` | Get system configuration |

## MCP Server Tools (secured, tenant-scoped)

- `get_client_profile` — client profile with tenant check
- `get_client_sector` — client sector mapping
- `get_client_technologies` — client technologies
- `get_available_log_sources` — client log source status
- `get_global_qradar_fields` — global QRadar fields
- `get_detection_rules` — global detection rules
- `get_detection_rule_details` — rule details
- `search_cti_reports` — search CTI reports (tenant-scoped)
- `get_adversary_brain` — get brain (tenant-scoped)
- `search_iocs` — search IOCs (tenant-scoped)
- `get_mitre_technique` — MITRE technique details
- `create_hunt_hypothesis_draft` — create hypothesis draft
- `get_hypothesis_evidence` — hypothesis evidence
- `get_detection_coverage` — coverage matrix

All MCP tools verify: caller identity, permissions, client_id, operation type, data volume limits, and create audit records.
## M7-F Manual Inventory (offline-first)

| Method | Endpoint | Purpose | Permission |
|---|---|---|---|
| GET | `/api/v1/qradar/inventory/completeness?client_id=` | Manual-evidence completeness per client-bound domain | `CanViewCTI` + client grant |
| GET | `/api/v1/qradar/inventory/import-templates/{kind}` | CSV template for `log_source_types`, `log_sources`, `qids`, `field_definitions`, `field_mappings` | `CanViewCTI` |
| POST | `/api/v1/qradar/inventory/import/preview` | Dry-run parse, validation and diff (no writes) | `CanViewCTI` + `CanImportFieldIntel` + CSRF |
| POST | `/api/v1/qradar/inventory/import/commit` | Atomic import; requires `confirm: true`; refuses conflicts | same |

Import body: `{client_id, domain_id, kind, format: "csv"|"json", content, declared_source, dry_run, confirm}`.
Bounds: 512 KiB, 2000 rows. Imported values are `IMPORTED_UNVERIFIED` and never
change bindings or approval state. 409 returns the preview with conflicts.
