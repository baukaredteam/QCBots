# Deployment Guide — MSSP Intelligence Workbench

## Deployment Model

On-premise only. No mandatory cloud dependency. Default network policy: deny
outbound unless explicitly approved.

## Components

| Component | Technology | Deployment |
|-----------|-----------|------------|
| Backend | Go | Local binary or Docker container |
| Frontend | React + TypeScript + Vite | Built static files, served by backend or reverse proxy |
| Database (MVP) | SQLite | File in `/storage`, WAL mode |
| Database (Production) | PostgreSQL | Local or internal network server |
| Octop Harness | Docker | `ghcr.nju.edu.cn/tencentcloud/octop:latest`, port 8088 |
| HarnessRouter | Candidate | Not mandatory; deploy only if PoC passes |

## Configuration

Configuration files in `/config`:
- `clients.yaml` — MSSP client definitions
- `sectors.yaml` — Sector definitions
- `rules_inventory.yaml` — QRadar detection rules
- `custom_fields_qradar.yaml` — Custom QRadar fields
- `declared_matrix.yaml` — Declared coverage matrix
- `mitre_mapping.yaml` — MITRE ATT&CK mappings
- `harness_registry.yaml` — Registered harnesses
- `model_providers.yaml` — LLM provider configuration

No secrets in source code. Use environment variables or secret store.

## Database

MVP: SQLite with WAL mode and foreign keys enabled. Database file stored in
`/storage`. Backup and restore procedures required.

Production: PostgreSQL with optional pgvector for semantic search.

## File Storage

`/storage` is the persistent runtime directory for:
- CTI reports, PDF documents, HTML reports
- Imported JSON files
- Analyst attachments
- Generated reports
- Evidence files

All files have checksums, metadata, and database record references.

## Health Checks

- Backend health endpoint
- Database health
- Harness availability
- MCP availability
- Model provider availability

## Backup and Restore

- Database backup (SQLite file copy or PostgreSQL dump)
- Configuration backup (`/config` files)
- File artifact backup (`/storage` files)
- Restore procedures tested

## Docker Compose (when permitted by internal infrastructure)

```yaml
services:
  backend:
    build: ./backend
    ports: ["8080:8080"]
    volumes:
      - ./storage:/storage
      - ./config:/config
  octop:
    image: ghcr.nju.edu.cn/tencentcloud/octop:latest
    ports: ["8088:8088"]
    volumes:
      - octop-data:/data/.octop
volumes:
  octop-data:
```

## Restrictions

- No Kubernetes for MVP
- No cloud deployment
- No Git as mandatory deployment tool
- No external data transfer without approval
- No automatic QRadar changes