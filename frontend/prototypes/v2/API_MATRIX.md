# UI / API Readiness Matrix — verified against `backend/main.go` routes (56 handlers)

> No backend changed for v2.1. Matrix reflects actual `mux.HandleFunc` registrations observed in `backend/main.go` (2026-11-08).

| UI feature | Backend endpoint/service | Available? | Permission | Real data? | Class |
|---|---|---|---|---|---|
| Auth login/logout/me | `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`, `GET /api/v1/auth/me` | yes | — | yes | EXISTING |
| Cases list + search/status/priority/client + pagination | `GET /api/v1/cases` | yes | ViewCTI + grants | yes | EXISTING |
| Create case (stable idempotency) | `POST /api/v1/cases` | yes | CreateCTI + grant | yes | EXISTING |
| Case detail / status / participants | `GET/PUT /api/v1/cases/{id}[/status]`, `GET/POST/DELETE …/participants` | yes | CreateCTI (edit), ViewCTI (view), owner (participants) | yes | EXISTING |
| Artifacts list + human review | `GET /api/v1/cases/{id}` (ctx artifacts) + `PUT …/artifacts/{aid}/review` | yes | ReviewArtifact + grant + classification | yes | EXISTING |
| Notes create/list + revisions | `POST/GET /api/v1/cases/{id}/notes` | yes | Note-create/view + grant | yes | EXISTING |
| Activity timeline (grant-predicate) | `GET /api/v1/cases/{id}/activity` | yes | ViewCTI + grant predicate | yes | EXISTING |
| Hypothesis link/list/unlink + per-client review | `POST/DELETE/GET …/hypotheses/{id}`, `POST …/review` | yes | Link/ReviewHypothesis + grant | yes | EXISTING |
| Hypotheses selection list | `GET /api/v1/hypotheses` (Stage G Stabilization) | yes | ViewCTI + grant | yes | EXISTING |
| Investigations create/list | `POST/GET /api/v1/cases/{id}/investigations` | yes | CreateCTI/ViewCTI + grant | yes | EXISTING |
| CTI reports list/import/analyze/iocs/ttps/cves/evidence | `GET /api/v1/tenants/{id}/cti/reports`, `POST /cti/import`, `GET/POST /cti/reports/{id}[/analyze|/iocs|/ttps|/cves|/evidence]` | yes | ViewCTI (+CreateCTI) | yes (seed CTI) | EXISTING |
| QRadar rules/groups/fields/telemetry | `GET /api/v1/inventory/{rules,fields}`, `GET /api/v1/qradar/{rules,building-blocks,fields}`, `POST /qradar/import`, `GET /inventory/telemetry` | yes | ViewCTI / admin-import | yes | EXISTING |
| Evidence Graph | Evidence DB ops (M5.1) via backend tables, no standalone UI endpoint | partial | ViewCTI | yes | BACKEND-GAP (UI) |
| Global search | none | no | — | no | BACKEND-GAP |
| CTI Feed / Report Explorer with IOC/TTP/CVE entities | partial (per-report endpoints exist, no feed) | partial | ViewCTI | partial | FRONTEND-ONLY / BACKEND-GAP |
| Threat entities browser, review queue global, findings store, user admin | none | no | — | no | BACKEND-GAP / PLANNED |
| SIEM execution / hunt outcome automation | none (verdict is human-set field) | no | — | no | PLANNED |

Corrections vs v2.0 matrix in `docs/FRONTEND_V2_ARCHITECTURE.md`:
- CTI endpoints were under-declared: `tenants/*/cti/reports`, `cti/import`, `cti/reports/*/{analyze,iocs,ttps,cves,evidence}` are EXISTING.
- `GET /api/v1/hypotheses` exists (added Stage G Stabilization) — hypotheses selection is EXISTING, not PLANNED.
- Evidence Graph has DB/API support in backend but no dedicated UI page → BACKEND-GAP (UI only).
- No endpoint was invented for v2.1; prototype is standalone and marks every panel REAL vs SYNTHETIC vs PLANNED.

# Explicitly Design-Only (no production API call, synthetic only)

- Intelligence Hub feed/report cards beyond per-report endpoints (no feed endpoint).
- Hypothesis Lab / Hunt Workspace (no hunt execution, no SIEM).
- AQL drafting/deployment, Field Intelligence Lab, Findings store, User admin, Global search.

