# Frontend Design v3.0 — UI → API Matrix & Migration Plan

> READ-ONLY mapping. No backend changes. Verified against `backend/main.go` (56 handlers) + M6 services (`mcp_case.go`, `case_stagee.go`). Legend: EXISTS = route + handler + tests present; PARTIAL = exists but limited; GAP = no API.

## A. Per-page matrix (17 screens)

| # | Screen (route) | Component/action | M6 route/service | Permission | Ready? | Fallback | Test |
|---|---|---|---|---|---|---|---|
| 01 | Home `#home` | My cases count | `GET /api/v1/cases?limit=1` | ViewCTI | EXISTS | No data → EmptyState | — |
| 01 | Home | Pending reviews | per-case artifacts only; **no global queue** | Review + grant | GAP | Hide queue | — |
| 01 | Home | New intelligence items | — | — | PLANNED | Disabled + label | — |
| 02 | My Work `#mywork` | Aggregate authorized records | `GET /api/v1/cases` + `GET …/investigations` + activity | ViewCTI | FRONTEND-ONLY | No cross-client rows | — |
| 03 | Review Queue `#reviews` | Review list | per-case artifact/hyp review only | Review + grant | GAP (global queue) | Per-case review in Workspace | — |
| 04 | Feed `#feed` | Triage feed | `GET /api/v1/tenants/{client_id}/cti/reports` (per-client list) + `POST /api/v1/cti/import` | ViewCTI | PARTIAL (no aggregated feed) | Show per-client reports only | — |
| 05 | Reports `#reports` | Report detail + entities | `GET /api/v1/cti/reports/{id}`, `…/iocs`, `…/ttps`, `…/cves`, `…/evidence`, `POST …/analyze` | ViewCTI | EXISTS | — | — |
| 06 | Entities `#entities` | IOC/TTP/CVE browser | per-report entity endpoints only (no global entity browser) | ViewCTI | GAP | Disable + label | — |
| 07 | Cases `#cases` | Explorer + search/filters/pagination + create | `GET/POST /api/v1/cases` | ViewCTI / CreateCTI + grant | EXISTS | Existing fallback `cases-list.html` | Stage B tests |
| 08 | Case Workspace `#case` | Header, tabs, lifecycle drawer | `GET /cases/{id}`, `PUT …/status` | View/CreateCTI | EXISTS | Existing fallback `case-detail.html` | Stage C tests |
| 08 | Case Workspace | Participants drawer | `POST/GET/DELETE …/participants` | Owner (mutate) | EXISTS | — | Stage C tests |
| 08 | Case Workspace | Evidence + Review | `PUT …/artifacts/{aid}/review` | Review + grant + classification | EXISTS | — | Stage D tests |
| 08 | Case Workspace | Notes | `POST/GET …/notes` | NoteCreate/View | EXISTS | — | Stage D tests |
| 08 | Case Workspace | Timeline | `GET …/activity` | ViewCTI + predicate | EXISTS | — | — |
| 09 | Hypothesis Lab `#hypotheses` | Registry | `GET /api/v1/hypotheses` (available), `POST …/hypotheses/{id}` link, `POST …/review` | Link/ReviewHypothesis + grant | EXISTS (link/list/review); authoring = GAP | — | Stage E tests |
| 10 | Hunt Workspace `#hunt` | README/AQL/execution evidence | none | — | PLANNED (no hunt engine) | Disabled + label | — |
| 11 | Detection Coverage `#detection` | ATT&CK mapping | `GET /api/v1/qradar/{rules,building-blocks,fields}`, `GET /api/v1/inventory/*`, `GET /inventory/telemetry` | ViewCTI | PARTIAL | Show "not verified" | — |
| 12 | QRadar Inventory `#qradar` | Rules/BB/Fields drilldown | same QRadar routes | ViewCTI | EXISTS | Legacy pages hardening pending | — |
| 13 | Field Intel Lab `#fields` | Parser + mapping + validation | none | — | PLANNED | Plain text note | — |
| 14 | Client Intelligence `#clients` | Per-client scope | `GET /api/v1/clients`, grants in `/me` | ViewCTI | PARTIAL (no relevance store) | — | — |
| 15 | Investigations `#investigations` | List + create | `GET/POST /api/v1/cases/{id}/investigations` (Stage G) | View/CreateCTI + grant | EXISTS | — | Stage E/G tests |
| 16 | Evidence Graph `#graph` | Graph visualization | M5.1 DB storage (no standalone UI endpoint) | — | GAP (UI) | Table alternative (backend storage check) | — |
| 17 | Settings `#settings` | Roles/grants/audit/integrations | `GET /api/v1/auth/me`, audit read (limited) | Admin (or read-only) | GAP | Read-only overview disabled | — |

## B. Deviations from reference

- Client context in reference: Global/Alpha/Gamma. Real grants are per-user `user_authorized_clients`; demo Gamma ≠ real client. Gamma must never appear in production.
- Synthetic IDs (RES-1042, HYP-021) in reference — production uses server UUIDs; reference labels must not be copied into live DOM as real.
- `GLOBAL` in reference often implies cross-client objects; M6 enforces grant-predicate for CLIENT content everywhere — reference Global Research must be metadata-only.

## C. Component plan

Production tree reusing Go + HTML/CSS/JS (no new build system):

```
frontend/
  design-tokens.css   (extract from v3: midnight navy #0f172a/#0b1120, teal-mint accent, status semantics)
  shell.js            (AppShell: topbar + sidebar + inspector + client context selector)
  components/
    DataTable.js / StatusBadge.js / TrustLabel.js / ClientScopeSelector.js
    SearchFilterBar.js / CTIReportCard.js / EvidenceCard.js / HypothesisCard.js
    ProvenanceInspector.js / Timeline.js / PermissionAwareAction.js
    Loading/Empty/Denied/Error states (shared renderers)
  pages/
    cases-list.*      (V2-F2 re-skin, API unchanged)
    case-detail.*     (V2-F3 re-skin, API unchanged)
    home.*            (V2-F4 aggregates via existing APIs)
    intelligence.*    (V2-F5 prototype only)
    hunt.*            (V2-F6 design-only)
  api.js              (existing — no change; cookies + CSRF authoritative)
```

Routing: hash routes mirroring reference (`#home`, `#cases`, `#case` etc.) → pages above. Deep links preserve `?case_id=` + `?tab=` params.

## D. Phased rollout (small independent milestones)

- **V2-F1** — Shell + Design System (tokens + shell + client selector + states). Exit: visual diff at 1280/1440/1600/1920, no route breakage.
- **V2-F2** — Cases Explorer re-skin (same `GET/POST /cases` contracts; saved filters frontend-only). Exit: Stage B tests + Browser E2E (create/list/pagination/deny).
- **V2-F3** — Case Workspace re-skin (Overview/Hypotheses/Evidence/Investigations/Notes/Timeline + drawers). Exit: Stage C/D/E browser workflow (status → participants → note → review → investigation → logout) + grant revocation checks.
- **V2-F4** — Analyst Home aggregates (cases + per-case reviews + investigations; queue items marked BACKEND-GAP where no global endpoint). Exit: two-role/multi-client E2E.
- **V2-F5** — Intelligence Hub (per-client reports only via existing CTI routes; feed marked PLANNED). Exit: no invented KPIs.
- **V2-F6** — Hypothesis/Hunt Workspace design-only chrome (no execution). Exit: prototype review only.
- **V2-F7** — Browser UX, accessibility (landmarks, keyboard, contrast), security acceptance (XSS/CSRF/session/no-storage), screenshot regression.

Old pages (`frontend/cases-list.html`, `case-detail.html`, QRadar legacy) remain fallback until each milestone is accepted; production `WORKBENCH_SEED_DATA` stays false and `storage/workbench.db` is untouched.

## E. Design-only / PLANNED (must not appear operational)

Global feed aggregation, Threat Entities global browser, Hunt execution / AQL deployment, Findings store, Field Intelligence parser, User Administration (roles/grants/audit mutation), SIEM execution, any demo KPI with fake scores.
