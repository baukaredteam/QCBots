# Frontend Architecture v2.0 — Sentinel Atlas Hybrid Workbench

## 1. Authority & Boundaries

- Backend: Go + SQLite (migrations 0001–0005), RBAC + per-client grants, tenant isolation, audit logging — **unchanged**.
- Evidence Graph MVP M5.1 and QRadar Inventory — preserved, not reimplemented.
- MCP code preserved; Octop / Telegram / other harnesses — **not integrated** in this phase.
- Production frontend (`frontend/cases-list.html`, `frontend/case-detail.html`, `frontend/login.html`, `frontend/dashboard.html`, QRadar pages) remains the **fallback functional UI**. Phase 1 creates isolated prototypes in `frontend/prototypes/v2/` only.
- Working SQLite (`storage/workbench.db`) is **never modified** by this design phase. Prototypes render static synthetic data and never call production APIs.

## 2. Information Architecture (sitemap)

Paid v2.0 IA uses five top-level groups. Only functional items are navigable.

```
HOME
  /home                  Analyst Home (functional, M6 APIs)
  /my-work               My Work (FRONTEND-ONLY via GET /api/v1/cases + filters)
  /review-queue          Review Queue (FRONTEND-ONLY: artifacts with review_decision IS NULL via GET /cases/{id}; flagged design-only until backend filter exists)

INTELLIGENCE
  /intelligence          Intelligence Hub (BACKEND-GAP: no CTI feed endpoint; prototype only)
  /reports               Report Explorer (BACKEND-GAP)
  /entities              Threat Entities (BACKEND-GAP: IOC/TTP/CVE explorer)
  /research-cases        Research Cases Explorer (EXISTING)

THREAT HUNTING
  /hypothesis-lab        Hypothesis Lab (PLANNED — no create hypothesis API)
  /hunt                  Hunt Workspace (PLANNED)
  /hunt-history          Hunt History (PLANNED)

DETECTION ENGINEERING
  /qradar/rules          QRadar Rules (EXISTING)
  /qradar/building-blocks (EXISTING)
  /qradar/fields          (EXISTING)
  /telemetry             Telemetry Coverage (EXISTING partial: ListClientTelemetry)
  /field-intel           Field Intelligence Lab (PLANNED)

SOC OPERATIONS
  /clients               Client Workspaces (FRONTEND-ONLY grouping of cases by primary_client)
  /investigations        Investigations (EXISTING partial: ListCaseInvestigations)
  /findings              Findings (BACKEND-GAP: no finding store)

KNOWLEDGE
  /evidence              Evidence Graph (EXISTING: M5.1)
  /sources               Sources & Provenance (FRONTEND-ONLY: artifact provenance_source)

ADMINISTRATION
  /admin/users           Users and Permissions (BACKEND-GAP: no user-admin API)
  /admin/clients         Client Access (BACKEND-GAP: no grant-admin API)
  /audit                 Audit and Settings (BACKEND-GAP)
```

Route hierarchy: `/` → `/login` (existing) → `/cases` → `/cases/:case_id` → tabs. Deep links use query params (`?case_id=`, `?tab=`). Breadcrumbs: `Home / Research Cases / {case title short}`. Global search filters current list (cases); non-case search is design-only placeholder and disabled until backend exists.

Sidebar groups mirror above. **Permission-aware navigation:** items render only if the user's role and client grants make them meaningful. Admin-only items (Users/Permissions) are hidden for non-admins; CLIENT-scoped filters are never offered to users lacking the grant. Frontend permissions are presentation-only — every API enforces RBAC/grants.

## 3. Global Application Shell

- Left: collapsible sidebar (260px, collapses to 64px) with group headings, current workspace label, user/role/grants footer. Active state via `aria-current="page"`.
- Top: global search (filters current list; no cross-client search), breadcrumb, **client context selector** (from `/me.authorized_clients`; `Global Research` = no client filter = metadata only), user menu (id/role), notifications bell (design-only until backend), quick actions (+ New Case, Back to Cases).
- Center: primary analytical workspace (max-width 1440, fluid).
- Right: collapsible contextual inspector (340px) — provenance, related objects, client relevance, review info, contextual actions. Expandable via toggle; hidden on <1280px.

Responsive: `grid-template-columns: 260px 1fr 340px` ≥1440px; at 1280px right panel becomes overlay drawer; at <1024px sidebar collapses to icon rail.

## 4. Design Language (dark-first, restrained)

- Surfaces: `#0b1120` body, `#0f172a` cards, `#1e293b` raised, `#334155` borders.
- Accent: blue/cyan `#3b82f6` / `#38bdf8`, controlled semantics: `OPEN` green, `IN_PROGRESS` blue, `REVIEW` amber, `CLOSED` slate, `ARCHIVED` dim.
- Density: 13–14px table text, 12px badges, 500–700 weights. No neon/glow, no emoji in primary nav, no decorative charts, no fake scores.
- Typography: system stack, mono for IDs/hashes. Evidence vs hypothesis vs judgment visually separated (amber = pending judgment, slate = evidence, blue = hypothesis).

## 5. Component Catalog (props / states / a11y)

| Component | Props | States | A11y |
|---|---|---|---|
| ApplicationShell | user, clients, nav | auth, loading | landmark `nav`, `main`, `aria-current` |
| WorkspaceHeader | title, breadcrumb, clientContext | — | `h1`, focusable actions |
| ClientContextSelector | clients[], value | unauthorized items hidden | `label` + native select/ radiogroup |
| CTIReportCard | report, relevance, actions | empty/loading/error | button actions focusable |
| ResearchCaseCard/Row | case, access chips | empty/loading/error/forbidden | row as button, keyboard enter |
| EvidenceCard | artifact, provenance, classification | SUMMARY/FULL/NONE | text via `textContent` |
| ProvenancePanel | source, hash, created_by | — | labelled list |
| HypothesisCard | hyp, latest decision | pending/approved/rejected | badge text, not colour alone |
| TelemetryCoveragePanel | coverage, gaps | partial/none | table not chart |
| ReviewDecisionPanel | decision, reason, reviewer | pending/reviewed | radios + textarea labels |
| InvestigationTimeline | events[] | empty | list with times |
| RelatedEntitiesPanel | iocs/ttps/cves[] | empty | text only |
| StatusBadge | status | open/progress/review/closed/archived | text + colour |
| PermissionAwareAction | perm, disabledReason | hidden/disabled | `disabled` + tooltip |
| DataTable | columns, rows, pagination | loading/empty/error | `scope="col"`, keyboard nav |
| FilterBar | filters, onChange | — | labelled controls |
| EmptyState/LoadingState/ErrorState/AccessDeniedState | title, hint, action | — | `role="status"`/`role="alert"` |

All components render untrusted data via `textContent`/`createElement`. No `innerHTML` with server data. No hidden DOM carrying unauthorized content; filtered-out rows are omitted server-side, never client-hidden.

## 6. UI → API / Permission / Data Readiness

| UI feature | Endpoint | Available? | Permission | Real data? | Class |
|---|---|---|---|---|---|
| Analyst Home stats (my cases count) | `GET /api/v1/cases?limit=1` | yes | ViewCTI | yes | EXISTING |
| New CTI reports feed | — | no | — | no | PLANNED / BACKEND-GAP |
| Hypotheses requiring attention | `GET /api/v1/cases/{id}/hypotheses` | yes | ViewCTI | yes | EXISTING |
| Pending reviews | — (no global endpoint; per-case artifacts) | partial | Review | yes (case-level) | FRONTEND-ONLY (per-case) |
| Recent investigations | `GET /api/v1/cases/{id}/investigations` | yes | ViewCTI | yes | EXISTING |
| Report cards + IOCs/TTPs | — | no | — | no | PLANNED |
| Case list + search/status/priority/client | `GET /api/v1/cases` | yes | ViewCTI + grants | yes | EXISTING |
| Create case (stable idempotency) | `POST /api/v1/cases` | yes | CreateCTI + grant | yes | EXISTING |
| Case header + lifecycle UI | `GET/PUT /api/v1/cases/{id}[/status]` | yes | CreateCTI for transition | yes | EXISTING |
| Participants UI | `GET/POST/DELETE …/participants` | yes | owner / ViewCTI | yes | EXISTING |
| Evidence + review | `GET /cases/{id}` (artifacts) + `PUT …/review` | yes | Review + grant + classification | yes | EXISTING |
| Hypotheses link/list/review | `POST/DELETE/GET …/hypotheses`, `POST …/review` | yes | Link/Review + grant | yes | EXISTING |
| Investigations create/list | `POST/GET …/investigations` | yes | CreateCTI/ViewCTI + grant | yes | EXISTING |
| Notes | `POST/GET …/notes` | yes | Note create/view | yes | EXISTING |
| Activity timeline | `GET …/activity` | yes | ViewCTI + grant predicate | yes | EXISTING |
| Global search | — | no | — | no | BACKEND-GAP (case text only currently) |
| Telemetry coverage, field intel, user admin | — | no | — | no | BACKEND-GAP |

No invented APIs. Landing/Home and Hub pages are **design prototypes with labelled synthetic data** where columns are marked BACKEND-GAP/PLANNED.

## 7. Analyst Workflows

**A. CTI Research** — Discover report → inspect sources → identify TTPs **(PLANNED — no report-detail API)** → Open Research Case **(EXISTING via Create modal)**. Intelligence Hub prototype shows the flow with `BACKEND-GAP` badges on report detail/CTI feed.

**B. Client Relevance** — Select case → Overview shows `primary_client` + artifacts grouped by client (EXISTING); authorized clients only (EXISTING Grant check). Applicable technologies/telemetry assessment text — PLANNED (no assessment store; Telemetry Coverage API partially exists).

**C. Hypothesis → Investigation** — Open case → select hypothesis from `GET /api/v1/hypotheses` selection → Link (EXISTING) → Review per-client (EXISTING append-only) → Create Investigation (EXISTING) → view evidence (EXISTING via CaseContext artifacts).

**D. Human Review** — Reviewer (`user-reviewer`, REVIEWER role) opens case → Artifacts Review or Hypothesis Review → submits decision (EXISTING) → history append-only (Triggers) → analyst views result (EXISTING latest decision).

**E. Multi-Tenant Privacy** — Alpha user opens GLOBAL case → `case_artifacts` filtered by grant, notes/hypotheses/activity/ investigations all predicate-filtered server-side. UI shows empty states, never beta content.

M6 supports: Case lifecycle, linking, per-client review, investigations create/list, notes, activity. M7–M12 required for: CTI feed/report explorer, discovery pagination/cursor, assessment store, hypothesis discovery & telemetry, investigation verdict workflow, global review queue.

## 8. Responsive / Accessibility / Security

- Desktop-first at 1280/1440/1920px; inspector overlays below 1440; sidebar icon-rail below 1024.
- Color-contrast AA for text on dark surfaces; status not by colour alone (badge text).
- Safe DOM rendering: `textContent`/`createElement` only for untrusted server data.
- Cookie-session (HttpOnly) + CSRF double-submit; no tokens in `localStorage/sessionStorage` (M6 pages fixed in Stage G; legacy `dashboard.html`/`qradar-rules.html` fixed, `qradar-building-blocks/fields/import.html` documented as limitation).
- 401 redirects to login; 403 shows AccessDeniedState; 409 conflict (idempotency) surfaced inline; 503 renders `SCHEMA_NOT_READY` state instead of silent fallback.
- Masked credential inputs, logout clears session server-side.

## 9. Implementation Milestones (Phase 3 — NOT started)

- V2-F1 Shell + Design System (extract `cases.css` tokens, ApplicationShell component).
- V2-F2 Cases Explorer (VirVir: reuse `cases-list.*` + filter bar polish).
- V2-F3 Case Workspace (reuse `case-detail.*` + Overview/Hypotheses/Investigations panels).
- V2-F4 Analyst Home (read-only aggregates from existing APIs).
- V2-F5 Intelligence Hub (prototype only until CTI feed API exists).
- V2-F6 Hypothesis/Hunt Workspace (design-only until telemetry/hunt APIs).
- V2-F7 Browser UX, accessibility and security acceptance (same checklist as Stage G).

Explicit non-goals: no new frontend build system, no endpoint invention, no M7 backend, no MCP/Octop/Telegram.
