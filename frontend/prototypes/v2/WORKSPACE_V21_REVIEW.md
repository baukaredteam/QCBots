# Research Case Workspace v2.1 — Design Review & Journey

## What was delivered (isolated, interactive, no backend changes)

- `frontend/prototypes/v2/research-case-workspace-v21.html` — standalone interactive workspace (local synthetic data only — **never calls production APIs**).
- `frontend/prototypes/v2/workspace-v21.css` — shared design tokens (sidebar 260px / inspector 340px / topbar 64px).
- `frontend/prototypes/v2/API_MATRIX.md` — verified vs actual `main.go` routes.
- Screenshots: exports via agent-browser at ~1280/1440/1920 (Chrome device metrics).

## Fixes vs v2.0

1. Cases Explorer demo rows with beta titles/IDs removed — explorer shows only authorized cases.
2. Grid shell repaired: `grid-template-areas "top top top" "left main right"`; sidebar compact (64px), inspector overlay drawer below 1440px. No overflow.
3. Data labelling: every card carries REAL / SYNTHETIC / PLANNED tags; synthetic cards state “not a finding”.

## User journey (synthetic, offline)

1. Load workspace → GLOBAL context hides CLIENT rows.
2. Select Context = client-alpha → linked hypotheses (hyp-1122/3344) appear.
3. Click hypothesis → Inspector shows TTPs, telemetry, AQL draft, confidence vs review vs outcome.
4. Open investigation drawer → create (prototype, no POST).
5. Open note, timeline, evidence tabs — filtering follows the same context.
6. Esc closes drawers; keyboard focus visible on all interactive elements; no raw UUIDs as primary labels (short IDs shown first).

## Explicitly design-only in v2.1

- CTI feed / report explorer detail, hunt execution/SIEM, AQL deployment, findings store, global search, user admin — prototyped surfaces only, never functional in production UI.
