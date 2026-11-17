# Sentinel Atlas — Future Milestones Planning Addendum (DOCS ONLY)

> This document is **planning only**. Nothing described here is implemented, deployed, or authorized. M7-D, Detection-as-Code, QRadar execution, Octop, and Telegram require separate explicit approvals.

Design references (not implementation directives): Andrey Pautov — detection engineering techniques; Mayank Joshi — anatomy of a good detection rule; Adam Goss — Detection as Code pipelines; Rcegan — multi-platform detection-as-code for MSSP. These inform future design; they do **not** authorize the future Detection-as-Code platform in M7-C.

## M7-D — Threat Hunting Hypotheses (planned, not started)

Each hypothesis artifact should carry:

| Field | Purpose |
|---|---|
| `hypothesis` | Falsifiable statement (what behavior, in which context). |
| `required_telemetry` | Log sources + fields needed to observe the behavior (per client, from M7-C telemetry evidence). |
| `expected_observables` | Concrete, measurable signals (with expected volume/conditions). |
| `known_benign_behavior` | Benign explanations to exclude before escalation. |
| `blind_spots` | What the hypothesis cannot see (missing sources, agents, retention). |
| `validation_plan` | How to test in shadow/lab before any operational use. |

All M7-D outputs remain human-approved; no automatic QRadar changes.

## Future Detection Engineering (Detection as Code) — planned boundaries

- **Native QRadar AQL artifacts** per rule (versioned, client-scoped content packs).
- Optional **Sigma source/reference** (reference only; canonical artifact stays QRadar AQL).
- **Content Packs per client** (tenant-scoped; no cross-client reuse without explicit publication).
- **Rule metadata and ownership** (owner, source, MITRE mapping, last review).
- **Schema validation** for every artifact before merge.
- **Positive/negative test fixtures** (synthetic events that must / must not fire the rule).
- **Shadow mode** before production enablement.
- **Human approval** for any deployment, edit, or deletion.
- **Deployment/rollback controls** (versioned promotion, instant rollback to prior version).

## Future Agent Harness — planned controls

- **Agent/tool audit events** (every tool call logged with inputs, outputs, model metadata; no secrets in logs).
- **Tenant-scoped permissions** (per-client credentials, grant-checked at every tool boundary; same-client-only as in M7-C).
- **Sandboxing** (no direct database access; API/MCP only; no outbound network by default).
- **Human approval for external actions** (any write, deployment, or response operation requires explicit approval).

## Explicit non-goals until separately approved

- No M7-D implementation, no rule deployment, no QRadar API execution, no Octop, no Telegram.
- No cloud dependency, no Kubernetes for MVP, no automatic incident response.
