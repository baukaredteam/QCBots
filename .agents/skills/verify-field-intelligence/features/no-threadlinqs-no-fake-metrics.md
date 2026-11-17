# No Threadlinqs calls and no fabricated metrics

Verdict: NOT VERIFIED at `e70de881`. Static source inspection is not a runtime observation; no authenticated session was available to observe network traffic.

## Sub-features

- During a Field Intelligence session, no request to any Threadlinqs host or MCP endpoint, and no request to an external enrichment service, unless separately approved and PoC-verified.
- Visible counts come from loaded `/api/v1/qradar/*` arrays; no hardcoded demo metrics are displayed when data is absent.
- `frontend/v3` source contains no Threadlinqs call; the only frontend mention is a prototype labelled approval pending and unverified (`frontend/prototypes/v2/intelligence-hub.html`).

## How to get to it (user POV)

An analyst should see either real loaded inventory numbers or an honest empty state; the screen must not imply a live CTI feed or show impressive-looking numbers that were never loaded.

## Driving it with agent-browser

With a live authenticated session, open `/v3/index.html#fields`, select an authorized client, then observe network requests made by the page and the visible metric text. Use whatever request/console observation the mounted surface provides; if it cannot expose the request log, say so and mark NOT VERIFIED rather than claiming no calls. Compare visible numbers with the loaded arrays from the QRadar endpoints.

A read-only source check (`grep -R -i threadlinq frontend/v3`) can be recorded as a static observation, but it does not prove runtime absence and must not upgrade this scenario to REAL PASS.

## Gotchas

- Absence of an error is not proof of absence of calls: report whether request observation was actually available.
- `docs/FIELD_INTELLIGENCE_DESIGN.md` is DESIGN ONLY; its sample numbers are synthetic and must not be treated as live metrics.
- No credentials, mocked responses or fabricated network results.
