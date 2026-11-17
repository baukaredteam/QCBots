# Open Field Intelligence with an authorized client

Verdict: NOT VERIFIED at `e70de881`. No live backend/session and no browser run occurred; no exit codes or observed page results were fabricated.

## Sub-features

- Nav link `Field Intelligence` (route `fields`) and the `Open Field Intelligence` button in Hunt Workspace.
- Client context `#tenant` (`aria-label="Client context"`) and the view's `Client` select populated from `me.authorized_clients`.
- Cascading selects: QRadar instance, domain, log source type, log source, event; tabs Event Catalog / Field Registry / Auto Import / Mapping Inspector / Hunt Readiness (Domain Bindings for ADMINISTRATOR).
- Honest states: `.statebox` messages for no client, empty result, 403/404/400/503/network errors; `UNVERIFIED` badge until manual AQL evidence exists.

## How to get to it (user POV)

An authorized analyst opens `/v3/index.html#fields`, picks an authorized client, and expects either real client-scoped rows or an explicit honest reason why data is unavailable — never zero-filled metrics or a silently empty catalogue.

## Driving it with agent-browser

Prerequisites are in `../SKILL.md#launch`: an authenticated session where `/api/v1/auth/me` returns 200. Then use the mounted Browser: open the URL, click the `Field Intelligence` nav ref, snapshot, select an authorized client in the `Client` select (and, if needed, `#tenant`), click `Field Registry`, snapshot again and inspect `.statebox` text and row badges. Capture the resulting state and reported errors.

At baseline the auth probe returned HTTP 000 on ports 8080/4174/4173, so no page action was executed. If a future run finds `/api/v1/auth/me` at 404/401/403, classify as ENVIRONMENT / NOT VERIFIED, not product FAIL.

## Gotchas

- `No rows for this selection.` means "not recorded", not "not present in QRadar" — the UI text must stay honest.
- A `CANDIDATE`/`UNVERIFIED` field must not be presented as `AQL VERIFIED`; the badge text is the observable check.
- The V4 concept HTML is synthetic design reference and must not be opened as if it were the live app.
- Browser actions have no shell exit code; record N/A rather than inventing 0.
