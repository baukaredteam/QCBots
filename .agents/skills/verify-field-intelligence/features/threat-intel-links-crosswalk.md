# Threat Intel Links crosswalk

Verdict: NOT VERIFIED as a browser scenario. The precondition "tab absent from shipped code" is removed: the tab exists in source at `e3cacbdaf807936d5e7eac95a1ede8fb7683e9f3` after PR #9, proven by a real static check. No authenticated browser run occurred, so no rendered crosswalk, screenshot, console output or browser exit code is recorded.

## Sub-features

- Designed crosswalk: External CTI (Threadlinqs) → technique/IOC/detection requirements → client/domain scope after admin confirmation → DSM/QID/Event/Fields → hunt readiness/gaps → M7-D hypothesis or hunt plan DRAFT (`docs/FIELD_INTELLIGENCE_DESIGN.md` §8).
- Source proof at `e3cacbd`: `grep -n "threat-links" frontend/v3/v3.js` exited 0 and printed line 376 `['threat-links', 'Threat Intel Links']` in `tabDefs` and line 407 `if (fieldCtl.tab === 'threat-links')`. `grep -n "Threat Intel Links"` also exited 0 and printed line 411 with `Threat Intel Links · DESIGN ONLY`. Raw stdout/stderr, exit codes and the revision are in `../evidence/2026-11-17-threat-links-static/`.
- Rendered honesty labels in source: `DESIGN ONLY - conceptual crosswalk; no client evidence or coverage verdict.`, `Threadlinqs live PoC: NOT VERIFIED`, and the statement that private event payloads are never sent externally and no synthetic metrics are displayed. These are source strings, not observed UI text.
- The earlier absence claim applied only to baseline `e70de881`; it must not be reused for the current code.

## How to get to it (user POV)

An analyst expects a Threat Intel Links tab that shows the crosswalk and marks the external CTI integration NOT VERIFIED rather than implying a live feed or confirmed detection.

## Driving it with agent-browser

With a live authenticated session, open `/v3/index.html#fields`, click the `Threat Intel Links` tab ref, snapshot the crosswalk text and its NOT VERIFIED labels, capture a screenshot plus reported console/page errors, and close the task browser. Record the action/ref and resulting state; browser actions have N/A exit codes.

At the time of this record this was NOT EXECUTED: the static proof establishes only that the code exists. If a future correctly provisioned run cannot find the tab, that is FAIL — do not weaken the journey.

## Gotchas

- Static `grep` evidence proves source presence, not rendered behavior; it does not upgrade the browser scenario.
- The DESIGN ONLY concept and design document are references, not proof of a live Threadlinqs integration.
- No private event payload may be sent to an external CTI service; no PoC exists and the integration stays NOT VERIFIED.
- Never fabricate metrics, console output or a browser exit code to fill the gap.
