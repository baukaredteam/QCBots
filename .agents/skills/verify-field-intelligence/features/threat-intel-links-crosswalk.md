# Threat Intel Links crosswalk

Verdict: NOT VERIFIED at `e70de881`. The tab is specified in the DESIGN ONLY document but is absent from the shipped v3 code, and no authenticated browser run occurred.

## Sub-features

- Designed crosswalk: External CTI (Threadlinqs) → technique/IOC/detection requirements → client/domain scope after admin confirmation → DSM/QID/Event/Fields → hunt readiness/gaps → M7-D hypothesis or hunt plan DRAFT (`docs/FIELD_INTELLIGENCE_DESIGN.md` §8).
- Expected honesty labels: Threadlinqs `[NOT VERIFIED · без приватных payload]`; admin confirmation required for client↔domain; Sigma/KQL/SPL presence does not prove coverage.
- Shipped-code precondition: `frontend/v3/v3.js` line 376 defines tabs without `Threat Intel Links`; the label exists only in the design doc and the concept HTML.

## How to get to it (user POV)

An analyst expects a Threat Intel Links tab that shows the crosswalk and marks the external CTI integration NOT VERIFIED rather than implying a live feed or confirmed detection.

## Driving it with agent-browser

With a live authenticated session, open `/v3/index.html#fields`, look for the `Threat Intel Links` tab ref, click it, snapshot the crosswalk text and its NOT VERIFIED labels, and capture a screenshot plus reported console/page errors. If the tab is absent in a correctly provisioned environment, that is a FAIL of this scenario — record the missing precondition instead of weakening the journey.

At baseline this was NOT EXECUTED: no backend session and no tab in code. The design document cannot substitute for a rendered tab.

## Gotchas

- Do not treat the DESIGN ONLY concept or the design document as proof that the tab exists.
- No private event payload may be sent to an external CTI service; the design forbids it and no PoC exists.
- A hypothetical integration status must read NOT VERIFIED, never VERIFIED by a mock or a static label.
