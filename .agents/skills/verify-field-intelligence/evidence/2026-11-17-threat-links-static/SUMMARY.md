# Static proof — Threat Intel Links tab exists in v3 source

Executed after PR #9 was merged. Code revision: `e3cacbdaf807936d5e7eac95a1ede8fb7683e9f3` (merge of `feat/field-intel-threat-links` and subsequent invariants work). The earlier claim "the tab is absent from shipped code" applied to `e70de881` only and is superseded here.

| Artifact prefix | Command | Exit code | Output |
|---|---|---|---|
| `01-revision` | `git rev-parse HEAD` | 0 | `e3cacbdaf807936d5e7eac95a1ede8fb7683e9f3` |
| `02-grep-threat-links` | `grep -n "threat-links" frontend/v3/v3.js` | 0 | Lines 376 (tab definition) and 407 (render branch) |
| `03-grep-label` | `grep -n "Threat Intel Links" frontend/v3/v3.js` | 0 | Lines 376 and 411 (`Threat Intel Links · DESIGN ONLY`) |

Raw stdout/stderr and fresh exit codes are stored beside this file.

Verdict: STATIC CODE PROOF — the tab and its render branch exist at `e3cacbd`. This is not a browser run: no rendered tab, crosswalk text, screenshot or request observation was captured. The browser scenario remains NOT VERIFIED until an authenticated backend session is available.
