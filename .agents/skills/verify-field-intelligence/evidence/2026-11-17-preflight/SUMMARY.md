# Preflight evidence — 2026-11-17

Operator: QA / Verification Engineer (MSSP Intelligence Workbench). Scope: environment discovery only. No browser action and no application run were executed.

## Executed commands and fresh exit codes

| Artifact prefix | Command | Exit code | Result |
|---|---|---|---|
| `01-revision` | `git -C <worktree> rev-parse HEAD` | 0 | `e70de881fe1e143ce115e0e216f632035b094a6c` |
| `02-agent-browser` | `agent-browser --version` | 0 | `agent-browser 0.41.2` |
| `03-probe-8080` | `curl.exe -s -o NUL -w "%{http_code}" --max-time 3 http://127.0.0.1:8080/api/v1/auth/me` | 7 | HTTP 000, connection refused |
| `04-probe-4174` | same probe on port 4174 | 52 | HTTP 000, empty reply |
| `05-probe-4173` | same probe on port 4173 | 52 | HTTP 000, empty reply |

Raw stdout/stderr, exit codes and the exact command list are stored beside this file.

## Verdicts

- Open Field Intelligence with an authorized client: NOT VERIFIED (no live backend session; no browser action).
- Threat Intel Links crosswalk: NOT VERIFIED (no live session; tab absent from shipped `frontend/v3` code at this revision).
- No Threadlinqs calls and no fabricated metrics: NOT VERIFIED (no session in which to observe requests; static source inspection is not runtime proof).

Browser tool availability is REAL PASS for `agent-browser --version` only. No page result, screenshot, console output or browser exit code is recorded because no page was driven; browser actions would have N/A exit codes even if driven through the mounted surface. This record does not certify a release or a product failure.
