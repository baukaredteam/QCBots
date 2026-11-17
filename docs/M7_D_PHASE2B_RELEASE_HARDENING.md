# M7-D Phase 2B-4B — Release Hardening

Scope: harden the completed Hunt Workspace. No new CTI, QRadar, AI, connector or
deployment functionality was added.

## 1. Vulnerabilities fixed

| # | Vulnerability | Impact | Fix |
|---|---|---|---|
| V1 | The acceptance seeder deleted an existing file (`os.Remove`) after a filename/test-user heuristic | Running `seed-hunt-acceptance` over any file named something else than `workbench.db`, or over a database whose users looked synthetic, destroyed it | All deletion removed. The target must not exist in any form and is created with `O_EXCL` after canonical path validation |
| V2 | Path trust was based on the basename and the default path only | A symlink, junction, relative path or alternate filename could point the seeder at an application or user database | Canonical resolution (`EvalSymlinks`) of the authorized directory and target parent; the target must be inside `SENTINEL_ACCEPTANCE_DIR`, which must be inside the OS temp root and outside the application tree; `Lstat` rejects files, directories, symlinks and broken symlinks |
| V3 | `frontend/api.js` and `login.html` hardcoded `localhost:8080` (and a special `:18081` branch) | The shell could send authenticated requests to an unintended host or fail on any other port, HTTPS or reverse proxy | Same-origin relative `/api/v1` everywhere (api.js, login.html and the legacy HTML pages). No absolute API origin remains |
| V4 | CSRF accepted only the configured origin | Same-origin writes failed on a custom port, behind TLS termination or a proxy unless the deployment origin was reconfigured | The validator now accepts a request whose `Origin` matches the request host/scheme, honouring `X-Forwarded-Proto`/`X-Forwarded-Host`; the allowlist remains for explicit cross-origin development |
| V5 | Plan creation always sent `hypothesis_version: 1` | A plan could reference the wrong hypothesis version | `GET /api/v1/hypotheses` now returns `current_version_no`; the UI sends the reported version and refuses to create a plan when it is missing |
| V6 | Async workspace renders used mostly-sequential guards | A late response after a client/rule/domain switch or navigation could overwrite a newer view | Sequence checks after every await, `isConnected` checks before painting, and navigation invalidates in-flight workspace requests; a version fork updates the deep link |

## 2. Files changed

| File | Change |
|---|---|
| `backend/seed_hunt.go` | safe path gate + `O_EXCL` creation, no deletion; HTML-safety fixture rule |
| `backend/hunt_acceptance_guard.go` | new canonical-path validator |
| `backend/hunt_acceptance_guard_test.go` | new safety tests |
| `backend/audit.go` | same-origin CSRF comparison with proxy headers |
| `backend/csrf_same_origin_test.go` | new CSRF matrix |
| `backend/case_stagee.go` | `current_version_no` in the hypothesis list |
| `backend/hypothesis_version_test.go` | new assertion |
| `frontend/api.js` | same-origin API base |
| `frontend/login.html` | relative login and redirect |
| `frontend/*.html` (legacy) | relative API base |
| `frontend/v3/hunt-workspace.js` | hypothesis version, AQL selector, async guards, fork deep link |
| `frontend/v3/v3.js` | navigation invalidates workspace requests |
| `tests/browser/*` | new reproducible Playwright acceptance suite |

## 3. Safety tests (acceptance database)

`go test -run 'TestValidateAcceptanceDBPath|TestSeedHuntAcceptance'` covers:

| Case | Expected |
|---|---|
| new path inside the authorized temp directory | accepted, nothing created by validation |
| existing SQLite database | refused, bytes unchanged |
| empty file | refused, bytes unchanged |
| malformed/garbage database | refused, bytes unchanged |
| synthetic-looking alternative filename | refused, content unchanged |
| symlink at the target | refused, link and target unchanged |
| application directory (`..`, `storage`, `config`) | refused |
| path outside the authorized directory | refused |
| authorized directory missing / empty target | refused |
| target is a directory or the production name | refused |
| no `SENTINEL_ACCEPTANCE_DIR` | refused, no file created |
| existing file end to end | refused, content unchanged |

No code path deletes or truncates a pre-existing file.

## 4. API configuration

- Browser clients call relative `/api/v1/...`; the request goes to the origin
  that served the page. There is no hardcoded host or port anywhere in
  `frontend/`.
- CSRF: state-changing requests need a matching `Origin`. A same-origin request
  is accepted for `http`/`https` on any port, including behind a TLS-terminating
  proxy (`X-Forwarded-Proto`, `X-Forwarded-Host`). `WORKBENCH_ORIGIN` remains the
  explicit allowlist for genuine cross-origin development.
- Sessions stay in HttpOnly `SameSite=Lax` cookies; the CSRF token stays in the
  readable `csrf_token` cookie and is sent as `X-CSRF-Token`. No token is stored
  in `localStorage`.
- CORS still reflects only the configured origin with credentials; it is not
  wildcard.

Deployment configurations exercised:

| Configuration | Result |
|---|---|
| `http://localhost:18081` (custom port, same-origin) | accepted by the CSRF matrix and the browser suite |
| `http://127.0.0.1:PORT` (loopback host) | accepted (browser suite uses this host) |
| `https://host` direct TLS | accepted by the CSRF matrix (`r.TLS` present); the app itself has no TLS listener — TLS is a proxy/server-front concern |
| `https://host` behind a proxy | accepted with `X-Forwarded-Proto: https` (CSRF matrix) |
| foreign origin / wrong scheme / wrong port | rejected |
| `WORKBENCH_ORIGIN` allowlist | still honoured for explicit development |

## 5. Reproducible browser acceptance

Location: `tests/browser/`. The suite starts its own disposable Go server and
seeds a disposable SQLite database inside an authorized temp directory, drives
the real v3 UI with system Chrome through `playwright-core`, and tears everything
down.

Command (Linux/macOS/Windows PowerShell):

```bash
cd tests/browser
npm ci        # or: npm install (first time / after changing dependencies)
npm test
```

Requirements: Go toolchain with CGO + MinGW/gcc on Windows, Node 20+, and
Chrome/Chromium (`CHROME_PATH` overrides detection). CI can run the same two
commands; no external service is contacted.

Coverage:

| Behaviour | Assertion |
|---|---|
| Alpha cannot access Beta data | client selector is exactly `[client-alpha]`, no Beta plan text; Beta user sees only Beta |
| role-based controls | writer sees no review button and gets 403; reviewer cannot create |
| Sigma/YAML safe rendering | markup in a rule title/description/YAML renders as text; zero `script`/`img` elements inside the layout |
| generated AQL display | `domainid=5`, `LAST 7 DAYS`, copy button, `NOT EXECUTED` |
| DRAFT → IN_REVIEW → APPROVED | attach, submit, reviewer approve; status polled from the API |
| unauthorized review | `POST /review` returns 403 and no approve control is rendered |
| stale approval | 409 conflict surfaced, plan stays `IN_REVIEW` |
| version history / immutability | v1 stays `APPROVED`, v2 is `DRAFT` and supersedes v1; no edit control |
| no execution/deployment | no such button; no `VALIDATED_BY_QRADAR` text |
| refresh and deep links | plan and draft deep links survive a reload with the right tab and context |

Screenshots: `frontend/v3/shots/2b4b-h1-plans.png`, `2b4b-h2-translation.png`,
`2b4b-h3-approved.png`, `2b4b-h4-stale-409.png`, `2b4b-h5-version.png`.

## 6. Deployment limitations

- The bundled database is SQLite with a single connection; this is a
  single-node deployment, not a horizontally scaled service.
- TLS is expected to terminate at the server (`WORKBENCH_SECURE=true` sets
  `Secure` cookies) or at a proxy that sends `X-Forwarded-Proto`. Proxy headers
  are trusted; deploy behind a proxy that overwrites them. The application has no
  TLS listener, so HTTPS was validated through the CSRF matrix (TLS state and
  proxy headers), not through a live TLS socket.
- The Python Sigma worker remains a bounded subprocess, not a sandbox
  (`network_sandbox=false`, `filesystem_sandbox=false`), and the `regex`
  dependency divergence is unchanged.
- `NOT`, `cased` and aggregation conversions remain unsupported upstream.
- There is no QRadar runtime validation and no AQL execution in any phase.
- The acceptance suite requires a desktop Chrome/Chromium; a headless-only CI
  image needs `CHROME_PATH` or a Playwright browser install.

## 7. Verification

| Command | Exit |
|---|---|
| `go build ./...` | 0 |
| `go vet ./...` | 0 |
| `go test -timeout 900s -count=1 ./...` | 0 — `ok mssp-workbench 466.2s` |
| `go test -race -run 'TestHuntPlan\|TestPreflight\|TestSecurity\|TestHardening\|TestAQL\|TestValidateAcceptanceDBPath\|TestSeedHuntAcceptance\|TestCSRF\|TestListAvailableHypotheses'` | 0 — `ok mssp-workbench 424.1s`, no data race |
| `node --check frontend/v3/v3.js` | 0 |
| `node --check frontend/v3/hunt-workspace.js` | 0 |
| `node --check frontend/api.js` | 0 |
| `npm test` in `tests/browser` | 0 — 9/9 tests passed, 52.7s |

## 8. GO / NO-GO

**GO for release hardening.** The destructive seeding path is gone, API origins
are same-origin, plan versions come from the server, async races are guarded,
and the security behaviours are covered by an executable browser suite.

**Excluded:** no QRadar API, no AQL execution, no rule deployment, no new CTI
connector, no Octop, no production migration. `storage/workbench.db` was not
opened or modified.
