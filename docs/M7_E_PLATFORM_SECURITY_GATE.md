# M7-E Phase 1 — Platform Security & Read-only Pilot Gate

Scope: prepare an isolated pilot. No QRadar API integration, no AQL execution,
no rule deployment, no incident response, no new CTI connectors, no Octop, no
production database access.

CodeGraph was used to map `applyMiddleware`, `OpenDB`, session cookies and the
CSRF validator before changing them.

## 1. Threat model

| Asset | Threat | Boundary |
|---|---|---|
| Client telemetry metadata, mappings, Sigma rules, AQL drafts, hunt plans | Cross-tenant read or write | Session → role → client grant, enforced server-side |
| Analyst review decisions | Self-approval, decision on stale evidence | Reviewer role + transactional evidence revalidation |
| Session and CSRF cookies | Theft, fixation, CSRF | HttpOnly/SameSite cookies, double-submit token, Origin check |
| Platform configuration and database | Unauthorized operator action, destructive test commands, spoofed audit source | Explicit env opt-ins, trusted-proxy allowlist, audit records |
| Host and data at rest | Compromise of the pilot host | Deployment controls (TLS proxy, firewall, OS permissions) — outside the app |
| Sigma worker | Malicious rule causing code execution or exfiltration | Bounded subprocess today; **no OS sandbox** (documented blocker) |

Trust boundaries: browser → reverse proxy → Go server; server → SQLite;
server → Python worker; operator → CLI. Forwarded HTTP headers cross a trust
boundary and are treated as untrusted data unless the TCP peer is configured.

## 2. Confirmed vulnerabilities and fixes

| # | Vulnerability | Severity | Fix |
|---|---|---|---|
| P0-1 | `sameOriginRequest` honoured `X-Forwarded-Proto`/`Host` from **any** client, so a request carrying a spoofed proto/host could shape the CSRF same-origin decision | High | Forwarded headers are accepted only from `WORKBENCH_TRUSTED_PROXIES` IPs/CIDRs; untrusted peers get `403 UNTRUSTED_PROXY_HEADER`; malformed values get `400`; CSRF reads validated request state only |
| P0-2 | Audit `SourceIP` and the login rate limiter read `X-Forwarded-For` unconditionally | High | Both now use `requestClientIP`, which honours forwarded addresses only through a trusted proxy |
| P0-3 | Cookies were `Secure` only for port 443 or `WORKBENCH_SECURE=true`, so TLS behind a proxy produced insecure cookies | Medium | `secureRequest` marks cookies `Secure` when the request arrived over TLS directly or through a trusted https proxy |
| P1-1 | Synthetic users could be seeded by `WORKBENCH_SEED_DATA=true`, and the seeder commands had no explicit opt-in | High (if misused in production) | `OpenDB` refuses to seed unless `SENTINEL_ENABLE_TEST_SEEDERS=1` is also set; both seeder commands require it and fail closed |
| P1-2 | `Config.SecretKey` carried an unused `dev-secret-change-in-production` default | Low | Removed; nothing referenced it, sessions use random 256-bit IDs stored server-side |
| P1-3 | `MCP_CREDENTIAL` was compared with `!=` | Low | Constant-time comparison |
| P2-1 | The server applied only migrations 0001–0002 at startup; features expected later schemas and returned 503 on a fresh deployment | High (pilot readiness) | Explicit `workbench migrate <db>` applies 0001–0021; the server fails fast with instructions when the schema is incomplete. No runtime auto-migration |
| P2-2 | The server open path did not set SQLite WAL, contrary to the project convention | Medium | `_journal_mode=WAL` on the server and seeder DSNs; test verifies `journal_mode=wal` and `foreign_keys=1` |
| P2-3 | No supported backup procedure | Medium | `workbench backup-sqlite <src> <new-file>` uses `VACUUM INTO`, verifies the copy with `PRAGMA integrity_check`, refuses an existing destination, and is covered by a snapshot/restore test |

Preserved: CSRF token validation (double-submit + Origin), RBAC, tenant grants,
transactional approval revalidation, immutable drafts and plans.

## 3. Security test matrix

| Requirement | Test |
|---|---|
| Direct backend access, same-origin custom port | `TestProxyTrustAndCSRF/direct_backend_same-origin` |
| Trusted proxy with HTTPS termination | `TestProxyTrustAndCSRF/trusted_proxy_HTTPS_termination` |
| Untrusted client spoofing forwarded headers | `TestProxyTrustAndCSRF/untrusted_client_cannot_spoof_forwarded_headers` |
| Malformed forwarded proto / host list / host with path | same test, three subtests |
| Wrong origin, wrong scheme, wrong port | same test |
| Explicit cross-origin allowlist | same test |
| Trusted-proxy configuration rejects bad IPs/CIDRs | `TestParseTrustedProxiesRejectsBadInput` |
| Session expiry (cache and database paths) | `TestSessionExpiryRejected` |
| Expired session at the HTTP boundary | `TestExpiredSessionHTTP401` |
| Failed migration leaves no partial schema or version row | `TestMigrationFailureRollsBack` |
| Migration command idempotent, WAL + foreign keys + core tables | `TestMigrateCommandIsIdempotentAndSetsSafetyPragmas` |
| Backup is a verified point-in-time snapshot; no overwrite | `TestBackupRestoreIntegrity` |
| Synthetic seeding requires explicit opt-in | `TestTestSeederRequiresExplicitOptIn`, `TestSeedHuntAcceptanceRefusesWithoutAuthorization` |
| Acceptance DB path safety (existing/symlink/forbidden) | `TestValidateAcceptanceDBPath`, `TestSeedHuntAcceptancePreservesExistingFile` |
| Cross-tenant access denied | `TestHuntPlan_RoleAndTenantEnforcement`, `TestHuntPlan_HTTPRBACAndTenant` |
| Service-level RBAC | `TestHuntPlan_RoleAndTenantEnforcement`, `TestSecurity_ReviewRoleChangedBeforeDecision` |
| Immutable approval history | `TestHuntPlan_LifecycleApproveAndImmutable`, `TestSecurity_AuditFailureRollsBackDecision` |
| Worker isolation claims stay honest | `TestHardening_IsolationIsReportedHonestly` |
| Browser acceptance (all previous checks) | `tests/browser` — 9 tests |

## 4. Configuration and secrets inventory

| Variable | Purpose | Secret | Notes |
|---|---|---|---|
| `WORKBENCH_DB_PATH` | SQLite file | No | Defaults to `../storage/workbench.db` |
| `WORKBENCH_PORT` | listen port | No | Default 8080 |
| `WORKBENCH_ORIGIN` | explicit cross-origin allowlist | No | Same-origin works without it |
| `WORKBENCH_SECURE` | force `Secure` cookies | No | Also inferred from trusted proxy scheme |
| `WORKBENCH_TRUSTED_PROXIES` | proxy IP/CIDR allowlist | No | Empty means forwarded headers are rejected |
| `WORKBENCH_SEED_DATA` | legacy seed switch | No | Requires `SENTINEL_ENABLE_TEST_SEEDERS=1` |
| `SENTINEL_ENABLE_TEST_SEEDERS` | opt-in for synthetic fixtures | No | Test/pilot-host only |
| `SENTINEL_ACCEPTANCE_DIR` | authorized temp dir for the acceptance DB | No | Must be inside the OS temp root |
| `MCP_CREDENTIAL` | MCP stdio shared credential | **Yes** | Env only, constant-time compare, never logged |
| `SIGMA_WORKER_PYTHON`, `SIGMA_WORKER_SCRIPT`, `SIGMA_WORKER_SCRIPT_SHA256`, `SIGMA_WORKER_TIMEOUT_MS` | worker selection and limits | No | Script hash optional but recommended |
| `WB_TEST_PASS_*` | seeder passwords | **Yes** | Used only by test/seed helpers |

Findings:
- No secret is written to logs. Login logging records user id and role only.
- No credential is placed in a URL. The API takes identifiers in paths/queries,
  never tokens.
- Passwords are PBKDF2-HMAC-SHA256 (100k iterations) with per-user salt.
- Sessions are random 256-bit identifiers stored in SQLite, 8-hour absolute
  expiry, HttpOnly, SameSite=Lax, `Secure` on TLS (direct or trusted proxy).
- The in-memory session cache re-checks expiry and revocation on every read.
- Config files contain no API keys; model provider entries have empty endpoints.
- File permissions are the deployment's responsibility: run under a dedicated
  OS account and keep the database file and backups readable only by that
  account (e.g. `0600`/`0700` on POSIX).

## 5. SQLite operational safety

- One connection (`MaxOpenConns(1)`) serializes access and avoids lock storms.
- WAL and foreign keys are set on every connection; busy timeout is 30 s.
- Every migration file runs in a single transaction with its
  `schema_migrations` row; a failure rolls back both (tested).
- Audit rows are written in the same transaction as the change they describe.
- `workbench migrate <db>` is the only supported schema path; the server does
  not migrate and refuses to start on an incomplete schema.

### Backup (online, verified)

```bash
workbench backup-sqlite /srv/atlas/workbench.db /backup/atlas-20261111T1200.db
```

`VACUUM INTO` produces a consistent snapshot while the server runs; the command
verifies the copy (`integrity_check`, table count, migration history) and refuses
to overwrite an existing file. Keep backups on a different volume with the same
OS permissions as the database.

### Restore (offline)

1. Stop the server.
2. Move `workbench.db`, `workbench.db-wal`, `workbench.db-shm` aside — never
   delete them before the restore is verified.
3. Copy the chosen backup to the database path.
4. Verify it before start (`sqlite3 <file> 'PRAGMA integrity_check'` or the
   backup command against a copy) and check ownership/permissions.
5. Start the server and verify `/api/v1/health`, one login and one read.
6. Keep the moved files until the restored instance is accepted.

Verified on disposable data by `TestBackupRestoreIntegrity`.

## 6. Worker security (unchanged facts, future architecture)

Verified in code and tests: the Python worker runs as a bounded subprocess with
`-I -B`, a fixed working directory, a minimal environment, a hard timeout, capped
output, best-effort tree kill and optional script SHA-256 pinning.
**`network_sandbox=false` and `filesystem_sandbox=false`.** `NOT`, `cased` and
aggregation conversions remain UNSUPPORTED upstream; the `regex` dependency
divergence remains.

Proposed isolation for a later phase (not implemented, not claimed):
dedicated low-privilege OS account, OS sandbox (Windows AppContainer/Job object
limits or Linux user+mount+network namespaces with seccomp), no network
namespace or a deny-all egress policy, read-only root with a single input/output
pipe, CPU/memory/wall-clock quotas, reproducible pinned dependencies inside a
container image, and a signed worker hash enforced at every call.

## 7. Pilot deployment checklist

| Area | Check |
|---|---|
| Host | Dedicated host/VM; no other services; full-disk encryption; patched OS |
| Network | Host firewall allows only the proxy → app port and operator → proxy; no inbound from the internet |
| Proxy | Explicit trusted proxy configured in `WORKBENCH_TRUSTED_PROXIES`; proxy overwrites `X-Forwarded-Proto`/`Host`; forwarded headers reach the app only from that peer |
| TLS | Terminated at the proxy with a valid certificate; HTTP redirected to HTTPS; app cookies observed as `Secure` |
| App | Dedicated OS user; database directory `0700`, DB and backups `0600`; `WORKBENCH_SECURE=true` behind TLS |
| Auth | Demo/synthetic accounts absent; unique strong passwords; role assignment reviewed; 8-hour sessions accepted or shortened |
| Tenancy | Each pilot user has only the grants they need; cross-tenant access tested after any grant change |
| Migrations | `workbench migrate <db>` run and recorded before first start; server refuses to start otherwise |
| Backup | Daily verified backup off-host; restore rehearsed; retention agreed |
| Logging | Audit written to the DB; log retention and access defined; no secrets in logs |
| Monitoring | `/api/v1/health` probed; disk, process and SQLite file size watched; failed logins and 403/409 rates alerted |
| Incident | Host compromise: isolate, preserve DB+logs, rotate `MCP_CREDENTIAL`, invalidate sessions, restore verified backup, post-incident review |

## 8. Blockers (pilot constraints)

1. The Sigma worker has no OS-level network or filesystem sandbox.
2. `regex` is outside the IBM backend's declared range; `NOT`/`cased`/
   aggregation are unsupported upstream.
3. There is no QRadar runtime validation and no AQL execution — drafts are
   reviewed, never executed.
4. The application has no TLS listener; TLS is a proxy responsibility.
5. Single-node SQLite deployment; no HA or horizontal scaling.
6. No external secret manager; secrets are environment variables.
7. MCP stdio (if enabled) shares one `MCP_CREDENTIAL`; keep it disabled in the
   pilot unless required, and protect the variable.
8. Legacy `hunt_plans` table (migration 0010) remains unused and should be
   retired in a later migration.

## 9. Verification

| Command | Exit |
|---|---|
| `go build ./...` | 0 |
| `go vet ./...` | 0 |
| `go test -timeout 900s -count=1 ./...` | 0 — `ok mssp-workbench 583.2s` |
| `go test -race -run 'TestProxyTrust\|TestParseTrustedProxies\|TestSessionExpiry\|TestExpiredSession\|TestMigrationFailure\|TestMigrateCommand\|TestBackupRestore\|TestTestSeeder\|TestValidateAcceptanceDBPath\|TestSeedHuntAcceptance\|TestHuntPlan\|TestSecurity\|TestHardening\|TestAQL'` | 0 — `ok mssp-workbench 457.2s`, no data race |
| `node --check frontend/v3/v3.js`, `hunt-workspace.js`, `api.js` | 0 / 0 / 0 |
| `npm test` in `tests/browser` | 0 — 9/9, 41.9s |

A first full-suite run failed on `TestMCPSubprocessIntegration` and
`TestMCPProtocolCompliance` because the new schema fail-fast also ran in MCP
stdio mode, whose database has no M7-D tables. The check was moved to HTTP mode
only; both MCP tests then passed and the full suite above is the clean re-run.

## 10. Pilot GO / NO-GO

**GO for an isolated, read-only pilot** on a dedicated host behind a trusted
proxy, with synthetic clients, no QRadar execution and no rule deployment. The
proxy trust boundary, session handling, schema/migration path, backup/restore and
tenant isolation are implemented and tested.

**NO-GO for any pilot that enables QRadar execution, worker network access,
production tenant data, or multi-node deployment.** The worker sandbox,
dependency divergence and absence of runtime QRadar validation remain open.

**Excluded as required:** no QRadar API, no AQL execution, no deployment, no
new connector, no Octop, no production database access. `storage/workbench.db`
was not opened or modified.
