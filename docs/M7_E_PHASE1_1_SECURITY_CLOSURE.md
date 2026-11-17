# M7-E Phase 1.1 — Trusted Proxy, Audit Reliability & Pilot Boundary Closure

Scope: close deployment trust-boundary gaps found after M7-E Phase 1. No product
functionality was added; M7-D behaviour, the frontend, browser acceptance, RBAC
and the domain-binding model are unchanged.

CodeGraph was used to map `AuditLogger`, `AuditMiddleware`, `auditInTx`, the CSRF
validator and `OpenDB` before editing. Worker sandboxing, QRadar execution, rule
deployment and production migrations remain out of scope.

## 1. Findings

| # | Finding | Where | Severity |
|---|---|---|---|
| F1 | A trusted peer made **any** right-most XFF element authoritative: with `hops` unmodelled, `X-Forwarded-For: <spoofed>, <real>` resolved differently per proxy behaviour, and the left-most value could reach rate limiting and audit | `backend/proxy_trust.go` (`requestClientIP`), `backend/main.go` login limiter, `backend/audit.go` middleware | High (attribution spoofing / audit poisoning) |
| F2 | `X-Forwarded-Proto: http,https` silently took the first value | `backend/proxy_trust.go` (`forwardedTarget`) | Medium (scheme confusion for CSRF/cookies) |
| F3 | `X-Real-IP` was accepted without validation and could disagree with XFF | `backend/proxy_trust.go` | Medium |
| F4 | HTTP access-log write failures were discarded: `AuditMiddleware` ignored `AuditLogger.Log`'s error | `backend/audit.go` (`Wrap`) | Medium (silent observability loss) |
| F5 | The listener bound `":" + port` (all interfaces) by default | `backend/main.go` (`ListenAndServe`) | Medium for a pilot host |
| F6 | The browser runner inherited `SENTINEL_ENABLE_TEST_SEEDERS`/`WORKBENCH_SEED_DATA` into the **server** process when exported by the shell | `tests/browser/acceptance.test.mjs` | Low (defence in depth) |
| F7 | Backup had no canonical path resolution, no atomic publish, and a check-then-write race; an interrupted `VACUUM INTO` could leave a partial file under the final name | `backend/sqlite_backup.go` | Medium |

Confirmed as already correct: security-critical decisions (review, approval,
binding, mapping, import publish) write their audit row with `auditInTx` inside
the decision transaction and roll back on failure; `AuditLogger.Log` returned an
error (only the middleware ignored it); migrations are transactional; the
acceptance seeder already refused existing paths.

## 2. Fixes

**F1 — forwarded chain policy** (`backend/proxy_trust.go`). The allowlist now
only says *which peers may speak*. `WORKBENCH_TRUSTED_PROXY_HOPS` (default 1,
1–16) says how many proxies are in the trusted chain. The client is
`XFF[len-hops]`; every entry to its right must be inside the trusted ranges; a
short chain, a client address inside the trusted ranges, a malformed entry, or a
conflicting `X-Real-IP` is rejected with `400 INVALID_PROXY_HEADER`. Entries to
the left of the trusted chain are ignored. A trusted peer with no identity
headers falls back to the TCP peer (and is not treated as a client address).
CSRF scheme/host, `Secure` cookies, audit `SourceIP` and rate limiting all read
the same validated `proxyInfo` context.

**F2/F3** — conflicting proto values are rejected (repeated identical values are
accepted); `X-Real-IP` must be a bare IP and must agree with the chain.

**F4 — audit reliability** (`backend/audit.go`). `AuditLogger.Log` now increments
`auditWriteFailures` and emits a sanitized `slog` line (`correlation_id`, bounded
`result`, bounded error) on every failure before returning the error. A caller
can no longer lose a failure silently, even if it ignores the return value.
Classification is explicit: access logs are **best effort** (the response is
already written; failure degrades observability only), while security decisions
use `auditInTx` and **roll back** on audit failure.

**F5 — listener boundary** (`backend/listen.go`, `backend/config.go`). New
`WORKBENCH_LISTEN_ADDR`, default `127.0.0.1`, must be an IP (IPv4 or IPv6); the
address is `net.JoinHostPort(addr, WORKBENCH_PORT)`. A hostname or CIDR is a
startup error. This is deliberate binding, not network isolation.

**F6 — seeder scoping** (`tests/browser/acceptance.test.mjs`). The seeding
subprocess gets `SENTINEL_ENABLE_TEST_SEEDERS=1` and `SENTINEL_ACCEPTANCE_DIR`;
the server subprocess explicitly deletes those plus `WORKBENCH_SEED_DATA` from
its inherited environment. Normal startup never seeds.

**F7 — backup** (`backend/sqlite_backup.go`). Source and destination directory
are canonicalized with `EvalSymlinks`; the source must be a regular file. The
snapshot is written to a temporary name in the destination directory, verified,
then published (Phase 1.2 replaces the O_EXCL copy with an atomic hard-link
publication; see `M7_E_PHASE1_2_BACKUP_CORRECTNESS.md`), and the temporary file
is removed on success or failure. Concurrent backups to distinct files succeed;
concurrent backups to the same file produce exactly one winner; a crash can leave
a `.tmp-*` file but never a partial backup under the final name.

## 3. Regression tests

| Requirement | Test |
|---|---|
| Direct request with spoofed headers | `TestProxyTrustAndCSRF/untrusted_client_cannot_spoof_forwarded_headers` |
| Trusted proxy overwrites XFF | `TestForwardedChainPolicy/proxy_overwrites_XFF` |
| Trusted proxy appends to spoofed XFF | `TestForwardedChainPolicy/proxy_appends_to_a_spoofed_XFF` |
| Multi-hop trusted/untrusted combination | `two_trusted_hops`, `two_hops_with_an_untrusted_intermediate`, `fewer_entries_than_hops` |
| IPv4 and IPv6 | `IPv4_and_IPv6` (including bracketed peer and `::1` hop) |
| Malformed / ambiguous values | `malformed_values`, `client_inside_the_proxy_ranges`, `X-Real-IP` subtests |
| Conflicting proto | `TestForwardedProtoConflicts` |
| Trusted proxy configuration validation | `TestTrustedProxyConfig` |
| Rate-limit attribution | `TestRateLimitAttributionUsesValidatedChain` |
| Access-log failure observable and recoverable | `TestAuditAccessLogFailureIsObservableAndRecoverable` |
| Audit database unavailable | `TestAuditUnavailableDatabaseReturnsError` |
| Access-log failure does not fail the request | `TestAccessLogFailureDoesNotFailTheRequest` |
| Security decision rolls back on audit failure | `TestMappingApprovalRollsBackWhenAuditFails`, `TestSecurity_AuditFailureRollsBackDecision` |
| Listener address selection (no production interface) | `TestListenAddress` |
| Backup canonicalization and existing refusal | `TestBackupRefusesExistingAndKeepsCanonicalPaths` |
| Concurrent backups and same-destination winner | `TestBackupConcurrentInvocations` |
| Interrupted/failed backup leaves nothing published | `TestBackupFailureLeavesNoPublishedFile` |
| Point-in-time snapshot and restore | `TestBackupRestoreIntegrity` |
| Migration rollback / idempotent migrate | `TestMigrationFailureRollsBack`, `TestMigrateCommandIsIdempotentAndSetsSafetyPragmas` |
| Seeder opt-in | `TestTestSeederRequiresExplicitOptIn`, `TestSeedHuntAcceptanceRefusesWithoutAuthorization` |
| Browser acceptance with scoped seeding | `tests/browser` (9 tests) |

## 4. Residual risks

1. **Chain correctness depends on configuration.** `WORKBENCH_TRUSTED_PROXY_HOPS`
   must equal the number of proxies you operate. Too low selects a value the
   immediate proxy appended only if it overwrites (safe); too high is rejected by
   the short-chain check. A proxy that neither overwrites nor appends (passes a
   client-supplied XFF unchanged while adding nothing) is unsafe and cannot be
   detected by this server. The proxy must append the peer address.
2. **Trusted proxies are still trusted.** A compromised proxy can inject any
   client identity. The allowlist, per-request validation and intra-range checks
   bound the damage but cannot verify a proxy's honesty.
3. **Access logs are best effort.** A SQLite outage loses HTTP access rows.
   Security decisions remain transactional; those fail closed.
4. **Listen address is not network isolation.** The host firewall and proxy
   controls are required; the app has no TLS listener.
5. **Backup publication** relies on `O_EXCL` support in the destination
   filesystem. Windows NTFS and POSIX filesystems provide it; exotic mounts may
   not.
6. Worker sandbox, dependency divergence, no QRadar runtime validation and the
   single-node SQLite design remain as documented in the M7-E gate.

## 5. Pilot deployment checklist (updated)

| Area | Check |
|---|---|
| Binding | `WORKBENCH_LISTEN_ADDR=127.0.0.1` with a same-host proxy, or the specific internal IP; never `0.0.0.0` on an untrusted network |
| Proxy | `WORKBENCH_TRUSTED_PROXIES` lists only proxy addresses/CIDRs; `WORKBENCH_TRUSTED_PROXY_HOPS` matches the real proxy count; the proxy **overwrites or appends** forwarded headers and strips client-supplied ones |
| TLS | Terminated at the proxy; `X-Forwarded-Proto: https`; cookies observed as `Secure`; HTTP redirected |
| Firewall | Only the proxy may reach the listen port; no direct client access |
| Auth | No synthetic accounts; strong unique passwords; role/grant review; session lifetime accepted |
| Tenancy | Grants reviewed; cross-tenant access re-tested after changes |
| Migrations | `workbench migrate <db>` recorded before first start; server refuses an incomplete schema |
| Backup | Daily verified backup off-host (`workbench backup-sqlite`); restore rehearsed; retention agreed |
| Logging | Access logs monitored for `audit write failed`; security decisions appear in `audit_log` |
| Monitoring | `/api/v1/health`, disk, SQLite-file growth, 403/409 rates, failed logins |
| Incident | Isolate, preserve DB+logs, rotate `MCP_CREDENTIAL`, invalidate sessions, restore a verified backup |

## 6. Verification

| Command | Exit |
|---|---|
| `go build ./...` | 0 |
| `go vet ./...` | 0 |
| `go test -timeout 900s -count=1 ./...` | 0 — `ok mssp-workbench 455.6s` |
| `go test -race -run 'TestForwarded\|TestTrustedProxy\|TestRateLimitAttribution\|TestProxyTrust\|TestAudit\|TestAccessLog\|TestMappingApprovalRollsBack\|TestListenAddress\|TestBackup\|TestMigration\|TestSessionExpiry\|TestHuntPlan\|TestSecurity\|TestHardening\|TestAQL'` | 0 — `ok mssp-workbench 459.7s`, no data race |
| `node --check frontend/v3/v3.js`, `hunt-workspace.js`, `api.js`, `tests/browser/acceptance.test.mjs` | 0 |
| `npm test` in `tests/browser` | 0 — 9/9, 36.2s |

During verification the first full-suite run failed on the two MCP stdio tests
(`TestMCPSubprocessIntegration`, `TestMCPProtocolCompliance`): the listen-address
validation ran before the `mcp-stdio` branch and those tests launch with
`WORKBENCH_PORT=0`. The validation now runs in HTTP mode only; the MCP tests
passed afterwards and the table above is the clean re-run.

## 7. GO / NO-GO

**GO for the isolated pilot** with the checklist above: loopback binding behind a
trusted proxy, explicit hop count, verified backups, transactional decision
audit, and best-effort access logs with observable failures.

**NO-GO** for direct internet exposure, a proxy that does not append the peer
address, enabling worker network access, QRadar execution/deployment, production
tenant data, or multi-node deployment.

**Excluded as required:** QRadar API, AQL execution, rule deployment, worker
sandbox implementation, Octop/AI orchestration, production migrations and
`storage/workbench.db` access.
