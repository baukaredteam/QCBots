# M7-E Phase 1.2 — SQLite Backup Atomic Publication & Crash Safety

Scope: correct the mismatch between the claimed atomic backup publication and the
actual implementation. No QRadar, AQL, deployment, UI or migration changes.
Disposable databases only; `storage/workbench.db` was not opened.

CodeGraph was used to locate `backupSQLite`, `copyFileExclusive` and the proxy
chain code before editing.

## 1. Confirmed defect

The previous publication path did this:

1. `VACUUM INTO` a private temporary snapshot;
2. `verifySQLiteFile` the snapshot;
3. create the **final** path with `O_CREATE|O_EXCL`;
4. `io.Copy` the bytes into that final file.

`O_EXCL` prevents overwriting, but it does not make the name appear atomically.
A reader could open the final name while it was still being copied (a partial
SQLite file), and a process killed during the copy left a truncated backup under
the final name. The M7-E Phase 1.1 text described O_EXCL publication without
distinguishing "exclusive" from "atomic"; this phase fixes the mechanism and
states the guarantees precisely.

## 2. Publication mechanism (current)

```
VACUUM INTO <.dst>.tmp-<pid>-<nanos>      # complete snapshot, private name
fsync(temp file)                          # flush data before the name appears
[test seam] verifySQLiteFile(temp)        # integrity_check + schema + migrations
SHA-256(temp)                             # hash of the verified bytes
link(temp, dst)                           # atomic, no-replace publication
SHA-256(dst) == SHA-256(temp)             # verify published content
fsync(destination directory)              # POSIX only; persists the link
unlink(temp)                              # cleanup of this invocation's file
```

- The final name does not exist until the complete, verified snapshot is ready.
- `link(2)` / `CreateHardLinkW` creates the directory entry atomically and fails
  if the destination exists. There is no copy window under the final name.
- The temporary file is unique per invocation (`pid` + nanoseconds) and is the
  only file cleanup ever removes. The destination is never removed, truncated or
  overwritten — not even by the failure paths.
- If the final hash differs from the staged hash, the just-published file is
  removed and the command fails (the file was created by this invocation).
- Two concurrent commands targeting the same name: exactly one `link` succeeds;
  the loser reports a refusal and removes only its own temporary file.
- Two concurrent commands targeting different names both succeed.

## 3. Platform guarantees

| Platform / filesystem | Atomic name creation | No overwrite | Data flush | Directory flush |
|---|---|---|---|---|
| Windows NTFS / ReFS | Yes (`CreateHardLinkW` is atomic) | Yes (fails if the name exists) | `FlushFileBuffers` via `File.Sync` on the staged file | Not portably available; not claimed |
| POSIX ext4/xfs/btrfs/tmpfs | Yes (`link(2)`) | Yes (`EEXIST`) | `fsync` on the staged file | `fsync` on the directory after the link |
| FAT/exFAT, some SMB/NFS mounts | Hard links unsupported | n/a | n/a | n/a |

On filesystems without hard-link support the command **fails closed** with
"atomic no-replace publication requires hard-link support". It never falls back
to a visible copy, so the atomicity contract is never silently weakened.

## 4. Crash and power-loss semantics

**Process crash / kill (no power loss).**
- Before `link`: the destination does not exist. A `.tmp-*` file may remain; it
  is never renamed into place and is never mistaken for a backup.
- During `link`: the operation is atomic; the destination either does not exist
  or is the complete staged inode.
- After `link`, before `unlink`: the destination is complete; a duplicate
  temporary link may remain.
- A reader can therefore observe only "absent" or "complete".

**Power loss.**
- The staged file is flushed before publication, and on POSIX the directory is
  flushed after, which is the strongest ordering the portable API offers.
- This does **not** prove power-loss durability: drive caches, filesystem
  journaling modes and virtualized storage can still lose or reorder writes, and
  a link may vanish (destination absent) or, on lying hardware, content may be
  stale. No power-loss atomicity is claimed.
- Consequence: after a power loss, re-verify the newest backup before relying on
  it (`workbench backup-sqlite` verifies its source; `PRAGMA integrity_check`
  verifies a candidate). Keeping two successive backups is recommended.

**Interruption cleanup.** Temporary files are named `.backup.db.tmp-*` and are
left only by a crash. They are not removed by later runs, because automatic
cleanup could delete a concurrent invocation's file. Operators may remove
`.tmp-*` files when no backup is running; the final names are unaffected.

## 5. Secondary verification of the proxy chain (M7-E 1.1)

Reviewed `forwardedClientIP`, `forwardedTarget`, the middleware, the login
limiter and the audit middleware:

- Hop indexing is correct: with `hops=N`, the client is `XFF[len-N]`; entries to
  its right must be inside the trusted ranges. Overwrite (single entry), append
  (spoofed left side ignored) and two-hop cases are covered by tests.
- Ambiguous/missing XFF: short chains, malformed entries, an "client" inside the
  trusted ranges and conflicting `X-Real-IP` are rejected. A trusted proxy with
  no identity headers falls back to the TCP peer, which is the only address that
  can be attributed (and is not a client identity).
- Host and proto are validated independently; conflicting proto values are
  rejected.
- The login limiter and audit middleware both use `requestClientIP`, which reads
  only the validated context.

**One concrete defect fixed:** `X-Real-IP` without `X-Forwarded-For` was accepted
as the client address. A client can send that header, and a proxy is not
guaranteed to overwrite it, so the value was still client-controlled despite the
trusted peer. It now fails closed with "X-Real-IP without X-Forwarded-For is
ambiguous"; the test that expected acceptance was updated to expect rejection.
`X-Real-IP` is still accepted when it agrees with a valid XFF chain.

## 6. Regression tests

| # | Requirement | Test |
|---|---|---|
| 1 | Existing destination remains unchanged | `TestBackupRefusesExistingAndKeepsCanonicalPaths`, `TestBackupNeverReplacesADestinationThatAppearsLate` |
| 2 | Concurrent same-name publication has one winner | `TestBackupConcurrentInvocations` |
| 3 | Concurrent different names succeed | `TestBackupConcurrentInvocations` |
| 4 | A reader never sees a partial final file | `TestBackupReaderNeverSeesPartialDestination` (poll hashes during publication; every observed hash equals the final hash), `TestBackupStagesBeforePublishing` |
| 5 | Simulated copy/link failure leaves no destination | `TestBackupNeverReplacesADestinationThatAppearsLate` |
| 6 | Failed verification prevents publication | `TestBackupFailedVerificationPreventsPublication` |
| 7 | Crash/interruption behavior | Documented in §4; the failure-path tests prove no final file is published without verification. A process-kill test is not automated (stated, not claimed). |
| 8 | Final SHA-256 equals the verified staged snapshot | `TestBackupStagesBeforePublishing`, and the production check in `backupSQLite` |
| 9 | Source database untouched | `TestBackupLeavesSourceUntouchedAndRestorable` (file hash, row count, integrity) |
| 10 | Restore from the published backup succeeds | `TestBackupLeavesSourceUntouchedAndRestorable`, `TestBackupRestoreIntegrity` |

These are unit-level fault-injection tests. They prove ordering and failure
behavior; they are **not** proof of power-loss durability.

## 7. Verification

| Command | Exit |
|---|---|
| `go build ./...` | 0 |
| `go vet ./...` | 0 |
| `go test -timeout 900s -count=1 ./...` | 0 — `ok mssp-workbench 467.0s` |
| `go test -race -run 'TestBackup\|TestForwarded\|TestTrustedProxy\|TestRateLimitAttribution\|TestProxyTrust\|TestAudit\|TestAccessLog\|TestListenAddress\|TestMigration\|TestHuntPlan\|TestSecurity\|TestHardening\|TestAQL'` | 0 — `ok mssp-workbench 469.3s`, no data race |
| `node --check frontend/v3/hunt-workspace.js` | 0 |
| `npm test` in `tests/browser` | 0 — 9/9, 43.2s |

## 8. Remaining limitations

- Power-loss durability is not guaranteed; only the ordering above is.
- Hard links are required. FAT/exFAT and some network filesystems fail closed.
- A crash can leave `.tmp-*` files; they are harmless but must not be confused
  with backups.
- Directory fsync is POSIX-only; Windows relies on the filesystem journal for
  metadata ordering, which is not claimed as a data guarantee.
- Backup verification reads the whole file (`integrity_check` plus hashing); very
  large databases take proportional time and I/O.
- The proxy chain still trusts the configured proxies and their append behaviour;
  a proxy that passes client headers through unchanged cannot be detected.

## 9. GO / NO-GO

**GO** for the isolated pilot: backup publication is atomic with respect to
readers and no-replace under concurrency on the supported filesystems, the
published file is byte-verified against the staged snapshot, and failure paths
never leave a partial backup under the final name.

**NO-GO** for claiming power-loss atomicity, for filesystems without hard links,
or for a deployment where the proxy does not append/overwrite forwarded headers.

**Excluded as required:** QRadar API, AQL execution, rule deployment, worker
sandbox implementation, Octop/AI orchestration, production migrations and
`storage/workbench.db` access.
