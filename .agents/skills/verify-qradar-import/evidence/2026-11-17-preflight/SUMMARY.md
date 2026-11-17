# Preflight evidence — 2026-11-17 (superseded)

This record is integrity-only and was written before the validator existed. The validator scenarios below are no longer NOT VERIFIED; see `../2026-11-17-validator-run/SUMMARY.md` for the executed run and current verdicts.

Operator: QA / Verification Engineer (MSSP Intelligence Workbench).
Scope: staged-file integrity and environment discovery only. This is NOT a validator run.

## Environment

- Host OS: Windows (PowerShell 5.1); Git for Windows provides GNU coreutils 8.32 and Bash.
- Go: `go1.22.5 windows/amd64`; `go env GOOS GOARCH CGO_ENABLED CC` = windows / amd64 / 0 / gcc.
- Working revision during preflight: `9d775c5349bdd7b6aa0f0dca2ad48f8cc702e123`. Another bot switched the shared checkout to `docs/field-intelligence-design` mid-task; the verification branch is based on `ce17fa03bc0907a3c5fa5539d4d3ba24e4e2377f`. Both are recorded, not reconciled by editing evidence.

## Executed commands and fresh exit codes

| Artifact prefix | Command | Exit code | Result |
|---|---|---|---|
| `01-revision` | `git -C <repo> rev-parse HEAD` | 0 | `9d775c5...` |
| `02-remote-branches` | `git -C <repo> ls-remote --heads origin` | 0 | No `feat/validate-qradar-import` ref; `docs/field-intelligence-design` appeared during the run |
| `03-checksums` | `sha256sum.exe -c SHA256SUMS.txt` (literal, Windows) | 1 | All five entries "FAILED open or read" — CRLF in checksum file |
| `03b-checksums-crlf-fixed` | PowerShell `ReadAllLines \| tr.exe -d '\r' \| sha256sum.exe -c -` | 1 | PowerShell re-added CRLF on the pipeline; same failure |
| `03c-checksums-bash` | Bash: `tr -d '\r' < SHA256SUMS.txt \| sha256sum -c -` | 0 | All five data files `OK`; one harmless warning for the `# SHA256SUMS` header line |
| `04-go` | `go version` | 0 | `go1.22.5 windows/amd64` |

Raw stdout and stderr are stored beside each exit code. `command.txt` lists the exact invocations.

## Verdicts

- Staged-file integrity: REAL PASS for the corrected Bash checksum command at `03c` (exit 0, five files OK).
- Validator scenario 1 (reject staged metadata mismatches): NOT VERIFIED.
- Validator scenario 2 (accept consistent fixture): NOT VERIFIED.
- Validator scenario 3 (resolve BB refs): NOT VERIFIED.

No validator stdout, stderr, exit code or report is recorded because no validator script exists at the baseline revision. Nothing was fabricated to fill the gap. `feat/validate-qradar-import` must provide the exact command before these rows can be driven.
