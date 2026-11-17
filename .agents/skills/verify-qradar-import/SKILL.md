---
name: verify-qradar-import
description: "Project-local verification for the QRadar import validator of MSSP Intelligence Workbench / Sentinel Atlas. Drives the validator as a release engineer does against config/imports/2026-07-11: reject staged files with inconsistent metadata, accept a consistent fixture, resolve building-block references. Use when reviewing feat/validate-qradar-import or any import-validation change; verdicts follow docs/VERIFICATION_CONTRACT.md."
disable-model-invocation: true
---

# Verify QRadar import

Surface: a CLI / Go test binary operating on staged YAML and CSV files. There is no import-validator web UI. `config/imports/2026-07-11/field_intelligence_concept_v4.html` is a design preview only (PROVENANCE.md: "DESIGN REFERENCE ONLY") and must never be imported as telemetry, AQL verification, QRadar connectivity, or client data.

Baseline revision of this draft: `ce17fa03bc0907a3c5fa5539d4d3ba24e4e2377f`.

BLOCKED / NOT VERIFIED: at this revision `git ls-remote --heads origin` shows no `feat/validate-qradar-import` branch and the repo contains no validator script. No invocation is written here on purpose — do not guess one. Copy the exact command from Backend Dev's PR, then re-prove this skill and replace the preflight artifacts with real validator artifacts. Until then every Drive step is NOT VERIFIED.

## Interview (observed facts, not assumptions)

- Staged inputs live in `config/imports/2026-07-11/` (untracked at baseline; supplied by the product owner on 2026-11-17 per `PROVENANCE.md`): `full_rules85.yaml`, `shared_bbs.yaml`, `fields.yaml`, `qradar_rules_bb_sysmon.csv`, `field_intelligence_concept_v4.html`, `PROVENANCE.md`, `SHA256SUMS.txt`.
- `PROVENANCE.md` declares claims versus parsed results: `full_rules85.yaml` claims 346 rules / ~85 fully configured but only 14 rule records parse; `shared_bbs.yaml` claims 85 BBs but 67 parse; `fields.yaml` claims 42 fields but 54 records parse with 5 duplicated names; the CSV is an unverified raw export (1326 rows, cp1251, 18 columns).
- `fields.yaml` natural key is `(name, log_sources)`, not `name` (PROVENANCE.md lines 15–17). Duplicates: `proc_file_path` (3), `proc_usr_sid` (2), `event_description` (2), `task_name` (2).
- `full_rules85.yaml` header claims "FIXED: All BB references aligned with shared_bbs.yaml"; `shared_bbs.yaml` usage says references resolve by `bb_id` through `depends_on_bb`. The header is a claim, not evidence.
- Staged files are evidence only: they do not modify `config/rules_inventory.yaml` or `config/custom_fields_qradar.yaml` (PROVENANCE.md lines 4–5). QRadar is read-only in MVP (AGENTS.md principle 10).
- Toolchain observed on the baseline host: Go 1.22.5 windows/amd64; GNU coreutils `sha256sum` 8.32 at `C:\Program Files\Git\usr\bin\sha256sum.exe`; Git credential manager for HTTPS. Backend tests need a C compiler and `CGO_ENABLED=1` (docs/LOCAL_VERIFICATION.md).

## Launch

Preflight from the repository root — read-only, starts no process:

```
git rev-parse HEAD
git status --short
cd config/imports/2026-07-11
tr -d '\r' < SHA256SUMS.txt | sha256sum -c -
```

On Windows, add `C:\Program Files\Git\usr\bin` to PATH or call the GNU tools by full path; the recorded preflight used the full paths. The `tr -d '\r'` is required: `SHA256SUMS.txt` has CRLF endings and a literal `sha256sum -c SHA256SUMS.txt` exits 1 on Windows with "FAILED open or read" for every entry (captured as `03-checksums.*`); a PowerShell string pipeline also re-adds CRLF and fails (`03b-*`). Run the corrected form in a POSIX shell (Git Bash). The `# SHA256SUMS` header produces a harmless "1 line is improperly formatted" warning; all five data files report OK. Failed and corrected runs are kept separately as evidence.

Ready means: HEAD equals the revision named in the run record, the corrected checksum check exits 0, and the validator command has been copied verbatim from `feat/validate-qradar-import`. A failing checksum means the staged evidence differs from the reviewed evidence — stop, do not drive.

Validator launch: BLOCKED at baseline. No validator process is started by this draft, so there is no validator teardown yet. Any future launch must use a disposable data directory and remove only what it created.

## Doctor

Run the preflight above, then confirm the validator command was copied verbatim from the PR (not reconstructed from memory) and that it resolves in this shell. Doctor fails closed: missing command, wrong revision, or checksum mismatch means "not worth driving". Baseline doctor result is in `evidence/2026-11-17-preflight/` and covers integrity only — it does not make the validator ready.

## Drive

Harness: direct CLI invocation, one isolated run per scenario. See `features/README.md` and the three feature files. Capture stdout, stderr, exit code and any report file for every invocation; keep one record per scenario (docs/VERIFICATION_CONTRACT.md).

Observable end states:
- Reject scenario: non-zero exit, reasons naming each metadata mismatch, no change to trusted inventory files.
- Accept scenario: zero exit on a clearly synthetic consistent fixture, with an import preview and no write to trusted inventory.
- BB refs scenario: every referenced `bb_id` resolves against `shared_bbs.yaml`, or unresolved refs are reported with rule id and bb id; no silent pass.

Do not type a guessed validator command. Until the exact PR command is filled in, no scenario has been driven and all three verdicts are NOT VERIFIED.

## Evidence

Per run, create `.agents/skills/verify-qradar-import/evidence/<utc-run-id>/` containing `command.txt`, `stdout.log`, `stderr.log`, `exit-code.txt`, `revision.txt`, `env.txt`, and the validator's own report files. Use verdicts REAL PASS / FAIL / NOT VERIFIED from docs/VERIFICATION_CONTRACT.md; a preflight, a build, or a dry-run is never a validator pass. The captured baseline artifacts are `evidence/2026-11-17-preflight/` — they prove staged-file integrity and the absence of the PR branch, and explicitly do not prove validator behavior.

## Cleanup

This draft's preflight starts no process and creates no data directory. Staged files are read-only: never edit or delete them to make a scenario pass. Future runs delete only their own disposable data directory and synthetic fixtures; evidence survives cleanup. Never kill by process name.

## Helpers

No helper script ships with this draft; none was invented. `sha256sum` is GNU coreutils 8.32 from Git for Windows (`C:\Program Files\Git\usr\bin\sha256sum.exe`) and `go` is 1.22.5. If a helper is added later, it must be executable and its exact invocation documented here.

## Feature map

- `features/README.md` — index and current verdicts.
- `features/reject-staged-metadata-mismatch.md` — reject the real staged files.
- `features/accept-consistent-fixture.md` — accept a small synthetic consistent fixture.
- `features/resolve-bb-refs.md` — resolve building-block references.
