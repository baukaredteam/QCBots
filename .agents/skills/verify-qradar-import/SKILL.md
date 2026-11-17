---
name: verify-qradar-import
description: "Project-local verification for the QRadar import validator of MSSP Intelligence Workbench / Sentinel Atlas. Drives the validator as a release engineer does against config/imports/2026-07-11: reject staged files with inconsistent metadata, accept a consistent fixture, resolve building-block references. Use when reviewing feat/validate-qradar-imports or any import-validation change; verdicts follow docs/VERIFICATION_CONTRACT.md."
disable-model-invocation: true
---

# Verify QRadar import

Surface: a Python CLI (`scripts/validate_imports.py`) plus a unittest suite (`tests/test_validate_imports.py`) operating on staged YAML and CSV files. No import-validator web UI exists. `config/imports/2026-07-11/field_intelligence_concept_v4.html` is a design preview only (PROVENANCE.md: "DESIGN REFERENCE ONLY") and must never be imported as telemetry, AQL verification, QRadar connectivity, or client data.

Validator under test: PR #8, branch `feat/validate-qradar-imports`, head `ccdfab4e3747e7887c987739ba6f82f7fb3ca447`. This skill itself lives on `test/verify-qradar-import` (PR #7), based on `ce17fa03bc0907a3c5fa5539d4d3ba24e4e2377f`.

All three validator scenarios are REAL PASS on the recorded revision. QRadar and ThreadLinqs integration PoCs remain NOT VERIFIED. Raw evidence is in `evidence/2026-11-17-validator-run/`.

## Interview (observed facts, not assumptions)

- Staged inputs live in `config/imports/2026-07-11/` (untracked at baseline; supplied by the product owner on 2026-11-17 per `PROVENANCE.md`): `full_rules85.yaml`, `shared_bbs.yaml`, `fields.yaml`, `qradar_rules_bb_sysmon.csv`, `field_intelligence_concept_v4.html`, `PROVENANCE.md`, `SHA256SUMS.txt`.
- `PROVENANCE.md` declares claims versus parsed results: `full_rules85.yaml` claims 346 rules / ~85 fully configured but only 14 rule records parse; `shared_bbs.yaml` claims 85 BBs but 67 parse; `fields.yaml` claims 42 fields but 54 records parse.
- `fields.yaml` natural key is `(name, log_sources)`, not `name` (PROVENANCE.md lines 15–17). The validator checks duplicates on that key; the real staged files produce no `DUPLICATE_FIELD_KEY` error because the duplicates differ by log source.
- `shared_bbs.yaml` usage says references resolve by `bb_id` through `depends_on_bb`. The "all aligned" header in `full_rules85.yaml` is a claim, not evidence.
- Staged files are evidence only: they do not modify `config/rules_inventory.yaml` or `config/custom_fields_qradar.yaml` (PROVENANCE.md lines 4–5). QRadar is read-only in MVP (AGENTS.md principle 10).
- Recorded toolchain: Python 3.14.4, PyYAML 6.0.3, GNU coreutils `sha256sum` 8.32 (Git for Windows), Git Bash. `SHA256SUMS.txt` has CRLF endings.

## Launch

Validate in an isolated worktree; do not switch the HEAD of the shared checkout:

```
git worktree add --detach <run-dir> ccdfab4e3747e7887c987739ba6f82f7fb3ca447
```

The staged directory is untracked in git, so copy it into `<run-dir>/config/imports/2026-07-11` as verification scaffolding. Copy the directory's contents directly; copying the directory into an existing destination creates a nested `2026-07-11/2026-07-11` and makes `test_real_staged_sources_and_cli` fail with `PermissionError` (observed in `05a-setup-blocked-*`). Guard before driving:

```
python -c "from pathlib import Path; p=Path('config/imports/2026-07-11'); assert not any(x.is_dir() for x in p.iterdir()), 'nested staged copy'"
tr -d '\r' < config/imports/2026-07-11/SHA256SUMS.txt | (cd config/imports/2026-07-11 && sha256sum -c -)
```

Ready means: HEAD is `ccdfab4`, no nested staged directory, and the checksum command exits 0. Run both drive commands from `<run-dir>`.

## Doctor

From the run worktree: `git rev-parse HEAD`, the nested-copy guard above, the corrected checksum command above, then `python -c "import yaml; print(yaml.__version__)"`. Doctor fails closed on wrong revision, nested staging, checksum mismatch or missing PyYAML. Recorded values: `ccdfab4e3747e7887c987739ba6f82f7fb3ca447`, 0, 0, `6.0.3`.

## Drive

Harness: direct CLI invocation, one record per command. From `<run-dir>`:

```
python -m unittest discover -s tests -p test_validate_imports.py -v
python scripts/validate_imports.py
```

Recorded results:
- Unit suite: exit 0, `Ran 15 tests`, `OK` (`07-unittest.*`). Includes `test_consistent_evidence_is_accepted`, `test_dependencies_resolve_shared_and_rule_local_ids`, `test_real_staged_sources_and_cli`, and checks that trusted config bytes do not change.
- CLI on the real staged files: exit 1, verdict `REJECT` (`08-validator.*`, `08-VALIDATION_REPORT.json`). Errors: six `COUNT_MISMATCH` (`total_rules` 346/14, `fully_configured_rules` 85/14, `rules_with_sysmon` 42/7, `rules_without_sysmon` 43/7, `total_shared_bbs` 85/67, `total_fields` 42/54) plus one `UNRESOLVED_BB`. Seven Sysmon rules are `CONDITIONAL`; `field_intelligence_concept_v4.html` and `qradar_rules_bb_sysmon.csv` are in `excluded_inputs`.

Exit 1 from the validator is the expected result of the reject scenario: the scenario passes when the observed verdict and reasons match, not when the process exits 0.

## Evidence

`evidence/2026-11-17-validator-run/` holds `command.txt`, `01-revision.*`, `02-python.*`, `03-yaml.*`, `04-checksums.*`, `07-unittest.*`, `08-validator.*` (stdout, stderr, fresh exit code for each) and the validator's `08-VALIDATION_REPORT.json` / `.md`. `05a-setup-blocked-*` and `06a-setup-blocked-*` retain the failed setup attempt and are not counted as a pass. `evidence/2026-11-17-preflight/` is the earlier, superseded integrity-only record.

Verdicts use REAL PASS / FAIL / NOT VERIFIED from docs/VERIFICATION_CONTRACT.md. A validator `REJECT` verdict with the expected reasons is a REAL PASS of the reject scenario; it does not promote staged data to trusted inventory.

## Cleanup

After driving, remove only the run worktree and its copied staged directory:

```
git worktree remove --force <run-dir>
```

Never edit staged source files to make a scenario pass, and never delete the evidence under this skill. The validator writes `VALIDATION_REPORT.json` and `.md` into the staged copy only; those were removed with the worktree after their contents were copied into evidence.

## Helpers

No helper script ships with this skill. `sha256sum` is GNU coreutils 8.32 from Git for Windows; Python is 3.14.4 with PyYAML 6.0.3. On Windows PowerShell, redirecting native output to a file writes UTF-16LE; the recorded artifacts were normalized to UTF-8 without BOM before committing.

## Feature map

- `features/README.md` — index and current verdicts.
- `features/reject-staged-metadata-mismatch.md` — reject the real staged files.
- `features/accept-consistent-fixture.md` — accept a small synthetic consistent fixture.
- `features/resolve-bb-refs.md` — resolve building-block references.
