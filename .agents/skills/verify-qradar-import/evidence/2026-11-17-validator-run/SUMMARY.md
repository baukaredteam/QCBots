# Validator run evidence — 2026-11-17

Operator: QA / Verification Engineer (MSSP Intelligence Workbench). All commands were executed, not transcribed from a report. Worktree HEAD: `ccdfab4e3747e7887c987739ba6f82f7fb3ca447` (PR #8, `feat/validate-qradar-imports`). Skill branch: `77e2392` (PR #7), based on `ce17fa0`.

## Environment

- Python 3.14.4 (`02-python.*`), PyYAML 6.0.3 (`03-yaml.*`).
- GNU coreutils `sha256sum` 8.32 via Git Bash; Windows host, PowerShell 5.1 shell driver.
- Staged inputs copied into the run worktree as verification scaffolding; the shared checkout's untracked `config/imports/2026-07-11` was not modified.

## Executed commands and fresh exit codes

| Artifact prefix | Command (run from the isolated worktree) | Exit code | Result |
|---|---|---|---|
| `01-revision` | `git rev-parse HEAD` | 0 | `ccdfab4e3747e7887c987739ba6f82f7fb3ca447` |
| `02-python` | `python --version` | 0 | `Python 3.14.4` |
| `03-yaml` | `python -c "import yaml; print(yaml.__version__)"` | 0 | `6.0.3` |
| `04-checksums` | Bash: `tr -d '\r' < config/imports/2026-07-11/SHA256SUMS.txt \| (cd config/imports/2026-07-11 && sha256sum -c -)` | 0 | Five staged files OK; harmless warning for the `# SHA256SUMS` header |
| — | Launch guard: `python -c "from pathlib import Path; p=Path('config/imports/2026-07-11'); assert not any(x.is_dir() for x in p.iterdir()), 'nested staged copy'"` | 0 | `staging layout OK` |
| `05a-setup-blocked-*` / `06a-setup-blocked-*` | First attempt, nested staged copy present | 1 / 1 | `PermissionError` in `test_real_staged_sources_and_cli`; historical failure, not a pass |
| `07-unittest` | `python -m unittest discover -s tests -p test_validate_imports.py -v` | 0 | `Ran 15 tests in 1.155s`, `OK` |
| `08-validator` | `python scripts/validate_imports.py` | 1 | `verdict: REJECT`, six `COUNT_MISMATCH`, one `UNRESOLVED_BB`, seven `CONDITIONAL`, HTML/CSV excluded |

Raw stdout/stderr and the fresh exit code for each command are stored beside this file. `08-VALIDATION_REPORT.json` and `.md` are copies of the validator's own output.

## Counts and defect observed on the real staged files

- `total_rules` 346 declared / 14 actual; `fully_configured_rules` 85/14; `rules_with_sysmon` 42/7; `rules_without_sysmon` 43/7; `total_shared_bbs` 85/67; `total_fields` 42/54.
- Source defect (not a validator bug): `UNRESOLVED_BB` — owner `shared_bbs`, `bb_id` `BB_0002100_common:Whoami_Executed_as_System_Windows`, `reference` `BB_eventype:ProcessCreate`. The referenced BB is absent from the shared block set.
- `CONDITIONAL` rules: `INC_0002100`, `INC_0002400`, `INC_0018700`, `INC_0018900`, `INC_0019000`, `INC_0019100`, `INC_0022500` — Sysmon telemetry unconfirmed for any client.

## Verdicts

- Reject staged metadata mismatches: REAL PASS. The validator returned its expected `REJECT` with named reasons and exit 1; trusted config bytes were not changed.
- Accept a small consistent fixture: REAL PASS (`test_consistent_evidence_is_accepted` and related tests).
- Resolve BB references: REAL PASS (`test_dependencies_resolve_shared_and_rule_local_ids`, `test_shared_dependency_cannot_use_other_rules_local_id`). The real staged file's `UNRESOLVED_BB` is a correctly detected source defect.
- QRadar live integration PoC: NOT VERIFIED.
- ThreadLinqs live integration PoC: NOT VERIFIED.
- Trusted-knowledge promotion, rule deployment, report publication: NOT VERIFIED (human approval gates; not exercised).

A validator `REJECT` is the expected observable end state of the reject scenario; exit 1 here is not a test failure. Earlier integrity-only results are in `../2026-11-17-preflight/`, which is superseded by this run.
