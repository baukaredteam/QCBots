# Reject staged files with inconsistent metadata

Verdict: REAL PASS on `ccdfab4`. Evidence: `../evidence/2026-11-17-validator-run/08-validator.*` and `08-VALIDATION_REPORT.json`.

## Sub-features

- `full_rules85.yaml`: declared 346 rules / 85 fully configured / 42 with Sysmon / 43 without; parsed 14 rules, 7 with Sysmon, 7 without.
- `shared_bbs.yaml`: declared `total_shared_bbs: 85`, parsed 67 building blocks.
- `fields.yaml`: declared `total_fields: 42`, parsed 54 records; duplicates resolve under `(name, log_sources)`, so no `DUPLICATE_FIELD_KEY` was emitted for the real staged files.
- `qradar_rules_bb_sysmon.csv` and `field_intelligence_concept_v4.html` appear in `excluded_inputs`; neither is used as authoritative evidence.

## How to get to it (user POV)

A release engineer points the validator at `config/imports/2026-07-11/` and expects it to refuse these files as authoritative, name each reason, and leave trusted inventory untouched.

## Driving it with the CLI

From the isolated run worktree (see `../SKILL.md#launch`):

```
python scripts/validate_imports.py
```

Recorded observable end state: exit 1; verdict `REJECT`; six `COUNT_MISMATCH` errors with declared and actual values; one `UNRESOLVED_BB` (see the BB-refs feature); seven `CONDITIONAL` Sysmon rules; `excluded_inputs` contains the HTML and CSV. The validator's own `sha256` map includes `rules_inventory.yaml` and `custom_fields_qradar.yaml`, proving they were read but not changed. Unit test `test_real_staged_sources_and_cli` additionally verifies input bytes and trusted config bytes are unchanged.

## Gotchas

- Exit 1 is the expected outcome here; do not relabel it FAIL. The scenario fails only if the verdict/reasons are missing or wrong.
- Header and metadata counts are claims; compare them with parsed records.
- A nested `2026-07-11/2026-07-11` copy in the staged dir makes the suite fail with `PermissionError` before validation (`05a-setup-blocked-*`); the guard in Launch prevents it.
- Never edit the staged files to make the scenario pass.
