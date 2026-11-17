# Staged QRadar validation (SPEC 11)

Requirements: Python 3.10+ and PyYAML. No Go, CGO, or new Python dependencies.
From the repository root:

```sh
python -m unittest discover -s tests -p test_validate_imports.py -v
python scripts/validate_imports.py
```

The validator writes JSON to stdout and regenerates VALIDATION_REPORT.json and
VALIDATION_REPORT.md in config/imports/2026-07-11. Use --staged-dir to select
another directory under config/imports. REJECT exits 1; ACCEPT or CONDITIONAL
exits 0. CONDITIONAL is not evidence of working detection or confirmed telemetry.
Results are deterministic for unchanged inputs.

Only full_rules85.yaml, shared_bbs.yaml, and fields.yaml are parsed as evidence.
The supplied files describe fully configured rules; both total_rules and
fully_configured_rules are checked against the records actually supplied.
Sysmon counters, shared BB count, and field count are also checked. Dependencies
resolve against shared BBs and the current rule's local BBs, never another rule's
local scope. Field identity is (name, sorted unique log_sources); repeated names
on different sources are valid. Rule custom_fields are checked for name existence.

Sysmon-dependent rules remain CONDITIONAL without client telemetry evidence.
There is no telemetry-confirmation override and no automatic trust promotion.
HTML and CSV are excluded; HTML markup and concept-file references in staged or
trusted YAML cause rejection. Trusted configuration files are inspected read-only.
The command never writes rules_inventory.yaml or custom_fields_qradar.yaml.
Import acceptance/approval and runtime integration are outside this validator.

Raw staged files retain their exact bytes in Git; SHA256SUMS.txt remains the
supplied evidence manifest. Reports are generated artifacts, not manually edited.
