# Resolve BB references

Verdict: REAL PASS on `ccdfab4`. Evidence: `../evidence/2026-11-17-validator-run/07-unittest.*`, `08-VALIDATION_REPORT.json`.

## Sub-features

- Rule logic references building blocks such as `BB_0002100_common:Whoami_Executed_as_System_Windows`.
- `shared_bbs.yaml` states references resolve by `bb_id` through `depends_on_bb` (metadata `usage`, lines 12–14).
- Resolution covers shared blocks, rule-local blocks and their `depends_on_bb` chains; unresolved refs are reported with owner and bb id.

## How to get to it (user POV)

A release engineer wants to know whether rule logic can be resolved against the shared BB library rather than trusting the header claim "FIXED: All BB references aligned with shared_bbs.yaml".

## Driving it with the CLI

From the isolated run worktree (see `../SKILL.md#launch`):

```
python -m unittest discover -s tests -p test_validate_imports.py -v
python scripts/validate_imports.py
```

Recorded observable end state: the suite's `test_dependencies_resolve_shared_and_rule_local_ids` and `test_shared_dependency_cannot_use_other_rules_local_id` pass (exit 0 overall). On the real staged files the CLI reports, as a source-data defect, `UNRESOLVED_BB` with owner `shared_bbs`, `bb_id` `BB_0002100_common:Whoami_Executed_as_System_Windows`, `reference` `BB_eventype:ProcessCreate`. The referenced building block is missing from the 67 shared blocks; the validator correctly refuses the import.

## Gotchas

- `UNRESOLVED_BB` here is a defect in the staged source data, not a validator bug. The validator's observable behavior is correct and this scenario passes.
- Resolve on `bb_id`; a matching `bb_name` is not a resolved reference.
- Do not edit the staged YAML files to make references resolve. Fixing the source inventory is a separate human-approved change.
