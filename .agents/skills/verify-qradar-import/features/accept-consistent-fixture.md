# Accept a small consistent fixture

Verdict: REAL PASS on `ccdfab4`. Evidence: `../evidence/2026-11-17-validator-run/07-unittest.*`.

## Sub-features

- A minimal import set whose declared counters equal parsed counts.
- Unique `(name, log_sources)` keys; two fields with the same name but different log sources are accepted.
- BB references that resolve against shared and rule-local ids.
- Cleanup writes a report without modifying input bytes.

## How to get to it (user POV)

A release engineer wants proof that the validator accepts a well-formed import rather than rejecting everything, and that acceptance changes no trusted knowledge.

## Driving it with the CLI

From the isolated run worktree (see `../SKILL.md#launch`):

```
python -m unittest discover -s tests -p test_validate_imports.py -v
```

Recorded observable end state: exit 0, `Ran 15 tests`, `OK`. The suite's synthetic fixture is built in a temporary directory by `setUp`, not in `config/imports`; `test_consistent_evidence_is_accepted` asserts verdict `ACCEPT`, `test_field_key_includes_log_source_set` asserts acceptance of same-name/different-source fields, and `test_output_is_deterministic_and_does_not_modify_inputs` asserts input bytes stay unchanged after report writing.

## Gotchas

- The fixture is synthetic test scaffolding and never proves QRadar connectivity or client telemetry.
- A green result against the real staged directory would be wrong for this scenario; the fixture must be separate.
- `test_real_staged_sources_and_cli` also runs the CLI on the real staged files and expects exit 1 — it is part of the green suite, not a contradiction.
