# Reject staged files with inconsistent metadata

## Sub-features

- `full_rules85.yaml`: header claims 346 rules / ~85 fully configured, only 14 rule records parse (PROVENANCE.md).
- `shared_bbs.yaml`: metadata claims `total_shared_bbs: 85`, only 67 building blocks parse.
- `fields.yaml`: metadata claims `total_fields: 42`, 54 records parse and 5 names duplicate; natural key is `(name, log_sources)`, not `name`.
- `qradar_rules_bb_sysmon.csv`: raw cp1251 export, 1326 rows, 18 columns — unverified, not an authoritative count.
- `field_intelligence_concept_v4.html`: design reference only, not importable evidence.

## How to get to it (user POV)

A release engineer points the validator at `config/imports/2026-07-11/` and expects it to refuse these files as authoritative, state each reason, and leave trusted inventory untouched.

## Driving it with the validator CLI

BLOCKED at `ce17fa03`: no validator command exists in the repo. Copy the exact invocation from `feat/validate-qradar-import`; do not reconstruct it. The inputs above are real and already staged; the checksum preflight in `SKILL.md` must pass first.

Expected observable end state once the command is known: non-zero exit; reasons naming the rule, BB and field count mismatches and the duplicate natural keys; `git status --short` shows no change to `config/rules_inventory.yaml` or `config/custom_fields_qradar.yaml`; stdout, stderr, exit code and report saved under the run id.

## Gotchas

- Header and metadata counts are claims; compare against parsed records, not against the claim.
- Do not treat `name` alone as the field key; duplicates must be evaluated on `(name, log_sources)`.
- The HTML concept is not telemetry or AQL verification.
- The staged directory is untracked and read-only for verification; never edit it to make the scenario pass.
