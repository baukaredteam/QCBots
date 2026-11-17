# Resolve BB references

## Sub-features

- `full_rules85.yaml` rule logic references building blocks such as `BB_0000100_common:...` and `INC_0000100_common:...`.
- `shared_bbs.yaml` states references resolve by `bb_id` through `depends_on_bb` (metadata `usage`, lines 12–14).
- Resolution must follow `depends_on_bb` chains; unresolved references are reported with rule id and bb id.

## How to get to it (user POV)

A release engineer wants to know whether the rule logic can actually be resolved against the shared BB library, rather than trusting the header claim "FIXED: All BB references aligned with shared_bbs.yaml".

## Driving it with the validator CLI

BLOCKED at `ce17fa03`: no validator command exists in the repo. Copy the exact invocation from `feat/validate-qradar-import`; do not reconstruct it. Use the real `full_rules85.yaml` and `shared_bbs.yaml` from `config/imports/2026-07-11/` after the checksum preflight.

Expected observable end state once the command is known: every referenced `bb_id` resolves against the 67 shared building blocks, dependency chains are traversed, and any unresolved reference is listed with its rule id and bb id instead of being silently ignored. Save stdout, stderr, exit code and the resolution report under the run id.

## Gotchas

- Resolve on `bb_id`; a matching `bb_name` is not a resolved reference.
- The "all aligned" header is a claim — only the validator's resolution report is evidence.
- Do not edit the staged YAML files to make references resolve.
