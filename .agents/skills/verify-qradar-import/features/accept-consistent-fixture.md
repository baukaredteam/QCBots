# Accept a small consistent fixture

## Sub-features

- A minimal import set whose declared counts equal parsed counts.
- Unique `(name, log_sources)` keys for every field record.
- BB references that resolve against the fixture's shared building blocks.
- Validator exits zero and emits an import preview; no write to trusted inventory.

## How to get to it (user POV)

A release engineer wants proof that the validator accepts a well-formed import instead of rejecting everything, and that acceptance is a preview: it changes no trusted knowledge.

## Driving it with the validator CLI

BLOCKED at `ce17fa03`: no validator command exists in the repo. Copy the exact invocation from `feat/validate-qradar-import`; do not reconstruct it. Build the fixture as verification scaffolding in a disposable directory under the run's evidence folder, not inside `config/imports/2026-07-11/`. Keep it clearly synthetic: no client telemetry, no real client identifiers, no external service calls.

Expected observable end state once the command is known: exit 0; preview enumerates the fixture's rules, fields and BBs; trusted inventory files unchanged; stdout, stderr, exit code and preview saved under the run id.

## Gotchas

- A green run against the real staged directory would be a failure of this scenario; the fixture must be separate and synthetic.
- A zero exit alone is not proof: verify the preview contents and the absence of side effects.
- Remove the fixture in cleanup, keep the evidence.
