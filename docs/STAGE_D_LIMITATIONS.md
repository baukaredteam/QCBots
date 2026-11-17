# Stage D Limitations (Acknowledged)

## Artifact Review — First-Wins Only

- `case_artifacts` stores a single review state (`reviewed_by`, `reviewed_at`, `review_reason`, `review_decision`, `review_status`).
- `ReviewCaseArtifact` uses `WHERE review_decision IS NULL` — the first submission wins. A second review on the same artifact returns `ErrInvalidTransition` (HTTP 409).
- There is **no separate `case_artifact_review_history` table** in this stage. Immutable history is provided by `case_activity` rows (`action = 'artifact_reviewed'`) which are append-only via DB triggers. A dedicated append-only review-history table with its own monotonic sequence is a future research item, not implemented here.

## GLOBAL Note Substring Check — Not Full DLP

- `CreateCaseNote` for GLOBAL scope rejects note text containing any `client_id` string from the `clients` table (e.g. `client-alpha`, `client-beta`).
- This is an identifier-based guard, **not a full DLP / content classification engine**. It does not detect free-form secrets, PHI, or client data that does not contain the literal client identifier. A dedicated DLP / policy review stage would be a separate research effort and is explicitly out of scope for this task.

## Note Edit Endpoint — Not Implemented

- `case_notes` rows are insert-only in this stage. A new body is never stored by updating the note row.
- `case_notes_revision` exists as append-only history, but there is **no `PUT /notes/{id}` edit endpoint** in Stage D. Editing a note would require a new revision row plus a new `case_activity` entry; that operation is intentionally deferred to a future stage, not implemented here.

## Historical `payload_hash` (v1) Acceptance

- Rows created before the canonical v2 serialization (length-prefixed) store the v1 `v1\x00...` hash. `payloadHashMatches` accepts v1 on lookup so idempotency retries for legacy rows keep working. New rows always use v2. This dual-accept is deliberate for compatibility and is not a schema break.
