# Feature map — verify-qradar-import

Validator revision: `ccdfab4e3747e7887c987739ba6f82f7fb3ca447` (PR #8, `feat/validate-qradar-imports`). Evidence: `../evidence/2026-11-17-validator-run/`.

| Scenario | File | Verdict | Evidence |
|---|---|---|---|
| Reject real staged files for metadata discrepancies | `reject-staged-metadata-mismatch.md` | REAL PASS | `08-validator.*` exit 1, verdict REJECT |
| Accept a small consistent fixture | `accept-consistent-fixture.md` | REAL PASS | `07-unittest.*` exit 0, 15 tests OK |
| Resolve BB references | `resolve-bb-refs.md` | REAL PASS | `07-unittest.*` + `08-VALIDATION_REPORT.json` (UNRESOLVED_BB detected as source defect) |

NOT VERIFIED and out of scope for this skill: QRadar live PoC, ThreadLinqs live PoC, trusted-knowledge promotion, rule deployment. This map is the maintained verification source; a proof that drives one entry point is incomplete while other rows exist.
