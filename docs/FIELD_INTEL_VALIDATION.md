# Local Field Intelligence invariants

Implements docs/FIELD_INTELLIGENCE_DESIGN.md section 10 / SPEC sections 11-13.
This is a read-only snapshot validator, not an authorization service, SQL syntax
checker, or proof that QRadar works. No external calls or output files are made.
It does not change inventory, activate bindings, or approve anything.

Requirements: Python 3.10+ and existing PyYAML. From the repository root:

```sh
python scripts/validate_field_intel.py path/to/snapshot.yaml
python -m unittest discover -s tests -p test_validate_field_intel.py -v
python -m unittest discover -s tests -p 'test_*.py' -v
```

JSON stdout has schema_version, verdict, errors (code/location), and scope.
Exit 0 means local invariants ACCEPT; exit 1 means REJECT. Input values, parser
exceptions, raw queries, file paths, and private payloads are never echoed.
The default inventory is config/custom_fields_qradar.yaml; --inventory permits
another local YAML/JSON file. Inventory entries use fields[].field_name and
is_active=true. Aliases and normalized names do not invent searchable properties.

## Snapshot contract (version 1)

JSON and YAML have the same shape. All record collections below are optional
lists of mappings. An empty snapshot validates no records and proves no readiness.
Only the documented top-level keys are allowed. Duplicate YAML keys reject.

| Key | Record shape / rule |
|---|---|
| schema_version | Required integer 1 |
| field_states | name, from_status (default UNKNOWN), status, evidence_id. Status is AQL VERIFIED, CANDIDATE, UNKNOWN. Names must exist in active global inventory; duplicate states reject. |
| manual_evidence | id, kind=MANUAL_QRADAR_SEARCH, field_name, result=SUCCESS, reviewer_id, reviewer_role=CTI_ANALYST or ADMINISTRATOR, reviewed_at, evidence_ref, synthetic=false. Every VERIFIED state requires its own matching separate evidence record. Raw samples and DEMO VERIFIED cannot substitute. |
| aql_drafts | query: restricted SELECT ... FROM events query. Every referenced field must exist and have a VERIFIED field state backed by separate manual evidence. |
| bindings | client_id, domain_id (nonnegative integer), active (boolean), approval_id. Inactive bindings may have no approval. |
| admin_approvals | id, client_id, domain_id, role=ADMINISTRATOR, decision=APPROVED, reviewer_id, reviewed_at, evidence_ref, synthetic=false. Active binding must reference an exact client/domain match. |
| coverage | status plus independent boolean/null facts: rule_exists, fields_available, telemetry_available, rule_tested, detection_observed. sigma/kql/spl metadata is ignored for coverage. |
| telemetry | status=CONNECTED/NOT_CONNECTED/NO_RECENT_EVENTS/UNKNOWN, event_count (nonnegative integer), threat_before, threat_after (nonempty status strings). Zero events or NO_RECENT_EVENTS cannot change threat state. |
| logs / audit | Only event, timestamp, actor_id, action, outcome, client_id, resource_id, correlation_id. No free-form message, raw query, nested metadata, credentials or payload keys. |

The first three coverage facts must all be true for PARTIAL; all five must be
true for COVERED. rule_exists=false yields NOT_COVERED; otherwise insufficient
facts yield UNKNOWN. The declared status must equal that conservative result.
AQL drafts and external detection formats cannot substitute for these facts.

Audit event codes: FIELD_REVIEW, AQL_REVIEW, BINDING_REVIEW, COVERAGE_REVIEW,
TELEMETRY_REVIEW. action: REVIEW/APPROVE/REJECT/READ/VALIDATE;
outcome: SUCCESS/FAILURE/PENDING. Values must be bounded metadata identifiers
(128 characters, letters/digits/underscore/dot/colon/at/plus/minus), with common
credential markers forbidden. This rejects unsafe records rather than masking
and then echoing them. Do not put arbitrary user text or payload into ID fields.

Supported AQL includes quoted property names, single-quoted literals, aliases,
WHERE, grouping, ordering, time windows and COUNT/QIDNAME/MIN/MAX/SUM/AVG/LOWER/
UPPER/DATEFORMAT/UTF8 functions. COUNT(*) is allowed; SELECT *, comments,
multiple statements, nested SELECTs, unsupported functions or tokens reject.
This conservative lexer checks field references, not full AQL semantics.

The script checks consistency of supplied proof records, not reviewer identity,
evidence authenticity, tenancy authorization, or actual QRadar search results.
Those checks belong at the authenticated application boundary. ACCEPT is never
a grant to promote trusted knowledge or deploy rules. Integrations NOT VERIFIED.
The tests use synthetic proof records only and never perform real approvals.
