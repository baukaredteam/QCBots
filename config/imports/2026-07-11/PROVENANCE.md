# Import provenance — QRadar rules, building blocks, fields, design concept

All files in this directory were supplied by the product owner on 2026-11-17.
They are staged evidence only. They do NOT modify the trusted global inventory
under `config/rules_inventory.yaml` or `config/custom_fields_qradar.yaml`.

| File | Claimed in metadata | Actually parsed | Status |
|---|---|---|---|
| full_rules85.yaml | total_rules=346, fully_configured_rules=85 | 14 rule records | MISMATCH — reject as authoritative count |
| shared_bbs.yaml | total_shared_bbs=85 | 67 building blocks | MISMATCH — reject as authoritative count |
| fields.yaml | total_fields=42 | 54 records, 5 duplicated names | MISMATCH — resolve source key before import |
| qradar_rules_bb_sysmon.csv | Excel export | 1326 rows, cp1251, 18 columns | Unverified raw export |
| field_intelligence_concept_v4.html | design preview | synthetic data, no live calls | DESIGN REFERENCE ONLY |

Duplicate field names in fields.yaml: proc_file_path (3), proc_usr_sid (2),
event_description (2), task_name (2). The natural key is (name, log_sources),
not name alone; this must be enforced by a validator before any import.

Field Intelligence V4 is a synthetic UI concept: it must not be imported as
telemetry evidence, AQL verification, QRadar connectivity, or client data.

See SHA256SUMS.txt for checksums. No external service was contacted.
