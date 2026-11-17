"""Validate local Field Intelligence snapshots without writes or external calls."""

import argparse
import json
from pathlib import Path
import re

import yaml

try:
    from .validate_imports import UniqueLoader
except ImportError:
    from validate_imports import UniqueLoader


FIELD_STATUSES = {"AQL VERIFIED", "CANDIDATE", "UNKNOWN"}
TELEMETRY_STATUSES = {"CONNECTED", "NOT_CONNECTED", "NO_RECENT_EVENTS", "UNKNOWN"}
COVERAGE_STATUSES = {"COVERED", "PARTIAL", "NOT_COVERED", "UNKNOWN"}
FLAGS = ("rule_exists", "fields_available", "telemetry_available", "rule_tested", "detection_observed")
TOKEN = re.compile(r"\s+|'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|[A-Za-z_][A-Za-z_0-9]*|\d+(?:\.\d+)?|[(),=<>!+*/%-]")
KEYWORDS = set("SELECT FROM WHERE AND OR NOT IN IS NULL LIKE ILIKE BETWEEN AS GROUP BY ORDER ASC DESC LIMIT LAST MINUTES HOURS DAYS DISTINCT HAVING TRUE FALSE".split())
FUNCTIONS = {"COUNT", "QIDNAME", "MIN", "MAX", "SUM", "AVG", "LOWER", "UPPER", "DATEFORMAT", "UTF8"}
LOG_KEYS = {"event", "timestamp", "actor_id", "action", "outcome", "client_id", "resource_id", "correlation_id"}
LOG_EVENTS = {"FIELD_REVIEW", "AQL_REVIEW", "BINDING_REVIEW", "COVERAGE_REVIEW", "TELEMETRY_REVIEW"}
SENSITIVE = re.compile(r"(?i)password|passwd|secret|bearer|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key|payload|authorization|gh[pousr]_|sk-[a-z0-9]|eyJ[a-zA-Z0-9_-]+\.")


def aql_fields(query):
    if not isinstance(query, str) or not query.strip():
        raise ValueError("INVALID_AQL")
    tokens, position = [], 0
    for match in TOKEN.finditer(query):
        if match.start() != position:
            raise ValueError("UNSUPPORTED_AQL")
        position = match.end()
        if not match.group().isspace():
            tokens.append(match.group())
    if position != len(query) or not tokens or tokens[0].upper() != "SELECT":
        raise ValueError("UNSUPPORTED_AQL")
    upper = [t.upper() for t in tokens]
    if upper.count("SELECT") != 1 or upper.count("FROM") != 1:
        raise ValueError("UNSUPPORTED_AQL")
    source = upper.index("FROM")
    if source <= 1 or source + 1 >= len(tokens) or tokens[source + 1].lower() != "events":
        raise ValueError("UNSUPPORTED_AQL")
    aliases = set()
    for i, token in enumerate(upper):
        if token == "AS":
            if i + 1 >= len(tokens) or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*|"(?:""|[^"])+"', tokens[i + 1]):
                raise ValueError("UNSUPPORTED_AQL")
            aliases.add(tokens[i + 1])
    fields = set()
    for i, token in enumerate(tokens):
        if i == source + 1 or (i > 0 and upper[i - 1] == "AS"):
            continue
        if token == "*":
            if not (i >= 2 and upper[i - 2:i] == ["COUNT", "("] and i + 1 < len(tokens) and tokens[i + 1] == ")"):
                raise ValueError("UNSUPPORTED_AQL")
        if token.startswith("'") or not (token[0].isalpha() or token[0] in '_"'):
            continue
        if token.upper() in KEYWORDS or (i > source and token in aliases):
            continue
        if i + 1 < len(tokens) and tokens[i + 1] == "(":
            if token.upper() not in FUNCTIONS:
                raise ValueError("UNSUPPORTED_AQL")
            continue
        fields.add(token[1:-1].replace('""', '"') if token.startswith('"') else token)
    return fields


def coverage_status(record):
    values = [record.get(flag) for flag in FLAGS]
    if any(value is not None and type(value) is not bool for value in values):
        raise ValueError("INVALID_COVERAGE_FACT")
    if values[0] is False:
        return "NOT_COVERED"
    if all(value is True for value in values):
        return "COVERED"
    if all(value is True for value in values[:3]):
        return "PARTIAL"
    return "UNKNOWN"


def validate(snapshot, inventory):
    errors = []

    def reject(code, location):
        errors.append({"code": code, "location": location})

    def rows(parent, key):
        value = parent.get(key, [])
        if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
            raise ValueError("INVALID_SCHEMA")
        return value

    def text(value):
        return isinstance(value, str) and bool(value.strip())

    try:
        if not isinstance(snapshot, dict) or not isinstance(inventory, dict) or snapshot.get("schema_version") != 1:
            raise ValueError("INVALID_SCHEMA")
        allowed = {"schema_version", "field_states", "aql_drafts", "manual_evidence", "bindings", "admin_approvals", "coverage", "telemetry", "logs", "audit"}
        if set(snapshot) - allowed:
            raise ValueError("INVALID_SCHEMA")
        entries = rows(inventory, "fields")
        if not entries:
            raise ValueError("INVALID_INVENTORY")
        names = set()
        for field in entries:
            if not text(field.get("field_name")):
                raise ValueError("INVALID_INVENTORY")
            if field.get("is_active") is True:
                names.add(field["field_name"])
        evidence, approvals = {}, {}
        for key, target in (("manual_evidence", evidence), ("admin_approvals", approvals)):
            for index, row in enumerate(rows(snapshot, key)):
                identifier = row.get("id")
                if not text(identifier) or identifier in target:
                    reject("INVALID_EVIDENCE_ID", f"{key}[{index}]")
                else:
                    target[identifier] = row
        states = {}
        for index, row in enumerate(rows(snapshot, "field_states")):
            location = f"field_states[{index}]"
            name, status = row.get("name"), row.get("status")
            if not text(name) or name in states or status not in FIELD_STATUSES or row.get("from_status", "UNKNOWN") not in FIELD_STATUSES:
                reject("INVALID_FIELD_STATE", location)
                continue
            states[name] = status
            if name not in names:
                reject("FIELD_NOT_IN_INVENTORY", location)
            if status == "AQL VERIFIED":
                proof = evidence.get(row.get("evidence_id"), {})
                if not (proof.get("kind") == "MANUAL_QRADAR_SEARCH" and proof.get("field_name") == name
                        and proof.get("result") == "SUCCESS" and text(proof.get("reviewer_id"))
                        and proof.get("reviewer_role") in {"CTI_ANALYST", "ADMINISTRATOR"}
                        and text(proof.get("evidence_ref")) and text(proof.get("reviewed_at"))
                        and proof.get("synthetic") is False):
                    reject("MANUAL_AQL_EVIDENCE_REQUIRED", location)
        for index, row in enumerate(rows(snapshot, "aql_drafts")):
            location = f"aql_drafts[{index}]"
            refs = aql_fields(row.get("query"))
            for name in sorted(refs):
                if name not in names:
                    reject("AQL_FIELD_NOT_IN_INVENTORY", location)
                elif states.get(name) != "AQL VERIFIED":
                    reject("AQL_FIELD_NOT_VERIFIED", location)
        for index, row in enumerate(rows(snapshot, "bindings")):
            location = f"bindings[{index}]"
            if not text(row.get("client_id")) or type(row.get("domain_id")) is not int or row["domain_id"] < 0 or type(row.get("active")) is not bool:
                reject("INVALID_BINDING", location)
                continue
            if row["active"]:
                approval = approvals.get(row.get("approval_id"), {})
                if not (approval.get("client_id") == row["client_id"] and type(approval.get("domain_id")) is int
                        and approval["domain_id"] == row["domain_id"] and approval.get("role") == "ADMINISTRATOR"
                        and approval.get("decision") == "APPROVED" and text(approval.get("reviewer_id"))
                        and text(approval.get("reviewed_at")) and text(approval.get("evidence_ref"))
                        and approval.get("synthetic") is False):
                    reject("ADMIN_APPROVAL_REQUIRED", location)
        for index, row in enumerate(rows(snapshot, "coverage")):
            location = f"coverage[{index}]"
            expected = coverage_status(row)
            if row.get("status") not in COVERAGE_STATUSES or row["status"] != expected:
                reject("UNSUPPORTED_COVERAGE", location)
        for index, row in enumerate(rows(snapshot, "telemetry")):
            location = f"telemetry[{index}]"
            count = row.get("event_count")
            if row.get("status") not in TELEMETRY_STATUSES or type(count) is not int or count < 0 or not text(row.get("threat_before")) or not text(row.get("threat_after")):
                reject("INVALID_TELEMETRY", location)
            elif (count == 0 or row["status"] == "NO_RECENT_EVENTS") and row["threat_before"] != row["threat_after"]:
                reject("ABSENCE_IS_NOT_THREAT_EVIDENCE", location)
        for key in ("logs", "audit"):
            for index, row in enumerate(rows(snapshot, key)):
                location = f"{key}[{index}]"
                if set(row) - LOG_KEYS or row.get("event") not in LOG_EVENTS:
                    reject("UNSAFE_LOG_RECORD", location)
                if "action" in row and row["action"] not in {"REVIEW", "APPROVE", "REJECT", "READ", "VALIDATE"}:
                    reject("UNSAFE_LOG_ACTION", location)
                if "outcome" in row and row["outcome"] not in {"SUCCESS", "FAILURE", "PENDING"}:
                    reject("UNSAFE_LOG_OUTCOME", location)
                for value in row.values():
                    if not isinstance(value, str) or len(value) > 128 or not re.fullmatch(r"[A-Za-z0-9_.:@+-]+", value) or SENSITIVE.search(value):
                        reject("UNSAFE_LOG_VALUE", location)
                        break
    except (ValueError, TypeError, KeyError):
        reject("INVALID_OR_UNSUPPORTED_INPUT", "snapshot")
    return {"schema_version": 1, "verdict": "REJECT" if errors else "ACCEPT", "errors": errors,
            "scope": "LOCAL_VALIDATION_ONLY; evidence authenticity and integrations NOT VERIFIED"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", help="Local YAML/JSON snapshot")
    parser.add_argument("--inventory", default=str(Path(__file__).resolve().parents[1] / "config/custom_fields_qradar.yaml"))
    args = parser.parse_args()
    try:
        snapshot = yaml.load(Path(args.snapshot).read_text(encoding="utf-8-sig"), Loader=UniqueLoader)
        inventory = yaml.load(Path(args.inventory).read_text(encoding="utf-8-sig"), Loader=UniqueLoader)
        result = validate(snapshot, inventory)
    except (OSError, UnicodeError, ValueError, TypeError, yaml.YAMLError):
        result = {"schema_version": 1, "verdict": "REJECT", "errors": [{"code": "INVALID_INPUT", "location": "input"}]}
    print(json.dumps(result, sort_keys=True))
    return 1 if result["verdict"] == "REJECT" else 0


if __name__ == "__main__":
    raise SystemExit(main())
