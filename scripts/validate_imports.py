"""Read-only validation of staged QRadar evidence; never promotes trusted data."""

import argparse
import hashlib
import json
from pathlib import Path
import re

import yaml


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if key in result:
            raise ValueError(f"Duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def validate(repo, staged):
    repo, staged = Path(repo).resolve(), Path(staged).resolve()
    if not staged.is_relative_to(repo / "config" / "imports") or "concepts" in staged.relative_to(repo).parts:
        raise ValueError("Staging must be inside config/imports")
    errors, conditions, counts, hashes = [], [], {}, {}

    def error(code, **detail):
        errors.append({"code": code, **detail})

    def read_yaml(path):
        if path.is_symlink() or not path.resolve().is_relative_to(path.parent.resolve()):
            raise ValueError(f"Symlink input forbidden: {path.name}")
        raw = path.read_bytes()
        hashes[path.name] = hashlib.sha256(raw).hexdigest()
        text = raw.decode("utf-8-sig")
        if re.search(r"<!doctype\s+html|<html\b|<script\b|(?:^|[/\\])concepts[/\\]|\.html\b", text, re.I):
            error("SYNTHETIC_CONTENT", file=path.name)
        data = yaml.load(text, Loader=UniqueLoader)
        if not isinstance(data, dict):
            raise ValueError(f"{path.name}: expected YAML mapping")
        return data

    def records(data, key):
        value = data.get(key)
        if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
            raise ValueError(f"{key}: expected list of mappings")
        return value

    def check_count(data, key, actual, filename):
        metadata = data.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError(f"{filename}: metadata must be a mapping")
        declared = metadata.get(key)
        counts[key] = {"declared": declared, "actual": actual}
        if type(declared) is not int or declared != actual:
            error("COUNT_MISMATCH", file=filename, counter=key, declared=declared, actual=actual)

    try:
        rule_doc = read_yaml(staged / "full_rules85.yaml")
        bb_doc = read_yaml(staged / "shared_bbs.yaml")
        field_doc = read_yaml(staged / "fields.yaml")
        rules = records(rule_doc, "rules")
        bbs = records(bb_doc, "shared_building_blocks")
        fields = records(field_doc, "custom_fields")
        for key, actual in (("total_rules", len(rules)), ("fully_configured_rules", len(rules)),
                            ("rules_with_sysmon", sum(r.get("sysmon_required") is True for r in rules)),
                            ("rules_without_sysmon", sum(r.get("sysmon_required") is False for r in rules))):
            check_count(rule_doc, key, actual, "full_rules85.yaml")
        check_count(bb_doc, "total_shared_bbs", len(bbs), "shared_bbs.yaml")
        check_count(field_doc, "total_fields", len(fields), "fields.yaml")
        keys, field_names = set(), set()
        for field in fields:
            name, sources = field.get("name"), field.get("log_sources")
            if not isinstance(name, str) or not name or not isinstance(sources, list) or not sources or any(not isinstance(s, str) or not s for s in sources):
                raise ValueError("Fields require name and nonempty log_sources list")
            key = (name, tuple(sorted(set(sources))))
            if key in keys:
                error("DUPLICATE_FIELD_KEY", name=name, log_sources=list(key[1]))
            keys.add(key)
            field_names.add(name)
        shared_ids = [bb.get("bb_id") for bb in bbs]
        if any(not isinstance(i, str) or not i for i in shared_ids):
            raise ValueError("Shared building blocks require bb_id")
        if len(set(shared_ids)) != len(shared_ids):
            error("DUPLICATE_BB_ID")

        def dependencies(blocks, known, owner):
            for bb in blocks:
                refs = bb.get("depends_on_bb", [])
                if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
                    raise ValueError("depends_on_bb must be a list of bb_id strings")
                for ref in refs:
                    if ref not in known:
                        error("UNRESOLVED_BB", owner=owner, bb_id=bb.get("bb_id"), reference=ref)

        dependencies(bbs, set(shared_ids), "shared_bbs")
        rule_ids = set()
        for rule in rules:
            rid = rule.get("rule_id")
            if not isinstance(rid, str) or not rid:
                raise ValueError("Rules require rule_id")
            if rid in rule_ids:
                error("DUPLICATE_RULE_ID", rule_id=rid)
            rule_ids.add(rid)
            if type(rule.get("sysmon_required")) is not bool:
                raise ValueError(f"{rid}: sysmon_required must be boolean")
            local = rule.get("building_blocks", [])
            if not isinstance(local, list) or any(not isinstance(b, dict) or not isinstance(b.get("bb_id"), str) for b in local):
                raise ValueError(f"{rid}: invalid building_blocks")
            known = set(shared_ids) | {b["bb_id"] for b in local}
            dependencies([rule] + local, known, rid)
            custom = rule.get("custom_fields", [])
            if not isinstance(custom, list):
                raise ValueError(f"{rid}: custom_fields must be a list")
            for field in custom:
                name = field.get("name") if isinstance(field, dict) else field
                if not isinstance(name, str):
                    raise ValueError(f"{rid}: invalid custom field")
                if name not in field_names:
                    error("UNKNOWN_CUSTOM_FIELD", rule_id=rid, name=name)
            if rule["sysmon_required"]:
                conditions.append({"rule_id": rid, "status": "CONDITIONAL", "reason": "Sysmon telemetry is not confirmed for any client"})
    except (OSError, UnicodeError, TypeError, ValueError, yaml.YAMLError) as exc:
        error("INVALID_INPUT", message=str(exc))

    for filename in ("rules_inventory.yaml", "custom_fields_qradar.yaml"):
        path = repo / "config" / filename
        try:
            if path.exists():
                read_yaml(path)
        except (OSError, UnicodeError, TypeError, ValueError, yaml.YAMLError) as exc:
            error("INVALID_TRUSTED_CONFIG", file=filename, message=str(exc))
    return {"schema_version": 1, "verdict": "REJECT" if errors else "CONDITIONAL" if conditions else "ACCEPT",
            "scope": "staged evidence only; no trust promotion or QRadar writes",
            "counts": counts, "errors": errors, "conditions": conditions, "sha256": hashes,
            "excluded_inputs": sorted(p.name for p in staged.iterdir() if p.suffix.lower() in (".html", ".csv")),
            "synthetic_policy": "HTML/concepts are excluded; references in YAML are rejected"}


def write_reports(staged, result):
    payload = json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    for name, content in (("VALIDATION_REPORT.json", payload),
                          ("VALIDATION_REPORT.md", "# Staged QRadar validation\n\nGenerated by scripts/validate_imports.py.\n\n"
                           + f"VERDICT: {result['verdict']}\n\n```json\n{payload}```\n")):
        path = Path(staged) / name
        if path.is_symlink():
            raise ValueError("Report destination must not be a symlink")
        path.write_text(content, encoding="utf-8", newline="\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged-dir", default="config/imports/2026-07-11")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    staged = repo / args.staged_dir
    try:
        result = validate(repo, staged)
        write_reports(staged, result)
    except (OSError, ValueError) as exc:
        print(json.dumps({"verdict": "REJECT", "errors": [{"code": "INVALID_INPUT", "message": str(exc)}]}))
        return 1
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 1 if result["verdict"] == "REJECT" else 0


if __name__ == "__main__":
    raise SystemExit(main())
