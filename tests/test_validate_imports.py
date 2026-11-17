import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("validate_imports", ROOT / "scripts/validate_imports.py")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class ImportValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.staged = self.repo / "config/imports/test"
        self.staged.mkdir(parents=True)
        self.docs = {
            "fields.yaml": {"metadata": {"total_fields": 1}, "custom_fields": [{"name": "process", "log_sources": ["Windows"]}]},
            "shared_bbs.yaml": {"metadata": {"total_shared_bbs": 1}, "shared_building_blocks": [{"bb_id": "base", "depends_on_bb": []}]},
            "full_rules85.yaml": {"metadata": {"total_rules": 1, "fully_configured_rules": 1, "rules_with_sysmon": 0, "rules_without_sysmon": 1},
                                  "rules": [{"rule_id": "rule", "sysmon_required": False, "depends_on_bb": ["base"], "custom_fields": [{"name": "process"}]}]},
        }

    def run_validation(self):
        for name, data in self.docs.items():
            (self.staged / name).write_text(yaml.safe_dump(data), encoding="utf-8")
        return validator.validate(self.repo, self.staged)

    def codes(self, result):
        return {e["code"] for e in result["errors"]}

    def test_consistent_evidence_is_accepted(self):
        self.assertEqual(self.run_validation()["verdict"], "ACCEPT")

    def test_each_metadata_counter_is_enforced(self):
        original = copy.deepcopy(self.docs)
        for filename, doc in original.items():
            for counter in doc["metadata"]:
                with self.subTest(counter=counter):
                    self.docs = copy.deepcopy(original)
                    self.docs[filename]["metadata"][counter] = 999
                    result = self.run_validation()
                    self.assertEqual(result["verdict"], "REJECT")
                    self.assertIn("COUNT_MISMATCH", self.codes(result))

    def test_field_key_includes_log_source_set(self):
        fields = self.docs["fields.yaml"]
        fields["custom_fields"].append({"name": "process", "log_sources": ["Sysmon"]})
        fields["metadata"]["total_fields"] = 2
        self.assertEqual(self.run_validation()["verdict"], "ACCEPT")
        fields["custom_fields"].append({"name": "process", "log_sources": ["Windows"]})
        fields["metadata"]["total_fields"] = 3
        self.assertIn("DUPLICATE_FIELD_KEY", self.codes(self.run_validation()))

    def test_invalid_counter_remains_machine_readable(self):
        import datetime
        self.docs["fields.yaml"]["metadata"]["total_fields"] = datetime.date(2026, 7, 11)
        result = self.run_validation()
        self.assertEqual(result["verdict"], "REJECT")
        json.dumps(result)

    def test_log_source_order_does_not_hide_duplicate(self):
        fields = self.docs["fields.yaml"]
        fields["custom_fields"] = [{"name": "x", "log_sources": sources} for sources in (["a", "b"], ["b", "a"])]
        fields["metadata"]["total_fields"] = 2
        self.assertIn("DUPLICATE_FIELD_KEY", self.codes(self.run_validation()))

    def test_dependencies_resolve_shared_and_rule_local_ids(self):
        rule = self.docs["full_rules85.yaml"]["rules"][0]
        rule["building_blocks"] = [{"bb_id": "local", "depends_on_bb": ["base"]}]
        rule["depends_on_bb"] = ["local"]
        self.assertEqual(self.run_validation()["verdict"], "ACCEPT")
        rule["building_blocks"][0]["depends_on_bb"] = ["missing"]
        self.assertIn("UNRESOLVED_BB", self.codes(self.run_validation()))

    def test_shared_dependency_cannot_use_other_rules_local_id(self):
        self.docs["shared_bbs.yaml"]["shared_building_blocks"][0]["depends_on_bb"] = ["missing"]
        self.assertIn("UNRESOLVED_BB", self.codes(self.run_validation()))

    def test_unknown_custom_field_is_rejected(self):
        self.docs["full_rules85.yaml"]["rules"][0]["custom_fields"] = [{"name": "invented"}]
        self.assertIn("UNKNOWN_CUSTOM_FIELD", self.codes(self.run_validation()))

    def test_sysmon_is_conditional_without_telemetry(self):
        rules = self.docs["full_rules85.yaml"]
        rules["rules"][0]["sysmon_required"] = True
        rules["metadata"].update(rules_with_sysmon=1, rules_without_sysmon=0)
        result = self.run_validation()
        self.assertEqual(result["verdict"], "CONDITIONAL")
        self.assertEqual(result["conditions"][0]["rule_id"], "rule")

    def test_synthetic_html_is_excluded_and_references_rejected(self):
        (self.staged / "concept.html").write_text("<html>invented</html>")
        result = self.run_validation()
        self.assertEqual(result["verdict"], "ACCEPT")
        self.assertIn("concept.html", result["excluded_inputs"])
        self.docs["fields.yaml"]["notes"] = "concepts/demo.html"
        self.assertIn("SYNTHETIC_CONTENT", self.codes(self.run_validation()))

    def test_trusted_config_cannot_reference_concepts(self):
        trusted = self.repo / "config/rules_inventory.yaml"
        trusted.write_text('source: concepts/design.html\n')
        before = trusted.read_bytes()
        self.assertIn("SYNTHETIC_CONTENT", self.codes(self.run_validation()))
        self.assertEqual(trusted.read_bytes(), before)

    def test_malformed_yaml_and_duplicate_mapping_keys_reject(self):
        self.run_validation()
        for content in ("rules: [", "rules: []\nrules: []\n"):
            (self.staged / "full_rules85.yaml").write_text(content)
            self.assertIn("INVALID_INPUT", self.codes(validator.validate(self.repo, self.staged)))

    def test_output_is_deterministic_and_does_not_modify_inputs(self):
        result = self.run_validation()
        before = {p.name: p.read_bytes() for p in self.staged.iterdir()}
        validator.write_reports(self.staged, result)
        first = (self.staged / "VALIDATION_REPORT.md").read_bytes()
        validator.write_reports(self.staged, result)
        self.assertEqual(first, (self.staged / "VALIDATION_REPORT.md").read_bytes())
        for name, raw in before.items():
            self.assertEqual(raw, (self.staged / name).read_bytes())

    def test_rejects_staging_outside_imports(self):
        with self.assertRaises(ValueError):
            validator.validate(self.repo, self.repo / "concepts")

    def test_real_staged_sources_and_cli(self):
        staged = ROOT / "config/imports/2026-07-11"
        for line in (staged / "SHA256SUMS.txt").read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            digest, name = line.split(maxsplit=1)
            self.assertEqual(hashlib.sha256((staged / name).read_bytes()).hexdigest(), digest)
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in staged.iterdir() if not p.name.startswith("VALIDATION_REPORT")}
        trusted = [ROOT / "config" / n for n in ("rules_inventory.yaml", "custom_fields_qradar.yaml")]
        before.update({p: hashlib.sha256(p.read_bytes()).hexdigest() for p in trusted})
        process = subprocess.run([sys.executable, str(ROOT / "scripts/validate_imports.py")], capture_output=True, text=True)
        self.assertEqual(process.returncode, 1, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result["verdict"], "REJECT")
        self.assertEqual(result["counts"]["total_rules"], {"declared": 346, "actual": 14})
        self.assertEqual(result["counts"]["total_shared_bbs"]["actual"], 67)
        self.assertEqual(result["counts"]["total_fields"]["actual"], 54)
        self.assertTrue(result["conditions"])
        self.assertNotIn("DUPLICATE_FIELD_KEY", self.codes(result))
        for path, digest in before.items():
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        self.assertEqual(json.loads((staged / "VALIDATION_REPORT.json").read_text()), result)


if __name__ == "__main__":
    unittest.main()
