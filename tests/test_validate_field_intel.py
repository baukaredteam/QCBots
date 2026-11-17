import copy
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.validate_field_intel import validate


class FieldIntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.inventory = {"fields": [{"field_name": name, "is_active": True} for name in ("username", "source_ip")]}
        self.snapshot = {
            "schema_version": 1,
            "field_states": [{"name": name, "from_status": "CANDIDATE", "status": "AQL VERIFIED", "evidence_id": name} for name in ("username", "source_ip")],
            "manual_evidence": [{"id": name, "kind": "MANUAL_QRADAR_SEARCH", "field_name": name, "result": "SUCCESS", "reviewer_id": "analyst-demo", "reviewer_role": "CTI_ANALYST", "reviewed_at": "2026-11-17T17:00:00Z", "evidence_ref": "local-proof-demo", "synthetic": False} for name in ("username", "source_ip")],
            "aql_drafts": [{"query": "SELECT username FROM events WHERE source_ip = 'example' LAST 24 HOURS"}],
            "bindings": [{"client_id": "demo-client", "domain_id": 1, "active": False}],
            "coverage": [{"status": "UNKNOWN", "sigma": True, "kql": True, "spl": True}],
            "telemetry": [{"status": "NO_RECENT_EVENTS", "event_count": 0, "threat_before": "UNKNOWN", "threat_after": "UNKNOWN"}],
            "audit": [{"event": "FIELD_REVIEW", "actor_id": "demo-analyst", "action": "REVIEW", "outcome": "PENDING"}],
        }

    def result(self):
        return validate(self.snapshot, self.inventory)

    def codes(self):
        return {error["code"] for error in self.result()["errors"]}

    def test_valid_local_snapshot(self):
        self.assertEqual(self.result()["verdict"], "ACCEPT")

    def test_all_aql_references_require_inventory(self):
        for query in ("SELECT invented FROM events", "SELECT username FROM events WHERE invented = 1", 'SELECT "Private Property" FROM events', "SELECT COUNT(invented) AS n FROM events"):
            with self.subTest(query=query):
                self.snapshot["aql_drafts"][0]["query"] = query
                self.assertIn("AQL_FIELD_NOT_IN_INVENTORY", self.codes())

    def test_aql_literals_aliases_functions_are_not_invented_fields(self):
        for query in ("SELECT COUNT(username) AS n FROM events ORDER BY n", "SELECT username FROM events WHERE username IN ('unknown-field', 'another')", 'SELECT "username" FROM events WHERE source_ip = \'quoted value\''):
            with self.subTest(query=query):
                self.snapshot["aql_drafts"][0]["query"] = query
                self.assertEqual(self.result()["verdict"], "ACCEPT")

    def test_unsupported_sql_fails_closed(self):
        for query in ("SELECT * FROM events", "SELECT username FROM events; SELECT invented FROM events", "SELECT username FROM events -- hidden", "SELECT username FROM (SELECT invented FROM events)", "SELECT CUSTOM(invented) FROM events"):
            with self.subTest(query=query):
                self.snapshot["aql_drafts"][0]["query"] = query
                self.assertEqual(self.result()["verdict"], "REJECT")

    def test_inactive_inventory_field_is_not_available(self):
        self.inventory["fields"][0]["is_active"] = False
        self.assertIn("AQL_FIELD_NOT_IN_INVENTORY", self.codes())

    def test_candidate_unknown_cannot_be_used_in_aql(self):
        for status in ("CANDIDATE", "UNKNOWN"):
            self.snapshot["field_states"][0]["status"] = status
            self.assertIn("AQL_FIELD_NOT_VERIFIED", self.codes())

    def test_promotion_requires_separate_matching_manual_proof(self):
        original = copy.deepcopy(self.snapshot)
        for origin in ("CANDIDATE", "UNKNOWN"):
            for change in ({"kind": "RAW_SAMPLE"}, {"kind": "DEMO VERIFIED"}, {"synthetic": True}, {"field_name": "other"}, {"result": "FAILURE"}, {"reviewer_id": ""}, {"evidence_ref": ""}, {"reviewer_role": "READ_ONLY"}):
                with self.subTest(origin=origin, change=change):
                    self.snapshot = copy.deepcopy(original)
                    self.snapshot["field_states"][0]["from_status"] = origin
                    self.snapshot["manual_evidence"][0].update(change)
                    self.assertIn("MANUAL_AQL_EVIDENCE_REQUIRED", self.codes())
        self.snapshot = original
        self.snapshot["manual_evidence"] = []
        self.assertIn("MANUAL_AQL_EVIDENCE_REQUIRED", self.codes())

    def test_active_binding_requires_admin_and_exact_scope(self):
        self.snapshot["bindings"][0].update(active=True, approval_id="approval")
        self.assertIn("ADMIN_APPROVAL_REQUIRED", self.codes())
        approval = {"id": "approval", "client_id": "demo-client", "domain_id": 1, "role": "ADMINISTRATOR", "decision": "APPROVED", "reviewer_id": "admin-demo", "reviewed_at": "2026-11-17T17:00:00Z", "evidence_ref": "local-admin-proof", "synthetic": False}
        self.snapshot["admin_approvals"] = [approval]
        self.assertEqual(self.result()["verdict"], "ACCEPT")
        for change in ({"client_id": "other-client"}, {"domain_id": 2}, {"role": "CTI_ANALYST"}, {"decision": "PENDING"}, {"synthetic": True}):
            with self.subTest(change=change):
                self.snapshot["admin_approvals"] = [{**approval, **change}]
                self.assertIn("ADMIN_APPROVAL_REQUIRED", self.codes())

    def test_sigma_kql_spl_do_not_raise_coverage(self):
        for format_name in ("sigma", "kql", "spl"):
            for status in ("PARTIAL", "COVERED"):
                self.snapshot["coverage"] = [{"status": status, format_name: True}]
                self.assertIn("UNSUPPORTED_COVERAGE", self.codes())

    def test_coverage_requires_independent_facts(self):
        facts = {name: True for name in ("rule_exists", "fields_available", "telemetry_available", "rule_tested", "detection_observed")}
        self.snapshot["coverage"] = [{"status": "COVERED", **facts}]
        self.assertEqual(self.result()["verdict"], "ACCEPT")
        for flag in facts:
            self.snapshot["coverage"] = [{"status": "COVERED", **facts, flag: False}]
            self.assertIn("UNSUPPORTED_COVERAGE", self.codes())
        self.snapshot["coverage"] = [{"status": "PARTIAL", **facts, "detection_observed": False}]
        self.assertEqual(self.result()["verdict"], "ACCEPT")

    def test_no_events_never_dismiss_threat(self):
        for status in ("CONNECTED", "NOT_CONNECTED", "NO_RECENT_EVENTS", "UNKNOWN"):
            self.snapshot["telemetry"] = [{"status": status, "event_count": 0, "threat_before": "SUSPECTED", "threat_after": "DISMISSED"}]
            self.assertIn("ABSENCE_IS_NOT_THREAT_EVIDENCE", self.codes())
            self.snapshot["telemetry"][0]["threat_after"] = "SUSPECTED"
            self.assertEqual(self.result()["verdict"], "ACCEPT")

    def test_invalid_telemetry_status_and_counts_reject(self):
        for change in ({"status": "NO_THREAT"}, {"event_count": -1}, {"event_count": False}):
            self.snapshot["telemetry"][0].update(change)
            self.assertIn("INVALID_TELEMETRY", self.codes())

    def test_logs_and_audit_reject_private_data_without_echo(self):
        for section in ("logs", "audit"):
            for record in ({"event": "FIELD_REVIEW", "password": "CANARY-123"}, {"event": "FIELD_REVIEW", "payload": "PRIVATE-CANARY"}, {"event": "FIELD_REVIEW", "metadata": {"token": "CANARY"}}, {"event": "FIELD_REVIEW", "actor_id": "Bearer-CANARY"}, {"event": "FIELD_REVIEW", "action": "PRIVATE-CANARY"}):
                with self.subTest(section=section, record=record):
                    self.snapshot[section] = [record]
                    result = self.result()
                    self.assertEqual(result["verdict"], "REJECT")
                    self.assertNotIn("CANARY", json.dumps(result))

    def test_validation_has_no_network_or_writes_or_mutation(self):
        original = copy.deepcopy(self.snapshot)
        inventory = copy.deepcopy(self.inventory)
        with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")), patch.object(Path, "write_text", side_effect=AssertionError("writes forbidden")), patch.object(Path, "write_bytes", side_effect=AssertionError("writes forbidden")):
            self.assertEqual(self.result()["verdict"], "ACCEPT")
        self.assertEqual(self.snapshot, original)
        self.assertEqual(self.inventory, inventory)

    def test_cli_exit_codes_safe_errors_and_unchanged_inventory(self):
        trusted = [ROOT / "config" / name for name in ("custom_fields_qradar.yaml", "rules_inventory.yaml")]
        before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in trusted}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            for data, expected in ((self.snapshot, 0), ({**self.snapshot, "logs": [{"event": "FIELD_REVIEW", "token": "SECRET-CANARY"}]}, 1)):
                path.write_text(json.dumps(data))
                process = subprocess.run([sys.executable, str(ROOT / "scripts/validate_field_intel.py"), str(path)], capture_output=True, text=True)
                self.assertEqual(process.returncode, expected, process.stderr)
                self.assertEqual(process.stderr, "")
                self.assertNotIn("CANARY", process.stdout)
                json.loads(process.stdout)
            path.write_text('password: SECRET-CANARY\ninvalid: [')
            process = subprocess.run([sys.executable, str(ROOT / "scripts/validate_field_intel.py"), str(path)], capture_output=True, text=True)
            self.assertEqual(process.returncode, 1)
            self.assertNotIn("CANARY", process.stdout + process.stderr)
        for path, digest in before.items():
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_malformed_shapes_reject_without_throwing(self):
        for snapshot in (None, [], {"schema_version": 1, "field_states": ["bad"]}, {"schema_version": 1, "field_states": [{"name": []}]}, {"schema_version": 1, "unexpected": "data"}):
            self.assertEqual(validate(snapshot, self.inventory)["verdict"], "REJECT")


if __name__ == "__main__":
    unittest.main()
