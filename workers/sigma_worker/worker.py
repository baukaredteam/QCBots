#!/usr/bin/env python3
"""Sentinel Atlas Sigma -> IBM QRadar AQL worker (Phase 2B-3).

Reads one JSON request on stdin, writes one JSON response on stdout.

Constraints enforced here:
  * no network access, no database access, no QRadar credentials;
  * input is parsed as data by pySigma, never executed;
  * the only configuration accepted is a field-map dictionary supplied by the Go
    orchestrator (already resolved from the client's approved registry);
  * output is bounded and carries an explicit status.

Protocol: sentinel.sigma.worker/1
"""

import json
import sys
import traceback

PROTOCOL = "sentinel.sigma.worker/1"
WORKER_VERSION = "1"
MAX_INPUT_BYTES = 512 * 1024
MAX_FIELD_MAP = 500
MAX_LIST = 200

ALLOWED_MODES = {"VERIFIED_FIELDS_ONLY", "REVIEW_REQUIRED_FIELDS", "PAYLOAD_FALLBACK"}


def fail(request_id, code, message, **extra):
    out = {
        "protocol": PROTOCOL,
        "request_id": request_id,
        "status": "ERROR",
        "error_code": code,
        "errors": [message],
        "worker_version": WORKER_VERSION,
    }
    out.update(extra)
    return out


def main():
    raw = sys.stdin.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        print(json.dumps(fail("", "INPUT_TOO_LARGE", "request exceeds worker input limit")))
        return 0
    try:
        req = json.loads(raw)
    except Exception as exc:
        print(json.dumps(fail("", "BAD_JSON", "request is not valid JSON: %s" % exc)))
        return 0

    if not isinstance(req, dict) or req.get("protocol") != PROTOCOL:
        print(json.dumps(fail("", "BAD_PROTOCOL", "unsupported or missing protocol")))
        return 0

    request_id = str(req.get("request_id", ""))[:128]
    sigma_yaml = req.get("sigma_yaml")
    field_map = req.get("field_map")
    mode = req.get("mode", "VERIFIED_FIELDS_ONLY")
    sigma_sha256 = str(req.get("sigma_sha256", ""))[:128]

    if not isinstance(sigma_yaml, str) or not sigma_yaml.strip():
        print(json.dumps(fail(request_id, "BAD_REQUEST", "sigma_yaml is required")))
        return 0
    if len(sigma_yaml.encode("utf-8")) > MAX_INPUT_BYTES:
        print(json.dumps(fail(request_id, "INPUT_TOO_LARGE", "sigma_yaml exceeds limit")))
        return 0
    if not isinstance(field_map, dict) or len(field_map) > MAX_FIELD_MAP:
        print(json.dumps(fail(request_id, "BAD_REQUEST", "field_map must be a bounded object")))
        return 0
    if mode not in ALLOWED_MODES:
        print(json.dumps(fail(request_id, "BAD_MODE", "unsupported conversion mode")))
        return 0

    result = {
        "protocol": PROTOCOL,
        "request_id": request_id,
        "sigma_sha256": sigma_sha256,
        "worker_version": WORKER_VERSION,
        "mode": mode,
        "converted_fields": [],
        "unmapped_fields": [],
        "unsupported_conditions": [],
        "warnings": [],
        "backend_version": "",
        "pysigma_version": "",
    }

    try:
        import sigma as pysigma_pkg  # noqa: F401
        from sigma.collection import SigmaCollection
        from sigma.backends.QRadarAQL import QRadarAQLBackend
        from sigma.pipelines.QRadarAQL import QRadarAQL as qradar_base
        from importlib.metadata import version as pkg_version

        result["pysigma_version"] = pkg_version("pysigma")
        result["backend_version"] = pkg_version("pysigma-backend-qradar-aql")
    except Exception as exc:
        print(json.dumps(fail(request_id, "WORKER_DEPENDENCY_MISSING", str(exc))))
        return 0

    # Authoritative parse. A structural Go check earlier is preliminary only.
    try:
        rules = SigmaCollection.from_yaml(sigma_yaml)
    except Exception as exc:
        result["status"] = "PARSE_ERROR"
        result["errors"] = [str(exc)]
        print(json.dumps(result))
        return 0

    if len(rules.rules) != 1:
        result["status"] = "UNSUPPORTED"
        result["unsupported_conditions"] = ["document must contain exactly one Sigma rule, found %d" % len(rules.rules)]
        print(json.dumps(result))
        return 0

    if mode == "PAYLOAD_FALLBACK":
        # The IBM base ships a payload pipeline, but switching an approved
        # field-based rule to raw payload matching silently changes semantics.
        # It is refused until that trade-off is reviewed explicitly.
        result["status"] = "UNSUPPORTED"
        result["unsupported_conditions"] = ["PAYLOAD_FALLBACK is not enabled in this worker version"]
        print(json.dumps(result))
        return 0

    # Client-specific mapping, already authorised and resolved by Go. Fields not
    # present here are reported as unmapped instead of being guessed.
    mapping = {}
    for k, v in field_map.items():
        if isinstance(k, str) and isinstance(v, str) and k.strip() and v.strip():
            mapping[k] = v

    rule_obj = rules.rules[0]
    used_fields = set()
    try:
        for identifier in rule_obj.detection.parsed_condition:
            pass
    except Exception:
        pass
    try:
        for det in rule_obj.detection.detections.values():
            for item in getattr(det, "detection_items", []):
                field = getattr(item, "field", None)
                if field:
                    used_fields.add(field)
    except Exception:
        pass

    mapped = {}
    for field in sorted(used_fields):
        if field in mapping:
            mapped[field] = mapping[field]
        else:
            result["unmapped_fields"].append(field)

    result["converted_fields"] = sorted(mapped.keys())

    mode_map = {
        "VERIFIED_FIELDS_ONLY": "strict",
        "REVIEW_REQUIRED_FIELDS": "review",
    }

    try:
        pipeline = qradar_base.QRadar_fields_pipeline(qradar_base.base_pipeline_items, mapping)
    except Exception as exc:
        print(json.dumps(fail(request_id, "PIPELINE_ERROR", str(exc), **{
            "sigma_sha256": sigma_sha256,
            "pysigma_version": result["pysigma_version"],
            "backend_version": result["backend_version"],
        })))
        return 0

    try:
        backend = QRadarAQLBackend(processing_pipeline=pipeline)
        converted = backend.convert(rules)
    except Exception as exc:
        msg = str(exc)
        result["status"] = "UNSUPPORTED"
        result["unsupported_conditions"] = [msg[:500]]
        result["errors"] = [msg[:500]]
        print(json.dumps(result))
        return 0

    if not converted:
        result["status"] = "UNSUPPORTED"
        result["unsupported_conditions"] = ["backend produced no query"]
        print(json.dumps(result))
        return 0

    if len(converted) > 1:
        # Multiple queries would need an explicit union policy; refusing is safer
        # than silently keeping the first one.
        result["status"] = "UNSUPPORTED"
        result["unsupported_conditions"] = ["backend produced %d queries; multi-query translation is not supported" % len(converted)]
        print(json.dumps(result))
        return 0

    result["status"] = "OK"
    result["aql"] = converted[0][:MAX_INPUT_BYTES]
    result["translation_mode"] = mode_map.get(mode, "review")
    if result["unmapped_fields"]:
        result["warnings"].append("unmapped fields: " + ", ".join(result["unmapped_fields"][:MAX_LIST]))
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc(file=sys.stderr)
        print(json.dumps({
            "protocol": PROTOCOL,
            "status": "ERROR",
            "error_code": "WORKER_CRASH",
            "errors": ["worker crashed; see stderr"],
            "worker_version": WORKER_VERSION,
        }))
        sys.exit(1)
