# Sigma → QRadar AQL worker (Phase 2B-3)

Local, offline worker that turns one Sigma rule into one IBM QRadar AQL candidate.
It is orchestrated by the Go backend and has no credentials, no database access
and no network use.

## Install (isolated venv)

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Windows
.venv/bin/python -m pip install -r requirements.txt       # POSIX
```

## Run

The worker reads one JSON request on stdin and writes one JSON response on stdout:

```bash
echo '{"protocol":"sentinel.sigma.worker/1","request_id":"r1","sigma_yaml":"...","field_map":{"EventID":"event_id"}}' \
  | .venv/bin/python worker.py
```

The backend configures it with:

| Variable | Meaning |
|---|---|
| `SIGMA_WORKER_PYTHON` | interpreter to run (e.g. `.venv/Scripts/python.exe`); unset ⇒ translations are reported BLOCKED, never faked |
| `SIGMA_WORKER_SCRIPT` | path to `worker.py` (default `workers/sigma_worker/worker.py`) |
| `SIGMA_WORKER_TIMEOUT_MS` | hard timeout (default 15000) |

## Protocol

`sentinel.sigma.worker/1`

Request: `protocol`, `request_id`, `sigma_yaml`, `sigma_sha256`, `field_map`
(raw Sigma field → QRadar AQL expression, resolved and authorised by Go), `mode`
(`VERIFIED_FIELDS_ONLY` | `REVIEW_REQUIRED_FIELDS` | `PAYLOAD_FALLBACK`).

Response: `status` (`OK` | `UNSUPPORTED` | `PARSE_ERROR` | `ERROR`), `aql`,
`converted_fields`, `unmapped_fields`, `unsupported_conditions`, `warnings`,
`worker_version`, `pysigma_version`, `backend_version`, `sigma_sha256`,
`request_id`, and `error_code`/`errors` on failure.

## Deliberate limits

- Exactly one Sigma rule per request; multiple queries are refused rather than
  truncated to the first.
- `PAYLOAD_FALLBACK` is refused in this worker version: switching an approved
  field-based rule to raw payload matching changes semantics and needs review.
- The worker never decides tenant scope. The Go layer validates the AQL and
  prepends the verified native domain constraint itself.
- Successful AQL text is not proof of semantic equivalence.
