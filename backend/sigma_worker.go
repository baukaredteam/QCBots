package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// M7-D Phase 2B-3: Go side of the local Sigma worker.
//
// The worker is a separate process with no credentials, no database access and no
// network use. Go owns authorisation, tenant scope and AQL validation; the worker
// only converts. Every response is treated as untrusted input.

const (
	sigmaWorkerProtocol    = "sentinel.sigma.worker/1"
	sigmaWorkerVersion     = "1"
	maxWorkerOutputBytes   = 256 << 10
	defaultWorkerTimeoutMs = 15000
)

var (
	ErrWorkerUnavailable = errors.New("SIGMA_WORKER_UNAVAILABLE")
	ErrWorkerProtocol    = errors.New("SIGMA_WORKER_PROTOCOL")
	ErrAQLInvalid        = errors.New("AQL_INVALID")
)

type sigmaWorkerRequest struct {
	Protocol   string            `json:"protocol"`
	RequestID  string            `json:"request_id"`
	SigmaYAML  string            `json:"sigma_yaml"`
	SigmaSHA   string            `json:"sigma_sha256"`
	FieldMap   map[string]string `json:"field_map"`
	Mode       string            `json:"mode"`
	Logsource  map[string]string `json:"logsource,omitempty"`
	Limits     map[string]int    `json:"limits,omitempty"`
}

type sigmaWorkerResponse struct {
	Protocol             string   `json:"protocol"`
	RequestID            string   `json:"request_id"`
	Status               string   `json:"status"`
	AQL                  string   `json:"aql"`
	SigmaSHA             string   `json:"sigma_sha256"`
	WorkerVersion        string   `json:"worker_version"`
	PySigmaVersion       string   `json:"pysigma_version"`
	BackendVersion       string   `json:"backend_version"`
	ConvertedFields      []string `json:"converted_fields"`
	UnmappedFields       []string `json:"unmapped_fields"`
	UnsupportedConditions []string `json:"unsupported_conditions"`
	Warnings             []string `json:"warnings"`
	ErrorCode            string   `json:"error_code"`
	Errors               []string `json:"errors"`
	// Filled by Go, not by the worker: the exact script that ran.
	WorkerScriptSHA256 string `json:"-"`
}

// workerCommand is injectable so tests can exercise protocol handling without a
// Python environment. Production always uses run().
var workerCommand = run()

// resolveWorkerScript returns the configured worker path, preferring env.
func resolveWorkerScript() string {
	if script := strings.TrimSpace(os.Getenv("SIGMA_WORKER_SCRIPT")); script != "" {
		return script
	}
	candidate := filepath.Join("..", "workers", "sigma_worker", "worker.py")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return filepath.Join("workers", "sigma_worker", "worker.py")
}

func run() func(ctx context.Context, req sigmaWorkerRequest) ([]byte, []byte, error) {
	return func(ctx context.Context, req sigmaWorkerRequest) ([]byte, []byte, error) {
		python := strings.TrimSpace(os.Getenv("SIGMA_WORKER_PYTHON"))
		if python == "" {
			return nil, nil, fmt.Errorf("%w: SIGMA_WORKER_PYTHON is not configured", ErrWorkerUnavailable)
		}
		script := resolveWorkerScript()
		if _, err := os.Stat(script); err != nil {
			return nil, nil, fmt.Errorf("%w: worker script not found: %s", ErrWorkerUnavailable, script)
		}
		if want := strings.TrimSpace(os.Getenv("SIGMA_WORKER_SCRIPT_SHA256")); want != "" {
			if got := fileSHA256(script); !strings.EqualFold(got, want) {
				return nil, nil, fmt.Errorf("%w: worker script hash mismatch", ErrWorkerIntegrity)
			}
		}
		payload, err := json.Marshal(req)
		if err != nil {
			return nil, nil, err
		}
		// -I: isolated mode (ignores PYTHON* env vars and user site-packages).
		// -B: no .pyc writes, so the worker cannot leave files behind.
		cmd := exec.CommandContext(ctx, python, "-I", "-B", script)
		cmd.Dir = filepath.Dir(script)
		cmd.Stdin = bytes.NewReader(payload)
		// A minimal environment: no proxy, no cloud credentials, nothing to leak.
		cmd.Env = []string{
			"PYTHONIOENCODING=utf-8",
			"PYTHONNOUSERSITE=1",
			"NO_PROXY=*",
			"PATH=" + os.Getenv("PATH"),
		}
		var out limitedBuffer
		var errBuf limitedBuffer
		out.limit = maxWorkerOutputBytes
		errBuf.limit = 4096
		cmd.Stdout = &out
		cmd.Stderr = &errBuf
		runErr := cmd.Run()
		if runErr != nil && ctx.Err() == context.DeadlineExceeded && cmd.Process != nil {
			killProcessTree(cmd.Process.Pid)
		}
		return out.Bytes(), errBuf.Bytes(), runErr
	}
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.limit > 0 && b.Len()+len(p) > b.limit {
		return 0, fmt.Errorf("worker output exceeded %d bytes", b.limit)
	}
	return b.Buffer.Write(p)
}

func workerTimeout() time.Duration {
	if v := os.Getenv("SIGMA_WORKER_TIMEOUT_MS"); v != "" {
		if ms, err := time.ParseDuration(v + "ms"); err == nil && ms > 0 && ms <= 120*time.Second {
			return ms
		}
	}
	return defaultWorkerTimeoutMs * time.Millisecond
}

// CallSigmaWorker runs one conversion and validates the protocol envelope.
func CallSigmaWorker(ctx context.Context, sigmaYAML, sigmaSHA string, fieldMap map[string]string, mode string) (*sigmaWorkerResponse, error) {
	if mode != "VERIFIED_FIELDS_ONLY" && mode != "REVIEW_REQUIRED_FIELDS" && mode != "PAYLOAD_FALLBACK" {
		return nil, fmt.Errorf("%w: unknown conversion mode", ErrFieldImportInvalid)
	}
	sum := sha256.Sum256([]byte(sigmaYAML))
	hash := hex.EncodeToString(sum[:])
	if sigmaSHA != "" && sigmaSHA != hash {
		return nil, fmt.Errorf("%w: sigma hash mismatch", ErrWorkerProtocol)
	}
	req := sigmaWorkerRequest{
		Protocol:  sigmaWorkerProtocol,
		RequestID: newID("sigreq"),
		SigmaYAML: sigmaYAML,
		SigmaSHA:  hash,
		FieldMap:  fieldMap,
		Mode:      mode,
		Limits:    map[string]int{"max_output_bytes": maxWorkerOutputBytes, "timeout_ms": int(workerTimeout().Milliseconds())},
	}
	reqCtx, cancel := context.WithTimeout(ctx, workerTimeout())
	defer cancel()

	stdout, stderr, err := workerCommand(reqCtx, req)
	if err != nil {
		if errors.Is(err, ErrWorkerUnavailable) {
			return nil, err
		}
		if reqCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("%w: worker timed out", ErrWorkerProtocol)
		}
		return nil, fmt.Errorf("%w: %v (stderr: %s)", ErrWorkerProtocol, err, truncate(string(stderr), 200))
	}
	if len(stdout) > maxWorkerOutputBytes {
		return nil, fmt.Errorf("%w: worker output too large", ErrWorkerProtocol)
	}
	var resp sigmaWorkerResponse
	if err := json.Unmarshal(stdout, &resp); err != nil {
		return nil, fmt.Errorf("%w: response is not valid JSON", ErrWorkerProtocol)
	}
	if resp.Protocol != sigmaWorkerProtocol {
		return nil, fmt.Errorf("%w: unexpected protocol %q", ErrWorkerProtocol, resp.Protocol)
	}
	if resp.RequestID != req.RequestID {
		return nil, fmt.Errorf("%w: request id mismatch", ErrWorkerProtocol)
	}
	if resp.Status == "OK" {
		if resp.SigmaSHA != hash {
			return nil, fmt.Errorf("%w: sigma hash mismatch in response", ErrWorkerProtocol)
		}
		if strings.TrimSpace(resp.AQL) == "" {
			return nil, fmt.Errorf("%w: OK response without AQL", ErrWorkerProtocol)
		}
		if resp.WorkerVersion == "" || resp.BackendVersion == "" || resp.PySigmaVersion == "" {
			return nil, fmt.Errorf("%w: OK response without version provenance", ErrWorkerProtocol)
		}
	}
	switch resp.Status {
	case "OK", "UNSUPPORTED", "PARSE_ERROR", "ERROR":
	default:
		return nil, fmt.Errorf("%w: unknown status %q", ErrWorkerProtocol, resp.Status)
	}
	// Bound the diagnostics we are willing to persist.
	resp.UnmappedFields = boundStrings(resp.UnmappedFields, 100)
	resp.UnsupportedConditions = boundStrings(resp.UnsupportedConditions, 50)
	resp.Warnings = boundStrings(resp.Warnings, 50)
	resp.Errors = boundStrings(resp.Errors, 20)
	resp.WorkerScriptSHA256 = fileSHA256(resolveWorkerScript())
	return &resp, nil
}

func boundStrings(in []string, max int) []string {
	if len(in) <= max {
		return in
	}
	out := append([]string(nil), in[:max]...)
	out = append(out, "... truncated")
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

var (
	ErrWorkerIntegrity = errors.New("SIGMA_WORKER_INTEGRITY")
)

// fileSHA256 hashes a file for optional worker integrity pinning.
func fileSHA256(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// killProcessTree is a best-effort tree termination on Windows. The worker is a
// single Python process that spawns no children, so this is defence in depth, not
// a sandbox: it is reported as partial isolation.
func killProcessTree(pid int) {
	if pid <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "taskkill", "/T", "/F", "/PID", strconv.Itoa(pid)).Run()
}
