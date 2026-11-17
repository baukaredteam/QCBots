package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// M7-E Phase 1: forwarded headers are only trusted from configured proxies, and
// CSRF uses only validated request state.
func TestProxyTrustAndCSRF(t *testing.T) {
	trusted, err := parseTrustedProxies("127.0.0.1/32,10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	untrusted := &proxyTrustSet{}
	cv := NewCSRFValidator([]string{"http://localhost:5173"}, false)

	// Run the request through the proxy middleware, then CSRF validation.
	run := func(set *proxyTrustSet, r *http.Request) (int, bool) {
		called := false
		h := proxyTrustMiddleware(set, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			if !cv.Validate(r) {
				w.WriteHeader(http.StatusForbidden)
			}
		}))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code, called
	}
	req := func(method, host, remote, origin string, tlsOn bool, headers map[string]string) *http.Request {
		r := httptest.NewRequest(method, "http://"+host+"/api/v1/test", nil)
		r.Host = host
		r.RemoteAddr = remote
		if tlsOn {
			r.TLS = &tls.ConnectionState{}
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return r
	}
	loopback := "127.0.0.1:5000"
	remote := "203.0.113.9:5000"

	t.Run("direct backend same-origin", func(t *testing.T) {
		code, _ := run(untrusted, req("POST", "localhost:18081", loopback, "http://localhost:18081", false, nil))
		if code != http.StatusOK {
			t.Fatalf("direct same-origin must pass, got %d", code)
		}
	})
	t.Run("direct TLS same-origin", func(t *testing.T) {
		code, _ := run(untrusted, req("POST", "atlas.example", loopback, "https://atlas.example", true, nil))
		if code != http.StatusOK {
			t.Fatalf("direct TLS must pass, got %d", code)
		}
	})
	t.Run("trusted proxy HTTPS termination", func(t *testing.T) {
		r := req("POST", "10.0.0.5:8080", loopback, "https://atlas.example", false, map[string]string{
			"X-Forwarded-Proto": "https", "X-Forwarded-Host": "atlas.example",
		})
		if code, called := run(trusted, r); code != http.StatusOK || !called {
			t.Fatalf("trusted proxy HTTPS must pass, got %d called=%v", code, called)
		}
	})
	t.Run("untrusted client cannot spoof forwarded headers", func(t *testing.T) {
		r := req("POST", "localhost:18081", remote, "https://atlas.example", false, map[string]string{
			"X-Forwarded-Proto": "https", "X-Forwarded-Host": "atlas.example",
		})
		if code, called := run(untrusted, r); code != http.StatusForbidden || called {
			t.Fatalf("spoofed forwarded headers must be rejected before the handler, got %d called=%v", code, called)
		}
	})
	t.Run("trusted proxy with malformed proto", func(t *testing.T) {
		r := req("POST", "10.0.0.5:8080", loopback, "https://atlas.example", false, map[string]string{
			"X-Forwarded-Proto": "javascript",
		})
		if code, _ := run(trusted, r); code != http.StatusBadRequest {
			t.Fatalf("malformed proto must be 400, got %d", code)
		}
	})
	t.Run("trusted proxy with host list", func(t *testing.T) {
		r := req("POST", "10.0.0.5:8080", loopback, "https://atlas.example", false, map[string]string{
			"X-Forwarded-Host": "atlas.example, evil.example",
		})
		if code, _ := run(trusted, r); code != http.StatusBadRequest {
			t.Fatalf("host list must be 400, got %d", code)
		}
	})
	t.Run("trusted proxy with path in host", func(t *testing.T) {
		r := req("POST", "10.0.0.5:8080", loopback, "https://atlas.example", false, map[string]string{
			"X-Forwarded-Host": "atlas.example/evil",
		})
		if code, _ := run(trusted, r); code != http.StatusBadRequest {
			t.Fatalf("host with a path must be 400, got %d", code)
		}
	})
	t.Run("foreign origin still rejected", func(t *testing.T) {
		code, _ := run(untrusted, req("POST", "localhost:18081", loopback, "http://evil.example", false, nil))
		if code != http.StatusForbidden {
			t.Fatalf("foreign origin must be rejected, got %d", code)
		}
	})
	t.Run("wrong scheme rejected", func(t *testing.T) {
		code, _ := run(untrusted, req("POST", "atlas.example", loopback, "https://atlas.example", false, nil))
		if code != http.StatusForbidden {
			t.Fatalf("scheme mismatch must be rejected, got %d", code)
		}
	})
	t.Run("wrong port rejected", func(t *testing.T) {
		code, _ := run(untrusted, req("POST", "localhost:18081", loopback, "http://localhost:9999", false, nil))
		if code != http.StatusForbidden {
			t.Fatalf("port mismatch must be rejected, got %d", code)
		}
	})
	t.Run("configured allowlist still works", func(t *testing.T) {
		code, _ := run(untrusted, req("POST", "api.internal:8080", loopback, "http://localhost:5173", false, nil))
		if code != http.StatusOK {
			t.Fatalf("configured origin must pass, got %d", code)
		}
	})
	t.Run("safe GET without origin", func(t *testing.T) {
		code, _ := run(untrusted, req("GET", "localhost:18081", loopback, "", false, nil))
		if code != http.StatusOK {
			t.Fatalf("GET must pass, got %d", code)
		}
	})
}

func TestParseTrustedProxiesRejectsBadInput(t *testing.T) {
	for _, spec := range []string{"not-an-ip", "10.0.0.0/33", "example.com", "127.0.0.1, bad"} {
		if _, err := parseTrustedProxies(spec); err == nil {
			t.Fatalf("invalid trusted proxy spec accepted: %q", spec)
		}
	}
	set, err := parseTrustedProxies(" 127.0.0.1 , ::1 , 10.0.0.0/8 ")
	if err != nil {
		t.Fatal(err)
	}
	if len(set.nets) != 3 {
		t.Fatalf("expected three networks, got %d", len(set.nets))
	}
}
