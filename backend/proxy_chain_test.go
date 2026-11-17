package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// M7-E Phase 1.1: forwarded chain policy. A trusted peer does not make every
// forwarded element trustworthy.
func TestForwardedChainPolicy(t *testing.T) {
	set, err := parseTrustedProxies("127.0.0.1/32,10.0.0.0/8,::1/128")
	if err != nil {
		t.Fatal(err)
	}
	req := func(remote string, headers map[string]string) *http.Request {
		r := httptest.NewRequest("POST", "http://atlas.example/api/v1/test", nil)
		r.RemoteAddr = remote
		r.Host = "atlas.example"
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return r
	}
	ok := func(name string, remote string, hops int, headers map[string]string, want string) {
		t.Helper()
		got, err := forwardedClientIP(req(remote, headers), set, hops)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		if got != want {
			t.Fatalf("%s: client = %q, want %q", name, got, want)
		}
	}
	bad := func(name string, remote string, hops int, headers map[string]string) {
		t.Helper()
		if got, err := forwardedClientIP(req(remote, headers), set, hops); err == nil {
			t.Fatalf("%s: expected rejection, got %q", name, got)
		}
	}

	t.Run("proxy overwrites XFF", func(t *testing.T) {
		ok("overwrite", "127.0.0.1:5000", 1, map[string]string{"X-Forwarded-For": "203.0.113.5"}, "203.0.113.5")
	})
	t.Run("proxy appends to a spoofed XFF", func(t *testing.T) {
		// The client sent 198.51.100.9; the proxy appended the real peer.
		ok("append", "127.0.0.1:5000", 1, map[string]string{"X-Forwarded-For": "198.51.100.9, 203.0.113.5"}, "203.0.113.5")
	})
	t.Run("two trusted hops", func(t *testing.T) {
		// client, proxy1; both proxy1 and the immediate peer are trusted.
		ok("hops2", "127.0.0.1:5000", 2, map[string]string{"X-Forwarded-For": "198.51.100.9, 10.1.2.3"}, "198.51.100.9")
	})
	t.Run("two hops with an untrusted intermediate", func(t *testing.T) {
		bad("untrusted hop", "127.0.0.1:5000", 2, map[string]string{"X-Forwarded-For": "198.51.100.9, 203.0.113.7"})
	})
	t.Run("fewer entries than hops", func(t *testing.T) {
		bad("short chain", "127.0.0.1:5000", 2, map[string]string{"X-Forwarded-For": "203.0.113.5"})
	})
	t.Run("client inside the proxy ranges", func(t *testing.T) {
		bad("ambiguous", "127.0.0.1:5000", 1, map[string]string{"X-Forwarded-For": "10.9.9.9"})
	})
	t.Run("IPv4 and IPv6", func(t *testing.T) {
		ok("v4", "127.0.0.1:5000", 1, map[string]string{"X-Forwarded-For": "203.0.113.5"}, "203.0.113.5")
		ok("v6", "[::1]:5000", 1, map[string]string{"X-Forwarded-For": "2001:db8::5"}, "2001:db8::5")
		ok("v6 hops2", "[::1]:5000", 2, map[string]string{"X-Forwarded-For": "2001:db8::5, ::1"}, "2001:db8::5")
	})
	t.Run("X-Real-IP", func(t *testing.T) {
		ok("agree", "127.0.0.1:5000", 1, map[string]string{"X-Forwarded-For": "203.0.113.5", "X-Real-IP": "203.0.113.5"}, "203.0.113.5")
		bad("conflict", "127.0.0.1:5000", 1, map[string]string{"X-Forwarded-For": "203.0.113.5", "X-Real-IP": "203.0.113.6"})
		bad("alone without XFF", "127.0.0.1:5000", 1, map[string]string{"X-Real-IP": "203.0.113.5"})
		bad("alone inside proxies", "127.0.0.1:5000", 1, map[string]string{"X-Real-IP": "10.1.2.3"})
	})
	t.Run("malformed values", func(t *testing.T) {
		for name, value := range map[string]string{
			"port":      "203.0.113.5:443",
			"hostname":  "client.example",
			"brackets":  "[2001:db8::5]",
			"empty item": "203.0.113.5, , 198.51.100.7",
			"garbage":   "not-an-ip",
		} {
			bad(name, "127.0.0.1:5000", 1, map[string]string{"X-Forwarded-For": value})
		}
	})
	t.Run("no identity falls back to the peer", func(t *testing.T) {
		ok("peer", "127.0.0.1:5000", 1, nil, "127.0.0.1")
	})
}

func TestForwardedProtoConflicts(t *testing.T) {
	r := httptest.NewRequest("POST", "http://atlas.example/api/v1/test", nil)
	r.Host = "atlas.example"
	r.Header.Set("X-Forwarded-Proto", "http,https")
	if _, _, err := forwardedTarget(r); err == nil {
		t.Fatal("conflicting X-Forwarded-Proto must be rejected")
	}
	r.Header.Set("X-Forwarded-Proto", "https,https")
	scheme, _, err := forwardedTarget(r)
	if err != nil || scheme != "https" {
		t.Fatalf("repeated identical proto must be accepted: %q %v", scheme, err)
	}
}

func TestTrustedProxyConfig(t *testing.T) {
	t.Setenv(trustedProxiesEnv, "127.0.0.1")
	t.Setenv(trustedHopsEnv, "")
	if _, hops, err := loadTrustedProxyConfig(); err != nil || hops != 1 {
		t.Fatalf("default hops: %d %v", hops, err)
	}
	t.Setenv(trustedHopsEnv, "2")
	if _, hops, err := loadTrustedProxyConfig(); err != nil || hops != 2 {
		t.Fatalf("explicit hops: %d %v", hops, err)
	}
	t.Setenv(trustedHopsEnv, "0")
	if _, _, err := loadTrustedProxyConfig(); err == nil {
		t.Fatal("zero hops must be rejected")
	}
	t.Setenv(trustedProxiesEnv, "")
	t.Setenv(trustedHopsEnv, "2")
	if _, _, err := loadTrustedProxyConfig(); err == nil {
		t.Fatal("hops without an allowlist must be rejected")
	}
}

// Attribution: two clients behind one trusted proxy must not share a bucket.
func TestRateLimitAttributionUsesValidatedChain(t *testing.T) {
	set, err := parseTrustedProxies("127.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	h := proxyTrustMiddleware(set, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, requestClientIP(r))
	}))
	for _, xff := range []string{"198.51.100.1, 203.0.113.5", "198.51.100.2, 203.0.113.6"} {
		r := httptest.NewRequest("POST", "http://atlas.example/api/v1/auth/login", nil)
		r.RemoteAddr = "127.0.0.1:5000"
		r.Header.Set("X-Forwarded-For", xff)
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if len(seen) != 2 || seen[0] != "203.0.113.5" || seen[1] != "203.0.113.6" {
		t.Fatalf("rate-limit attribution = %v", seen)
	}
	// Limiter buckets are per address, so the two clients are independent.
	rl := newRateLimiter()
	if !rl.allow(seen[0]) || !rl.allow(seen[1]) {
		t.Fatal("distinct clients must start with separate buckets")
	}
}
