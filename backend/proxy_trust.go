package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// M7-E Phase 1.1: trusted proxy chain policy.
//
// Forwarded headers are data, not authority. They are honoured only when the
// immediate TCP peer is in WORKBENCH_TRUSTED_PROXIES, and even then only a
// configured number of right-most X-Forwarded-For entries are trusted:
//
//	X-Forwarded-For: <client-controlled...>, <client>, <proxy N-1>, ..., <proxy 1>
//	                                              ^-- selected with hops = N
//
// WORKBENCH_TRUSTED_PROXY_HOPS (default 1) is the number of proxies you operate
// between the client and this server. A peer being in the allowlist does not
// make every forwarded value trustworthy: entries to the left of the trusted
// chain are ignored, malformed chains are rejected, and a "client" address that
// falls inside the trusted proxy ranges is treated as ambiguous.

const (
	trustedProxiesEnv = "WORKBENCH_TRUSTED_PROXIES"
	trustedHopsEnv    = "WORKBENCH_TRUSTED_PROXY_HOPS"
)

type proxyTrustSet struct {
	nets []*net.IPNet
}

func (p *proxyTrustSet) enabled() bool { return p != nil && len(p.nets) > 0 }

func (p *proxyTrustSet) contains(ip net.IP) bool {
	if p == nil || ip == nil {
		return false
	}
	for _, n := range p.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (p *proxyTrustSet) trusts(r *http.Request) bool {
	if !p.enabled() {
		return false
	}
	return p.contains(peerIP(r))
}

func peerIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(strings.TrimSpace(host))
}

func parseTrustedProxies(spec string) (*proxyTrustSet, error) {
	set := &proxyTrustSet{}
	for _, part := range strings.Split(spec, ",") {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", s, err)
			}
			set.nets = append(set.nets, n)
			continue
		}
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid trusted proxy address %q", s)
		}
		bits := 128
		if ip.To4() != nil {
			bits = 32
		}
		set.nets = append(set.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return set, nil
}

// loadTrustedProxyConfig reads the allowlist and the trusted hop count. A hop
// count without an allowlist, or an allowlist with an invalid hop count, is a
// configuration error: the server refuses to start rather than guessing.
func loadTrustedProxyConfig() (*proxyTrustSet, int, error) {
	set, err := parseTrustedProxies(os.Getenv(trustedProxiesEnv))
	if err != nil {
		return nil, 0, err
	}
	raw := strings.TrimSpace(os.Getenv(trustedHopsEnv))
	if raw == "" {
		if !set.enabled() {
			return set, 1, nil
		}
		return set, 1, nil
	}
	hops, err := strconv.Atoi(raw)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid %s: %q is not a number", trustedHopsEnv, raw)
	}
	if hops < 1 || hops > 16 {
		return nil, 0, fmt.Errorf("invalid %s: must be between 1 and 16", trustedHopsEnv)
	}
	if !set.enabled() {
		return nil, 0, fmt.Errorf("%s requires %s", trustedHopsEnv, trustedProxiesEnv)
	}
	return set, hops, nil
}

type proxyInfo struct {
	trusted  bool
	scheme   string
	host     string
	clientIP string
}

type proxyInfoKey struct{}

func forwardedHeadersPresent(r *http.Request) bool {
	for _, h := range []string{
		"X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host",
		"X-Real-IP", "Forwarded",
	} {
		if strings.TrimSpace(r.Header.Get(h)) != "" {
			return true
		}
	}
	return false
}

func proxyTrustMiddleware(set *proxyTrustSet, hops int, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !forwardedHeadersPresent(r) {
			info := proxyInfo{clientIP: ipString(peerIP(r))}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), proxyInfoKey{}, info)))
			return
		}
		if !set.trusts(r) {
			writeJSONError(w, http.StatusForbidden, "UNTRUSTED_PROXY_HEADER",
				"forwarded headers are only accepted from a configured trusted proxy")
			return
		}
		scheme, host, err := forwardedTarget(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "INVALID_PROXY_HEADER", err.Error())
			return
		}
		clientIP, err := forwardedClientIP(r, set, hops)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "INVALID_PROXY_HEADER", err.Error())
			return
		}
		info := proxyInfo{trusted: true, scheme: scheme, host: host, clientIP: clientIP}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), proxyInfoKey{}, info)))
	})
}

// forwardedTarget validates the forwarded scheme and host. Conflicting scheme
// values are rejected rather than resolved by taking the first one.
func forwardedTarget(r *http.Request) (string, string, error) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if raw := r.Header.Get("X-Forwarded-Proto"); strings.TrimSpace(raw) != "" {
		seen := map[string]bool{}
		parts := strings.Split(raw, ",")
		for _, part := range parts {
			v := strings.ToLower(strings.TrimSpace(part))
			if v != "http" && v != "https" {
				return "", "", fmt.Errorf("invalid X-Forwarded-Proto")
			}
			seen[v] = true
		}
		if len(seen) > 1 {
			return "", "", fmt.Errorf("conflicting X-Forwarded-Proto values")
		}
		scheme = strings.ToLower(strings.TrimSpace(parts[0]))
	}
	host := r.Host
	if raw := r.Header.Get("X-Forwarded-Host"); strings.TrimSpace(raw) != "" {
		if strings.Contains(raw, ",") {
			return "", "", fmt.Errorf("multiple X-Forwarded-Host values are not accepted")
		}
		h := strings.TrimSpace(raw)
		if !validForwardedHost(h) {
			return "", "", fmt.Errorf("invalid X-Forwarded-Host")
		}
		host = h
	}
	if host == "" {
		return "", "", fmt.Errorf("forwarded request has no host")
	}
	return scheme, host, nil
}

// forwardedClientIP selects the address appended by the trusted chain.
func forwardedClientIP(r *http.Request, set *proxyTrustSet, hops int) (string, error) {
	peer := ipString(peerIP(r))
	xffRaw := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	xrealRaw := strings.TrimSpace(r.Header.Get("X-Real-IP"))

	var chain []net.IP
	if xffRaw != "" {
		for _, part := range strings.Split(xffRaw, ",") {
			s := strings.TrimSpace(part)
			if s == "" {
				return "", fmt.Errorf("malformed X-Forwarded-For")
			}
			ip := net.ParseIP(s)
			if ip == nil {
				return "", fmt.Errorf("malformed X-Forwarded-For entry")
			}
			chain = append(chain, ip)
		}
		if len(chain) < hops {
			return "", fmt.Errorf("X-Forwarded-For has fewer entries than the configured proxy hops")
		}
		idx := len(chain) - hops
		for i := idx + 1; i < len(chain); i++ {
			if !set.contains(chain[i]) {
				return "", fmt.Errorf("X-Forwarded-For contains an untrusted proxy hop")
			}
		}
		client := chain[idx]
		if set.contains(client) {
			return "", fmt.Errorf("forwarded client address is inside the trusted proxy ranges")
		}
		if xrealRaw != "" {
			real := net.ParseIP(xrealRaw)
			if real == nil {
				return "", fmt.Errorf("malformed X-Real-IP")
			}
			if !real.Equal(client) {
				return "", fmt.Errorf("X-Real-IP conflicts with X-Forwarded-For")
			}
		}
		return client.String(), nil
	}

	if xrealRaw != "" {
		// X-Real-IP without an X-Forwarded-For chain is client-controlled unless
		// the proxy overwrites it, which the server cannot verify. Fail closed and
		// require the de-facto standard header.
		return "", fmt.Errorf("X-Real-IP without X-Forwarded-For is ambiguous")
	}
	// A trusted proxy forwarded no client identity. The immediate peer is the
	// only address that can be attributed; this is not a client address.
	return peer, nil
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func validForwardedHost(h string) bool {
	if h == "" || len(h) > 255 {
		return false
	}
	if strings.ContainsAny(h, " /\\@#?") {
		return false
	}
	if host, port, err := net.SplitHostPort(h); err == nil {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
		return host != ""
	}
	if strings.Count(h, ":") > 1 {
		return net.ParseIP(h) != nil // bare IPv6
	}
	return h != ""
}

// requestSchemeHost returns the effective scheme and host for a request from the
// validated proxy context only.
func requestSchemeHost(r *http.Request) (string, string) {
	if info, ok := r.Context().Value(proxyInfoKey{}).(proxyInfo); ok && info.trusted {
		return info.scheme, info.host
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme, r.Host
}

// requestClientIP returns the validated client address. Audit, rate limiting and
// any other attribution must use this function, never a raw header.
func requestClientIP(r *http.Request) string {
	if info, ok := r.Context().Value(proxyInfoKey{}).(proxyInfo); ok && info.clientIP != "" {
		return info.clientIP
	}
	return ipString(peerIP(r))
}

func secureRequest(r *http.Request) bool {
	if isSecure {
		return true
	}
	scheme, _ := requestSchemeHost(r)
	return scheme == "https"
}
