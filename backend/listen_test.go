package main

import "testing"

func TestListenAddress(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		port    string
		want    string
		wantErr bool
	}{
		{"default loopback", "", "8080", "127.0.0.1:8080", false},
		{"explicit loopback", "127.0.0.1", "18081", "127.0.0.1:18081", false},
		{"all interfaces", "0.0.0.0", "8080", "0.0.0.0:8080", false},
		{"IPv6 loopback", "::1", "9443", "[::1]:9443", false},
		{"internal address", "10.1.2.3", "443", "10.1.2.3:443", false},
		{"hostname is refused", "localhost", "8080", "", true},
		{"CIDR is refused", "10.0.0.0/8", "8080", "", true},
		{"port zero", "127.0.0.1", "0", "", true},
		{"port too large", "127.0.0.1", "70000", "", true},
		{"non-numeric port", "127.0.0.1", "http", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := listenAddress(&Config{ListenAddr: tc.addr, ServerPort: tc.port})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("listen address = %q, want %q", got, tc.want)
			}
		})
	}
}
