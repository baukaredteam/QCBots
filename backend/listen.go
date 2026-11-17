package main

import (
	"fmt"
	"net"
	"strconv"
)

// M7-E Phase 1.1: explicit listener boundary.
//
// The default is loopback, so a pilot that forgets to configure anything is not
// reachable from the network. A reverse-proxy deployment sets
// WORKBENCH_LISTEN_ADDR to the internal address the proxy connects to. This is
// not network isolation on its own: the host firewall and the proxy remain the
// control points.
const listenAddrEnv = "WORKBENCH_LISTEN_ADDR"

func listenAddress(cfg *Config) (string, error) {
	host := cfg.ListenAddr
	if host == "" {
		host = "127.0.0.1"
	}
	if ip := net.ParseIP(host); ip == nil {
		return "", fmt.Errorf("must be an IP address (e.g. 127.0.0.1, 10.0.0.5, ::1), got %q", host)
	}
	port := cfg.ServerPort
	if port == "" {
		port = "8080"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid port %q", port)
	}
	return net.JoinHostPort(host, port), nil
}
