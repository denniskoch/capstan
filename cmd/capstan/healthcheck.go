// Copyright (C) 2026 Dennis Koch
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// healthcheck is a subcommand, not a configuration flag: `capstan healthcheck`
// exists so the container image can declare a HEALTHCHECK without shipping a
// shell or a curl. Configuration itself remains environment-only.
//
// It completes a TLS handshake against our own listener and stops there. That
// proves the process is up, the port is bound and the certificate loaded —
// everything capstan is responsible for. It deliberately does not send a
// request: doing so would need the token, and a health probe that has to be
// handed the bearer token is a second place for the token to leak.
func healthcheck() int {
	addr := os.Getenv("CAPSTAN_LISTEN")
	if addr == "" {
		addr = ":9443"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	} else if host, port, err := net.SplitHostPort(addr); err == nil && (host == "" || host == "0.0.0.0" || host == "::") {
		addr = net.JoinHostPort("127.0.0.1", port)
	}

	// InsecureSkipVerify is correct here and only here: we are dialing our own
	// self-signed listener over loopback to see whether it answers. Authenticity
	// is the pinning client's job, not ours.
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp", addr,
		&tls.Config{InsecureSkipVerify: true}, //nolint:gosec // see comment above
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "capstan: healthcheck: %v\n", err)
		return 1
	}
	_ = conn.Close()
	return 0
}
