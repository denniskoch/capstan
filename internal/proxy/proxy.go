// Copyright (C) 2026 Dennis Koch
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package proxy forwards an approved request to the Docker socket and copies
// the answer back unchanged.
//
// capstan speaks the Docker Engine API verbatim. It has no API version of its
// own, renames nothing, wraps nothing, and adds no fields. A standard Docker
// client pointed at capstan must behave exactly as it would against the socket,
// so every transformation this package could apply is one it deliberately does
// not: paths, query strings, request bodies, status codes, response headers and
// response bodies all pass through untouched. Any observable difference between
// capstan and the socket is a bug in capstan.
package proxy

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

// New returns a handler that forwards to the Docker daemon listening on the
// given unix socket.
func New(socketPath string, logger *slog.Logger) http.Handler {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,

		// Go's transport would otherwise volunteer "Accept-Encoding: gzip" and
		// transparently inflate the reply, rewriting Content-Encoding and
		// dropping Content-Length. That is a divergence the client can see, so
		// we stay out of it: whatever encoding the caller negotiated with the
		// daemon is the encoding it gets.
		DisableCompression: true,

		// No ResponseHeaderTimeout. /events and /containers/{id}/logs?follow=1
		// legitimately produce headers immediately and then nothing at all for
		// hours, and an idle stream is not a stalled one.
		ExpectContinueTimeout: 1 * time.Second,
	}

	rp := &httputil.ReverseProxy{
		Transport: transport,

		// -1 flushes every write straight through. Docker's streaming
		// endpoints are useless behind a buffer: `docker events` and
		// `logs -f` would arrive in silent lumps.
		FlushInterval: -1,

		Rewrite: func(pr *httputil.ProxyRequest) {
			// The unix dialer ignores the host entirely; it exists only
			// because net/http requires a well-formed URL.
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "docker"
			pr.Out.Host = "docker"

			// Path, RawPath and RawQuery are carried over from the inbound
			// request untouched, including any API version prefix. capstan
			// decided on a normalized copy; it forwards the original.

			// Our bearer token authenticates the caller to capstan. The daemon
			// has no use for it and no business seeing it.
			pr.Out.Header.Del("Authorization")

			// Rewrite (unlike the older Director) adds no X-Forwarded-* of its
			// own, which is what we want: the daemon should see the request
			// the client sent, not an annotated version of it.
		},

		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// Reaching this means the socket is gone, not that the caller did
			// anything wrong. Shape the reply like an Engine API error so a
			// standard client can parse it, and keep the detail in the log.
			logger.Error("upstream failure",
				"method", r.Method, "path", r.URL.Path, "error", err)
			writeDockerError(w, http.StatusBadGateway, "capstan: cannot reach the Docker daemon")
		},
	}

	return rp
}
