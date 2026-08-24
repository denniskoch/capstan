// Copyright (C) 2026 Dennis Koch
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package server assembles capstan: TLS in front, bearer auth, the allowlist,
// and the verbatim proxy behind.
//
// The order of the checks is deliberate. Authentication runs before the
// allowlist so that an unauthenticated caller learns nothing about which
// endpoints exist — a 403 where a 401 belongs is a free map of the allowlist
// for anyone who can reach the port.
package server

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"time"

	"github.com/denniskoch/capstan/internal/allowlist"
	"github.com/denniskoch/capstan/internal/certs"
	"github.com/denniskoch/capstan/internal/config"
	"github.com/denniskoch/capstan/internal/proxy"
)

// NewHandler builds the request pipeline without any transport around it:
// auth, then allowlist, then the verbatim proxy.
func NewHandler(cfg *config.Config, logger *slog.Logger) http.Handler {
	return &handler{
		auth:    newAuthenticator(cfg.Token),
		allowed: allowlist.New(cfg.AllowWrite),
		proxy:   proxy.New(cfg.DockerSocket, logger),
		logger:  logger,
	}
}

// New builds the HTTP server. It does not listen.
func New(cfg *config.Config, id *certs.Identity, logger *slog.Logger) *http.Server {
	h := NewHandler(cfg, logger)

	return &http.Server{
		Addr:    cfg.Listen,
		Handler: h,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{id.TLS},
			MinVersion:   tls.VersionTLS12,

			// HTTP/1.1 only. Go would happily negotiate h2 here, but dockerd
			// never offers it, and a client that gets h2 from capstan and
			// h1 from the socket is talking to two different servers in every
			// way that a proxy is supposed to hide: no connection upgrades,
			// different header canonicalization, different trailer handling.
			// Matching the daemon's wire behaviour is part of speaking its API
			// verbatim.
			NextProtos: []string{"http/1.1"},
		},

		// Belt to that suspenders: nil-ing the h2 map keeps net/http from
		// re-enabling HTTP/2 automatically when TLSConfig is inspected.
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		IdleTimeout:       cfg.IdleTimeout,

		// No WriteTimeout, on purpose. /events, logs?follow=1 and stats are
		// open-ended streams; a write deadline would cut them off at a fixed
		// age and look to the client like the daemon dropping the connection.
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelDebug),
	}
}

type handler struct {
	auth    *authenticator
	allowed *allowlist.Checker
	proxy   http.Handler
	logger  *slog.Logger
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &recorder{ResponseWriter: w, status: http.StatusOK}

	outcome := h.serve(rec, r)

	level := slog.LevelInfo
	if outcome == "forbidden" {
		// Someone asked for host escape. That is worth waking up for.
		level = slog.LevelWarn
	}
	h.logger.Log(r.Context(), level, "request",
		"method", r.Method,
		"path", r.URL.Path,
		"outcome", outcome,
		"status", rec.status,
		"remote", r.RemoteAddr,
		"duration", time.Since(start).Round(time.Millisecond).String(),
	)
}

// serve runs the checks and returns a short outcome label for the log. It never
// logs or echoes the request body, and never logs the Authorization header.
func (h *handler) serve(w *recorder, r *http.Request) string {
	if !h.auth.check(r) {
		// Nothing useful in the body: no hint about whether the token was
		// absent, malformed or simply wrong.
		w.Header().Set("WWW-Authenticate", `Bearer realm="capstan"`)
		w.WriteHeader(http.StatusUnauthorized)
		return "unauthorized"
	}

	d := h.allowed.Check(r.Method, r.URL.Path)
	switch {
	case d.Forbidden:
		proxy.WriteDockerError(w, http.StatusForbidden, "capstan: "+d.Reason)
		return "forbidden"
	case !d.Allowed:
		proxy.WriteDockerError(w, http.StatusForbidden, "capstan: "+d.Reason)
		if d.Tier == allowlist.TierWrite {
			return "write-disabled"
		}
		return "denied"
	}

	h.proxy.ServeHTTP(w, r)
	return d.Tier.String()
}

// recorder remembers the status code for the access log. It forwards Flush so
// the streaming endpoints keep streaming.
type recorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *recorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(b)
}

func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
