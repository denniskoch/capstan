// Copyright (C) 2026 Dennis Koch
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command capstan is an authenticating TLS front door for a Docker host's
// /var/run/docker.sock.
//
// It runs as a container on the host and lets a remote console drive Docker
// over the network without exposing the socket. It speaks the Docker Engine API
// verbatim; see internal/proxy. What it may forward is decided by
// internal/allowlist, which is the security model and the place to read first.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/denniskoch/capstan/internal/certs"
	"github.com/denniskoch/capstan/internal/config"
	"github.com/denniskoch/capstan/internal/server"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "capstan: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: parseLevel(cfg.LogLevel),
	}))

	if _, err := os.Stat(cfg.DockerSocket); err != nil {
		// Not fatal: the daemon may start after us, and requests will 502
		// until it does. But it is nearly always a compose mistake, so say so.
		logger.Warn("docker socket not present yet", "path", cfg.DockerSocket, "error", err)
	}

	id, err := certs.LoadOrCreate(cfg.CertFile, cfg.KeyFile, cfg.ExtraSANs)
	if err != nil {
		return err
	}

	banner(cfg, id)

	if cfg.TokenGenerated {
		// Logged exactly once, at startup, because there is nowhere else to
		// get it. Set CAPSTAN_TOKEN to keep it out of the logs entirely.
		logger.Warn("no CAPSTAN_TOKEN set; generated one for this certificate's lifetime",
			"token", cfg.Token)
	}

	srv := server.New(cfg, id, logger)

	errc := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.Listen, "socket", cfg.DockerSocket, "write_tier", cfg.AllowWrite)
		// Certificate and key are already loaded into TLSConfig.
		errc <- srv.ListenAndServeTLS("", "")
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		logger.Info("shutting down")
		// Streaming endpoints hold connections open indefinitely, so a
		// graceful shutdown will always hit this deadline when anything is
		// watching /events. Keep it short.
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		return nil
	}
}

// banner prints the certificate fingerprint on stdout, separately from the
// structured log, because it is the one value an operator must read off the
// host by eye and type into the console. Burying it in a log line is how a
// first connection ends up trust-on-first-use by accident.
func banner(cfg *config.Config, id *certs.Identity) {
	line := strings.Repeat("=", 76)
	state := "loaded existing certificate"
	if id.Generated {
		state = "generated new certificate"
	}

	fmt.Println(line)
	fmt.Println("  capstan — Docker Engine API front door")
	fmt.Println(line)
	fmt.Printf("  listening      https://%s\n", cfg.Listen)
	fmt.Printf("  docker socket  %s\n", cfg.DockerSocket)
	fmt.Printf("  certificate    %s (%s)\n", cfg.CertFile, state)
	fmt.Printf("  write tier     %s\n", writeTierLabel(cfg.AllowWrite))
	fmt.Printf("  valid until    %s\n", id.Leaf.NotAfter.UTC().Format(time.RFC3339))
	fmt.Println()
	fmt.Println("  SHA-256 fingerprint — pin this value in the console:")
	fmt.Println()
	for _, part := range wrap(id.Fingerprint, 48) {
		fmt.Printf("    %s\n", part)
	}
	fmt.Println()
	fmt.Println(line)
}

// writeTierLabel spells the write tier out in the banner rather than printing
// a bare boolean. Whether this host can be stopped and pruned from the network
// is the first thing an operator should see, and "true" reads as a detail.
func writeTierLabel(on bool) string {
	if on {
		return "ENABLED — start/stop/kill/pause, pull, delete (CAPSTAN_ALLOW_WRITE)"
	}
	return "disabled (read-only; set CAPSTAN_ALLOW_WRITE=true to enable)"
}

func wrap(s string, width int) []string {
	var out []string
	for len(s) > width {
		cut := width
		for cut > 0 && s[cut] != ':' {
			cut--
		}
		if cut == 0 {
			cut = width
		}
		out = append(out, s[:cut+1])
		s = s[cut+1:]
	}
	return append(out, s)
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
