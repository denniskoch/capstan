// Copyright (C) 2026 Dennis Koch
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config loads capstan's settings from the environment.
//
// Environment only, and every variable has a working default: capstan is
// deployed as a container on a Docker host, where a compose file is the only
// configuration surface that exists. `docker run` with no -e at all must
// produce a running, secure service.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	// Listen is the TLS listen address.
	Listen string

	// Token is the bearer token every request must present.
	Token string

	// TokenGenerated reports that no token was supplied and Token was minted
	// at startup. The caller logs it once so the operator can copy it out.
	TokenGenerated bool

	// CertFile and KeyFile persist the self-signed certificate. They must
	// survive restarts: the client pins the fingerprint, so a regenerated
	// certificate reads as an attack.
	CertFile string
	KeyFile  string

	// ExtraSANs are additional DNS names or IPs to put in the certificate,
	// for operators who reach the host by a name capstan cannot discover.
	ExtraSANs []string

	// DockerSocket is the unix socket to forward to.
	DockerSocket string

	// AllowWrite enables the write tier: start/stop/restart/kill/pause/unpause,
	// docker pull, and deletion of containers, images and volumes. Off by
	// default, because a console that only reads cannot be turned into a way
	// to break the host by a stolen token. It never enables anything on the
	// forbidden list; see internal/allowlist.
	AllowWrite bool

	// ReadHeaderTimeout bounds the header-read phase only. There is
	// deliberately no write timeout: /events, /containers/{id}/logs?follow=1
	// and /containers/{id}/stats are open-ended streams, and a write deadline
	// would sever them mid-response.
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration

	// LogLevel is one of debug, info, warn, error.
	LogLevel string
}

// Load reads the environment. It returns an error only for values that are
// present but unusable; absent values fall back to defaults.
func Load() (*Config, error) {
	c := &Config{
		Listen:            env("CAPSTAN_LISTEN", ":9443"),
		CertFile:          env("CAPSTAN_TLS_CERT", "/data/capstan.crt"),
		KeyFile:           env("CAPSTAN_TLS_KEY", "/data/capstan.key"),
		DockerSocket:      env("CAPSTAN_DOCKER_SOCKET", "/var/run/docker.sock"),
		LogLevel:          env("CAPSTAN_LOG_LEVEL", "info"),
		AllowWrite:        boolEnv("CAPSTAN_ALLOW_WRITE"),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	if s := strings.TrimSpace(os.Getenv("CAPSTAN_TLS_SANS")); s != "" {
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				c.ExtraSANs = append(c.ExtraSANs, p)
			}
		}
	}

	c.Token = os.Getenv("CAPSTAN_TOKEN")
	if c.Token == "" {
		tok, err := generateToken()
		if err != nil {
			return nil, fmt.Errorf("generate token: %w", err)
		}
		c.Token, c.TokenGenerated = tok, true
	}

	return c, nil
}

// boolEnv reads a boolean that defaults to false. Only the obvious
// affirmatives count: a typo like CAPSTAN_ALLOW_WRITE=yes! must leave writes
// off rather than quietly enabling them, and an unparseable value is a typo,
// not consent.
func boolEnv(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// generateToken mints 32 bytes of randomness, URL-safe so it survives being
// pasted into a config file or a URL-ish field without escaping.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
