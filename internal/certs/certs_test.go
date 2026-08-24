// Copyright (C) 2026 Dennis Koch
// SPDX-License-Identifier: AGPL-3.0-or-later

package certs

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func paths(t *testing.T) (string, string) {
	d := t.TempDir()
	return filepath.Join(d, "c.crt"), filepath.Join(d, "c.key")
}

// The pin is the contract. A restart must not change the fingerprint.
func TestFingerprintStableAcrossRestart(t *testing.T) {
	c, k := paths(t)
	first, err := LoadOrCreate(c, k, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Generated {
		t.Error("first run should report Generated")
	}
	second, err := LoadOrCreate(c, k, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.Generated {
		t.Error("second run regenerated the certificate; every pinned client would now see an attack")
	}
	if first.Fingerprint != second.Fingerprint {
		t.Errorf("fingerprint changed: %s -> %s", first.Fingerprint, second.Fingerprint)
	}
}

func TestFingerprintFormat(t *testing.T) {
	c, k := paths(t)
	id, err := LoadOrCreate(c, k, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 32 bytes as uppercase hex pairs joined by colons, matching
	// `openssl x509 -noout -fingerprint -sha256`.
	if len(id.Fingerprint) != 32*2+31 {
		t.Fatalf("length %d, want %d: %q", len(id.Fingerprint), 32*2+31, id.Fingerprint)
	}
	for i, r := range id.Fingerprint {
		if i%3 == 2 {
			if r != ':' {
				t.Fatalf("expected colon at %d in %q", i, id.Fingerprint)
			}
		} else if !(r >= '0' && r <= '9' || r >= 'A' && r <= 'F') {
			t.Fatalf("non uppercase-hex %q at %d", r, i)
		}
	}
	if got := Fingerprint(id.Leaf); got != id.Fingerprint {
		t.Errorf("Fingerprint(leaf) = %s, want %s", got, id.Fingerprint)
	}
}

func TestKeyIsNotWorldReadable(t *testing.T) {
	c, k := paths(t)
	if _, err := LoadOrCreate(c, k, nil); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(k)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("key mode %v is readable beyond the owner", fi.Mode().Perm())
	}
}

func TestLifetime(t *testing.T) {
	c, k := paths(t)
	id, err := LoadOrCreate(c, k, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := id.Leaf.NotAfter.Sub(time.Now())
	if got < Lifetime-48*time.Hour {
		t.Errorf("expires in %v, want about %v", got, Lifetime)
	}
	if !id.Leaf.NotBefore.Before(time.Now()) {
		t.Error("NotBefore is in the future; a client with a lagging clock would reject it")
	}
}

// A half-written pair means the previous run died between the two writes.
// Minting a fresh identity there would silently break every pin, so refuse.
func TestHalfWrittenPairIsRefused(t *testing.T) {
	c, k := paths(t)
	if _, err := LoadOrCreate(c, k, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(c); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(c, k, nil); err == nil {
		t.Fatal("key without certificate should be an error, not a silent regeneration")
	}
}

func TestExtraSANs(t *testing.T) {
	c, k := paths(t)
	id, err := LoadOrCreate(c, k, []string{"docker-01.lan", "10.0.0.7"})
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Leaf.VerifyHostname("docker-01.lan"); err != nil {
		t.Errorf("DNS SAN missing: %v", err)
	}
	if err := id.Leaf.VerifyHostname("10.0.0.7"); err != nil {
		t.Errorf("IP SAN missing: %v", err)
	}
	if err := id.Leaf.VerifyHostname("localhost"); err != nil {
		t.Errorf("localhost SAN missing: %v", err)
	}
}
