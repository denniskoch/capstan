// Package certs manages capstan's self-signed TLS identity.
//
// There is no CA in a homelab, so capstan is its own: it mints one self-signed
// certificate on first run, persists it, and never touches it again. The client
// (vantric) pins the SHA-256 fingerprint of that certificate, which makes the
// usual PKI questions — who signed it, is the name right, has it expired —
// irrelevant, and makes one question critical: is it the same certificate as
// last time. Everything here is arranged around keeping that answer "yes".
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Lifetime is ten years. A pinned self-signed certificate gains nothing from
// expiring: rotation would break every pin, and an operator who has to
// re-pin annually will eventually stop checking the fingerprint, which is the
// only check that actually protects the connection.
const Lifetime = 10 * 365 * 24 * time.Hour

// Identity is a loaded certificate plus the fingerprint the client pins.
type Identity struct {
	TLS         tls.Certificate
	Leaf        *x509.Certificate
	Fingerprint string // uppercase colon-separated hex, as openssl prints it
	Generated   bool   // true if this run created it
}

// LoadOrCreate returns the certificate at certFile/keyFile, creating a new
// self-signed pair if either is missing.
//
// An existing certificate is used exactly as found — never regenerated, never
// "refreshed" to add a SAN or extend a date. A fingerprint that changes behind
// the operator's back is indistinguishable from an interception, and capstan
// must never be the one to cause that alarm.
func LoadOrCreate(certFile, keyFile string, extraSANs []string) (*Identity, error) {
	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)

	if certErr == nil && keyErr == nil {
		id, err := load(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load existing certificate: %w", err)
		}
		return id, nil
	}
	if certErr == nil || keyErr == nil {
		return nil, fmt.Errorf("certificate and key must both exist or both be absent (%s, %s)", certFile, keyFile)
	}

	if err := generate(certFile, keyFile, extraSANs); err != nil {
		return nil, fmt.Errorf("generate certificate: %w", err)
	}
	id, err := load(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	id.Generated = true
	return id, nil
}

func load(certFile, keyFile string) (*Identity, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	pair.Leaf = leaf
	return &Identity{
		TLS:         pair,
		Leaf:        leaf,
		Fingerprint: Fingerprint(leaf),
	}, nil
}

// Fingerprint is the SHA-256 digest of the certificate's DER bytes, formatted
// the way `openssl x509 -noout -fingerprint -sha256` prints it so an operator
// can compare the two by eye.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

func generate(certFile, keyFile string, extraSANs []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	host, _ := os.Hostname()
	dns, ips := subjectAltNames(host, extraSANs)

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "capstan"},
		// Backdated an hour so a host with a lagging clock, or a client in a
		// different timezone that mishandles the boundary, does not reject a
		// certificate that was valid the moment it was written.
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(Lifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dns,
		IPAddresses:           ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}

	if dir := filepath.Dir(certFile); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if dir := filepath.Dir(keyFile); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	// Key first, and 0600. If the process dies between the two writes, the
	// next run sees a key without a certificate and refuses to start rather
	// than silently minting a second identity.
	if err := writeFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return writeFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func writeFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// subjectAltNames collects every name this host might be reached by. Pinning
// makes SANs largely moot, but a client that verifies normally before falling
// back to the pin, or an operator poking at it with curl, will thank us.
func subjectAltNames(hostname string, extra []string) ([]string, []net.IP) {
	dnsSeen := map[string]bool{}
	ipSeen := map[string]bool{}
	var dns []string
	var ips []net.IP

	addDNS := func(s string) {
		if s != "" && !dnsSeen[s] {
			dnsSeen[s] = true
			dns = append(dns, s)
		}
	}
	addIP := func(ip net.IP) {
		if ip != nil && !ipSeen[ip.String()] {
			ipSeen[ip.String()] = true
			ips = append(ips, ip)
		}
	}

	addDNS("localhost")
	addDNS(hostname)
	if hostname != "" && !strings.Contains(hostname, ".") {
		addDNS(hostname + ".local")
	}
	addIP(net.IPv4(127, 0, 0, 1))
	addIP(net.IPv6loopback)

	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.IsGlobalUnicast() {
				addIP(n.IP)
			}
		}
	}

	for _, s := range extra {
		if ip := net.ParseIP(s); ip != nil {
			addIP(ip)
		} else {
			addDNS(s)
		}
	}
	return dns, ips
}
