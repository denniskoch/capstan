// Copyright (C) 2026 Dennis Koch
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

// authenticator checks the bearer token.
//
// It stores the digest rather than the token so the comparison operates on two
// fixed-length values. A raw subtle.ConstantTimeCompare over the tokens
// themselves is constant-time in content but not in length — it returns early
// when the lengths differ — which leaks the token's length one probe at a time.
type authenticator struct {
	want [32]byte
}

func newAuthenticator(token string) *authenticator {
	return &authenticator{want: sha256.Sum256([]byte(token))}
}

func (a *authenticator) check(r *http.Request) bool {
	h := r.Header.Get("Authorization")

	// The scheme is case-insensitive per RFC 7235; the token is not.
	const prefix = "bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		// Still hash something, so an absent header and a wrong token take
		// indistinguishable amounts of time.
		got := sha256.Sum256(nil)
		subtle.ConstantTimeCompare(got[:], a.want[:])
		return false
	}

	got := sha256.Sum256([]byte(h[len(prefix):]))
	return subtle.ConstantTimeCompare(got[:], a.want[:]) == 1
}
