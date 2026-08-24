package server

import (
	"net/http"
	"testing"
)

func req(header string) *http.Request {
	r, _ := http.NewRequest("GET", "/version", nil)
	if header != "" {
		r.Header.Set("Authorization", header)
	}
	return r
}

func TestAuthenticator(t *testing.T) {
	a := newAuthenticator("s3cr3t")

	ok := []string{"Bearer s3cr3t", "bearer s3cr3t", "BEARER s3cr3t"}
	for _, h := range ok {
		if !a.check(req(h)) {
			t.Errorf("%q: rejected, want accepted (scheme is case-insensitive)", h)
		}
	}

	bad := []string{
		"", "Bearer", "Bearer ", "Bearer s3cr3", "Bearer s3cr3tx", "Bearer S3CR3T",
		"Basic s3cr3t", "s3cr3t", "Bearer  s3cr3t", "Token s3cr3t",
	}
	for _, h := range bad {
		if a.check(req(h)) {
			t.Errorf("%q: accepted, want rejected", h)
		}
	}
}

// An empty configured token must not turn into "anything goes".
func TestEmptyTokenStillRequiresAMatch(t *testing.T) {
	a := newAuthenticator("")
	if a.check(req("Bearer anything")) {
		t.Error("arbitrary token accepted")
	}
	if a.check(req("")) {
		t.Error("missing header accepted")
	}
}
