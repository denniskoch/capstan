// Copyright (C) 2026 Dennis Koch
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/denniskoch/capstan/internal/config"
)

const testToken = "s3cr3t"

// upstream is a stand-in for dockerd on a unix socket. It reports back exactly
// what it received, which is how the tests assert that capstan forwards
// requests without editing them.
type upstream struct {
	socket string
	last   chan received
}

type received struct {
	Method   string      `json:"method"`
	URI      string      `json:"uri"`
	Path     string      `json:"path"`
	RawQuery string      `json:"raw_query"`
	Headers  http.Header `json:"headers"`
}

func newUpstream(t *testing.T, h http.HandlerFunc) *upstream {
	t.Helper()
	// Unix socket paths are limited to ~104 bytes on darwin, so keep it short.
	dir, err := os.MkdirTemp("", "cs")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	u := &upstream{socket: sock, last: make(chan received, 8)}

	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.last <- received{
			Method: r.Method, URI: r.RequestURI, Path: r.URL.Path,
			RawQuery: r.URL.RawQuery, Headers: r.Header.Clone(),
		}
		if h != nil {
			h(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Api-Version", "1.54")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); _ = ln.Close(); _ = os.RemoveAll(dir) })
	return u
}

func newFront(t *testing.T, u *upstream) *httptest.Server {
	t.Helper()
	cfg := &config.Config{Token: testToken, DockerSocket: u.socket}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := httptest.NewServer(NewHandler(cfg, logger))
	t.Cleanup(s.Close)
	return s
}

func do(t *testing.T, front *httptest.Server, method, path string, hdr http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, front.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	for k, vs := range hdr {
		req.Header[k] = vs
	}
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// The whole point of capstan: the daemon must see the request the client sent.
func TestRequestForwardedVerbatim(t *testing.T) {
	u := newUpstream(t, nil)
	front := newFront(t, u)

	for _, path := range []string{
		"/containers/json?all=1&limit=5&filters=%7B%22status%22%3A%5B%22running%22%5D%7D",
		"/v1.54/containers/json?all=1",
		"/images/ghcr.io/example/app/json",
	} {
		resp := do(t, front, "GET", path, nil)
		resp.Body.Close()
		got := <-u.last
		if got.URI != path {
			t.Errorf("upstream saw %q, client sent %q", got.URI, path)
		}
	}
}

func TestTokenNotForwardedAndNoHeadersInvented(t *testing.T) {
	u := newUpstream(t, nil)
	front := newFront(t, u)

	resp := do(t, front, "GET", "/version", http.Header{
		"X-Registry-Auth": {"opaque"},
		"User-Agent":      {"vantric/1.0"},
	})
	resp.Body.Close()
	got := <-u.last

	if v := got.Headers.Get("Authorization"); v != "" {
		t.Errorf("capstan leaked its bearer token upstream: %q", v)
	}
	// The daemon must not learn about the hop. Rewrite (unlike Director) adds
	// nothing, and this test is what keeps it that way.
	for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"} {
		if v := got.Headers.Get(h); v != "" {
			t.Errorf("capstan invented %s: %q", h, v)
		}
	}
	if got.Headers.Get("X-Registry-Auth") != "opaque" {
		t.Error("client header X-Registry-Auth did not survive the hop")
	}
	if got.Headers.Get("User-Agent") != "vantric/1.0" {
		t.Error("client User-Agent was rewritten")
	}
}

// Compression must be the client's business, end to end. If capstan let Go's
// transport volunteer "Accept-Encoding: gzip" it would also transparently
// inflate the reply, rewriting Content-Encoding and dropping Content-Length —
// a difference the client can see.
func TestCompressionIsTheClientsBusiness(t *testing.T) {
	u := newUpstream(t, nil)
	front := newFront(t, u)

	// A client that asks for nothing must have nothing asked on its behalf.
	// (The default http.Client would add gzip itself, so opt out here.)
	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	req, _ := http.NewRequest("GET", front.URL+"/version", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := (<-u.last).Headers.Get("Accept-Encoding"); got != "" {
		t.Errorf("capstan negotiated compression the client did not ask for: %q", got)
	}

	// A client that does ask must have its exact request forwarded.
	req, _ = http.NewRequest("GET", front.URL+"/version", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Accept-Encoding", "br, gzip;q=0.5")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := (<-u.last).Headers.Get("Accept-Encoding"); got != "br, gzip;q=0.5" {
		t.Errorf("Accept-Encoding = %q, want the client's exact value", got)
	}
}

func TestResponsePassthrough(t *testing.T) {
	u := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Api-Version", "1.54")
		w.Header().Set("Docker-Experimental", "false")
		w.Header().Set("Ostype", "linux")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"message":"No such container: abc"}`)
	})
	front := newFront(t, u)

	resp := do(t, front, "GET", "/containers/abc/json", nil)
	defer resp.Body.Close()
	<-u.last

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status %d, want 404 passed through", resp.StatusCode)
	}
	for k, want := range map[string]string{
		"Api-Version": "1.54", "Docker-Experimental": "false", "Ostype": "linux",
	} {
		if got := resp.Header.Get(k); got != want {
			t.Errorf("header %s = %q, want %q", k, got, want)
		}
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"message":"No such container: abc"}` {
		t.Errorf("body rewritten: %q", body)
	}
}

// /events and logs?follow=1 are useless if capstan buffers them.
func TestStreamingIsNotBuffered(t *testing.T) {
	release := make(chan struct{})
	u := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{\"first\":1}\n")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "{\"second\":2}\n")
		w.(http.Flusher).Flush()
	})
	front := newFront(t, u)

	resp := do(t, front, "GET", "/events", nil)
	defer resp.Body.Close()
	<-u.last

	br := bufio.NewReader(resp.Body)
	type res struct {
		line string
		err  error
	}
	first := make(chan res, 1)
	go func() { l, err := br.ReadString('\n'); first <- res{l, err} }()

	select {
	case got := <-first:
		if got.err != nil {
			t.Fatalf("reading first event: %v", got.err)
		}
		if got.line != "{\"first\":1}\n" {
			t.Fatalf("first line = %q", got.line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first event never arrived: capstan is buffering the stream")
	}

	close(release)
	line, err := br.ReadString('\n')
	if err != nil || line != "{\"second\":2}\n" {
		t.Fatalf("second event = %q, err = %v", line, err)
	}
}

func TestUnauthorizedRevealsNothing(t *testing.T) {
	u := newUpstream(t, nil)
	front := newFront(t, u)

	// An allowed route, a forbidden route and a nonexistent one must be
	// indistinguishable without a token.
	var bodies []string
	for _, p := range []string{"/version", "/containers/create", "/nonsense"} {
		req, _ := http.NewRequest("GET", front.URL+p, nil)
		resp, err := front.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", p, resp.StatusCode)
		}
		if len(b) != 0 {
			t.Errorf("%s: 401 body should be empty, got %q", p, b)
		}
		if got := resp.Header.Get("WWW-Authenticate"); got == "" {
			t.Errorf("%s: missing WWW-Authenticate", p)
		}
		bodies = append(bodies, resp.Status+string(b))
	}
	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Errorf("401 responses differ between routes: %q vs %q", bodies[0], bodies[i])
		}
	}

	select {
	case got := <-u.last:
		t.Fatalf("unauthenticated request reached the daemon: %s %s", got.Method, got.URI)
	default:
	}
}

func TestDeniedRequestsNeverReachTheDaemon(t *testing.T) {
	u := newUpstream(t, nil)
	front := newFront(t, u)

	for _, c := range []struct{ method, path string }{
		{"POST", "/containers/create"},
		{"POST", "/containers/abc/exec"},
		{"POST", "/build"},
		{"POST", "/containers/abc/start"},
		{"DELETE", "/containers/abc"},
		{"GET", "/system/df"},
		{"GET", "/containers/json/../../build"},
	} {
		resp := do(t, front, c.method, c.path, nil)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s: status %d, want 403", c.method, c.path, resp.StatusCode)
		}
		// Denials must still look like Engine API errors so a stock client
		// renders them instead of choking.
		var e struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(body, &e); err != nil || e.Message == "" {
			t.Errorf("%s %s: body %q is not an Engine API error", c.method, c.path, body)
		}

		select {
		case got := <-u.last:
			t.Fatalf("%s %s reached the daemon as %s %s", c.method, c.path, got.Method, got.URI)
		default:
		}
	}
}

func TestUpstreamDownReturnsDockerShapedError(t *testing.T) {
	cfg := &config.Config{Token: testToken, DockerSocket: "/nonexistent/docker.sock"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	front := httptest.NewServer(NewHandler(cfg, logger))
	defer front.Close()

	req, _ := http.NewRequest("GET", front.URL+"/version", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status %d, want 502", resp.StatusCode)
	}
	var e struct {
		Message string `json:"message"`
	}
	body, _ := io.ReadAll(resp.Body)
	if json.Unmarshal(body, &e) != nil || e.Message == "" {
		t.Errorf("body %q is not an Engine API error", body)
	}
}

func TestWriteToggleAtTheServerLevel(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	for _, tc := range []struct {
		name       string
		allowWrite bool
		wantStatus int
		wantReach  bool
	}{
		{"disabled", false, http.StatusForbidden, false},
		{"enabled", true, http.StatusOK, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := newUpstream(t, nil)
			cfg := &config.Config{Token: testToken, DockerSocket: u.socket, AllowWrite: tc.allowWrite}
			front := httptest.NewServer(NewHandler(cfg, logger))
			defer front.Close()

			resp := do(t, front, "POST", "/containers/abc/stop?t=10", nil)
			resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("status %d, want %d", resp.StatusCode, tc.wantStatus)
			}

			select {
			case got := <-u.last:
				if !tc.wantReach {
					t.Fatalf("write reached the daemon with writes disabled: %s", got.URI)
				}
				if got.URI != "/containers/abc/stop?t=10" {
					t.Errorf("upstream saw %q, want the query preserved", got.URI)
				}
			case <-time.After(time.Second):
				if tc.wantReach {
					t.Fatal("write never reached the daemon with writes enabled")
				}
			}

			// The toggle must never reach the forbidden list, at either setting.
			resp = do(t, front, "POST", "/containers/create", nil)
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("/containers/create: status %d, want 403", resp.StatusCode)
			}
			select {
			case got := <-u.last:
				t.Fatalf("/containers/create reached the daemon: %s", got.URI)
			default:
			}
		})
	}
}
