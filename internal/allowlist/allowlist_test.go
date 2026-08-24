package allowlist

import "testing"

// readOnly and writeEnabled are the two configurations capstan ships with.
var (
	readOnly     = New(false)
	writeEnabled = New(true)
)

func Check(method, path string) Decision { return readOnly.Check(method, path) }

func TestReadTierAllowed(t *testing.T) {
	cases := []struct{ method, path string }{
		{"HEAD", "/_ping"},
		{"GET", "/_ping"},
		{"GET", "/v1.54/_ping"},
		{"GET", "/version"},
		{"GET", "/info"},
		{"GET", "/events"},
		{"GET", "/containers/json"},
		{"GET", "/v1.41/containers/json"},
		{"GET", "/containers/abc123/json"},
		{"GET", "/containers/abc123/logs"},
		{"GET", "/containers/abc123/stats"},
		{"GET", "/containers/abc123/top"},
		{"GET", "/images/json"},
		{"GET", "/images/nginx/json"},
		{"GET", "/images/library/nginx/json"},
		{"GET", "/images/ghcr.io/example/app/json"},
		{"GET", "/volumes"},
		{"GET", "/networks"},
	}
	for _, c := range cases {
		if d := Check(c.method, c.path); !d.Allowed {
			t.Errorf("%s %s: denied (%s), want allowed", c.method, c.path, d.Reason)
		}
	}
}

func TestPermanentlyForbidden(t *testing.T) {
	cases := []struct{ method, path string }{
		{"POST", "/containers/create"},
		{"POST", "/v1.54/containers/create"},
		{"POST", "/containers/abc/exec"},
		{"POST", "/exec/abc/start"},
		{"GET", "/exec/abc/json"},
		{"POST", "/build"},
		{"POST", "/commit"},
		{"POST", "/containers/abc/attach"},
		{"GET", "/containers/abc/archive"},
		{"PUT", "/containers/abc/archive"},
	}
	for _, c := range cases {
		d := Check(c.method, c.path)
		if d.Allowed {
			t.Fatalf("%s %s: ALLOWED, must never be", c.method, c.path)
		}
		if !d.Forbidden {
			t.Errorf("%s %s: denied but not flagged Forbidden", c.method, c.path)
		}
	}
}

var writeCases = []struct{ method, path string }{
	{"POST", "/containers/abc/start"},
	{"POST", "/containers/abc/stop"},
	{"POST", "/containers/abc/restart"},
	{"POST", "/containers/abc/kill"},
	{"POST", "/containers/abc/pause"},
	{"POST", "/containers/abc/unpause"},
	{"POST", "/images/create"},
	{"POST", "/v1.54/images/create"},
	{"DELETE", "/containers/abc"},
	{"DELETE", "/images/nginx"},
	{"DELETE", "/images/ghcr.io/example/app"},
	{"DELETE", "/volumes/data"},
}

// Off by default. This is the toggle's entire reason to exist, so assert it
// rather than assuming it.
func TestWriteTierDeniedWhenDisabled(t *testing.T) {
	for _, c := range writeCases {
		d := readOnly.Check(c.method, c.path)
		if d.Allowed {
			t.Errorf("%s %s: allowed with writes disabled", c.method, c.path)
		}
		// The operator must be able to tell "turn on writes" apart from
		// "this will never work".
		if d.Reason != "write operations are disabled" {
			t.Errorf("%s %s: reason %q, want the write-disabled reason", c.method, c.path, d.Reason)
		}
		if d.Forbidden {
			t.Errorf("%s %s: flagged Forbidden; it is merely disabled", c.method, c.path)
		}
	}
}

func TestWriteTierAllowedWhenEnabled(t *testing.T) {
	for _, c := range writeCases {
		d := writeEnabled.Check(c.method, c.path)
		if !d.Allowed {
			t.Errorf("%s %s: denied (%s) with writes enabled", c.method, c.path, d.Reason)
		}
		if d.Tier != TierWrite {
			t.Errorf("%s %s: tier %v, want write", c.method, c.path, d.Tier)
		}
	}
}

// The toggle must not reach the forbidden list. This is the single most
// important property of the write tier.
func TestWriteToggleNeverUnlocksHostEscape(t *testing.T) {
	for _, c := range []struct{ method, path string }{
		{"POST", "/containers/create"},
		{"POST", "/v1.54/containers/create"},
		{"POST", "/containers/abc/exec"},
		{"POST", "/exec/abc/start"},
		{"POST", "/build"},
		{"POST", "/commit"},
		{"PUT", "/containers/abc/archive"},
	} {
		if d := writeEnabled.Check(c.method, c.path); d.Allowed {
			t.Fatalf("%s %s: ALLOWED with writes on — the toggle must never reach the forbidden list", c.method, c.path)
		}
	}
	// And every forbidden entry, exhaustively.
	for _, r := range neverAllowed {
		path := r.pattern
		for _, sub := range []string{"*", "**"} {
			for {
				i := indexSeg(path, sub)
				if i < 0 {
					break
				}
				path = path[:i] + "id" + path[i+len(sub):]
			}
		}
		if d := writeEnabled.Check(r.method, path); d.Allowed {
			t.Errorf("%s %s: allowed with writes on", r.method, path)
		}
	}
}

// Enabling writes must not widen anything else either.
func TestWriteToggleDoesNotWidenDefaultDeny(t *testing.T) {
	for _, c := range []struct{ method, path string }{
		{"POST", "/containers/prune"},
		{"POST", "/images/prune"},
		{"POST", "/volumes/prune"},
		{"POST", "/volumes/create"},
		{"POST", "/networks/create"},
		{"DELETE", "/networks/abc"},
		{"DELETE", "/secrets/abc"},
		{"DELETE", "/plugins/abc"},
		{"POST", "/containers/abc/update"},
		{"POST", "/containers/abc/rename"},
		{"POST", "/images/nginx/push"},
		{"POST", "/images/nginx/tag"},
		{"POST", "/images/load"},
		{"POST", "/swarm/init"},
		{"DELETE", "/containers/abc/extra"},
		{"DELETE", "/volumes/a/b"},
	} {
		if d := writeEnabled.Check(c.method, c.path); d.Allowed {
			t.Errorf("%s %s: allowed with writes on, want denied", c.method, c.path)
		}
	}
}

func TestDefaultDeny(t *testing.T) {
	cases := []struct{ method, path string }{
		// Unlisted endpoints that really exist in the Engine API.
		{"GET", "/images/nginx/history"},
		{"GET", "/images/nginx/get"},
		{"GET", "/images/search"},
		{"POST", "/images/nginx/push"},
		{"POST", "/images/nginx/tag"},
		{"POST", "/images/load"},
		{"POST", "/images/prune"},
		{"POST", "/containers/prune"},
		{"POST", "/volumes/create"},
		{"POST", "/networks/create"},
		{"POST", "/networks/abc/connect"},
		{"GET", "/networks/abc"},
		{"GET", "/volumes/data"},
		{"POST", "/containers/abc/update"},
		{"POST", "/containers/abc/rename"},
		{"GET", "/containers/abc/changes"},
		{"GET", "/containers/abc/export"},
		{"POST", "/containers/abc/wait"},
		{"GET", "/swarm"},
		{"GET", "/nodes"},
		{"GET", "/services"},
		{"GET", "/tasks"},
		{"GET", "/secrets"},
		{"GET", "/configs"},
		{"GET", "/plugins"},
		{"GET", "/system/df"},
		{"POST", "/auth"},
		{"GET", "/"},

		// Right path, wrong method.
		{"POST", "/version"},
		{"DELETE", "/containers/json"},
		{"PUT", "/info"},
		{"POST", "/events"},
		{"HEAD", "/version"},

		// Right shape, wrong arity.
		{"GET", "/containers"},
		{"GET", "/containers/abc"},
		{"GET", "/containers/abc/json/extra"},
		{"GET", "/images"},
		{"GET", "/images/json/extra"},
		{"GET", "/volumes/x"},
		{"GET", "/networks/x"},
	}
	for _, c := range cases {
		if d := Check(c.method, c.path); d.Allowed {
			t.Errorf("%s %s: allowed, want denied", c.method, c.path)
		}
	}
}

// A wildcard must never swallow a path separator and so reach an endpoint the
// table never named.
func TestWildcardDoesNotOverMatch(t *testing.T) {
	cases := []struct{ method, path string }{
		{"GET", "/containers/abc/exec/json"},
		{"GET", "/containers/abc/extra/logs"},
	}
	for _, c := range cases {
		if d := Check(c.method, c.path); d.Allowed {
			t.Errorf("%s %s: allowed via wildcard over-match", c.method, c.path)
		}
	}
}

// The greedy image wildcard must not become a way to reach a forbidden route.
// The image wildcard is greedy on purpose, and that means some paths that look
// like list endpoints are really inspects of oddly named images. The daemon
// resolves them the same way, and matching the daemon is the whole contract.
func TestImageWildcardMatchesDaemonRouting(t *testing.T) {
	// Image literally named "json/nginx": daemon binds name=json/nginx.
	if d := Check("GET", "/images/json/nginx/json"); !d.Allowed {
		t.Error("/images/json/nginx/json is an inspect of image json/nginx")
	}
}

func TestImageWildcardStaysAnchored(t *testing.T) {
	cases := []struct{ method, path string }{
		{"GET", "/images/a/b/c/history"},
		{"GET", "/images/a/b/json/extra"},
		{"POST", "/images/a/b/json"},
	}
	for _, c := range cases {
		if d := Check(c.method, c.path); d.Allowed {
			t.Errorf("%s %s: allowed, want denied", c.method, c.path)
		}
	}
}

func TestTraversalRejected(t *testing.T) {
	cases := []struct{ method, path string }{
		{"GET", "/containers/json/../../version"},
		{"GET", "/containers/../containers/json"},
		{"GET", "/./containers/json"},
		{"GET", "//containers/json"},
		{"GET", "/containers//json"},
		{"GET", "/containers/json/"},
		{"GET", "/v1.54//containers/json"},
		{"GET", "containers/json"},
		{"GET", ""},
		// Decoded forms of the same tricks. The caller sends %2e%2e; net/http
		// decodes it before we see it, which is precisely why we decide on the
		// decoded path.
		{"POST", "/containers/abc/logs/../exec"},
		{"POST", "/v1.54/containers/foo/../create"},
	}
	for _, c := range cases {
		d := Check(c.method, c.path)
		if d.Allowed {
			t.Errorf("%s %q: allowed, want rejected", c.method, c.path)
		}
	}
}

func TestVersionPrefixParsing(t *testing.T) {
	// Only a real version prefix is stripped; anything else stays a segment.
	if d := Check("GET", "/v1.54/version"); !d.Allowed {
		t.Error("/v1.54/version should be allowed")
	}
	if d := Check("GET", "/v99.999/containers/json"); !d.Allowed {
		t.Error("unknown-but-well-formed version prefix should still route")
	}
	for _, p := range []string{"/vX.Y/version", "/v1/version", "/v1./version", "/v.1/version", "/version/v1.54"} {
		if d := Check("GET", p); d.Allowed {
			t.Errorf("%s: allowed, want denied", p)
		}
	}
	// A bare version is not an endpoint.
	if d := Check("GET", "/v1.54"); d.Allowed {
		t.Error("/v1.54 alone should be denied")
	}
}

// Guards the invariant that makes the neverAllowed table safe to keep around:
// it must not be able to allow anything.
func TestNeverAllowedTableCannotAllow(t *testing.T) {
	for _, r := range neverAllowed {
		path := r.pattern
		for _, sub := range []string{"*", "**"} {
			for {
				i := indexSeg(path, sub)
				if i < 0 {
					break
				}
				path = path[:i] + "id" + path[i+len(sub):]
			}
		}
		if d := Check(r.method, path); d.Allowed {
			t.Errorf("%s %s: neverAllowed entry was allowed", r.method, path)
		}
	}
}

func indexSeg(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] != sub {
			continue
		}
		if i > 0 && s[i-1] != '/' {
			continue
		}
		if i+len(sub) < len(s) && s[i+len(sub)] != '/' {
			continue
		}
		return i
	}
	return -1
}

func TestRootIsDeniedNotMalformed(t *testing.T) {
	d := Check("GET", "/")
	if d.Allowed {
		t.Fatal("/ must not be allowed")
	}
	if d.Reason == "malformed path" {
		t.Errorf("/ is well-formed, just not a route; got reason %q", d.Reason)
	}
}
