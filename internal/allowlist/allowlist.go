// Copyright (C) 2026 Dennis Koch
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package allowlist decides whether a Docker Engine API request may be
// forwarded to the host's socket.
//
// This package is the security model. Everything else in capstan is plumbing.
//
// Two rules govern any change here:
//
//  1. Default deny. A request that matches no entry in the table is refused.
//     There is no fallthrough, no catch-all, no "unknown but harmless" branch.
//     Adding a capability means adding a row; nothing else can grant one.
//
//  2. Never trust the caller. Anything that can reach capstan's port is
//     untrusted, valid token or not. A token proves the caller is the console;
//     it does not prove the console has not been compromised. The allowlist is
//     what stands between a stolen token and a root shell on the host.
package allowlist

import (
	"strings"
)

// Tier is the privilege class a route belongs to.
type Tier int

const (
	// TierRead is always enabled. These routes observe the host; none of them
	// change its state.
	TierRead Tier = iota

	// TierWrite is off unless the operator turns it on. These routes change
	// the state of containers and images that already exist. None of them can
	// create a container, and that boundary is the whole point of having a
	// separate tier rather than a longer read list.
	TierWrite
)

func (t Tier) String() string {
	switch t {
	case TierRead:
		return "read"
	case TierWrite:
		return "write"
	default:
		return "unknown"
	}
}

// Decision is the outcome of consulting the allowlist.
type Decision struct {
	Allowed bool
	Tier    Tier

	// Reason is a short, caller-safe explanation of a denial. It never
	// contains anything the caller did not already send us.
	Reason string

	// Forbidden marks a denial that hit the neverAllowed table rather than
	// simply falling off the end of the allowlist. These are worth logging
	// loudly: something is asking for host escape.
	Forbidden bool
}

// route is one row of the table.
//
// pattern is a slash-separated path where a segment of "*" matches exactly one
// path segment and "**" matches one or more. Literal segments must match
// exactly. See match for the full semantics.
type route struct {
	method  string
	pattern string
	tier    Tier
}

// ---------------------------------------------------------------------------
// The allowlist.
// ---------------------------------------------------------------------------

// readRoutes are always permitted. Every one of them is a GET (or HEAD) that
// returns information about the host and changes nothing on it.
//
// "*" is one path segment: container and volume identifiers never contain a
// slash. "**" is one or more: image *names* do, because a fully qualified name
// carries its registry and namespace, so `docker image inspect
// ghcr.io/example/app` becomes GET /images/ghcr.io/example/app/json. The
// daemon's own router treats that as a single greedy parameter and so must we.
var readRoutes = []route{
	// Handshake and host facts.
	{"HEAD", "/_ping", TierRead}, // the Docker client pings with HEAD first
	{"GET", "/_ping", TierRead},
	{"GET", "/version", TierRead},
	{"GET", "/info", TierRead},

	// Event stream. Long-lived; capstan must not buffer or time it out.
	{"GET", "/events", TierRead},

	// Containers.
	{"GET", "/containers/json", TierRead},
	{"GET", "/containers/*/json", TierRead},
	{"GET", "/containers/*/logs", TierRead},
	{"GET", "/containers/*/stats", TierRead},
	{"GET", "/containers/*/top", TierRead},

	// Images.
	{"GET", "/images/json", TierRead},
	{"GET", "/images/**/json", TierRead},

	// Volumes and networks.
	{"GET", "/volumes", TierRead},
	{"GET", "/networks", TierRead},
}

// writeRoutes are permitted only when the operator sets CAPSTAN_ALLOW_WRITE.
//
// The line between this tier and the forbidden list is not "how much damage
// could this do" — a careless DELETE can ruin a day. It is whether the endpoint
// can hand the caller control of the *host*. Everything here acts on a
// container or image that already exists, and was created by someone with a
// real trust relationship to the machine: capstan can stop your database, but
// it cannot start a new container with / bind-mounted into it. Nothing may
// enter this tier that narrows that gap.
var writeRoutes = []route{
	// Lifecycle of containers that already exist. The daemon rejects an
	// unknown id with a 404 of its own; capstan does not need to care which
	// containers exist, only that the shape is right.
	{"POST", "/containers/*/start", TierWrite},
	{"POST", "/containers/*/stop", TierWrite},
	{"POST", "/containers/*/restart", TierWrite},
	{"POST", "/containers/*/kill", TierWrite},
	{"POST", "/containers/*/pause", TierWrite},
	{"POST", "/containers/*/unpause", TierWrite},

	// docker pull. Fetching an image is not running one, and with
	// /containers/create permanently closed, a pulled image cannot be started
	// through capstan at all — it can only be pulled ahead of a deploy that
	// happens by some other means.
	//
	// Note this is /images/create, which is pull. It is not
	// /containers/create, which is on the forbidden list. The names are
	// confusingly close; the endpoints are nothing alike.
	{"POST", "/images/create", TierWrite},

	// Cleanup. "**" for images because a fully qualified image name spans
	// segments; the only DELETE the Engine API defines under /images is
	// /images/{name}, so a greedy tail cannot reach anything else.
	{"DELETE", "/containers/*", TierWrite},
	{"DELETE", "/images/**", TierWrite},
	{"DELETE", "/volumes/*", TierWrite},
}

// ---------------------------------------------------------------------------
// The routes that are never allowed, at any setting, and why.
// ---------------------------------------------------------------------------

// neverAllowed exists for the maintainer, not for the matcher. Default deny
// already refuses everything below; this table can only ever produce a denial,
// so it cannot weaken the model. What it buys is that the argument is in the
// code, in the path of anyone about to widen the allowlist.
//
// If you are here because you want compose support, or a terminal in the
// console, or remote builds — read this first. The objection is not that these
// endpoints are risky. It is that each one is, on its own, a complete host
// takeover, and no configuration toggle changes that.
//
//   - POST /containers/create
//     The request body is HostConfig. HostConfig.Binds mounts any host path
//     into the new container, so `-v /:/host` reads and writes the entire
//     filesystem as root. Privileged: true drops every restriction. PidMode:
//     "host" and the equivalent IpcMode/NetworkMode escape the namespaces
//     outright. There is no subset of create that is safe to expose, because
//     the dangerous part is a field in a JSON body, not a separate path — the
//     only way to allow "safe" creates would be to parse and validate
//     HostConfig ourselves, which is a whitelist of a moving target inside an
//     API we have promised to pass through verbatim. Compose belongs on the
//     host, driven by something with a real trust relationship to it.
//
//   - POST /containers/{id}/exec, POST /exec/{id}/start, and /exec/*
//     Same outcome by another door. Exec into any container that is already
//     privileged or already has the socket or a host path mounted, and you are
//     root on the host. Since capstan cannot see how the target container was
//     built, it cannot tell a safe exec from a fatal one. A console that needs
//     a shell should get it over SSH, where the host authenticates the user.
//
//   - POST /build, POST /commit
//     Build accepts a tar context and a Dockerfile, which is arbitrary code
//     execution by design, and its surface (contexts, cache mounts, buildkit
//     sessions) is large out of proportion to what a console needs — which is
//     nothing; images come from a registry. Commit turns a running container
//     into a new image, which is the same trick with fewer steps.
//
// The common thread: capstan's whole claim is that reaching its port gets you
// less than reaching the socket. Every route above collapses that difference to
// zero, and once one of them is open, the token is the only thing left, which
// is exactly the posture capstan exists to replace.
var neverAllowed = []route{
	{"POST", "/containers/create", TierRead},
	{"POST", "/containers/*/exec", TierRead},
	{"POST", "/exec/*/start", TierRead},
	{"POST", "/exec/*/resize", TierRead},
	{"GET", "/exec/*/json", TierRead},
	{"POST", "/build", TierRead},
	{"POST", "/commit", TierRead},
	{"POST", "/containers/*/attach", TierRead},
	{"GET", "/containers/*/attach/ws", TierRead},
	{"POST", "/containers/*/archive", TierRead},
	{"PUT", "/containers/*/archive", TierRead},
	{"GET", "/containers/*/archive", TierRead},
	{"POST", "/session", TierRead},
}

// ---------------------------------------------------------------------------
// Matching.
// ---------------------------------------------------------------------------

// Checker answers whether a request may be forwarded. Construct one with New.
type Checker struct {
	allowWrite bool
}

// New returns a Checker. allowWrite enables the write tier; the read tier is
// always on and the forbidden list is always off.
func New(allowWrite bool) *Checker {
	return &Checker{allowWrite: allowWrite}
}

// Check consults the allowlist for a request.
//
// path must be the decoded request path, exactly as the Docker daemon's own
// router would see it. Deciding on a differently normalized string than the
// daemon routes on is the standard way a filtering proxy gets walked past, so
// capstan makes its decision on the same bytes and forwards the request URI
// untouched.
func (c *Checker) Check(method, path string) Decision {
	clean, ok := normalize(path)
	if !ok {
		// A path with an empty, "." or ".." segment. No Docker client emits
		// one; the only reason to send it is to make our matcher and the
		// daemon's disagree. Refuse rather than guess at the intent.
		return Decision{Reason: "malformed path"}
	}

	segs := strings.Split(strings.TrimPrefix(clean, "/"), "/")

	for _, r := range neverAllowed {
		if r.method == method && match(r.pattern, segs) {
			return Decision{
				Reason:    "endpoint permanently disabled",
				Forbidden: true,
			}
		}
	}

	for _, r := range readRoutes {
		if r.method == method && match(r.pattern, segs) {
			return Decision{Allowed: true, Tier: r.tier}
		}
	}

	for _, r := range writeRoutes {
		if r.method == method && match(r.pattern, segs) {
			if !c.allowWrite {
				// A distinct reason, because this is the one denial an
				// operator can actually do something about.
				return Decision{Tier: TierWrite, Reason: "write operations are disabled"}
			}
			return Decision{Allowed: true, Tier: r.tier}
		}
	}

	return Decision{Reason: "endpoint not permitted"}
}

// apiVersionPrefix reports whether seg is a Docker API version prefix such as
// "v1.54". Clients may address any endpoint with or without one.
func apiVersionPrefix(seg string) bool {
	if len(seg) < 4 || seg[0] != 'v' {
		return false
	}
	rest := seg[1:]
	dot := strings.IndexByte(rest, '.')
	if dot <= 0 || dot == len(rest)-1 {
		return false
	}
	return allDigits(rest[:dot]) && allDigits(rest[dot+1:])
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// normalize strips an optional API version prefix and rejects any path that is
// not already in canonical form. It never rewrites a path into something
// acceptable — a path that needs cleaning is refused, not cleaned, so that the
// string we decide on is always the string the daemon will route on.
func normalize(path string) (string, bool) {
	if path == "" || path[0] != '/' {
		return "", false
	}
	if path == "/" {
		// Not an endpoint, but well-formed. Let it fall through to the normal
		// "no such route" denial rather than reporting it as malformed.
		return path, true
	}
	for _, seg := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if seg == "" || seg == "." || seg == ".." {
			// Trailing slash lands here too, as an empty final segment. The
			// daemon treats /containers/json and /containers/json/ as
			// different routes; we do not paper over the difference.
			return "", false
		}
	}
	if i := strings.IndexByte(path[1:], '/'); i >= 0 {
		if first := path[1 : 1+i]; apiVersionPrefix(first) {
			return path[1+i:], true
		}
	} else if apiVersionPrefix(path[1:]) {
		return "/", true
	}
	return path, true
}

// match reports whether segs satisfies pattern.
//
// A literal segment matches itself. "*" matches exactly one segment. "**"
// matches one or more segments and may appear at most once, which is enough
// for the only case that needs it: multi-segment image names.
func match(pattern string, segs []string) bool {
	pat := strings.Split(strings.TrimPrefix(pattern, "/"), "/")

	star := -1
	for i, p := range pat {
		if p == "**" {
			star = i
			break
		}
	}

	if star < 0 {
		if len(pat) != len(segs) {
			return false
		}
		for i, p := range pat {
			if p != "*" && p != segs[i] {
				return false
			}
		}
		return true
	}

	// With a "**" the pattern is prefix + at least one segment + suffix.
	prefix, suffix := pat[:star], pat[star+1:]
	if len(segs) < len(prefix)+1+len(suffix) {
		return false
	}
	for i, p := range prefix {
		if p != "*" && p != segs[i] {
			return false
		}
	}
	tail := segs[len(segs)-len(suffix):]
	for i, p := range suffix {
		if p != "*" && p != tail[i] {
			return false
		}
	}
	return true
}
