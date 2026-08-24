# capstan

[![ci](https://github.com/denniskoch/capstan/actions/workflows/ci.yml/badge.svg)](https://github.com/denniskoch/capstan/actions/workflows/ci.yml)
[![image](https://github.com/denniskoch/capstan/actions/workflows/image.yml/badge.svg)](https://github.com/denniskoch/capstan/actions/workflows/image.yml)
[![license: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

An authenticating TLS front door for a Docker host's `/var/run/docker.sock`.

capstan runs as a container on each Docker host and lets a remote console drive
Docker over the network without exposing the socket. It is one static binary
with no dependencies outside the Go standard library.

## The rule that shapes everything

**capstan speaks the Docker Engine API verbatim.** Paths, query strings, request
bodies and responses pass through unchanged — no wrapping, no renaming, no API
version of its own. A standard Docker API client pointed at capstan just works.

There is therefore no protocol to negotiate with the consumer, and **any
divergence from the Engine API is a bug in capstan**.

What capstan adds is at the edges, not in the API: a TLS listener, a bearer
token, and an allowlist of what may be forwarded.

## Quick start

```bash
cp .env.example .env      # set DOCKER_GID and CAPSTAN_TOKEN
docker compose up -d
docker compose logs | grep -A3 'pin this value'
```

Images are published to GHCR for `linux/amd64` and `linux/arm64`:

```
ghcr.io/denniskoch/capstan:edge      tip of main, rebuilt on every push
ghcr.io/denniskoch/capstan:latest    newest release
ghcr.io/denniskoch/capstan:0.1.0     an exact release
ghcr.io/denniskoch/capstan:0.1       newest patch of that minor
```

`compose.yaml` defaults to `:edge`. Pin a release in `.env` for anything you
care about:

```
CAPSTAN_TAG=0.1.0
```

To build from source instead of pulling:

```bash
docker compose -f compose.yaml -f compose.build.yaml up -d --build
```

`DOCKER_GID` is the docker socket's group **on the host that will run capstan**:

```bash
stat -c '%g' /var/run/docker.sock
```

If Docker itself runs in a VM (colima, Docker Desktop), read it from inside:

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  alpine stat -c '%g' /var/run/docker.sock
```

Compose reads `.env` for every subcommand, so `logs` and `ps` keep working
without re-exporting anything.

```yaml
# compose.yaml — one per Docker host
services:
  capstan:
    image: ghcr.io/denniskoch/capstan:${CAPSTAN_TAG:-edge}
    container_name: capstan
    restart: unless-stopped

    # Non-root. The gid must be the docker socket's group on THIS host:
    #   stat -c '%g' /var/run/docker.sock
    user: "65532:${DOCKER_GID:?see .env.example}"

    environment:
      # Omit to have capstan generate one and log it once at startup.
      CAPSTAN_TOKEN: "${CAPSTAN_TOKEN:?set CAPSTAN_TOKEN in .env}"
      # Names the console will reach this host by, if not an IP already in
      # the certificate. Only matters if you verify normally rather than pin.
      CAPSTAN_TLS_SANS: "${CAPSTAN_TLS_SANS:-}"
      # Read-only unless you say otherwise.
      CAPSTAN_ALLOW_WRITE: "${CAPSTAN_ALLOW_WRITE:-false}"

    ports:
      - "9443:9443"

    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - capstan-data:/data          # holds the certificate; must persist

    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]

volumes:
  capstan-data:
```

The socket is mounted `:ro`. That is defence in depth, not the security model —
the Docker API does everything over one bidirectional socket, so `:ro` prevents
nothing an attacker would want. The allowlist is what protects the host.

`capstan-data` must persist. It holds the certificate, and the certificate's
fingerprint is what the console pins.

## First connection

On startup capstan prints the certificate fingerprint to stdout:

```
============================================================================
  capstan — Docker Engine API front door
============================================================================
  listening      https://:9443
  docker socket  /var/run/docker.sock
  certificate    /data/capstan.crt (generated new certificate)
  valid until    2036-08-21T00:08:29Z

  SHA-256 fingerprint — pin this value in the console:

    E2:13:D8:F3:5F:07:A3:55:32:12:B4:78:3B:A3:8F:2D:
    FC:D2:0F:B8:23:80:BB:EC:B5:C7:47:23:42:14:3B:ED

============================================================================
```

Read it off the host with `docker logs capstan` and type it into the console.
Reading it off the host is the point: it is the one step that is not
trust-on-first-use, and it is why the value is printed as a banner instead of
buried in a log line.

To confirm it independently — the image has no shell, so ask the listener
itself:

```bash
openssl s_client -connect docker-01.lan:9443 </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256
```

That must print the same value as the banner. Run it from the host, not from
wherever you happen to be sitting: verifying over the network is what pinning
is for.

The certificate is self-signed with a ten-year expiry and is **never
regenerated**. A homelab has no CA, so the fingerprint is the whole identity: a
value that changes behind your back is indistinguishable from an interception,
and capstan must never be the cause of that alarm. If you genuinely need a new
identity, delete `/data` and re-pin deliberately.

## Configuration

Environment only. Every variable has a working default; `docker run` with no
`-e` at all produces a running, secure service.

| Variable                 | Default                   | Notes |
|--------------------------|---------------------------|-------|
| `CAPSTAN_LISTEN`         | `:9443`                   | TLS listen address. |
| `CAPSTAN_TOKEN`          | *generated*               | Bearer token. If unset, one is minted and logged **once** at startup. Set it to keep it out of the logs. |
| `CAPSTAN_TLS_CERT`       | `/data/capstan.crt`       | Created on first run. |
| `CAPSTAN_TLS_KEY`        | `/data/capstan.key`       | Created on first run, mode `0600`. |
| `CAPSTAN_TLS_SANS`       | —                         | Extra DNS names or IPs for the certificate, comma-separated. |
| `CAPSTAN_DOCKER_SOCKET`  | `/var/run/docker.sock`    | Upstream socket. |
| `CAPSTAN_ALLOW_WRITE`    | `false`                   | Enables the write tier. Only `1`, `true`, `yes`, `on` count; anything else is treated as a typo and leaves writes off. |
| `CAPSTAN_LOG_LEVEL`      | `info`                    | `debug`, `info`, `warn`, `error`. |

## Authentication

Every request needs `Authorization: Bearer <token>`. Anything else gets `401`
with an empty body — no hint about whether the token was absent, malformed or
wrong, and no indication of which endpoints exist. The comparison is
constant-time over SHA-256 digests rather than the raw tokens, so it leaks
neither the content nor the length.

Authentication runs **before** the allowlist. A `403` where a `401` belongs
would be a free map of the allowlist for anyone who can reach the port.

## The allowlist is the security model

Enforced here, never trusted to the caller. Anything that can reach this port is
untrusted, token or not — a token proves the caller is the console, not that the
console is uncompromised.

Default deny: a request matching no row is refused.

### Read tier — always on

```
GET  /_ping  /version  /info  /events
GET  /containers/json  /containers/{id}/json  /containers/{id}/logs
     /containers/{id}/stats  /containers/{id}/top
GET  /images/json  /images/{name}/json  /volumes  /networks
```

### Write tier — off by default, `CAPSTAN_ALLOW_WRITE=true`

```
POST   /containers/{id}/start|stop|restart|kill|pause|unpause
POST   /images/create                     (docker pull)
DELETE /containers/{id}  /images/{id}  /volumes/{name}
```

The line between this tier and the forbidden list is not "how much damage could
this do" — a careless `DELETE` can ruin a day. It is whether the endpoint can
hand the caller control of the *host*. Everything in the write tier acts on a
container or image that already exists, created by someone with a real trust
relationship to the machine. capstan can stop your database; it cannot start a
new container with `/` bind-mounted into it.

Note that `POST /images/create` (which is `docker pull`) is in this tier, while
`POST /containers/create` is permanently forbidden. The names are confusingly
close; the endpoints are nothing alike.

With writes disabled these return `403` with a distinct message, so an operator
can tell a setting apart from a wall:

```
$ docker stop web
Error response from daemon: capstan: write operations are disabled

$ docker run --rm alpine true
docker: Error response from daemon: capstan: endpoint permanently disabled
```

### Never, at any setting

`POST /containers/create`, `POST /containers/{id}/exec` and `/exec/*`,
`POST /build`, `POST /commit`.

These are host escape, not merely "dangerous". The full argument lives in
[`internal/allowlist/allowlist.go`](internal/allowlist/allowlist.go), next to
the table, because anyone about to widen the allowlist should have to walk past
it. In short: `HostConfig.Binds`, `Privileged` and `PidMode` make `create`
trivially root on the host, and they are fields in a JSON body rather than
separate paths, so there is no subset of `create` that can be safely allowed
without validating a moving target inside an API capstan has promised to pass
through verbatim. `exec` reaches the same place through any container that is
already privileged or already has a host path mounted. `build` is arbitrary code
execution by design.

Denials are shaped like Engine API errors (`{"message": "..."}`), so a stock
client renders them rather than choking:

```
$ docker run --rm alpine true
docker: Error response from daemon: capstan: endpoint permanently disabled
```

Requests that hit the never-allowed table are logged at `WARN`. Something asking
for `/containers/create` is worth noticing.

## Integration contract

The consumer (the [vantric](https://example.invalid/vantric) console) stores
three things per Docker host and nothing else:

- base URL — `https://docker-01.lan:9443`
- bearer token
- certificate SHA-256 fingerprint, pinned on connect

That is the entire contract. Because capstan speaks the Engine API verbatim,
there is nothing else to coordinate: point any Docker API client at it.

```bash
# A stock Docker CLI, with capstan's certificate as the CA and the token
# supplied through the client's own HttpHeaders config.
mkdir -p certs && cp capstan.crt certs/ca.pem
echo '{"HttpHeaders":{"Authorization":"Bearer '"$CAPSTAN_TOKEN"'"}}' > cfg/config.json

DOCKER_CONFIG=cfg DOCKER_HOST=tcp://docker-01.lan:9443 \
DOCKER_TLS_VERIFY=1 DOCKER_CERT_PATH=certs \
  docker ps
```

capstan serves HTTP/1.1 only, because `dockerd` does. Offering HTTP/2 would make
capstan and the socket observably different servers — different header
canonicalization, different trailer handling, no connection upgrades — which is
exactly the kind of divergence it exists to avoid.

## Why not tecnativa/docker-socket-proxy

It is the same idea and it is good, but it has no auth and no TLS — it relies on
being unreachable. capstan is that plus both, in one binary instead of an
haproxy config, because by definition it has to cross a network.

## Non-goals

No UI, no database, no scheduler, no Docker features of its own. One instance
per host, no multi-host awareness.

## Development

```bash
go test ./...          # no Docker required; the server tests use a fake socket
go build ./cmd/capstan
docker build -t capstan:local .
```

CI runs `gofmt`, `go vet` and `go test -race` on every push and pull request.
Pushes to `main` publish `:edge`; a `vX.Y.Z` tag publishes the semver tags and
moves `:latest`.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

capstan is a network service, so section 13 is the operative clause: if you
modify it and let others interact with it over a network, they are entitled to
the source of your modified version. Running an unmodified copy on your own
hosts carries no obligation.

Note that capstan does not advertise a source link in its responses, which is
the usual way a network service discharges that offer. Injecting a header into
proxied replies would be a divergence from the Docker Engine API, and this
codebase treats such divergences as bugs. If you deploy a modified capstan for
others to use, make the offer out of band.

Running it against a socket directly:

```bash
CAPSTAN_TOKEN=dev \
CAPSTAN_LISTEN=127.0.0.1:9443 \
CAPSTAN_TLS_CERT=./data/capstan.crt \
CAPSTAN_TLS_KEY=./data/capstan.key \
CAPSTAN_DOCKER_SOCKET=/var/run/docker.sock \
  go run ./cmd/capstan
```
