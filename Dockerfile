# Build a fully static binary. capstan has no dependencies outside the standard
# library, so there is nothing to vendor and nothing to link against.
FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /capstan ./cmd/capstan

# /data holds the certificate and key. Create it here, owned by the runtime
# uid, so that a fresh named volume inherits that ownership and capstan can
# write its certificate on first run without being root.
RUN mkdir -p /data && chown 65532:65532 /data && chmod 700 /data

# scratch, because the attack surface of a process that fronts the Docker
# socket should not include a shell, a package manager or a libc. There is
# nothing in this image but the binary and an empty data directory, which is
# also why `capstan healthcheck` exists as a subcommand.
FROM scratch

COPY --from=build /capstan /capstan
COPY --from=build --chown=65532:65532 /data /data

# Non-root. The container still needs group access to the socket, which is a
# deploy-time fact (the docker group's gid differs per host), so compose
# supplies it as `user: "65532:<docker gid>"`. See the README.
USER 65532:65532

VOLUME ["/data"]
EXPOSE 9443

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/capstan", "healthcheck"]

ENTRYPOINT ["/capstan"]
