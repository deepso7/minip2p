# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# The download stage runs on the build platform (no QEMU for apt or curl) and
# picks the prebuilt static musl binary for TARGETARCH; only the runtime stage
# is per-arch. The binary needs no libc, so the runtime is distroless/static.
FROM --platform=$BUILDPLATFORM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS download

# Kept above the version ARGs so a release bump reuses this layer.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir /data

ARG MINIP2P_VERSION
ARG MINIP2P_RELEASE_BASE_URL
ARG TARGETARCH

RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) target="x86_64-unknown-linux-musl" ;; \
      arm64) target="aarch64-unknown-linux-musl" ;; \
      *) echo "unsupported container architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    archive="minip2p-relay-server-v${MINIP2P_VERSION}-${target}"; \
    release="${MINIP2P_RELEASE_BASE_URL:-https://github.com/deepso7/minip2p/releases/download/v${MINIP2P_VERSION}}"; \
    mkdir /release /out; \
    curl -fsSL -o "/release/$archive.tar.gz" "$release/$archive.tar.gz"; \
    curl -fsSL -o /release/SHA256SUMS "$release/SHA256SUMS"; \
    grep -F "  $archive.tar.gz" /release/SHA256SUMS > /release/CHECKSUM; \
    cd /release; \
    sha256sum --check CHECKSUM; \
    tar -xzf "$archive.tar.gz"; \
    install -m 0755 "$archive/minip2p-relay" /out/minip2p-relay

FROM gcr.io/distroless/static-debian13@sha256:15f8637509792e05b97d83451b0b6ccfa4abd548f997e406ac1e72c87fe1fa78 AS runtime

ARG MINIP2P_VERSION

LABEL org.opencontainers.image.title="minip2p relay server" \
      org.opencontainers.image.description="Circuit relay server for minip2p" \
      org.opencontainers.image.source="https://github.com/deepso7/minip2p" \
      org.opencontainers.image.version="$MINIP2P_VERSION" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

# COPY rather than RUN mkdir: distroless has no shell, and building the runtime
# stage then executes nothing on the target arch.
COPY --from=download --chown=10001:10001 /data /data

USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 19876/tcp 19876/udp
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/minip2p-relay"]
CMD ["--key", "/data/identity.key"]

FROM runtime AS release-image
COPY --from=download --chown=10001:10001 /out/minip2p-relay /usr/local/bin/minip2p-relay
