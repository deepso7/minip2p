# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS download

ARG MINIP2P_VERSION
ARG TARGETARCH

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    rm -rf /var/lib/apt/lists/*; \
    case "$TARGETARCH" in \
      amd64) target="x86_64-unknown-linux-gnu" ;; \
      arm64) target="aarch64-unknown-linux-gnu" ;; \
      *) echo "unsupported container architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    archive="minip2p-relay-server-v${MINIP2P_VERSION}-${target}"; \
    release="https://github.com/deepso7/minip2p/releases/download/v${MINIP2P_VERSION}"; \
    mkdir /release /out; \
    curl -fsSL -o "/release/$archive.tar.gz" "$release/$archive.tar.gz"; \
    curl -fsSL -o /release/SHA256SUMS "$release/SHA256SUMS"; \
    grep -F "  $archive.tar.gz" /release/SHA256SUMS > /release/CHECKSUM; \
    cd /release; \
    sha256sum --check CHECKSUM; \
    tar -xzf "$archive.tar.gz"; \
    install -m 0755 "$archive/minip2p-relay-server" /out/minip2p-relay-server

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

ARG MINIP2P_VERSION

LABEL org.opencontainers.image.title="minip2p relay server" \
      org.opencontainers.image.description="Circuit relay server for minip2p" \
      org.opencontainers.image.source="https://github.com/deepso7/minip2p" \
      org.opencontainers.image.version="$MINIP2P_VERSION" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

COPY --from=download --chown=10001:10001 /out/minip2p-relay-server /usr/local/bin/minip2p-relay-server

RUN mkdir /data && chown 10001:10001 /data

USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 19876/tcp 19876/udp
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/minip2p-relay-server"]
CMD ["--key", "/data/identity.key"]
