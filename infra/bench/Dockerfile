# syntax=docker/dockerfile:1.7

FROM node:24-bookworm@sha256:be23f54a88d34e8824c741b19b91064094f92c1c97b194144bfc8b50d67258e2

ARG VALGRIND_SHA256=5d589152eb8071c02feab8ce6ab719e431a1fbc3e2b1700f5432632a8b9264dc
ARG PNPM_VERSION=11.24.0
ARG BUILD_JOBS=2

ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_BUILD_JOBS=$BUILD_JOBS \
    PATH=/usr/local/cargo/bin:$PATH \
    CARGO_TERM_COLOR=always

COPY bench/pins.json /tmp/bench-pins.json

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      autoconf \
      automake \
      build-essential \
      bzip2 \
      ca-certificates \
      clang \
      cmake \
      curl \
      git \
      jq \
      libclang-dev \
      pkg-config \
      python3 \
    && rm -rf /var/lib/apt/lists/* \
    && RUST_TOOLCHAIN=$(jq -r .rust /tmp/bench-pins.json) \
    && GUNGRAUN_VERSION=$(jq -r .gungraun /tmp/bench-pins.json) \
    && VALGRIND_VERSION=$(jq -r .valgrind /tmp/bench-pins.json) \
    && curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain "$RUST_TOOLCHAIN" --profile minimal \
    && cargo install --locked --version "$GUNGRAUN_VERSION" gungraun-runner \
    && curl -fsSLO "https://sourceware.org/pub/valgrind/valgrind-${VALGRIND_VERSION}.tar.bz2" \
    && printf '%s  %s\n' "$VALGRIND_SHA256" "valgrind-${VALGRIND_VERSION}.tar.bz2" | sha256sum --check \
    && tar -xjf "valgrind-${VALGRIND_VERSION}.tar.bz2" \
    && cd "valgrind-${VALGRIND_VERSION}" \
    && ./configure --prefix=/usr/local \
    && make -j"$BUILD_JOBS" \
    && make install \
    && cd / \
    && rm -rf "valgrind-${VALGRIND_VERSION}" "valgrind-${VALGRIND_VERSION}.tar.bz2" /tmp/bench-pins.json \
    && npm install --global "pnpm@${PNPM_VERSION}"

WORKDIR /minip2p
COPY . .

RUN pnpm --dir bindings/ts install --frozen-lockfile \
    && pnpm --dir bindings/ts --filter @minip2p/node native:build \
    && cargo bench -p minip2p-core --bench multiaddr --no-run \
    && cargo bench -p minip2p-yamux --bench data_path --no-run \
    && cargo bench -p minip2p-discovery --bench peer_book --no-run \
    && cargo bench -p minip2p-pubsub --bench fanout --no-run \
    && cargo bench -p minip2p-relay-server --bench relay_server_event --no-run \
    && cargo bench -p minip2p-quic --bench idle_poll --no-run \
    && cargo bench -p minip2p-tcp --bench readiness_poll --no-run \
    && cargo bench -p minip2p-rs --features tcp --bench endpoint_e2e --no-run \
    && cargo bench -p minip2p-core --bench multiaddr_ir --no-run \
    && cargo bench -p minip2p-yamux --bench data_path_ir --no-run \
    && cargo bench -p minip2p-discovery --bench peer_book_ir --no-run \
    && cargo bench -p minip2p-pubsub --bench fanout_ir --no-run \
    && cargo bench -p minip2p-relay-server --bench relay_server_event_ir --no-run

ENTRYPOINT ["scripts/run-fargate-benches.sh"]
