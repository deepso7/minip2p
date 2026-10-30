# syntax=docker/dockerfile:1.7

FROM node:24-bookworm@sha256:be23f54a88d34e8824c741b19b91064094f92c1c97b194144bfc8b50d67258e2 AS toolchain

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
      curl \
      git \
      jq \
      pkg-config \
      python3 \
    && rm -rf /var/lib/apt/lists/* \
    && RUST_TOOLCHAIN=$(jq -r .rust /tmp/bench-pins.json) \
    && CARGO_CHEF_VERSION=$(jq -r .cargo_chef /tmp/bench-pins.json) \
    && GUNGRAUN_VERSION=$(jq -r .gungraun /tmp/bench-pins.json) \
    && VALGRIND_VERSION=$(jq -r .valgrind /tmp/bench-pins.json) \
    && VALGRIND_SHA256=$(jq -r .valgrind_sha256 /tmp/bench-pins.json) \
    && curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain "$RUST_TOOLCHAIN" --profile minimal \
    && cargo install --locked --version "$CARGO_CHEF_VERSION" cargo-chef \
    && cargo install --locked --version "$GUNGRAUN_VERSION" gungraun-runner \
    && curl -fsSLO "https://sourceware.org/pub/valgrind/valgrind-${VALGRIND_VERSION}.tar.bz2" \
    && printf '%s  %s\n' "$VALGRIND_SHA256" "valgrind-${VALGRIND_VERSION}.tar.bz2" | sha256sum --check \
    && tar -xjf "valgrind-${VALGRIND_VERSION}.tar.bz2" \
    && cd "valgrind-${VALGRIND_VERSION}" \
    && ./configure --prefix=/usr/local \
    && make -j"$BUILD_JOBS" \
    && make install \
    && cd / \
    && rm -rf "valgrind-${VALGRIND_VERSION}" "valgrind-${VALGRIND_VERSION}.tar.bz2" /tmp/bench-pins.json

FROM toolchain AS planner

WORKDIR /minip2p
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM toolchain AS builder

WORKDIR /minip2p

COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY docs/package.json docs/
COPY bindings/ts/core/package.json bindings/ts/core/
COPY bindings/ts/node/package.json bindings/ts/node/
COPY bindings/ts/node-platforms/ bindings/ts/node-platforms/
COPY bindings/ts/react-native/package.json bindings/ts/react-native/
COPY examples/react-native/package.json examples/react-native/
COPY bindings/ts/react-native/patches/ bindings/ts/react-native/patches/
COPY bindings/ts/test-fixtures/package.json bindings/ts/test-fixtures/
# Install the pnpm pinned by `packageManager` so it can never drift from the
# workspace (a mismatched pnpm tries to self-switch and fails in the image).
RUN PNPM_VERSION=$(jq -er '.packageManager | select(startswith("pnpm@")) | ltrimstr("pnpm@") | split("+")[0]' package.json) \
    && npm install --global "pnpm@${PNPM_VERSION}" \
    && pnpm install --frozen-lockfile

COPY --from=planner /minip2p/recipe.json recipe.json
COPY bench/targets bench/
COPY scripts/build-benches.sh scripts/
RUN cargo chef cook --release --package minip2p-nodejs --recipe-path recipe.json \
    && scripts/build-benches.sh cook

COPY . .

RUN pnpm --filter @minip2p/node native:build \
    && scripts/build-benches.sh

# No ENTRYPOINT: scripts/run-bench-container.sh supplies the entrypoint.
