# syntax=docker/dockerfile:1.7

FROM node:24-bookworm@sha256:be23f54a88d34e8824c741b19b91064094f92c1c97b194144bfc8b50d67258e2 AS toolchain

ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
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
    && make -j"$(nproc)" \
    && make install \
    && cd / \
    && rm -rf "valgrind-${VALGRIND_VERSION}" "valgrind-${VALGRIND_VERSION}.tar.bz2" /tmp/bench-pins.json

FROM toolchain AS planner

WORKDIR /minip2p
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM toolchain AS deps

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

# The Node addon builds in its own stage, which BuildKit runs alongside the
# bench dependency cook, and only the `.node` file reaches the image: `napi build`
# always passes `--target <host triple>`, so its artifacts land in
# target/<triple>/, which nothing at run time reads. Cook steps stay at
# CARGO_BUILD_JOBS=1 so concurrent addon + builder cooks across two A/B builds
# stay within 4 job slots and share layers regardless of BUILD_JOBS.
FROM deps AS addon

RUN CARGO_BUILD_JOBS=1 cargo chef cook --release --package minip2p-nodejs --target "$(rustc -vV | sed -n 's/^host: //p')" --recipe-path recipe.json

COPY . .

ARG BUILD_JOBS=2
RUN addon_jobs=$((BUILD_JOBS / 2 > 0 ? BUILD_JOBS / 2 : 1)) \
    && CARGO_BUILD_JOBS=$addon_jobs pnpm --filter @minip2p/node native:build

FROM deps AS builder

COPY bench/targets bench/
COPY scripts/build-benches.sh scripts/
# Fetch every locked crate, for all targets, so the offline container can run
# `cargo metadata`, which Criterion calls to find target/criterion.
RUN CARGO_BUILD_JOBS=1 scripts/build-benches.sh cook \
    && cargo fetch --locked

COPY . .
COPY --from=addon /minip2p/bindings/ts/node/*.node bindings/ts/node/

ARG BUILD_JOBS=2
RUN CARGO_BUILD_JOBS=$BUILD_JOBS scripts/build-benches.sh

# No ENTRYPOINT: scripts/run-bench-container.sh supplies the entrypoint.
