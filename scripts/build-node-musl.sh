#!/usr/bin/env bash
set -euo pipefail

target="${1:-}"
shift || true
run_tests=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --test)
      run_tests=true
      shift
      ;;
    *)
      echo "usage: $0 <target> [--test]" >&2
      exit 2
      ;;
  esac
done

case "$target" in
  x86_64-unknown-linux-musl) output=minip2p.linux-x64-musl.node ;;
  aarch64-unknown-linux-musl) output=minip2p.linux-arm64-musl.node ;;
  *)
    echo "Unsupported musl target: $target" >&2
    exit 1
    ;;
esac

repository="$(cd "$(dirname "$0")/.." && pwd)"
image="${NAPI_BUILD_IMAGE:-ghcr.io/napi-rs/napi-rs/nodejs-rust@sha256:caac2d1b9194eada0c69e669e72763869701351d8957ab805cc45a43999d8be2}"

docker run --rm \
  --env OUTPUT="$output" \
  --env RUN_TESTS="$run_tests" \
  --volume "$repository:/work" \
  --workdir /work/bindings/ts \
  "$image" \
  bash -lc '
    set -euo pipefail
    rustup toolchain install 1.91 --profile minimal
    rustup default 1.91
    export CC=gcc
    export CXX=g++
    export RUSTFLAGS="-C target-feature=-crt-static"
    cargo build --release --locked --manifest-path ../../crates/nodejs/Cargo.toml
    install ../../target/release/libminip2p_nodejs.so "node/$OUTPUT"
    if [[ "$RUN_TESTS" == true ]]; then
      apk add --no-cache --upgrade \
        --repository https://dl-cdn.alpinelinux.org/alpine/v3.23/main \
        nodejs npm
      export PATH=/usr/bin:$PATH
      npm install --global --prefix /opt/pnpm "$(node -p "require(\"/work/package.json\").packageManager.split(\"+\")[0]")"
      export PATH=/opt/pnpm/bin:/usr/bin:$PATH
      cargo build --release --locked -p minip2p-relay-server-example
      mkdir -p ../../target/debug
      cp ../../target/release/minip2p-relay ../../target/debug/minip2p-relay
      pnpm install --frozen-lockfile
      pnpm --filter @minip2p/node exec vitest run
    fi
  '
