#!/usr/bin/env bash
# Builds the static musl `minip2p-relay` release binary for TARGET and prints
# its path. The release workflow and the relay container test both call this,
# so the published binary and the tested one come from the same command.
#
# Needs the Rust TARGET installed (`rustup target add TARGET`) and musl-tools'
# `musl-gcc` for TARGET's architecture, so build on a native host.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 TARGET (x86_64-unknown-linux-musl or aarch64-unknown-linux-musl)" >&2
  exit 2
fi

target="$1"
case "$target" in
  x86_64-unknown-linux-musl | aarch64-unknown-linux-musl) ;;
  *)
    echo "unsupported relay release target: $target" >&2
    exit 2
    ;;
esac

repository="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repository"

# musl-gcc compiles ring's and mimalloc's C for the target; the linker stays
# Rust's default, since linking through musl-gcc produced a dynamic, crashing
# binary.
export "CC_${target//-/_}=musl-gcc"
export RUSTFLAGS="-C target-feature=+crt-static"
cargo build --release --locked --target "$target" \
  -p minip2p-relay-server-example --bin minip2p-relay >&2

binary="${CARGO_TARGET_DIR:-$repository/target}/$target/release/minip2p-relay"

# A glibc build linked for a newer runner fails to start on older hosts and
# images, so refuse anything that still needs a loader or shared libraries.
# A standalone assignment, so a readelf failure stops the script under set -e.
headers="$(readelf -lW -dW "$binary")"
if grep -qE 'INTERP|\(NEEDED\)' <<<"$headers"; then
  echo "relay binary is not statically linked: $binary" >&2
  grep -E 'INTERP|interpreter|NEEDED' <<<"$headers" >&2
  exit 1
fi

echo "$binary"
