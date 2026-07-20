#!/usr/bin/env sh
set -eu

# Maintainer-only helper. It downloads the exact producer crate, verifies the
# crates.io checksum, and applies two test-only substitutions so rust-libp2p's
# otherwise-random Noise static and ephemeral keys are reproducible.
version=0.46.1
checksum=bc73eacbe6462a0eb92a6527cac6e63f02026e5407f8831bde8293f19217bfbf
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' EXIT HUP INT TERM

archive="$temp_dir/libp2p-noise.crate"
curl -fsSL \
  "https://static.crates.io/crates/libp2p-noise/libp2p-noise-$version.crate" \
  -o "$archive"
actual=$(shasum -a 256 "$archive" | awk '{print $1}')
if [ "$actual" != "$checksum" ]; then
  echo "libp2p-noise checksum mismatch: expected $checksum, got $actual" >&2
  exit 1
fi

tar -xzf "$archive" -C "$temp_dir"
producer="$temp_dir/libp2p-noise-$version"
protocol="$producer/src/protocol.rs"

perl -0pi -e \
  's/let mut sk_bytes = \[0u8; 32\];\n        rand::thread_rng\(\)\.fill\(&mut sk_bytes\);/let mut sk_bytes = [31u8; 32];/' \
  "$protocol"
perl -0pi -e \
  's/rand::rngs::StdRng::from_entropy\(\)/rand::rngs::StdRng::from_seed([32u8; 32])/' \
  "$protocol"
perl -0pi -e \
  's/use rand::\{Rng as _, SeedableRng\};/use rand::SeedableRng;/' \
  "$protocol"

if ! grep -q 'let mut sk_bytes = \[31u8; 32\];' "$protocol" || \
   ! grep -q 'from_seed(\[32u8; 32\])' "$protocol" || \
   ! grep -q 'use rand::SeedableRng;' "$protocol"; then
  echo "failed to apply deterministic producer substitutions" >&2
  exit 1
fi

CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR="$temp_dir/target" cargo \
  --config "patch.crates-io.libp2p-noise.path='$producer'" \
  run --quiet --manifest-path "$fixture_dir/generate-libp2p/Cargo.toml"
