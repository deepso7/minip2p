#!/usr/bin/env sh
set -eu

version=0.13.8
checksum=deab71f2e20691b4728b349c6cee8fc7223880fa67b6b4f92225ec32225447e5
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' EXIT HUP INT TERM

archive="$temp_dir/yamux.crate"
curl -fsSL \
  "https://static.crates.io/crates/yamux/yamux-$version.crate" \
  -o "$archive"
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$archive" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$archive" | awk '{print $1}')
else
  echo "sha256sum or shasum is required to verify the producer crate" >&2
  exit 1
fi
if [ "$actual" != "$checksum" ]; then
  echo "yamux checksum mismatch: expected $checksum, got $actual" >&2
  exit 1
fi

tar -xzf "$archive" -C "$temp_dir"
producer="$temp_dir/yamux-$version"

CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR="$temp_dir/target" cargo \
  --config "patch.crates-io.yamux.path='$producer'" \
  run --locked --quiet --manifest-path "$fixture_dir/generate-yamux/Cargo.toml"
