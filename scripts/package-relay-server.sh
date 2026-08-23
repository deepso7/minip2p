#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 VERSION TARGET BINARY OUTPUT_DIR" >&2
  exit 2
fi

version="$1"
target="$2"
binary="$3"
output_dir="$4"

[[ -x "$binary" ]] || {
  echo "relay binary is not executable: $binary" >&2
  exit 2
}
[[ -n "$version" && "$version" != *[!0-9A-Za-z.+-]* ]] || {
  echo "invalid release version: $version" >&2
  exit 2
}
[[ -n "$target" && "$target" != *[!0-9A-Za-z_-]* ]] || {
  echo "invalid release target: $target" >&2
  exit 2
}

repository="$(cd "$(dirname "$0")/.." && pwd)"
archive_name="minip2p-relay-server-v${version}-${target}"
mkdir -p "$output_dir"
staging="$(mktemp -d "${TMPDIR:-/tmp}/minip2p-relay-server.XXXXXX")"
trap 'rm -rf "$staging"' EXIT

mkdir "$staging/$archive_name"
install -m 0755 "$binary" "$staging/$archive_name/minip2p-relay"
install -m 0644 "$repository/examples/relay-server/README.md" "$staging/$archive_name/README.md"
install -m 0644 "$repository/LICENSE" "$staging/$archive_name/LICENSE"

tar -C "$staging" -czf "$output_dir/$archive_name.tar.gz" "$archive_name"
echo "$output_dir/$archive_name.tar.gz"
