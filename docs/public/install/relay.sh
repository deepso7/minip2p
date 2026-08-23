#!/bin/sh
set -eu

fail() {
  printf 'minip2p relay installer: %s\n' "$1" >&2
  exit 1
}

for command in curl tar sha256sum install; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done

test "$(uname -s)" = Linux || fail "prebuilt relay binaries currently support Linux only"
case "$(uname -m)" in
  x86_64|amd64) target="x86_64-unknown-linux-gnu" ;;
  aarch64|arm64) target="aarch64-unknown-linux-gnu" ;;
  *) fail "unsupported Linux architecture: $(uname -m)" ;;
esac

version="${MINIP2P_VERSION:-}"
if [ -z "$version" ]; then
  latest_url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
    https://github.com/deepso7/minip2p/releases/latest)"
  version="${latest_url##*/}"
fi
version="${version#v}"
case "$version" in
  ""|*[!0-9A-Za-z.+-]*) fail "invalid release version: $version" ;;
esac

archive="minip2p-relay-server-v$version-$target"
release_url="https://github.com/deepso7/minip2p/releases/download/v$version"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/minip2p-relay-install.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

curl -fsSL -o "$work_dir/$archive.tar.gz" "$release_url/$archive.tar.gz" ||
  fail "relay binary is not available for v$version on $target"
curl -fsSL -o "$work_dir/SHA256SUMS" "$release_url/SHA256SUMS" ||
  fail "SHA256SUMS is not available for v$version"

checksum_line="$(grep -F "  $archive.tar.gz" "$work_dir/SHA256SUMS" | head -n 1)"
test -n "$checksum_line" || fail "SHA256SUMS does not list $archive.tar.gz"
printf '%s\n' "$checksum_line" > "$work_dir/CHECKSUM"
(
  cd "$work_dir"
  sha256sum --check CHECKSUM
)

tar -xzf "$work_dir/$archive.tar.gz" -C "$work_dir"
binary="$work_dir/$archive/minip2p-relay-server"
test -x "$binary" || fail "archive does not contain an executable relay server"

install_dir="${MINIP2P_INSTALL_DIR:-/usr/local/bin}"
if [ ! -d "$install_dir" ]; then
  mkdir -p "$install_dir" 2>/dev/null || true
fi
if [ -w "$install_dir" ]; then
  install -m 0755 "$binary" "$install_dir/minip2p-relay-server"
elif command -v sudo >/dev/null 2>&1; then
  sudo install -d "$install_dir"
  sudo install -m 0755 "$binary" "$install_dir/minip2p-relay-server"
else
  fail "cannot write to $install_dir; set MINIP2P_INSTALL_DIR to a writable directory"
fi

printf 'installed minip2p-relay-server %s to %s\n' "$version" "$install_dir/minip2p-relay-server"
