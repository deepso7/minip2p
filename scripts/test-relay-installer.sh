#!/usr/bin/env bash
set -euo pipefail

repository="$(cd "$(dirname "$0")/.." && pwd)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/minip2p-relay-installer.XXXXXX")"
trap 'rm -rf "$test_root"' EXIT

version="9.8.7"
target="x86_64-unknown-linux-gnu"
archive="minip2p-relay-server-v$version-$target"
mkdir -p "$test_root/release/$archive" "$test_root/bin" "$test_root/install"

cat >"$test_root/release/$archive/minip2p-relay" <<EOF
#!/bin/sh
printf '%s\n' 'minip2p-relay $version'
EOF
chmod 0755 "$test_root/release/$archive/minip2p-relay"
tar -C "$test_root/release" -czf "$test_root/release/$archive.tar.gz" "$archive"

arm_target="aarch64-unknown-linux-gnu"
arm_archive="minip2p-relay-server-v$version-$arm_target"
mkdir "$test_root/release/$arm_archive"
cp "$test_root/release/$archive/minip2p-relay" \
  "$test_root/release/$arm_archive/minip2p-relay"
tar -C "$test_root/release" -czf "$test_root/release/$arm_archive.tar.gz" "$arm_archive"
(
  cd "$test_root/release"
  sha256sum "$archive.tar.gz" "$arm_archive.tar.gz" > SHA256SUMS
)

cat >"$test_root/bin/uname" <<'EOF'
#!/bin/sh
case "$1" in
  -s) printf '%s\n' Linux ;;
  -m) printf '%s\n' "${RELAY_INSTALLER_UNAME_M:-x86_64}" ;;
  *) exit 2 ;;
esac
EOF
chmod 0755 "$test_root/bin/uname"

cat >"$test_root/bin/curl" <<'EOF'
#!/bin/sh
set -eu
output=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o)
      output="$2"
      shift 2
      ;;
    http://*|https://*)
      url="$1"
      shift
      ;;
    *) shift ;;
  esac
done
case "$url" in
  */releases/latest)
    printf 'https://github.com/deepso7/minip2p/releases/tag/v%s' "$RELAY_INSTALLER_VERSION"
    exit 0
    ;;
  */SHA256SUMS) source="$RELAY_INSTALLER_FIXTURE/SHA256SUMS" ;;
  */*.tar.gz)
    case "${url##*/}" in
      *-"$RELAY_INSTALLER_EXPECT_TARGET".tar.gz) ;;
      *) exit 22 ;;
    esac
    source="$RELAY_INSTALLER_FIXTURE/${url##*/}"
    ;;
  *) exit 22 ;;
esac
test -n "$output"
cp "$source" "$output"
EOF
chmod 0755 "$test_root/bin/curl"

touch "$test_root/install/minip2p-relay-server"

PATH="$test_root/bin:$PATH" \
  RELAY_INSTALLER_FIXTURE="$test_root/release" \
  RELAY_INSTALLER_EXPECT_TARGET="$target" \
  MINIP2P_VERSION="$version" \
  MINIP2P_INSTALL_DIR="$test_root/install" \
  sh "$repository/docs/public/install/relay.sh"

test -x "$test_root/install/minip2p-relay"
test ! -e "$test_root/install/minip2p-relay-server"
test "$("$test_root/install/minip2p-relay" --version)" = \
  "minip2p-relay $version"

mkdir "$test_root/install-latest"
PATH="$test_root/bin:$PATH" \
  RELAY_INSTALLER_FIXTURE="$test_root/release" \
  RELAY_INSTALLER_EXPECT_TARGET="$arm_target" \
  RELAY_INSTALLER_VERSION="$version" \
  RELAY_INSTALLER_UNAME_M="aarch64" \
  MINIP2P_INSTALL_DIR="$test_root/install-latest" \
  sh "$repository/docs/public/install/relay.sh"

test "$("$test_root/install-latest/minip2p-relay" --version)" = \
  "minip2p-relay $version"
test ! -e "$test_root/install-latest/minip2p-relay-server"
