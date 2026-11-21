#!/usr/bin/env bash
set -euo pipefail

release_version="${1:-${RELEASE_VERSION:-}}"
packages_dir="${2:-packages}"
if [[ -z "$release_version" ]]; then
  echo "usage: $0 <version> [packages-dir]" >&2
  exit 2
fi

npm_version="$(npm --version)"
node -e '
  const [major, minor] = process.argv[1].split(".").map(Number);
  if (major < 11 || (major === 11 && minor < 5)) process.exit(1);
' "$npm_version"
echo "npm $npm_version supports trusted publishing"

publish_package() {
  local package_name="$1"
  local tarball="$2"
  local encoded_name="${package_name/@/%40}"
  encoded_name="${encoded_name/\//%2f}"
  local package_http_code
  package_http_code="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --connect-timeout 10 \
    --max-time 30 \
    --retry 2 \
    --user-agent 'minip2p-release-workflow (https://github.com/deepso7/minip2p)' \
    "https://registry.npmjs.org/$encoded_name/$release_version")"

  if [[ "$package_http_code" == "200" ]]; then
    echo "$package_name $release_version is already published; skipping"
    return
  fi
  if [[ "$package_http_code" != "404" ]]; then
    echo "::error::npm returned HTTP $package_http_code while checking $package_name@$release_version" >&2
    exit 1
  fi

  if [[ "$tarball" != /* && "$tarball" != ./* ]]; then
    tarball="./$tarball"
  fi
  npm publish "$tarball" --access public
}

publish_package "@minip2p/core" "$packages_dir/minip2p-core-$release_version.tgz"
publish_package "@minip2p/react-native" "$packages_dir/minip2p-react-native-$release_version.tgz"
publish_package "@minip2p/node" "$packages_dir/minip2p-node-$release_version.tgz"
publish_package "@minip2p/web" "$packages_dir/minip2p-web-$release_version.tgz"
