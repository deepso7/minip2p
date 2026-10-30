#!/usr/bin/env bash
# Builds the relay release binary with scripts/build-relay-release.sh, packages
# it like a release, builds the image through infra/relay/Dockerfile from a
# local release URL, and runs scripts/check-relay-image.sh on it.
set -euo pipefail

repository="$(cd "$(dirname "$0")/.." && pwd)"
version="$(cargo metadata --locked --no-deps --format-version 1 \
  | jq -r '.packages[] | select(.name == "minip2p-relay-server-example") | .version')"
suffix="$$"
image="minip2p-relay-test:$suffix"
builder_image="minip2p-relay-builder:$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/minip2p-relay-container.XXXXXX")"
server_pid=""

cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" 2>/dev/null || true
  fi
  docker image rm --force "$image" >/dev/null 2>&1 || true
  docker image rm --force "$builder_image" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT

case "$(docker version --format '{{.Server.Arch}}')" in
  amd64) target="x86_64-unknown-linux-musl" ;;
  arm64) target="aarch64-unknown-linux-musl" ;;
  *) echo "unsupported Docker architecture" >&2; exit 1 ;;
esac

docker build \
  --file "$repository/scripts/relay-builder.Dockerfile" \
  --tag "$builder_image" \
  "$repository"
mkdir "$work_dir/build" "$work_dir/release"
docker run --rm \
  --user "$(id -u):$(id -g)" \
  --env CARGO_HOME=/build/cargo \
  --env CARGO_TARGET_DIR=/build/target \
  --volume "$repository:/src:ro" \
  --volume "$work_dir/build:/build" \
  --workdir /src \
  "$builder_image" \
  scripts/build-relay-release.sh "$target" >/dev/null

"$repository/scripts/package-relay-server.sh" \
  "$version" \
  "$target" \
  "$work_dir/build/target/$target/release/minip2p-relay" \
  "$work_dir/release" >/dev/null
(
  cd "$work_dir/release"
  sha256sum minip2p-relay-server-*.tar.gz > SHA256SUMS
)

python3 - "$work_dir/release" "$work_dir/port" <<'PY' &
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys

root, port_file = sys.argv[1:]
server = ThreadingHTTPServer(
    ("0.0.0.0", 0), partial(SimpleHTTPRequestHandler, directory=root)
)
Path(port_file).write_text(str(server.server_port))
server.serve_forever()
PY
server_pid="$!"
for _ in {1..20}; do
  [[ -s "$work_dir/port" ]] && break
  sleep 0.1
done
[[ -s "$work_dir/port" ]]
release_base_url="http://host.docker.internal:$(<"$work_dir/port")"

docker build \
  --add-host host.docker.internal:host-gateway \
  --file "$repository/infra/relay/Dockerfile" \
  --build-arg "MINIP2P_VERSION=$version" \
  --build-arg "MINIP2P_RELEASE_BASE_URL=$release_base_url" \
  --tag "$image" \
  "$repository"

"$repository/scripts/check-relay-image.sh" "$image" "$version"
