#!/usr/bin/env bash
set -euo pipefail

repository="$(cd "$(dirname "$0")/.." && pwd)"
version="$(cargo metadata --locked --no-deps --format-version 1 \
  | jq -r '.packages[] | select(.name == "minip2p-relay-server-example") | .version')"
suffix="$$"
image="minip2p-relay-test:$suffix"
builder_image="minip2p-relay-builder:$suffix"
container="minip2p-relay-test-$suffix"
volume="minip2p-relay-test-$suffix"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/minip2p-relay-container.XXXXXX")"
server_pid=""

cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" 2>/dev/null || true
  fi
  docker container rm --force "$container" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  docker image rm --force "$image" >/dev/null 2>&1 || true
  docker image rm --force "$builder_image" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT

case "$(docker version --format '{{.Server.Arch}}')" in
  amd64) target="x86_64-unknown-linux-gnu" ;;
  arm64) target="aarch64-unknown-linux-gnu" ;;
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
  cargo build --release --locked \
    -p minip2p-relay-server-example --bin minip2p-relay

"$repository/scripts/package-relay-server.sh" \
  "$version" \
  "$target" \
  "$work_dir/build/target/release/minip2p-relay" \
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
  --build-arg "MINIP2P_VERSION=$version" \
  --build-arg "MINIP2P_RELEASE_BASE_URL=$release_base_url" \
  --tag "$image" \
  "$repository"

test "$(docker image inspect --format '{{.Config.User}}' "$image")" = "10001:10001"
metadata="$(docker image inspect "$image")"
jq -e '.[0].Config.Entrypoint == ["/usr/local/bin/minip2p-relay"]' \
  <<<"$metadata" >/dev/null
jq -e '.[0].Config.ExposedPorts | has("19876/tcp")' <<<"$metadata" >/dev/null
jq -e '.[0].Config.ExposedPorts | has("19876/udp")' <<<"$metadata" >/dev/null
jq -e '.[0].Config.Volumes | has("/data")' <<<"$metadata" >/dev/null
test "$(docker run --rm "$image" --version)" = "minip2p-relay $version"

docker volume create "$volume" >/dev/null
docker run --detach \
  --name "$container" \
  --volume "$volume:/data" \
  "$image" >/dev/null

wait_for_relay() {
  for _ in {1..20}; do
    logs="$(docker logs "$container" 2>&1)"
    if grep -F "/tcp/19876/" <<<"$logs" >/dev/null &&
      grep -F "/udp/19876/quic-v1/" <<<"$logs" >/dev/null; then
      test "$(docker container inspect --format '{{.State.Running}}' "$container")" = true
      return 0
    fi
    sleep 0.25
  done

  docker logs "$container" >&2
  return 1
}

wait_for_relay
first_key="$(docker run --rm \
  --entrypoint sha256sum \
  --volume "$volume:/data" \
  "$image" \
  /data/identity.key)"

docker container rm --force "$container" >/dev/null
docker run --detach \
  --name "$container" \
  --volume "$volume:/data" \
  "$image" >/dev/null

wait_for_relay
second_key="$(docker run --rm \
  --entrypoint sha256sum \
  --volume "$volume:/data" \
  "$image" \
  /data/identity.key)"

test "$first_key" = "$second_key"
