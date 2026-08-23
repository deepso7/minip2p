#!/usr/bin/env bash
set -euo pipefail

repository="$(cd "$(dirname "$0")/.." && pwd)"
version="${MINIP2P_CONTAINER_TEST_VERSION:-0.4.3}"
suffix="$$"
image="minip2p-relay-test:$suffix"
container="minip2p-relay-test-$suffix"
volume="minip2p-relay-test-$suffix"

cleanup() {
  docker container rm --force "$container" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  docker image rm --force "$image" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker build \
  --build-arg "MINIP2P_VERSION=$version" \
  --tag "$image" \
  "$repository"

test "$(docker image inspect --format '{{.Config.User}}' "$image")" = "10001:10001"
metadata="$(docker image inspect "$image")"
jq -e '.[0].Config.ExposedPorts | has("19876/tcp")' <<<"$metadata" >/dev/null
jq -e '.[0].Config.ExposedPorts | has("19876/udp")' <<<"$metadata" >/dev/null
jq -e '.[0].Config.Volumes | has("/data")' <<<"$metadata" >/dev/null
test "$(docker run --rm "$image" --version)" = "minip2p-relay-server $version"

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
