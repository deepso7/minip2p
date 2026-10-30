#!/usr/bin/env bash
# Checks that a built relay image starts: its metadata, `--version`, both
# TCP and QUIC listeners, and that its identity survives a container
# replacement on the same /data volume. Used by test-relay-container.sh and by
# the publish workflow on the release image before it is pushed.
#
# PLATFORM (e.g. linux/arm64) runs a foreign-arch image under QEMU.
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: $0 IMAGE VERSION [PLATFORM]" >&2
  exit 2
fi

image="$1"
version="$2"
platform=()
[[ $# -eq 3 ]] && platform=(--platform "$3")
suffix="$$"
container="minip2p-relay-check-$suffix"
volume="minip2p-relay-check-$suffix"

cleanup() {
  docker container rm --force "$container" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

metadata="$(docker image inspect "$image")"
jq -e '.[0].Config.User == "10001:10001"' <<<"$metadata" >/dev/null
jq -e '.[0].Config.Entrypoint == ["/usr/local/bin/minip2p-relay"]' \
  <<<"$metadata" >/dev/null
jq -e '.[0].Config.ExposedPorts | has("19876/tcp")' <<<"$metadata" >/dev/null
jq -e '.[0].Config.ExposedPorts | has("19876/udp")' <<<"$metadata" >/dev/null
jq -e '.[0].Config.Volumes | has("/data")' <<<"$metadata" >/dev/null
test "$(docker run --rm "${platform[@]}" "$image" --version)" = "minip2p-relay $version"

# Starts the relay on the volume and prints its peer ID once both listeners
# are up.
start_relay() {
  docker container rm --force "$container" >/dev/null 2>&1 || true
  docker run --detach "${platform[@]}" \
    --name "$container" \
    --volume "$volume:/data" \
    "$image" >/dev/null

  local logs
  for _ in {1..40}; do
    logs="$(docker logs "$container" 2>&1)"
    if grep -F "/tcp/19876/" <<<"$logs" >/dev/null &&
      grep -F "/udp/19876/quic-v1/" <<<"$logs" >/dev/null; then
      [[ "$(docker container inspect --format '{{.State.Running}}' "$container")" == true ]] ||
        return 1
      sed -n 's/^\[relay\] peer=\([^ ]*\).*/\1/p' <<<"$logs" | head -n 1
      return 0
    fi
    sleep 0.25
  done

  docker logs "$container" >&2
  return 1
}

docker volume create "$volume" >/dev/null
first_peer="$(start_relay)"
second_peer="$(start_relay)"
test -n "$first_peer"
test "$first_peer" = "$second_peer"
echo "relay image $image ok: peer $first_peer kept across restarts"
