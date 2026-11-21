#!/usr/bin/env bash
# The checks that are not host feature rows (scripts/run-feature-matrix.sh
# holds those). `just` and CI both call this, so the lists live only here.
#
#   nostd          every no_std crate, and the Endpoint's portable feature
#                  sets, on a real no_std target
#   wasm           the browser build's crates on wasm32
#   docs           rustdoc, with -D warnings where the docs are kept clean
#   package-check  every published crate ships its README, and the publish
#                  order resolves; pass --allow-dirty to package a dirty tree
set -eu

operation=${1:-}
shift || true

run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

nostd() {
  local target=thumbv7em-none-eabi
  run cargo check --no-default-features --target "$target" \
    -p minip2p-core -p minip2p-identity -p minip2p-transport -p minip2p-tls \
    -p minip2p-secure-mux -p minip2p-smoltcp -p minip2p-tcp -p minip2p-circuit \
    -p minip2p-identify -p minip2p-multistream-select -p minip2p-ping \
    -p minip2p-pubsub -p minip2p-discovery -p minip2p-mdns -p minip2p-relay \
    -p minip2p-relay-server -p minip2p-swarm \
    -p minip2p-nat -p minip2p-webtransport -p minip2p-rs
  run cargo check --no-default-features --features smoltcp --target "$target" -p minip2p-tcp -p minip2p-mdns -p minip2p-rs
  local features
  for features in smoltcp,pubsub autonat relay relay,pubsub relay-server mdns,discovery,relay smoltcp,relay,discovery,relay-server; do
    run cargo check --no-default-features --features "$features" --target "$target" -p minip2p-rs
  done
}

wasm() {
  local target=wasm32-unknown-unknown
  run cargo check --target "$target" -p minip2p-ffi-core --no-default-features --features serde
  run cargo check --target "$target" -p minip2p-rs --no-default-features --features pubsub
  run cargo check --target "$target" -p minip2p-webtransport --no-default-features
  run cargo clippy --target "$target" -p minip2p-web -- -D warnings
  run cargo clippy --target "$target" -p minip2p-web --no-default-features -- -D warnings
}

docs() {
  run cargo doc --workspace --no-deps
  RUSTDOCFLAGS="-D warnings" run cargo doc -p minip2p-relay-server --no-deps
  RUSTDOCFLAGS="-D warnings" run cargo doc -p minip2p-rs --features relay,discovery,mdns,tcp,relay-server --no-deps
  run cargo doc -p minip2p-tcp --features smoltcp --no-deps
  run cargo doc -p minip2p-mdns --features smoltcp --no-deps
  local features
  for features in smoltcp smoltcp,pubsub autonat relay smoltcp,relay,discovery,relay-server; do
    run cargo doc -p minip2p-rs --no-default-features --features "$features" --no-deps
  done
}

package_check() {
  local package_args=()
  if [ "${1:-}" = --allow-dirty ]; then
    package_args+=(--allow-dirty)
  fi
  local metadata package
  metadata=$(cargo metadata --no-deps --format-version 1)
  jq -e '[.packages[] | select(.publish != []) | .readme != null] | all' <<<"$metadata"
  jq -e '.packages[] | select(.name == "minip2p-rs") | .features["relay-server"] == ["dep:minip2p-relay-server"]' <<<"$metadata"
  for package in $(jq -r '.packages[] | select(.publish != []) | .name' <<<"$metadata"); do
    if ! cargo package -p "$package" "${package_args[@]}" --list | grep -qx 'README.md'; then
      echo "$package does not ship README.md" >&2
      exit 1
    fi
  done
  scripts/publish-order.py >/dev/null
}

case "$operation" in
nostd | wasm | docs) "$operation" ;;
package-check) package_check "$@" ;;
*)
  echo "usage: $0 nostd|wasm|docs|package-check [--allow-dirty]" >&2
  exit 2
  ;;
esac
