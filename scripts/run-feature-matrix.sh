#!/usr/bin/env bash
set -eu

operation=${1:-}
case "$operation" in
check | clippy | test) ;;
*)
  echo "usage: $0 check|clippy|test" >&2
  exit 2
  ;;
esac

# package | default features | explicit features
matrix=$(cat <<'EOF'
minip2p-rs|default|autonat
minip2p-rs|default|relay
minip2p-rs|default|pubsub
minip2p-rs|default|relay,pubsub
minip2p-rs|default|discovery
minip2p-rs|default|mdns
minip2p-rs|default|mdns,pubsub
minip2p-rs|default|discovery,mdns
minip2p-rs|default|discovery,mdns,relay
minip2p-rs|default|relay-server
minip2p-rs|default|relay,relay-server
minip2p-rs|default|relay,relay-server,tcp
minip2p-rs|no-default|std,tcp,relay-server
minip2p-rs|default|tcp
minip2p-rs|no-default|std,tcp
minip2p-rs|default|discovery,mdns,tcp,relay
minip2p-rs|default|discovery,mdns,tcp,relay,relay-server,bench
minip2p-rs|no-default|smoltcp
minip2p-rs|no-default|smoltcp,pubsub
minip2p-rs|no-default|smoltcp,discovery
minip2p-rs|default|relay,smoltcp
minip2p-rs|no-default|autonat
minip2p-rs|no-default|relay
minip2p-rs|no-default|relay,pubsub
minip2p-rs|no-default|relay-server
minip2p-rs|no-default|mdns,discovery
minip2p-rs|no-default|smoltcp,relay,discovery,relay-server
minip2p-tcp|default|smoltcp
minip2p-mdns|default|smoltcp
minip2p-transport|default|bench
minip2p-quic|default|diagnostics
minip2p-ffi-core|no-default|serde
EOF
)

run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

while IFS='|' read -r package defaults features; do
  set -- -p "$package"
  if [ "$defaults" = "no-default" ]; then
    set -- "$@" --no-default-features
  fi
  set -- "$@" --features "$features"

  case "$operation" in
  check)
    if [ "$package" = "minip2p-rs" ]; then
      run cargo check "$@"
    else
      run cargo check "$@" --all-targets
    fi
    ;;
  clippy)
    run cargo clippy "$@" --all-targets -- -D warnings
    ;;
  test)
    run cargo nextest run --profile variants "$@"
    ;;
  esac
done <<<"$matrix"
