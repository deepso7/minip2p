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
minip2p-rs|default|nat
minip2p-rs|default|pubsub
minip2p-rs|default|nat,pubsub
minip2p-rs|default|discovery
minip2p-rs|default|mdns
minip2p-rs|default|mdns,pubsub
minip2p-rs|default|discovery,mdns
minip2p-rs|default|relay-server
minip2p-rs|default|nat,relay-server
minip2p-rs|default|nat,relay-server,tcp
minip2p-rs|no-default|std,tcp,relay-server
minip2p-rs|default|tcp
minip2p-rs|no-default|std,tcp
minip2p-rs|default|discovery,mdns,tcp
minip2p-rs|default|discovery,mdns,tcp,relay-server
minip2p-rs|no-default|smoltcp
minip2p-rs|no-default|smoltcp,pubsub
minip2p-rs|default|nat,smoltcp
minip2p-rs|default|nat,portable-autonat
minip2p-rs|default|nat,portable-mdns
minip2p-rs|no-default|portable-autonat
minip2p-rs|no-default|portable-relay
minip2p-rs|no-default|portable-relay,pubsub
minip2p-rs|default|nat,portable-relay,pubsub
minip2p-tcp|default|smoltcp
minip2p-mdns|default|smoltcp
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
