#!/usr/bin/env bash
set -eu

usage() {
  echo "usage: $0 check|clippy|test [ci|full|<row>]" >&2
  echo "       $0 list" >&2
  exit 2
}

operation=${1:-}
selection=${2:-ci}
case "$operation" in
check | clippy | test | list) ;;
*) usage ;;
esac

matrix=$(cat <<'EOF'
autonat|minip2p-rs|default|autonat|ci
relay|minip2p-rs|default|relay|release
pubsub|minip2p-rs|default|pubsub|release
relay-pubsub|minip2p-rs|default|relay,pubsub|release
discovery|minip2p-rs|default|discovery|release
mdns|minip2p-rs|default|mdns|release
mdns-pubsub|minip2p-rs|default|mdns,pubsub|release
discovery-mdns|minip2p-rs|default|discovery,mdns|release
discovery-mdns-relay|minip2p-rs|default|discovery,mdns,relay|release
relay-server|minip2p-rs|default|relay-server|release
relay-relay-server|minip2p-rs|default|relay,relay-server|release
relay-relay-server-tcp|minip2p-rs|default|relay,relay-server,tcp|release
bare-tcp-relay-server|minip2p-rs|no-default|std,tcp,relay-server|ci
tcp|minip2p-rs|default|tcp|release
bare-tcp|minip2p-rs|no-default|std,tcp|release
discovery-mdns-tcp-relay|minip2p-rs|default|discovery,mdns,tcp,relay|release
everything|minip2p-rs|default|discovery,mdns,tcp,relay,relay-server,bench|ci
smoltcp|minip2p-rs|no-default|smoltcp|release
smoltcp-pubsub|minip2p-rs|no-default|smoltcp,pubsub|ci
smoltcp-discovery|minip2p-rs|no-default|smoltcp,discovery|release
relay-smoltcp|minip2p-rs|default|relay,smoltcp|release
bare-autonat|minip2p-rs|no-default|autonat|release
bare-relay|minip2p-rs|no-default|relay|release
bare-relay-pubsub|minip2p-rs|no-default|relay,pubsub|release
bare-relay-server|minip2p-rs|no-default|relay-server|release
bare-mdns-discovery|minip2p-rs|no-default|mdns,discovery|release
smoltcp-embedded|minip2p-rs|no-default|smoltcp,relay,discovery,relay-server|ci
tcp-smoltcp|minip2p-tcp|default|smoltcp|ci
mdns-smoltcp|minip2p-mdns|default|smoltcp|ci
secure-mux-bare|minip2p-secure-mux|no-default||ci
transport-bench|minip2p-transport|default|bench|release
quic-diagnostics|minip2p-quic|default|diagnostics|ci
ffi-core-serde|minip2p-ffi-core|no-default|serde|release
web-bare|minip2p-web|no-default||ci
EOF
)

duplicates=$(cut -d'|' -f1 <<<"$matrix" | sort | uniq -d)
if [ -n "$duplicates" ]; then
  echo "duplicate matrix row names: $duplicates" >&2
  exit 1
fi

if [ "$operation" = list ]; then
  column -t -s'|' <<<"$matrix"
  exit 0
fi

case "$selection" in
ci | full) ;;
*)
  if ! cut -d'|' -f1 <<<"$matrix" | grep -qxF -- "$selection"; then
    echo "unknown matrix row: $selection (see \`$0 list\`)" >&2
    exit 2
  fi
  ;;
esac

run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

while IFS='|' read -r name package defaults features tier; do
  case "$selection" in
  ci) [ "$tier" = ci ] || continue ;;
  full) ;;
  *) [ "$name" = "$selection" ] || continue ;;
  esac

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
    run cargo nextest run --profile variants --locked "$@"
    ;;
  esac
done <<<"$matrix"
