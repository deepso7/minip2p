#!/usr/bin/env bash
set -eu

operation=${1:-}
case "$operation" in
check | clippy | test | test-full) ;;
*)
  echo "usage: $0 check|clippy|test|test-full" >&2
  exit 2
  ;;
esac

# package | default features | explicit features | test tier
#
# check and clippy build every row. `test` runs only the `ci` rows, which PRs
# and pushes to main use; `test-full` runs every row and gates releases. The
# `ci` rows plus the workspace run already list every test the full matrix
# does (1,975 distinct package/binary/test identities), so the `release` rows
# only re-run those tests under other feature combinations: a bug that needs
# one of those combinations at runtime is caught at release time, not on PRs.
matrix=$(cat <<'EOF'
minip2p-rs|default|autonat|ci
minip2p-rs|default|relay|release
minip2p-rs|default|pubsub|release
minip2p-rs|default|relay,pubsub|release
minip2p-rs|default|discovery|release
minip2p-rs|default|mdns|release
minip2p-rs|default|mdns,pubsub|release
minip2p-rs|default|discovery,mdns|release
minip2p-rs|default|discovery,mdns,relay|release
minip2p-rs|default|relay-server|release
minip2p-rs|default|relay,relay-server|release
minip2p-rs|default|relay,relay-server,tcp|release
minip2p-rs|no-default|std,tcp,relay-server|ci
minip2p-rs|default|tcp|release
minip2p-rs|no-default|std,tcp|release
minip2p-rs|default|discovery,mdns,tcp,relay|release
minip2p-rs|default|discovery,mdns,tcp,relay,relay-server,bench|ci
minip2p-rs|no-default|smoltcp|release
minip2p-rs|no-default|smoltcp,pubsub|ci
minip2p-rs|no-default|smoltcp,discovery|release
minip2p-rs|default|relay,smoltcp|release
minip2p-rs|no-default|autonat|release
minip2p-rs|no-default|relay|release
minip2p-rs|no-default|relay,pubsub|release
minip2p-rs|no-default|relay-server|release
minip2p-rs|no-default|mdns,discovery|release
minip2p-rs|no-default|smoltcp,relay,discovery,relay-server|ci
minip2p-tcp|default|smoltcp|ci
minip2p-mdns|default|smoltcp|ci
minip2p-transport|default|bench|release
minip2p-quic|default|diagnostics|ci
minip2p-ffi-core|no-default|serde|release
EOF
)

run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

while IFS='|' read -r package defaults features tier; do
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
    if [ "$tier" = "ci" ]; then
      run cargo nextest run --profile variants --locked "$@"
    fi
    ;;
  test-full)
    run cargo nextest run --profile variants --locked "$@"
    ;;
  esac
done <<<"$matrix"
