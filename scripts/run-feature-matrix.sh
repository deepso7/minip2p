#!/usr/bin/env bash
set -eu

usage() {
  echo "usage: $0 check|clippy|test [ci|full|<row>|--rows <csv>] [--shard <i/n>]" >&2
  echo "       $0 list" >&2
  exit 2
}

operation=${1:-}
shift || true
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

selection="ci"
rows_csv=""
shard_requested=false
shard_index=""
shard_total=""

while [ "$#" -gt 0 ]; do
  case "$1" in
  --rows)
    [ "$#" -ge 2 ] || usage
    selection="rows"
    rows_csv="$2"
    shift 2
    ;;
  --shard)
    [ "$#" -ge 2 ] || usage
    shard_requested=true
    case "$2" in
    */*)
      shard_index=${2%%/*}
      shard_total=${2#*/}
      ;;
    *) usage ;;
    esac
    shift 2
    ;;
  -*)
    usage
    ;;
  *)
    selection="$1"
    shift
    ;;
  esac
done

if [ "$shard_requested" = true ]; then
  if ! [[ "$shard_index" =~ ^[1-9][0-9]*$ && "$shard_total" =~ ^[1-9][0-9]*$ ]] || [ "$shard_index" -gt "$shard_total" ]; then
    echo "invalid shard specification: $shard_index/$shard_total" >&2
    exit 2
  fi
fi

validate_row_name() {
  if ! cut -d'|' -f1 <<<"$matrix" | grep -qxF -- "$1"; then
    echo "unknown matrix row: $1 (see \`$0 list\`)" >&2
    exit 2
  fi
}

case "$selection" in
ci | full) ;;
rows)
  if [ -z "$rows_csv" ]; then
    exit 0
  fi
  IFS=',' read -r -a requested_rows <<<"$rows_csv"
  for row_name in "${requested_rows[@]}"; do
    validate_row_name "$row_name"
  done
  ;;
*)
  validate_row_name "$selection"
  ;;
esac

row_selected() {
  local name="$1"
  local tier="$2"
  case "$selection" in
  ci) [ "$tier" = ci ] ;;
  full) return 0 ;;
  rows) [[ ",$rows_csv," == *",$name,"* ]] ;;
  *) [ "$name" = "$selection" ] ;;
  esac
}

run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

matched_index=0
while IFS='|' read -r name package defaults features tier; do
  row_selected "$name" "$tier" || continue

  if [ "$shard_requested" = true ]; then
    bucket=$(( (matched_index % shard_total) + 1 ))
    matched_index=$((matched_index + 1))
    [ "$bucket" -eq "$shard_index" ] || continue
  fi

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
