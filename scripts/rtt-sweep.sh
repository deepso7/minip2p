#!/usr/bin/env bash
set -euo pipefail

out=target/bench-results/rtt
primary=${MINIP2P_RTT_PROFILE:-100m_100ms}
mkdir -p "$out"
cargo bench -p minip2p-rs --features tcp,relay,relay-server,bench --bench endpoint_rtt --no-run

run() {
  local sweep=$1 profile=${2:-$primary}
  echo "== $sweep on $profile" >&2
  MINIP2P_RTT_SWEEP=$sweep MINIP2P_RTT_PROFILE=$profile \
    cargo bench -q -p minip2p-rs --features tcp,relay,relay-server,bench --bench endpoint_rtt \
    | tee "$out/$sweep-$profile.log" >&2
}

pick() {
  local kib
  kib=$(sed -n 's/^pick: \([0-9]*\)K.*/\1/p' "$out/$1-$primary.log")
  if [[ -z "$kib" ]]; then
    echo "$1 picked nothing; see $out/$1-$primary.log" >&2
    exit 1
  fi
  echo $((kib * 1024))
}

sweeps=("$@")
if ((${#sweeps[@]} == 0)); then
  sweeps=(quic-stream quic-connection quic-send quic-check yamux retry secondary)
fi
for sweep in "${sweeps[@]}"; do
  case $sweep in
  quic-stream)
    run quic-stream
    MINIP2P_RTT_STREAM=$(pick quic-stream)
    export MINIP2P_RTT_STREAM
    ;;
  quic-connection)
    run quic-connection
    MINIP2P_RTT_CONNECTION=$(pick quic-connection)
    export MINIP2P_RTT_CONNECTION
    ;;
  quic-send)
    run quic-send
    MINIP2P_RTT_SEND=$(pick quic-send)
    export MINIP2P_RTT_SEND
    ;;
  quic-check | yamux | retry) run "$sweep" ;;
  yamux-check)
    for profile in ${MINIP2P_RTT_CHECK_PROFILES:-10m_20ms 100m_10ms 100m_100ms 1g_20ms 1g_1ms}; do
      run yamux-check "$profile"
    done
    ;;
  secondary)
    run quic-check 1g_20ms
    run yamux 1g_20ms
    ;;
  *)
    echo "unknown sweep $sweep" >&2
    exit 2
    ;;
  esac
done

echo "picks: stream=${MINIP2P_RTT_STREAM:-default} connection=${MINIP2P_RTT_CONNECTION:-default} send=${MINIP2P_RTT_SEND:-default}"
grep -H '^pick:' "$out"/*.log || true
