#!/usr/bin/env bash
# Runs #361's window sweeps over the emulated link (`endpoint_rtt` bench) in
# order, feeding each pick into the next sweep:
#
#   quic-stream -> S*; quic-connection at S* -> C*; quic-send at S* -> W*;
#   quic-check at (S*, C*, W*); yamux; retry; then quic-check and yamux on
#   the secondary 1g_20ms profile, recorded only.
#
# Logs and JSON lines land in target/bench-results/rtt/. Pass sweep names to
# run only those (picks then come from MINIP2P_RTT_{STREAM,CONNECTION,SEND}).
# MINIP2P_RTT_RUNS sets the runs per point (default 5).
set -euo pipefail

out=target/bench-results/rtt
mkdir -p "$out"
cargo bench -p minip2p-rs --features tcp,nat,relay-server,bench --bench endpoint_rtt --no-run

run() {
  local sweep=$1 profile=${2:-100m_100ms}
  echo "== $sweep on $profile" >&2
  MINIP2P_RTT_SWEEP=$sweep MINIP2P_RTT_PROFILE=$profile \
    cargo bench -q -p minip2p-rs --features tcp,nat,relay-server,bench --bench endpoint_rtt \
    | tee "$out/$sweep-$profile.log" >&2
}

# The bytes of the value a sweep's summary picked ("pick: 1216K ...").
pick() {
  local kib
  kib=$(sed -n 's/^pick: \([0-9]*\)K.*/\1/p' "$out/$1-100m_100ms.log")
  if [[ -z "$kib" ]]; then
    echo "$1 picked nothing; see $out/$1-100m_100ms.log" >&2
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
  quic-stream) run quic-stream && MINIP2P_RTT_STREAM=$(pick quic-stream) && export MINIP2P_RTT_STREAM ;;
  quic-connection) run quic-connection && MINIP2P_RTT_CONNECTION=$(pick quic-connection) && export MINIP2P_RTT_CONNECTION ;;
  quic-send) run quic-send && MINIP2P_RTT_SEND=$(pick quic-send) && export MINIP2P_RTT_SEND ;;
  quic-check | yamux | retry) run "$sweep" ;;
  secondary) run quic-check 1g_20ms && run yamux 1g_20ms ;;
  *)
    echo "unknown sweep $sweep" >&2
    exit 2
    ;;
  esac
done

echo "picks: stream=${MINIP2P_RTT_STREAM:-default} connection=${MINIP2P_RTT_CONNECTION:-default} send=${MINIP2P_RTT_SEND:-default}"
grep -H '^pick:' "$out"/*.log || true
