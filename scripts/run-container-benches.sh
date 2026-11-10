#!/usr/bin/env bash
# Runs one pass inside a benchmark container (cwd /minip2p, the measured
# code): scripts/run-bench-container.sh `docker exec`s it once per pass, from
# the trusted checkout as the `bash -c` argument, so the measured ref never
# supplies it. Each tier runs with the measured code's own harness and
# registries, so a base and a head tree each validate their own rows.
#
#   ir | wall | node   run that tier
#   results            merge the tiers and print the result document as a
#                      base64 stdout marker
#   sweep              run only the emulated-link window sweeps (#361) and
#                      print their logs and JSON lines as a marker instead
set -euo pipefail

: "${BENCH_GIT_SHA:?BENCH_GIT_SHA must identify the measured commit}"

mkdir -p target/bench-results

case "${1:-}" in
ir | wall)
  scripts/run-benches.sh "$1"
  ;;
node)
  pnpm --filter @minip2p/node bench
  ;;
results)
  python3 scripts/bench_results.py merge \
    target/bench-results/rust-micro.json \
    target/bench-results/rust-wall.json \
    target/bench-results/custom.json \
    target/bench-results/node-ffi.json \
    --output target/bench-results/current.json \
    --git-sha "$BENCH_GIT_SHA"
  printf 'MINIP2P_BENCH_RESULTS=%s\n' "$(base64 -w0 target/bench-results/current.json)"
  ;;
sweep)
  read -ra sweeps <<< "${BENCH_SWEEP:-}"
  if ((${#sweeps[@]} == 0)); then
    echo "BENCH_SWEEP names no sweep" >&2
    exit 2
  fi
  if [[ "${sweeps[0]}" == all ]]; then sweeps=(); fi
  scripts/rtt-sweep.sh "${sweeps[@]}"
  printf 'MINIP2P_SWEEP_RESULTS=%s\n' "$(tar -czf - -C target/bench-results rtt | base64 -w0)"
  ;;
*)
  echo "usage: run-container-benches ir|wall|node|results|sweep" >&2
  exit 2
  ;;
esac
