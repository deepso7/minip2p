#!/usr/bin/env bash
# Runs inside the benchmark image (cwd /minip2p, the measured code) and prints
# the result document, or a sweep's logs, as a base64 stdout marker.
# scripts/run-bench-container.sh passes it from the trusted checkout as the
# container's `bash -c` argument, so the measured ref never supplies it.
set -euo pipefail

: "${BENCH_GIT_SHA:?BENCH_GIT_SHA must identify the measured commit}"

rm -rf target/bench-results
mkdir -p target/bench-results

# A dispatched sweep (#361) runs only the emulated-link window sweeps and
# publishes their logs and JSON lines instead of the benchmark rows.
if [[ -n "${BENCH_SWEEP:-}" ]]; then
  read -ra sweeps <<< "$BENCH_SWEEP"
  if ((${#sweeps[@]} == 0)); then
    echo "BENCH_SWEEP names no sweep" >&2
    exit 2
  fi
  if [[ "${sweeps[0]}" == all ]]; then sweeps=(); fi
  scripts/rtt-sweep.sh "${sweeps[@]}"
  printf 'MINIP2P_SWEEP_RESULTS=%s\n' "$(tar -czf - -C target/bench-results rtt | base64 -w0)"
  exit 0
fi

scripts/run-benches.sh ir
scripts/run-benches.sh wall
pnpm --filter @minip2p/node bench

python3 scripts/bench_results.py merge \
  target/bench-results/rust-micro.json \
  target/bench-results/rust-wall.json \
  target/bench-results/custom.json \
  target/bench-results/node-ffi.json \
  --output target/bench-results/current.json \
  --git-sha "$BENCH_GIT_SHA"

printf 'MINIP2P_BENCH_RESULTS=%s\n' "$(base64 -w0 target/bench-results/current.json)"
