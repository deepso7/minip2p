#!/usr/bin/env bash
set -euo pipefail

: "${BENCH_GIT_SHA:?BENCH_GIT_SHA must identify the measured commit}"

# Fargate's seccomp profile blocks the personality syscall that Gungraun uses to
# disable ASLR. Run Valgrind directly; all compared AWS runs use the same mode.
export GUNGRAUN_ALLOW_ASLR=1
# Establishing hundreds of loopback QUIC connections can exceed the local
# benchmark's setup guard under Fargate's fixed CPU quota. Setup is not timed.
export MINIP2P_BENCH_SETUP_TIMEOUT_SECS=600

rm -rf target/bench-results
mkdir -p target/bench-results

scripts/run-benches.sh ir
scripts/run-benches.sh wall
pnpm --dir bindings/ts --filter @minip2p/node bench

python3 scripts/bench_results.py merge \
  target/bench-results/rust-micro.json \
  target/bench-results/rust-wall.json \
  target/bench-results/node-ffi.json \
  --output target/bench-results/current.json \
  --git-sha "$BENCH_GIT_SHA"

printf 'MINIP2P_BENCH_RESULTS=%s\n' "$(base64 -w0 target/bench-results/current.json)"
