#!/usr/bin/env bash
# Run one pass of the benchmarks listed in bench/targets and collect its
# result document under target/bench-results/.
set -eu

git_sha=${BENCH_GIT_SHA:-$(git rev-parse HEAD)}

# Runs every bench/targets line of one pass, in file order. The list is read
# on fd 3 so a benchmark can never consume it from stdin.
run_pass() {
  local pass package features bench args
  while read -r -u 3 pass package features bench _; do
    [[ "$pass" == "$1" ]] || continue
    args=(-p "$package" --bench "$bench")
    [[ "$features" == - ]] || args+=(--features "$features")
    cargo bench "${args[@]}"
  done 3< bench/targets
}

case "${1:-}" in
wall)
  python3 scripts/bench_results.py start --output target/bench-results/criterion-start
  run_pass criterion
  python3 scripts/bench_results.py criterion --since target/bench-results/criterion-start --output target/bench-results/rust-wall.json --git-sha "$git_sha"
  python3 scripts/bench_results.py start --output target/bench-results/custom-start
  run_pass custom
  python3 scripts/bench_results.py custom --since target/bench-results/custom-start --output target/bench-results/custom.json --git-sha "$git_sha"
  ;;
ir)
  python3 scripts/bench_results.py start --output target/bench-results/gungraun-start
  export GUNGRAUN_SAVE_SUMMARY=json
  run_pass ir
  python3 scripts/bench_results.py gungraun --since target/bench-results/gungraun-start --output target/bench-results/rust-micro.json --git-sha "$git_sha"
  ;;
*)
  echo "usage: $0 wall|ir" >&2
  exit 2
  ;;
esac
