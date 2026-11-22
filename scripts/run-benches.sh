#!/usr/bin/env bash
set -eu

git_sha=${BENCH_GIT_SHA:-$(git rev-parse HEAD)}

bench_one() {
  local package=$1 features=$2 bench=$3 args
  args=(-p "$package" --bench "$bench")
  [[ "$features" == - ]] || args+=(--features "$features")
  cargo bench "${args[@]}"
}

run_pass() {
  local pass package features bench
  while read -r -u 3 pass package features bench _; do
    [[ "$pass" == "$1" ]] || continue
    bench_one "$package" "$features" "$bench"
  done 3< bench/targets
}

run_ir() {
  local jobs logs=target/bench-results/ir-logs status=0 bench
  jobs=$(getconf _NPROCESSORS_ONLN)
  jobs=${BENCH_IR_JOBS:-$((jobs < 4 ? jobs : 4))}
  rm -rf "$logs"
  mkdir -p "$logs"
  export -f bench_one
  awk '$1 == "ir" { print $2, $3, $4 }' bench/targets \
    | xargs -P "$jobs" -n 3 bash -c 'bench_one "$@" > "$0/$3.log" 2>&1' "$logs" || status=$?
  for bench in $(awk '$1 == "ir" { print $4 }' bench/targets); do
    cat "$logs/$bench.log" || true
  done
  return "$status"
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
  run_ir
  python3 scripts/bench_results.py gungraun --since target/bench-results/gungraun-start --output target/bench-results/rust-micro.json --git-sha "$git_sha"
  ;;
*)
  echo "usage: $0 wall|ir" >&2
  exit 2
  ;;
esac
