#!/usr/bin/env bash
set -euo pipefail

: "${BENCH_GIT_SHA:?BENCH_GIT_SHA is required}"
export BENCH_SWEEP=${BENCH_SWEEP:-}
export MINIP2P_BENCH_QUICK=

if [[ -n "${GITHUB_RUN_ID:-}" ]]; then
  run_id=${BENCH_RUN_ID:-$GITHUB_RUN_ID-${GITHUB_RUN_ATTEMPT:-1}}
else
  run_id=${BENCH_RUN_ID:-local-$(date +%s)}
fi
name=bench-$run_id
work=${RUNNER_TEMP:-target}/$name
quarantine=$work/quarantine
output=target/bench-artifacts
max_bytes=$((50 * 1024 * 1024))
log_max_bytes=$((256 * 1024 * 1024))
script=$(< scripts/run-container-benches.sh)
pids=()

declare -A context sha
if [[ -n "${BENCH_BASE_CONTEXT:-}" ]]; then
  : "${BENCH_BASE_GIT_SHA:?BENCH_BASE_GIT_SHA is required with BENCH_BASE_CONTEXT}"
  if [[ -n "$BENCH_SWEEP" ]]; then
    echo "a sweep measures one tree; unset BENCH_BASE_CONTEXT" >&2
    exit 2
  fi
  sides=(base head)
  MINIP2P_BENCH_QUICK=1
  context[base]=$BENCH_BASE_CONTEXT sha[base]=$BENCH_BASE_GIT_SHA
  context[head]=${BENCH_CONTEXT:-.} sha[head]=$BENCH_GIT_SHA
else
  sides=(current)
  context[current]=${BENCH_CONTEXT:-.} sha[current]=$BENCH_GIT_SHA
fi
mapfile -t reversed < <(printf '%s\n' "${sides[@]}" | tac)
containers=("${sides[@]/#/$name-}")

rm -rf "$work" "$output"
mkdir -p "$quarantine" "$output"

keep_log() {
  local log
  for log in "$work"/bench.log "$work"/*.pass.log "$work"/*.build.log; do
    if [[ -f "$log" ]]; then
      cp "$log" "$output/" || true
    fi
  done
}

stop_jobs() {
  if ((${#pids[@]})); then
    kill "${pids[@]}" 2>/dev/null || true
  fi
}

on_signal() {
  trap - EXIT
  trap '' INT TERM
  stop_jobs
  keep_log
  timeout 5 docker rm -f "${containers[@]}" >/dev/null 2>&1 || true
  exit "$1"
}

cleanup() {
  local status=$?
  trap - EXIT
  stop_jobs
  keep_log
  timeout 20 docker rm -f "${containers[@]}" >/dev/null 2>&1 || true
  timeout 60 docker rmi "${containers[@]}" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

reject() {
  echo "rejected benchmark output: $1" >&2
  exit 1
}

declare -A building
started=$SECONDS
for side in "${sides[@]}"; do
  docker build -f infra/bench/Dockerfile --build-arg BUILD_JOBS=4 \
    --provenance=false --output "type=docker,name=$name-$side,compression=uncompressed" \
    "${context[$side]}" > "$work/$side.build.log" 2>&1 &
  pids+=($!)
  building[$!]=$side
done
while ((${#pids[@]})); do
  status=0
  wait -n -p done_pid "${pids[@]}" || status=$?
  side=${building[$done_pid]}
  unset "building[$done_pid]"
  pids=("${!building[@]}")
  printf '==> %s: build (%ss)\n' "$side" "$((SECONDS - started))"
  cat "$work/$side.build.log"
  if ((status != 0)); then
    echo "$side image build exited with code $status" >&2
    exit 1
  fi
done

for side in "${sides[@]}"; do
  docker run -d --name "$name-$side" --network none --memory 6g \
    --ulimit nofile=65536:65536 \
    --sysctl net.ipv6.conf.lo.disable_ipv6=0 \
    --cap-add SYS_PTRACE --security-opt seccomp=unconfined \
    --entrypoint sleep "$name-$side" infinity >/dev/null
done

start_pass() {
  local side=$1 pass=$2
  rm -f "$work/$side.exit"
  {
    status=0
    docker exec -e BENCH_GIT_SHA="${sha[$side]}" -e BENCH_SWEEP -e MINIP2P_BENCH_QUICK -e BENCH_IR_JOBS "$name-$side" \
      bash -c "$script" run-container-benches "$pass" 2>&1 || status=$?
    echo "$status $SECONDS" > "$work/$side.exit"
  } | head -c "$log_max_bytes" > "$work/$side.pass.log" &
  pids+=($!)
}

finish_pass() {
  local side=$1 pass=$2 started=$3 exit_code ended
  read -r exit_code ended < "$work/$side.exit" || exit_code=unknown ended=$SECONDS
  printf '==> %s: %s (%ss)\n' "$side" "$pass" "$((ended - started))" | tee -a "$work/bench.log"
  cat "$work/$side.pass.log" >> "$work/bench.log"
  if (($(stat -c %s "$work/$side.pass.log") >= log_max_bytes)); then
    timeout 20 docker kill "$name-$side" >/dev/null 2>&1 || true
    reject "$side $pass output reached $((log_max_bytes / 1024 / 1024)) MB"
  fi
  if [[ "$exit_code" != 0 ]]; then
    cat "$work/$side.pass.log" >&2
    echo "$side $pass pass exited with code $exit_code" >&2
    exit 1
  fi
}

run_pass() {
  local pass=$1 started=$SECONDS side
  shift
  for side; do start_pass "$side" "$pass"; done
  while ((${#pids[@]})); do
    wait "${pids[0]}" || true
    pids=("${pids[@]:1}")
  done
  for side; do finish_pass "$side" "$pass" "$started"; done
}

take_marker() {
  local side=$1 marker=MINIP2P_BENCH_RESULTS
  [[ -n "$BENCH_SWEEP" ]] && marker=MINIP2P_SWEEP_RESULTS
  local encoded_max=$((max_bytes / 3 * 4 + 1024))
  sed -n "/^$marker=/{s///p;q}" "$work/$side.pass.log" | head -c "$encoded_max" > "$work/encoded"
  [[ -s "$work/encoded" ]] || reject "$marker marker missing from the $side output"
  (($(stat -c %s "$work/encoded") < encoded_max)) || reject "$marker marker is larger than 50 MB"
  if [[ -n "$BENCH_SWEEP" ]]; then
    base64 -d "$work/encoded" | gzip -dc | head -c "$((max_bytes + 1))" \
      | tar -xf - --no-same-owner --no-same-permissions -C "$quarantine" \
      || reject "sweep archive is malformed or larger than 50 MB"
  else
    base64 -d "$work/encoded" | head -c "$((max_bytes + 1))" \
      > "$quarantine/$side.json" || reject "result marker is not valid base64"
  fi
  [[ -z "$(find "$quarantine" ! -type f ! -type d)" ]] \
    || reject "contains entries other than regular files and directories"
  [[ -z "$(find "$quarantine" -type f -links +1)" ]] || reject "contains hard links"
  (($(du -sb "$quarantine" | cut -f1) <= max_bytes)) || reject "larger than 50 MB"
  if [[ -n "$BENCH_SWEEP" ]]; then
    [[ -d "$quarantine/rtt" ]] || reject "sweep archive has no rtt/ directory"
    cp -R "$quarantine/rtt" "$output/"
  else
    cp "$quarantine/$side.json" "$output/$side.json"
  fi
}

if [[ -n "$BENCH_SWEEP" ]]; then
  run_pass sweep current
  take_marker current
  exit 0
fi

cores=$(nproc)
BENCH_IR_JOBS=$((cores / ${#sides[@]} > 0 ? cores / ${#sides[@]} : 1)) run_pass ir "${sides[@]}"
for side in "${reversed[@]}"; do run_pass wall "$side"; done
for side in "${sides[@]}"; do run_pass node "$side"; done
for side in "${sides[@]}"; do
  run_pass results "$side"
  take_marker "$side"
done
