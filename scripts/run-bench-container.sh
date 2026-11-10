#!/usr/bin/env bash
# Build the benchmark image and run the suite on this host, writing the result
# document (or a sweep's rtt/ tree) and the container log to
# target/bench-artifacts/. With BENCH_BASE_CONTEXT set it measures two trees,
# base and head, each from its own image, and interleaves their tiers so drift
# on the host hits both sides alike. Run it from the trusted checkout's root;
# the Bench workflow's Measure step `exec`s it so cancellation reaches its
# traps.
#
#   BENCH_GIT_SHA        the measured commit (required)
#   BENCH_CONTEXT        build context holding the measured code (default `.`)
#   BENCH_BASE_CONTEXT   build context of a base tree to measure alongside it;
#                        the result is then base.json and head.json instead
#                        of current.json
#   BENCH_BASE_GIT_SHA   the base tree's commit (required with BENCH_BASE_CONTEXT)
#   BENCH_SWEEP          emulated-link sweeps to run instead of the benchmarks
#                        (scripts/rtt-sweep.sh names, space-separated, or
#                        `all`); one tree only
#   BENCH_RUN_ID         names the images, containers and work directory
set -euo pipefail

: "${BENCH_GIT_SHA:?BENCH_GIT_SHA is required}"
export BENCH_SWEEP=${BENCH_SWEEP:-}

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
build_pid=

# Each side names its image, container and result file.
declare -A context sha
if [[ -n "${BENCH_BASE_CONTEXT:-}" ]]; then
  : "${BENCH_BASE_GIT_SHA:?BENCH_BASE_GIT_SHA is required with BENCH_BASE_CONTEXT}"
  if [[ -n "$BENCH_SWEEP" ]]; then
    echo "a sweep measures one tree; unset BENCH_BASE_CONTEXT" >&2
    exit 2
  fi
  sides=(base head)
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

# Keeps the log for the artifact, plus the latest pass's own log, which holds
# the output of a pass that a cancellation or timeout cut short.
keep_log() {
  local log
  for log in bench.log pass.log; do
    if [[ -f "$work/$log" ]]; then
      cp "$work/$log" "$output/$log" || true
    fi
  done
}

# Cancellation: GitHub allows about ten seconds (SIGINT, 7.5 s, SIGTERM), so
# only force-remove the containers; the next job's hook removes the images.
on_signal() {
  trap - EXIT
  trap '' INT TERM
  if [[ -n "$build_pid" ]]; then
    kill "$build_pid" 2>/dev/null || true
  fi
  keep_log
  timeout 5 docker rm -f "${containers[@]}" >/dev/null 2>&1 || true
  exit "$1"
}

# Every other exit: keep the log for the artifact and remove the containers
# and both images (two images at once are most of the disk a run uses), best
# effort, without changing the exit status.
cleanup() {
  local status=$?
  trap - EXIT
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

# Bash defers traps while a foreground command runs, so each long wait is a
# background job joined with `wait`, which a trapped signal interrupts.
# The images never leave this host, so skip the provenance attestation and
# layer compression; together they were most of the export (87 s -> 9 s).
# Both builds share the local BuildKit cache, so layers the trees have in
# common (the toolchain, usually the cooked dependencies) build once.
for side in "${sides[@]}"; do
  docker build -f infra/bench/Dockerfile --build-arg BUILD_JOBS=4 \
    --provenance=false --output "type=docker,name=$name-$side,compression=uncompressed" \
    "${context[$side]}" &
  build_pid=$!
  wait "$build_pid"
  build_pid=
done

# Every benchmark is loopback or in-process, so the containers get no network
# (`endpoint_idle`'s dual-stack variant needs IPv6 loopback, hence the sysctl).
# Unconfined seccomp lets Gungraun disable ASLR with personality(2). Memory is
# capped so a runaway run cannot take the host down. The socket sweeps open
# over a thousand descriptors, past Docker's default soft limit of 1024. Each
# container idles until a pass is exec'd into it, and only one pass runs at a
# time.
for side in "${sides[@]}"; do
  docker run -d --name "$name-$side" --network none --memory 6g \
    --ulimit nofile=65536:65536 \
    --sysctl net.ipv6.conf.lo.disable_ipv6=0 \
    --cap-add SYS_PTRACE --security-opt seccomp=unconfined \
    --entrypoint sleep "$name-$side" infinity >/dev/null
done

# Runs one pass of scripts/run-container-benches.sh in a side's container,
# its output in $work/pass.log (capped) and appended to the log. A pass whose
# output reaches the cap stops its container: `head` exits at the cap, and
# killing the container ends the exec.
run_pass() {
  local side=$1 pass=$2
  printf '==> %s: %s\n' "$side" "$pass" >> "$work/bench.log"
  rm -f "$work/exit-code"
  {
    status=0
    docker exec -e BENCH_GIT_SHA="${sha[$side]}" -e BENCH_SWEEP "$name-$side" \
      bash -c "$script" run-container-benches "$pass" 2>&1 || status=$?
    echo "$status" > "$work/exit-code"
  } | head -c "$log_max_bytes" > "$work/pass.log" &
  wait $!
  cat "$work/pass.log" >> "$work/bench.log"
  if (($(stat -c %s "$work/pass.log") >= log_max_bytes)); then
    timeout 20 docker kill "$name-$side" >/dev/null 2>&1 || true
    reject "$side $pass output reached $((log_max_bytes / 1024 / 1024)) MB"
  fi
  local exit_code
  exit_code=$(cat "$work/exit-code" 2>/dev/null || echo unknown)
  if [[ "$exit_code" != 0 ]]; then
    cat "$work/pass.log" >&2
    echo "$side $pass pass exited with code $exit_code" >&2
    exit 1
  fi
}

# Copies the marker of the pass that just ran into the quarantine (decoded,
# never more than the size limit) and checks it before anything reaches the
# artifact: a sweep's rtt/ tree, or a side's result document as <side>.json.
take_marker() {
  local side=$1 marker=MINIP2P_BENCH_RESULTS
  [[ -n "$BENCH_SWEEP" ]] && marker=MINIP2P_SWEEP_RESULTS
  # Base64 of the largest accepted result, plus slack; a longer marker is
  # rejected rather than decoded.
  local encoded_max=$((max_bytes / 3 * 4 + 1024))
  sed -n "/^$marker=/{s///p;q}" "$work/pass.log" | head -c "$encoded_max" > "$work/encoded"
  [[ -s "$work/encoded" ]] || reject "$marker marker missing from the $side output"
  (($(stat -c %s "$work/encoded") < encoded_max)) || reject "$marker marker is larger than 50 MB"
  # `head -c` also bounds a gzip bomb before tar writes it out.
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
  # `du` counts a hard-linked file once but `cp` copies every link.
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
  run_pass current sweep
  take_marker current
  exit 0
fi

# Instruction counts are deterministic, so Ir runs once per side in any order.
# The timing tiers alternate which side goes first.
for side in "${sides[@]}"; do run_pass "$side" ir; done
for side in "${reversed[@]}"; do run_pass "$side" wall; done
for side in "${sides[@]}"; do run_pass "$side" node; done
for side in "${sides[@]}"; do
  run_pass "$side" results
  take_marker "$side"
done
