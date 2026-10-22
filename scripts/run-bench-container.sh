#!/usr/bin/env bash
# Build the benchmark image and run the suite in one container on this host,
# writing the result document (or a sweep's rtt/ tree) and the container log
# to target/bench-artifacts/. Run it from the trusted checkout's root; the
# Bench workflow's Measure step `exec`s it so cancellation reaches its traps.
#
#   BENCH_GIT_SHA   the measured commit (required)
#   BENCH_SWEEP     emulated-link sweeps to run instead of the benchmarks
#                   (scripts/rtt-sweep.sh names, space-separated, or `all`)
#   BENCH_CONTEXT   build context holding the measured code (default `.`)
#   BENCH_NO_CACHE  `1` builds without the layer cache (release baselines)
#   BENCH_RUN_ID    names the image, container and work directory
set -euo pipefail

: "${BENCH_GIT_SHA:?BENCH_GIT_SHA is required}"
export BENCH_GIT_SHA BENCH_SWEEP=${BENCH_SWEEP:-}

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
build_pid=

rm -rf "$work" "$output"
mkdir -p "$quarantine" "$output"

keep_log() {
  if [[ -f "$work/bench.log" ]]; then
    cp "$work/bench.log" "$output/bench.log" || true
  fi
}

# Cancellation: GitHub allows about ten seconds (SIGINT, 7.5 s, SIGTERM), so
# only force-remove the container; the next job's hook removes the image.
on_signal() {
  trap - EXIT
  trap '' INT TERM
  if [[ -n "$build_pid" ]]; then
    kill "$build_pid" 2>/dev/null || true
  fi
  keep_log
  timeout 5 docker rm -f "$name" >/dev/null 2>&1 || true
  exit "$1"
}

# Every other exit: keep the log for the artifact and clean up, best effort,
# without changing the exit status.
cleanup() {
  local status=$?
  trap - EXIT
  keep_log
  timeout 20 docker rm -f "$name" >/dev/null 2>&1 || true
  timeout 20 docker rmi "$name" >/dev/null 2>&1 || true
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
build_args=(-f infra/bench/Dockerfile --build-arg BUILD_JOBS=4 -t "$name")
[[ "${BENCH_NO_CACHE:-}" == 1 ]] && build_args+=(--no-cache)
docker build "${build_args[@]}" "${BENCH_CONTEXT:-.}" &
build_pid=$!
wait "$build_pid"
build_pid=

# Every benchmark is loopback or in-process, so the container gets no network
# (`endpoint_idle`'s dual-stack variant needs IPv6 loopback, hence the sysctl).
# Unconfined seccomp lets Gungraun disable ASLR with personality(2). Memory and
# Docker's own log are capped so a runaway run cannot take the host down.
docker run -d --name "$name" --network none --memory 6g \
  --log-opt max-size=100m --log-opt max-file=3 \
  --sysctl net.ipv6.conf.lo.disable_ipv6=0 \
  --cap-add SYS_PTRACE --security-opt seccomp=unconfined \
  -e BENCH_GIT_SHA -e BENCH_SWEEP \
  --entrypoint bash "$name" -c "$(< scripts/run-container-benches.sh)" >/dev/null
docker logs -f "$name" 2>&1 | head -c "$log_max_bytes" > "$work/bench.log" &
logs_pid=$!
docker wait "$name" > "$work/exit-code" &
wait $!
if ! wait "$logs_pid"; then
  echo "failed to follow the benchmark container's log" >&2
  exit 1
fi

(($(stat -c %s "$work/bench.log") < log_max_bytes)) \
  || reject "container log reached $((log_max_bytes / 1024 / 1024)) MB"

exit_code=$(< "$work/exit-code")
if [[ "$exit_code" != 0 ]]; then
  cat "$work/bench.log" >&2
  echo "benchmark container exited with code $exit_code" >&2
  exit "$exit_code"
fi

marker=MINIP2P_BENCH_RESULTS
[[ -n "$BENCH_SWEEP" ]] && marker=MINIP2P_SWEEP_RESULTS
encoded=$(sed -n "/^$marker=/{s///p;q}" "$work/bench.log")
[[ -n "$encoded" ]] || reject "$marker marker missing from the container log"

# Decode into the quarantine, never more than the size limit (`head -c` also
# bounds a gzip bomb before tar writes it out), and check it before anything
# reaches the artifact.
if [[ -n "$BENCH_SWEEP" ]]; then
  printf '%s' "$encoded" | base64 -d | gzip -dc | head -c "$((max_bytes + 1))" \
    | tar -xf - --no-same-owner --no-same-permissions -C "$quarantine" \
    || reject "sweep archive is malformed or larger than 50 MB"
else
  printf '%s' "$encoded" | base64 -d | head -c "$((max_bytes + 1))" \
    > "$quarantine/current.json" || reject "result marker is not valid base64"
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
  cp "$quarantine/current.json" "$output/current.json"
fi
