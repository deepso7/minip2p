#!/usr/bin/env bash
# Job-start hook for the minip2p bench runner (ACTIONS_RUNNER_HOOK_JOB_STARTED).
#
# The runner runs this as the `runner` user before any workflow-controlled
# step, container-action build, or job container. It admits only the trusted
# Bench workflow: bench.yml from `main` (pull_request_target, workflow_dispatch,
# schedule) or from a `v*` tag (release). Anything else is killed. Admitted jobs
# then get leftover `bench-*` containers and images removed, the BuildKit cache
# pruned, and a free-disk check.
set -euo pipefail

repo=deepso7/minip2p
workflow="$repo/.github/workflows/bench.yml"

# Kill the job's Runner.Worker and exit. Exiting non-zero alone is not enough:
# the runner marks the job failed but still evaluates later steps' conditions,
# so a hostile `if: always()` step would run as `runner`, which is in `docker`
# and therefore root on this host. The listener reports the killed job as
# failed and takes the next one.
reject() {
  echo "minip2p-bench: refusing job: $*" >&2
  local pid=$PPID ppid comm argv0
  while [[ "$pid" -gt 1 ]]; do
    comm=$(cat "/proc/$pid/comm" 2>/dev/null || true)
    argv0=$(tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | head -n1 || true)
    if [[ "$comm" == Runner.Worker || "${argv0##*/}" == Runner.Worker ]]; then
      echo "minip2p-bench: killing Runner.Worker $pid" >&2
      kill -KILL "$pid"
      exit 1
    fi
    # Field 4 of /proc/<pid>/stat is the parent PID. Strip through the last
    # `)` first, since the command name in field 2 may contain spaces.
    ppid=$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null | cut -d' ' -f2) || break
    [[ -n "$ppid" ]] || break
    pid=$ppid
  done
  echo "minip2p-bench: Runner.Worker not found among ancestors" >&2
  exit 1
}

event=${GITHUB_EVENT_NAME:-}
ref=${GITHUB_WORKFLOW_REF:-}
echo "minip2p-bench: job ${GITHUB_JOB:-?} of ${GITHUB_REPOSITORY:-?} run ${GITHUB_RUN_ID:-?}, event '$event', workflow '$ref'"

[[ "${GITHUB_REPOSITORY:-}" == "$repo" ]] || reject "repository '${GITHUB_REPOSITORY:-}' is not $repo"
case "$event" in
  pull_request_target | workflow_dispatch | schedule)
    [[ "$ref" == "$workflow@refs/heads/main" ]] || reject "event '$event' needs $workflow@refs/heads/main, got '$ref'"
    ;;
  release)
    [[ "$ref" == "$workflow@refs/tags/v"* ]] || reject "event 'release' needs $workflow@refs/tags/v*, got '$ref'"
    ;;
  *)
    reject "event '$event' is not allowed"
    ;;
esac

# The runner service does not wait for Docker, so the first job after a boot
# can arrive before the daemon is up.
deadline=$((SECONDS + 60))
until timeout 10 docker info >/dev/null 2>&1; do
  if ((SECONDS >= deadline)); then
    echo "minip2p-bench: Docker is not ready after 60 s" >&2
    exit 1
  fi
  sleep 2
done

# Leftovers from cancelled or killed runs. Each docker call is bounded so a
# wedged daemon fails the job instead of hanging it, and its output is
# captured first so a failure stops the hook (a process substitution would
# swallow it).
containers_out=$(timeout 30 docker ps -aq --filter 'name=^bench-')
mapfile -t containers < <(printf '%s' "$containers_out" | grep . || true)
if [[ ${#containers[@]} -gt 0 ]]; then
  timeout 60 docker rm -f "${containers[@]}" >/dev/null
fi
images_out=$(timeout 30 docker image ls --filter 'reference=bench-*' --format '{{.Repository}}:{{.Tag}}')
mapfile -t images < <(printf '%s' "$images_out" | grep . || true)
if [[ ${#images[@]} -gt 0 ]]; then
  timeout 120 docker image rm -f "${images[@]}" >/dev/null
fi

# Bound the BuildKit cache at 40 GB. Docker 28+ names the bound
# --max-used-space; older CLIs only have --keep-storage, which newer ones
# reinterpret as a reserved minimum.
if timeout 30 docker builder prune --help | grep -q -- '--max-used-space'; then
  timeout 600 docker builder prune -f --max-used-space 40GB >/dev/null
else
  timeout 600 docker builder prune -f --keep-storage 40GB >/dev/null
fi

free_gb=$(df --output=avail -BG / | tail -n1 | tr -dc '0-9')
if [[ "$free_gb" -lt 15 ]]; then
  echo "minip2p-bench: only ${free_gb} GB free on / after pruning; need 15 GB" >&2
  exit 1
fi
echo "minip2p-bench: job admitted, ${free_gb} GB free"
