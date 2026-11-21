# Bench instance start and job-start hook tolerate races and a slow Docker

Amends ADR 0025's runner design with how the scripts on either side of a run stay robust:

- **`scripts/start-bench-runner.sh` rechecks the instance state on every pass** instead of waiting on a transition, because another starter or a watchdog poweroff may already have moved the instance past it. It sets the `bench-lease-until` tag first, so the watchdog keeps the instance up while the run's job is queued.
- **The job-start hook (`infra/bench/runner-hooks/job-started.sh`) waits up to 60 s for Docker.** The runner service does not wait for the daemon, so the first job after a boot can arrive before it is up.
- **Every docker call in the hook is bounded by `timeout`**, so a wedged daemon fails the job instead of hanging it, and its output is captured into a variable first so a failure stops the hook (a process substitution would swallow it).
- **The BuildKit cache is bounded with `--max-used-space 40GB` when the CLI has it** (Docker 28+), else `--keep-storage`. Newer CLIs reinterpret `--keep-storage` as a reserved minimum, so it must not be used where `--max-used-space` exists.
- **`reject` walks ancestors through `/proc/<pid>/stat` field 4**, after stripping through the last `)`, because the command name in field 2 may contain spaces. The listener reports the killed `Runner.Worker` job as failed and takes the next one.
