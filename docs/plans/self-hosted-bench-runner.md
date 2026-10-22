# Plan: move the Bench workflow from Fargate to an on-demand EC2 runner

> **Status:** Accepted (revision 8, dedicated-instance design); implemented on branch `bench-ec2-runner`. Replaces the AWS Fargate execution described in [infra/bench/README.md](../../infra/bench/README.md). Everything else in the benchmark contract stays: the tiers, `results.json`, release-only baselines on `bench-data`, informational PR comments, the `aws-bench` approval gate, the same-repository PR guard, and the trusted-scripts / untrusted-build-context split.

## Why

The Fargate path is unreliable. Of the last 40 Bench runs, 5 succeeded and 28 were cancelled. Each run pushes an image to ECR, registers a task definition, polls ECS, and scrapes CloudWatch for a base64 marker. A run that succeeds takes 25–30 minutes on 2 vCPU / 4 GiB with a fixed CPU quota. Fargate also forces `GUNGRAUN_ALLOW_ASLR=1` (seccomp blocks `personality`) and a 600 s socket-sweep setup timeout.

An earlier revision put the runner on mito, the maintainer's always-on dev box. That needed a permanent CPU split, a restricted user, egress filtering, and cgroup limits to keep PR code and benchmark noise away from dev work. A dedicated instance that runs only during benchmarks removes all of that, for roughly $10–20 a month.

## Goals and non-goals

Goals:

- Bench runs finish reliably. The only AWS call left on the critical path is starting one stopped instance.
- The instance runs only while benchmarks run, and it stops itself.
- Same triggers, approval gate, artifacts, comparison, and sticky comment as today.
- Code from the measured ref cannot reach AWS credentials, the maintainer's machines, or the tailnet.
- Gungraun runs with ASLR disabled again, and the whole machine is the benchmark (no co-tenants).

Non-goals:

- A fresh instance per job. Recorded as the follow-up (see Trust boundary).
- Making wall-clock rows classified. They stay informational.
- `tc netem` link emulation. The in-process delay emulation stays.

## Trust boundary

Repository writers are trusted: they can already push to `main`, publish releases, and change workflows. The `aws-bench` environment approval guards against accidental runs, not against writers. What the design defends against is anyone without write access, in two layers:

- **Server side:** the repository setting "Require approval for all external contributors" holds every fork-PR workflow run until a maintainer approves it. The workflow's same-repository guard keeps fork PRs out of `bench.yml` itself.
- **On the host:** a job-start hook kills the job's worker process before any workflow-controlled step can run, unless the job is `bench.yml` from `main` or a release tag. A failing hook alone would not be enough: the runner records the failure and still evaluates later steps, so a hostile `if: always()` step would run.

The instance and its disk persist between runs, so a container escape in one job could tamper with later jobs, including release baselines. This is accepted under the boundary above. The instance holds no credentials and has no IAM role, and the escape gains nothing beyond the instance. If a compromise is suspected, run `infra/bench/bootstrap.sh --replace` before the next release baseline. It terminates the instance and creates a fresh one from the same definition. Per-job fresh instances are the follow-up if outside contributors ever need benchmarks.

## Design

### Topology

```
GitHub (pull_request_target / release / workflow_dispatch / weekly schedule)
  ├─ job `start-runner`   ubuntu-latest, environment aws-bench (aws-bench-keepalive on schedule), OIDC
  │     └─ sets a lease tag, then ec2:StartInstances on the one bench instance (idempotent)
  ├─ job `bench`          needs start-runner; runs-on [self-hosted, linux, x64, minip2p-bench]
  │     └─ instance `minip2p-bench`: Docker, GitHub Actions runner, build cache on its disk
  │          └─ idle watchdog powers it off (shutdown behaviour: stop)
  └─ jobs `compare`, `baseline` stay on ubuntu-latest; bench-comment.yml unchanged except the artifact name
```

### The instance

- **Type:** `c7a.xlarge` (4 vCPU on 4 physical cores, since c7a has no SMT; 8 GiB) in `us-east-1`, the region the existing role and `AWS_BENCH_REGION` already use. On-demand, not spot: an interruption mid-run is exactly the unreliability being removed. If 8 GiB proves tight for the image build, `m7a.xlarge` (same cores, 16 GiB) is the fallback.
- **OS and disk:** Ubuntu 24.04 LTS, 80 GB gp3 root volume. That leaves room for the BuildKit cache (pruned to 40 GB), one image, and the runner's checkouts.
- **Network:** a dedicated VPC created by bootstrap: one `/24` with one public subnet, an internet gateway, and a route table whose only non-local route is `0.0.0.0/0` to it. There is no peering, endpoints, or other resources. The instance gets a public IPv4 for egress (no NAT gateway to pay for), and its security group has **no inbound rules**. The default VPC's private routes and anything else in the account are out of reach, and it is not on the tailnet, so PR code can reach only the public internet and its own VPC's DNS resolver.
- **IAM / metadata:** no instance profile. IMDSv2 is required with hop limit 1, so containers cannot reach it; Docker's default builder also runs `RUN` steps on the bridge network, which the limit covers. Instance tags in metadata are enabled so the watchdog can read the lease tag. Nothing secret sits behind IMDS (see the registration token below).
- **Admin access:** none by default. `bootstrap.sh --ssh-from <cidr>` temporarily adds a port-22 rule and `--no-ssh` removes it. The key pair is created by bootstrap and stays on the maintainer's machine.
- **Instance-initiated shutdown behaviour:** `stop`, so a poweroff from inside stops (not terminates) the instance and keeps the disk.

Cost, at us-east-1 on-demand ($0.205/h for c7a.xlarge):
- about 40 minutes per run, including boot and the idle tail, which is about $0.15;
- storage, about $6.40/month for the 80 GB gp3 volume;
- the public IPv4 address, billed only while the instance runs.

At around 50 runs a month the total is about $15/month.

### Provisioning (`infra/bench/bootstrap.sh`, rewritten)

Run once by the maintainer with administrator credentials; idempotent. It:

1. Creates the VPC, subnet, internet gateway and route table described above, the security group `minip2p-bench-runner` (no inbound), and the key pair `minip2p-bench`. Everything is tagged `project=minip2p`.
2. Launches the instance, tagged `project=minip2p` and `Name=minip2p-bench`, with the settings above. Its cloud-init user data is `infra/bench/cloud-init.yaml` plus a runner registration token, which the script fetches with `gh api -X POST repos/deepso7/minip2p/actions/runners/registration-token`. The token can be reused, but only for an hour. EC2 keeps the user data, and cloud-init caches it on the instance, so the token stays readable after that hour: from the instance's host (not from containers, which hop limit 1 blocks) and by account administrators. Once it has expired it is worthless. Bootstrap never prints or logs the rendered user data. Cloud-init:
   - installs Docker CE from Docker's apt repository and `jq`;
   - creates the user `runner`, in the `docker` group, with no sudo;
   - installs the pinned `actions/runner` release (SHA-256 verified) and registers it at repo level with labels `self-hosted,linux,x64,minip2p-bench`;
   - installs the runner as a systemd service, the job-start hook, the idle watchdog, and the prune settings.

   These steps run once per instance (cloud-init's `scripts-user` semantics), so later boots don't re-apply them. Cloud-init stays enabled, since disabling it buys nothing.
3. Prints the instance ID for the maintainer to store as the `AWS_BENCH_INSTANCE_ID` variable on the `aws-bench` environment.
4. Replaces the CI role `minip2p-github-bench`'s inline policy with exactly:
   - `ec2:StartInstances` on `arn:aws:ec2:us-east-1:<account>:instance/<id>`;
   - `ec2:CreateTags` on that instance, with `ForAllValues:StringEquals` `aws:TagKeys = ["bench-lease-until"]` and `Null: {"aws:TagKeys": "false"}`, so it can set only that key. The value is not restricted in IAM; the watchdog treats an implausible value as expired;
   - `ec2:DescribeInstances`, which cannot be resource-scoped.

   The ECS, ECR, logs, and `iam:PassRole` permissions go. The OIDC trust gains a second subject, `environment:aws-bench-keepalive`, beside `environment:aws-bench` (see Keepalive). The root volume uses the default EBS encryption key, so no KMS permissions are needed.

`--replace` terminates the instance and runs steps 2–4 again. `--ssh-from` and `--no-ssh` only touch the security group.

### On the instance

- **Job-start hook** (`ACTIONS_RUNNER_HOOK_JOB_STARTED`, from `infra/bench/runner-hooks/job-started.sh`). It refuses the job unless:
  - `GITHUB_REPOSITORY == deepso7/minip2p`;
  - the event and workflow ref are one of these pairs:
    - `pull_request_target`, `workflow_dispatch`, or `schedule` with `deepso7/minip2p/.github/workflows/bench.yml@refs/heads/main`;
    - `release` with `…/bench.yml@refs/tags/v*`.

  The hook is the first pre-job step: the runner adds it ahead of container-action builds and job containers (`JobExtension.InitializeJob`), so nothing a workflow controls has run yet. To reject a job it does not just exit non-zero. A failed hook marks the job failed, but the runner still evaluates later steps' conditions, so an `if: always()` step would run as the `runner` user, which is in `docker` and therefore root. Instead the hook walks its parent chain to the `Runner.Worker` process, sends it `SIGKILL`, and exits. The listener reports the job as failed and takes the next one. A fork PR whose workflow targets the `minip2p-bench` label runs under `pull_request` with a `refs/pull/N/merge` ref, so it is killed this way even if a maintainer approved the run and it lands while the instance is up. After the checks pass, the hook removes leftover `bench-*` containers and images (bounded with `timeout`), prunes the BuildKit cache to 40 GB, and fails if less than 15 GB is free.
- **Lease and idle watchdog.** Before every start, `start-runner` sets the instance tag `bench-lease-until` to now + 20 minutes. That is long enough for the instance to boot and the runner to collect the queued job. A systemd timer runs every minute and powers the instance off when either:
  - it has been up at least 10 minutes, the lease has expired (read from instance metadata tags; a missing, malformed, or more-than-30-minutes-ahead value counts as expired, so no tag value can pin the instance on), and no `Runner.Worker` process has existed for 10 consecutive minutes; or
  - the current `Runner.Worker` process is older than 120 minutes. That is a stuck job, since the job timeout is 90 minutes. The bound is per job and resets with each new worker, so a busy day of back-to-back PRs never cuts a job short.

  The lease narrows the hand-off race to almost nothing, but cannot close it. A watchdog that read the old lease a moment before `start-runner` set the new one can still power off. Poweroff is asynchronous, and both the EC2 API and IMDS tags are eventually consistent, so `start-runner` cannot reliably detect that. This is accepted as a rare, manual-retry failure (see Failure modes) rather than adding a shutdown handshake. The idle rule covers normal completion, a cancelled run, and a start whose job never came. A job-completed hook is not used to power off, because it runs before GitHub has recorded the job's completion.
- **Docker** is rootful, with the default seccomp profile and the default bridge for build steps. The runner user being in `docker` is root-equivalent on the instance. That is acceptable because the instance holds nothing and is replaceable.

### Workflow changes (`.github/workflows/bench.yml`)

- **Triggers:** add `schedule: - cron: '17 6 * * 1'` (weekly). GitHub removes a non-ephemeral self-hosted runner that has not connected for 14 days, which would leave bench jobs queued with no runner. The weekly run starts the instance, runs a no-op `keepalive` job on it, and lets the watchdog stop it again.
- **Keepalive environment:** a second environment, `aws-bench-keepalive`, with **no** required reviewers and deployment restricted to `main`, so the weekly start never waits for a human. It gets the same `AWS_BENCH_ROLE_ARN` and `AWS_BENCH_INSTANCE_ID` variables. It can only start the instance and run trusted code from `main`, which a writer could do anyway. `start-runner` picks it with `environment: ${{ github.event_name == 'schedule' && 'aws-bench-keepalive' || 'aws-bench' }}`.

  GitHub can drop a scheduled run, and it disables schedules on public repos after 60 days without activity, so the keepalive keeps the runner registered only while those hold. The job-start hook logs each job, and the README's recovery for "no runner online" is `bootstrap.sh --replace`, which creates a fresh, freshly registered instance (one cold build afterwards).
- **`start-runner`** (new) runs on `ubuntu-latest` with the environment above and `permissions: id-token: write, contents: read`. Its `if:` is today's `aws-bench` job's, plus `|| github.event_name == 'schedule'`. It assumes the role with `configure-aws-credentials` and runs the trusted `scripts/start-bench-runner.sh`. That script sets the lease tag, then loops for up to 10 minutes, rechecking state on every pass. It never waits for a transient state that a concurrent starter might already have moved past:
  - `stopped`: call `start-instances`, retrying `InsufficientInstanceCapacity` and `IncorrectInstanceState` with backoff;
  - `stopping`, `pending`, or `shutting-down`: sleep 10 s and recheck;
  - `running`: done.
- **`bench`** (the old `aws-bench` job). Its settings:
  - `needs: start-runner` and `runs-on: [self-hosted, linux, x64, minip2p-bench]`, with `if: github.event_name != 'schedule'`;
  - `timeout-minutes: 90` and `permissions: contents: read`;
  - no `environment`: `needs` already means it runs only after the approved `start-runner` job. A new run cannot reach the instance without its own approved `start-runner`, even while the instance is up from another run.

  Re-running a failed bench means **Re-run all jobs**. "Re-run failed jobs" or re-running only `bench` keeps the earlier `start-runner` result: it neither wakes a stopped instance nor asks for approval again. Under the trust boundary only writers can re-run, so the missing approval is acceptable, but the job may sit queued. The README and the failure comment say to re-run all jobs.

  Both checkouts stay the same: trusted scripts and Dockerfile from the base, measured code in `bench-source/`. `configure-aws-credentials`, `amazon-ecr-login`, `setup-buildx-action`, `build-push-action`, and the gha cache are removed.
- **`keepalive`** (new): `needs: start-runner`, the same `runs-on`, `if: github.event_name == 'schedule'`, and one `run: true` step.
- **Measure** runs `exec scripts/run-bench-container.sh` from the trusted checkout. `exec` makes the helper the step's own process, so the runner's cancellation signals reach its traps. The helper:
  1. builds the image with `docker build` (local BuildKit cache) from the trusted `infra/bench/Dockerfile` and the chosen context, tagged `bench-<run_id>-<attempt>`, with `--build-arg BUILD_JOBS=4`. A `release` event adds `--no-cache`, so a baseline never reuses layers a PR build produced;
  2. starts it detached as `docker run -d --name bench-<run_id>-<attempt> --network none --sysctl net.ipv6.conf.lo.disable_ipv6=0 --cap-add SYS_PTRACE --security-opt seccomp=unconfined -e BENCH_GIT_SHA -e BENCH_SWEEP --entrypoint bash <image> -c "$(< scripts/run-container-benches.sh)"`:
     - the entrypoint script comes from the trusted checkout as a `-c` argument (about 1.5 KB), so a measured ref never supplies it, older refs work, and no child can read it from stdin;
     - `seccomp=unconfined` lets Gungraun's `personality(ADDR_NO_RANDOMIZE)` through;
     - every benchmark is loopback or in-process, so the measure phase needs no network. `endpoint_idle`'s `quic_dual_stack` variant needs `::1`; Docker 26+ already enables IPv6 loopback under `none`, and the sysctl makes that explicit;
  3. follows the container with `docker logs -f` into `$RUNNER_TEMP/bench/bench.log` in the background (PID saved), and blocks on `docker wait` as a background job via `wait $!`, so a trapped signal interrupts it immediately. After the container stops, the helper waits for the log follower and requires it to succeed before reading the log. The container's exit code becomes the step's;
  4. on `INT`/`TERM` (cancellation), runs only `timeout 5 docker rm -f` on the container, within GitHub's roughly 10 s grace period, then exits. On a normal `EXIT` it also removes the container and does a best-effort `docker rmi`. Anything left behind is removed by the next job's hook;
  5. decodes the `MINIP2P_BENCH_RESULTS` / `MINIP2P_SWEEP_RESULTS` marker from the log into a quarantine directory under `$RUNNER_TEMP`, as `run-aws-bench-task.sh` does today. A sweep archive is extracted there with `--no-same-owner --no-same-permissions`. The quarantine is rejected if it contains anything other than regular files and directories, or exceeds 50 MB. Only accepted files and the log are copied into `target/bench-artifacts/`, which the `always()` upload reads.
- **Prepare result slice** keeps its logic, with `bench-fargate.log` renamed to `bench.log`. Artifact `bench-aws` becomes `bench-results`, and `bench-comment.yml` downloads `bench-results`.
- Every job-ID reference in `compare` and `baseline` changes from `aws-bench` to `bench` (`needs`, `.result`, `.outputs.complete`).
- `AWS_REGION` env stays (used by `start-runner`).

Concurrency stays as it is. With one runner, jobs serialise: a second PR's `bench` job waits for the first, and `cancel-in-progress` still drops superseded PR runs.

### Container entrypoint

`scripts/run-fargate-benches.sh` becomes `scripts/run-container-benches.sh`:

- Remove `GUNGRAUN_ALLOW_ASLR=1`.
- Remove the `MINIP2P_BENCH_SETUP_TIMEOUT_SECS=600` override. Restore it only if validation shows the sweep setup timing out.
- Keep the stdout markers. Children inherit a closed stdin. The script still calls the measured ref's `scripts/run-benches.sh`.

The Dockerfile drops its `ENTRYPOINT` line and is otherwise unchanged.

### Baseline continuity

Instruction counts measured on the new instance with ASLR disabled are not comparable with the Fargate baselines. At cutover:

1. Cancel any queued or running Fargate Bench runs, and don't re-run them afterwards: a re-run uses the old workflow, and a release re-run would restore a Fargate baseline.
2. In one commit, remove both the `latest` and `latest-release` pointers on `bench-data`. The `<sha>.json` history stays.
3. Merge the switch.

Until the next stable release writes the first new baseline, `compare` takes its existing "no baseline" path. A future change of instance type repeats these steps; the README says so.

### Docs

- `infra/bench/README.md`: rewrite around the on-demand runner. Cover the resources, bootstrap with `--replace` and `--ssh-from`, the GitHub configuration (`AWS_BENCH_INSTANCE_ID`), the trust boundary, the watchdog and keepalive, measurement notes (ASLR off, whole-machine), baseline resets on a hardware change, cost, and running `scripts/run-bench-container.sh` by hand on the instance.
- New ADR `docs/adr/0025-benchmarks-on-an-on-demand-ec2-runner.md`. It records the context (Fargate failure rate, ASLR, CPU quota), the decision and the trust boundary. Alternatives considered:
  - GitHub-hosted runners: noisy, variable hardware;
  - mito: free, but shares a dev box, needs heavy isolation, and loses cores permanently;
  - an always-on instance: about $150/month;
  - JIT runners registered per start: no 14-day removal and a clean runner each time, but they need a GitHub App or PAT secret with repo admin rights, and a way to hand the config to the instance. Deferred;
  - a fresh instance per job: cold builds and more moving parts; this is the follow-up trigger;
  - staying on Fargate with retries.
- `docs/plans/pr-benchmarking-pipeline.md`: point its status note at the new README and ADR.
- `crates/minip2p/benches/support/delay.rs`: change the "Fargate grants no `NET_ADMIN`" comment to say the bench container runs unprivileged with `--network none`.

### Retiring Fargate

In the same PR, delete `scripts/run-aws-bench-task.sh` and `infra/bench/task-definition.json`. `bootstrap.sh` is rewritten rather than deleted. Until teardown, rollback is:
1. revert the PR;
2. re-run the old `bootstrap.sh` from the reverted tree to restore the CI role's ECS permissions;
3. restore the `bench-data` pointers.

After two weeks of healthy runs, as a separate step the maintainer approves, delete the ECS cluster `minip2p-bench`, the ECR repository, the `/minip2p/bench` log group, and the roles `minip2p-bench-task` and `minip2p-bench-execution`. Keep `minip2p-github-bench` and the `aws-bench` environment; the new design uses both.

## Rollout

1. **Provision.** The maintainer runs `infra/bench/bootstrap.sh` from the branch and stores `AWS_BENCH_INSTANCE_ID`. Then check:
   - the runner shows online in repo settings;
   - the security group has no inbound rules and the instance has no IAM profile;
   - the instance's shutdown behaviour is `stop`.
2. **Watchdog and lease.** Leave the freshly booted instance idle. It must stop itself 10–11 minutes after boot. Start it with `scripts/start-bench-runner.sh`. The runner must come back online and the instance must stay up until the 20-minute lease expires, then stop about 10 minutes later. Also start it while it is `stopping`: the script must end with it `running`. Finally set the tag a year ahead by hand: the idle instance must still stop about 10 minutes later.
3. **Dry run on the instance.** With `--ssh-from`, run `scripts/run-bench-container.sh` against `main` by hand, starting from an empty BuildKit cache. Record the build's peak memory (`/proc/pressure/memory` and `free`, sampled). If it comes within 1 GiB of 8 GiB, switch to `m7a.xlarge` before going further. Check that a full run completes, Gungraun reports ASLR disabled, the `quic_dual_stack` rows are present, `current.json` validates, and the elapsed time is recorded. Also run one sweep (`BENCH_SWEEP=all`) and confirm the extracted `rtt/` tree passes the file-type check. Then `--no-ssh`.
4. **Determinism.** Run twice back to back: Ir rows must be identical. Record the wall-clock spread and compare it with the last two Fargate artifacts.
5. **Network probe.** A throwaway `docker build` whose `RUN` tries IMDS must fail (hop limit 1). From the host, nothing but the VPC resolver should be reachable in private ranges.
6. **Actions path.** A `workflow_dispatch` of `bench.yml` on the feature branch must be refused by the hook, since its ref is not `main`; a dispatch at a `v*` tag likewise. Temporarily allow the branch ref in the hook, dispatch again, and confirm the whole path end to end:
   - `start-runner` starts the stopped instance;
   - `bench` runs and the artifact `bench-results` holds `bench.log`;
   - the instance stops itself afterwards.

   Then remove the allowance.

   Hostile-workflow check: push a throwaway branch whose own workflow runs on `minip2p-bench` under `workflow_dispatch`, with a step `if: always()` that writes `/tmp/hook-bypass`. Dispatch it while the instance is up. The hook must kill the worker, and `/tmp/hook-bypass` must not exist afterwards. Then delete the branch.
7. **Cancellation.** During an Actions run, cancel from the UI. `docker ps -a` on the instance must show no `bench-*` container within 10 s, and the instance must stop within the watchdog window. Repeat with a throwaway container that ignores `SIGTERM`.
8. **Cutover** as in Baseline continuity: cancel old runs, reset both pointers, merge. PR comments then show no-baseline results.
9. **First release** writes the new baseline. The next PR compares cleanly.
10. **Teardown** of Fargate resources after two weeks, with approval.

## Failure modes

| Failure | Behaviour |
| --- | --- |
| No capacity to start the instance | `start-runner` retries for 10 minutes, then fails clearly; the comment shows the existing failure warning. Re-run later. |
| Watchdog shutting down just as a new run starts | Rare: the watchdog must have read the old lease within seconds of `start-runner` setting the new one. `bench` stays queued. Cancel it and use Re-run all jobs, which starts the instance again. |
| Runner removed after 14 days offline | Avoided while the unattended weekly keepalive runs. If GitHub drops or disables the schedule, `bootstrap.sh --replace` restores the runner. |
| Instance fails to boot, or the runner never comes online | `bench` stays queued, and GitHub holds a self-hosted job for up to 24 h. The watchdog stops an instance that booted but stays idle once the lease expires. Cancel the run by hand and investigate with `--ssh-from`. Together with the two rows below, these are the failures not bounded automatically. |
| Partial re-run of only `bench` while the instance is stopped | Stays queued; cancel it and use Re-run all jobs. |
| Disk below 15 GB | The hook prunes, then fails the job with a clear message. |
| Job cancelled mid-measure | The trap force-removes the container within the grace period; the watchdog stops the instance. |
| Image build fails (PR breaks the build) | Measure fails; the result slice is empty; the comment shows the existing failure warning. |
| Hostile output (symlinks, huge archive) | The quarantine check fails the job before upload. |
| Forgotten or runaway instance | Idle shutdown 10 minutes after the lease expires, and a 120-minute cap per job. |
| Suspected compromise | `bootstrap.sh --replace` before the next release baseline. |

## Open questions

1. `c7a.xlarge` (8 GiB, $0.205/h), or `m7a.xlarge` (16 GiB, $0.232/h, about 13% more) from the start? Rollout step 3 measures the build's peak memory either way.
2. Should the weekly keepalive also run the benchmarks against `main` as a drift check (about $0.15/week), or stay a no-op?
