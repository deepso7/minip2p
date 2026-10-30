# Benchmarks on an on-demand EC2 runner

The Bench workflow ran every benchmark in one AWS Fargate task, and it was unreliable. Of 40 recent runs, 5 succeeded and 28 were cancelled. Each run pushed an image to ECR, registered a task definition, polled ECS, and scraped CloudWatch for a base64 result marker. A run that did succeed took 25–30 minutes on 2 vCPU / 4 GiB under a fixed CPU quota. Fargate's seccomp profile also blocks `personality`, so Gungraun ran with ASLR enabled (`GUNGRAUN_ALLOW_ASLR=1`), and the socket-sweep setup needed a 600 s timeout. The design is in [the plan](../plans/self-hosted-bench-runner.md), and the operating details are in [the runner README](../../infra/bench/README.md).

## Decision

- **One dedicated, normally stopped `m8a.xlarge` in `ap-south-1` is a persistent self-hosted runner** with the label `minip2p-bench`. A hosted `start-runner` job, approved through the `aws-bench` environment, assumes an OIDC role that can only tag and start that one instance. It sets a `bench-lease-until` tag and starts it. The `bench` job then builds and runs the benchmark container on the instance with a local BuildKit cache. A per-minute watchdog on the instance powers it off (shutdown behaviour `stop`) once the lease has expired and no job has run for 10 minutes, or when a job is older than 120 minutes.
- **The whole machine is the benchmark.** m8a has no SMT, so the four vCPUs are four physical cores. Nothing else runs there, and the container runs with `seccomp=unconfined` and `--network none`, so Gungraun disables ASLR and the setup-timeout override goes.
- **The instance holds nothing.** It has no instance profile, IMDSv2 with hop limit 1, a security group with no inbound rules, and its own VPC whose only route out is the internet gateway. It is not on the tailnet. Admin SSH is added and removed by `bootstrap.sh` on demand.
- **Releases and a weekly keepalive run unattended** through a second environment, `aws-bench-unattended`, with no reviewers and only `main` and `v*` tags allowed. Both run only trusted code. The keepalive keeps the runner from being removed after 14 days offline. Pull requests and manual runs still need approval through `aws-bench`.

## Trust boundary

Repository writers are trusted, since they can already change workflows and publish releases. The design defends against everyone else, in two layers. On GitHub, "Require approval for all external contributors" holds fork pull requests' runs, and the workflow's same-repository guard keeps forks out of `bench.yml`. On the instance, a job-start hook admits only `bench.yml` from `main` (for `pull_request_target`, `workflow_dispatch` and `schedule`) or from a `v*` tag (for `release`). The hook runs before any workflow-controlled step. It refuses a job by killing `Runner.Worker` with `SIGKILL`, because a failing hook still lets the runner evaluate `if: always()` steps, which would run as a user that is effectively root through `docker`.

The instance and its disk persist between runs, so a container escape could tamper with later jobs, release baselines included. We accept that: the escape gains no credentials or network position, and `bootstrap.sh --replace` swaps in a fresh instance before the next release baseline if a compromise is suspected.

## Rejected alternatives

- **GitHub-hosted runners.** They are noisy, and the hardware varies between runs.
- **mito, the maintainer's always-on dev box.** It is free, but it would mix PR code and benchmark noise with dev work. That would need a permanent CPU split, a restricted user, egress filtering, and cgroup limits, and it would lose those cores to the benchmarks all the time.
- **An always-on instance.** About $190/month, against about $16 on demand.
- **JIT runners registered per start.** They avoid the 14-day removal and give a clean runner each time. But they need a GitHub App or PAT secret with repository admin rights, and a way to hand the JIT config to the instance. Deferred.
- **A fresh instance per job.** It would close the persistence gap, but every build would be cold and there would be more moving parts. This is the follow-up if outside contributors ever need benchmarks.
- **Staying on Fargate with retries.** Retries multiply the slow ECR/ECS path without fixing ASLR or the CPU quota.

## Consequences

- The only AWS call on a run's critical path is starting one stopped instance. Every build, release baselines included, reuses the warm BuildKit cache. Cache keys cover each layer's inputs, so a release reuses only layers built from identical inputs, and the digest-pinned base image and the toolchain pinned in `bench/pins.json` keep releases on the same toolchain layer that pull requests are measured with. A container escape could still tamper with the cache, as with anything else on the persistent disk (see Trust boundary).
- Instruction counts are not comparable with the Fargate baselines. At cutover both `bench-data` pointers are removed, and the next stable release writes the first new baseline. A later change of instance type repeats that reset.
- With one runner, Bench jobs serialise. A second run's `bench` job waits for the first.
- Re-running a failed run means **Re-run all jobs**. A partial re-run reuses the earlier `start-runner` result and can sit queued against a stopped instance.
- The watchdog cannot fully close the race with a start that lands just as it powers off. Such a run stays queued and needs a manual cancel and re-run.
- If GitHub drops or disables the weekly schedule, the runner can still be removed. `bootstrap.sh --replace` restores it, at the cost of one cold build.
- The CI role loses its ECS, ECR, logs, and `iam:PassRole` permissions. The Fargate resources are deleted by hand after two weeks of healthy runs.
