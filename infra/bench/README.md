# Bench runner: an on-demand EC2 instance

The Bench workflow runs on one dedicated EC2 instance, `minip2p-bench` (`m8a.xlarge`: 4 physical cores without SMT, 16 GiB, in `ap-south-1`). The instance is a persistent self-hosted GitHub Actions runner with the labels `self-hosted,linux,x64,minip2p-bench`, and it stays stopped between runs. For each run, a hosted `start-runner` job assumes the CI role through OIDC, sets a lease tag and starts the instance with `scripts/start-bench-runner.sh`. The `bench` job then runs on the instance: `scripts/run-bench-container.sh` builds the image from `infra/bench/Dockerfile` with the local BuildKit cache and runs the suite in one container. The result is uploaded as the `bench-results` artifact, and an on-instance watchdog stops the instance once it is idle. The design and its trade-offs are in [ADR 0025](../../docs/adr/0025-benchmarks-on-an-on-demand-ec2-runner.md) and [the plan](../../docs/plans/self-hosted-bench-runner.md).

Published stable releases produce the baseline stored on `bench-data`. Pull requests from this repository run the same job and compare their head commit with that release when a baseline is available. Fork pull requests skip the bench job and comparison. Manual runs measure the default branch and produce artifacts, but never change the release baseline.

## Resources

`bootstrap.sh` creates everything, tagged `project=minip2p`, in `AWS_BENCH_REGION` (default `ap-south-1`):

- a dedicated VPC `10.77.0.0/24` with one public subnet, an internet gateway, and a route table whose only non-local route is `0.0.0.0/0` to it. There is no peering, no endpoints, and no NAT gateway;
- the security group `minip2p-bench-runner`, with no inbound rules;
- the key pair `minip2p-bench`, whose private key is written to `BENCH_SSH_KEY` (default `~/.ssh/minip2p-bench.pem`, mode 0600) and never leaves that machine;
- the instance `minip2p-bench`: Ubuntu 24.04 LTS amd64, an 80 GB gp3 root volume, a public IPv4 address for egress, no instance profile, IMDSv2 required with hop limit 1 (containers cannot reach it), instance tags in metadata, and instance-initiated shutdown behaviour `stop`;
- the inline policy of the CI role `minip2p-github-bench`: `ec2:StartInstances` on the instance, `ec2:CreateTags` on the instance for the `bench-lease-until` key only, and `ec2:DescribeInstances`.

The instance's first boot runs `cloud-init.yaml`, which bootstrap renders with the scripts in this directory and a runner registration token. It installs Docker CE from Docker's apt repository and `jq`. It creates the user `runner`, in `docker` and without sudo, and installs the pinned, SHA-256-verified `actions/runner` release in `/home/runner/actions-runner` as a systemd service. It also installs the job-start hook (`runner-hooks/job-started.sh`, as `/opt/minip2p-bench/job-started.sh`) and the watchdog (`watchdog.sh` with `minip2p-bench-watchdog.{service,timer}`). These steps run once per instance; later boots only start the services. The runner updates itself when GitHub ships a new release.

## Bootstrap

With administrator credentials exported and `gh` logged in as a repository admin:

```bash
AWS_BENCH_REGION=ap-south-1 infra/bench/bootstrap.sh
```

It is idempotent and finds existing resources by tag. Rerun it to recreate anything missing or to restore the CI role's trust and policy. It prints the instance ID to store as `AWS_BENCH_INSTANCE_ID`. `BENCH_INSTANCE_TYPE` overrides the instance type for a new instance.

- `--replace` terminates the instance and creates a fresh one, registered anew, then points the CI role's policy at it. Use it when the runner was removed after 14 days offline, the instance is broken, or a compromise is suspected (run it before the next release baseline). The first run afterwards does a cold build. Update `AWS_BENCH_INSTANCE_ID` afterwards.
- `--ssh-from <cidr>` adds a port-22 rule for that CIDR, and `--no-ssh` removes every port-22 rule. Neither touches anything else. Log in as `ubuntu` with the key pair's private key.
- `--render-user-data <file>` writes the rendered user data with a dummy token, for inspection. It makes no AWS calls.

The rendered user data holds a live registration token, so bootstrap never prints or logs it. The token is valid for one hour. EC2 keeps the user data and cloud-init caches it on the instance, so the expired token stays readable by account administrators and from the instance's host (not from containers).

## GitHub configuration

- **Environment `aws-bench`**, with required reviewers. Variables: `AWS_BENCH_ROLE_ARN`, `AWS_BENCH_INSTANCE_ID`, and optionally `AWS_BENCH_REGION` (default `ap-south-1`).
- **Environment `aws-bench-keepalive`**, with **no** required reviewers and deployments restricted to `main`. Same variables. Only the weekly schedule uses it.
- **Actions setting** "Require approval for all external contributors", so no fork pull request's workflow runs without a maintainer's approval.

The OIDC role `minip2p-github-bench` is created once by hand with a maximum session duration of at least one hour. `bootstrap.sh` then rewrites its trust to exactly this:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::AWS_ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": [
            "repo:deepso7/minip2p:environment:aws-bench",
            "repo:deepso7/minip2p:environment:aws-bench-keepalive"
          ]
        }
      }
    }
  ]
}
```

No AWS access keys are stored in GitHub, and the instance holds no credentials.

## Trust boundary

Repository writers are trusted: they can already push to `main`, publish releases, and change workflows. The `aws-bench` approval guards against accidental runs. The design defends against everyone without write access, in two layers:

- **On GitHub:** the external-contributor approval setting holds fork pull requests' runs, and the workflow's same-repository guard keeps fork pull requests out of `bench.yml`.
- **On the instance:** the job-start hook runs before any workflow-controlled step, container-action build, or job container. It admits a job only if it comes from `deepso7/minip2p` and is `bench.yml` from `refs/heads/main` (for `pull_request_target`, `workflow_dispatch`, and `schedule`) or from a `refs/tags/v*` tag (for `release`). To refuse a job, it walks its parent processes to `Runner.Worker` and kills it with `SIGKILL`. A non-zero exit would not be enough: the runner records the failure but still evaluates later steps, so a hostile `if: always()` step would run as `runner`, which is in `docker` and therefore root on the instance. A fork's workflow aimed at the `minip2p-bench` label runs under `pull_request` with a `refs/pull/N/merge` ref, so it is killed even if it is approved.

Within an admitted run, the workflow, the Dockerfile, and the helper scripts come from the trusted base commit. Only the Docker build context (`bench-source/`) comes from the measured ref, and Docker still executes its build scripts during the image build. The instance and its disk persist between runs, so a container escape could tamper with later jobs. That is accepted: the instance has no IAM role, no inbound access, no route to anything but the internet, and nothing worth stealing. `--replace` restores a clean instance.

After admitting a job, the hook removes leftover `bench-*` containers and images, prunes the BuildKit cache to 40 GB, and fails the job if less than 15 GB is free on `/`.

## Lease and watchdog

Before each start, `start-runner` sets the tag `bench-lease-until` to now + 20 minutes (Unix seconds). That covers the boot and the runner picking up the queued job. A systemd timer runs `watchdog.sh` every minute and powers the instance off, which stops it, when either:

- it has been up for at least 10 minutes, the lease has expired, and no `Runner.Worker` process has existed for 10 consecutive minutes; or
- the oldest `Runner.Worker` is older than 120 minutes, which means a stuck job, since the bench job's timeout is 90 minutes.

A missing, malformed, or more-than-30-minutes-ahead lease counts as expired, so no tag value can keep the instance on. The first boot's setup counts as busy for up to an hour. Decisions are logged to the journal: `journalctl -u minip2p-bench-watchdog`. For a long manual session, stop the timer with `sudo systemctl stop minip2p-bench-watchdog.timer`; the next boot starts it again.

The lease cannot fully close the race with a watchdog that read the old lease just before a new start, so rarely `bench` stays queued after the instance stopped. Cancel the run and use **Re-run all jobs**.

## Keepalive

GitHub removes a self-hosted runner that has not connected for 14 days. A weekly `schedule` run therefore starts the instance through `aws-bench-keepalive`, runs a no-op `keepalive` job on it, and lets the watchdog stop it again. GitHub can drop scheduled runs, and it disables schedules on public repositories after 60 days without activity. If the runner shows offline in the repository settings and bench jobs stay queued, run `bootstrap.sh --replace`.

## Re-running

Re-run a failed Bench run with **Re-run all jobs**. Re-running only the failed jobs, or only `bench`, keeps the earlier `start-runner` result. It neither starts a stopped instance nor asks for approval again, so the job can sit queued.

## Measurement notes

The container runs with no network (`--network none`, IPv6 loopback enabled) and `seccomp=unconfined`, so Gungraun disables ASLR as it does locally; `GUNGRAUN_ALLOW_ASLR` is no longer set. The whole machine is the benchmark, with no co-tenants and no CPU quota, so `MINIP2P_BENCH_SETUP_TIMEOUT_SECS` is no longer overridden either. Comparisons classify instruction-count deltas. They show wall-clock deltas as informational.

Each result row names one metric from the fixed `METRICS` registry in `scripts/bench_results.py`, and one benchmark may have several metric rows. The registry sets each metric's direction and whether it is classified. Classified metrics (`Ir`, `allocs_per_msg`, `bytes_allocated_per_msg`) get noise/changed/notable bands. The others are informational: the comparison reports their change and direction but never classifies them. For higher-is-better metrics such as `mb_per_s`, an increase counts as `improved`. Only `Ir` rows depend on the instruction-count pins. A bench that measures its own metrics writes a JSON array of rows into `target/bench-results/custom/`; the `custom` subcommand collects them and checks them against `EXPECTED_CUSTOM`. The `wall` pass of `scripts/run-benches.sh` runs these benches between a `start` marker and the `custom` subcommand, which writes `target/bench-results/custom.json`; `scripts/run-container-benches.sh` merges it with the other tiers. These are `minip2p-rs`'s `endpoint_idle` (`wakeups_per_s` and `cpu_ms_per_s` of an idle endpoint) and `endpoint_throughput` (`mb_per_s`, `allocs_per_mb` and `bytes_allocated_per_mb` over TCP, QUIC and a relayed circuit, plus each QUIC-carried Endpoint's `datagrams_per_mb` and `avg_datagram_bytes` per direction), `endpoint_ping_load` (`rtt_us_p50` and `rtt_us_p99` of application-observed ping latency over TCP and QUIC on an endpoint that is idle, relaying, or forwarding pubsub), `endpoint_rtt` (`mb_per_s` over QUIC and TCP + Yamux on an emulated 100 Mbit/s, 100 ms link), and `minip2p-pubsub`'s `router_allocs` (`allocs_per_msg` and `bytes_allocated_per_msg` for gossipsub forwarding). To add another, add any metric it reports to `METRICS`, register every `(tier, name, metric)` row it emits in `EXPECTED_CUSTOM`, and run it in the same span of the `wall` pass, building it in `infra/bench/Dockerfile` as well.

The container runs all three tiers sequentially and publishes one result document. If any tier fails, it publishes no rows. This avoids comparing a partial run as though it covered the full benchmark set.

### Baseline resets

Instruction counts depend on the host. When the host changes (the move from Fargate, or a later change of instance type):

1. cancel queued and running Bench runs from the old setup, and don't re-run them, since a re-run uses the old workflow;
2. remove both the `latest` and `latest-release` pointers on `bench-data` in one commit, keeping the `<sha>.json` history;
3. merge the change.

Until the next stable release writes a new baseline, comparisons take the "no baseline" path.

## Emulated-link sweeps

A manual dispatch of the Bench workflow with `sweep` set (for example `all`, or `quic-stream yamux`) and optionally `ref` runs `scripts/rtt-sweep.sh` on the instance instead of the benchmarks: #361's window sweeps over the `endpoint_rtt` emulated link. The artifact carries their logs and JSON lines under `rtt/`; each log ends with the value the sweep picks. A full sweep takes about 20 minutes, well inside the job's 90-minute timeout.

## Cost

On-demand `m8a.xlarge` in `ap-south-1` is about $0.256/hour, billed only while running. A run, including boot and the idle tail, takes about 40 minutes, about $0.17. The 80 GB gp3 volume costs about $7.30/month, and the public IPv4 address is billed only while the instance runs. At about 50 runs a month, the total is about $16/month.

## Running by hand on the instance

Allow SSH, start the instance, and log in:

```bash
infra/bench/bootstrap.sh --ssh-from "$(curl -s https://checkip.amazonaws.com)/32"
AWS_REGION=ap-south-1 AWS_BENCH_INSTANCE_ID=i-... scripts/start-bench-runner.sh
ssh -i ~/.ssh/minip2p-bench.pem ubuntu@<public IP>
```

On the instance, check out the repository as `runner` (for example `sudo -iu runner`, then `git clone https://github.com/deepso7/minip2p`), and from its root:

```bash
BENCH_GIT_SHA=$(git rev-parse HEAD) scripts/run-bench-container.sh
BENCH_GIT_SHA=$(git rev-parse HEAD) BENCH_SWEEP=all scripts/run-bench-container.sh
```

Run it in the foreground, as above. A script started with `&` from another non-interactive script inherits SIGINT as ignored, so its cancellation trap would never fire.

`BENCH_CONTEXT` selects another build context, and `BENCH_NO_CACHE=1` builds without the layer cache, as releases do. The result lands in `target/bench-artifacts/current.json` (or `rtt/` for a sweep) with the container log in `target/bench-artifacts/bench.log`. Run `infra/bench/bootstrap.sh --no-ssh` when done. The watchdog stops the instance afterwards.

## Retiring Fargate

The Fargate resources are left in place until the instance has run healthily for two weeks, as a rollback path: revert the change, rerun the previous `bootstrap.sh` to restore the CI role's ECS permissions, and restore the `bench-data` pointers. After that, with approval, delete by hand:

- the ECS cluster `minip2p-bench` and its task-definition revisions;
- the ECR repository `minip2p-bench`;
- the CloudWatch log group `/minip2p/bench`;
- the roles `minip2p-bench-task` and `minip2p-bench-execution`.

Keep the role `minip2p-github-bench` and the `aws-bench` environment; the instance design uses both.
