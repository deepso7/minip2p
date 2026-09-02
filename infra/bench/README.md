# AWS benchmark runner

The benchmark workflow deploys this Alchemy stack and runs the full benchmark
suite in one AWS Fargate task. GitHub Actions orchestrates the task and stores
the returned JSON as its normal `bench-aws` artifact.

Published stable releases produce the baseline stored on `bench-data`. Pull
requests from this repository run the same task and compare their head commit
with that release when a baseline is available. Fork pull requests skip AWS
execution and comparison. Manual runs measure the default branch and produce
artifacts, but never change the release baseline.

The stack pins `alchemy@2.0.0-beta.76` and `effect@4.0.0-rc.112`. It creates:

- an ECS cluster and 2-vCPU, 4-GiB Fargate task definition;
- an ECR repository and image;
- task and execution IAM roles;
- a CloudWatch log group; and
- an account-regional S3 bucket for Alchemy state.

The Fargate task uses the account's default VPC, default subnets, and default
security group. It receives a public IP so it can pull the image from ECR.

## GitHub configuration

Create a protected GitHub Environment named `aws-bench`, require reviewer
approval for deployments, prevent self-review, and store `AWS_BENCH_ROLE_ARN`
as an environment variable. Create an OIDC role whose trust is restricted to
that environment:

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
          "token.actions.githubusercontent.com:sub": "repo:deepso7/minip2p:environment:aws-bench"
        }
      }
    }
  ]
}
```

The role needs permission to manage this stack's ECS cluster and task
definitions, ECR repository, IAM roles, CloudWatch log group, and S3 state
bucket. The benchmark runner also calls these actions:

- `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, and
  `ec2:DescribeSecurityGroups`;
- `ecs:DescribeClusters`, `ecs:DescribeTaskDefinition`, `ecs:DescribeTasks`,
  `ecs:ListTasks`, `ecs:RunTask`, and `ecs:StopTask`;
- `logs:GetLogEvents`; and
- `iam:PassRole`, scoped to the stack's task and execution roles.

Keep the role dedicated to this repository and set its maximum session duration
to at least 7200 seconds.

Set these GitHub repository variables under **Settings > Secrets and variables
> Actions > Variables**:

- `AWS_BENCH_REGION`: the AWS region, or omit it to use `us-east-1`.

No AWS access keys are stored in GitHub. Pull requests from forks do not run
the AWS job. For same-repository pull requests, the workflow and infrastructure
code come from the trusted base commit; only the source compiled inside Docker
comes from the pull request. Docker still executes the pull request's Rust build
scripts and package install scripts with the container's permissions. The
container is the isolation boundary.

AWS runs set `GUNGRAUN_ALLOW_ASLR=1` because Fargate blocks the syscall Gungraun
uses to disable ASLR. Instruction counts from AWS runs are comparable with
other AWS runs that use the same setting, not with local runs that disable
ASLR. The task also raises both socket-sweep setup timeouts to 120 seconds for
Fargate's fixed CPU quota.

The task runs all three tiers sequentially and publishes one result document.
If any tier fails, the task publishes no rows. This avoids comparing a partial
run as though it covered the full benchmark set.

## Local commands

With AWS credentials exported in the environment:

```bash
cd infra/bench
pnpm install --frozen-lockfile
pnpm run deploy
```

The deploy command builds its Docker context under `.alchemy/` from tracked
files. Local `target/`, dependency trees, reference checkouts, and other
generated directories never enter Alchemy's pre-Docker content hash.

CI sets `BENCH_STAGE`, `BENCH_CLUSTER`, and `BENCH_TASK_FAMILY` from the
workflow run ID. Each run therefore owns a separate stack and can execute
without a lossy GitHub Actions concurrency queue. Local commands omit these
variables and continue to use the shared `ci` stack.

Remove every stack-owned resource with:

```bash
cd infra/bench
pnpm run destroy
```

Cleanup retries transient ECS discovery and stop errors, then waits once for
the tasks to stop. If ECS does not confirm that state, cleanup fails without
destroying the stack. Retry that run's cleanup with the names from the workflow
log:

```bash
cd infra/bench
BENCH_STAGE=run-RUN_ID-RUN_ATTEMPT \
BENCH_CLUSTER=minip2p-bench-run-RUN_ID-RUN_ATTEMPT \
BENCH_TASK_FAMILY=minip2p-bench-run-RUN_ID-RUN_ATTEMPT \
pnpm run destroy
```

Alchemy state remains in its S3 bucket so later deployments retain resource
ownership history.
