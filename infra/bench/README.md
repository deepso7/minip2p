# AWS benchmark runner

The benchmark workflow builds one container image, runs the full benchmark
suite in it as a single AWS Fargate task, and stores the returned JSON as its
`bench-aws` artifact. GitHub Actions orchestrates the task directly with the
AWS CLI and `jq`; there is no deployment tool in the loop.

Published stable releases produce the baseline stored on `bench-data`. Pull
requests from this repository run the same task and compare their head commit
with that release when a baseline is available. Fork pull requests skip AWS
execution and comparison. Manual runs measure the default branch and produce
artifacts, but never change the release baseline.

## Resources

All AWS resources are static and created once by `bootstrap.sh`:

- ECS cluster `minip2p-bench`;
- ECR repository `minip2p-bench`, immutable tags, with a lifecycle policy that
  keeps the ten newest images and drops untagged layers after a day;
- CloudWatch log group `/minip2p/bench` with 14-day retention;
- task role `minip2p-bench-task` (no AWS access) and execution role
  `minip2p-bench-execution` (pull the image, write logs);
- the inline permissions of the CI role `minip2p-github-bench`.

Per run, the workflow pushes one image tagged with the measured commit, GitHub
Actions run ID, and run attempt. It registers one revision of the
`minip2p-bench` task-definition family from `task-definition.json`, runs it,
and deregisters the revision when the runner exits. Nothing else is created,
so there is nothing to tear down and nothing to leak when a run fails.

The task uses 2 vCPU and 4 GiB in the account's default VPC, default subnets,
and default security group, with a public IP so it can pull from ECR.

## GitHub configuration

Create a GitHub Environment named `aws-bench` with required reviewers and
store `AWS_BENCH_ROLE_ARN` as an environment variable. `AWS_BENCH_REGION` is
optional and defaults to `us-east-1`. Then create the OIDC role
`minip2p-github-bench` whose trust is restricted to that environment:

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

Set its maximum session duration to at least 7200 seconds. Its permissions
are written by `bootstrap.sh`: push to the one repository, register and run
tasks on the one cluster, pass the two task roles, and read the one log group.

With administrator credentials exported, create or update everything else.
Set `AWS_BENCH_REGION` to the same region configured in GitHub, or omit it to
use `us-east-1`:

```bash
AWS_BENCH_REGION=us-east-1 infra/bench/bootstrap.sh
```

The script is idempotent. Rerun it after changing a policy, retention, or the
lifecycle rules.

## Security model

No AWS access keys are stored in GitHub. Pull requests from forks do not run
the AWS job. For same-repository pull requests, the workflow, Dockerfile, and
runner script come from the trusted base commit; only the Docker build context
comes from the pull request. Docker still executes the pull request's Rust
build scripts and package install scripts on the runner during the image
build. The container is the isolation boundary.

## Measurement notes

AWS runs set `GUNGRAUN_ALLOW_ASLR=1` because Fargate blocks the syscall Gungraun
uses to disable ASLR. Instruction counts from AWS runs are comparable with
other AWS runs that use the same setting, not with local runs that disable
ASLR. The task also raises both socket-sweep setup timeouts to 600 seconds for
Fargate's fixed CPU quota. Comparisons classify instruction-count deltas; they
show wall-clock deltas as informational because Fargate placement affects them.

The task runs all three tiers sequentially and publishes one result document.
If any tier fails, the task publishes no rows. This avoids comparing a partial
run as though it covered the full benchmark set.

## Running locally

With credentials that can push to the repository and run tasks:

```bash
AWS_REGION=${AWS_BENCH_REGION:-us-east-1}
export AWS_REGION
IMAGE_TAG="$(git rev-parse HEAD)-local-$(date +%s)"
aws ecr get-login-password | docker login --username AWS --password-stdin "$REGISTRY"
docker build -f infra/bench/Dockerfile -t "$REGISTRY/minip2p-bench:$IMAGE_TAG" .
docker push "$REGISTRY/minip2p-bench:$IMAGE_TAG"
BENCH_GIT_SHA=$(git rev-parse HEAD) \
  BENCH_IMAGE="$REGISTRY/minip2p-bench:$IMAGE_TAG" \
  scripts/run-aws-bench-task.sh
```

Set `AWS_BENCH_REGION` to the region used by `bootstrap.sh` and the GitHub
environment. `REGISTRY` is `ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com`. The
result lands in `target/bench-artifacts/current.json` and the task log in
`target/bench-fargate.log`.
