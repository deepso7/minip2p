# AWS benchmark runner

The benchmark workflow deploys this Alchemy stack and runs the full benchmark
suite in one AWS Fargate task. GitHub Actions orchestrates the task and stores
the returned JSON as its normal `bench-aws` artifact.

The stack pins `alchemy@2.0.0-beta.76` and `effect@4.0.0-rc.112`. It creates:

- an ECS cluster and 2-vCPU, 4-GiB Fargate task definition;
- an ECR repository and image;
- task and execution IAM roles;
- a CloudWatch log group; and
- an account-regional S3 bucket for Alchemy state.

The Fargate task uses the account's default VPC, default subnets, and default
security group. It receives a public IP so it can pull the image from ECR.

## GitHub configuration

Create a GitHub Actions OIDC role in the AWS account. Restrict its trust policy
to this repository:

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
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:deepso7/minip2p:*"
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
- `ecs:DescribeTaskDefinition`, `ecs:DescribeTasks`, `ecs:RunTask`, and
  `ecs:StopTask`;
- `logs:GetLogEvents`; and
- `iam:PassRole`, scoped to the stack's task and execution roles.

Keep the role dedicated to this repository.

Set these GitHub repository variables under **Settings > Secrets and variables
> Actions > Variables**:

- `AWS_BENCH_ROLE_ARN`: the OIDC role ARN;
- `AWS_BENCH_REGION`: the AWS region, or omit it to use `us-east-1`.

No AWS access keys are stored in GitHub. Pull requests from forks do not run
the AWS job because their code must not receive the repository's AWS identity.

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

Remove every stack-owned resource with:

```bash
cd infra/bench
pnpm run destroy
```

Alchemy state remains in its S3 bucket so later deployments retain resource
ownership history.
