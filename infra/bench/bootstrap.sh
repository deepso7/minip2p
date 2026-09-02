#!/usr/bin/env bash
# One-time setup of the static AWS resources the benchmark workflow uses.
# Idempotent: rerun it after editing a policy or retention setting. Needs
# administrator credentials; the CI role only pushes images and runs tasks.
set -euo pipefail

region=${AWS_BENCH_REGION:-${AWS_REGION:-us-east-1}}
export AWS_REGION="$region"
export AWS_DEFAULT_REGION="$region"
account=$(aws sts get-caller-identity --query Account --output text)

echo "Bootstrapping minip2p benchmark resources in $account/$region"

# --- ECS cluster ------------------------------------------------------------
status=$(aws ecs describe-clusters --clusters minip2p-bench \
  --query 'clusters[0].status' --output text 2>/dev/null || true)
if [[ "$status" != ACTIVE ]]; then
  aws ecs create-cluster --cluster-name minip2p-bench \
    --tags key=project,value=minip2p >/dev/null
  echo "created cluster minip2p-bench"
fi

# --- ECR repository with a lifecycle policy bounding storage -----------------
if ! aws ecr describe-repositories --repository-names minip2p-bench >/dev/null 2>&1; then
  aws ecr create-repository --repository-name minip2p-bench \
    --image-tag-mutability IMMUTABLE \
    --tags Key=project,Value=minip2p >/dev/null
  echo "created repository minip2p-bench"
fi
aws ecr put-image-tag-mutability --repository-name minip2p-bench \
  --image-tag-mutability IMMUTABLE >/dev/null
aws ecr put-lifecycle-policy --repository-name minip2p-bench \
  --lifecycle-policy-text '{
    "rules": [
      {
        "rulePriority": 1,
        "description": "Drop untagged layers from interrupted pushes",
        "selection": {"tagStatus": "untagged", "countType": "sinceImagePushed", "countUnit": "days", "countNumber": 1},
        "action": {"type": "expire"}
      },
      {
        "rulePriority": 2,
        "description": "Keep only the most recent benchmark images",
        "selection": {"tagStatus": "any", "countType": "imageCountMoreThan", "countNumber": 10},
        "action": {"type": "expire"}
      }
    ]
  }' >/dev/null

# --- CloudWatch log group ----------------------------------------------------
if ! aws logs describe-log-groups --log-group-name-prefix /minip2p/bench \
  --query 'logGroups[?logGroupName==`/minip2p/bench`]' --output text | grep -q .; then
  aws logs create-log-group --log-group-name /minip2p/bench \
    --tags project=minip2p
  echo "created log group /minip2p/bench"
fi
aws logs put-retention-policy --log-group-name /minip2p/bench --retention-in-days 14

# --- Task roles --------------------------------------------------------------
ecs_trust='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ecs-tasks.amazonaws.com"},
    "Action": "sts:AssumeRole",
    "Condition": {"StringEquals": {"aws:SourceAccount": "'"$account"'"}}
  }]
}'
ensure_role() {
  local name=$1
  if ! aws iam get-role --role-name "$name" >/dev/null 2>&1; then
    aws iam create-role --role-name "$name" \
      --assume-role-policy-document "$ecs_trust" \
      --tags Key=project,Value=minip2p >/dev/null
    echo "created role $name"
  else
    aws iam update-assume-role-policy --role-name "$name" \
      --policy-document "$ecs_trust"
  fi
}

# Strip every inline and attached policy so reruns converge the role to no
# AWS access. JSON output distinguishes an empty list from a policy named
# `None`, which the AWS CLI's text output cannot do.
clear_role_permissions() {
  local name=$1 policy_names_json policy_arns_json policy_name policy_arn
  local -a policy_names policy_arns

  policy_names_json=$(aws iam list-role-policies --role-name "$name" \
    --query 'PolicyNames' --output json)
  mapfile -t policy_names < <(jq -r '.[]' <<< "$policy_names_json")
  for policy_name in "${policy_names[@]}"; do
    aws iam delete-role-policy --role-name "$name" --policy-name "$policy_name"
  done

  policy_arns_json=$(aws iam list-attached-role-policies --role-name "$name" \
    --query 'AttachedPolicies[].PolicyArn' --output json)
  mapfile -t policy_arns < <(jq -r '.[]' <<< "$policy_arns_json")
  for policy_arn in "${policy_arns[@]}"; do
    aws iam detach-role-policy --role-name "$name" --policy-arn "$policy_arn"
  done
}

# The task role runs the benchmarks and needs no AWS access.
ensure_role minip2p-bench-task
clear_role_permissions minip2p-bench-task

# The execution role pulls the image and ships logs.
ensure_role minip2p-bench-execution
aws iam put-role-policy --role-name minip2p-bench-execution \
  --policy-name pull-and-log \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {"Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*"},
      {
        "Effect": "Allow",
        "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"],
        "Resource": "arn:aws:ecr:'"$region"':'"$account"':repository/minip2p-bench"
      },
      {
        "Effect": "Allow",
        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "arn:aws:logs:'"$region"':'"$account"':log-group:/minip2p/bench:*"
      }
    ]
  }'

# --- CI role policy ---------------------------------------------------------
# The OIDC role itself (trust policy, GitHub environment binding) is created by
# hand once; see README.md. This keeps its permissions in sync with the runner.
if aws iam get-role --role-name minip2p-github-bench >/dev/null 2>&1; then
  aws iam put-role-policy --role-name minip2p-github-bench \
    --policy-name minip2p-benchmark-runner \
    --policy-document '{
      "Version": "2012-10-17",
      "Statement": [
        {"Sid": "EcrLogin", "Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*"},
        {
          "Sid": "PushImage",
          "Effect": "Allow",
          "Action": [
            "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:CompleteLayerUpload",
            "ecr:GetDownloadUrlForLayer", "ecr:InitiateLayerUpload", "ecr:PutImage", "ecr:UploadLayerPart"
          ],
          "Resource": "arn:aws:ecr:'"$region"':'"$account"':repository/minip2p-bench"
        },
        {
          "Sid": "TaskDefinitions",
          "Effect": "Allow",
          "Action": ["ecs:RegisterTaskDefinition", "ecs:DeregisterTaskDefinition", "ecs:DescribeTaskDefinition"],
          "Resource": "*"
        },
        {
          "Sid": "TagNewTaskDefinitions",
          "Effect": "Allow",
          "Action": "ecs:TagResource",
          "Resource": "arn:aws:ecs:'"$region"':'"$account"':task-definition/minip2p-bench:*",
          "Condition": {"StringEquals": {"ecs:CreateAction": "RegisterTaskDefinition"}}
        },
        {
          "Sid": "RunTasks",
          "Effect": "Allow",
          "Action": ["ecs:RunTask", "ecs:StopTask", "ecs:DescribeTasks", "ecs:ListTasks"],
          "Resource": "*",
          "Condition": {"ArnEquals": {"ecs:cluster": "arn:aws:ecs:'"$region"':'"$account"':cluster/minip2p-bench"}}
        },
        {
          "Sid": "PassTaskRoles",
          "Effect": "Allow",
          "Action": "iam:PassRole",
          "Resource": [
            "arn:aws:iam::'"$account"':role/minip2p-bench-task",
            "arn:aws:iam::'"$account"':role/minip2p-bench-execution"
          ],
          "Condition": {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}}
        },
        {
          "Sid": "ReadLogs",
          "Effect": "Allow",
          "Action": "logs:GetLogEvents",
          "Resource": "arn:aws:logs:'"$region"':'"$account"':log-group:/minip2p/bench:*"
        },
        {
          "Sid": "DefaultNetwork",
          "Effect": "Allow",
          "Action": ["ec2:DescribeVpcs", "ec2:DescribeSubnets", "ec2:DescribeSecurityGroups"],
          "Resource": "*"
        }
      ]
    }'
  # Remove the policy from the previous Alchemy-based deployment, if present.
  aws iam delete-role-policy --role-name minip2p-github-bench \
    --policy-name minip2p-benchmark-deploy 2>/dev/null || true
  echo "updated CI role policy"
else
  echo "role minip2p-github-bench not found; create it per README.md, then rerun" >&2
fi

echo "done"
