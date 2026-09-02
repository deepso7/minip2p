#!/usr/bin/env bash
set -euo pipefail

: "${AWS_REGION:?AWS_REGION is required}"
: "${BENCH_GIT_SHA:?BENCH_GIT_SHA is required}"

cluster=${BENCH_CLUSTER:-minip2p-bench}
family=${BENCH_TASK_FAMILY:-minip2p-bench}
output=${BENCH_OUTPUT:-target/bench-artifacts/current.json}
task_arn=

stop_active_task() {
  [[ -z "$task_arn" ]] && return 0

  aws ecs stop-task \
    --cluster "$cluster" \
    --task "$task_arn" \
    --reason "Benchmark runner cleanup" >/dev/null

  local stop_deadline=$((SECONDS + 180))
  local status
  while (( SECONDS < stop_deadline )); do
    status=$(aws ecs describe-tasks \
      --cluster "$cluster" \
      --tasks "$task_arn" \
      --query 'tasks[0].lastStatus' \
      --output text)
    if [[ "$status" == STOPPED ]]; then
      task_arn=
      return 0
    fi
    sleep 5
  done
  echo "ECS task did not stop within 3 minutes: $task_arn" >&2
  return 1
}

cleanup_on_exit() {
  local exit_status=$?
  trap - EXIT
  if ! stop_active_task; then
    exit_status=1
  fi
  exit "$exit_status"
}

trap cleanup_on_exit EXIT
trap 'exit 130' INT TERM

task_definition=$(aws ecs describe-task-definition \
  --task-definition "$family" \
  --query 'taskDefinition.taskDefinitionArn' \
  --output text)
container_name=$(aws ecs describe-task-definition \
  --task-definition "$task_definition" \
  --query 'taskDefinition.containerDefinitions[0].name' \
  --output text)
log_group=$(aws ecs describe-task-definition \
  --task-definition "$task_definition" \
  --query 'taskDefinition.containerDefinitions[0].logConfiguration.options."awslogs-group"' \
  --output text)
stream_prefix=$(aws ecs describe-task-definition \
  --task-definition "$task_definition" \
  --query 'taskDefinition.containerDefinitions[0].logConfiguration.options."awslogs-stream-prefix"' \
  --output text)

vpc_id=$(aws ec2 describe-vpcs \
  --filters Name=is-default,Values=true \
  --query 'Vpcs[0].VpcId' \
  --output text)
if [[ -z "$vpc_id" || "$vpc_id" == None ]]; then
  echo "AWS account has no default VPC in $AWS_REGION" >&2
  exit 1
fi

subnets=$(aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=$vpc_id" Name=default-for-az,Values=true \
  --query 'Subnets[].SubnetId' \
  --output text | tr '\t' ',')
security_group=$(aws ec2 describe-security-groups \
  --filters "Name=vpc-id,Values=$vpc_id" Name=group-name,Values=default \
  --query 'SecurityGroups[0].GroupId' \
  --output text)

task_arn=$(aws ecs run-task \
  --cluster "$cluster" \
  --task-definition "$task_definition" \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[$subnets],securityGroups=[$security_group],assignPublicIp=ENABLED}" \
  --overrides "$(jq -cn \
    --arg container "$container_name" \
    --arg sha "$BENCH_GIT_SHA" \
    '{containerOverrides:[{name:$container,environment:[{name:"BENCH_GIT_SHA",value:$sha}]}]}')" \
  --query 'tasks[0].taskArn' \
  --output text)

if [[ -z "$task_arn" || "$task_arn" == None ]]; then
  echo "ECS did not return a task ARN" >&2
  exit 1
fi

echo "Started $task_arn"

deadline=$((SECONDS + 2700))
while (( SECONDS < deadline )); do
  status=$(aws ecs describe-tasks \
    --cluster "$cluster" \
    --tasks "$task_arn" \
    --query 'tasks[0].lastStatus' \
    --output text)
  [[ "$status" == STOPPED ]] && break
  sleep 15
done

if [[ ${status:-} != STOPPED ]]; then
  echo "Fargate benchmark exceeded 45 minutes" >&2
  # The EXIT trap owns the bounded stop-and-wait cleanup.
  exit 1
fi

task_id=${task_arn##*/}
log_stream="$stream_prefix/$container_name/$task_id"
mkdir -p "$(dirname "$output")"

retrieve_log() {
  local next_token=
  local new_token
  local page=target/bench-fargate-page.json
  local -a args

  : > target/bench-fargate.log
  while true; do
    args=(
      --log-group-name "$log_group"
      --log-stream-name "$log_stream"
      --start-from-head
      --no-paginate
      --output json
    )
    if [[ -n "$next_token" ]]; then
      args+=(--next-token "$next_token")
    fi

    aws logs get-log-events "${args[@]}" > "$page" || return 1
    jq -r '.events[].message' "$page" >> target/bench-fargate.log

    new_token=$(jq -r '.nextForwardToken' "$page")
    if [[ "$new_token" == "$next_token" ]]; then
      return 0
    fi
    next_token=$new_token
  done
}

for attempt in {1..12}; do
  if retrieve_log 2>/dev/null \
    && rg -q 'MINIP2P_BENCH_RESULTS=' target/bench-fargate.log; then
    break
  fi
  sleep 5
done

exit_code=$(aws ecs describe-tasks \
  --cluster "$cluster" \
  --tasks "$task_arn" \
  --query 'tasks[0].containers[0].exitCode' \
  --output text)
task_arn=

if [[ "$exit_code" != 0 ]]; then
  cat target/bench-fargate.log >&2
  echo "Fargate benchmark exited with code $exit_code" >&2
  exit 1
fi

python3 - "$output" <<'PY'
import base64
import pathlib
import sys

log = pathlib.Path("target/bench-fargate.log").read_text()
prefix = "MINIP2P_BENCH_RESULTS="
encoded = next((line.removeprefix(prefix) for line in log.splitlines() if line.startswith(prefix)), None)
if encoded is None:
    raise SystemExit("benchmark result marker missing from CloudWatch logs")
pathlib.Path(sys.argv[1]).write_bytes(base64.b64decode(encoded, validate=True))
PY

python3 scripts/bench_results.py merge "$output" --output "$output" --git-sha "$BENCH_GIT_SHA"
