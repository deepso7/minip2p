#!/usr/bin/env bash
# Run one benchmark task on the static Fargate infrastructure and write the
# result document. Registers a task-definition revision for BENCH_IMAGE, runs
# it in the account's default VPC, streams the CloudWatch log back, and
# decodes the MINIP2P_BENCH_RESULTS marker the container prints on success.
set -euo pipefail

: "${AWS_REGION:?AWS_REGION is required}"
: "${BENCH_GIT_SHA:?BENCH_GIT_SHA is required}"
: "${BENCH_IMAGE:?BENCH_IMAGE is the image URI to run}"

cluster=minip2p-bench
log_group=/minip2p/bench
output=${BENCH_OUTPUT:-target/bench-artifacts/current.json}
task_arn=
task_definition=

interruptible_sleep() {
  sleep "$1" &
  wait $!
}

task_status() {
  aws ecs describe-tasks \
    --cluster "$cluster" \
    --tasks "$1" \
    --query 'tasks[0].lastStatus' \
    --output text
}

wait_for_stopped() {
  local arn=$1 timeout=$2 interval=$3
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    [[ "$(task_status "$arn")" == STOPPED ]] && return 0
    interruptible_sleep "$interval"
  done
  return 1
}

stop_task() {
  local arn=$1 attempt
  for attempt in 1 2 3; do
    if aws ecs stop-task --cluster "$cluster" --task "$arn" \
      --reason "Benchmark runner exit" >/dev/null; then
      return 0
    fi
    if (( attempt < 3 )); then
      interruptible_sleep 1
    fi
  done
  return 1
}

# Stop a still-running task and deregister this run's revision. Runs on every
# exit, including cancellation, where GitHub allows about ten seconds (SIGINT,
# 7.5 s, SIGTERM, 2.5 s, SIGKILL). Stop retries and status polling add no more
# than seven seconds of deliberate waiting. Nothing else needs cleaning up
# because the cluster, repository, roles, and log group are permanent.
cleanup() {
  local exit_status=$? status
  trap '' INT TERM
  trap - EXIT
  if [[ -n "$task_arn" ]]; then
    status=$(task_status "$task_arn" 2>/dev/null || true)
    if [[ "$status" != STOPPED ]] && ! stop_task "$task_arn"; then
      echo "failed to stop ECS task, stop it by hand: $task_arn" >&2
      exit_status=1
    elif [[ "$status" != STOPPED ]] && ! wait_for_stopped "$task_arn" 5 1; then
      echo "ECS task did not stop before cleanup timed out: $task_arn" >&2
      exit_status=1
    fi
  fi
  if [[ -n "$task_definition" ]]; then
    if ! aws ecs deregister-task-definition \
      --task-definition "$task_definition" >/dev/null; then
      echo "failed to deregister task definition: $task_definition" >&2
      exit_status=1
    fi
  fi
  exit "$exit_status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

account=$(aws sts get-caller-identity --query Account --output text)
mkdir -p target
jq \
  --arg image "$BENCH_IMAGE" \
  --arg region "$AWS_REGION" \
  --arg account "$account" \
  '.containerDefinitions[0].image = $image
   | .containerDefinitions[0].logConfiguration.options["awslogs-region"] = $region
   | .taskRoleArn |= sub("ACCOUNT_ID"; $account)
   | .executionRoleArn |= sub("ACCOUNT_ID"; $account)' \
  infra/bench/task-definition.json > target/bench-task-definition.json
task_definition=$(aws ecs register-task-definition \
  --cli-input-json file://target/bench-task-definition.json \
  --query 'taskDefinition.taskDefinitionArn' --output text)
echo "Registered $task_definition"

vpc_id=$(aws ec2 describe-vpcs \
  --filters Name=is-default,Values=true \
  --query 'Vpcs[0].VpcId' --output text)
if [[ -z "$vpc_id" || "$vpc_id" == None ]]; then
  echo "AWS account has no default VPC in $AWS_REGION" >&2
  exit 1
fi
subnets=$(aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=$vpc_id" Name=default-for-az,Values=true \
  --query 'Subnets[].SubnetId' --output text | tr '\t' ',')
security_group=$(aws ec2 describe-security-groups \
  --filters "Name=vpc-id,Values=$vpc_id" Name=group-name,Values=default \
  --query 'SecurityGroups[0].GroupId' --output text)

task_arn=$(aws ecs run-task \
  --cluster "$cluster" \
  --task-definition "$task_definition" \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[$subnets],securityGroups=[$security_group],assignPublicIp=ENABLED}" \
  --overrides "$(jq -cn --arg sha "$BENCH_GIT_SHA" \
    '{containerOverrides:[{name:"bench",environment:[{name:"BENCH_GIT_SHA",value:$sha}]}]}')" \
  --query 'tasks[0].taskArn' --output text)
if [[ -z "$task_arn" || "$task_arn" == None ]]; then
  echo "ECS did not return a task ARN" >&2
  exit 1
fi
echo "Started $task_arn"

if ! wait_for_stopped "$task_arn" 2700 15; then
  echo "Fargate benchmark exceeded 45 minutes" >&2
  exit 1
fi

# The stream name is <prefix>/<container>/<task id>; both fixed parts come
# from infra/bench/task-definition.json.
log_stream="run/bench/${task_arn##*/}"
mkdir -p "$(dirname "$output")"

retrieve_log() {
  local next_token= new_token
  local page=target/bench-fargate-page.json
  local -a args
  : > target/bench-fargate.log
  while true; do
    args=(--log-group-name "$log_group" --log-stream-name "$log_stream"
          --start-from-head --no-paginate --output json)
    [[ -n "$next_token" ]] && args+=(--next-token "$next_token")
    aws logs get-log-events "${args[@]}" > "$page" || return 1
    jq -r '.events[].message' "$page" >> target/bench-fargate.log
    new_token=$(jq -r '.nextForwardToken' "$page")
    [[ "$new_token" == "$next_token" ]] && return 0
    next_token=$new_token
  done
}

# Log delivery lags task exit by a few seconds.
for _ in {1..12}; do
  if retrieve_log 2>/dev/null && grep -q 'MINIP2P_BENCH_RESULTS=' target/bench-fargate.log; then
    break
  fi
  sleep 5
done

exit_code=$(aws ecs describe-tasks \
  --cluster "$cluster" --tasks "$task_arn" \
  --query 'tasks[0].containers[0].exitCode' --output text)
if [[ "$exit_code" != 0 ]]; then
  cat target/bench-fargate.log >&2
  echo "Fargate benchmark exited with code $exit_code" >&2
  exit 1
fi

encoded=$(sed -n 's/^MINIP2P_BENCH_RESULTS=//p' target/bench-fargate.log | head -n1)
if [[ -z "$encoded" ]]; then
  echo "benchmark result marker missing from CloudWatch logs" >&2
  exit 1
fi
printf '%s' "$encoded" | base64 -d > "$output"
