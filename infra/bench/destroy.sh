#!/usr/bin/env bash
set -euo pipefail

stage=${BENCH_STAGE:-ci}
cluster=${BENCH_CLUSTER:-minip2p-bench}

cluster_status=$(aws ecs describe-clusters \
  --clusters "$cluster" \
  --query 'clusters[0].status' \
  --output text)
if [[ "$cluster_status" == ACTIVE ]]; then
  tasks=$(aws ecs list-tasks \
    --cluster "$cluster" \
    --desired-status RUNNING \
    --query 'taskArns[]' \
    --output text)
  task_arns=()
  if [[ -n "$tasks" && "$tasks" != None ]]; then
    read -r -a task_arns <<< "$tasks"
  fi
  for task_arn in "${task_arns[@]}"; do
    aws ecs stop-task \
      --cluster "$cluster" \
      --task "$task_arn" \
      --reason "Stack cleanup" >/dev/null
  done
  if (( ${#task_arns[@]} > 0 )); then
    aws ecs wait tasks-stopped --cluster "$cluster" --tasks "${task_arns[@]}"
  fi
fi

exec alchemy destroy --stage "$stage" --yes
