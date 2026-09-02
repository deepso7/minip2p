#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

cluster=$BENCH_CLUSTER

stop_running_tasks() {
  local cluster_status tasks task_arn
  local -a task_arns=()

  cluster_status=$(aws ecs describe-clusters \
    --clusters "$cluster" \
    --query 'clusters[0].status' \
    --output text) || return
  if [[ "$cluster_status" == ACTIVE ]]; then
    tasks=$(aws ecs list-tasks \
      --cluster "$cluster" \
      --desired-status RUNNING \
      --query 'taskArns[]' \
      --output text) || return
    if [[ -n "$tasks" && "$tasks" != None ]]; then
      read -r -a task_arns <<< "$tasks"
    fi
    for task_arn in "${task_arns[@]}"; do
      aws ecs stop-task \
        --cluster "$cluster" \
        --task "$task_arn" \
        --reason "Stack cleanup" >/dev/null || return
    done
    if (( ${#task_arns[@]} > 0 )); then
      aws ecs wait tasks-stopped --cluster "$cluster" --tasks "${task_arns[@]}" || return
    fi
  fi
}

if ! stop_running_tasks; then
  echo "ECS task cleanup did not finish; continuing with stack destruction" >&2
fi

exec alchemy destroy --stage "$BENCH_STAGE" --yes
