#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

cluster=$BENCH_CLUSTER

stop_running_tasks() {
  local cluster_status tasks task_arn task_status tracked_task
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
    if [[ -s "$BENCH_TASK_ARN_FILE" ]]; then
      tracked_task=$(<"$BENCH_TASK_ARN_FILE")
      if [[ ! " ${task_arns[*]} " =~ [[:space:]]${tracked_task}[[:space:]] ]]; then
        task_arns+=("$tracked_task")
      fi
    fi
    for task_arn in "${task_arns[@]}"; do
      task_status=$(aws ecs describe-tasks \
        --cluster "$cluster" \
        --tasks "$task_arn" \
        --query 'tasks[0].lastStatus' \
        --output text) || return
      if [[ "$task_status" == STOPPED ]]; then
        continue
      fi
      aws ecs stop-task \
        --cluster "$cluster" \
        --task "$task_arn" \
        --reason "Stack cleanup" >/dev/null || return
    done
    if (( ${#task_arns[@]} > 0 )); then
      aws ecs wait tasks-stopped --cluster "$cluster" --tasks "${task_arns[@]}" || return
    fi
  fi
  rm -f "$BENCH_TASK_ARN_FILE"
}

for attempt in 1 2 3; do
  if stop_running_tasks; then
    exec alchemy destroy --stage "$BENCH_STAGE" --yes
  fi
  echo "ECS task cleanup attempt $attempt failed" >&2
done

echo "ECS tasks are not confirmed stopped; refusing to destroy the stack" >&2
exit 1
