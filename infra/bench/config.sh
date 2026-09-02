#!/usr/bin/env bash

BENCH_STAGE=${BENCH_STAGE:-ci}
BENCH_CLUSTER=${BENCH_CLUSTER:-minip2p-bench}
BENCH_TASK_FAMILY=${BENCH_TASK_FAMILY:-minip2p-bench}
BENCH_TASK_ARN_FILE=${BENCH_TASK_ARN_FILE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/target/bench-fargate-task-arn}
export BENCH_STAGE BENCH_CLUSTER BENCH_TASK_FAMILY BENCH_TASK_ARN_FILE
