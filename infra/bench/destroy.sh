#!/usr/bin/env bash
set -euo pipefail

repository=$(git rev-parse --show-toplevel)
stage=${BENCH_STAGE:-ci}
export BENCH_DOCKER_CONTEXT="$repository/infra/bench/.alchemy/docker-context"
exec alchemy destroy --stage "$stage" --yes
