#!/usr/bin/env bash
set -euo pipefail

repository=$(git rev-parse --show-toplevel)
context="$repository/infra/bench/.alchemy/docker-context"

# Alchemy hashes the raw context before Docker applies .dockerignore. Copy only
# tracked files so local build outputs and reference checkouts never enter that
# hash or exhaust the deploy runner's memory.
mkdir -p "$context"
find "$context" -mindepth 1 -delete
git -C "$repository" ls-files -z \
  | tar --directory "$repository" --null --create --files-from=- \
  | tar --extract --directory "$context"

export BENCH_DOCKER_CONTEXT="$context"
exec alchemy deploy --stage ci --yes
