#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

repository=$(git rev-parse --show-toplevel)
source_repository=${BENCH_SOURCE_DIR:-$repository}
context="$repository/infra/bench/.alchemy/docker-context"

# Alchemy hashes the raw context before Docker applies .dockerignore. Copy only
# tracked files so local build outputs and reference checkouts never enter that
# hash or exhaust the deploy runner's memory.
mkdir -p "$context"
find "$context" -mindepth 1 -delete
git -C "$source_repository" ls-files -z \
  | tar --directory "$source_repository" --null --create --files-from=- \
  | tar --extract --directory "$context"

export BENCH_DOCKER_CONTEXT="$context"
exec alchemy deploy --stage "$BENCH_STAGE" --yes
