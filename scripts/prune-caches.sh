#!/usr/bin/env bash
set -euo pipefail

repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
ref="${PRUNE_CACHE_REF:-refs/heads/main}"
keep="${PRUNE_CACHE_KEEP:-2}"

caches_json="$(gh api --paginate "repos/$repo/actions/caches?ref=$ref&per_page=100" --jq '.actions_caches')"

mapfile -t ids_to_delete < <(
  jq -sr --argjson keep "$keep" '
    def cache_group:
      if startswith("v0-rust-") then
        capture("^(?<prefix>v0-rust-.+-(?:Linux|Darwin|macOS|Windows_NT)-(?:x64|arm64))-[0-9a-f]{8}-[0-9a-f]{8}$").prefix // .
      elif startswith("ubrn-") or startswith("pnpm-") or startswith("playwright-") then
        capture("^(?<prefix>[^-]+-[^-]+-[^-]+)-").prefix // .
      elif startswith("gradle-") then
        capture("^(?<prefix>gradle-[^-]+)-").prefix // .
      else
        .
      end;

    add
    | group_by(.key | cache_group)
    | map(sort_by(.last_accessed_at // .created_at) | reverse | .[$keep:][])
    | .[].id
  ' <<<"$caches_json"
)

if [[ ${#ids_to_delete[@]} -eq 0 ]]; then
  echo "no superseded caches to prune on $ref"
  exit 0
fi

for id in "${ids_to_delete[@]}"; do
  gh api --method DELETE "repos/$repo/actions/caches/$id" >/dev/null || true
done
echo "pruned ${#ids_to_delete[@]} superseded cache entries on $ref"
