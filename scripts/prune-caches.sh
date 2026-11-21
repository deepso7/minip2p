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

deleted=0
failed=0
for id in "${ids_to_delete[@]}"; do
  if err="$(gh api --method DELETE "repos/$repo/actions/caches/$id" 2>&1 >/dev/null)"; then
    deleted=$((deleted + 1))
  elif [[ "$err" == *"HTTP 404"* ]]; then
    echo "cache $id already evicted; skipping"
  else
    echo "failed to delete cache $id: $err" >&2
    failed=$((failed + 1))
  fi
done
echo "pruned $deleted superseded cache entries on $ref"
if [[ "$failed" -gt 0 ]]; then
  echo "$failed cache deletions failed on $ref" >&2
  exit 1
fi
