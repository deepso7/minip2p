#!/usr/bin/env bash
set -euo pipefail

mode=${1:-build}
cd "$(dirname "$0")/.."

groups=$(awk '$1 !~ /^#/ && NF {
  key = $2 " " $3
  if (!(key in benches)) order[++n] = key
  benches[key] = benches[key] " --bench " $4
} END { for (i = 1; i <= n; i++) print order[i] benches[order[i]] }' bench/targets)

while read -r -u 3 package features targets; do
  args=(--package "$package")
  [[ "$features" == - ]] || args+=(--features "$features")
  case $mode in
    build)
      # shellcheck disable=SC2086 # word-split the --bench flags
      cargo bench "${args[@]}" $targets --no-run
      ;;
    cook)
      cargo chef cook --release "${args[@]}" --benches --recipe-path recipe.json
      ;;
    *)
      echo "usage: $0 [cook]" >&2
      exit 2
      ;;
  esac
done 3<<< "$groups"
