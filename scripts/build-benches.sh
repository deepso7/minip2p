#!/usr/bin/env bash
# Compile every benchmark in bench/targets without running it, one cargo call
# per package and feature set, as the bench image and CI's bench-build job do.
#
#   scripts/build-benches.sh        cargo bench --no-run
#   scripts/build-benches.sh cook   cargo chef cook the same package and
#                                   feature sets' dependencies (bench image)
set -euo pipefail

mode=${1:-build}
cd "$(dirname "$0")/.."

# One "<package> <features> --bench <target>..." line per package and feature
# set, in first-seen order. awk rather than an associative array keeps this
# working on macOS's Bash 3.2. The groups are read on fd 3 so cargo can never
# consume them from stdin.
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
