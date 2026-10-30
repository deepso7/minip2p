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

# "<package> <features>" -> its bench targets, in first-seen order.
declare -A benches=()
order=()
while read -r pass package features bench _; do
  [[ -z "$pass" || "$pass" == \#* ]] && continue
  key="$package $features"
  [[ -v "benches[$key]" ]] || order+=("$key")
  benches[$key]+=" --bench $bench"
done < bench/targets

for key in "${order[@]}"; do
  read -r package features <<< "$key"
  args=(--package "$package")
  [[ "$features" == - ]] || args+=(--features "$features")
  case $mode in
    build)
      # shellcheck disable=SC2086 # word-split the --bench flags
      cargo bench "${args[@]}" ${benches[$key]} --no-run
      ;;
    cook)
      cargo chef cook --release "${args[@]}" --benches --recipe-path recipe.json
      ;;
    *)
      echo "usage: $0 [cook]" >&2
      exit 2
      ;;
  esac
done
