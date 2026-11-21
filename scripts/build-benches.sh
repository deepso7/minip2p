#!/usr/bin/env bash
set -euo pipefail

mode="build"
only_csv=""

if [[ $# -gt 0 && "$1" != --* ]]; then
  mode="$1"
  shift
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --only)
      [[ $# -ge 2 ]] || { echo "usage: $0 [build|cook] [--only <csv>]" >&2; exit 2; }
      only_csv="$2"
      shift 2
      ;;
    *)
      echo "usage: $0 [build|cook] [--only <csv>]" >&2
      exit 2
      ;;
  esac
done

cd "$(dirname "$0")/.."

groups=$(awk -v only="$only_csv" '
BEGIN {
  if (only != "") {
    n_only = split(only, parts, ",")
    for (i = 1; i <= n_only; i++) want[parts[i]] = 1
  }
}
$1 !~ /^#/ && NF {
  if (only != "" && !($4 in want)) next
  key = $2 " " $3
  if (!(key in benches)) order[++n] = key
  benches[key] = benches[key] " --bench " $4
}
END { for (i = 1; i <= n; i++) print order[i] benches[order[i]] }' bench/targets)

[[ -n "$groups" ]] || exit 0

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
      echo "usage: $0 [build|cook] [--only <csv>]" >&2
      exit 2
      ;;
  esac
done 3<<< "$groups"
