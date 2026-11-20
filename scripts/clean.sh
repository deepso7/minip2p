#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/clean.sh [--dry-run]

Remove generated artifacts from the minip2p repository: Cargo target
directories, node_modules, Turbo caches, docs output, native addons, and
other build products.

Prints a cargo-clean-style summary of files and bytes reclaimed.

Does not remove code-ref/, fuzz corpus, local identity keys, or editor
state.
EOF
}

dry_run=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      dry_run=true
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
  shift
done

root="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$root"

skip=(
  -path './.git' -o
  -path './code-ref' -o
  -path './.delta' -o
  -path './.repos' -o
  -path './.claude'
)

dir_names=(
  -name node_modules -o
  -name target -o
  -name .turbo -o
  -name __pycache__ -o
  -name .blume -o
  -name .blume-verify -o
  -name .expo -o
  -name .pnpm-store -o
  -name dist -o
  -name coverage -o
  -name artifacts -o
  -name nitrogen -o
  -name .cxx -o
  -name .gradle -o
  -name DerivedData
)

extras=(
  target-linux
  tmp
  bindings/ts/react-native/lib
  bindings/ts/react-native/build
  bindings/ts/react-native/android/build
  bindings/ts/react-native/android/app/libs
  bindings/ts/react-native/android/src/main/jniLibs
  bindings/ts/react-native/ios/build
  examples/react-native/android
  examples/react-native/ios
  examples/react-native/web-build
  docs/snippets/quickstart/Cargo.lock
  docs/snippets/custom-stream/Cargo.lock
)

paths=()

consider() {
  local path="$1"
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    return 0
  fi
  paths+=("$path")
}

while IFS= read -r -d '' path; do
  consider "${path#./}"
done < <(find . \( "${skip[@]}" \) -prune -o -type d \( "${dir_names[@]}" \) -prune -print0)

for path in "${extras[@]}"; do
  consider "$path"
done

while IFS= read -r -d '' path; do
  consider "${path#./}"
done < <(
  find . \( "${skip[@]}" \) -prune -o \
    -type d \( -name node_modules -o -name target \) -prune -o \
    -type f -name '*.node' -print0
)

if [[ ${#paths[@]} -eq 0 ]]; then
  echo "nothing to clean"
  exit 0
fi

in_array() {
  local candidate="$1"
  shift
  local existing
  for existing in "$@"; do
    if [[ "$candidate" == "$existing" ]]; then
      return 0
    fi
  done
  return 1
}

unique=()
for path in "${paths[@]}"; do
  if in_array "$path" "${unique[@]+"${unique[@]}"}"; then
    continue
  fi
  unique+=("$path")
done

kept=()
for path in "${unique[@]}"; do
  nested=false
  for other in "${unique[@]}"; do
    if [[ "$path" == "$other"/* ]]; then
      nested=true
      break
    fi
  done
  if $nested; then
    continue
  fi
  kept+=("$path")
done

in_repo() {
  local path="$1"
  local abs parent
  case "$path" in
    /* | .. | ../* | */.. | */../*)
      return 1
      ;;
  esac
  if [[ -d "$path" ]]; then
    abs="$(cd "$path" && pwd -P)" || return 1
  else
    parent="$(cd "$(dirname "$path")" && pwd -P)" || return 1
    abs="$parent/$(basename "$path")"
  fi
  case "$abs" in
    "$root" | "$root"/*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

human_kib() {
  awk -v k="$1" 'BEGIN {
    b = k * 1024
    if (b < 1024) { printf "%.1fB", b; exit }
    b /= 1024
    if (b < 1024) { printf "%.1fKiB", b; exit }
    b /= 1024
    if (b < 1024) { printf "%.1fMiB", b; exit }
    b /= 1024
    if (b < 1024) { printf "%.1fGiB", b; exit }
    b /= 1024
    printf "%.1fTiB", b
  }'
}

summary_phrase() {
  local files="$1"
  local dirs="$2"
  if [[ "$files" -eq 0 && "$dirs" -eq 1 ]]; then
    echo "1 directory"
  elif [[ "$files" -eq 0 ]]; then
    echo "$dirs directories"
  elif [[ "$files" -eq 1 ]]; then
    echo "1 file"
  else
    echo "$files files"
  fi
}

total_kib=0
total_files=0
removed=0

for path in "${kept[@]}"; do
  if ! in_repo "$path"; then
    echo "skipping $path (outside repository)" >&2
    continue
  fi
  kib=$(du -sk "$path" 2>/dev/null | awk '{print $1}')
  kib=${kib:-0}
  files=$(find "$path" -type f -print | wc -l | tr -d ' ')
  files=${files:-0}
  if $dry_run; then
    if [[ "$kib" -gt 0 ]]; then
      echo "would remove $path ($(human_kib "$kib"))"
    else
      echo "would remove $path"
    fi
  else
    if [[ "$kib" -gt 0 ]]; then
      echo "removing $path ($(human_kib "$kib"))"
    else
      echo "removing $path"
    fi
    rm -rf "$path"
  fi
  total_kib=$((total_kib + kib))
  total_files=$((total_files + files))
  removed=$((removed + 1))
done

total=$(human_kib "$total_kib")
phrase=$(summary_phrase "$total_files" "$removed")
if $dry_run; then
  echo "Summary $phrase, $total total"
else
  echo "Removed $phrase, $total total"
fi

