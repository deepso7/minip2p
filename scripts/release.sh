#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/release.sh <version> [--full-local]

Prepare, publish, and verify a minip2p release.

By default, the script runs fast local release checks and relies on the
push-triggered GitHub workflows for the full test matrix. Pass --full-local to
also run test, clippy, and no_std checks before committing.

The command is resumable. Running it again with the same version reuses an
existing release commit, GitHub release, and successful workflow runs.

Environment:
  RELEASE_POLL_SECONDS     Poll interval in seconds (default: 15)
  RELEASE_TIMEOUT_SECONDS Maximum wait per workflow phase (default: 7200)
EOF
}

die() {
  echo "release: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

version="${1:-}"
[[ -n "$version" ]] || {
  usage
  exit 2
}
if [[ "$version" == "-h" || "$version" == "--help" ]]; then
  usage
  exit 0
fi
shift

full_local=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --full-local)
      full_local=true
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
  shift
done

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must look like 0.3.2"

for command in cargo curl gh git jq just perl pnpm rg; do
  require_command "$command"
done

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

poll_seconds="${RELEASE_POLL_SECONDS:-15}"
timeout_seconds="${RELEASE_TIMEOUT_SECONDS:-7200}"
[[ "$poll_seconds" =~ ^[1-9][0-9]*$ ]] || die "RELEASE_POLL_SECONDS must be a positive integer"
[[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || die "RELEASE_TIMEOUT_SECONDS must be a positive integer"

tag="v$version"
branch="$(git branch --show-current)"
[[ "$branch" == "main" ]] || die "releases must be run from main (currently $branch)"
[[ -z "$(git status --porcelain)" ]] || die "the worktree must be clean"

gh auth status >/dev/null
git fetch origin main --tags

current_version="$(awk '
  /^\[workspace\.package\]$/ { workspace = 1; next }
  /^\[/ { workspace = 0 }
  workspace && /^version = / {
    sub(/^[^"]*"/, "", $0)
    sub(/".*$/, "", $0)
    print
    exit
  }
' Cargo.toml)"
[[ -n "$current_version" ]] || die "could not read workspace.package.version"

head_sha="$(git rev-parse HEAD)"
origin_sha="$(git rev-parse origin/main)"
if [[ "$current_version" == "$version" ]]; then
  echo "release: workspace is already prepared at $version"
  if [[ "$head_sha" != "$origin_sha" ]]; then
    git merge-base --is-ancestor origin/main HEAD || die "main has diverged from origin/main"
    echo "release: pushing the existing prepared commit"
    git push origin main
    git fetch origin main
    origin_sha="$(git rev-parse origin/main)"
    [[ "$head_sha" == "$origin_sha" ]] || die "origin/main did not advance to $head_sha"
  fi
else
  [[ "$head_sha" == "$origin_sha" ]] || die "main must match origin/main before preparing a release"
  perl -Mversion -e 'exit(version->parse($ARGV[1]) > version->parse($ARGV[0]) ? 0 : 1)' \
    "$current_version" "$version" || die "$version must be newer than $current_version"
  if git show-ref --verify --quiet "refs/tags/$tag" ||
    git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then
    die "tag $tag already exists but the workspace is at $current_version"
  fi

  echo "release: bumping $current_version to $version"

  cargo_manifests=(
    Cargo.toml
    crates/*/Cargo.toml
    transports/*/Cargo.toml
    examples/*/Cargo.toml
    docs/snippets/*/Cargo.toml
    fuzz/Cargo.toml
  )
  perl -pi -e "if (/minip2p|^version = \"\\Q$current_version\\E\"/) { s/\\Q$current_version\\E/$version/g }" \
    "${cargo_manifests[@]}"

  documentation_files=()
  while IFS= read -r file; do
    documentation_files+=("$file")
  done < <(rg -l "minip2p-rs[^[:alnum:]]|version = \"$current_version\"" README.md docs \
    --glob '*.md' --glob '*.mdx' --glob 'Cargo.toml')
  if [[ ${#documentation_files[@]} -gt 0 ]]; then
    perl -pi -e "s/\\Q$current_version\\E/$version/g" "${documentation_files[@]}"
  fi

  perl -pi -e "s/\"version\": \"\\Q$current_version\\E\"/\"version\": \"$version\"/" \
    bindings/ts/core/package.json \
    bindings/ts/react-native/package.json \
    bindings/ts/node/npm/*/package.json
  perl -pi -e "s/\\Q$current_version\\E/$version/g" bindings/ts/node/package.json

  echo "release: regenerating lockfiles"
  cargo metadata --format-version 1 >/dev/null
  cargo metadata --manifest-path fuzz/Cargo.toml --format-version 1 >/dev/null
  pnpm --dir bindings/ts install --lockfile-only --ignore-scripts

  echo "release: validating release metadata"
  metadata="$(cargo metadata --no-deps --format-version 1)"
  metadata_version="$(jq -r '.packages[] | select(.name == "minip2p-rs") | .version' <<<"$metadata")"
  [[ "$metadata_version" == "$version" ]] || die "minip2p-rs is $metadata_version, expected $version"

  mismatched_versions="$(jq -r --arg version "$version" '
    .packages[]
    | select(
        (.name == "minip2p-rs" or (.name | startswith("minip2p-")))
        and .publish != []
        and .version != $version
      )
    | "\(.name) is \(.version), expected \($version)"
  ' <<<"$metadata")"
  [[ -z "$mismatched_versions" ]] || die "published package versions do not match:
$mismatched_versions"

  mismatched_dependencies="$(jq -r --arg requirement "^$version" '
    .packages[]
    | select(.publish != [])
    | .name as $package
    | .dependencies[]
    | select(
        .source == null
        and .kind != "dev"
        and (.name | startswith("minip2p"))
        and .req != $requirement
      )
    | "\($package) -> \(.name) uses \(.req), expected \($requirement)"
  ' <<<"$metadata")"
  [[ -z "$mismatched_dependencies" ]] || die "local dependency versions do not match:
$mismatched_dependencies"

  [[ "$(jq -r .version bindings/ts/core/package.json)" == "$version" ]] ||
    die "@minip2p/core version does not match"
  [[ "$(jq -r .version bindings/ts/react-native/package.json)" == "$version" ]] ||
    die "@minip2p/react-native version does not match"
  [[ "$(jq -r .version bindings/ts/node/package.json)" == "$version" ]] ||
    die "@minip2p/node version does not match"
  for manifest in bindings/ts/node/npm/*/package.json; do
    [[ "$(jq -r .version "$manifest")" == "$version" ]] ||
      die "$(jq -r .name "$manifest") version does not match"
  done
  [[ "$(jq --arg version "$version" '[.optionalDependencies | to_entries[] | select((.key | startswith("@minip2p/node-")) and .value == $version)] | length' bindings/ts/node/package.json)" == 7 ]] ||
    die "@minip2p/node platform dependencies do not match"

  just fmt
  git diff --check

  if [[ "$full_local" == true ]]; then
    echo "release: running the full local CI suite"
    just test
    just clippy
    just check-nostd
  else
    echo "release: skipping duplicate full local CI (use --full-local to enable it)"
  fi

  [[ -n "$(git status --porcelain)" ]] || die "version bump produced no changes"
  git add -u
  git diff --cached --check
  git commit -m "chore: prepare $tag release"
  git push origin main
  head_sha="$(git rev-parse HEAD)"
fi

wait_for_push_workflows() {
  local sha="$1"
  local started now elapsed runs summary workflow row run_status conclusion url
  local all_success
  local workflows=("CI" "TypeScript bindings")
  started="$(date +%s)"

  echo "release: waiting for push workflows on ${sha:0:8}"
  while true; do
    runs="$(gh run list --commit "$sha" --limit 20 \
      --json databaseId,name,status,conclusion,url,headSha)"
    all_success=true
    summary=""

    for workflow in "${workflows[@]}"; do
      row="$(jq -r --arg workflow "$workflow" --arg sha "$sha" '
        [.[] | select(.name == $workflow and .headSha == $sha)][0]
        | if . == null then "missing\t\t" else "\(.status)\t\(.conclusion // "")\t\(.url)" end
      ' <<<"$runs")"
      IFS=$'\t' read -r run_status conclusion url <<<"$row"
      summary="$summary $workflow=$run_status${conclusion:+/$conclusion}"

      if [[ "$run_status" == "completed" && "$conclusion" != "success" ]]; then
        die "$workflow failed: $url"
      fi
      [[ "$run_status" == "completed" && "$conclusion" == "success" ]] || all_success=false
    done

    echo "release:${summary}"
    [[ "$all_success" == true ]] && break

    now="$(date +%s)"
    elapsed=$((now - started))
    (( elapsed < timeout_seconds )) || die "timed out waiting for push workflows"
    sleep "$poll_seconds"
  done
}

wait_for_run() {
  local run_id="$1"
  local label="$2"
  local started now elapsed run_json run_status conclusion jobs url
  started="$(date +%s)"

  while true; do
    run_json="$(gh run view "$run_id" --json status,conclusion,jobs,url)"
    run_status="$(jq -r .status <<<"$run_json")"
    conclusion="$(jq -r '.conclusion // ""' <<<"$run_json")"
    url="$(jq -r .url <<<"$run_json")"
    jobs="$(jq -r '[.jobs[] | "\(.name)=\(.status)\(if .conclusion then "/" + .conclusion else "" end)"] | join(", ")' <<<"$run_json")"
    echo "release: $label=$run_status${conclusion:+/$conclusion}: $jobs"

    if [[ "$run_status" == "completed" ]]; then
      [[ "$conclusion" == "success" ]] || die "$label failed: $url"
      break
    fi

    now="$(date +%s)"
    elapsed=$((now - started))
    (( elapsed < timeout_seconds )) || die "timed out waiting for $label: $url"
    sleep "$poll_seconds"
  done
}

wait_for_push_workflows "$head_sha"

release_url=""
if release_json="$(gh release view "$tag" --json targetCommitish,isDraft,isPrerelease,url 2>/dev/null)"; then
  release_target="$(jq -r .targetCommitish <<<"$release_json")"
  [[ "$release_target" == "$head_sha" ]] || die "$tag targets $release_target, expected $head_sha"
  [[ "$(jq -r .isDraft <<<"$release_json")" == false ]] || die "$tag is still a draft"
  [[ "$(jq -r .isPrerelease <<<"$release_json")" == false ]] || die "$tag is a prerelease"
  release_url="$(jq -r .url <<<"$release_json")"
  echo "release: reusing $release_url"
else
  echo "release: publishing GitHub release $tag"
  if git show-ref --verify --quiet "refs/tags/$tag" ||
    git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then
    git fetch origin "refs/tags/$tag:refs/tags/$tag"
    [[ "$(git rev-parse "refs/tags/$tag^{}")" == "$head_sha" ]] ||
      die "$tag already exists at a different commit"
  fi
  release_url="$(gh release create "$tag" --target "$head_sha" --title "$tag" --generate-notes)"
fi

echo "release: locating publish workflow"
started="$(date +%s)"
publish_run_id=""
while [[ -z "$publish_run_id" ]]; do
  publish_runs="$(gh run list --workflow publish.yml --limit 20 \
    --json databaseId,headBranch,headSha,status,conclusion,url)"
  publish_run_id="$(jq -r --arg sha "$head_sha" --arg tag "$tag" '
    [.[] | select(.headSha == $sha and .headBranch == $tag)][0].databaseId // empty
  ' <<<"$publish_runs")"
  [[ -n "$publish_run_id" ]] && break

  now="$(date +%s)"
  elapsed=$((now - started))
  (( elapsed < timeout_seconds )) || die "timed out waiting for the publish workflow"
  sleep "$poll_seconds"
done

wait_for_run "$publish_run_id" "publish workflow"

echo "release: verifying relay-server assets"
release_assets="$(gh release view "$tag" --json assets)"
expected_relay_assets=(
  "minip2p-relay-server-v$version-x86_64-unknown-linux-gnu.tar.gz"
  "minip2p-relay-server-v$version-aarch64-unknown-linux-gnu.tar.gz"
  SHA256SUMS
)
for asset in "${expected_relay_assets[@]}"; do
  jq -e --arg asset "$asset" \
    'any(.assets[]; .name == $asset and .size > 0)' \
    <<<"$release_assets" >/dev/null || die "missing or empty GitHub release asset: $asset"
done

verify_crate() {
  local crate="$1"
  local lower path attempt found
  lower="$(printf '%s' "$crate" | tr '[:upper:]' '[:lower:]')"
  path="${lower:0:2}/${lower:2:2}/$lower"

  for attempt in $(seq 1 30); do
    found="$(curl -fsSL "https://index.crates.io/$path" 2>/dev/null |
      jq -s --arg version "$version" 'any(.vers == $version and .yanked == false)' 2>/dev/null || true)"
    [[ "$found" == true ]] && return 0
    sleep 2
  done
  die "$crate $version is not visible in the crates.io index"
}

verify_npm_package() {
  local encoded_name="$1"
  local display_name="$2"
  local attempt found

  for attempt in $(seq 1 30); do
    found="$(curl -fsSL "https://registry.npmjs.org/$encoded_name/$version" 2>/dev/null |
      jq -r '.version // empty' 2>/dev/null || true)"
    [[ "$found" == "$version" ]] && return 0
    sleep 2
  done
  die "$display_name@$version is not visible on npm"
}

echo "release: verifying public registries"
metadata="$(cargo metadata --no-deps --format-version 1)"
publishable_crates=($(jq -r '
  .packages[]
  | select(
      (.name == "minip2p-rs" or (.name | startswith("minip2p-")))
      and .publish != []
    )
  | .name
' <<<"$metadata"))
for crate in "${publishable_crates[@]}"; do
  verify_crate "$crate"
done

verify_npm_package '%40minip2p%2Fcore' '@minip2p/core'
verify_npm_package '%40minip2p%2Freact-native' '@minip2p/react-native'
verify_npm_package '%40minip2p%2Fnode' '@minip2p/node'
for manifest in bindings/ts/node/npm/*/package.json; do
  package_name="$(jq -r .name "$manifest")"
  encoded_name="${package_name/@/%40}"
  encoded_name="${encoded_name/\//%2F}"
  verify_npm_package "$encoded_name" "$package_name"
done

git fetch origin main --tags
git merge-base --is-ancestor "$head_sha" origin/main ||
  die "the release commit is no longer an ancestor of origin/main"
[[ "$(git rev-parse "refs/tags/$tag^{}")" == "$head_sha" ]] || die "$tag does not target $head_sha"
[[ -z "$(git status --porcelain)" ]] || die "the worktree is dirty after the release"

echo
echo "release: $tag published and verified"
echo "release: commit $head_sha"
echo "release: GitHub $release_url"
echo "release: relay server ${#expected_relay_assets[@]}/${#expected_relay_assets[@]} assets"
echo "release: crates.io ${#publishable_crates[@]}/${#publishable_crates[@]} packages"
echo "release: npm @minip2p/core, @minip2p/react-native, @minip2p/node, and 7 platform packages at $version"
