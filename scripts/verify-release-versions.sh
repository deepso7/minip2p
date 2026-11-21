#!/usr/bin/env bash
set -euo pipefail

event_name="${EVENT_NAME:-}"
input_release_tag="${INPUT_RELEASE_TAG:-}"
release_tag="${RELEASE_TAG:-}"

metadata="$(cargo metadata --no-deps --format-version 1)"
version="$(jq -r '.packages[] | select(.name == "minip2p-rs") | .version' <<<"$metadata")"

if [[ "$event_name" == "release" || -n "$input_release_tag" ]] &&
  [[ "$release_tag" != "v$version" ]]; then
  echo "::error::Release tag $release_tag does not match workspace version $version (expected v$version)" >&2
  exit 1
fi

mismatched_versions="$(
  jq -r --arg version "$version" '
    .packages[]
    | select(
        (.name == "minip2p-rs" or (.name | startswith("minip2p-")))
        and .publish != []
        and .version != $version
      )
    | "\(.name) is \(.version), expected \($version)"
  ' <<<"$metadata"
)"
if [[ -n "$mismatched_versions" ]]; then
  echo "::error::All published minip2p crates must use the same version:" >&2
  echo "$mismatched_versions" >&2
  exit 1
fi

mismatched_dependencies="$(
  jq -r --arg requirement "^$version" '
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
  ' <<<"$metadata"
)"
if [[ -n "$mismatched_dependencies" ]]; then
  echo "::error::Publishable local dependencies do not match workspace version:" >&2
  echo "$mismatched_dependencies" >&2
  exit 1
fi

core_version="$(jq -r '.version' bindings/ts/core/package.json)"
react_native_version="$(jq -r '.version' bindings/ts/react-native/package.json)"
node_version="$(jq -r '.version' bindings/ts/node/package.json)"
web_version="$(jq -r '.version' bindings/ts/web/package.json)"
if [[ "$core_version" != "$version" || "$react_native_version" != "$version" || "$node_version" != "$version" || "$web_version" != "$version" ]]; then
  echo "::error::Rust and public TypeScript packages must use $version; core=$core_version react-native=$react_native_version node=$node_version web=$web_version" >&2
  exit 1
fi

if [[ "$(jq -r '.private // false' bindings/ts/web/package.json)" == "true" ]]; then
  echo "::error::@minip2p/web must be public" >&2
  exit 1
fi
if [[ "$(jq -r '.private // false' bindings/ts/node/package.json)" == "true" ]]; then
  echo "::error::@minip2p/node must be public" >&2
  exit 1
fi

platform_errors="$({
  for manifest in bindings/ts/node-platforms/*/package.json; do
    jq -r --arg version "$version" '
      select(.version != $version or .publishConfig.access != "public")
      | "\(.name) is not public at \($version)"
    ' "$manifest"
  done
  jq -r '
    .optionalDependencies // {}
    | to_entries[]
    | select(.key | startswith("@minip2p/node-"))
    | select(.value != "workspace:*")
    | "\(.key) uses \(.value), expected workspace:*"
  ' bindings/ts/node/package.json
})"
if [[ -n "$platform_errors" ]] ||
  [[ "$(jq '[.optionalDependencies | to_entries[] | select(.key | startswith("@minip2p/node-"))] | length' bindings/ts/node/package.json)" != 7 ]]; then
  echo "::error::Node platform packages must be public and lockstep-versioned" >&2
  echo "$platform_errors" >&2
  exit 1
fi

if [[ "$(jq -r '.dependencies["@minip2p/core"]' bindings/ts/react-native/package.json)" != "workspace:*" ]]; then
  echo "::error::@minip2p/react-native must depend on @minip2p/core through workspace:*" >&2
  exit 1
fi

printf '%s\n' "$version"
