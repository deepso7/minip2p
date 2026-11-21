#!/usr/bin/env bash
set -euo pipefail

crate_version="${1:-${CRATE_VERSION:-}}"
if [[ -z "$crate_version" ]]; then
  echo "usage: $0 <version>" >&2
  exit 2
fi

crate_http_code() {
  curl \
    --silent \
    --output /dev/null \
    --write-out '%{http_code}' \
    --connect-timeout 10 \
    --max-time 30 \
    --retry 2 \
    --user-agent 'minip2p-release-workflow (https://github.com/deepso7/minip2p)' \
    "https://crates.io/api/v1/crates/$1/$crate_version"
}

order="$(scripts/publish-order.py)"
mapfile -t crates <<<"$order"

for crate in "${crates[@]}"; do
  status="$(crate_http_code "$crate")"

  if [[ "$status" == "200" ]]; then
    echo "$crate $crate_version is already published; skipping"
    continue
  fi
  if [[ "$status" != "404" ]]; then
    echo "::error::crates.io returned HTTP $status while checking $crate $crate_version" >&2
    exit 1
  fi

  for attempt in {1..6}; do
    if cargo publish --package "$crate"; then
      break
    fi

    delay=$((attempt * 10))
    echo "Publish attempt $attempt for $crate failed; checking the registry in ${delay}s"
    sleep "$delay"

    status="$(crate_http_code "$crate")"
    if [[ "$status" == "200" ]]; then
      echo "$crate $crate_version reached crates.io despite the publish error; continuing"
      break
    fi
    if [[ "$status" != "404" ]]; then
      echo "::error::crates.io returned HTTP $status while checking $crate $crate_version" >&2
      exit 1
    fi
    if [[ "$attempt" == 6 ]]; then
      echo "::error::Failed to publish $crate after $attempt attempts" >&2
      exit 1
    fi

    echo "$crate $crate_version is not visible yet; retrying publication"
  done
done
