#!/usr/bin/env sh
set -eu

# Maintainer-only helper. Normal tests consume noise-c-basic-xx.txt and do not
# download or build the producer. The upstream revision is deliberately pinned.
revision=5d0a74760320e5486ced302e36ccad91606aac43
url="https://raw.githubusercontent.com/rweather/noise-c/${revision}/tests/vector/noise-c-basic.txt"

curl -fsSL "$url" \
  | jq '.vectors[] | select(.name == "Noise_XX_25519_ChaChaPoly_SHA256")'
