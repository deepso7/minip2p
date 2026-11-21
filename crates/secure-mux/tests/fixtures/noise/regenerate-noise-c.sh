#!/usr/bin/env sh
set -eu

revision=5d0a74760320e5486ced302e36ccad91606aac43
url="https://raw.githubusercontent.com/rweather/noise-c/${revision}/tests/vector/noise-c-basic.txt"

curl -fsSL "$url" \
  | jq '.vectors[] | select(.name == "Noise_XX_25519_ChaChaPoly_SHA256")'
