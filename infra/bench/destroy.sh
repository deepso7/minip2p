#!/usr/bin/env bash
set -euo pipefail

stage=${BENCH_STAGE:-ci}
exec alchemy destroy --stage "$stage" --yes
