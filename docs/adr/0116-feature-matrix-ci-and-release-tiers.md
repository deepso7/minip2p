# Feature-matrix rows are split into `ci` and `release` test tiers

Each row in `scripts/run-feature-matrix.sh` has a test tier. PRs and pushes to `main` test only the `ci` rows; CI lints every row (`full`), and releases test every row. The `ci` rows plus the workspace run already list every test the full matrix does (1,975 distinct package/binary/test identities at the time), so the `release` rows only re-run those tests under other feature combinations. The trade-off: a bug that needs one of those combinations at runtime is caught at release time, not on the PR.
