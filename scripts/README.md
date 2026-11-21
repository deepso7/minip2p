# scripts

Each script prints its usage when called without valid arguments; the environment and subcommands it does not print are below. The `justfile` and the workflows in `.github/workflows/` call most of them; run them from the repo root.

## Local dev and CI

| Script | Used by | What it does |
| --- | --- | --- |
| `affected.py` | `ci.yml` (`plan`) | Computes diff-reachable crates, matrix rows, benches, fuzz, docs, and TS binding checks. |
| `test_affected.py` | `ci.yml` (`checks`) | Unit tests for `affected.py`, including cross-checks against `cargo tree`. |
| `run-feature-matrix.sh` | `just check`, `just clippy`, `just test`, `just matrix`, `ci.yml`, `publish.yml` | Runs `check`, `clippy` or `test` over named feature-matrix rows (`ci`, `full`, `<row>`, `--rows <csv>`, optional `--shard i/n`; `list` prints them). |
| `check-targets.sh` | `just check-nostd`, `check-wasm`, `docs`, `package-check`, `ci.yml`, `publish.yml` | The no_std, wasm32, rustdoc and package lists. |
| `publish-order.py` | `check-targets.sh package-check`, `publish-crates.sh` | Prints the publishable crates in dependency order. |
| `prune-caches.sh` | `ci.yml` (`prune-caches` on `main`) | Deletes superseded GitHub Actions caches per key group to stay under the 10 GiB cap. |
| `clean.sh` | `just clean`, `pnpm clean:all` | Removes build outputs, `node_modules`, Turbo caches and docs output. |

`check-targets.sh` subcommands:

- `nostd`: every `no_std` crate, and the Endpoint's portable feature sets, on a real `no_std` target (`thumbv7em-none-eabi`).
- `wasm`: the browser build's crates on `wasm32-unknown-unknown`.
- `docs`: rustdoc, with `-D warnings` where the docs are kept clean.
- `package-check [--allow-dirty]`: every published crate ships its README, and the publish order resolves.

## Benchmarks

| Script | Used by | What it does |
| --- | --- | --- |
| `run-benches.sh` | `just bench`, `just bench-ir`, `run-container-benches.sh` | Runs one pass of `bench/targets` and collects its result documents. |
| `build-benches.sh` | `just bench-build`, CI, `infra/bench/Dockerfile` | Builds the benches listed in `bench/targets` without running them. |
| `check-bench-ids.py` | `just bench-build`, CI | Checks the IR bench ids against `bench_results.py`. |
| `bench_results.py` | `run-benches.sh`, `run-container-benches.sh`, the Node package's `bench` script, `bench.yml`, `check-bench-ids.py`, `bench/test_bench_results.py` | Normalizes results and compares a head run with its base. |
| `run-bench-container.sh` | `bench.yml` | Builds the bench image and runs the suite on this host. |
| `run-container-benches.sh` | `run-bench-container.sh` | Runs one pass inside the bench container. |
| `start-bench-runner.sh` | `bench.yml` | Wakes the on-demand EC2 bench instance (ADR 0025). |
| `rtt-sweep.sh` | `run-container-benches.sh` (entry point: `bench.yml`'s sweep input) | Runs the `endpoint_rtt` window sweeps over an emulated link. |

`run-bench-container.sh` runs from the trusted checkout's root and writes the result document (or a sweep's `rtt/` tree) and the container log to `target/bench-artifacts/`. Its environment:

- `BENCH_GIT_SHA` (required): the measured commit.
- `BENCH_CONTEXT`: the build context holding the measured code (default `.`).
- `BENCH_BASE_CONTEXT`, with `BENCH_BASE_GIT_SHA`: a base tree to measure alongside it. The result is then `base.json` and `head.json` instead of `current.json`, and both sides run with `MINIP2P_BENCH_QUICK=1` (ADR 0026).
- `BENCH_SWEEP`: `rtt-sweep.sh` sweep names, space-separated, or `all`, to run instead of the benchmarks; one tree only.
- `BENCH_RUN_ID`: names the images, containers and work directory (default: the GitHub run ID and attempt, or `local-<time>`).

`run-container-benches.sh` takes one pass: `ir`, `wall` or `node` runs that tier, `results` merges the tiers and prints the result document as a base64 `MINIP2P_BENCH_RESULTS=` line, and `sweep` runs `rtt-sweep.sh` and prints its logs as a `MINIP2P_SWEEP_RESULTS=` line. `build-benches.sh cook` cooks the same package and feature sets' dependencies with `cargo chef` (the bench image's dependency layer).

`rtt-sweep.sh` runs the sweeps in order, feeding each pick into the next: `quic-stream` picks S\*; `quic-connection` at S\* picks C\*; `quic-send` at S\* picks W\*; `quic-check` at (S\*, C\*, W\*); `yamux`; `retry`; then `secondary`, which runs `quic-check` and `yamux` on the `1g_20ms` profile and is recorded only. `yamux-check` is not in the default order: pass it by name to measure 256 KiB, 1,216 KiB and `TcpConfig::std_default()` against a large window, with loaded ping, on each profile in `MINIP2P_RTT_CHECK_PROFILES` (default `10m_20ms 100m_10ms 100m_100ms 1g_20ms 1g_1ms`). Logs and JSON lines land in `target/bench-results/rtt/`. Pass sweep names to run only those; the picks then come from `MINIP2P_RTT_STREAM`, `MINIP2P_RTT_CONNECTION` and `MINIP2P_RTT_SEND`. `MINIP2P_RTT_RUNS` sets the runs per point (default 5), and `MINIP2P_RTT_PROFILE` the profile the picks come from (default `100m_100ms`; any `<rate>m_<rtt>ms`, such as `100m_300ms`).

## Release

| Script | Used by | What it does |
| --- | --- | --- |
| `release.sh` | `just release` | Bumps versions, pushes, publishes the GitHub release and waits for the registries. |
| `verify-release-versions.sh` | `publish.yml` | Checks lockstep Rust and TypeScript versions and release tag alignment. |
| `publish-crates.sh` | `publish.yml` | Publishes workspace crates to crates.io in dependency order with idempotent retries. |
| `publish-npm-packages.sh` | `publish.yml` | Publishes packed `@minip2p/*` tarballs to npm with trusted publishing. |
| `build-node-musl.sh` | `bindings-native.yml`, `publish.yml` | Builds (and optionally tests with `--test`) Linux musl `@minip2p/node` addons in Docker. |
| `npm-trusted-publisher-web.sh` | by hand | Wizard for the npm trusted-publisher setup of `@minip2p/web`. |

## Relay container and installer

| Script | Used by | What it does |
| --- | --- | --- |
| `build-relay-release.sh` | `publish.yml`, `test-relay-container.sh` | Builds the static musl `minip2p-relay` binary. |
| `package-relay-server.sh` | `publish.yml`, `test-relay-container.sh`, `examples/relay-server/tests/release_archive.rs` | Packages the relay binary as a release archive. |
| `relay-builder.Dockerfile` | `test-relay-container.sh` | Toolchain image for the musl build. |
| `check-relay-image.sh` | `test-relay-container.sh`, `relay-container.yml` | Checks that a built relay image starts and keeps its identity. |
| `test-relay-container.sh` | CI | Builds, packages and checks the relay image end to end. |
| `test-relay-installer.sh` | CI | Tests the relay install script. |

`build-relay-release.sh TARGET` needs the Rust target installed (`rustup target add TARGET`) and musl-tools' `musl-gcc` for TARGET's architecture, so build on a native host. It prints the binary's path. `check-relay-image.sh IMAGE VERSION [PLATFORM]` runs a foreign-architecture image (`PLATFORM`, such as `linux/arm64`) under QEMU.
