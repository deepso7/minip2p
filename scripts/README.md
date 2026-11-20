# scripts

Each script says what it does in its header comment. The `justfile` and the workflows in `.github/workflows/` call most of them; run them from the repo root.

## Local dev and CI

| Script | Used by | What it does |
| --- | --- | --- |
| `run-feature-matrix.sh` | `just check`, `just clippy`, `just test`, `just matrix`, CI | Runs `check`, `clippy` or `test` over the named feature-matrix rows (`ci`, `full`, or one row; `list` prints them). |
| `check-targets.sh` | `just check-nostd`, `check-wasm`, `docs`, `package-check`, CI | The no_std, wasm32, rustdoc and package lists. |
| `publish-order.py` | `check-targets.sh package-check`, `publish.yml` | Prints the publishable crates in dependency order. |
| `clean.sh` | `just clean` | Removes build outputs, `node_modules`, Turbo caches and docs output. |

## Benchmarks

| Script | Used by | What it does |
| --- | --- | --- |
| `run-benches.sh` | `just bench`, `just bench-ir` | Runs one pass of `bench/targets` and collects the result document. |
| `build-benches.sh` | `just bench-build`, CI | Builds every bench without running it. |
| `check-bench-ids.py` | `just bench-build`, CI | Checks the IR bench ids against `bench_results.py`. |
| `bench_results.py` | the bench scripts, `bench.yml`, CI | Normalizes results and compares a head run with its base. |
| `run-bench-container.sh` | `bench.yml` | Builds the bench image and runs the suite on this host. |
| `run-container-benches.sh` | `run-bench-container.sh` | Runs one pass inside the bench container. |
| `start-bench-runner.sh` | `bench.yml` | Wakes the on-demand EC2 bench instance (ADR 0025). |
| `rtt-sweep.sh` | `bench.yml`, the bench container | Runs the `endpoint_rtt` window sweeps over an emulated link. |

## Release

| Script | Used by | What it does |
| --- | --- | --- |
| `release.sh` | `just release` | Bumps versions, pushes, publishes the GitHub release and waits for the registries. |
| `npm-trusted-publisher-web.sh` | by hand | Wizard for the npm trusted-publisher setup of `@minip2p/web`. |

## Relay container and installer

| Script | Used by | What it does |
| --- | --- | --- |
| `build-relay-release.sh` | `publish.yml`, `test-relay-container.sh` | Builds the static musl `minip2p-relay` binary. |
| `package-relay-server.sh` | `publish.yml`, `test-relay-container.sh` | Packages the relay binary as a release archive. |
| `relay-builder.Dockerfile` | `test-relay-container.sh` | Toolchain image for the musl build. |
| `check-relay-image.sh` | `test-relay-container.sh`, `relay-container.yml` | Checks that a built relay image starts and keeps its identity. |
| `test-relay-container.sh` | CI | Builds, packages and checks the relay image end to end. |
| `test-relay-installer.sh` | CI | Tests the relay install script. |
