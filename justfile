default: test

fmt:
    cargo fmt --all
    cargo fmt --manifest-path fuzz/Cargo.toml

# Wipe Cargo targets, node_modules, Turbo caches, docs output, and other
# generated artifacts. Keeps code-ref/, fuzz corpus, and local identity keys.
clean:
    ./scripts/clean.sh

# Fast workspace-only loop: format check, lint, and tests at default features.
dev:
    cargo fmt --all -- --check
    python3 scripts/check-comments.py
    cargo clippy --workspace --all-targets -- -D warnings
    cargo nextest run --workspace

# `tier` picks feature-matrix rows: `ci`, `full`, or one row name
# (`scripts/run-feature-matrix.sh list` prints them).
check tier="full":
    cargo check --workspace --all-targets
    cargo check --manifest-path fuzz/Cargo.toml --all-targets
    scripts/run-feature-matrix.sh check {{tier}}

# CI lints every row: run `just clippy full` before pushing feature-gated code.
clippy tier="ci":
    cargo clippy --workspace --all-targets -- -D warnings
    scripts/run-feature-matrix.sh clippy {{tier}}
    cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --locked -- -D warnings

# Mirrors CI's `test` job, which runs the feature matrix's `ci` rows;
# `just test full` runs every row, like the release workflow.
# Needs cargo-nextest: https://get.nexte.st
test tier="ci":
    cargo nextest run --workspace
    scripts/run-feature-matrix.sh test {{tier}}
    # nextest does not run doctests, and --workspace --doc is default-features
    # only, so feature-gated doctests need their own line.
    cargo test --workspace --doc
    cargo test -p minip2p-tcp --features smoltcp --doc

# One feature-matrix operation alone, e.g. `just matrix clippy smoltcp`.
matrix operation tier="ci":
    scripts/run-feature-matrix.sh {{operation}} {{tier}}

# Comment ratchet: `check`, `update` (lock in deletions), or `list [paths]`.
comments operation="check" *paths:
    python3 scripts/check-comments.py {{ if operation == "check" { "" } else { "--" + operation } }} {{paths}}

check-nostd:
    rustup target add thumbv7em-none-eabi
    scripts/check-targets.sh nostd

# The browser build's crates compile for wasm32 without the std driver.
check-wasm:
    rustup target add wasm32-unknown-unknown
    scripts/check-targets.sh wasm

peer-ping:
    cargo test -p minip2p-peer --test ping

# Local-link discovery between two instances (needs host multicast on UDP 5353).
mdns-discovery:
    cargo test -p minip2p-mdns-demo --test discovery -- --ignored --nocapture

# Live foreign-implementation gate: TCP + Noise XX + Yamux in both directions.
interop-go:
    cargo test -p minip2p-ffi --test go_interop -- --ignored --nocapture

# Pinned rust-libp2p relay client against the minip2p server (network/build opt-in).
interop-relay-rust:
    cargo test -p minip2p-rs --features relay-server,tcp --test relay_rust_interop -- --ignored --nocapture

# go-libp2p's circuit relay v2 client across a two-node minip2p relay mesh (needs Go).
interop-relay-go:
    cargo test -p minip2p-rs --features relay-server,tcp --test relay_go_interop -- --ignored --nocapture

docs:
    scripts/check-targets.sh docs

package-check:
    scripts/check-targets.sh package-check --allow-dirty

docs-site:
    pnpm docs:check
    cargo check --manifest-path docs/snippets/quickstart/Cargo.toml
    cargo check --manifest-path docs/snippets/custom-stream/Cargo.toml

bindings-check:
    pnpm typecheck
    pnpm --filter @minip2p/node native:build
    pnpm test
    pnpm lint
    pnpm build:bindings
    pnpm rn:generate
    test -z "$(git status --porcelain)"

bindings-format:
    pnpm format

bindings-generate:
    pnpm rn:generate

bindings-ios:
    pnpm rn:ios

bindings-android:
    pnpm rn:android

bench:
    scripts/run-benches.sh wall

bench-ir:
    scripts/run-benches.sh ir

# Mirrors CI's bench-build job: build every bench in bench/targets, check IR ids.
bench-build:
    python3 scripts/check-bench-ids.py
    scripts/build-benches.sh

bench-node:
    pnpm --filter @minip2p/node bench

bench-results-test:
    python3 -m unittest discover -s bench -p 'test_*.py'

fuzz seconds="30":
    cargo +nightly fuzz run wire_inputs -- -max_total_time={{seconds}}

release version *args:
    ./scripts/release.sh "{{version}}" {{args}}
