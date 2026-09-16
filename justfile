default: test

fmt:
    cargo fmt --all
    cargo fmt --manifest-path fuzz/Cargo.toml

# Wipe Cargo targets, node_modules, Turbo caches, docs output, and other
# generated artifacts. Keeps code-ref/, fuzz corpus, and local identity keys.
clean:
    ./scripts/clean.sh

check:
    cargo check --workspace --all-targets
    cargo check --manifest-path fuzz/Cargo.toml --all-targets
    scripts/run-feature-matrix.sh check

clippy:
    cargo clippy --workspace --all-targets -- -D warnings
    scripts/run-feature-matrix.sh clippy
    cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings

# Mirrors CI's `test` job. Needs cargo-nextest: https://get.nexte.st
test:
    cargo nextest run --workspace
    scripts/run-feature-matrix.sh test
    # nextest does not run doctests, and --workspace --doc is default-features
    # only, so feature-gated doctests need their own line.
    cargo test --workspace --doc
    cargo test -p minip2p-tcp --features smoltcp --doc

check-nostd:
    rustup target add thumbv7em-none-eabi
    cargo check --no-default-features --target thumbv7em-none-eabi -p minip2p-core -p minip2p-platform -p minip2p-identity -p minip2p-transport -p minip2p-tls -p minip2p-noise -p minip2p-yamux -p minip2p-secure-mux -p minip2p-smoltcp -p minip2p-tcp -p minip2p-circuit -p minip2p-identify -p minip2p-multistream-select -p minip2p-ping -p minip2p-pubsub -p minip2p-discovery -p minip2p-mdns -p minip2p-relay -p minip2p-relay-server -p minip2p-autonat -p minip2p-dcutr -p minip2p-swarm -p minip2p-nat -p minip2p-rs
    cargo check --no-default-features --features smoltcp --target thumbv7em-none-eabi -p minip2p-tcp -p minip2p-mdns -p minip2p-rs
    cargo check --no-default-features --features smoltcp,pubsub --target thumbv7em-none-eabi -p minip2p-rs
    cargo check --no-default-features --features portable-autonat --target thumbv7em-none-eabi -p minip2p-rs
    cargo check --no-default-features --features portable-relay --target thumbv7em-none-eabi -p minip2p-rs

peer-ping:
    cargo test -p minip2p-peer --test ping

# Live foreign-implementation gate: TCP + Noise XX + Yamux in both directions.
interop-go:
    cargo test -p minip2p-ffi --test go_interop -- --ignored --nocapture

# Pinned rust-libp2p relay client against the minip2p server (network/build opt-in).
interop-relay-rust:
    cargo test -p minip2p-rs --features relay-server,tcp --test relay_rust_interop -- --ignored --nocapture

docs:
    cargo doc --workspace --no-deps
    RUSTDOCFLAGS="-D warnings" cargo doc -p minip2p-relay-server --no-deps
    RUSTDOCFLAGS="-D warnings" cargo doc -p minip2p-rs --features nat,pubsub,discovery,mdns,tcp,relay-server --no-deps
    cargo doc -p minip2p-tcp --features smoltcp --no-deps
    cargo doc -p minip2p-mdns --features smoltcp --no-deps
    cargo doc -p minip2p-rs --no-default-features --features smoltcp --no-deps
    cargo doc -p minip2p-rs --no-default-features --features smoltcp,pubsub --no-deps
    cargo doc -p minip2p-rs --no-default-features --features portable-autonat --no-deps
    cargo doc -p minip2p-rs --no-default-features --features portable-relay --no-deps

package-check:
    # Every published workspace package declares and actually ships its README.
    cargo metadata --no-deps --format-version 1 | jq -e '[.packages[] | select(.publish != []) | .readme != null] | all'
    cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.publish != []) | .name' | while read package; do cargo package -p "$package" --allow-dirty --list | rg -q '^README.md$' || exit 1; done
    cargo metadata --no-deps --format-version 1 | jq -e '.packages[] | select(.name == "minip2p-rs") | .features["relay-server"] == ["std", "dep:minip2p-relay-server"]'

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

bench-node:
    pnpm --filter @minip2p/node bench

bench-results-test:
    python3 -m unittest discover -s bench -p 'test_*.py'

fuzz seconds="30":
    cargo +nightly fuzz run wire_inputs -- -max_total_time={{seconds}}

release version *args:
    ./scripts/release.sh "{{version}}" {{args}}
