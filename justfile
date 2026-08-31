default: test

fmt:
    cargo fmt --all
    cargo fmt --manifest-path fuzz/Cargo.toml

check:
    cargo check --workspace --all-targets
    cargo check --manifest-path fuzz/Cargo.toml --all-targets
    cargo check -p minip2p-rs
    cargo check -p minip2p-rs --features nat
    cargo check -p minip2p-rs --features pubsub
    cargo check -p minip2p-rs --features nat,pubsub
    cargo check -p minip2p-rs --features relay-server
    cargo check -p minip2p-rs --features nat,relay-server
    cargo check -p minip2p-rs --features nat,relay-server,tcp
    cargo check -p minip2p-rs --no-default-features --features std,tcp,relay-server
    cargo check -p minip2p-rs --features discovery
    cargo check -p minip2p-rs --features mdns
    cargo check -p minip2p-rs --features discovery,mdns
    cargo check -p minip2p-rs --features tcp
    cargo check -p minip2p-rs --no-default-features --features std,tcp
    cargo check -p minip2p-rs --no-default-features --features smoltcp
    cargo check -p minip2p-rs --no-default-features --features smoltcp,pubsub
    cargo check -p minip2p-rs --no-default-features --features portable-autonat
    cargo check -p minip2p-rs --no-default-features --features portable-relay
    cargo check -p minip2p-rs --features discovery,mdns,tcp
    cargo check -p minip2p-tcp --features smoltcp --all-targets
    cargo check -p minip2p-mdns --features smoltcp --all-targets

clippy:
    cargo clippy --workspace --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --features discovery --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --features mdns --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --features discovery,mdns --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --features relay-server --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --features nat,relay-server --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --features nat,relay-server,tcp --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --no-default-features --features std,tcp,relay-server --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --features tcp --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --no-default-features --features std,tcp --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --no-default-features --features smoltcp --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --no-default-features --features smoltcp,pubsub --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --no-default-features --features portable-autonat --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --no-default-features --features portable-relay --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --features discovery,mdns,tcp --all-targets -- -D warnings
    cargo clippy -p minip2p-tcp --features smoltcp --all-targets -- -D warnings
    cargo clippy -p minip2p-mdns --features smoltcp --all-targets -- -D warnings
    cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings

# Mirrors CI's `test` job. Needs cargo-nextest: https://get.nexte.st
test:
    cargo nextest run --workspace
    cargo nextest run --profile variants -p minip2p-rs --features nat
    cargo nextest run --profile variants -p minip2p-rs --features pubsub
    cargo nextest run --profile variants -p minip2p-rs --features nat,pubsub
    cargo nextest run --profile variants -p minip2p-rs --features discovery
    cargo nextest run --profile variants -p minip2p-rs --features mdns
    cargo nextest run --profile variants -p minip2p-rs --features discovery,mdns
    cargo nextest run --profile variants -p minip2p-rs --features relay-server
    cargo nextest run --profile variants -p minip2p-rs --features nat,relay-server
    cargo nextest run --profile variants -p minip2p-rs --features nat,relay-server,tcp
    cargo nextest run --profile variants -p minip2p-rs --no-default-features --features std,tcp,relay-server
    cargo nextest run --profile variants -p minip2p-rs --features tcp
    cargo nextest run --profile variants -p minip2p-rs --no-default-features --features std,tcp
    cargo nextest run --profile variants -p minip2p-rs --features discovery,mdns,tcp
    cargo nextest run --profile variants -p minip2p-rs --no-default-features --features smoltcp
    cargo nextest run --profile variants -p minip2p-rs --no-default-features --features smoltcp,pubsub
    cargo nextest run --profile variants -p minip2p-rs --no-default-features --features portable-autonat
    cargo nextest run --profile variants -p minip2p-rs --no-default-features --features portable-relay
    cargo nextest run --profile variants -p minip2p-tcp --features smoltcp
    cargo nextest run --profile variants -p minip2p-mdns --features smoltcp
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
    cd docs && pnpm run check
    cargo check --manifest-path docs/snippets/quickstart/Cargo.toml
    cargo check --manifest-path docs/snippets/custom-stream/Cargo.toml

bindings-check:
    cd bindings/ts && pnpm typecheck
    cd bindings/ts && pnpm --filter @minip2p/node native:build
    cd bindings/ts && pnpm test
    cd bindings/ts && pnpm lint
    cd bindings/ts && pnpm build
    cd bindings/ts && pnpm rn:generate
    test -z "$(git status --porcelain)"

bindings-format:
    cd bindings/ts && pnpm format

bindings-generate:
    cd bindings/ts && pnpm rn:generate

bindings-ios:
    cd bindings/ts && pnpm rn:ios

bindings-android:
    cd bindings/ts && pnpm rn:android

bench:
    cargo bench -p minip2p-core --bench multiaddr
    cargo bench -p minip2p-yamux --bench data_path
    cargo bench -p minip2p-discovery --bench peer_book
    cargo bench -p minip2p-pubsub --bench fanout
    cargo bench -p minip2p-relay-server --bench relay_server_event
    cargo bench -p minip2p-quic --bench idle_poll
    cargo bench -p minip2p-tcp --bench readiness_poll
    cargo bench -p minip2p-rs --features tcp --bench endpoint_e2e
    python3 scripts/bench_results.py criterion --output target/bench-results/rust-wall.json --git-sha "$(git rev-parse HEAD)"

bench-ir:
    GUNGRAUN_SAVE_SUMMARY=json cargo bench -p minip2p-core --bench multiaddr_ir
    GUNGRAUN_SAVE_SUMMARY=json cargo bench -p minip2p-yamux --bench data_path_ir
    GUNGRAUN_SAVE_SUMMARY=json cargo bench -p minip2p-discovery --bench peer_book_ir
    GUNGRAUN_SAVE_SUMMARY=json cargo bench -p minip2p-pubsub --bench fanout_ir
    GUNGRAUN_SAVE_SUMMARY=json cargo bench -p minip2p-relay-server --bench relay_server_event_ir
    python3 scripts/bench_results.py gungraun --output target/bench-results/rust-micro.json --git-sha "$(git rev-parse HEAD)"

bench-results-test:
    python3 -m unittest discover -s bench -p 'test_*.py'

fuzz seconds="30":
    cargo +nightly fuzz run wire_inputs -- -max_total_time={{seconds}}

release version *args:
    ./scripts/release.sh "{{version}}" {{args}}
