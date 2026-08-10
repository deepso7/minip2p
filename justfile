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
    cargo check -p minip2p-rs --features discovery
    cargo check -p minip2p-rs --features mdns
    cargo check -p minip2p-rs --features discovery,mdns
    cargo check -p minip2p-rs --features tcp
    cargo check -p minip2p-rs --no-default-features --features std,tcp
    cargo check -p minip2p-rs --no-default-features --features smoltcp
    cargo check -p minip2p-rs --no-default-features --features smoltcp,pubsub
    cargo check -p minip2p-rs --no-default-features --features portable-relay
    cargo check -p minip2p-rs --features discovery,mdns,tcp
    cargo check -p minip2p-tcp --features smoltcp --all-targets
    cargo check -p minip2p-mdns --features smoltcp --all-targets

clippy:
    cargo clippy --workspace --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --features discovery --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --features mdns --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --features discovery,mdns --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --features tcp --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --no-default-features --features std,tcp --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --no-default-features --features smoltcp --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --no-default-features --features smoltcp,pubsub --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --no-default-features --features portable-relay --all-targets -- -D warnings
    cargo clippy -p minip2p-rs --features discovery,mdns,tcp --all-targets -- -D warnings
    cargo clippy -p minip2p-tcp --features smoltcp --all-targets -- -D warnings
    cargo clippy -p minip2p-mdns --features smoltcp --all-targets -- -D warnings
    cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings

test:
    cargo test
    cargo test -p minip2p-rs --features nat
    cargo test -p minip2p-rs --features pubsub
    cargo test -p minip2p-rs --features nat,pubsub
    cargo test -p minip2p-rs --features discovery
    cargo test -p minip2p-rs --features mdns
    cargo test -p minip2p-rs --features discovery,mdns
    cargo test -p minip2p-rs --features tcp
    cargo test -p minip2p-rs --features discovery,mdns,tcp
    cargo test -p minip2p-rs --no-default-features --features smoltcp
    cargo test -p minip2p-rs --no-default-features --features smoltcp,pubsub
    cargo test -p minip2p-rs --no-default-features --features portable-relay
    cargo test -p minip2p-tcp --features smoltcp
    cargo test -p minip2p-mdns --features smoltcp

check-nostd:
    rustup target add thumbv7em-none-eabi
    cargo check --no-default-features --target thumbv7em-none-eabi -p minip2p-core -p minip2p-platform -p minip2p-identity -p minip2p-transport -p minip2p-tls -p minip2p-noise -p minip2p-yamux -p minip2p-secure-mux -p minip2p-smoltcp -p minip2p-tcp -p minip2p-circuit -p minip2p-identify -p minip2p-multistream-select -p minip2p-ping -p minip2p-pubsub -p minip2p-discovery -p minip2p-mdns -p minip2p-relay -p minip2p-autonat -p minip2p-dcutr -p minip2p-swarm -p minip2p-nat -p minip2p-rs
    cargo check --no-default-features --features smoltcp --target thumbv7em-none-eabi -p minip2p-tcp -p minip2p-mdns -p minip2p-rs
    cargo check --no-default-features --features smoltcp,pubsub --target thumbv7em-none-eabi -p minip2p-rs
    cargo check --no-default-features --features portable-relay --target thumbv7em-none-eabi -p minip2p-rs

peer-ping:
    cargo test -p minip2p-peer --test ping

# Live foreign-implementation gate: TCP + Noise XX + Yamux in both directions.
interop-go:
    cargo test -p minip2p-ffi --test go_interop -- --ignored --nocapture

docs:
    cargo doc --workspace --no-deps
    cargo doc -p minip2p-rs --features nat,pubsub,discovery,mdns,tcp --no-deps
    cargo doc -p minip2p-tcp --features smoltcp --no-deps
    cargo doc -p minip2p-mdns --features smoltcp --no-deps
    cargo doc -p minip2p-rs --no-default-features --features smoltcp --no-deps
    cargo doc -p minip2p-rs --no-default-features --features smoltcp,pubsub --no-deps
    cargo doc -p minip2p-rs --no-default-features --features portable-relay --no-deps

docs-site:
    cd docs && pnpm run check
    cargo check --manifest-path docs/snippets/quickstart/Cargo.toml
    cargo check --manifest-path docs/snippets/custom-stream/Cargo.toml

bindings-check:
    cd bindings/ts && pnpm typecheck
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

fuzz seconds="30":
    cargo +nightly fuzz run wire_inputs -- -max_total_time={{seconds}}

release version *args:
    ./scripts/release.sh "{{version}}" {{args}}
