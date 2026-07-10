default: test

fmt:
    cargo fmt --all
    cargo fmt --manifest-path fuzz/Cargo.toml

check:
    cargo check --workspace --all-targets
    cargo check --manifest-path fuzz/Cargo.toml --all-targets

clippy:
    cargo clippy --workspace --all-targets -- -D warnings
    cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings

test:
    cargo test

check-nostd:
    cargo check --no-default-features -p minip2p-core -p minip2p-identity -p minip2p-transport -p minip2p-tls -p minip2p-identify -p minip2p-multistream-select -p minip2p-ping -p minip2p-relay -p minip2p-autonat -p minip2p-dcutr -p minip2p-swarm

peer-direct:
    cargo test -p minip2p-peer --test direct

docs:
    cargo doc --workspace --no-deps

bench:
    cargo bench -p minip2p-core --bench multiaddr

fuzz seconds="30":
    cargo +nightly fuzz run wire_inputs -- -max_total_time={{seconds}}
