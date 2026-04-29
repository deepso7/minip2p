default: test

fmt:
    cargo fmt --all

check:
    cargo check --workspace

test:
    cargo test

check-nostd:
    cargo check --no-default-features -p minip2p-core -p minip2p-identity -p minip2p-transport -p minip2p-tls -p minip2p-identify -p minip2p-ping -p minip2p-relay -p minip2p-dcutr -p minip2p-swarm

peer-direct:
    cargo test -p minip2p-peer --test direct

docs:
    cargo doc --workspace --no-deps
