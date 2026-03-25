# minip2p-core

Small, `no_std`-friendly core primitives for minip2p.

This crate currently focuses on typed address handling for a QUIC-first stack.

## Features

- `Multiaddr` parsing/formatting for a minimal protocol set.
- `PeerAddr` helper for validated `transport + peer id` addresses.
- Typed error model with actionable parse context.
- `no_std` support (`alloc`-based), with `std` enabled by default.

## Supported multiaddr protocols (v0)

- `/ip4/<addr>`
- `/ip6/<addr>`
- `/dns/<name>`
- `/dns4/<name>`
- `/dns6/<name>`
- `/udp/<port>`
- `/quic-v1`
- `/p2p/<peer-id>`

## Usage

Parse and inspect a multiaddr:

```rust
use core::str::FromStr;
use minip2p_core::Multiaddr;

let addr = Multiaddr::from_str("/dns4/example.com/udp/4001/quic-v1").unwrap();
assert!(addr.is_quic_transport());
assert_eq!(addr.to_string(), "/dns4/example.com/udp/4001/quic-v1");
```

Work with peer-qualified addresses:

```rust
use core::str::FromStr;
use minip2p_core::PeerAddr;

let peer_addr = PeerAddr::from_str(
    "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N",
)
.unwrap();

assert_eq!(
    peer_addr.transport().to_string(),
    "/ip4/127.0.0.1/udp/4001/quic-v1"
);
```

## no_std

Disable default features:

```toml
[dependencies]
minip2p-core = { path = "packages/core", default-features = false }
```

## Scope

This crate intentionally does not include runtime networking, DNS resolution,
or protocol handlers. It provides stable typed building blocks for higher-level
transport/protocol crates.
