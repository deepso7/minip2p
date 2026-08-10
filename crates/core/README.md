# minip2p-core

Small, `no_std`-friendly core primitives for minip2p.

This crate focuses on typed address handling and peer-qualified endpoint types.

## Features

- `Multiaddr` parsing/formatting for a minimal protocol set.
- `PeerAddr` helper for validated `transport + peer id` addresses with terminal `/p2p/<peer-id>`.
- `SansIoProtocol` trait for poll-driven, runtime-agnostic protocol engines.
- Varint-length-prefixed frame codec (`decode_frame`/`encode_frame`/`FrameDecode`) shared by the protocol crates; decoding is bounded by a caller-supplied maximum payload length.
- Typed error model with actionable parse context.
- `no_std` support (`alloc`-based), with `std` enabled by default.

## Supported multiaddr protocols (v0)

- `/ip4/<addr>`
- `/ip6/<addr>`
- `/dns/<name>`
- `/dns4/<name>`
- `/dns6/<name>`
- `/tcp/<port>`
- `/udp/<port>`
- `/quic-v1`
- `/p2p/<peer-id>`

DNS names are validated identically by the text and binary codecs: a name may not be empty or contain `/`, whitespace, or control characters. Without that, a binary name containing `/` would print as several components and re-parse into a *different* address.

## Transport classification

`Multiaddr::transport_kind()` reports which base transport can dial an address, which is what a multi-transport host routes on:

| Shape | `transport_kind()` |
| --- | --- |
| `/<host>/tcp/<port>` | `Some(TransportKind::Tcp)` |
| `/<host>/udp/<port>/quic-v1` | `Some(TransportKind::Quic)` |
| anything else | `None` |

A trailing `/p2p/<peer-id>` makes an address a *peer* address rather than a transport address, so it classifies as `None`; strip it with `PeerAddr::transport()` first. `is_quic_transport()` and `is_tcp_transport()` answer the same question for one transport.

## Usage

Parse and inspect a multiaddr:

```rust
use core::str::FromStr;
use minip2p_core::Multiaddr;

let addr = Multiaddr::from_str("/dns4/example.com/udp/4001/quic-v1").unwrap();
assert!(addr.is_quic_transport());
assert_eq!(addr.to_string(), "/dns4/example.com/udp/4001/quic-v1");
```

Binary multicodec encoding (on-wire form used by Identify, DCUtR, etc.):

```rust
use core::str::FromStr;
use minip2p_core::Multiaddr;

let addr = Multiaddr::from_str("/ip4/127.0.0.1/udp/4001/quic-v1").unwrap();
let bytes = addr.to_bytes();
// [0x04, 0x7F, 0x00, 0x00, 0x01, 0x91, 0x02, 0x0F, 0xA1, 0xCC, 0x03]
let decoded = Multiaddr::from_bytes(&bytes).unwrap();
assert_eq!(decoded, addr);
```

Wire layout: each component is `<varint(multicodec)><value>`. Value
shape depends on the protocol: fixed-size bytes for ip4/ip6 and for the
tcp/udp ports (both two bytes, big-endian),
varint-length-prefixed UTF-8 for dns*, varint-length-prefixed
multihash for p2p, absent for quic-v1 and p2p-circuit. See
<https://github.com/multiformats/multiaddr> for the full spec.

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
minip2p-core = { path = "crates/core", default-features = false }
```

## Scope

This crate intentionally does not include runtime networking, DNS resolution,
or protocol handlers. It provides stable typed building blocks for higher-level
transport/protocol crates, and it does not enforce transport-specific address
shapes (that validation belongs in transport adapters).
