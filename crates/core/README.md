# minip2p-core

Small, `no_std`-friendly core primitives for minip2p.

This crate focuses on typed address handling, peer-qualified endpoint types, Connection-attempt correlation IDs, shared stream framing, the shared protobuf field wire vocabulary, and the platform contracts (clock, deadline, entropy) every caller-driven component is driven through.

## Features

- `Multiaddr` parsing/formatting for a minimal protocol set.
- `PeerAddr` helper for validated `transport + peer id` addresses with terminal `/p2p/<peer-id>`.
- `ConnectId` — endpoint-local identity of one Connection attempt (`from_u64` / `as_u64`). Shared by the Connection-attempt engine and `NatAgent`.
- `Path` — how an established connection was made: `Direct`, `Punched` (by DCUtR), or `Relayed { relay }`. Shared by the Endpoint and `NatAgent`.
- Poll-driven protocol machines: every protocol machine takes inputs through inherent methods named for what they do (`on_data`, `accept`, `send_sync`, ...) and exposes an inherent `poll_output`. After any input, drain `poll_output` until it returns `None` before waiting on I/O, timers, or the application again.
- `Bytes`, the shared stream payload type (a re-export of `bytes::Bytes` without default features, ADR 0011): stream reads and writes carry one, so fan-out and forwarding clone a handle instead of the bytes.
- Varint-length-prefixed frame codec (`decode_frame`/`encode_frame`/`FrameDecode`) shared by the protocol crates; decoding is bounded by a caller-supplied maximum payload length. Canonical framing goldens and malformed-header cases live here.
- `FrameExchange` — one side of a framed request/response exchange: the bytes to send, the bytes received, and the decode loop between them, with the receive buffer bounded from the frame header: a frame declaring more than the maximum is refused before its payload is copied in, and so are bytes that could never complete a legal frame. Protocol crates keep their own messages, states, errors and trailing-byte policy, and map `FrameFault` onto their own error type. `take_buffered` hands the bytes behind the last frame to a protocol that switches the stream to something else, such as a relay circuit or the application.
- Shared protobuf field codec (`write_tag` / field-number `encode_*` helpers, `skip_field`, `WireError`; `tag_byte` only for single-byte tags) for protocol message bodies; `no_std` + `alloc`, with no I/O, clock, or async dependency. `read_tag` rejects field numbers outside `1..=2^29-1` with `WireError::InvalidFieldNumber` for every protocol ([ADR 0016](../../docs/adr/0016-reject-invalid-protobuf-field-numbers.md)). Protocol crates wrap `WireError` in their own contextual errors. Generic field framing and malformed-input cases live here.
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

DNS names are validated identically by the text and binary codecs: a name may not be empty or contain `/`, whitespace, or control characters. Without that, a binary name containing `/` would print as several components and re-parse into a _different_ address.

## Transport classification

`Multiaddr::transport_kind()` reports which base transport can dial an address, which is what a multi-transport host routes on:

| Shape                        | `transport_kind()`          |
| ---------------------------- | --------------------------- |
| `/<host>/tcp/<port>`         | `Some(TransportKind::Tcp)`  |
| `/<host>/udp/<port>/quic-v1` | `Some(TransportKind::Quic)` |
| anything else                | `None`                      |

A trailing `/p2p/<peer-id>` makes an address a _peer_ address rather than a transport address, so it classifies as `None`; strip it with `PeerAddr::transport()` first. `is_quic_transport()` and `is_tcp_transport()` answer the same question for one transport.

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

Wire layout: each component is `<varint(multicodec)><value>`. Value shape depends on the protocol: fixed-size bytes for ip4/ip6 and for the tcp/udp ports (both two bytes, big-endian), varint-length-prefixed UTF-8 for dns*, varint-length-prefixed multihash for p2p, absent for quic-v1 and p2p-circuit. See <https://github.com/multiformats/multiaddr> for the full spec.

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

## Platform contracts

`minip2p_core::platform` holds the portable clock, deadline, and entropy contracts. Everything in minip2p is caller-driven: protocol agents, transports, and runtimes never read a system clock and never draw randomness themselves. The host samples time once per drive iteration and passes that one value to everything it drives; components that need randomness are handed an entropy source. These contracts keep the rest of the workspace deterministic and testable, and keep all platform access in adapters.

- `Now`: one time sample, carrying monotonic milliseconds and optional wall-clock seconds.
- `Clock`: the trait adapters implement to produce `Now`.
- `Deadline`: a point on a clock's monotonic timeline, used by caller-driven components to report when they next need attention.
- `EntropySource` and `EntropyError`: cryptographically secure random bytes, with an explicit "this platform has none" error.
- `IoErrorKind`: a portable classification of I/O failures, so `no_std` and hosted adapters report the same kinds (`From<std::io::ErrorKind>` behind `std`).
- `StdClock` and `StdEntropy` behind the default `std` feature (which adds the `getrandom` dependency).

### Usage

Sample once, then drive everything with that sample:

```rust
use minip2p_core::platform::{Clock, Deadline, Now, StdClock};

struct Heartbeat {
    interval_ms: u64,
    next: Deadline,
}

impl Heartbeat {
    fn poll(&mut self, now: Now) -> bool {
        if !self.next.is_expired_at(now) {
            return false;
        }
        self.next = now.deadline_after(self.interval_ms);
        true
    }

    fn next_deadline(&self) -> Option<Deadline> {
        Some(self.next)
    }
}

let mut clock = StdClock::new();

// The only sample of this drive iteration; everything below is derived from it.
let now = clock.now();
let mut heartbeat = Heartbeat {
    interval_ms: 15_000,
    next: now.as_deadline(),
};

assert!(heartbeat.poll(now));
assert!(!heartbeat.poll(now));

// The host can idle until the earliest deadline across all its subsystems.
let idle_ms = heartbeat
    .next_deadline()
    .map(|deadline| deadline.millis_until(now));
assert_eq!(idle_ms, Some(15_000));
```

### Wall-clock time is optional

`Now::unix_seconds` is `None` whenever the platform has no usable wall-clock reading: an embedded board without an RTC or NTP sync has none at all, and a host whose clock is set before the Unix epoch has none that can be reported. Components that need real time — signed beacon freshness, certificate validity — must handle its absence explicitly. Substituting monotonic time is never correct: monotonic epochs are arbitrary and not comparable between peers.

### `no_std` platforms

Build without the `std` feature and supply your own implementations. A `Clock` must never let `monotonic_ms` decrease, and must saturate at `Now::MAX_MONOTONIC_MS` — `u64::MAX` is reserved for `Deadline::NEVER`, so it is not a usable instant:

```rust
use minip2p_core::platform::{Clock, EntropyError, EntropySource, Now};

struct BoardClock;

impl Clock for BoardClock {
    fn now(&mut self) -> Now {
        // No RTC on this board, so no wall clock is reported.
        Now::from_millis(ticks_since_boot())
    }
}

struct BoardRng;

impl EntropySource for BoardRng {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        for byte in output.iter_mut() {
            *byte = hardware_rng_byte();
        }
        Ok(())
    }
}
```

## no_std

Disable default features:

```toml
[dependencies]
minip2p-core = { path = "crates/core", default-features = false }
```

## Scope

This crate intentionally does not include runtime networking, DNS resolution, or protocol handlers. It provides stable typed building blocks for higher-level transport/protocol crates, and it does not enforce transport-specific address shapes (that validation belongs in transport adapters).
