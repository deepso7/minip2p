# minip2p-quic

Synchronous QUIC transport adapter for minip2p, powered by [quiche](https://github.com/cloudflare/quiche).

No async runtime required. The host drives the transport by calling `poll(now)` with its own time sample.

## Features

- Implements `minip2p_transport::Transport`.
- Non-blocking UDP socket integration.
- Connection lifecycle events (`IncomingConnection`, `Connected`, `Closed`).
- Native QUIC stream operations:
  - `open_stream`
  - `send_stream`
  - `close_stream_write`
  - `reset_stream`
- Stream events (`StreamOpened`, `IncomingStream`, `StreamData`, `StreamRemoteWriteClosed`, `StreamClosed`).
- Mutual libp2p TLS peer authentication. Dialing and listening require a configured Ed25519 keypair.
- Automatic peer-id verification from libp2p TLS certificates. `Connected` carries the verified endpoint; `PeerIdentityVerified` is also emitted when the peer index is bound or updated.
- `QuicNodeConfig` is identity-first: constructing a transport requires an Ed25519 host keypair.
- Dial supports `/ip4`, `/ip6`, `/dns`, `/dns4`, `/dns6` QUIC transport addresses.
- `QuicEndpoint::dual_stack` binds separate IPv4 and IPv6 wildcard sockets for the common "listen on both" case.
- QUIC deadlines are exposed through `Transport::next_deadline()` and processed
  by `poll()`; no async runtime or hidden timer thread is used. Idle drivers
  block on `BlockingTransport::wait_for_input()` (a readiness peek on the UDP socket)
  instead of polling on a fixed cadence. Both report immediately-due work when
  events are already buffered, so calls made between polls -- `listen`,
  `open_stream`, and the stream operations -- never leave a host asleep on an
  undelivered event.
- Quiet connections send an ack-eliciting packet at half `idle_timeout_ms`
  (15 s by default) so NAT bindings and the peer's idle timer stay warm
  without an application ping. Dead paths still idle-timeout: only one ping
  is sent per receive.
- Stateless Retry authenticates source addresses before inbound connection
  allocation. Configurable limits bound connections, streams, queued stream
  bytes, queued UDP datagrams, and idle time.

## Basic usage

```rust
use minip2p_identity::Ed25519Keypair;
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_transport::Transport;

let listener_key = Ed25519Keypair::generate();
let listener_cfg = QuicNodeConfig::new(listener_key.clone());
let mut listener = QuicTransport::new(listener_cfg, "127.0.0.1:0")?;
let listen_addr = listener.listen_on_bound_addr()?;

let dialer_cfg = QuicNodeConfig::generate();
let mut dialer = QuicTransport::new(dialer_cfg, "127.0.0.1:0")?;

let peer_addr = minip2p_core::PeerAddr::new(
    listen_addr,
    listener_key.peer_id(),
)?;
let conn_id = dialer.dial(&peer_addr)?;
let stream_id = dialer.open_stream(conn_id)?;
dialer.send_stream(conn_id, stream_id, b"hello".to_vec())?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Scope

This crate is a concrete transport adapter and depends on `std`.
For Sans-I/O contracts and shared types, use `minip2p-transport`.

## Clocks

Unlike the portable transports, this adapter does not run purely on the host's
time sample. quiche keeps its own clock: it reads `Instant::now()` internally
to drive loss detection and to answer `conn.timeout()`. Converting it to
caller-supplied time would mean forking or wrapping quiche's timer handling,
which is out of scope, so the dual clock is deliberate and this adapter is
`std`-only.

What the adapter *does* guarantee is that nothing quiche's clock touches leaks
into what the host sees:

- `poll(now)` retains the sample purely to anchor `next_deadline()` on the
  host's timeline, so a host driving several transports can still compare
  their deadlines.
- quiche measures its timeout from an `Instant::now()` at or after that
  sample, so anchoring rounds the deadline slightly early — an extra harmless
  wakeup, never a missed timer.
- Sub-millisecond timeouts (common on loopback) are rounded *up* to a whole
  millisecond rather than truncated to zero. Truncation would report "already
  due" and spin a driver's budget loop until wall time caught up.

`quiche 0.29` exposes its TLS builder using `boring` 4.x types, so this crate
intentionally uses the newest compatible `boring` 4.x release rather than the
incompatible 5.x major.

## Authentication Notes

- QUIC handshakes require mutual TLS. A peer that omits a certificate or presents a certificate without the libp2p public-key extension is rejected before `Connected` is emitted.
- The TLS backend only handles the wire handshake. libp2p identity verification is performed by `minip2p-tls` after quiche exposes the peer certificate.
- `minip2p-tls` currently accepts Ed25519 host-key signatures for verified peers.
- `IncomingConnection` is pre-auth and may be emitted before certificate verification finishes. Treat `Connected` or `PeerIdentityVerified` as the authenticated connection signal.
