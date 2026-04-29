# minip2p-quic

Synchronous QUIC transport adapter for minip2p, powered by [quiche](https://github.com/cloudflare/quiche).

No async runtime required. The host drives the transport by calling `poll()`.

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

## Basic usage

```rust
use minip2p_core::{Multiaddr, PeerAddr, Protocol};
use minip2p_identity::Ed25519Keypair;
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_transport::{ConnectionId, Transport};

let listener_key = Ed25519Keypair::generate();
let listener_cfg = QuicNodeConfig::new(listener_key.clone());
let mut listener = QuicTransport::new(listener_cfg, "127.0.0.1:0")?;

let local = listener.local_addr()?;
let listen_addr = Multiaddr::from_protocols(vec![
    Protocol::Ip4([127, 0, 0, 1]),
    Protocol::Udp(local.port()),
    Protocol::QuicV1,
]);
listener.listen(&listen_addr)?;

let dialer_cfg = QuicNodeConfig::dev_dialer();
let mut dialer = QuicTransport::new(dialer_cfg, "127.0.0.1:0")?;

let peer_addr = PeerAddr::new(listen_addr, listener_key.peer_id())?;

let conn_id = ConnectionId::new(1);
dialer.dial(conn_id, &peer_addr)?;
let stream_id = dialer.open_stream(conn_id)?;
dialer.send_stream(conn_id, stream_id, b"hello".to_vec())?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Scope

This crate is a concrete transport adapter and depends on `std`.
For Sans-I/O contracts and shared types, use `minip2p-transport`.

## Authentication Notes

- QUIC handshakes require mutual TLS. A peer that omits a certificate or presents a certificate without the libp2p public-key extension is rejected before `Connected` is emitted.
- The TLS backend only handles the wire handshake. libp2p identity verification is performed by `minip2p-tls` after quiche exposes the peer certificate.
- `minip2p-tls` currently accepts Ed25519 host-key signatures for verified peers.
- `IncomingConnection` is pre-auth and may be emitted before certificate verification finishes. Treat `Connected` or `PeerIdentityVerified` as the authenticated connection signal.
