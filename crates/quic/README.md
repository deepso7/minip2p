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
- Optional peer-id binding with `verify_connection_peer_id(...)`.
- Dial supports `/ip4`, `/ip6`, `/dns`, `/dns4`, `/dns6` QUIC transport addresses.

## Basic usage

```rust
use minip2p_core::{Multiaddr, PeerAddr, Protocol};
use minip2p_identity::PeerId;
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_transport::{ConnectionId, Transport};
use std::str::FromStr;

let listener_cfg = QuicNodeConfig::dev_listener_with_tls("cert.pem", "key.pem");
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

let peer_id = PeerId::from_str("QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N")?;
let peer_addr = PeerAddr::new(listen_addr, peer_id)?;

let conn_id = ConnectionId::new(1);
dialer.dial(conn_id, &peer_addr)?;
let stream_id = dialer.open_stream(conn_id)?;
dialer.send_stream(conn_id, stream_id, b"hello".to_vec())?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Scope

This crate is a concrete transport adapter and depends on `std`.
For Sans-I/O contracts and shared types, use `minip2p-transport`.
