# quic

QUIC transport crate for this `minip2p` workspace.

It is a Sans-IO wrapper over `quiche`, with libp2p-oriented TLS authentication.

## Current scope

- QUIC v1 (`/quic-v1`) transport core using `quiche`.
- BoringSSL-backed TLS context setup.
- ALPN fixed to `libp2p`.
- Peer authentication via the libp2p TLS certificate extension (`1.3.6.1.4.1.53594.1.1`).
- Expected remote `PeerId` verification on client dial.
- Multiaddr helpers for `/ip4|ip6/.../udp/.../quic-v1`.

## Out of scope (for now)

- Legacy `/quic` (draft-29) support.
- Non-Ed25519 host identity keys.
- Runtime-specific socket integration (Tokio/async-std adapters).

## API shape

`QuicConnection` is Sans-IO:

- You feed inbound UDP payloads via `recv(...)`.
- You pull outbound payloads via `poll_transmit(...)`.
- You drive time with `timeout()` and `on_timeout()`.
- Stream operations (`stream_send`, `stream_recv`) are available only after authentication succeeds.

## Example (in-memory packet pump)

```rust
use minip2p_identity::{Keypair, PeerId};
use quic::{QuicConnection, TransportConfig};

let client_id = Keypair::from_ed25519_secret([1u8; 32]);
let server_id = Keypair::from_ed25519_secret([2u8; 32]);
let expected_server = PeerId::from_public_key(&server_id.public());

let mut client = QuicConnection::connect(
    "127.0.0.1:5001".parse().unwrap(),
    "127.0.0.1:5002".parse().unwrap(),
    &client_id,
    Some(expected_server),
    TransportConfig::default(),
)
.unwrap();

let mut server = QuicConnection::accept(
    "127.0.0.1:5002".parse().unwrap(),
    "127.0.0.1:5001".parse().unwrap(),
    &server_id,
    TransportConfig::default(),
)
.unwrap();

let mut cbuf = [0u8; 1500];
let mut sbuf = [0u8; 1500];

while !(client.is_authenticated() && server.is_authenticated()) {
    while let Some(tx) = client.poll_transmit(&mut cbuf).unwrap() {
        let mut pkt = cbuf[..tx.len].to_vec();
        server.recv(&mut pkt, tx.from, tx.to).unwrap();
    }

    while let Some(tx) = server.poll_transmit(&mut sbuf).unwrap() {
        let mut pkt = sbuf[..tx.len].to_vec();
        client.recv(&mut pkt, tx.from, tx.to).unwrap();
    }

    if client.timeout().is_some_and(|d| d.is_zero()) {
        client.on_timeout();
    }

    if server.timeout().is_some_and(|d| d.is_zero()) {
        server.on_timeout();
    }
}
```

## Notes

- This crate intentionally gates stream usage until peer auth completes.
- For overall implementation plan and milestones, see `docs/quic-transport-plan.md`.
