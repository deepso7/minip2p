# minip2p-transport

Sans-IO transport trait and connection/stream types for minip2p. `no_std` + `alloc` compatible.

This crate defines the transport abstraction that concrete adapters (QUIC, WebSocket, etc.) implement. It contains no runtime or networking code.

## Features

- `Transport` trait with a `poll()`-based event model.
- `ConnectionId` and `StreamId` identifiers.
- Connection lifecycle events (`Connected`, `Closed`, `IncomingConnection`, `PeerIdentityVerified`, `Listening`).
- Stream lifecycle events (`StreamOpened`, `IncomingStream`, `StreamData`, `StreamRemoteWriteClosed`, `StreamClosed`).
- Host intents via trait methods: `dial`, `listen`, `open_stream`, `send_stream`, `close_stream_write`, `reset_stream`, `close`.
- Typed error model with transport, connection, and stream context.

## Usage

Implement the `Transport` trait for your adapter:

```rust
use minip2p_core::{Multiaddr, PeerAddr};
use minip2p_transport::{ConnectionId, StreamId, Transport, TransportError, TransportEvent};

struct MyTransport;

impl Transport for MyTransport {
    fn dial(&mut self, id: ConnectionId, addr: &PeerAddr) -> Result<(), TransportError> {
        todo!("initiate outgoing connection")
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<(), TransportError> {
        todo!("start listening")
    }

    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        todo!("open a new outbound stream")
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        todo!("write stream data")
    }

    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        todo!("half-close stream write side")
    }

    fn reset_stream(&mut self, id: ConnectionId, stream_id: StreamId) -> Result<(), TransportError> {
        todo!("reset stream")
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        todo!("close connection")
    }

    fn poll(&mut self) -> Result<Vec<TransportEvent>, TransportError> {
        todo!("drive transport and emit events")
    }
}
```

## no_std

Disable default features:

```toml
[dependencies]
minip2p-transport = { path = "crates/transport", default-features = false }
```

## Scope

This crate defines the transport contract only. Concrete runtime adapters live in separate crates (e.g. `minip2p-quic`).
