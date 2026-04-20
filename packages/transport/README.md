# minip2p-transport

Sans-IO transport trait and connection types for minip2p. `no_std` + `alloc` compatible.

This crate defines the transport abstraction that concrete adapters (QUIC, WebSocket, etc.) implement. It contains no runtime or networking code — only types and a trait.

## Features

- `Transport` trait with a `poll()`-based event model.
- `ConnectionId` — lightweight `u64`-backed connection identifier.
- `ConnectionEndpoint` — transport endpoint + optional remote `PeerId`.
- `ConnectionState` — connection lifecycle: `Connecting`, `Connected`, `Closing`, `Closed`.
- `PeerSendPolicy` — peer-level connection selection for `send_to_peer` style APIs.
- `TransportAction` — host-side intents: `Dial`, `Listen`, `Send`, `Close`.
- `TransportEvent` — transport-side outcomes: `Connected`, `Received`, `Closed`, `Error`, `IncomingConnection`, `PeerIdentityVerified`, `Listening`.
- `TransportError` — typed errors with connection, address, and config context.
- `no_std` support (`alloc`-based), with `std` enabled by default.

## Usage

Implement the `Transport` trait for your adapter:

```rust
use minip2p_transport::{
    ConnectionId, ConnectionState, Transport, TransportError, TransportEvent,
};
use minip2p_core::{Multiaddr, PeerAddr};

struct MyTransport;

impl Transport for MyTransport {
    fn dial(
        &mut self,
        id: ConnectionId,
        addr: &PeerAddr,
    ) -> Result<(), TransportError> {
        todo!("initiate an outgoing connection")
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<(), TransportError> {
        todo!("start listening on the given address")
    }

    fn send(
        &mut self,
        id: ConnectionId,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        todo!("send data on an established connection")
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        todo!("close a connection gracefully")
    }

    fn poll(&mut self) -> Result<Vec<TransportEvent>, TransportError> {
        todo!("drive the transport and return pending events")
    }
}
```

Drive the transport in a synchronous loop:

```rust
use minip2p_transport::{ConnectionId, Transport, TransportEvent};

fn event_loop(transport: &mut impl Transport) {
    loop {
        let events = transport.poll().expect("poll failure");

        for event in events {
            match event {
                TransportEvent::Connected { id, endpoint } => {
                    if let Some(peer_id) = endpoint.peer_id() {
                        println!("connected: {id} -> {} (peer: {peer_id})", endpoint.transport());
                    } else {
                        println!("connected: {id} -> {}", endpoint.transport());
                    }
                }
                TransportEvent::Received { id, data } => {
                    println!("received {} bytes on {id}", data.len());
                }
                TransportEvent::Closed { id } => {
                    println!("connection {id} closed");
                }
                TransportEvent::Error { id, message } => {
                    eprintln!("error on {id}: {message}");
                }
                TransportEvent::IncomingConnection { id, endpoint } => {
                    println!("incoming connection {id} from {}", endpoint.transport());
                }
                TransportEvent::PeerIdentityVerified { id, endpoint, .. } => {
                    println!("connection {id} identity verified as {:?}", endpoint.peer_id());
                }
                TransportEvent::Listening { addr } => {
                    println!("listening on {addr}");
                }
            }
        }
    }
}
```

## Error handling

All fallible methods return `Result<_, TransportError>`. Errors include connection, address, and configuration context so callers can act on failures quickly:

```rust
use minip2p_transport::{ConnectionId, TransportError};

fn handle_error(err: TransportError) {
    match err {
        TransportError::InvalidAddress { context, reason } => {
            eprintln!("invalid address for {context}: {reason}");
        }
        TransportError::InvalidConfig { reason } => {
            eprintln!("invalid config: {reason}");
        }
        TransportError::ResourceExhausted { resource } => {
            eprintln!("resource exhausted: {resource}");
        }
        TransportError::PeerNotConnected { peer_id } => {
            eprintln!("no connected connections for peer {peer_id}");
        }
        TransportError::ConnectionNotFound { id } => {
            eprintln!("connection {id} does not exist");
        }
        TransportError::ConnectionExists { id } => {
            eprintln!("connection {id} already exists");
        }
        TransportError::InvalidState { id, state, expected } => {
            eprintln!(
                "connection {id} is {state}, expected {expected}"
            );
        }
        TransportError::DialFailed { id, reason } => {
            eprintln!("dial failed for {id}: {reason}");
        }
        TransportError::SendFailed { id, reason } => {
            eprintln!("send failed for {id}: {reason}");
        }
        TransportError::CloseFailed { id, reason } => {
            eprintln!("close failed for {id}: {reason}");
        }
        TransportError::ListenFailed { reason } => {
            eprintln!("listen failed: {reason}");
        }
        TransportError::NotListening => {
            eprintln!("not listening on any address");
        }
        TransportError::PollError { reason } => {
            eprintln!("poll error: {reason}");
        }
    }
}
```

## no_std

Disable default features:

```toml
[dependencies]
minip2p-transport = { path = "packages/transport", default-features = false }
```

## Scope

This crate defines the transport interface only. Concrete implementations live in separate crates (e.g. `minip2p-quic`).
