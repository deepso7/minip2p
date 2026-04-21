use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::{Multiaddr, PeerId};

use crate::{ConnectionEndpoint, ConnectionId, StreamId};

/// Events emitted by a transport back to the host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportEvent {
    /// Connection handshake completed. No stream events precede this.
    Connected {
        id: ConnectionId,
        endpoint: ConnectionEndpoint,
    },
    /// A locally-opened stream is ready. Emitted after `open_stream()`.
    StreamOpened {
        id: ConnectionId,
        stream_id: StreamId,
    },
    /// The remote peer opened a new stream. Precedes any `StreamData` for it.
    IncomingStream {
        id: ConnectionId,
        stream_id: StreamId,
    },
    /// Data received on a stream.
    StreamData {
        id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    },
    /// The remote peer half-closed its write side (FIN received).
    StreamRemoteWriteClosed {
        id: ConnectionId,
        stream_id: StreamId,
    },
    /// Both sides of the stream are closed. No further events for this stream.
    StreamClosed {
        id: ConnectionId,
        stream_id: StreamId,
    },
    /// The connection is fully closed. No further events for this connection.
    Closed {
        id: ConnectionId,
    },
    /// A non-fatal error on a connection.
    Error {
        id: ConnectionId,
        message: String,
    },
    /// A new inbound connection was accepted. `Connected` follows after handshake.
    IncomingConnection {
        id: ConnectionId,
        endpoint: ConnectionEndpoint,
    },
    /// A peer identity was bound to a connection.
    PeerIdentityVerified {
        id: ConnectionId,
        endpoint: ConnectionEndpoint,
        previous_peer_id: Option<PeerId>,
    },
    /// The transport is now listening on the given address.
    Listening {
        addr: Multiaddr,
    },
}
