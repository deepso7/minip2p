use alloc::string::String;

use minip2p_core::{Bytes, Multiaddr, PeerId};

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
        data: Bytes,
    },
    /// A stream that reported [`TransportError::Full`](crate::TransportError::Full)
    /// can queue again.
    ///
    /// One-shot per Full: it fires once the stream can queue at least half of
    /// the smaller of its stream and connection send caps, and never after
    /// the stream's write side has ended.
    StreamWritable {
        id: ConnectionId,
        stream_id: StreamId,
    },
    /// The remote peer half-closed its write side (FIN received).
    StreamRemoteWriteClosed {
        id: ConnectionId,
        stream_id: StreamId,
    },
    /// The remote peer asked us to stop sending (QUIC STOP_SENDING).
    ///
    /// Our write side is closed for good and any queued writes were dropped;
    /// the read side stays open, so `StreamData` and `StreamRemoteWriteClosed`
    /// may still follow. Emitted at most once per stream. Yamux has no
    /// equivalent, so byte-stream transports never emit it.
    StreamWriteStopped {
        id: ConnectionId,
        stream_id: StreamId,
        error_code: u64,
    },
    /// Both sides of the stream are closed. No further events for this stream.
    StreamClosed {
        id: ConnectionId,
        stream_id: StreamId,
    },
    /// The connection is fully closed. No further events for this connection.
    Closed { id: ConnectionId },
    /// A non-fatal error on a connection.
    Error { id: ConnectionId, message: String },
    /// A new inbound connection was accepted. `Connected` follows after handshake.
    IncomingConnection {
        id: ConnectionId,
        endpoint: ConnectionEndpoint,
    },
    /// A peer identity was bound to a connection.
    ///
    /// Transports may emit this after `Connected` when identity is learned as a
    /// post-handshake upgrade. Transports that verify identity during the
    /// handshake may also emit both `Connected` with the verified endpoint and
    /// this event so consumers that track identity-upgrade events have one
    /// consistent signal to observe.
    PeerIdentityVerified {
        id: ConnectionId,
        endpoint: ConnectionEndpoint,
        previous_peer_id: Option<PeerId>,
    },
    /// The transport is now listening on the given address.
    Listening { addr: Multiaddr },
}
