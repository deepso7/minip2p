//! Event, action, and error types exposed by the swarm.
//!
//! Kept in a dedicated module so both the Sans-I/O core and the std driver
//! reference the same concrete types.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::PeerId;
use minip2p_identify::IdentifyMessage;
use minip2p_transport::{ConnectionId, StreamId};

/// Events emitted by the swarm to the application.
#[derive(Clone, Debug)]
pub enum SwarmEvent {
    /// A new connection was established and identity verified.
    ConnectionEstablished { peer_id: PeerId },
    /// A connection was closed.
    ConnectionClosed { peer_id: PeerId },
    /// Identify information received from a remote peer.
    IdentifyReceived { peer_id: PeerId, info: IdentifyMessage },
    /// A ping RTT measurement completed.
    PingRttMeasured { peer_id: PeerId, rtt_ms: u64 },
    /// A ping timed out.
    PingTimeout { peer_id: PeerId },
    /// A user-registered protocol was successfully negotiated on a stream.
    /// `initiated_locally` is `true` when we opened the stream and `false`
    /// when the remote peer did.
    UserStreamReady {
        peer_id: PeerId,
        stream_id: StreamId,
        protocol_id: String,
        initiated_locally: bool,
    },
    /// Raw data arrived on a negotiated user stream.
    UserStreamData {
        peer_id: PeerId,
        stream_id: StreamId,
        data: Vec<u8>,
    },
    /// The remote closed its write side on a user stream.
    UserStreamRemoteWriteClosed { peer_id: PeerId, stream_id: StreamId },
    /// A user stream was fully closed.
    UserStreamClosed { peer_id: PeerId, stream_id: StreamId },
    /// A non-fatal error occurred.
    Error { message: String },
}

/// Opaque correlation handle for a pending outbound stream-open request.
///
/// The core emits it as part of [`SwarmAction::OpenStream`]; the driver
/// echoes it back unchanged when reporting the stream id (or failure) via
/// the core's `on_stream_opened` / `on_open_stream_failed` methods.
///
/// The token's numeric value is an implementation detail and meaningless
/// outside the core.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OpenStreamToken(pub(crate) u64);

/// Commands the swarm asks its driver to execute against the underlying
/// transport.
///
/// `Listen` and `Dial` are handled by the driver directly (they need to
/// allocate connection ids and interact with the transport synchronously)
/// and do not appear here.
#[derive(Clone, Debug)]
pub enum SwarmAction {
    /// Open a new outbound stream on the given connection.
    ///
    /// The driver calls `transport.open_stream(conn_id)`. On success it
    /// reports the allocated stream id back to the core via
    /// `on_stream_opened(conn_id, stream_id, token, now_ms)`. On failure it
    /// reports the error via `on_open_stream_failed(token, error, now_ms)`.
    /// The driver must echo `token` unchanged.
    OpenStream {
        conn_id: ConnectionId,
        token: OpenStreamToken,
    },
    /// Send bytes on an existing stream.
    SendStream {
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    },
    /// Half-close our write side on a stream.
    CloseStreamWrite {
        conn_id: ConnectionId,
        stream_id: StreamId,
    },
    /// Abruptly reset a stream in both directions.
    ResetStream {
        conn_id: ConnectionId,
        stream_id: StreamId,
    },
    /// Gracefully close a connection.
    CloseConnection { conn_id: ConnectionId },
}

/// Errors returned by the sans-I/O core for application-driven operations.
///
/// Transport-originated errors are surfaced as [`SwarmEvent::Error`]; this
/// type covers the cases where an API call is rejected synchronously.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SwarmError {
    /// The peer is not currently connected.
    #[error("peer {peer_id} is not connected")]
    NotConnected { peer_id: PeerId },
    /// A user protocol id was used before registering it.
    #[error("user protocol '{protocol_id}' is not registered")]
    ProtocolNotRegistered { protocol_id: String },
    /// The ping state machine rejected the request (e.g. a ping is already
    /// in flight on the target peer).
    #[error("ping error: {reason}")]
    PingError { reason: String },
    /// The identify state machine rejected the request.
    #[error("identify error: {reason}")]
    IdentifyError { reason: String },
}
