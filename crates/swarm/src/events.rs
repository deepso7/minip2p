//! Event, action, and error types exposed by the swarm.
//!
//! Kept in a dedicated module so both the Sans-I/O core and the std driver
//! reference the same concrete types.

use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::{PeerAddr, PeerId};
use minip2p_identify::IdentifyMessage;
use minip2p_transport::{ConnectionId, StreamId, TransportEvent};

/// Events emitted by the swarm to the application.
#[derive(Clone, Debug)]
pub enum SwarmEvent {
    /// A peer went from disconnected to connected: its first connection was
    /// established and its identity verified.
    ConnectionEstablished {
        peer_id: PeerId,
        conn_id: ConnectionId,
    },
    /// The peer's last connection closed; the peer is now disconnected.
    ///
    /// A connection that is replaced never reports this; see
    /// [`ConnectionReplaced`](Self::ConnectionReplaced).
    ConnectionClosed {
        peer_id: PeerId,
        conn_id: ConnectionId,
    },
    /// A newer connection took the peer's single connection slot from `old`.
    ///
    /// The peer stays connected throughout: this takes the place of both a
    /// `ConnectionClosed` for `old` and a `ConnectionEstablished` for `new`.
    /// Everything that belonged to `old` ends with it, without per-stream
    /// terminal events: its streams, pending opens, readiness and Identify
    /// info. The swarm re-identifies the peer on `new`, so a fresh
    /// [`PeerReady`](Self::PeerReady) follows for `new`; until then the peer
    /// is connected but not ready. A ping pending or in flight on `old` is
    /// re-sent on `new`. The event is delivered before the transport is asked
    /// to close `old`.
    ///
    /// The newest connection wins, except in a simultaneous dial: a direct
    /// connection in the opposite direction to a direct `old` that registered
    /// less than [`SIMULTANEOUS_DIAL_WINDOW_MS`](crate::SIMULTANEOUS_DIAL_WINDOW_MS)
    /// ago replaces it only if the lower peer id dialed it. Otherwise it is
    /// closed without any event, so both peers keep the same connection.
    ConnectionReplaced {
        peer_id: PeerId,
        old: ConnectionId,
        new: ConnectionId,
    },
    /// Identify information received from a remote peer.
    IdentifyReceived {
        peer_id: PeerId,
        info: IdentifyMessage,
    },
    /// A peer is ready for application-level operations on `conn_id`.
    ///
    /// This fires after the swarm has a stable peer id for the connection and
    /// has processed the first Identify message on it. At this point callers
    /// can safely use protocol-specific APIs without racing peer-id migration
    /// or unknown protocol support. Readiness belongs to a connection: it
    /// fires once per connection, so after a
    /// [`ConnectionReplaced`](Self::ConnectionReplaced) it fires again for
    /// the new connection. A `PeerReady` whose `conn_id` is no longer the
    /// peer's current connection is stale.
    PeerReady {
        peer_id: PeerId,
        conn_id: ConnectionId,
        protocols: Vec<String>,
    },
    /// A ping RTT measurement completed.
    PingRttMeasured { peer_id: PeerId, rtt_ms: u64 },
    /// A ping timed out.
    PingTimeout { peer_id: PeerId },
    /// A user-registered protocol was successfully negotiated on a stream.
    /// `initiated_locally` is `true` when we opened the stream and `false`
    /// when the remote peer did.
    StreamReady {
        peer_id: PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        protocol_id: String,
        initiated_locally: bool,
    },
    /// Raw data arrived on a negotiated user stream.
    StreamData {
        peer_id: PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    },
    /// The remote closed its write side on a user stream.
    StreamRemoteWriteClosed {
        peer_id: PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
    },
    /// The remote asked us to stop sending on a user stream.
    ///
    /// Writes to the stream now fail and any queued bytes were dropped; the
    /// read side stays open until `StreamClosed`. Only QUIC emits this.
    StreamWriteStopped {
        peer_id: PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        error_code: u64,
    },
    /// A user stream was fully closed.
    StreamClosed {
        peer_id: PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
    },
    /// A non-fatal runtime error occurred.
    Error(SwarmRuntimeError),
    /// An outbound dial's connection closed before it was established.
    ///
    /// Raw [`crate::SwarmRuntime::dial`] callers see this for a refused or
    /// aborted-too-late handshake. Connection-attempt engines consume the
    /// events they own and never surface them as application diagnostics of
    /// their own; [`crate::SwarmRuntime::abort_dial`] forgets the dial first
    /// so no `DialFailed` follows.
    DialFailed {
        conn_id: ConnectionId,
        addr: PeerAddr,
        reason: String,
    },
}

impl SwarmEvent {
    /// The peer this event names; `None` for [`DialFailed`](Self::DialFailed)
    /// and errors without a peer.
    pub fn peer_id(&self) -> Option<&PeerId> {
        match self {
            Self::ConnectionEstablished { peer_id, .. }
            | Self::ConnectionClosed { peer_id, .. }
            | Self::ConnectionReplaced { peer_id, .. }
            | Self::IdentifyReceived { peer_id, .. }
            | Self::PeerReady { peer_id, .. }
            | Self::PingRttMeasured { peer_id, .. }
            | Self::PingTimeout { peer_id }
            | Self::StreamReady { peer_id, .. }
            | Self::StreamData { peer_id, .. }
            | Self::StreamRemoteWriteClosed { peer_id, .. }
            | Self::StreamWriteStopped { peer_id, .. }
            | Self::StreamClosed { peer_id, .. } => Some(peer_id),
            Self::Error(error) => error.peer_id.as_ref(),
            Self::DialFailed { .. } => None,
        }
    }

    /// Returns `true` if this is a stream-scoped event
    /// ([`StreamReady`](Self::StreamReady), [`StreamData`](Self::StreamData),
    /// [`StreamRemoteWriteClosed`](Self::StreamRemoteWriteClosed),
    /// [`StreamWriteStopped`](Self::StreamWriteStopped), or
    /// [`StreamClosed`](Self::StreamClosed)) for the given peer, connection,
    /// and stream id.
    ///
    /// Useful for filtering queued events that belong to a stream being torn
    /// down. Stream ids are per connection, so the connection must match too.
    pub fn matches_stream(
        &self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> bool {
        matches!(
            self,
            Self::StreamReady { peer_id: peer, conn_id: conn, stream_id: stream, .. }
                | Self::StreamData { peer_id: peer, conn_id: conn, stream_id: stream, .. }
                | Self::StreamRemoteWriteClosed { peer_id: peer, conn_id: conn, stream_id: stream, .. }
                | Self::StreamWriteStopped { peer_id: peer, conn_id: conn, stream_id: stream, .. }
                | Self::StreamClosed { peer_id: peer, conn_id: conn, stream_id: stream, .. }
                if peer == peer_id && *conn == conn_id && *stream == stream_id
        )
    }
}

/// Structured runtime error emitted through [`SwarmEvent::Error`].
///
/// This keeps the Sans-I/O core testable without string matching while still
/// carrying a human-readable detail for logs and CLIs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwarmRuntimeError {
    /// Broad subsystem that produced the error.
    pub kind: SwarmErrorKind,
    /// Remote peer involved, if known at the swarm layer.
    pub peer_id: Option<PeerId>,
    /// Transport connection involved, if known.
    pub conn_id: Option<ConnectionId>,
    /// Transport stream involved, if known.
    ///
    /// Outbound open and multistream negotiation failures populate this so
    /// callers can correlate an asynchronous error with the exact open.
    pub stream_id: Option<StreamId>,
    /// Human-readable context for logs and diagnostics.
    pub detail: String,
}

/// Machine-testable runtime error category.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SwarmErrorKind {
    /// Underlying transport operation or event failed.
    Transport,
    /// Multistream-select negotiation failed.
    Multistream,
    /// Identify protocol failed.
    Identify,
    /// Ping protocol failed.
    Ping,
    /// Identify stream setup was rejected.
    IdentifyStreamRejected,
    /// Outbound stream opening failed.
    OpenStreamFailed,
    /// The remote peer did not support the requested protocol.
    UnsupportedProtocol,
    /// The swarm driver violated the core/driver contract.
    Driver,
}

/// Opaque correlation handle for a pending outbound stream-open request.
///
/// The core emits it as part of [`SwarmAction::OpenStream`]; the driver
/// echoes it back unchanged when reporting the stream id (or failure) via
/// [`SwarmInput::StreamOpened`] / [`SwarmInput::OpenStreamFailed`].
///
/// The token's numeric value is an implementation detail and meaningless
/// outside the core.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OpenStreamToken(pub(crate) u64);

/// Inputs accepted by the Sans-I/O swarm core.
///
/// A custom runtime feeds exactly one input, then drains [`SwarmOutput`] values
/// through `SwarmCore::poll_output()` before feeding the next input.
#[derive(Clone, Debug)]
pub enum SwarmInput {
    /// An event produced by the underlying transport.
    Transport {
        event: TransportEvent,
        /// Monotonic milliseconds supplied by the driver.
        now_ms: u64,
    },
    /// Time advanced; used for protocol timers such as ping timeouts.
    Tick {
        /// Monotonic milliseconds supplied by the driver.
        now_ms: u64,
    },
    /// The driver successfully opened an outbound stream requested by
    /// [`SwarmAction::OpenStream`].
    StreamOpened {
        conn_id: ConnectionId,
        stream_id: StreamId,
        token: OpenStreamToken,
        /// Monotonic milliseconds supplied by the driver.
        now_ms: u64,
    },
    /// The driver failed to open an outbound stream requested by
    /// [`SwarmAction::OpenStream`].
    OpenStreamFailed {
        token: OpenStreamToken,
        reason: String,
        /// Monotonic milliseconds supplied by the driver.
        now_ms: u64,
    },
    /// A non-fatal runtime error observed by the driver while executing a
    /// [`SwarmAction`].
    RuntimeError(SwarmRuntimeError),
}

/// Outputs produced by the Sans-I/O swarm core.
#[derive(Clone, Debug)]
pub enum SwarmOutput {
    /// A command the runtime must execute against its transport.
    Action(SwarmAction),
    /// An application-visible event.
    Event(SwarmEvent),
}

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
    /// [`SwarmInput::StreamOpened`]. On failure it reports the error via
    /// [`SwarmInput::OpenStreamFailed`].
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
    /// A built-in protocol id was registered as a user protocol.
    ///
    /// Inbound routing gives built-in handlers precedence over user
    /// protocols, so a user registration under a reserved id could never
    /// receive traffic. See [`crate::RESERVED_PROTOCOL_IDS`].
    #[error("protocol '{protocol_id}' is reserved for the swarm's built-in handlers")]
    ReservedProtocol { protocol_id: String },
    /// The peer has completed Identify and did not advertise the requested protocol.
    #[error("peer {peer_id} does not support user protocol '{protocol_id}'")]
    RemoteDoesNotSupport {
        peer_id: PeerId,
        protocol_id: String,
    },
    /// A caller tried to use a user stream that is not currently negotiated
    /// on the requested connection, or that connection is no longer the
    /// peer's (it closed or was replaced).
    #[error("user stream {stream_id} on connection {conn_id} for peer {peer_id} is not active")]
    StreamNotFound {
        /// Peer the caller expected the stream to belong to.
        peer_id: PeerId,
        /// Connection the caller expected the stream to live on.
        conn_id: ConnectionId,
        /// Stream id supplied by the caller.
        stream_id: StreamId,
    },
    /// The ping state machine rejected the request (e.g. a ping is already
    /// in flight on the target peer).
    #[error("ping error: {reason}")]
    PingError { reason: String },
}
