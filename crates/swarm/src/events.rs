//! Event, action, and error types exposed by the swarm.
//!
//! Kept in a dedicated module so both the Sans-I/O core and the std driver
//! reference the same concrete types.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::PeerId;
use minip2p_identify::IdentifyMessage;
use minip2p_transport::{ConnectionId, StreamId, TransportEvent};

/// Events emitted by the swarm to the application.
#[derive(Clone, Debug)]
pub enum SwarmEvent {
    /// A new connection was established and identity verified.
    ConnectionEstablished { peer_id: PeerId },
    /// A connection was closed.
    ConnectionClosed { peer_id: PeerId },
    /// Identify information received from a remote peer.
    IdentifyReceived {
        peer_id: PeerId,
        info: IdentifyMessage,
    },
    /// A peer is ready for application-level operations.
    ///
    /// This fires after the swarm has a stable peer id for the connection and
    /// has processed the first Identify message from that peer. At this point
    /// callers can safely use protocol-specific APIs without racing peer-id
    /// migration or unknown protocol support.
    PeerReady {
        peer_id: PeerId,
        protocols: Vec<String>,
    },
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
    UserStreamRemoteWriteClosed {
        peer_id: PeerId,
        stream_id: StreamId,
    },
    /// A user stream was fully closed.
    UserStreamClosed {
        peer_id: PeerId,
        stream_id: StreamId,
    },
    /// A non-fatal runtime error occurred.
    Error(SwarmRuntimeError),
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
    /// User-protocol stream failed.
    UserProtocol { protocol_id: String },
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
    /// for the requested peer.
    #[error("user stream {stream_id} for peer {peer_id} is not active")]
    UserStreamNotFound {
        /// Peer the caller expected the stream to belong to.
        peer_id: PeerId,
        /// Stream id supplied by the caller.
        stream_id: StreamId,
    },
    /// The ping state machine rejected the request (e.g. a ping is already
    /// in flight on the target peer).
    #[error("ping error: {reason}")]
    PingError { reason: String },
}
