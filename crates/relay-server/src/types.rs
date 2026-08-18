use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::PeerId;
use minip2p_relay::Status;
use minip2p_swarm::ConnectionCloseCause;
use minip2p_transport::{ConnectionId, StreamId};

/// Exact identity of a transport stream.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StreamKey {
    /// Owning transport connection.
    pub conn_id: ConnectionId,
    /// Stream id within that connection.
    pub stream_id: StreamId,
}

/// Opaque correlation token echoed with a driver result.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RelayServerToken(pub(crate) u64);

/// I/O operation requested from the relay server's host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayServerAction {
    /// Open and negotiate a protocol on an exact connection.
    OpenStream {
        /// Correlation token echoed to `stream_open_result`.
        token: RelayServerToken,
        /// Remote peer expected on the connection.
        peer_id: PeerId,
        /// Connection on which the stream must land.
        expected_conn_id: ConnectionId,
        /// Multistream-select protocol id to negotiate.
        protocol_id: String,
    },
    /// Queue a complete byte chunk on a stream.
    SendStream {
        /// Correlation token echoed to `send_stream_result`.
        token: RelayServerToken,
        /// Remote peer owning the stream.
        peer_id: PeerId,
        /// Exact destination stream.
        stream: StreamKey,
        /// Complete chunk whose acceptance is reported atomically.
        data: Vec<u8>,
    },
    /// Half-close the local write side.
    CloseStreamWrite {
        /// Correlation token echoed to `close_stream_write_result`.
        token: RelayServerToken,
        /// Remote peer owning the stream.
        peer_id: PeerId,
        /// Exact stream to half-close.
        stream: StreamKey,
    },
    /// Abruptly reset a stream.
    ResetStream {
        /// Correlation token echoed to `reset_stream_result`.
        token: RelayServerToken,
        /// Remote peer owning the stream.
        peer_id: PeerId,
        /// Exact stream to reset.
        stream: StreamKey,
    },
}

/// Exactly-once terminal reason for a committed reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationCloseReason {
    /// Its monotonic deadline became due.
    Expired,
    /// Its owning transport connection closed.
    ConnectionClosed,
    /// A replacement connection became active for the peer.
    Superseded,
    /// An invariant failure forced stable lifecycle termination.
    InternalFailure,
}

/// Application-payload direction relative to the HOP CONNECT requester.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitDirection {
    /// HOP requester to reserved destination.
    SourceToDestination,
    /// Reserved destination to HOP requester.
    DestinationToSource,
}

/// One transport leg of a circuit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitLeg {
    /// HOP requester leg.
    Source,
    /// Reserved destination's STOP leg.
    Destination,
}

/// Saturating accepted-byte totals for both circuit directions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CircuitByteCounts {
    /// Bytes accepted for forwarding from source to destination.
    pub source_to_destination: u64,
    /// Bytes accepted for forwarding from destination to source.
    pub destination_to_source: u64,
}

/// Exactly-once terminal reason for a committed circuit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitCloseReason {
    /// Both directions reached EOF after half-close propagation.
    Eof,
    /// A successfully accepted full chunk crossed a directional limit.
    ByteLimit {
        /// Direction whose accepted total crossed the limit.
        direction: CircuitDirection,
    },
    /// The committed circuit's monotonic duration became due.
    DurationLimit,
    /// One stream terminated abruptly.
    StreamReset {
        /// Leg which reset.
        leg: CircuitLeg,
    },
    /// The destination transport rejected a forwarding chunk.
    ForwardFailed {
        /// Direction whose destination rejected the chunk.
        direction: CircuitDirection,
    },
    /// A circuit's underlying connection left Swarm.
    ConnectionClosed {
        /// Leg carried by the closed connection.
        leg: CircuitLeg,
        /// Swarm's transport-versus-supersession cause.
        cause: ConnectionCloseCause,
    },
    /// An invariant failure forced stable lifecycle termination.
    InternalFailure,
}

/// Stable category for an asynchronous host/agent failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayServerRuntimeErrorKind {
    /// Opening or negotiating a STOP stream failed.
    OpenStream,
    /// A control or forwarding send was rejected.
    SendStream,
    /// A write-side close failed.
    CloseStream,
    /// A stream reset failed.
    ResetStream,
    /// The caller/agent action contract was violated.
    InternalInvariant,
}

/// Actionable diagnostic for an asynchronous operational failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayServerRuntimeError {
    /// Stable operation category.
    pub kind: RelayServerRuntimeErrorKind,
    /// Involved peer when known.
    pub peer_id: Option<PeerId>,
    /// Human-readable context without internal tokens or stream keys.
    pub detail: String,
}

/// Public reservation, circuit, denial, and diagnostic output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayServerEvent {
    /// A new reservation or renewal response entered the transport queue.
    ReservationAccepted {
        /// Reserving peer.
        peer_id: PeerId,
        /// Whether this replaced the same exact connection's reservation.
        renewed: bool,
        /// Optional saturating Unix metadata advertised on the wire.
        expires_unix_secs: Option<u64>,
    },
    /// A stable RESERVE denial decision.
    ReservationDenied {
        /// Peer whose request was denied.
        peer_id: PeerId,
        /// Exact response status.
        status: Status,
    },
    /// Exactly-once terminal event for a committed reservation.
    ReservationClosed {
        /// Peer whose reservation ended.
        peer_id: PeerId,
        /// Stable terminal reason.
        reason: ReservationCloseReason,
    },
    /// A stable CONNECT denial decision.
    CircuitDenied {
        /// HOP CONNECT requester.
        source_peer_id: PeerId,
        /// Peer named by CONNECT.
        destination_peer_id: PeerId,
        /// Exact HOP wire status selected by policy.
        status: Status,
    },
    /// Circuit commit after STOP and HOP success acceptance.
    CircuitOpened {
        /// HOP CONNECT requester.
        source_peer_id: PeerId,
        /// Reserved STOP peer.
        destination_peer_id: PeerId,
    },
    /// Exactly-once circuit terminal event with accepted-byte totals.
    CircuitClosed {
        /// HOP CONNECT requester.
        source_peer_id: PeerId,
        /// Reserved STOP peer.
        destination_peer_id: PeerId,
        /// Saturating totals at termination.
        bytes: CircuitByteCounts,
        /// Stable terminal reason.
        reason: CircuitCloseReason,
    },
    /// Asynchronous diagnostic that does not replace stable lifecycle events.
    Error(RelayServerRuntimeError),
}
