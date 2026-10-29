use alloc::string::String;

use minip2p_core::PeerId;
use minip2p_relay::Status;
use minip2p_transport::{ConnectionId, StreamId};

use crate::{RelayServerAddrSource, RelayServerAddressError};

/// Exact identity of a transport stream.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StreamKey {
    /// Owning transport connection.
    pub conn_id: ConnectionId,
    /// Stream id within that connection.
    pub stream_id: StreamId,
}

/// Exactly-once terminal reason for a committed reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationCloseReason {
    /// Its monotonic deadline became due.
    Expired,
    /// Its owning transport connection closed, or was replaced by a relay
    /// circuit. A direct replacement instead rebinds the reservation.
    ConnectionClosed,
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
    /// Accepted bytes crossed a directional limit.
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
    /// The destination transport rejected a forwarding chunk. A Full is
    /// backpressure, not a rejection: it pauses the direction instead.
    ForwardFailed {
        /// Direction whose destination rejected the chunk.
        direction: CircuitDirection,
    },
    /// A leg's underlying connection closed or was replaced.
    ConnectionClosed {
        /// Leg carried by the closed connection.
        leg: CircuitLeg,
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
    /// An agent invariant failed.
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

/// Public reservation, circuit, denial, address-source, and diagnostic output.
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
    /// A host address refresh was rejected while `source` was healthy, or
    /// with a different error while it was already failing. The source's
    /// previously accepted addresses stay in effect until an accepted
    /// refresh; an identical repeated rejection queues nothing.
    AddrsRejected {
        /// Address source whose refresh was rejected.
        source: RelayServerAddrSource,
        /// First invalid address and why it was rejected.
        error: RelayServerAddressError,
    },
    /// The first accepted refresh of a `source` that was failing; later
    /// accepted refreshes queue nothing.
    AddrsRestored {
        /// Address source that accepted a refresh again.
        source: RelayServerAddrSource,
    },
    /// Asynchronous diagnostic that does not replace stable lifecycle events.
    Error(RelayServerRuntimeError),
}
