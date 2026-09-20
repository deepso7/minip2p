//! Single Endpoint event stream type (ADR 0007).
//!
//! Base connection, Identify, ping, stream, and Connection-attempt transitions
//! leave through [`EndpointEvent`]. Capability-specific queues remain until a
//! later ticket folds them into this stream.

use minip2p_core::{PeerAddr, PeerId};
use minip2p_swarm::{ConnectionCloseCause, IdentifyMessage, SwarmEvent, SwarmRuntimeError};
use minip2p_transport::{ConnectionId, StreamId};

use super::connect::{ConnectId, ConnectOutcome};

/// Ordered application event from the Endpoint's single public stream.
///
/// Connection, Identify, ping, stream, raw-dial, and Connection-attempt
/// transitions leave through this enum. Prefer this name at the Endpoint
/// boundary. [`crate::Event`] is a migration alias for the same type. NAT,
/// pubsub, discovery, and relay-server output stay on focused queues until a
/// later ticket adds variants here.
///
/// Payloads move by value across the Endpoint boundary; callers own each
/// delivered event. Swarm variants keep the same names and fields as
/// [`SwarmEvent`], so existing `Event::PeerReady { .. }` patterns compile
/// unchanged.
#[derive(Clone, Debug)]
pub enum EndpointEvent {
    /// A new connection was established and identity verified.
    ConnectionEstablished {
        peer_id: PeerId,
        conn_id: ConnectionId,
    },
    /// A connection was closed.
    ConnectionClosed {
        peer_id: PeerId,
        conn_id: ConnectionId,
        cause: ConnectionCloseCause,
    },
    /// Identify information received from a remote peer.
    IdentifyReceived {
        peer_id: PeerId,
        info: IdentifyMessage,
    },
    /// A peer is ready for application-level operations.
    PeerReady {
        peer_id: PeerId,
        protocols: alloc::vec::Vec<alloc::string::String>,
    },
    /// A ping RTT measurement completed.
    PingRttMeasured { peer_id: PeerId, rtt_ms: u64 },
    /// A ping timed out.
    PingTimeout { peer_id: PeerId },
    /// A user-registered protocol was successfully negotiated on a stream.
    StreamReady {
        peer_id: PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        protocol_id: alloc::string::String,
        initiated_locally: bool,
    },
    /// Raw data arrived on a negotiated user stream.
    StreamData {
        peer_id: PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: alloc::vec::Vec<u8>,
    },
    /// The remote closed its write side on a user stream.
    StreamRemoteWriteClosed {
        peer_id: PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
    },
    /// A user stream was fully closed.
    StreamClosed {
        peer_id: PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
    },
    /// A non-fatal runtime error occurred.
    Error(SwarmRuntimeError),
    /// A raw `dial`'s connection closed before it was established.
    ///
    /// Attempt-owned dials never surface here; they become
    /// [`Self::ConnectSettled`] diagnostics.
    DialFailed {
        conn_id: ConnectionId,
        addr: PeerAddr,
        reason: alloc::string::String,
    },
    /// The one terminal event of a Connection attempt.
    ///
    /// On success, [`Self::ConnectionEstablished`] for the peer is delivered
    /// in the same drain before this Settled event (snapshot getters are true
    /// at both points).
    ConnectSettled {
        connect_id: ConnectId,
        peer_id: PeerId,
        outcome: ConnectOutcome,
    },
}

impl EndpointEvent {
    /// Returns `true` if this is a stream-scoped event for the given peer and
    /// stream id.
    pub fn matches_stream(&self, peer_id: &PeerId, stream_id: StreamId) -> bool {
        matches!(
            self,
            Self::StreamReady { peer_id: peer, stream_id: stream, .. }
                | Self::StreamData { peer_id: peer, stream_id: stream, .. }
                | Self::StreamRemoteWriteClosed { peer_id: peer, stream_id: stream, .. }
                | Self::StreamClosed { peer_id: peer, stream_id: stream, .. }
                if peer == peer_id && *stream == stream_id
        )
    }
}

impl From<SwarmEvent> for EndpointEvent {
    fn from(event: SwarmEvent) -> Self {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, conn_id } => {
                Self::ConnectionEstablished { peer_id, conn_id }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                conn_id,
                cause,
            } => Self::ConnectionClosed {
                peer_id,
                conn_id,
                cause,
            },
            SwarmEvent::IdentifyReceived { peer_id, info } => {
                Self::IdentifyReceived { peer_id, info }
            }
            SwarmEvent::PeerReady { peer_id, protocols } => Self::PeerReady { peer_id, protocols },
            SwarmEvent::PingRttMeasured { peer_id, rtt_ms } => {
                Self::PingRttMeasured { peer_id, rtt_ms }
            }
            SwarmEvent::PingTimeout { peer_id } => Self::PingTimeout { peer_id },
            SwarmEvent::StreamReady {
                peer_id,
                conn_id,
                stream_id,
                protocol_id,
                initiated_locally,
            } => Self::StreamReady {
                peer_id,
                conn_id,
                stream_id,
                protocol_id,
                initiated_locally,
            },
            SwarmEvent::StreamData {
                peer_id,
                conn_id,
                stream_id,
                data,
            } => Self::StreamData {
                peer_id,
                conn_id,
                stream_id,
                data,
            },
            SwarmEvent::StreamRemoteWriteClosed {
                peer_id,
                conn_id,
                stream_id,
            } => Self::StreamRemoteWriteClosed {
                peer_id,
                conn_id,
                stream_id,
            },
            SwarmEvent::StreamClosed {
                peer_id,
                conn_id,
                stream_id,
            } => Self::StreamClosed {
                peer_id,
                conn_id,
                stream_id,
            },
            SwarmEvent::Error(error) => Self::Error(error),
            SwarmEvent::DialFailed {
                conn_id,
                addr,
                reason,
            } => Self::DialFailed {
                conn_id,
                addr,
                reason,
            },
        }
    }
}
