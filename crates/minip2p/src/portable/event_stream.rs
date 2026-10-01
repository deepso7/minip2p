//! Single Endpoint event stream type (ADR 0007).
//!
//! Connection, Identify, ping, stream, Connection-attempt, and enabled
//! capability (NAT, Gossipsub, Discovery, relay-server) transitions all leave
//! through [`EndpointEvent`].

use minip2p_core::{PeerAddr, PeerId};
use minip2p_swarm::{IdentifyMessage, SwarmEvent, SwarmRuntimeError};
use minip2p_transport::{ConnectionId, StreamId};

use super::connect::{ConnectId, ConnectOutcome};

/// Ordered application event from the Endpoint's single public stream.
///
/// Connection, Identify, ping, stream, raw-dial, Connection-attempt, and
/// enabled capability transitions leave through this enum.
///
/// Each event is emitted once. The order is fixed when the Endpoint queues
/// the event, and `poll` and `wait` preserve that queue order.
/// A Connection attempt's [`Self::ConnectSettled`] follows the
/// `ConnectionEstablished` it reports. No order is promised between
/// concurrently racing Transport candidates.
///
/// On the std endpoint, `poll` and `wait` finish each swarm event before
/// the next one: that swarm event, then capability events (relay-server,
/// NAT, Gossipsub, Discovery), then Connection-attempt terminals. Embedded
/// endpoints emit the same variants from their smoltcp loop and do not use
/// that step order.
///
/// Payloads move by value across the Endpoint boundary; callers own each
/// delivered event. Swarm variants keep the same names and fields as
/// [`SwarmEvent`], so existing `Event::PeerReady { .. }` patterns compile
/// unchanged. The enum is non-exhaustive because enabling a capability
/// feature adds variants.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum EndpointEvent {
    /// A peer went from disconnected to connected: its first connection was
    /// established and its identity verified.
    ConnectionEstablished {
        peer_id: PeerId,
        conn_id: ConnectionId,
    },
    /// The peer's last connection closed; the peer is now disconnected.
    ConnectionClosed {
        peer_id: PeerId,
        conn_id: ConnectionId,
    },
    /// A newer connection took the peer's single connection slot from `old`.
    ///
    /// The peer stays connected: this takes the place of a
    /// `ConnectionClosed` for `old` and a `ConnectionEstablished` for `new`.
    /// Every stream and pending open on `old` ends with it, without
    /// per-stream terminal events. Readiness belongs to a connection, so a
    /// fresh [`Self::PeerReady`] follows for `new` once it is identified.
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
    /// Fires once per connection. A `PeerReady` whose `conn_id` is no longer
    /// the peer's current connection (see [`Self::ConnectionReplaced`]) is
    /// stale.
    PeerReady {
        peer_id: PeerId,
        conn_id: ConnectionId,
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
    /// A raw swarm dial's connection closed before it was established.
    ///
    /// Raw dials are made on the lower-level swarm runtime (for example
    /// through `Endpoint::swarm_mut`), bypassing Connection-attempt policy.
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
    /// NAT traversal output: path transitions, reachability, and relay
    /// reservations.
    ///
    /// Attempt terminals travel only as [`Self::ConnectSettled`]:
    /// `NatEvent::ConnectFailed` and `NatEvent::FellBackToRelay` are consumed
    /// by the Connection-attempt engine and never appear here. A path
    /// transition such as `NatEvent::PathUpgraded` can still follow its
    /// attempt's `ConnectSettled` when the attempt settled on a provisional
    /// Relayed path first.
    #[cfg(feature = "_nat-driver")]
    Nat(minip2p_nat::NatEvent),
    /// Gossipsub output: messages, subscription changes, and diagnostics.
    /// Discovery-owned beacon-topic traffic never appears here.
    #[cfg(feature = "pubsub")]
    Gossipsub(minip2p_pubsub::GossipsubEvent),
    /// Discovery peer-book changes from signed beacons and mDNS.
    #[cfg(feature = "_discovery-driver")]
    Discovery(minip2p_discovery::DiscoveryEvent),
    /// Relay-service output: reservations, circuits, and runtime errors.
    #[cfg(feature = "relay-server")]
    RelayServer(minip2p_relay_server::RelayServerEvent),
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
                | Self::StreamWriteStopped { peer_id: peer, stream_id: stream, .. }
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
            SwarmEvent::ConnectionClosed { peer_id, conn_id } => {
                Self::ConnectionClosed { peer_id, conn_id }
            }
            SwarmEvent::ConnectionReplaced { peer_id, old, new } => {
                Self::ConnectionReplaced { peer_id, old, new }
            }
            SwarmEvent::IdentifyReceived { peer_id, info } => {
                Self::IdentifyReceived { peer_id, info }
            }
            SwarmEvent::PeerReady {
                peer_id,
                conn_id,
                protocols,
            } => Self::PeerReady {
                peer_id,
                conn_id,
                protocols,
            },

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
            SwarmEvent::StreamWriteStopped {
                peer_id,
                conn_id,
                stream_id,
                error_code,
            } => Self::StreamWriteStopped {
                peer_id,
                conn_id,
                stream_id,
                error_code,
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
