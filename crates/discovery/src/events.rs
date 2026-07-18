//! Caller-facing actions, events, and address-book records.

use alloc::{string::String, vec::Vec};
use minip2p_core::{Multiaddr, PeerId};

/// Work emitted by [`DiscoveryAgent`](crate::DiscoveryAgent).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryAction {
    /// Publish a presence beacon. Backpressure may be dropped until the next interval.
    PublishBeacon {
        /// Pubsub topic to publish on.
        topic: String,
        /// Encoded [`Beacon`](crate::Beacon) payload.
        payload: Vec<u8>,
    },
    /// Start a connection attempt and report its outcome to the agent.
    Dial {
        /// Peer to connect to.
        peer: PeerId,
        /// Normalized transport-shaped candidates in sender preference order.
        addrs: Vec<Multiaddr>,
    },
    /// Cancel queued or in-flight dialing because the peer was removed.
    CancelDial {
        /// Peer whose attempt should be cancelled.
        peer: PeerId,
    },
}

/// Application-facing discovery state changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryEvent {
    /// A valid beacon introduced a peer.
    PeerDiscovered {
        /// Discovered peer.
        peer: PeerId,
        /// Current normalized address snapshot.
        addrs: Vec<Multiaddr>,
    },
    /// A valid beacon replaced a peer's address snapshot.
    PeerUpdated {
        /// Updated peer.
        peer: PeerId,
        /// Replacement normalized address snapshot.
        addrs: Vec<Multiaddr>,
    },
    /// A peer expired or was evicted from the bounded book.
    PeerExpired {
        /// Removed peer.
        peer: PeerId,
    },
    /// An automatic dial failed.
    DialFailed {
        /// Peer that could not be reached.
        peer: PeerId,
        /// Human-readable failure cause.
        reason: String,
    },
    /// A beacon failed wire or identity validation.
    ProtocolViolation {
        /// Publisher of the rejected pubsub message.
        peer: PeerId,
        /// Human-readable rejection cause.
        reason: String,
    },
}

/// Snapshot of one entry in the discovery address book.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnownPeer {
    /// Peer identity authenticated by its beacon public key.
    pub peer: PeerId,
    /// Most recently advertised normalized addresses.
    pub addrs: Vec<Multiaddr>,
    /// Caller-supplied timestamp of the last valid beacon.
    pub last_seen_ms: u64,
    /// Whether the surrounding swarm currently has a connection.
    pub connected: bool,
}
