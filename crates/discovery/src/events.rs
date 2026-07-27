//! Caller-facing actions, events, observations, and address-book records.

use alloc::{string::String, vec::Vec};
use minip2p_core::{Multiaddr, PeerId};

/// The mechanism that contributed a discovery observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoverySource {
    /// A public-key-authenticated pubsub presence beacon.
    SignedBeacon,
    /// An unauthenticated local-link mDNS claim.
    Mdns,
}

/// A validated signed-beacon observation ready for the shared peer book.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observation {
    /// Authenticated publisher identity.
    pub peer: PeerId,
    /// Normalized transport addresses in publisher preference order.
    pub addrs: Vec<Multiaddr>,
}

/// Work emitted by [`BeaconAgent`](crate::BeaconAgent).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BeaconAction {
    /// Publish a presence beacon. Backpressure may be dropped until the next interval.
    PublishBeacon {
        /// Pubsub topic to publish on.
        topic: String,
        /// Encoded [`Beacon`](crate::Beacon) payload.
        payload: Vec<u8>,
    },
}

/// Validated output emitted by [`BeaconAgent`](crate::BeaconAgent).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BeaconEvent {
    /// A signed beacon was authenticated and normalized.
    Observation(Observation),
    /// A signed-beacon claim failed wire or identity validation.
    ProtocolViolation {
        /// Publisher of the rejected pubsub message.
        peer: PeerId,
        /// Human-readable rejection cause.
        reason: String,
    },
}

/// Work emitted by [`PeerDiscoveryAgent`](crate::PeerDiscoveryAgent).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryAction {
    /// Start a connection attempt and report its outcome to the agent.
    Dial {
        /// Peer to connect to.
        peer: PeerId,
        /// Normalized transport-shaped candidates in source preference order.
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
    /// An observation introduced a peer.
    PeerDiscovered {
        /// Discovered peer.
        peer: PeerId,
        /// Current merged address snapshot. mDNS entries are unauthenticated.
        addrs: Vec<Multiaddr>,
        /// Source of the observation that produced this transition.
        source: DiscoverySource,
    },
    /// An observation changed addresses, provenance, or source presence.
    PeerUpdated {
        /// Updated peer.
        peer: PeerId,
        /// Current merged address snapshot. mDNS entries are unauthenticated.
        addrs: Vec<Multiaddr>,
        /// Source of the observation that produced this transition.
        source: DiscoverySource,
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
    /// A source made a recognizable but invalid discovery claim.
    ProtocolViolation {
        /// Claimed peer, when one could be identified.
        peer: Option<PeerId>,
        /// Source carrying the invalid claim.
        source: DiscoverySource,
        /// Human-readable rejection cause.
        reason: String,
        /// Additional violations folded into this pending event.
        suppressed: u32,
    },
}

/// Snapshot of one entry in the shared discovery address book.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnownPeer {
    /// Claimed peer identity.
    pub peer: PeerId,
    /// Merged dial order: signed beacon addresses first, then mDNS addresses.
    ///
    /// Not every address is authenticated. Consult `beacon_addrs` and
    /// `mdns_addrs` when provenance matters.
    pub addrs: Vec<Multiaddr>,
    /// Public-key-authenticated addresses from signed beacons.
    pub beacon_addrs: Vec<Multiaddr>,
    /// Unauthenticated addresses claimed over local-link mDNS.
    pub mdns_addrs: Vec<Multiaddr>,
    /// Last accepted signed-beacon timestamp, including address-less beacons.
    pub beacon_last_seen_ms: Option<u64>,
    /// Most recent mDNS observation timestamp across retained addresses.
    pub mdns_last_seen_ms: Option<u64>,
    /// Whether the surrounding swarm currently has a connection.
    pub connected: bool,
}
