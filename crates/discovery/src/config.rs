//! Discovery policy configuration.

use alloc::string::{String, ToString};

use crate::{DISCOVERY_TOPIC, MAX_BEACON_ADDRS, MAX_TOPIC_LEN};

/// Caller-controlled discovery cadence, address-book, and dialing policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryConfig {
    /// Pubsub topic carrying discovery beacons.
    pub topic: String,
    /// Milliseconds between local beacons.
    pub beacon_interval_ms: u64,
    /// Milliseconds after the last valid beacon before a peer expires.
    pub peer_ttl_ms: u64,
    /// Maximum number of peer records retained.
    pub max_known_peers: usize,
    /// Maximum normalized addresses retained and announced per peer.
    pub max_addrs_per_peer: usize,
    /// Whether accepted beacons may trigger dial actions.
    pub auto_dial: bool,
    /// Whether only the lower peer id initiates a dial.
    pub dial_tie_break: bool,
    /// Delay after a failed dial before unchanged beacons can retry.
    pub redial_backoff_ms: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            topic: DISCOVERY_TOPIC.to_string(),
            beacon_interval_ms: 10_000,
            peer_ttl_ms: 35_000,
            max_known_peers: 128,
            max_addrs_per_peer: 16,
            auto_dial: true,
            dial_tie_break: true,
            redial_backoff_ms: 30_000,
        }
    }
}

impl DiscoveryConfig {
    /// Validates bounds required by the codec and caller-driven timer loop.
    pub fn validate(&self) -> Result<(), DiscoveryConfigError> {
        if self.topic.is_empty() {
            return Err(DiscoveryConfigError::EmptyTopic);
        }
        if self.topic.len() > MAX_TOPIC_LEN {
            return Err(DiscoveryConfigError::TopicTooLong);
        }
        if self.beacon_interval_ms == 0 {
            return Err(DiscoveryConfigError::ZeroBeaconInterval);
        }
        if self.peer_ttl_ms == 0 {
            return Err(DiscoveryConfigError::ZeroPeerTtl);
        }
        if self.max_known_peers == 0 {
            return Err(DiscoveryConfigError::ZeroMaxKnownPeers);
        }
        if self.max_addrs_per_peer == 0 || self.max_addrs_per_peer > MAX_BEACON_ADDRS {
            return Err(DiscoveryConfigError::InvalidMaxAddrs);
        }
        Ok(())
    }
}

/// Why a [`DiscoveryConfig`] is invalid.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DiscoveryConfigError {
    /// The configured pubsub topic is empty.
    #[error("discovery topic must be non-empty")]
    EmptyTopic,
    /// The topic exceeds the pubsub topic bound.
    #[error("discovery topic exceeds the maximum length")]
    TopicTooLong,
    /// A zero interval would livelock a quiescence loop.
    #[error("beacon interval must be non-zero")]
    ZeroBeaconInterval,
    /// Peers must remain valid for a non-zero duration.
    #[error("peer TTL must be non-zero")]
    ZeroPeerTtl,
    /// The address book must have room for at least one peer.
    #[error("maximum known peers must be non-zero")]
    ZeroMaxKnownPeers,
    /// The per-peer address cap must fit the wire-format bound.
    #[error("maximum addresses per peer must be between 1 and MAX_BEACON_ADDRS")]
    InvalidMaxAddrs,
}
