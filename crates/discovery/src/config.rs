//! Discovery source and shared peer-book configuration.

use alloc::string::{String, ToString};

use crate::{DISCOVERY_TOPIC, MAX_BEACON_ADDRS, MAX_TOPIC_LEN};

/// Shared address-book, expiry, and automatic-dial policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerDiscoveryConfig {
    /// Maximum number of peer records retained.
    pub max_known_peers: usize,
    /// Maximum addresses retained per source and exported after merging.
    ///
    /// A peer may retain up to twice this many addresses: this many signed
    /// beacon addresses and this many mDNS addresses. Exported and dialed
    /// snapshots contain at most this many, with signed addresses first.
    pub max_addrs_per_peer: usize,
    /// Whether accepted observations may trigger dial actions.
    pub auto_dial: bool,
    /// Whether only the lower peer id initiates a dial.
    pub dial_tie_break: bool,
    /// Delay after a failed dial before another unchanged observation can retry.
    pub redial_backoff_ms: u64,
    /// Milliseconds after the last valid signed beacon before that source expires.
    pub beacon_peer_ttl_ms: u64,
    /// Maximum accepted lifetime for an observed unauthenticated address.
    pub max_observed_ttl_ms: u64,
    /// Window used by both per-peer and global mDNS-triggered dial limits.
    pub mdns_dial_window_ms: u64,
    /// Maximum mDNS-triggered dials for one claimed peer in a window.
    pub max_mdns_dials_per_window: u32,
    /// Maximum mDNS-triggered dials across all claimed peers in a window.
    pub max_mdns_dials_per_window_global: u32,
    /// Maximum protocol-violation event slots retained while the caller is not draining.
    pub max_pending_violations: u32,
}

impl Default for PeerDiscoveryConfig {
    fn default() -> Self {
        Self {
            max_known_peers: 128,
            max_addrs_per_peer: 16,
            auto_dial: true,
            dial_tie_break: true,
            redial_backoff_ms: 30_000,
            beacon_peer_ttl_ms: 35_000,
            max_observed_ttl_ms: 360_000,
            mdns_dial_window_ms: 60_000,
            max_mdns_dials_per_window: 3,
            max_mdns_dials_per_window_global: 32,
            max_pending_violations: 4,
        }
    }
}

impl PeerDiscoveryConfig {
    /// Validates bounds required by the bounded book and caller-driven timer loop.
    pub fn validate(&self) -> Result<(), DiscoveryConfigError> {
        if self.max_known_peers == 0 {
            return Err(DiscoveryConfigError::ZeroMaxKnownPeers);
        }
        if self.max_addrs_per_peer == 0 {
            return Err(DiscoveryConfigError::ZeroMaxAddrs);
        }
        if self.beacon_peer_ttl_ms == 0 {
            return Err(DiscoveryConfigError::ZeroBeaconPeerTtl);
        }
        if self.max_observed_ttl_ms == 0 {
            return Err(DiscoveryConfigError::ZeroMaxObservedTtl);
        }
        if self.mdns_dial_window_ms == 0 {
            return Err(DiscoveryConfigError::ZeroMdnsDialWindow);
        }
        if self.max_mdns_dials_per_window == 0 || self.max_mdns_dials_per_window_global == 0 {
            return Err(DiscoveryConfigError::ZeroMdnsDialLimit);
        }
        if self.max_pending_violations == 0 {
            return Err(DiscoveryConfigError::ZeroPendingViolations);
        }
        Ok(())
    }
}

/// Signed pubsub beacon scheduling and encoding policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeaconConfig {
    /// Pubsub topic carrying discovery beacons.
    pub topic: String,
    /// Milliseconds between local beacons.
    pub beacon_interval_ms: u64,
    /// Maximum local addresses included in one beacon.
    pub max_announced_addrs: usize,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self {
            topic: DISCOVERY_TOPIC.to_string(),
            beacon_interval_ms: 10_000,
            max_announced_addrs: 16,
        }
    }
}

impl BeaconConfig {
    /// Validates bounds required by the beacon codec and timer loop.
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
        if self.max_announced_addrs == 0 || self.max_announced_addrs > MAX_BEACON_ADDRS {
            return Err(DiscoveryConfigError::InvalidMaxAnnouncedAddrs);
        }
        Ok(())
    }
}

/// Why a discovery component cannot be constructed from its configuration.
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
    /// The local announcement cap must fit the beacon wire-format bound.
    #[error("maximum announced addresses must be between 1 and MAX_BEACON_ADDRS")]
    InvalidMaxAnnouncedAddrs,
    /// The address book must have room for at least one peer.
    #[error("maximum known peers must be non-zero")]
    ZeroMaxKnownPeers,
    /// A peer source must have room for at least one address.
    #[error("maximum addresses per peer must be non-zero")]
    ZeroMaxAddrs,
    /// Signed-beacon presence must remain valid for a non-zero duration.
    #[error("beacon peer TTL must be non-zero")]
    ZeroBeaconPeerTtl,
    /// Observed mDNS addresses must have a non-zero maximum TTL.
    #[error("maximum observed TTL must be non-zero")]
    ZeroMaxObservedTtl,
    /// The mDNS dial-rate window must be non-zero.
    #[error("mDNS dial window must be non-zero")]
    ZeroMdnsDialWindow,
    /// Both mDNS dial-rate limits must permit at least one attempt.
    #[error("mDNS dial limits must be non-zero")]
    ZeroMdnsDialLimit,
    /// Violation coalescing needs at least one pending slot.
    #[error("maximum pending violations must be non-zero")]
    ZeroPendingViolations,
    /// The local identity cannot fit in a discovery beacon.
    #[error("local public key exceeds the discovery beacon payload budget")]
    LocalPublicKeyTooLarge,
}
