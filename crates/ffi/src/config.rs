//! Foreign-facing endpoint configuration.

use std::fmt;

/// Signed-discovery configuration.
#[derive(Clone, uniffi::Record)]
pub struct DiscoveryOptions {
    /// Pubsub topic carrying signed discovery beacons.
    pub topic: String,
    /// Milliseconds between local beacon announcements.
    pub beacon_interval_ms: u64,
    /// Milliseconds before a signed peer observation expires.
    pub peer_ttl_ms: u64,
    /// Whether accepted observations may trigger automatic dials.
    pub auto_dial: bool,
}

impl fmt::Debug for DiscoveryOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveryOptions")
            .field("topic", &self.topic)
            .field("beacon_interval_ms", &self.beacon_interval_ms)
            .field("peer_ttl_ms", &self.peer_ttl_ms)
            .field("auto_dial", &self.auto_dial)
            .finish()
    }
}

/// Configuration used to construct an FFI endpoint.
#[derive(Clone, uniffi::Record)]
pub struct EndpointConfig {
    /// Identify agent version, or the crate-derived default when absent.
    pub agent_version: Option<String>,
    /// Relay peer addresses.
    pub relays: Vec<String>,
    /// QUIC listen multiaddress, or dual-stack wildcard binding when absent.
    pub listen_addr: Option<String>,
    /// Whether connection attempts must remain relayed.
    pub force_relay: bool,
    /// Whether unsigned pubsub messages are accepted.
    pub allow_unsigned: bool,
    /// Signed-discovery settings, or no discovery when absent.
    pub discovery: Option<DiscoveryOptions>,
}

impl fmt::Debug for EndpointConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EndpointConfig")
            .field("agent_version", &self.agent_version)
            .field("relays", &self.relays)
            .field("listen_addr", &self.listen_addr)
            .field("force_relay", &self.force_relay)
            .field("allow_unsigned", &self.allow_unsigned)
            .field("discovery", &self.discovery)
            .finish()
    }
}
