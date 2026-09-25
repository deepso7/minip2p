//! Foreign-facing endpoint configuration.

use std::fmt;

/// Signed-discovery configuration.
#[derive(Clone)]
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

/// Local-link mDNS discovery configuration.
#[derive(Clone, Debug)]
pub struct MdnsOptions {
    /// Whether IPv6 interfaces and advertisements are enabled.
    pub enable_ipv6: bool,
    /// Positive record lifetime advertised on the wire, in milliseconds.
    pub ttl_ms: u64,
    /// Steady-state query interval, in milliseconds.
    pub query_interval_ms: u64,
    /// Maximum DNS/UDP payload emitted by the encoder.
    pub max_packet_bytes: u32,
    /// Maximum local addresses announced in one response burst.
    pub max_announced_addrs: u32,
    /// Interface re-enumeration interval, in milliseconds.
    pub interface_refresh_ms: u64,
    /// Maximum blocking wait before polling mDNS sockets again.
    pub socket_poll_interval_ms: u64,
    /// Whether accepted mDNS observations may trigger automatic dials.
    pub auto_dial: bool,
}

/// Configuration used to construct an FFI endpoint.
#[derive(Clone)]
pub struct EndpointConfig {
    /// Identify agent version, or the crate-derived default when absent.
    pub agent_version: Option<String>,
    /// Relay peer addresses.
    pub relays: Vec<String>,
    /// AutoNAT server peer addresses.
    pub autonat_servers: Vec<String>,
    /// Listen multiaddresses; each address's shape selects its transport
    /// (`/udp/<port>/quic-v1` or `/tcp/<port>`).
    ///
    /// Absent binds the QUIC dual-stack defaults (`/ip4/0.0.0.0/udp/0/quic-v1`
    /// and `/ip6/::/udp/0/quic-v1`). An explicit empty list is rejected.
    pub listen: Option<Vec<String>>,
    /// Whether connection attempts must remain relayed.
    pub force_relay: bool,
    /// Whether unsigned pubsub messages are accepted.
    pub allow_unsigned: bool,
    /// Application protocol ids registered before the endpoint starts.
    pub protocols: Vec<String>,
    /// Signed-discovery settings, or no discovery when absent.
    pub discovery: Option<DiscoveryOptions>,
    /// Local-link mDNS settings, or no mDNS discovery when absent.
    pub mdns: Option<MdnsOptions>,
}

/// One peer in the shared discovery address book.
#[derive(Clone, Debug)]
pub struct KnownPeerInfo {
    /// Discovered peer.
    pub peer_id: String,
    /// Merged dial-order addresses.
    pub addrs: Vec<String>,
    /// Addresses authenticated by signed beacons.
    pub beacon_addrs: Vec<String>,
    /// Addresses learned from unauthenticated mDNS.
    pub mdns_addrs: Vec<String>,
    /// Age of the most recent signed beacon.
    pub beacon_last_seen_age_ms: Option<u64>,
    /// Age of the most recent mDNS observation.
    pub mdns_last_seen_age_ms: Option<u64>,
    /// Whether the endpoint currently has a connection to this peer.
    pub connected: bool,
}

/// Snapshot of the active inbound relay reservation.
#[derive(Clone, Debug)]
pub struct RelayReservationInfo {
    /// Relay holding the reservation.
    pub relay_peer_id: String,
    /// Absolute relay-reported expiry, when present.
    pub expires_unix_secs: Option<u64>,
}

impl fmt::Debug for EndpointConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EndpointConfig")
            .field("agent_version", &self.agent_version)
            .field("relays", &self.relays)
            .field("autonat_servers", &self.autonat_servers)
            .field("listen", &self.listen)
            .field("force_relay", &self.force_relay)
            .field("allow_unsigned", &self.allow_unsigned)
            .field("protocols", &self.protocols)
            .field("discovery", &self.discovery)
            .field("mdns", &self.mdns)
            .finish()
    }
}
