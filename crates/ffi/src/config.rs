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

/// Local-link mDNS discovery configuration.
#[derive(Clone, Debug, uniffi::Record)]
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

/// Pubsub routing engine selected at endpoint construction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, uniffi::Enum)]
pub enum PubsubRouter {
    /// Mesh-based gossipsub routing.
    #[default]
    Gossipsub,
    /// Flood-to-all-subscribers floodsub routing.
    Floodsub,
}

/// One enabled transport and the addresses it should listen on.
#[derive(Clone, Debug, uniffi::Record)]
pub struct TransportOptions {
    /// Exact listen multiaddresses, or transport defaults when absent.
    ///
    /// An explicitly empty list is rejected: omit this field for defaults or
    /// disable the transport by omitting it from [`EndpointConfig`].
    pub listen_addrs: Option<Vec<String>>,
}

/// Configuration used to construct an FFI endpoint.
#[derive(Clone, uniffi::Record)]
pub struct EndpointConfig {
    /// Identify agent version, or the crate-derived default when absent.
    pub agent_version: Option<String>,
    /// Relay peer addresses.
    pub relays: Vec<String>,
    /// AutoNAT server peer addresses.
    pub autonat_servers: Vec<String>,
    /// QUIC configuration, or no QUIC transport when absent.
    pub quic: Option<TransportOptions>,
    /// TCP configuration, or no TCP transport when absent.
    pub tcp: Option<TransportOptions>,
    /// Whether connection attempts must remain relayed.
    pub force_relay: bool,
    /// Whether unsigned pubsub messages are accepted.
    pub allow_unsigned: bool,
    /// Pubsub routing engine.
    pub pubsub_router: PubsubRouter,
    /// Application protocol ids registered before the endpoint starts.
    pub protocols: Vec<String>,
    /// Signed-discovery settings, or no discovery when absent.
    pub discovery: Option<DiscoveryOptions>,
    /// Local-link mDNS settings, or no mDNS discovery when absent.
    pub mdns: Option<MdnsOptions>,
}

/// One peer in the shared discovery address book.
#[derive(Clone, Debug, uniffi::Record)]
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
#[derive(Clone, Debug, uniffi::Record)]
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
            .field("quic", &self.quic)
            .field("tcp", &self.tcp)
            .field("force_relay", &self.force_relay)
            .field("allow_unsigned", &self.allow_unsigned)
            .field("pubsub_router", &self.pubsub_router)
            .field("protocols", &self.protocols)
            .field("discovery", &self.discovery)
            .field("mdns", &self.mdns)
            .finish()
    }
}
