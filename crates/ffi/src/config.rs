//! UniFFI mirrors for endpoint configuration.

use minip2p_ffi_core as core;

/// UniFFI mirror of the core signed-discovery options.
pub type DiscoveryOptions = core::DiscoveryOptions;
/// UniFFI mirror of the core transport options.
pub type TransportOptions = core::TransportOptions;
/// UniFFI mirror of the core endpoint configuration.
pub type EndpointConfig = core::EndpointConfig;
/// UniFFI mirror of the core mDNS options.
pub type MdnsOptions = core::MdnsOptions;
/// UniFFI mirror of a known-peer snapshot.
pub type KnownPeerInfo = core::KnownPeerInfo;
/// UniFFI mirror of an active relay reservation.
pub type RelayReservationInfo = core::RelayReservationInfo;

/// Signed-discovery configuration.
#[uniffi::remote(Record)]
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

/// Local-link mDNS discovery configuration.
#[uniffi::remote(Record)]
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

/// One enabled transport and the addresses it should listen on.
#[uniffi::remote(Record)]
pub struct TransportOptions {
    /// Exact listen multiaddresses, or transport defaults when absent.
    ///
    /// An explicitly empty list is rejected: omit this field for defaults or
    /// disable the transport by omitting it from [`EndpointConfig`].
    pub listen_addrs: Option<Vec<String>>,
}

/// Configuration used to construct an FFI endpoint.
#[uniffi::remote(Record)]
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
    /// Application protocol ids registered before the endpoint starts.
    pub protocols: Vec<String>,
    /// Signed-discovery settings, or no discovery when absent.
    pub discovery: Option<DiscoveryOptions>,
    /// Local-link mDNS settings, or no mDNS discovery when absent.
    pub mdns: Option<MdnsOptions>,
}

/// One peer in the shared discovery address book.
#[uniffi::remote(Record)]
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
#[uniffi::remote(Record)]
pub struct RelayReservationInfo {
    /// Relay holding the reservation.
    pub relay_peer_id: String,
    /// Absolute relay-reported expiry, when present.
    pub expires_unix_secs: Option<u64>,
}
