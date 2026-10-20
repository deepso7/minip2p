//! Foreign-facing endpoint configuration.

use std::fmt;

/// Signed-discovery configuration.
#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
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
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
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
    /// Whether accepted mDNS observations may trigger automatic dials.
    pub auto_dial: bool,
}

/// Transport limit overrides.
///
/// Every field is optional: an absent record or field keeps the native
/// default, so an omitted record and an empty one behave identically. Limits
/// for a transport the endpoint does not bind (TCP without a `/tcp` listen
/// address, say) are ignored, not validated. An invalid limit fails
/// construction with `InvalidConfig { capability: Transport }`.
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct LimitsOptions {
    /// QUIC (and WebTransport) transport limits.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub quic: Option<QuicLimitsOptions>,
    /// TCP transport limits, including its connections' Yamux limits.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub tcp: Option<TcpLimitsOptions>,
    /// Relay circuits' Yamux limits; independent of [`TcpLimitsOptions::yamux`].
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub circuit: Option<YamuxOptions>,
    /// Most relayed circuits held at once (`NatConfig::max_circuits`): past
    /// it inbound circuits are refused and relay legs fail.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub max_circuits: Option<u64>,
}

/// QUIC overrides; each field mirrors `minip2p::QuicLimits`.
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct QuicLimitsOptions {
    /// Simultaneous connections, inbound and outbound.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub max_connections: Option<u64>,
    /// Locally initiated bidirectional streams per connection.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub max_streams_per_connection: Option<u64>,
    /// Bytes queued per stream beyond what the engine accepts; non-zero.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub max_pending_bytes_per_stream: Option<u64>,
    /// Bytes queued per connection beyond what the engine accepts; greater
    /// than `control_stream_reserve_bytes`.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub max_pending_connection_bytes: Option<u64>,
    /// Part of the connection queue only control streams may fill.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub control_stream_reserve_bytes: Option<u64>,
    /// UDP datagrams retained while the socket would block; non-zero.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub max_pending_datagrams: Option<u64>,
    /// Idle timeout advertised to peers, in milliseconds; non-zero.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub idle_timeout_ms: Option<u64>,
    /// Whether inbound connections need a stateless Retry first.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub require_address_validation: Option<bool>,
    /// Per-stream receive window in bytes; non-zero.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub stream_receive_window: Option<u64>,
    /// Per-connection receive window (unlimited by default).
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub connection_receive_window: Option<WindowLimit>,
    /// Bytes buffered per connection for sending; non-zero.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub send_window: Option<u64>,
    /// Time an `h3` connection has to complete Noise, in milliseconds;
    /// non-zero.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub webtransport_handshake_timeout_ms: Option<u64>,
}

/// TCP overrides; each field mirrors `minip2p::TcpConfig` (its connection-id
/// namespace stays internal).
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct TcpLimitsOptions {
    /// Connections held at once, dialed and accepted alike.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub max_connections: Option<u64>,
    /// How long a connection may take to authenticate.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub handshake_timeout_ms: Option<TimeoutLimit>,
    /// Encrypted bytes one connection holds for its socket.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub max_buffered_send: Option<u64>,
    /// How long a connection may hold bytes its socket refuses.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub send_stall_timeout_ms: Option<TimeoutLimit>,
    /// Each TCP connection's Yamux limits; independent of
    /// [`LimitsOptions::circuit`].
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub yamux: Option<YamuxOptions>,
}

/// Yamux overrides; each field mirrors `minip2p::YamuxConfig`.
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct YamuxOptions {
    /// Per-stream receive window in bytes; at least 256 KiB.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub receive_window: Option<u32>,
    /// Largest data-frame payload sent; non-zero.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub max_frame_len: Option<u32>,
    /// Streams tracked at once, counting unsettled closed ones.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub max_streams: Option<u64>,
    /// Per-stream cap on accepted, unpulled send bytes; non-zero.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub max_buffered_send: Option<u64>,
    /// Session-wide cap on accepted, unpulled send bytes; greater than
    /// `control_stream_reserve`.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub max_total_buffered_send: Option<u64>,
    /// Part of the session-wide cap only control streams may fill.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub control_stream_reserve: Option<u64>,
    /// Control frames that may wait to be pulled.
    #[cfg_attr(feature = "uniffi", uniffi(default))]
    pub max_pending_control: Option<u64>,
}

/// A receive window that may be unbounded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum WindowLimit {
    /// At most `bytes`.
    Bounded {
        /// Window size in bytes.
        bytes: u64,
    },
    /// No window.
    Unlimited,
}

/// A timeout that may be disabled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum TimeoutLimit {
    /// Fires after `ms` milliseconds.
    AfterMs {
        /// Timeout in milliseconds.
        ms: u64,
    },
    /// Waits indefinitely.
    Never,
}

/// Configuration used to construct an FFI endpoint.
#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
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
    /// Transport limit overrides, or every native default when absent.
    pub limits: Option<LimitsOptions>,
}

/// One peer in the shared discovery address book.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(rename_all = "camelCase")
)]
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
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub beacon_last_seen_age_ms: Option<u64>,
    /// Age of the most recent mDNS observation.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub mdns_last_seen_age_ms: Option<u64>,
    /// Whether the endpoint currently has a connection to this peer.
    pub connected: bool,
}

/// Snapshot of the active inbound relay reservation.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(rename_all = "camelCase")
)]
pub struct RelayReservationInfo {
    /// Relay holding the reservation.
    pub relay_peer_id: String,
    /// Absolute relay-reported expiry, when present.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
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
            .field("limits", &self.limits)
            .finish()
    }
}
