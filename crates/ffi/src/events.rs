//! UniFFI mirrors for endpoint events.

use minip2p_ffi_core as core;

/// UniFFI mirror of a peer's Identify snapshot.
pub type IdentifyInfo = core::IdentifyInfo;
/// UniFFI mirror of an opened stream identity.
pub type OpenStreamResult = core::OpenStreamResult;
/// UniFFI mirror of the local reachability state.
pub type Reachability = core::Reachability;
/// UniFFI mirror of a usable connection path.
pub type PathKind = core::PathKind;
/// UniFFI mirror of a discovery observation source.
pub type DiscoverySource = core::DiscoverySource;
/// UniFFI mirror of an endpoint error category.
pub type EndpointErrorKind = core::EndpointErrorKind;
/// UniFFI mirror of a NAT failure category.
pub type NatErrorKind = core::NatErrorKind;
/// UniFFI mirror of a driver failure category.
pub type DriverFailureKind = core::DriverFailureKind;
/// UniFFI mirror of a flattened endpoint event.
pub type P2pEvent = core::P2pEvent;

/// Foreign-friendly snapshot of a peer's Identify message.
#[uniffi::remote(Record)]
pub struct IdentifyInfo {
    /// Protobuf-encoded libp2p public key, when supplied.
    pub public_key: Option<Vec<u8>>,
    /// Listen addresses advertised by the peer.
    pub listen_addrs: Vec<String>,
    /// Protocol ids advertised by the peer.
    pub protocols: Vec<String>,
    /// Address the peer observed for this endpoint, when supplied.
    pub observed_addr: Option<String>,
    /// Remote libp2p protocol version, when supplied.
    pub protocol_version: Option<String>,
    /// Remote agent version, when supplied.
    pub agent_version: Option<String>,
}

/// Full identity allocated for an outbound application stream.
#[uniffi::remote(Record)]
pub struct OpenStreamResult {
    /// Transport connection carrying the stream.
    pub conn_id: u64,
    /// Opaque stream id.
    pub stream_id: u64,
}

/// Coarse local reachability state.
#[uniffi::remote(Enum)]
pub enum Reachability {
    /// Not enough evidence is available.
    Unknown,
    /// The endpoint is directly reachable.
    Public,
    /// The endpoint needs traversal or relay assistance.
    Private,
}

/// Kind of usable connection path.
#[uniffi::remote(Enum)]
pub enum PathKind {
    /// A known address was dialed directly.
    DirectDialed,
    /// A direct path was established by hole punching.
    DirectPunched,
    /// Traffic is carried through a relay.
    Relayed {
        /// Relay carrying the circuit.
        relay_peer_id: String,
    },
}

/// Source that contributed a discovery observation.
#[uniffi::remote(Enum)]
pub enum DiscoverySource {
    /// Public-key-authenticated signed beacon.
    SignedBeacon,
    /// Unauthenticated local-link mDNS observation.
    Mdns,
}

/// Category of a non-fatal endpoint runtime error.
#[uniffi::remote(Enum)]
pub enum EndpointErrorKind {
    /// Underlying transport operation failed.
    Transport,
    /// Multistream negotiation failed.
    Multistream,
    /// Identify protocol failed.
    Identify,
    /// Ping protocol failed.
    Ping,
    /// Identify stream setup was rejected.
    IdentifyStreamRejected,
    /// Outbound stream opening failed.
    OpenStreamFailed,
    /// The remote does not support a requested protocol.
    UnsupportedProtocol,
    /// The swarm driver contract failed.
    Driver,
}

/// Category of a failed NAT connection attempt.
#[uniffi::remote(Enum)]
pub enum NatErrorKind {
    /// No usable direct or relayed path exists.
    NoPathAvailable,
    /// The connection attempt timed out.
    Timeout,
    /// A transport dial failed.
    DialFailed,
    /// A traversal protocol exchange failed.
    Protocol,
    /// A relay refused the circuit.
    RelayRefused,
}

/// Category of a fatal background-driver failure.
#[uniffi::remote(Enum)]
pub enum DriverFailureKind {
    /// The transport driver failed.
    Transport,
    /// The swarm driver failed.
    Swarm,
    /// An internal driver invariant failed.
    Invariant,
    /// The background pump panicked.
    Panic,
}

/// Event delivered by the native endpoint driver.
#[uniffi::remote(Enum)]
#[expect(
    clippy::large_enum_variant,
    reason = "UniFFI exports complete event payloads by value to foreign callers."
)]
pub enum P2pEvent {
    /// Native event carry overflow discarded source events.
    EventsDropped {
        /// Events discarded since the previous diagnostic.
        dropped: u64,
        /// Events discarded since this driver started.
        total_dropped: u64,
    },
    /// The background driver terminated after a fatal failure.
    DriverFailed {
        /// Machine-readable failure category.
        kind: DriverFailureKind,
        /// Human-readable diagnostic detail.
        detail: String,
    },
    /// A verified connection was established.
    ConnectionEstablished {
        /// Remote peer.
        peer_id: String,
        /// Endpoint-local transport connection id.
        conn_id: u64,
    },
    /// A connection closed.
    ConnectionClosed {
        /// Remote peer.
        peer_id: String,
        /// Endpoint-local transport connection id.
        conn_id: u64,
    },
    /// A peer completed Identify and is ready for application protocols.
    PeerReady {
        /// Remote peer.
        peer_id: String,
        /// Protocols advertised by the peer.
        protocols: Vec<String>,
    },
    /// A peer supplied a new Identify snapshot.
    IdentifyReceived {
        /// Remote peer.
        peer_id: String,
        /// Decoded Identify information.
        info: IdentifyInfo,
    },
    /// A ping round-trip measurement completed.
    PingRttMeasured {
        /// Remote peer.
        peer_id: String,
        /// Round-trip duration in milliseconds.
        rtt_ms: u64,
    },
    /// A ping timed out.
    PingTimeout {
        /// Remote peer.
        peer_id: String,
    },
    /// A custom application stream completed protocol negotiation.
    StreamReady {
        /// Remote peer.
        peer_id: String,
        /// Transport connection carrying the stream.
        conn_id: u64,
        /// Opaque stream id.
        stream_id: u64,
        /// Negotiated application protocol.
        protocol_id: String,
        /// Whether this endpoint initiated the stream.
        initiated_locally: bool,
    },
    /// Bytes arrived on a custom application stream.
    StreamData {
        /// Remote peer.
        peer_id: String,
        /// Transport connection carrying the stream.
        conn_id: u64,
        /// Opaque stream id.
        stream_id: u64,
        /// Received bytes.
        data: Vec<u8>,
    },
    /// The remote peer half-closed its stream write side.
    StreamRemoteWriteClosed {
        /// Remote peer.
        peer_id: String,
        /// Transport connection carrying the stream.
        conn_id: u64,
        /// Opaque stream id.
        stream_id: u64,
    },
    /// A custom application stream fully closed.
    StreamClosed {
        /// Remote peer.
        peer_id: String,
        /// Transport connection that carried the stream.
        conn_id: u64,
        /// Opaque stream id.
        stream_id: u64,
    },
    /// A non-fatal endpoint error occurred.
    EndpointError {
        /// Machine-readable category.
        kind: EndpointErrorKind,
        /// Remote peer, when known.
        peer_id: Option<String>,
        /// Transport connection, when known.
        conn_id: Option<u64>,
        /// Transport stream, when known.
        stream_id: Option<u64>,
        /// Human-readable diagnostic detail.
        detail: String,
    },
    /// The local reachability verdict changed.
    ReachabilityChanged {
        /// Previous verdict.
        previous: Reachability,
        /// Current verdict.
        current: Reachability,
        /// AutoNAT-confirmed public addresses.
        confirmed_addrs: Vec<String>,
    },
    /// AutoNAT confirmed a changed public address set.
    PublicAddressesChanged {
        /// Current public addresses.
        addrs: Vec<String>,
    },
    /// A relay reservation was acquired or renewed.
    RelayReserved {
        /// Relay holding the reservation.
        relay_peer_id: String,
        /// Absolute relay-reported expiry, when present.
        expires_unix_secs: Option<u64>,
    },
    /// A relay reservation was lost.
    RelayReservationLost {
        /// Relay that held the reservation.
        relay_peer_id: String,
    },
    /// The first usable path for an attempt became available.
    PathEstablished {
        /// Endpoint-local connection-attempt id.
        connect_id: u64,
        /// Remote peer.
        peer_id: String,
        /// Established path.
        path: PathKind,
    },
    /// An inbound relay circuit became a usable path.
    InboundPathEstablished {
        /// Remote peer.
        peer_id: String,
        /// Established relayed path.
        path: PathKind,
    },
    /// A better path replaced an earlier path.
    PathUpgraded {
        /// Endpoint-local connection-attempt id.
        connect_id: u64,
        /// Remote peer.
        peer_id: String,
        /// Previous path.
        from: PathKind,
        /// Replacement path.
        to: PathKind,
    },
    /// One hole-punch window failed.
    HolePunchFailed {
        /// Endpoint-local connection-attempt id.
        connect_id: u64,
        /// One-based attempt number.
        attempt: u32,
        /// Human-readable failure detail.
        reason: String,
    },
    /// Direct upgrade attempts ended with the relay path retained.
    FellBackToRelay {
        /// Endpoint-local connection-attempt id.
        connect_id: u64,
        /// Remote peer.
        peer_id: String,
    },
    /// A connection attempt ended without a usable path.
    ConnectFailed {
        /// Endpoint-local connection-attempt id.
        connect_id: u64,
        /// Remote peer.
        peer_id: String,
        /// Machine-readable failure category.
        kind: NatErrorKind,
        /// Human-readable failure detail.
        detail: String,
    },
    /// An inbound circuit upgraded to a direct connection.
    InboundDirectUpgrade {
        /// Remote peer.
        peer_id: String,
    },
    /// An accepted pubsub message arrived.
    ///
    /// When unsigned messages are enabled, `signed` can be `false`; hosts
    /// must treat both `from_peer_id` and `data` as unauthenticated unless
    /// `signed` is `true`.
    Message {
        /// Publisher identity.
        from_peer_id: String,
        /// Topics carried by the message.
        topics: Vec<String>,
        /// Application payload.
        data: Vec<u8>,
        /// Opaque publisher sequence number.
        seqno: Vec<u8>,
        /// Whether the message carried a verified signature.
        signed: bool,
    },
    /// A peer announced a subscription.
    PeerSubscribed {
        /// Remote peer.
        peer_id: String,
        /// Subscribed topic.
        topic: String,
    },
    /// A peer withdrew a subscription.
    PeerUnsubscribed {
        /// Remote peer.
        peer_id: String,
        /// Unsubscribed topic.
        topic: String,
    },
    /// Pubsub outbound work was discarded.
    PubsubOutboundFailure {
        /// Destination peer.
        peer_id: String,
        /// Human-readable failure detail.
        reason: String,
    },
    /// A peer violated the pubsub protocol.
    PubsubProtocolViolation {
        /// Offending peer.
        peer_id: String,
        /// Human-readable violation detail.
        reason: String,
    },
    /// Discovery introduced a peer.
    PeerDiscovered {
        /// Discovered peer.
        peer_id: String,
        /// Current merged address snapshot.
        addrs: Vec<String>,
        /// Observation source.
        source: DiscoverySource,
    },
    /// Discovery updated a peer.
    PeerUpdated {
        /// Updated peer.
        peer_id: String,
        /// Current merged address snapshot.
        addrs: Vec<String>,
        /// Observation source.
        source: DiscoverySource,
    },
    /// A discovered peer expired or was evicted.
    PeerExpired {
        /// Removed peer.
        peer_id: String,
    },
    /// An automatic discovery dial failed.
    DiscoveryDialFailed {
        /// Peer that could not be reached.
        peer_id: String,
        /// Human-readable failure detail.
        reason: String,
    },
    /// A discovery source supplied an invalid claim.
    DiscoveryProtocolViolation {
        /// Claimed peer, when identifiable.
        peer_id: Option<String>,
        /// Observation source.
        source: DiscoverySource,
        /// Human-readable violation detail.
        reason: String,
        /// Additional violations folded into this event.
        suppressed: u32,
    },
}
