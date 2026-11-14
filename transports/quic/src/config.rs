use minip2p_core::PeerId;
use minip2p_identity::Ed25519Keypair;
use minip2p_transport::ConnectionNamespace;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Resource and flow-control limits for the synchronous QUIC adapter.
///
/// The defaults are intentionally conservative: enough for normal peer-to-peer
/// workloads while bounding memory and unauthenticated connection state.
///
/// # Lossy or reordering paths
///
/// [`congestion_controller`](Self::congestion_controller),
/// [`packet_threshold`](Self::packet_threshold) and
/// [`time_threshold`](Self::time_threshold) can help on unusual paths. These
/// are measurements from the v0.11.2 netem retests, each on the link profile
/// named, not universal settings; measure your own path:
///
/// - **Reordering** (5 Mbit/s, 100 ms, 5% reorder): the defaults (3 packets,
///   1.125 RTTs) reached 1.3–1.4 Mbit/s; a packet threshold of 50 with a time
///   threshold of 2.0 reached 4.5 Mbit/s. Raising only one of the two did not
///   help. Rule of thumb: a packet threshold above the reorder depth, which
///   grows with the rate, and a time threshold of at least 2.
/// - **Random loss and long paths** (1–5% loss; GEO at 20 Mbit/s, 600 ms,
///   0.5% loss): [`CongestionController::Bbr`] did clearly better than CUBIC,
///   but worse under reordering and on bulk efficiency, and quinn marks it
///   experimental.
///
/// CUBIC with 3 packets and 1.125 RTTs stays the default: they are quinn's
/// and RFC 9002's values, higher thresholds slow recovery from real loss, and
/// BBR lost under reordering and on bulk efficiency, so neither alternative
/// suits every path.
///
/// ```
/// use minip2p_quic::QuicLimits;
///
/// // The reordering profile above.
/// let limits = QuicLimits {
///     packet_threshold: 50,
///     time_threshold: 2.0,
///     ..QuicLimits::default()
/// };
/// # let _ = limits;
/// ```
#[derive(Clone, Debug)]
pub struct QuicLimits {
    /// Maximum simultaneous QUIC connections across all of the transport's
    /// sockets, counting both inbound (accepted) and outbound (dialed)
    /// connections.
    ///
    /// An ended connection whose delivered bytes are not yet acknowledged or
    /// abandoned still counts (ADR 0012's unsettled connection): with every
    /// slot held, dials fail with `ResourceExhausted` and Initials are
    /// ignored.
    pub max_connections: usize,
    /// Maximum locally initiated bidirectional streams per connection.
    pub max_streams_per_connection: u64,
    /// Maximum application bytes queued per stream beyond what the QUIC
    /// engine accepts immediately. Must be non-zero.
    ///
    /// A stream stalled on the peer's credit fills only this share, so it
    /// cannot keep the connection's other streams from writing (ADR 0012).
    pub max_pending_bytes_per_stream: usize,
    /// Maximum application bytes queued per connection beyond what the QUIC
    /// engine accepts immediately, shared by all its streams. Must be greater
    /// than [`control_stream_reserve_bytes`](Self::control_stream_reserve_bytes).
    ///
    /// A write takes what the engine accepts now plus what fits both this and
    /// [`max_pending_bytes_per_stream`](Self::max_pending_bytes_per_stream),
    /// regardless of the peer's flow-control credit, and returns
    /// [`TransportError::Full`](minip2p_transport::TransportError::Full) with
    /// the rest. An armed stream gets a
    /// [`StreamWritable`](minip2p_transport::TransportEvent::StreamWritable)
    /// once it can queue at least half of the smaller cap again (for a
    /// control stream, at most half a non-zero
    /// [`control_stream_reserve_bytes`](Self::control_stream_reserve_bytes),
    /// the room it may be left). Queued bytes
    /// enter the engine round-robin across streams. Neither cap counts the
    /// engine's own send buffer.
    pub max_pending_connection_bytes: usize,
    /// Part of [`max_pending_connection_bytes`](Self::max_pending_connection_bytes)
    /// that only control streams may fill: those the swarm marks with
    /// [`Transport::set_control_stream`](minip2p_transport::Transport::set_control_stream)
    /// (ping, Identify, multistream negotiation). Application streams cannot
    /// starve them of it.
    pub control_stream_reserve_bytes: usize,
    /// Maximum UDP datagrams retained after the non-blocking socket reports
    /// `WouldBlock`.
    pub max_pending_datagrams: usize,
    /// QUIC idle timeout advertised to peers, in milliseconds. Must be
    /// greater than zero: QUIC interprets zero as "no timeout", so transport
    /// construction rejects it.
    ///
    /// Quiet connections send an ack-eliciting keepalive at half this value
    /// so the idle timer does not fire on a live but silent path.
    ///
    /// Not a hard bound: the connection uses the lower of the two peers'
    /// advertised values, and quinn never waits less than 3 × PTO, so on a
    /// high-RTT link a dead connection can outlive this value.
    pub idle_timeout_ms: u64,
    /// Require a stateless Retry before allocating an inbound connection.
    pub require_address_validation: bool,
    /// Per-stream receive window, and each stream's receive budget: the most
    /// delivered bytes it holds unacknowledged (ADR 0012). Must be non-zero.
    ///
    /// Fixed, so the engine buffers at most one more window behind a reader
    /// that is not acknowledging. Defaults to quinn's 1,250,000 bytes.
    pub stream_receive_window: usize,
    /// Per-connection receive window, fixed like
    /// [`stream_receive_window`](Self::stream_receive_window). Must be
    /// non-zero; `usize::MAX` (the default), or anything past what QUIC can
    /// express (2^62 - 1), is unlimited.
    ///
    /// Unlimited by default, as in quinn, so one stalled stream cannot spend
    /// the credit the connection's other streams need (ADR 0022). Nothing
    /// then bounds a connection's received data in aggregate but twice
    /// [`max_streams_per_connection`](Self::max_streams_per_connection)
    /// (local and peer streams are limited separately) times two stream
    /// windows: one delivered and unacknowledged, one the engine buffers
    /// behind it.
    pub connection_receive_window: usize,
    /// Bytes the engine buffers per connection for sending and
    /// retransmission. Must be non-zero. Defaults to quinn's 10,000,000.
    pub send_window: usize,
    /// How long an `h3` connection may take from the QUIC handshake to a
    /// completed Noise handshake, in milliseconds. Must be greater than zero.
    ///
    /// A WebTransport client that has not authenticated by then is closed
    /// with `H3_EXCESSIVE_LOAD`, and its `Closed` reports
    /// [`TimedOut`](minip2p_transport::ConnectionCloseReason::TimedOut).
    pub webtransport_handshake_timeout_ms: u64,
    /// The congestion controller each connection runs. Defaults to quinn's
    /// [`Cubic`](CongestionController::Cubic).
    pub congestion_controller: CongestionController,
    /// Packets that must be acknowledged after an unacknowledged one before
    /// loss detection declares it lost (RFC 9002 §6.1.1). Must be at least 3.
    /// Defaults to quinn's 3.
    ///
    /// Raising it stops reordering on the path from counting as loss, which
    /// would otherwise retransmit and shrink the congestion window. Raise it
    /// with [`time_threshold`](Self::time_threshold); see
    /// [Lossy or reordering paths](Self#lossy-or-reordering-paths).
    pub packet_threshold: u32,
    /// How long, as a multiple of the RTT, an unacknowledged packet may wait
    /// behind a later acknowledged one before loss detection declares it lost
    /// (RFC 9002 §6.1.2). Must be between 1.0 and 10.0. Defaults to
    /// quinn's 1.125 (9/8).
    ///
    /// Raising it, like [`packet_threshold`](Self::packet_threshold),
    /// tolerates more reordering at the cost of slower loss recovery.
    pub time_threshold: f32,
}

/// Congestion controllers a QUIC connection can run; all are quinn-proto's.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CongestionController {
    /// CUBIC (RFC 9438), quinn's default. Loss-based: it fills deep
    /// bottleneck queues before backing off.
    #[default]
    Cubic,
    /// NewReno (RFC 9002 §7), loss-based and gentler in its growth than
    /// CUBIC.
    NewReno,
    /// BBR (v1), which paces to the estimated bottleneck rate and RTT rather
    /// than reacting to loss, aiming to keep queues short. quinn marks its
    /// implementation experimental.
    Bbr,
}

impl Default for QuicLimits {
    fn default() -> Self {
        Self {
            max_connections: 1_024,
            max_streams_per_connection: 128,
            max_pending_bytes_per_stream: 256 * 1024,
            max_pending_connection_bytes: 1024 * 1024,
            control_stream_reserve_bytes: 256 * 1024,
            max_pending_datagrams: 1_024,
            idle_timeout_ms: 30_000,
            require_address_validation: true,
            // quinn's own defaults (ADR 0022).
            stream_receive_window: 1_250_000,
            connection_receive_window: usize::MAX,
            send_window: 10_000_000,
            webtransport_handshake_timeout_ms: 10_000,
            // quinn's own loss-detection and congestion defaults (#478).
            congestion_controller: CongestionController::Cubic,
            packet_threshold: 3,
            time_threshold: 9.0 / 8.0,
        }
    }
}

/// The certificate a WebTransport-serving socket presents to `h3` clients.
/// Clients negotiating `libp2p` always get the libp2p certificate.
#[derive(Debug, Default)]
pub enum WebTransportCertificates {
    /// Self-signed certificates derived from the host key, one per 13-day
    /// period, rotated by the host's wall clock. Addresses carry their
    /// `/certhash`es, which browsers pin.
    #[default]
    Derived,
    /// An operator's CA-signed certificate, presented until the transport is
    /// dropped or it is replaced with
    /// [`QuicTransport::replace_webtransport_certificate`](crate::QuicTransport::replace_webtransport_certificate). Browsers check it with WebPKI, so addresses carry no
    /// `/certhash` and should name the certificate's domain (`/dns/…`).
    ///
    /// Checked at bind: the key must match the leaf, and the leaf must not
    /// have expired. Any key type the ring provider signs with (ECDSA,
    /// Ed25519, RSA) is accepted.
    Provided {
        /// The leaf certificate first, then its intermediates.
        chain: Vec<CertificateDer<'static>>,
        /// The leaf's private key.
        key: PrivateKeyDer<'static>,
    },
}

impl Clone for WebTransportCertificates {
    fn clone(&self) -> Self {
        match self {
            Self::Derived => Self::Derived,
            Self::Provided { chain, key } => Self::Provided {
                chain: chain.clone(),
                key: key.clone_key(),
            },
        }
    }
}

/// Configuration for a QUIC transport node.
///
/// QUIC always uses mutual libp2p TLS in minip2p, so a node identity is
/// mandatory. A TLS certificate is auto-generated from the keypair, and the
/// remote peer's identity is verified inside each QUIC handshake.
#[derive(Clone, Debug)]
pub struct QuicNodeConfig {
    /// Ed25519 host keypair for libp2p TLS identity.
    pub(crate) keypair: Ed25519Keypair,
    /// Runtime resource and flow-control limits.
    pub(crate) limits: QuicLimits,
    /// What WebTransport-serving sockets present to `h3` clients.
    pub(crate) webtransport_certificates: WebTransportCertificates,
    /// Where each socket allocates its connection ids.
    pub(crate) namespaces: QuicNamespaces,
}

impl QuicNodeConfig {
    /// Creates a configuration from an Ed25519 host keypair.
    ///
    /// A libp2p-spec TLS certificate is auto-generated from the keypair. Both
    /// dialing and listening are enabled. Peer identity is verified inside
    /// each QUIC handshake.
    pub fn new(keypair: Ed25519Keypair) -> Self {
        Self {
            keypair,
            limits: QuicLimits::default(),
            webtransport_certificates: WebTransportCertificates::default(),
            namespaces: QuicNamespaces::default(),
        }
    }

    /// Generates a configuration with a fresh Ed25519 host keypair.
    pub fn generate() -> Self {
        Self::new(Ed25519Keypair::generate())
    }

    /// Returns this node's `PeerId`, derived from the configured keypair.
    pub fn peer_id(&self) -> PeerId {
        self.keypair.peer_id()
    }

    /// Replaces the default runtime limits.
    pub fn with_limits(mut self, limits: QuicLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Returns the configured runtime limits.
    pub fn limits(&self) -> &QuicLimits {
        &self.limits
    }

    /// Replaces the default [`WebTransportCertificates::Derived`]. Only
    /// sockets bound with a `/quic-v1/webtransport` address use it.
    pub fn with_webtransport_certificates(
        mut self,
        certificates: WebTransportCertificates,
    ) -> Self {
        self.webtransport_certificates = certificates;
        self
    }

    /// Returns what WebTransport-serving sockets present to `h3` clients.
    pub fn webtransport_certificates(&self) -> &WebTransportCertificates {
        &self.webtransport_certificates
    }

    /// Replaces the default [`QuicNamespaces::QUIC`], so this transport's
    /// connection ids stay apart from another QUIC transport's in the same
    /// host — a mesh relay's backbone uses [`QuicNamespaces::MESH`].
    pub fn with_namespaces(mut self, namespaces: QuicNamespaces) -> Self {
        self.namespaces = namespaces;
        self
    }

    /// Returns the namespaces this transport allocates connection ids in.
    pub fn namespaces(&self) -> QuicNamespaces {
        self.namespaces
    }

    /// Returns the Ed25519 host keypair.
    pub(crate) fn keypair(&self) -> &Ed25519Keypair {
        &self.keypair
    }
}

/// The [`ConnectionNamespace`]s a [`QuicTransport`](crate::QuicTransport)
/// allocates connection ids in, one per IP family.
///
/// The default, [`QUIC`](Self::QUIC), suits a host with one QUIC transport.
/// A host running two side by side gives the second its own pair, so a router
/// can tell their connections apart by id alone.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct QuicNamespaces {
    ipv4: ConnectionNamespace,
    ipv6: ConnectionNamespace,
}

impl QuicNamespaces {
    /// [`QUIC_IPV4`](ConnectionNamespace::QUIC_IPV4) and
    /// [`QUIC_IPV6`](ConnectionNamespace::QUIC_IPV6): the default.
    pub const QUIC: Self = Self {
        ipv4: ConnectionNamespace::QUIC_IPV4,
        ipv6: ConnectionNamespace::QUIC_IPV6,
    };
    /// [`MESH_IPV4`](ConnectionNamespace::MESH_IPV4) and
    /// [`MESH_IPV6`](ConnectionNamespace::MESH_IPV6): a mesh relay's backbone.
    pub const MESH: Self = Self {
        ipv4: ConnectionNamespace::MESH_IPV4,
        ipv6: ConnectionNamespace::MESH_IPV6,
    };

    /// Creates a pair, or `None` if both families would share one namespace:
    /// a namespace takes exactly one allocator, or ids would repeat.
    pub const fn new(ipv4: ConnectionNamespace, ipv6: ConnectionNamespace) -> Option<Self> {
        if ipv4.get() == ipv6.get() {
            return None;
        }
        Some(Self { ipv4, ipv6 })
    }

    /// The namespace for connections over the IPv4 socket.
    pub const fn ipv4(self) -> ConnectionNamespace {
        self.ipv4
    }

    /// The namespace for connections over the IPv6 socket.
    pub const fn ipv6(self) -> ConnectionNamespace {
        self.ipv6
    }
}

impl Default for QuicNamespaces {
    fn default() -> Self {
        Self::QUIC
    }
}
