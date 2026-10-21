use minip2p_core::PeerId;
use minip2p_identity::Ed25519Keypair;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Resource and flow-control limits for the synchronous QUIC adapter.
///
/// The defaults are intentionally conservative: enough for normal peer-to-peer
/// workloads while bounding memory and unauthenticated connection state.
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
    /// dropped. Browsers check it with WebPKI, so addresses carry no
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

    /// Returns the Ed25519 host keypair.
    pub(crate) fn keypair(&self) -> &Ed25519Keypair {
        &self.keypair
    }
}
