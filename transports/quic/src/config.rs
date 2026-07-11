use minip2p_core::PeerId;
use minip2p_identity::Ed25519Keypair;

/// Resource and flow-control limits for the synchronous QUIC adapter.
///
/// The defaults are intentionally conservative: enough for normal peer-to-peer
/// workloads while bounding memory and unauthenticated connection state.
#[derive(Clone, Debug)]
pub struct QuicLimits {
    /// Maximum simultaneous QUIC connections per UDP socket, counting both
    /// inbound (accepted) and outbound (dialed) connections.
    pub max_connections: usize,
    /// Maximum locally initiated bidirectional streams per connection.
    pub max_streams_per_connection: u64,
    /// Maximum application bytes queued per connection beyond what quiche
    /// accepts immediately. A single write may exceed this limit as long as
    /// the remainder quiche leaves unsent fits within it.
    pub max_pending_stream_bytes: usize,
    /// Maximum UDP datagrams retained after the non-blocking socket reports
    /// `WouldBlock`.
    pub max_pending_datagrams: usize,
    /// QUIC idle timeout advertised to peers, in milliseconds. Must be
    /// greater than zero: quiche interprets zero as "no timeout", so
    /// transport construction rejects it.
    pub idle_timeout_ms: u64,
    /// Require a stateless Retry before allocating an inbound connection.
    pub require_address_validation: bool,
}

impl Default for QuicLimits {
    fn default() -> Self {
        Self {
            max_connections: 1_024,
            max_streams_per_connection: 128,
            max_pending_stream_bytes: 8 * 1024 * 1024,
            max_pending_datagrams: 1_024,
            idle_timeout_ms: 30_000,
            require_address_validation: true,
        }
    }
}

/// Configuration for a QUIC transport node.
///
/// QUIC always uses mutual libp2p TLS in minip2p, so a node identity is
/// mandatory. A TLS certificate is auto-generated from the keypair, and the
/// remote peer's identity is verified automatically after each QUIC handshake.
#[derive(Clone, Debug)]
pub struct QuicNodeConfig {
    /// Ed25519 host keypair for libp2p TLS identity.
    pub(crate) keypair: Ed25519Keypair,
    /// Runtime resource and flow-control limits.
    pub(crate) limits: QuicLimits,
}

impl QuicNodeConfig {
    /// Creates a configuration from an Ed25519 host keypair.
    ///
    /// A libp2p-spec TLS certificate is auto-generated from the keypair. Both
    /// dialing and listening are enabled. Peer identity is verified
    /// automatically after each QUIC handshake.
    pub fn new(keypair: Ed25519Keypair) -> Self {
        Self {
            keypair,
            limits: QuicLimits::default(),
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

    /// Returns the Ed25519 host keypair.
    pub(crate) fn keypair(&self) -> &Ed25519Keypair {
        &self.keypair
    }
}
