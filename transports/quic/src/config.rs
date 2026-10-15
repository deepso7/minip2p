use minip2p_core::PeerId;
use minip2p_identity::Ed25519Keypair;

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
    /// The QUIC memory budget: the bytes this transport may reserve for its
    /// connections and streams, across all its sockets. It caps the
    /// transport's worst-case queued memory.
    ///
    /// Each connection reserves
    /// [`connection_reservation_bytes`](Self::connection_reservation_bytes)
    /// from admission until it drains, and each stream reserves
    /// [`stream_reservation_bytes`](Self::stream_reservation_bytes) from when
    /// it opens or is admitted until its delivered bytes are acknowledged or
    /// abandoned, also after its connection ended (an unsettled connection
    /// keeps its streams' reservations, not its own). What does not fit is
    /// refused, never queued: a dial or `open_stream` fails with
    /// `ResourceExhausted { resource: "QUIC memory budget" }`, an inbound
    /// connection gets `CONNECTION_REFUSED` once its address is validated
    /// (silence before that), and an inbound stream is refused like one over
    /// the stream limit. Must fit at least one connection and one stream.
    pub memory_budget_bytes: usize,
    /// Per-stream receive window, and each stream's receive budget: the most
    /// delivered bytes it holds unacknowledged (ADR 0012). Must be non-zero.
    ///
    /// Fixed, as is the connection window, so the engine buffers at most one
    /// more window behind a reader that is not acknowledging.
    pub stream_receive_window: usize,
    /// Per-connection receive window, fixed like
    /// [`stream_receive_window`](Self::stream_receive_window). Must be
    /// non-zero.
    pub connection_receive_window: usize,
    /// Bytes the engine buffers per connection for sending and
    /// retransmission. Must be non-zero.
    pub send_window: usize,
}

impl QuicLimits {
    /// The fixed part of a connection's memory reservation: its pending
    /// send queue, the engine's send buffer and its connection receive
    /// window.
    ///
    /// The queue counts twice: a queued write may keep a slice of its
    /// caller's payload, and ADR 0012 only bounds the allocation it pins to
    /// twice the bytes it counts.
    pub fn connection_reservation_bytes(&self) -> usize {
        self.max_pending_connection_bytes
            .saturating_mul(2)
            .saturating_add(self.send_window)
            .saturating_add(self.connection_receive_window)
    }

    /// Each stream's memory reservation: its receive window.
    pub fn stream_reservation_bytes(&self) -> usize {
        self.stream_receive_window
    }
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
            memory_budget_bytes: 512 * 1024 * 1024,
            stream_receive_window: 1_000_000,
            connection_receive_window: 3 * 1024 * 1024,
            send_window: 2 * 1024 * 1024,
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
