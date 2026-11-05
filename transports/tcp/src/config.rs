use minip2p_secure_mux::YamuxConfig;
use minip2p_transport::{ConnectionNamespace, InvalidLimit};

/// Limits and identifiers for one [`TcpTransport`](crate::TcpTransport).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpConfig {
    /// Namespace this transport allocates its connection ids in.
    ///
    /// Namespaces exist so several transports can hand ids to one swarm without
    /// colliding. Use [`ConnectionNamespace::TCP_IPV4`] and
    /// [`ConnectionNamespace::TCP_IPV6`] when you run one instance per address
    /// family; a single dual-stack instance can use either, since its own
    /// allocator already keeps its ids distinct.
    pub namespace: ConnectionNamespace,
    /// Ceiling on connections held at once, counting dialed and accepted alike.
    ///
    /// Every connection costs a session -- Noise state, a Yamux session, and
    /// whatever is buffered for it -- from the moment the byte stream comes up,
    /// which is well before the peer has proved who it is. Without a ceiling an
    /// unauthenticated peer decides how much of that a host holds. A dial past
    /// the ceiling fails the caller; an inbound one is dropped where it stands,
    /// because nothing has been announced about it to report against.
    ///
    /// An ended connection whose delivered bytes are not yet acknowledged or
    /// abandoned still counts (ADR 0012's unsettled connection).
    pub max_connections: usize,
    /// How long a connection may take to authenticate before it is dropped, or
    /// `None` to wait indefinitely.
    ///
    /// A ceiling alone is not enough: a peer that completes the TCP handshake
    /// and then says nothing holds its slot for as long as the socket lives,
    /// so a handful of silent peers can fill the ceiling and keep it full.
    /// Measured from the first [`poll`](minip2p_transport::Transport::poll)
    /// that sees the connection, since a transport owns no clock and that is
    /// the first time it is told what the time is.
    pub handshake_timeout_ms: Option<u64>,
    /// How many encrypted bytes one connection holds above its socket, beyond
    /// the one frame it always may.
    ///
    /// The session is pulled for the next frame only while this queue is
    /// below the limit (or empty, when the limit is zero), so a peer that reads slowly or not at all fills
    /// Yamux's send caps instead, and stream writes report
    /// [`TransportError::Full`](minip2p_transport::TransportError::Full)
    /// rather than tearing the connection down. A pull may overshoot by one
    /// Noise-encrypted Yamux frame; zero, the default, holds one frame at a
    /// time.
    ///
    /// The queue is first in, first out, so whatever sits in it has its order
    /// fixed: a deep one lets the first stream to write claim the link ahead
    /// of streams that write a moment later, and puts pings and window
    /// updates behind it. Shallow, frames wait in Yamux instead, which
    /// interleaves streams round-robin, at most
    /// [`YamuxConfig::max_frame_len`] each, and sends control frames first.
    /// The provider's own send buffer still keeps the link busy. How much it
    /// queues ahead of Yamux depends on the provider: `StdTcpProvider` asks
    /// the kernel to keep at most about 32 KiB unsent on Linux and Android
    /// (best effort), but other platforms' kernel buffers can still queue
    /// more, and smoltcp's is its per-socket `tx_buffer`. Raising this trades
    /// fairness and control latency for fewer, larger socket writes.
    pub max_buffered_send: usize,
    /// How long a connection may hold bytes its socket refuses before it is
    /// failed, or `None` to wait indefinitely.
    ///
    /// A socket that stops accepting is normal and momentary; one that never
    /// accepts again is a dead peer. Without a bound, such a connection sits
    /// with bytes queued forever -- and a host driven purely by deadlines
    /// would spin on it, since there is always work outstanding and never any
    /// progress.
    pub send_stall_timeout_ms: Option<u64>,
    /// Limits applied to each connection's Yamux session.
    pub yamux: YamuxConfig,
}

impl TcpConfig {
    /// Checks the limits can work: the Yamux invariants hold. A zero
    /// [`max_buffered_send`](Self::max_buffered_send) is valid.
    pub fn validate(&self) -> Result<(), InvalidLimit> {
        self.yamux.validate().map_err(|requirement| InvalidLimit {
            field: "TcpConfig::yamux",
            requirement,
        })
    }
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            namespace: ConnectionNamespace::TCP_IPV4,
            // Matches the QUIC transport's ceiling, so a host that runs both
            // budgets them the same way.
            max_connections: 1_024,
            // Generous next to the handful of round trips an upgrade actually
            // takes, so only a peer that has stopped participating trips it.
            handshake_timeout_ms: Some(30_000),
            // One frame at a time: the provider's send buffer keeps the link
            // busy, and everything else waits in Yamux, which interleaves
            // streams and sends control frames first.
            max_buffered_send: 0,
            // Long enough that a briefly wedged peer recovers, short enough
            // that a dead one does not hold a connection indefinitely.
            send_stall_timeout_ms: Some(30_000),
            yamux: YamuxConfig::default(),
        }
    }
}
