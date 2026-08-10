use minip2p_secure_mux::YamuxConfig;
use minip2p_transport::ConnectionNamespace;

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
    /// Ceiling on bytes held for one connection while its socket is not
    /// accepting writes.
    ///
    /// A peer that stops reading while the local side keeps sending would
    /// otherwise grow this buffer without bound. Reaching the ceiling fails
    /// that connection instead. Yamux applies its own per-substream limits
    /// above this; this one backs the socket itself.
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
            // Comfortably above one Yamux frame plus a Noise transport frame,
            // so an ordinary write never trips the ceiling on a healthy socket.
            max_buffered_send: 1024 * 1024,
            // Long enough that a briefly wedged peer recovers, short enough
            // that a dead one does not hold a connection indefinitely.
            send_stall_timeout_ms: Some(30_000),
            yamux: YamuxConfig::default(),
        }
    }
}
