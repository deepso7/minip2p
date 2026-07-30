use minip2p_secure_mux::YamuxConfig;
use minip2p_transport::ConnectionNamespace;

/// Limits and identifiers for one [`TcpTransport`](crate::TcpTransport).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpConfig {
    /// Namespace this transport allocates its connection ids in.
    ///
    /// Namespaces exist so several transports can hand ids to one swarm without
    /// collliding. Use [`ConnectionNamespace::TCP_IPV4`] and
    /// [`ConnectionNamespace::TCP_IPV6`] when you run one instance per address
    /// family; a single dual-stack instance can use either, since its own
    /// allocator already keeps its ids distinct.
    pub namespace: ConnectionNamespace,
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
