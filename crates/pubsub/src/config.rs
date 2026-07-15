//! Floodsub agent configuration.

/// Tunables for [`FloodsubAgent`](crate::FloodsubAgent).
#[derive(Clone, Debug)]
pub struct FloodsubConfig {
    /// How long a message id stays in the seen-cache. Duplicates arriving
    /// within this window are dropped silently.
    pub seen_ttl_ms: u64,
    /// Hard bound on seen-cache entries; the oldest are evicted first so
    /// no_std hosts get a fixed memory ceiling regardless of traffic.
    pub max_seen_messages: usize,
    /// Bound on RPCs queued toward one peer while its sender is busy.
    /// `publish` preflights every recipient against this bound (all-or-
    /// nothing); forwards to a full peer are dropped best-effort.
    pub max_pending_per_peer: usize,
    /// Bound on the remote-subscription set tracked per peer. An RPC whose
    /// resulting set would exceed it is a protocol violation.
    pub max_topics_per_peer: usize,
    /// Bound on concurrent inbound RPC streams per peer (one-shot senders
    /// legitimately open several). The newest stream beyond it is reset.
    pub max_inbound_streams_per_peer: usize,
    /// Deadline for one outbound RPC to make it from `OpenStream` all the
    /// way to `StreamClosed`; a stuck send is reset and discarded.
    pub send_timeout_ms: u64,
    /// Accept unsigned messages (rust-libp2p's floodsub does not sign).
    /// Unsigned messages still require a valid `from` and an 8-byte
    /// `seqno`; messages that do carry a signature are always verified.
    pub allow_unsigned: bool,
}

impl Default for FloodsubConfig {
    fn default() -> Self {
        Self {
            seen_ttl_ms: 120_000,
            max_seen_messages: 4096,
            max_pending_per_peer: 32,
            max_topics_per_peer: 256,
            max_inbound_streams_per_peer: 4,
            send_timeout_ms: 10_000,
            allow_unsigned: false,
        }
    }
}
