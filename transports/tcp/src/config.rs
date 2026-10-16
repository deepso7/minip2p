use minip2p_secure_mux::{NOISE_WIRE_FRAME, SecureMuxSession, YamuxConfig};
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
    /// How many encrypted bytes one connection holds for its socket.
    ///
    /// The session is pulled for more only while the buffer is below this,
    /// so a peer that reads slowly or not at all fills Yamux's send caps
    /// instead, and stream writes report
    /// [`TransportError::Full`](minip2p_transport::TransportError::Full)
    /// rather than tearing the connection down. A pull may overshoot by one
    /// Noise-encrypted Yamux frame; zero holds one frame at a time.
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
    /// The TCP memory budget: the bytes this transport may reserve for its
    /// connections and streams, across all its listeners (ADR 0021). It caps
    /// the transport's worst-case retained payload.
    ///
    /// Each connection reserves
    /// [`connection_reservation_bytes`](Self::connection_reservation_bytes)
    /// from its dial or accept until teardown drops its session, and each
    /// stream reserves
    /// [`stream_reservation_bytes`](Self::stream_reservation_bytes) from when
    /// it opens or is admitted until it settles: closed and its delivered
    /// bytes acknowledged or abandoned, also after its connection ended.
    /// What does not fit is refused, never queued: a dial or `open_stream`
    /// fails with `ResourceExhausted { resource: "TCP memory budget" }`, an
    /// inbound connection is aborted at accept, as at
    /// [`max_connections`](Self::max_connections), and an inbound stream is
    /// reset, as past Yamux's stream limit. Must fit one connection with one
    /// stream.
    pub memory_budget_bytes: usize,
}

impl TcpConfig {
    /// The fixed part of a connection's memory reservation: its session's
    /// ([`SecureMuxSession::fixed_reservation_bytes`]: twice the Yamux send
    /// cap, its write queue and its decoders' backlogs) plus the outbound
    /// buffer, [`max_buffered_send`](Self::max_buffered_send) and the one
    /// Noise message a pull may overshoot it by.
    ///
    /// Container overhead, allocator slack, temporary copies and the
    /// provider's socket buffers are not counted. Saturates rather than
    /// overflowing; [`validate`](Self::validate) rejects that.
    pub fn connection_reservation_bytes(&self) -> usize {
        SecureMuxSession::fixed_reservation_bytes(&self.yamux)
            .saturating_add(self.max_buffered_send)
            .saturating_add(NOISE_WIRE_FRAME)
    }

    /// Each stream's memory reservation: its Yamux receive window.
    pub fn stream_reservation_bytes(&self) -> usize {
        self.yamux.receive_window as usize
    }

    /// Checks the limits can work: the Yamux invariants hold, the
    /// reservation arithmetic does not overflow, and the budget fits one
    /// connection with one stream. A zero
    /// [`max_buffered_send`](Self::max_buffered_send) is valid.
    pub fn validate(&self) -> Result<(), InvalidLimit> {
        self.yamux.validate().map_err(|requirement| InvalidLimit {
            field: "TcpConfig::yamux",
            requirement,
        })?;
        let smallest = self
            .connection_reservation_bytes()
            .checked_add(self.stream_reservation_bytes())
            .filter(|bytes| *bytes != usize::MAX)
            .ok_or(InvalidLimit {
                field: "TcpConfig::yamux",
                requirement: "the memory reservation arithmetic must not overflow",
            })?;
        if self.memory_budget_bytes < smallest {
            return Err(InvalidLimit {
                field: "TcpConfig::memory_budget_bytes",
                requirement: "must fit one connection's fixed reservation and one stream",
            });
        }
        Ok(())
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
            // Several Yamux windows' worth, so a healthy socket is never
            // starved between polls.
            max_buffered_send: 1024 * 1024,
            // Long enough that a briefly wedged peer recovers, short enough
            // that a dead one does not hold a connection indefinitely.
            send_stall_timeout_ms: Some(30_000),
            yamux: YamuxConfig::default(),
            // At least 64 connections with a stream each (ADR 0021): 11.25 MiB
            // fixed plus a 2,432 KiB window is 13.6 MiB, so 1 GiB admits 75.
            memory_budget_bytes: 1024 * 1024 * 1024,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_budget_admits_at_least_64_connections_with_a_stream_each() {
        let config = TcpConfig::default();
        let session = config.connection_reservation_bytes() + config.stream_reservation_bytes();
        assert!(
            config.memory_budget_bytes / session >= 64,
            "{session} bytes each"
        );
        config.validate().expect("the default is valid");
    }
}
