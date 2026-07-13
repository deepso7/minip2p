use minip2p_core::PeerId;
use minip2p_transport::StreamId;

/// Clock sample supplied by the driver with every input.
///
/// The agent never reads clocks itself. `mono_ms` orders all internal
/// deadlines; `unix_secs` is only needed to schedule relay-reservation
/// renewal from the absolute `expire` timestamp a relay returns, and may be
/// `None` on hosts without a real-time clock (renewal then falls back to a
/// configured default TTL).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Now {
    /// Monotonic milliseconds. Any epoch, as long as it never goes backward.
    pub mono_ms: u64,
    /// Wall-clock seconds since the unix epoch, if available.
    pub unix_secs: Option<u64>,
}

impl Now {
    /// A `Now` carrying only a monotonic reading.
    pub fn from_mono(mono_ms: u64) -> Self {
        Self {
            mono_ms,
            unix_secs: None,
        }
    }
}

/// Handle identifying one [`NatAgent::connect`](crate::NatAgent::connect)
/// intent across its actions and events.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectId(pub(crate) u64);

/// Opaque correlation token for a pending [`NatAction::Dial`] or
/// [`NatAction::OpenStream`].
///
/// The driver executes the synchronous swarm call and echoes the token back
/// unchanged via [`NatAgent::dial_result`](crate::NatAgent::dial_result) /
/// [`NatAgent::stream_open_result`](crate::NatAgent::stream_open_result).
///
/// [`NatAction::Dial`]: crate::NatAction::Dial
/// [`NatAction::OpenStream`]: crate::NatAction::OpenStream
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NatToken(pub(crate) u64);

/// A usable path to a peer.
///
/// Ranking: [`Path::DirectDialed`] ≈ [`Path::DirectPunched`] >
/// [`Path::Relayed`]. When a better path becomes available after a worse one
/// was announced, the agent emits an explicit
/// [`NatEvent::PathUpgraded`](crate::NatEvent::PathUpgraded) — never a silent
/// switch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Path {
    /// A direct QUIC connection established by dialing a known candidate
    /// address. Use the ordinary swarm APIs with the peer id.
    DirectDialed,
    /// A direct QUIC connection established by a DCUtR hole punch. Use the
    /// ordinary swarm APIs with the peer id.
    DirectPunched,
    /// A raw bridged relay stream.
    ///
    /// **This is not a full swarm connection.** No identify, ping, or
    /// multistream-select negotiation runs over the circuit; the application
    /// exchanges raw bytes on `stream_id` (addressed to `relay`) with
    /// `Swarm::send_stream` and receives them as ordinary `StreamData`
    /// events. A circuit transport that makes a relayed path look like any
    /// other connection is future work.
    Relayed {
        /// The relay peer the bridge stream runs through.
        relay: PeerId,
        /// The bridged stream (originally the HOP CONNECT stream).
        stream_id: StreamId,
        /// Whether the remote write half reached EOF while the NAT control
        /// plane still owned the bridge. When true, the original stream event
        /// was consumed and will not be delivered again.
        remote_write_closed: bool,
    },
}

impl Path {
    /// Returns `true` for direct (dialed or punched) paths.
    pub fn is_direct(&self) -> bool {
        !matches!(self, Self::Relayed { .. })
    }
}

/// Our current view of this node's reachability from the public internet.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ReachabilityState {
    /// Not enough probe evidence yet.
    #[default]
    Unknown,
    /// Confidently reachable: inbound dials to our advertised addresses work.
    Public,
    /// Confidently unreachable: we need a relay reservation to be dialable.
    Private,
}

/// A currently held relay reservation, as reported by
/// [`NatAgent::active_reservation`](crate::NatAgent::active_reservation).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationInfo {
    /// The relay holding the reservation.
    pub relay: PeerId,
    /// Absolute expiry reported by the relay, if any.
    pub expires_unix_secs: Option<u64>,
    /// When renewal fires, on the driver's monotonic clock.
    pub renew_at_mono_ms: u64,
}

/// Terminal errors for a connect attempt, carried by
/// [`NatEvent::ConnectFailed`](crate::NatEvent::ConnectFailed).
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NatError {
    /// No dialable direct candidates and no relay configured.
    #[error("no dialable candidates and no relay configured")]
    NoPathAvailable,
    /// The connect deadline elapsed before any path was established.
    #[error("connect deadline elapsed before any path was established")]
    Timeout,
    /// A dial was rejected or a connection was lost.
    #[error("dial failed: {0}")]
    DialFailed(alloc::string::String),
    /// A protocol state machine rejected the exchange.
    #[error("protocol error: {0}")]
    Protocol(alloc::string::String),
    /// The relay refused the circuit.
    #[error("relay refused: {0}")]
    RelayRefused(alloc::string::String),
}
