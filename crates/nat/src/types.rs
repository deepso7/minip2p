use minip2p_core::PeerId;

/// Opaque correlation token the agent allocates for work whose result the
/// host reports later: a dial the host parked to resolve its named address
/// ([`DialStart::Deferred`](crate::DialStart::Deferred), reported through
/// [`NatAgent::dial_result`](crate::NatAgent::dial_result)) and a
/// [`NatAction::PromoteBridge`] (reported through
/// [`NatAgent::promote_result`](crate::NatAgent::promote_result)). The host
/// echoes it back unchanged.
///
/// [`NatAction::PromoteBridge`]: crate::NatAction::PromoteBridge
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
#[non_exhaustive]
pub enum Path {
    /// A direct QUIC connection established by dialing a known candidate
    /// address. Use the ordinary swarm APIs with the peer id.
    DirectDialed,
    /// A direct QUIC connection established by a DCUtR hole punch. Use the
    /// ordinary swarm APIs with the peer id.
    DirectPunched,
    /// A full Noise- and Yamux-protected connection through a relay.
    Relayed {
        /// The relay carrying the circuit connection.
        relay: PeerId,
    },
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

/// The relay-leg step a [`NatError::Timeout`] stalled in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RelayStage {
    /// Dialing the relay, or waiting for its connection to finish Identify.
    RelayDial,
    /// Negotiating the HOP protocol on the relay connection.
    HopNegotiation,
    /// Waiting for the relay's answer to HOP CONNECT.
    HopStatus,
    /// The bridged circuit's Noise and Yamux handshake.
    CircuitHandshake,
}

impl core::fmt::Display for RelayStage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            RelayStage::RelayDial => "relay dial",
            RelayStage::HopNegotiation => "HOP negotiation",
            RelayStage::HopStatus => "HOP status",
            RelayStage::CircuitHandshake => "circuit handshake",
        })
    }
}

/// Terminal errors for a connect attempt, carried by
/// [`NatEvent::ConnectFailed`](crate::NatEvent::ConnectFailed), and the
/// per-relay errors carried by
/// [`NatEvent::RelayFailed`](crate::NatEvent::RelayFailed).
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NatError {
    /// No dialable direct candidates and no relay configured.
    #[error("no dialable candidates and no relay configured")]
    NoPathAvailable,
    /// A relay ran out its budget
    /// ([`NatConfig::relay_timeout_ms`](crate::NatConfig::relay_timeout_ms),
    /// clipped by the attempt's deadline) before its circuit carried a
    /// path. The overall connect deadline belongs to the Connection-attempt
    /// engine.
    #[error("{stage} timed out after {elapsed_ms} ms (budget {budget_ms} ms){}", relay_suffix(.relay))]
    Timeout {
        /// The step that stalled.
        stage: RelayStage,
        /// The relay being tried.
        relay: Option<PeerId>,
        /// Time spent on this relay when it gave up.
        elapsed_ms: u64,
        /// The relay's budget.
        budget_ms: u64,
    },
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

fn relay_suffix(relay: &Option<PeerId>) -> alloc::string::String {
    match relay {
        Some(relay) => alloc::format!(" at relay {relay}"),
        None => alloc::string::String::new(),
    }
}

/// Why a relayed attempt settled on its Relayed path without a direct
/// upgrade, carried by
/// [`NatEvent::FellBackToRelay`](crate::NatEvent::FellBackToRelay). The
/// budgets are in [`NatConfig`](crate::NatConfig), each clipped to the
/// attempt's deadline; `budget_ms` is the clipped value.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum UpgradeStop {
    /// The remote never started DCUtR within
    /// [`NatConfig::dcutr_start_timeout_ms`](crate::NatConfig::dcutr_start_timeout_ms)
    /// of the Relayed path becoming usable.
    #[error("the remote did not start DCUtR within {budget_ms} ms")]
    StartTimeout { budget_ms: u64 },
    /// A DCUtR exchange did not reach SYNC within
    /// [`NatConfig::dcutr_exchange_timeout_ms`](crate::NatConfig::dcutr_exchange_timeout_ms).
    #[error("DCUtR round {round} did not finish within {budget_ms} ms")]
    ExchangeTimeout { round: u32, budget_ms: u64 },
    /// The whole upgrade ran past
    /// [`NatConfig::upgrade_timeout_ms`](crate::NatConfig::upgrade_timeout_ms).
    #[error("the direct upgrade did not finish within {budget_ms} ms")]
    UpgradeTimeout { budget_ms: u64 },
    /// Every DCUtR round ended without a direct connection.
    #[error("{rounds} hole-punch rounds failed")]
    PunchFailed { rounds: u32 },
    /// The upgrade could not continue, for example because another
    /// attempt's circuit took over the peer's connection.
    #[error("upgrade aborted: {reason}")]
    Aborted { reason: alloc::string::String },
}

/// Failure reported by the driver while promoting a relay bridge.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PromoteError {
    /// A verified direct connection won the race before promotion.
    #[error("peer already has a direct connection")]
    PeerAlreadyDirect,
    /// The wrapped relay connection disappeared before adoption.
    #[error("wrapped relay connection is unknown")]
    UnknownConnection,
    /// The bridge could not be adopted.
    #[error("bridge promotion failed: {0}")]
    Failed(alloc::string::String),
}
