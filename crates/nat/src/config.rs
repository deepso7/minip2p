use alloc::vec::Vec;

use minip2p_core::PeerAddr;

/// When the agent should hold a relay reservation for inbound reachability.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ReservationPolicy {
    /// Never reserve. Outbound connects can still use per-connect relay
    /// legs — HOP CONNECT needs the *target's* reservation, not ours.
    Never,
    /// Reserve while reachability is [`Private`] (or [`Unknown`] after the
    /// first failed probe round), release when it settles [`Public`].
    ///
    /// [`Private`]: crate::ReachabilityState::Private
    /// [`Unknown`]: crate::ReachabilityState::Unknown
    /// [`Public`]: crate::ReachabilityState::Public
    #[default]
    WhenPrivate,
    /// Always hold a reservation while a relay is configured.
    Always,
}

/// Tuning knobs for [`NatAgent`](crate::NatAgent).
///
/// The defaults mirror the hand-rolled orchestration in `examples/peer` and
/// common go-libp2p practice; every value can be overridden.
#[derive(Clone, Debug)]
pub struct NatConfig {
    /// Relays available for circuit legs and reservations, in preference
    /// order. Empty disables the relay leg entirely.
    pub relays: Vec<PeerAddr>,
    /// AutoNAT servers used for reachability probes, in preference order.
    /// Empty leaves reachability [`Unknown`](crate::ReachabilityState::Unknown).
    pub autonat_servers: Vec<PeerAddr>,
    /// Head start given to the direct leg before the relay leg spins up.
    /// `0` races both fully in parallel.
    pub relay_stagger_ms: u64,
    /// Overall deadline for a connect attempt.
    pub connect_deadline_ms: u64,
    /// Deadline for an inbound promoted circuit to finish its Noise and
    /// Yamux handshake. The deadline is disarmed once the circuit connection
    /// is established.
    pub circuit_handshake_timeout_ms: u64,
    /// Use relayed circuits without racing direct dials or attempting DCUtR.
    pub force_relay: bool,
    /// Deadline for the relay leg to reach `Bridged` (measured from when the
    /// leg starts, i.e. after the stagger).
    pub relay_leg_deadline_ms: u64,
    /// One hole-punch window: how long to wait for the direct connection
    /// after dialing the remote's observed addresses.
    pub punch_deadline_ms: u64,
    /// Extra punch windows after the first one fails (re-dialing the same
    /// observed addresses each time).
    pub punch_max_retries: u32,
    /// Cadence of responder-side random-UDP blasts during a punch.
    pub blast_interval_ms: u64,
    /// Payload length of each random-UDP blast packet.
    pub blast_payload_len: usize,
    /// Responder-side approximation of RTT/2: minimum delay between SYNC
    /// arrival and the first blast.
    pub responder_sync_delay_ms: u64,
    /// Probe verdicts (out of [`confidence_window`](Self::confidence_window))
    /// that must agree before reachability flips.
    pub confidence_threshold: u8,
    /// Size of the sliding window of recent probe verdicts.
    pub confidence_window: u8,
    /// Probe interval once reachability is settled.
    pub probe_interval_settled_ms: u64,
    /// Probe interval while reachability is unknown or contested.
    pub probe_interval_unsettled_ms: u64,
    /// Deadline for a single AutoNAT probe exchange.
    pub probe_deadline_ms: u64,
    /// Renew a reservation this many seconds before its `expire` timestamp.
    pub reservation_renewal_margin_secs: u64,
    /// Assumed reservation lifetime when the relay returns no `expire` or
    /// the host has no wall clock.
    pub reservation_default_ttl_secs: u64,
    /// Backoff before retrying (or rotating relays) after a refused or
    /// failed reservation.
    pub reservation_retry_backoff_ms: u64,
    /// When to hold a relay reservation.
    pub reservation_policy: ReservationPolicy,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            relays: Vec::new(),
            autonat_servers: Vec::new(),
            relay_stagger_ms: 200,
            connect_deadline_ms: 60_000,
            circuit_handshake_timeout_ms: 20_000,
            force_relay: false,
            relay_leg_deadline_ms: 12_000,
            punch_deadline_ms: 3_000,
            punch_max_retries: 2,
            blast_interval_ms: 100,
            blast_payload_len: 32,
            responder_sync_delay_ms: 50,
            confidence_threshold: 3,
            confidence_window: 5,
            probe_interval_settled_ms: 90_000,
            probe_interval_unsettled_ms: 5_000,
            probe_deadline_ms: 20_000,
            reservation_renewal_margin_secs: 120,
            reservation_default_ttl_secs: 3_600,
            reservation_retry_backoff_ms: 500,
            reservation_policy: ReservationPolicy::WhenPrivate,
        }
    }
}
