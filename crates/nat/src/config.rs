use alloc::vec::Vec;

use minip2p_core::PeerAddr;

/// The most DCUtR rounds the reservation holder runs per relayed session:
/// each a fresh CONNECT/SYNC exchange with its own RTT and punch window. The
/// circuit dialer settles on its Relayed path once this many have failed.
pub const MAX_DCUTR_ROUNDS: u32 = 3;

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
/// The defaults follow common go-libp2p practice; every value can be
/// overridden.
#[derive(Clone, Debug)]
pub struct NatConfig {
    /// Relays available for circuit legs and reservations, in preference
    /// order. A connect's relay leg tries them one at a time, moving on when
    /// a relay fails; relays the target is known to be reachable through
    /// ([`ConnectLegs::target_addrs`](crate::ConnectLegs::target_addrs)) go
    /// first. Empty disables the relay leg entirely.
    pub relays: Vec<PeerAddr>,
    /// AutoNAT servers used for reachability probes, in preference order.
    /// Empty leaves reachability [`Unknown`](crate::ReachabilityState::Unknown).
    pub autonat_servers: Vec<PeerAddr>,
    /// Head start given to the direct leg before the relay leg spins up.
    /// `0` races both fully in parallel. Ignored when the caller is not
    /// racing direct candidates.
    pub relay_stagger_ms: u64,
    /// Deadline for an inbound promoted circuit to finish its Noise and
    /// Yamux handshake. The deadline is disarmed once the circuit connection
    /// is established.
    pub circuit_handshake_timeout_ms: u64,
    /// Use relayed circuits without racing direct dials or attempting DCUtR.
    pub force_relay: bool,
    /// Upgrade relayed connections to direct ones with DCUtR. `false` keeps
    /// direct racing and the relay leg but never starts an upgrade: a
    /// circuit dialer arms no upgrade budgets and answers no DCUtR round,
    /// and a reservation holder settles on the inbound circuit at once.
    /// Hosts that cannot hole punch (browsers) turn it off.
    pub dcutr: bool,
    /// Budget for one relay, from its first dial to its circuit carrying a
    /// usable Relayed path, clipped by the caller's
    /// [`ConnectLegs::deadline_ms`](crate::ConnectLegs::deadline_ms). A
    /// relay that fails earlier hands over to the next one at once; a relay
    /// listed under several addresses splits its budget across them. Also
    /// the flight budget of reservation and STOP exchanges.
    pub relay_timeout_ms: u64,
    /// One hole-punch window: how long each side keeps punching after a
    /// DCUtR round's SYNC.
    pub punch_deadline_ms: u64,
    /// How long the circuit dialer waits for the remote to start DCUtR,
    /// counted from the Relayed path becoming usable. Past it the attempt
    /// settles on the Relayed path with
    /// [`UpgradeStop::StartTimeout`](crate::UpgradeStop::StartTimeout).
    pub dcutr_start_timeout_ms: u64,
    /// Budget for one DCUtR CONNECT/SYNC exchange, on either side.
    pub dcutr_exchange_timeout_ms: u64,
    /// Budget for the whole direct upgrade (every DCUtR round and punch
    /// window), counted from the Relayed path becoming usable.
    pub upgrade_timeout_ms: u64,
    /// Cadence of responder-side random-UDP blasts during a punch.
    pub blast_interval_ms: u64,
    /// Payload length of each random-UDP blast packet.
    pub blast_payload_len: usize,
    /// Distinct AutoNAT servers (out of
    /// [`confidence_window`](Self::confidence_window)) whose latest votes
    /// must agree before reachability flips; a public verdict also needs this
    /// many to confirm each address it reports. Values above the window mean
    /// unanimity.
    pub confidence_threshold: u8,
    /// How many servers' votes count: the latest vote of each of the most
    /// recent servers to answer, each live for
    /// [`AUTONAT_VOTE_TTL_MS`](crate::AUTONAT_VOTE_TTL_MS).
    pub confidence_window: u8,
    /// Probe interval once reachability is settled.
    pub probe_interval_settled_ms: u64,
    /// Probe interval while reachability is unknown or contested.
    pub probe_interval_unsettled_ms: u64,
    /// Deadline for a single AutoNAT probe exchange.
    pub probe_deadline_ms: u64,
    /// Assumed reservation lifetime when the relay returns no `expire` or
    /// the host has no wall clock, and the cap on any lifetime the relay
    /// reports.
    ///
    /// Reservations renew at half their lifetime, so this bounds the renewal
    /// delay at half its value: a far-future `expire` cannot postpone renewal
    /// indefinitely. It does not guarantee renewal before the relay's actual
    /// expiry; a relay that enforces 600s but reports far more still renews
    /// after 1800s with the default of 3600. `0` and `1` are a
    /// misconfiguration: every reservation then renews every 500ms.
    pub reservation_default_ttl_secs: u64,
    /// Backoff before retrying (or rotating relays) after a refused or
    /// failed reservation. Each consecutive failure doubles it, plus up to a
    /// fifth more as jitter, up to
    /// [`MAX_RESERVATION_RETRY_BACKOFF_MS`](crate::MAX_RESERVATION_RETRY_BACKOFF_MS);
    /// a held reservation resets it.
    pub reservation_retry_backoff_ms: u64,
    /// Interval between liveness pings while holding a QUIC relay
    /// reservation. Keep this below the QUIC idle timeout. `0` disables
    /// automatic reservation liveness traffic. TCP reservations never use
    /// this setting. Drivers that expose ping RTT events also expose results
    /// from these automatic pings.
    pub reservation_keep_alive_interval_ms: u64,
    /// When to hold a relay reservation.
    pub reservation_policy: ReservationPolicy,
    /// Circuit admission limit (ADR 0012). A circuit slot is reserved before a
    /// STOP CONNECT is accepted (past the limit it is refused with
    /// `RESOURCE_LIMIT_EXCEEDED`) and before a HOP CONNECT is sent (past it
    /// the relay leg fails with [`NatError::ResourceExhausted`]), and every
    /// failure or cancellation releases it. Once adopted, the circuit holds
    /// its slot in the host's circuit transport until it closes and its
    /// delivered bytes settle; [`NatSwarm::circuit_slots`] reports those.
    ///
    /// [`NatError::ResourceExhausted`]: crate::NatError::ResourceExhausted
    /// [`NatSwarm::circuit_slots`]: crate::NatSwarm::circuit_slots
    pub max_circuits: usize,
    /// Accept DCUtR punch targets outside globally routable unicast space:
    /// loopback, private (RFC 1918), shared CGNAT, link-local, and other
    /// special-use unicast IPs. They are still QUIC-only, IP-only, unicast
    /// addresses: never DNS names, and never unspecified, multicast, or
    /// broadcast.
    ///
    /// Off by default because punch targets come from the remote peer, which
    /// could otherwise aim our dials and random-UDP blasts at hosts on our
    /// own network. Turn it on only where both peers share a private address
    /// space, such as a lab network or loopback tests.
    pub allow_private_punch_targets: bool,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            relays: Vec::new(),
            autonat_servers: Vec::new(),
            relay_stagger_ms: 200,
            circuit_handshake_timeout_ms: 20_000,
            force_relay: false,
            dcutr: true,
            relay_timeout_ms: 12_000,
            punch_deadline_ms: 3_000,
            dcutr_start_timeout_ms: 10_000,
            dcutr_exchange_timeout_ms: 10_000,
            upgrade_timeout_ms: 20_000,
            blast_interval_ms: 100,
            blast_payload_len: 32,
            confidence_threshold: 3,
            confidence_window: 5,
            probe_interval_settled_ms: 90_000,
            probe_interval_unsettled_ms: 5_000,
            probe_deadline_ms: 20_000,
            reservation_default_ttl_secs: 3_600,
            reservation_retry_backoff_ms: 500,
            reservation_keep_alive_interval_ms: 15_000,
            reservation_policy: ReservationPolicy::WhenPrivate,
            max_circuits: 64,
            allow_private_punch_targets: false,
        }
    }
}

impl NatConfig {
    /// Whether relayed connections may be upgraded with DCUtR: neither
    /// `force_relay` nor `dcutr = false` rules it out.
    pub(crate) fn upgrades(&self) -> bool {
        !self.force_relay && self.dcutr
    }
}
