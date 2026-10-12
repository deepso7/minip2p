//! Own-side housekeeping, independent of any connect attempt:
//!
//! - [`Prober`] — AutoNAT reachability probing that trusts a quorum of
//!   distinct servers: N of the latest votes of the last M servers to
//!   answer. `AutoNatClient` is single-shot; the aggregation (and the
//!   never-flap-on-one-server guarantee) lives here.
//! - [`ReservationManager`] — holds a relay reservation per the configured
//!   [`ReservationPolicy`], renewing at half the relay-reported lifetime
//!   and rotating relays (with backoff) on refusal or loss.
//!
//! Both reach their peer through the shared acquisition
//! ([`crate::acquire`]) and end only work bound to the exact connection a
//! close or replacement retires.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use minip2p_autonat::{
    AUTONAT_PROTOCOL_ID, AutoNatClient, AutoNatClientOutput, AutoNatError, Reachability,
};
use minip2p_core::{Multiaddr, PeerAddr, PeerId, select_direct_addrs};
use minip2p_platform::Now;
use minip2p_relay::{HOP_PROTOCOL_ID, HopReservation, HopReservationOutput, ReservationOutcome};
use minip2p_transport::{ConnectionId, StreamId};

use crate::ReservationPolicy;
use crate::acquire::{self, AcquireError, Acquired};
use crate::agent::{DialPurpose, Shared, StreamInput, StreamRole, close_write, reset, send};
use crate::events::NatEvent;
use crate::swarm::NatSwarm;
use crate::types::{ReachabilityState, ReservationInfo};

/// The longest reservation retry backoff, unless the configured base
/// [`reservation_retry_backoff_ms`](crate::NatConfig::reservation_retry_backoff_ms)
/// is longer still.
pub const MAX_RESERVATION_RETRY_BACKOFF_MS: u64 = 60_000;

/// How long an AutoNAT server's vote counts toward reachability: 15 minutes.
pub const AUTONAT_VOTE_TTL_MS: u64 = 15 * 60 * 1_000;

/// The delay before retrying after `failures` earlier consecutive failures:
/// `base` doubled per failure, plus up to a fifth more as jitter, capped at
/// [`MAX_RESERVATION_RETRY_BACKOFF_MS`] (or `base`, if larger). Once the
/// doubling reaches the cap, the delay is drawn from the cap's top fifth,
/// never below `base`.
///
/// The jitter keeps clients that failed together from retrying together,
/// including during a long outage at the cap, and staying under the next
/// doubling keeps the delays strictly growing until the cap.
fn retry_backoff_ms(base: u64, failures: u32, jitter: u64) -> u64 {
    let cap = MAX_RESERVATION_RETRY_BACKOFF_MS.max(base);
    let exp = base.saturating_mul(1u64.checked_shl(failures).unwrap_or(u64::MAX));
    let draw = |spread: u64| if spread == 0 { 0 } else { jitter % spread };
    let delay = exp.saturating_add(draw(exp / 5));
    if delay < cap {
        delay
    } else {
        (cap - draw(cap / 5)).max(base)
    }
}

/// Advances SplitMix64 `state` and returns its next value.
fn next_jitter(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// Milliseconds to wait before renewing a reservation with `lifetime_secs`
/// left: half of it, DHCP-T1 style.
///
/// With an accurate lifetime this renews before expiry however short it is (a
/// 1s reservation renews after 500ms), and since each renewal is granted a
/// similar lifetime, renewals stay half a lifetime apart rather than piling up
/// as expiry nears. The delay is never under 500ms: a zero lifetime counts as
/// one second, so renewal never busy-loops.
///
/// The relay's `expire` is an absolute timestamp, so a relay clock ahead of
/// ours by `S` inflates the lifetime we compute by `S` without our being able
/// to tell. When the reported lifetime is not capped by
/// `reservation_default_ttl_secs`, renewal still lands before the actual
/// expiry only while `S` is less than half of it (at exactly half it lands at
/// expiry); a binding cap only shortens the delay.
/// A fixed margin before expiry would tolerate only skew below the margin.
fn renewal_delay_ms(lifetime_secs: u64) -> u64 {
    lifetime_secs.max(1).saturating_mul(1_000) / 2
}

/// Progress of one outbound single-stream exchange (probe or reservation).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExchangeStage {
    /// Waiting for the server's connection to reach `PeerReady`
    /// (a dial may be in flight).
    WaitPeerReady,
    /// Stream allocated on `conn`; waiting for multistream negotiation.
    WaitStreamReady {
        conn: ConnectionId,
        stream: StreamId,
    },
    /// Request sent; waiting for the response.
    AwaitResponse {
        conn: ConnectionId,
        stream: StreamId,
    },
}

impl ExchangeStage {
    fn stream(&self) -> Option<(ConnectionId, StreamId)> {
        match self {
            Self::WaitStreamReady { conn, stream } | Self::AwaitResponse { conn, stream } => {
                Some((*conn, *stream))
            }
            Self::WaitPeerReady => None,
        }
    }

    /// Whether the exchange's stream lives on `conn_id`.
    fn is_on(&self, conn_id: ConnectionId) -> bool {
        self.stream().is_some_and(|(conn, _)| conn == conn_id)
    }
}

/// Resets an abandoned exchange stream and releases it.
fn abandon_stream(
    peer: &PeerId,
    stage: ExchangeStage,
    swarm: &mut dyn NatSwarm,
    shared: &mut Shared,
    now: Now,
) {
    if let Some((conn, stream)) = stage.stream() {
        reset(swarm, peer, conn, stream, now);
        shared.release_stream(conn, stream);
    }
}

/// Half-closes a completed exchange stream and releases it.
fn finish_stream(
    peer: &PeerId,
    conn: ConnectionId,
    stream: StreamId,
    swarm: &mut dyn NatSwarm,
    shared: &mut Shared,
    now: Now,
) {
    close_write(swarm, peer, conn, stream, now);
    shared.release_stream(conn, stream);
}

// ---------------------------------------------------------------------------
// Reachability prober
// ---------------------------------------------------------------------------

/// One in-flight AutoNAT probe.
struct ProbeFlight {
    server: PeerAddr,
    stage: ExchangeStage,
    machine: Option<AutoNatClient>,
    deadline: u64,
}

/// One server's latest conclusive probe verdict.
struct Vote {
    /// The dialable addresses it confirmed; empty for a private vote.
    public_addrs: Vec<Multiaddr>,
    cast_at_ms: u64,
}

/// AutoNAT probing that trusts a quorum of distinct servers.
///
/// Each server holds at most one vote, its latest, for
/// [`AUTONAT_VOTE_TTL_MS`]; only the last M servers to vote count. The
/// verdict turns Public once N of them confirm the same address (and only
/// addresses N of them confirm are reported), or Private once N report a
/// failed dial-back. Each flip emits exactly one
/// [`NatEvent::ReachabilityChanged`].
pub(crate) struct Prober {
    verdict: ReachabilityState,
    /// The latest vote of each recent server.
    votes: BTreeMap<PeerId, Vote>,
    /// Most recently confirmed, directly dialable public addresses.
    public_addrs: Vec<Multiaddr>,
    flight: Option<ProbeFlight>,
    next_probe_at: Option<u64>,
    server_idx: usize,
}

impl Prober {
    fn new(has_servers: bool) -> Self {
        Self {
            verdict: ReachabilityState::Unknown,
            votes: BTreeMap::new(),
            public_addrs: Vec::new(),
            flight: None,
            // Without configured servers there is nothing to schedule, and
            // the agent must not report a phantom timeout.
            next_probe_at: has_servers.then_some(0),
            server_idx: 0,
        }
    }

    fn on_tick(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        self.settle_verdict(shared, now);
        if let Some(flight) = &self.flight
            && now.monotonic_ms >= flight.deadline
        {
            self.abort_flight(swarm, shared, now);
        }
        if self.flight.is_none()
            && let Some(due) = self.next_probe_at
            && now.monotonic_ms >= due
        {
            self.start_probe(swarm, shared, now);
        }
    }

    /// Starts the next probe if the preconditions hold.
    fn start_probe(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        if shared.config.autonat_servers.is_empty() || shared.listen_addrs.is_empty() {
            // Nothing to probe (yet); check again at the unsettled cadence.
            self.next_probe_at = Some(now.monotonic_ms + shared.config.probe_interval_unsettled_ms);
            return;
        }
        let servers = &shared.config.autonat_servers;
        let server = servers
            .get(
                self.server_idx
                    .checked_rem(servers.len())
                    .expect("empty AutoNAT server lists return before scheduling"),
            )
            .expect("the checked AutoNAT server cursor is within the configured list")
            .clone();
        let deadline_ms = shared.config.probe_deadline_ms;
        // Another machine may already be dialing this peer (an AutoNAT
        // server can double as the configured relay); the acquisition then
        // waits on that connection.
        let result = acquire::start(
            &server,
            AUTONAT_PROTOCOL_ID,
            DialPurpose::Probe(server.peer_id().clone()),
            deadline_ms,
            swarm,
            shared,
            now,
        );
        self.flight = Some(ProbeFlight {
            server,
            stage: ExchangeStage::WaitPeerReady,
            machine: None,
            deadline: now.monotonic_ms + deadline_ms,
        });
        self.next_probe_at = None;
        self.on_acquired(result, swarm, shared, now);
    }

    /// Applies one step of the probe stream acquisition. A failure (the
    /// server is unreachable or does not serve AutoNAT) rotates servers.
    fn on_acquired(
        &mut self,
        result: Result<Acquired, AcquireError>,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        let Some(flight) = &mut self.flight else {
            return;
        };
        match result {
            Ok(Acquired::Waiting) => {}
            Ok(Acquired::Opened(conn, stream)) => {
                shared.own_stream(
                    flight.server.peer_id(),
                    conn,
                    stream,
                    StreamRole::AutonatProbe,
                );
                flight.machine = Some(AutoNatClient::new(
                    &shared.local_peer_id,
                    &shared.listen_addrs,
                ));
                flight.stage = ExchangeStage::WaitStreamReady { conn, stream };
            }
            Err(_) => self.abort_flight(swarm, shared, now),
        }
    }

    fn on_peer_ready(
        &mut self,
        peer: &PeerId,
        conn: ConnectionId,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        let Some(flight) = &self.flight else {
            return;
        };
        if flight.stage != ExchangeStage::WaitPeerReady || flight.server.peer_id() != peer {
            return;
        }
        if let Some(result) = acquire::on_ready(peer, conn, AUTONAT_PROTOCOL_ID, swarm, now) {
            self.on_acquired(result, swarm, shared, now);
        }
    }

    /// `conn_id` to `peer` closed. A probe whose stream lived on it is lost,
    /// as is one waiting for a server that can no longer become ready.
    fn on_connection_closed(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        swarm: &dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        let Some(flight) = &self.flight else {
            return;
        };
        if flight.server.peer_id() != peer {
            return;
        }
        let lost = flight.stage.is_on(conn_id)
            || (flight.stage == ExchangeStage::WaitPeerReady
                && !acquire::can_become_ready(peer, swarm, shared, now));
        if lost {
            self.lose_flight(shared, now);
        }
    }

    /// The server's connection `old` was replaced. A probe still waiting for
    /// readiness carries on with the new connection; one whose stream lived
    /// on `old` is lost like on a disconnect.
    fn on_connection_replaced(
        &mut self,
        peer: &PeerId,
        old: ConnectionId,
        shared: &mut Shared,
        now: Now,
    ) {
        if self
            .flight
            .as_ref()
            .is_some_and(|f| f.server.peer_id() == peer && f.stage.is_on(old))
        {
            self.lose_flight(shared, now);
        }
    }

    /// The flight's connection is gone. Releasing local bookkeeping is
    /// sufficient: there is no stream left to reset.
    fn lose_flight(&mut self, shared: &mut Shared, now: Now) {
        if let Some(flight) = self.flight.take()
            && let Some((conn, stream)) = flight.stage.stream()
        {
            shared.release_stream(conn, stream);
        }
        self.server_idx += 1;
        self.next_probe_at = Some(now.monotonic_ms + shared.config.probe_interval_unsettled_ms);
    }

    /// A probe dial toward `peer` failed. Only a probe still waiting on
    /// that server, with no other way to become ready, is aborted: the
    /// failure may belong to an earlier flight's dial after a rotation.
    fn on_dial_failed(
        &mut self,
        peer: &PeerId,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        if self.flight.as_ref().is_some_and(|f| {
            f.stage == ExchangeStage::WaitPeerReady
                && f.server.peer_id() == peer
                && !acquire::can_become_ready(peer, swarm, shared, now)
        }) {
            self.abort_flight(swarm, shared, now);
        }
    }

    /// Drains the AutoNAT client after an input and returns the probe's
    /// verdict, if it reached one; `Err` when the machine rejected the input.
    fn settle(
        machine: &mut AutoNatClient,
        fed: Result<(), AutoNatError>,
    ) -> Result<Option<Reachability>, ()> {
        if fed.is_err() {
            return Err(());
        }
        let mut sample = None;
        while let Some(output) = machine.poll_output() {
            if let AutoNatClientOutput::Outcome(reachability) = output {
                sample = Some(reachability);
            }
        }
        Ok(sample)
    }

    /// Routes a probe-stream event. Returns whether the verdict flipped.
    fn on_stream_input(
        &mut self,
        stream: StreamId,
        input: StreamInput<'_>,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) -> bool {
        let Some(flight) = &mut self.flight else {
            return false;
        };
        let Some((conn, _)) = flight.stage.stream().filter(|(_, s)| *s == stream) else {
            return false;
        };
        let Some(machine) = flight.machine.as_mut() else {
            return false;
        };
        let fed = match (flight.stage, input) {
            (ExchangeStage::WaitStreamReady { .. }, StreamInput::Ready) => {
                let server_peer = flight.server.peer_id().clone();
                while let Some(output) = machine.poll_output() {
                    if let AutoNatClientOutput::Outbound(data) = output {
                        send(swarm, &server_peer, conn, stream, data, now);
                    }
                }
                flight.stage = ExchangeStage::AwaitResponse { conn, stream };
                return false;
            }
            (ExchangeStage::AwaitResponse { .. }, StreamInput::Data(data)) => machine.on_data(data),
            (ExchangeStage::AwaitResponse { .. }, StreamInput::RemoteWriteClosed) => {
                machine.on_remote_write_closed()
            }
            (_, StreamInput::Closed) => {
                self.abort_flight(swarm, shared, now);
                return false;
            }
            _ => return false,
        };
        match Self::settle(machine, fed) {
            Err(()) => {
                self.abort_flight(swarm, shared, now);
                false
            }
            Ok(Some(reachability)) => {
                let server = flight.server.peer_id().clone();
                self.finish_flight(swarm, shared, now);
                self.record_vote(server, &reachability, shared, now)
            }
            Ok(None) => false,
        }
    }

    /// Records `server`'s probe verdict as its only vote and applies the
    /// quorum rule. Returns whether the verdict flipped.
    fn record_vote(
        &mut self,
        server: PeerId,
        reachability: &Reachability,
        shared: &mut Shared,
        now: Now,
    ) -> bool {
        let public_addrs = match reachability {
            Reachability::Public { addrs, .. } => {
                let selected = select_direct_addrs(addrs, None, None);
                // A successful dial-back is useful public evidence only when
                // it leaves the application with an address something can
                // actually dial. Counting an empty selection could release a
                // WhenPrivate reservation while providing no direct
                // replacement path.
                if selected.is_empty() {
                    return false;
                }
                selected
            }
            Reachability::Private { .. } => Vec::new(),
            // No signal: an inconclusive probe never casts a vote.
            Reachability::Unknown { .. } => return false,
        };
        self.votes.insert(
            server,
            Vote {
                public_addrs,
                cast_at_ms: now.monotonic_ms,
            },
        );
        self.settle_verdict(shared, now)
    }

    /// Drops expired votes and votes beyond the window, then re-derives the
    /// verdict. A quorum flips it; disagreement short of a quorum keeps it,
    /// so one server cannot flap it. Once fewer than a quorum of votes are
    /// live, the evidence for any verdict is gone and it lapses to Unknown.
    /// Returns whether the verdict flipped.
    fn settle_verdict(&mut self, shared: &mut Shared, now: Now) -> bool {
        let now_ms = now.monotonic_ms;
        self.votes
            .retain(|_, vote| now_ms.saturating_sub(vote.cast_at_ms) < AUTONAT_VOTE_TTL_MS);
        let window = usize::from(shared.config.confidence_window.max(1));
        while self.votes.len() > window {
            let oldest = self
                .votes
                .iter()
                .min_by_key(|(_, vote)| vote.cast_at_ms)
                .map(|(server, _)| server.clone())
                .expect("the window is over a positive size");
            self.votes.remove(&oldest);
        }

        // A threshold above the bounded window can never be reached. Treat
        // it as unanimity for the configured window instead of leaving
        // reachability permanently Unknown.
        let threshold = usize::from(shared.config.confidence_threshold.max(1)).min(window);
        let confirmed = self.quorum_addrs(threshold);
        let private_votes = self
            .votes
            .values()
            .filter(|vote| vote.public_addrs.is_empty())
            .count();
        let new = if !confirmed.is_empty() {
            ReachabilityState::Public
        } else if private_votes >= threshold {
            ReachabilityState::Private
        } else if self.votes.len() < threshold {
            ReachabilityState::Unknown
        } else {
            self.verdict
        };
        if new == self.verdict {
            if new == ReachabilityState::Public
                && !confirmed.is_empty()
                && confirmed != self.public_addrs
            {
                self.public_addrs = confirmed.clone();
                shared.push_event(NatEvent::PublicAddressesChanged { addrs: confirmed });
            }
            return false;
        }
        let old = core::mem::replace(&mut self.verdict, new);
        self.public_addrs = confirmed;
        shared.push_event(NatEvent::ReachabilityChanged {
            old,
            new,
            confirmed_addrs: self.public_addrs.clone(),
        });
        true
    }

    /// The addresses at least `threshold` live votes confirm, newest vote
    /// first, each in its server's order.
    fn quorum_addrs(&self, threshold: usize) -> Vec<Multiaddr> {
        let mut newest_first: Vec<&Vote> = self.votes.values().collect();
        newest_first.sort_by_key(|vote| core::cmp::Reverse(vote.cast_at_ms));
        let mut confirmed = Vec::new();
        for addr in newest_first.iter().flat_map(|vote| &vote.public_addrs) {
            let votes = newest_first
                .iter()
                .filter(|vote| vote.public_addrs.contains(addr))
                .count();
            if votes >= threshold && !confirmed.contains(addr) {
                confirmed.push(addr.clone());
            }
        }
        confirmed
    }

    /// Ends the current flight cleanly (response consumed), rotates to the
    /// next server so no single server answers twice in a row, and
    /// schedules the next probe.
    fn finish_flight(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        if let Some(flight) = self.flight.take()
            && let Some((conn, stream)) = flight.stage.stream()
        {
            finish_stream(flight.server.peer_id(), conn, stream, swarm, shared, now);
        }
        self.server_idx += 1;
        self.schedule_next(shared, now);
    }

    /// Ends the current flight without a sample (error/timeout/refusal),
    /// rotates servers, and schedules a quick retry.
    fn abort_flight(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        if let Some(flight) = self.flight.take() {
            abandon_stream(flight.server.peer_id(), flight.stage, swarm, shared, now);
        }
        self.server_idx += 1;
        self.next_probe_at = Some(now.monotonic_ms + shared.config.probe_interval_unsettled_ms);
    }

    fn schedule_next(&mut self, shared: &mut Shared, now: Now) {
        let interval = if self.verdict == ReachabilityState::Unknown {
            shared.config.probe_interval_unsettled_ms
        } else {
            shared.config.probe_interval_settled_ms
        };
        self.next_probe_at = Some(now.monotonic_ms + interval);
    }

    fn next_deadline(&self) -> Option<u64> {
        let flight_deadline = self.flight.as_ref().map(|f| f.deadline);
        match (flight_deadline, self.next_probe_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

// ---------------------------------------------------------------------------
// Reservation manager
// ---------------------------------------------------------------------------

/// Where the reservation flow currently stands.
enum ResState {
    /// Not holding and not acquiring (policy says no, or nothing to do).
    Idle,
    /// Acquisition (or renewal) exchange in flight.
    Acquiring {
        relay: PeerAddr,
        stage: ExchangeStage,
        machine: Option<HopReservation>,
        deadline: u64,
    },
    /// Reservation held on connection `conn`; renewal fires at
    /// `info.renew_at_mono_ms`.
    Reserved {
        relay: PeerAddr,
        conn: ConnectionId,
        info: ReservationInfo,
        keep_alive_at_mono_ms: Option<u64>,
    },
    /// Waiting out a failure/refusal before trying the (rotated) relay.
    Backoff { until: u64 },
}

/// Holds a relay reservation according to policy: `Wanted ↔ Reserved`, with
/// renewal scheduled from the relay's absolute `expire`, a default-TTL
/// fallback for missing expiries or clockless hosts, and relay rotation
/// plus backoff on refusal.
///
/// rust-libp2p relays drop a reservation with the connection that made it,
/// so a reservation is bound to that exact connection.
pub(crate) struct ReservationManager {
    state: ResState,
    relay_idx: usize,
    /// The initial policy reconciliation is an immediate timer source. Once
    /// it runs, later policy flips call `sync` directly from probe handling.
    needs_sync: bool,
    /// The reservation being renewed and the connection it was made on, so
    /// its loss emits [`NatEvent::RelayReservationLost`] exactly once.
    held: Option<(PeerId, ConnectionId)>,
    /// Backoffs since the last held reservation; each doubles the next.
    failures: u32,
    /// SplitMix64 state for backoff jitter, seeded by the host.
    jitter: u64,
}

impl ReservationManager {
    fn new(config: &crate::NatConfig, jitter_seed: u64) -> Self {
        Self {
            state: ResState::Idle,
            relay_idx: 0,
            needs_sync: !config.relays.is_empty()
                && config.reservation_policy != ReservationPolicy::Never,
            held: None,
            failures: 0,
            jitter: jitter_seed,
        }
    }

    fn wanted(&self, shared: &Shared, verdict: ReachabilityState) -> bool {
        if shared.config.relays.is_empty() {
            return false;
        }
        match shared.config.reservation_policy {
            ReservationPolicy::Never => false,
            ReservationPolicy::Always => true,
            // Reserve unless we are confidently public: a NAT'd listener
            // must be dialable while evidence is still being gathered.
            ReservationPolicy::WhenPrivate => verdict != ReachabilityState::Public,
        }
    }

    /// Reconciles the state machine with the policy and clock.
    fn sync(
        &mut self,
        verdict: ReachabilityState,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        self.needs_sync = false;
        let wanted = self.wanted(shared, verdict);
        if !wanted {
            self.release(swarm, shared, now);
            return;
        }
        match &self.state {
            ResState::Idle => self.begin_acquire(swarm, shared, now),
            ResState::Backoff { until } if now.monotonic_ms >= *until => {
                self.begin_acquire(swarm, shared, now);
            }
            ResState::Reserved { info, conn, .. } if now.monotonic_ms >= info.renew_at_mono_ms => {
                self.held = Some((info.relay.clone(), *conn));
                self.begin_acquire(swarm, shared, now);
            }
            ResState::Reserved {
                relay,
                keep_alive_at_mono_ms: Some(due),
                ..
            } if now.monotonic_ms >= *due => {
                // Relay liveness is re-established from lifecycle events; a
                // refused ping changes nothing here.
                match swarm.ping(relay.peer_id(), now.monotonic_ms) {
                    Ok(()) | Err(_) => {}
                }
                if let ResState::Reserved {
                    keep_alive_at_mono_ms,
                    ..
                } = &mut self.state
                {
                    *keep_alive_at_mono_ms = Some(
                        now.monotonic_ms
                            .saturating_add(shared.config.reservation_keep_alive_interval_ms),
                    );
                }
            }
            ResState::Acquiring { deadline, .. } if now.monotonic_ms >= *deadline => {
                self.fail_acquire(swarm, shared, now);
            }
            _ => {}
        }
    }

    /// Drops any held reservation and stops acquiring (policy says no).
    fn release(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        match core::mem::replace(&mut self.state, ResState::Idle) {
            ResState::Reserved { relay, .. } => {
                shared.push_event(NatEvent::RelayReservationLost {
                    relay: relay.peer_id().clone(),
                });
            }
            ResState::Acquiring { relay, stage, .. } => {
                abandon_stream(relay.peer_id(), stage, swarm, shared, now);
                self.emit_held_lost(shared);
            }
            _ => {}
        }
        self.held = None;
    }

    fn begin_acquire(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        let relays = &shared.config.relays;
        if relays.is_empty() {
            self.state = ResState::Idle;
            return;
        }
        let relay = relays
            .get(
                self.relay_idx
                    .checked_rem(relays.len())
                    .expect("empty relay lists return before acquisition"),
            )
            .expect("the checked relay cursor is within the configured list")
            .clone();
        self.acquire_from(relay, swarm, shared, now);
    }

    /// Starts a reservation exchange with `relay`. A connect attempt's relay
    /// leg already dialing this relay is shared instead of replaced.
    fn acquire_from(
        &mut self,
        relay: PeerAddr,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        let deadline_ms = shared.config.relay_leg_deadline_ms;
        let result = acquire::start(
            &relay,
            HOP_PROTOCOL_ID,
            DialPurpose::Reserve(relay.peer_id().clone()),
            deadline_ms,
            swarm,
            shared,
            now,
        );
        self.state = ResState::Acquiring {
            relay,
            stage: ExchangeStage::WaitPeerReady,
            machine: None,
            deadline: now.monotonic_ms + deadline_ms,
        };
        self.on_acquired(result, swarm, shared, now);
    }

    /// Applies one step of the reservation stream acquisition.
    fn on_acquired(
        &mut self,
        result: Result<Acquired, AcquireError>,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        let ResState::Acquiring {
            relay,
            stage,
            machine,
            ..
        } = &mut self.state
        else {
            return;
        };
        match result {
            Ok(Acquired::Waiting) => {}
            Ok(Acquired::Opened(conn, stream)) => {
                shared.own_stream(relay.peer_id(), conn, stream, StreamRole::HopReserve);
                *machine = Some(HopReservation::new());
                *stage = ExchangeStage::WaitStreamReady { conn, stream };
            }
            Err(_) => self.fail_acquire(swarm, shared, now),
        }
    }

    /// Emits the loss of a reservation being renewed, once.
    fn emit_held_lost(&mut self, shared: &mut Shared) {
        if let Some((relay, _)) = self.held.take() {
            shared.push_event(NatEvent::RelayReservationLost { relay });
        }
    }

    /// The acquisition failed (dial error, refusal, timeout, machine
    /// error): emit `RelayReservationLost` if a reservation was being
    /// renewed, rotate relays, and back off.
    fn fail_acquire(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        if let ResState::Acquiring { relay, stage, .. } =
            core::mem::replace(&mut self.state, ResState::Idle)
        {
            abandon_stream(relay.peer_id(), stage, swarm, shared, now);
        }
        self.emit_held_lost(shared);
        self.back_off(shared, now);
    }

    /// Rotates to the next relay after an exponential, jittered backoff.
    fn back_off(&mut self, shared: &Shared, now: Now) {
        self.relay_idx += 1;
        let delay = retry_backoff_ms(
            shared.config.reservation_retry_backoff_ms,
            self.failures,
            next_jitter(&mut self.jitter),
        );
        self.failures = self.failures.saturating_add(1);
        self.state = ResState::Backoff {
            until: now.monotonic_ms.saturating_add(delay),
        };
    }

    fn on_peer_ready(
        &mut self,
        peer: &PeerId,
        conn: ConnectionId,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        let ResState::Acquiring { relay, stage, .. } = &self.state else {
            return;
        };
        if *stage != ExchangeStage::WaitPeerReady || relay.peer_id() != peer {
            return;
        }
        if let Some(result) = acquire::on_ready(peer, conn, HOP_PROTOCOL_ID, swarm, now) {
            self.on_acquired(result, swarm, shared, now);
        }
    }

    /// `conn_id` to `peer` closed. The relay session carries inbound
    /// circuits; a reservation made on it is useless without it, so it is
    /// lost and reacquired after a short backoff. An exchange on it, or one
    /// waiting for a relay that can no longer become ready, fails likewise.
    fn on_connection_closed(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        swarm: &dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        if self.held.as_ref() == Some(&(peer.clone(), conn_id)) {
            self.emit_held_lost(shared);
        }
        match &self.state {
            ResState::Reserved { relay, conn, .. }
                if relay.peer_id() == peer && *conn == conn_id =>
            {
                shared.push_event(NatEvent::RelayReservationLost {
                    relay: peer.clone(),
                });
                self.back_off(shared, now);
            }
            ResState::Acquiring { relay, stage, .. }
                if relay.peer_id() == peer
                    && (stage.is_on(conn_id)
                        || (*stage == ExchangeStage::WaitPeerReady
                            && !acquire::can_become_ready(peer, swarm, shared, now))) =>
            {
                if let Some((conn, stream)) = stage.stream() {
                    // The connection is terminal; nothing to reset.
                    shared.release_stream(conn, stream);
                }
                self.emit_held_lost(shared);
                self.back_off(shared, now);
            }
            _ => {}
        }
    }

    /// `peer`'s connection `old` was replaced. A reservation made on `old`
    /// is reported lost at once (withdrawing its circuit address) and
    /// reacquired over the new connection; an exchange whose stream lived
    /// on `old` restarts there. Work already on the new connection stays.
    fn on_connection_replaced(
        &mut self,
        peer: &PeerId,
        old: ConnectionId,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        if self.held.as_ref() == Some(&(peer.clone(), old)) {
            self.emit_held_lost(shared);
        }
        let relay = match &self.state {
            ResState::Reserved { relay, conn, .. } if relay.peer_id() == peer && *conn == old => {
                shared.push_event(NatEvent::RelayReservationLost {
                    relay: peer.clone(),
                });
                relay.clone()
            }
            ResState::Acquiring { relay, stage, .. }
                if relay.peer_id() == peer && stage.is_on(old) =>
            {
                if let Some((conn, stream)) = stage.stream() {
                    // The stream lived on the retired connection: release
                    // it without a reset.
                    shared.release_stream(conn, stream);
                }
                relay.clone()
            }
            _ => return,
        };
        self.acquire_from(relay, swarm, shared, now);
    }

    /// A reservation dial toward `peer` failed. It is moot for an
    /// acquisition from another relay (an earlier flight's dial, after a
    /// rotation), and while the relay is connected or another dial toward
    /// it is in flight (say, the connection that replaced the one we
    /// reserved on).
    fn on_dial_failed(
        &mut self,
        peer: &PeerId,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        if matches!(
            &self.state,
            ResState::Acquiring {
                relay,
                stage: ExchangeStage::WaitPeerReady,
                ..
            } if relay.peer_id() == peer && !acquire::can_become_ready(peer, swarm, shared, now)
        ) {
            self.fail_acquire(swarm, shared, now);
        }
    }

    fn on_stream_input(
        &mut self,
        stream: StreamId,
        input: StreamInput<'_>,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        let ResState::Acquiring {
            relay,
            stage,
            machine,
            ..
        } = &mut self.state
        else {
            return;
        };
        let Some((conn, _)) = stage.stream().filter(|(_, s)| *s == stream) else {
            return;
        };
        let Some(m) = machine.as_mut() else {
            return;
        };
        let fed = match (*stage, input) {
            (ExchangeStage::WaitStreamReady { .. }, StreamInput::Ready) => {
                let relay_peer = relay.peer_id().clone();
                while let Some(output) = m.poll_output() {
                    if let HopReservationOutput::Outbound(data) = output {
                        send(swarm, &relay_peer, conn, stream, data, now);
                    }
                }
                *stage = ExchangeStage::AwaitResponse { conn, stream };
                return;
            }
            (ExchangeStage::AwaitResponse { .. }, StreamInput::Data(data)) => m.on_data(data),
            (ExchangeStage::AwaitResponse { .. }, StreamInput::RemoteWriteClosed) => {
                m.on_remote_write_closed()
            }
            (_, StreamInput::Closed) => {
                self.fail_acquire(swarm, shared, now);
                return;
            }
            _ => return,
        };
        if fed.is_err() {
            self.fail_acquire(swarm, shared, now);
            return;
        }
        let mut outcome = None;
        while let Some(output) = m.poll_output() {
            if let HopReservationOutput::Outcome(o) = output {
                outcome = Some(o);
            }
        }
        match outcome {
            Some(ReservationOutcome::Accepted { reservation, .. }) => {
                let relay = relay.clone();
                let expire = reservation.and_then(|r| r.expire);
                self.complete_acquire(relay, conn, stream, expire, swarm, shared, now);
            }
            Some(ReservationOutcome::Refused { .. }) => {
                self.fail_acquire(swarm, shared, now);
            }
            None => {}
        }
    }

    /// A reservation (initial or renewal) was accepted: compute the renewal
    /// time and announce it.
    #[expect(
        clippy::too_many_arguments,
        reason = "the accepted exchange's identity plus the call context"
    )]
    fn complete_acquire(
        &mut self,
        relay: PeerAddr,
        conn: ConnectionId,
        stream: StreamId,
        expire_unix_secs: Option<u64>,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        let relay_peer = relay.peer_id().clone();
        finish_stream(&relay_peer, conn, stream, swarm, shared, now);
        self.held = None;

        let default_ttl = shared.config.reservation_default_ttl_secs;
        // Renew at half the reported lifetime when both the expiry and a wall
        // clock exist; otherwise at half the default TTL. Clockless renewal is
        // approximate by design.
        //
        // The relay owns `expire` and is not trusted to report it sanely.
        // Clamping to the default TTL bounds the renewal delay, so a value far
        // in the future cannot postpone renewal indefinitely. Past that, a
        // relay enforcing a shorter lifetime than it reports can still expire
        // first: it then drops the reservation with the connection still up
        // -- so no `RelayReservationLost` -- while we keep advertising a
        // ticket that dialers get NO_RESERVATION on. An expiry at or before now (a stale
        // value, or clock skew) is treated as no expiry at all.
        let lifetime_secs = match (expire_unix_secs, now.unix_seconds) {
            (Some(expire), Some(unix_now)) if expire > unix_now => {
                (expire - unix_now).min(default_ttl)
            }
            _ => default_ttl,
        };
        let info = ReservationInfo {
            relay: relay_peer.clone(),
            expires_unix_secs: expire_unix_secs,
            // The relay controls `expire`, so this conversion must not let a
            // large value wrap the monotonic renewal deadline.
            renew_at_mono_ms: now
                .monotonic_ms
                .saturating_add(renewal_delay_ms(lifetime_secs)),
        };
        shared.push_event(NatEvent::RelayReserved {
            relay: relay_peer,
            expires_unix_secs: info.expires_unix_secs,
            renew_at_mono_ms: info.renew_at_mono_ms,
        });
        let keep_alive_at_mono_ms = (relay.transport().is_quic_transport()
            && shared.config.reservation_keep_alive_interval_ms > 0)
            .then(|| {
                now.monotonic_ms
                    .saturating_add(shared.config.reservation_keep_alive_interval_ms)
            });
        self.failures = 0;
        self.state = ResState::Reserved {
            relay,
            conn,
            info,
            keep_alive_at_mono_ms,
        };
    }

    fn active(&self) -> Option<&ReservationInfo> {
        match &self.state {
            ResState::Reserved { info, .. } => Some(info),
            _ => None,
        }
    }

    fn next_deadline(&self) -> Option<u64> {
        match &self.state {
            ResState::Idle if self.needs_sync => Some(0),
            ResState::Idle => None,
            ResState::Acquiring { deadline, .. } => Some(*deadline),
            ResState::Reserved {
                info,
                keep_alive_at_mono_ms,
                ..
            } => Some(
                keep_alive_at_mono_ms.map_or(info.renew_at_mono_ms, |keep_alive| {
                    keep_alive.min(info.renew_at_mono_ms)
                }),
            ),
            ResState::Backoff { until } => Some(*until),
        }
    }
}

// ---------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------

/// The agent's own-side housekeeping, running independently of connect
/// attempts.
pub(crate) struct Housekeeping {
    prober: Prober,
    reservations: ReservationManager,
}

impl Housekeeping {
    pub(crate) fn new(config: &crate::NatConfig, jitter_seed: u64) -> Self {
        Self {
            prober: Prober::new(!config.autonat_servers.is_empty()),
            reservations: ReservationManager::new(config, jitter_seed),
        }
    }

    /// Reseeds the reservation backoff jitter.
    pub(crate) fn seed_jitter(&mut self, seed: u64) {
        self.reservations.jitter = seed;
    }

    pub(crate) fn reachability(&self) -> ReachabilityState {
        self.prober.verdict
    }

    pub(crate) fn active_reservation(&self) -> Option<&ReservationInfo> {
        self.reservations.active()
    }

    pub(crate) fn on_tick(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        self.prober.on_tick(swarm, shared, now);
        self.reservations
            .sync(self.prober.verdict, swarm, shared, now);
    }

    pub(crate) fn on_peer_ready(
        &mut self,
        peer: &PeerId,
        conn: ConnectionId,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        self.prober.on_peer_ready(peer, conn, swarm, shared, now);
        self.reservations
            .on_peer_ready(peer, conn, swarm, shared, now);
    }

    pub(crate) fn on_connection_closed(
        &mut self,
        peer: &PeerId,
        conn: ConnectionId,
        swarm: &dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        self.prober
            .on_connection_closed(peer, conn, swarm, shared, now);
        self.reservations
            .on_connection_closed(peer, conn, swarm, shared, now);
    }

    pub(crate) fn on_connection_replaced(
        &mut self,
        peer: &PeerId,
        old: ConnectionId,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        self.prober.on_connection_replaced(peer, old, shared, now);
        self.reservations
            .on_connection_replaced(peer, old, swarm, shared, now);
    }

    pub(crate) fn on_probe_dial_failed(
        &mut self,
        peer: &PeerId,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        self.prober.on_dial_failed(peer, swarm, shared, now);
    }

    pub(crate) fn on_reserve_dial_failed(
        &mut self,
        peer: &PeerId,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        self.reservations.on_dial_failed(peer, swarm, shared, now);
    }

    pub(crate) fn on_stream_input(
        &mut self,
        role: StreamRole,
        stream: StreamId,
        input: StreamInput<'_>,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        match role {
            StreamRole::AutonatProbe => {
                if self
                    .prober
                    .on_stream_input(stream, input, swarm, shared, now)
                {
                    // A verdict flip can change what the reservation policy
                    // wants; reconcile inside the same cascade.
                    self.reservations
                        .sync(self.prober.verdict, swarm, shared, now);
                }
            }
            StreamRole::HopReserve => {
                self.reservations
                    .on_stream_input(stream, input, swarm, shared, now);
            }
            StreamRole::HopConnect(_)
            | StreamRole::StopInbound(_)
            | StreamRole::DcutrAttempt(_)
            | StreamRole::DcutrInbound(_)
            | StreamRole::RejectedControl => {}
        }
    }

    pub(crate) fn next_deadline(&self) -> Option<u64> {
        match (
            self.prober.next_deadline(),
            self.reservations.next_deadline(),
        ) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// `true` when nothing is actively in flight (scheduled future probes
    /// don't count as work).
    pub(crate) fn is_quiet(&self) -> bool {
        self.prober.flight.is_none()
            && matches!(
                self.reservations.state,
                ResState::Idle | ResState::Reserved { .. }
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A configured base at or above the cap is honoured in full, whatever
    /// the jitter draws.
    #[test]
    fn a_base_above_the_cap_is_never_shortened() {
        for jitter in [0, 1, 7_919, u64::MAX] {
            assert_eq!(retry_backoff_ms(120_000, 0, jitter), 120_000);
            assert_eq!(retry_backoff_ms(120_000, 5, jitter), 120_000);
        }
    }
}
