use alloc::collections::{BTreeSet, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use minip2p_core::platform::Now;
use minip2p_core::{ConnectId, Multiaddr, PeerAddr, PeerId, Protocol};
use minip2p_dcutr::{DcutrError, DcutrResponder, DcutrResponderOutput, ResponderEvent};
use minip2p_relay::{ConnectOutcome, HOP_PROTOCOL_ID, HopConnect, HopConnectOutput, RelayError};
use minip2p_transport::{ConnectionId, StreamId};

use crate::acquire::{self, AcquireError, Acquired};
use crate::agent::{
    ConnectLegs, DialPurpose, Shared, StreamInput, StreamRole, TokenPurpose, reset, send,
};
use crate::config::MAX_DCUTR_ROUNDS;
use crate::events::{BridgeRole, NatAction, NatEvent};
use crate::inbound::select_global_punch_candidates;
use crate::swarm::NatSwarm;
use crate::types::{NatError, NatToken, Path, PromoteError, RelayStage, UpgradeStop};

/// Progress of the relay leg of a connect attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelayLeg {
    /// No relay configured, or the leg was cancelled after a direct win.
    Inactive,
    /// Waiting out the direct leg's head start.
    WaitStagger { until: u64 },
    /// Relay dial issued and/or waiting for `PeerReady` on the relay.
    WaitRelayReady,
    /// HOP stream allocated on `conn`; waiting for multistream negotiation.
    WaitHopReady {
        conn: ConnectionId,
        stream: StreamId,
    },
    /// HOP CONNECT sent; waiting for the relay's STATUS response.
    AwaitHopStatus {
        conn: ConnectionId,
        stream: StreamId,
    },
    /// Circuit bridged; the stream is being promoted through secure-mux.
    Bridged {
        conn: ConnectionId,
        stream: StreamId,
    },
    /// The leg failed; only the direct leg (if any) can still win.
    Failed,
}

/// Per-target relay-leg arbiter: staggered HOP CONNECT, bridge promotion,
/// and DCUtR. Direct candidate racing belongs to the Connection-attempt
/// engine; this machine only tracks a direct establishment so it can report
/// [`Path::Direct`] and upgrade a relayed path.
///
/// The relay leg tries eligible relays one at a time. Each relay gets
/// [`NatConfig::relay_timeout_ms`](crate::NatConfig::relay_timeout_ms),
/// clipped by the attempt's deadline, to carry a usable Relayed path; a
/// relay listed under several addresses splits that across them. Any
/// relay-scoped failure before the circuit carries a path, including a
/// bridge that fails to promote, is reported as
/// [`NatEvent::RelayFailed`] and moves on to the next relay at once; the leg
/// fails with the last relay's error.
///
/// On the Relayed path the reservation holder drives DCUtR. This side
/// answers each round, dials the holder's addresses for one punch window,
/// and settles on the Relayed path once [`MAX_DCUTR_ROUNDS`] rounds failed
/// or an upgrade budget ran out.
pub(crate) struct ConnectAttempt {
    id: ConnectId,
    peer: PeerId,
    /// The relay currently being tried.
    relay: Option<PeerAddr>,
    /// Relays still to try after `relay`, in order.
    untried: VecDeque<PeerAddr>,
    leg: RelayLeg,
    /// The caller's deadline for the attempt, which clips every budget.
    attempt_deadline: Option<u64>,
    /// Absolute end of the current relay's budget, across all its addresses.
    relay_budget_deadline: u64,
    /// Absolute deadline for the current relay address: the end of its part
    /// of the relay's budget. Armed until the circuit carries a path.
    relay_deadline: Option<u64>,
    /// When the current relay address was started, for timeout diagnostics.
    relay_started_at: u64,
    hop: Option<HopConnect>,
    /// The responder for an opened DCUtR stream, or the error that kept it
    /// from being built, reported once the stream carries input.
    dcutr: Option<Result<DcutrResponder, DcutrError>>,
    /// The inbound DCUtR stream, on the promoted circuit.
    dcutr_stream: Option<(ConnectionId, StreamId)>,
    /// The bridge exists and has not been torn down by a close/disconnect.
    bridge_alive: bool,
    /// The bridge stream has been handed to the circuit transport.
    bridge_released: bool,
    /// Circuit connection the host reported for the promotion.
    promoted: Option<ConnectionId>,
    /// The token of the current bridge's promotion request, once requested;
    /// a result for any other token is stale.
    promotion: Option<NatToken>,
    /// The remote write half reached EOF while the bridge was agent-owned.
    bridge_remote_write_closed: bool,
    /// Secure-mux bytes coalesced behind the HOP success response. Passed to
    /// the circuit transport with `PromoteBridge`.
    bridge_pending_data: Vec<u8>,
    punch_addrs: Vec<Multiaddr>,
    /// Connections started by punch dials, in any round.
    punch_conns: BTreeSet<ConnectionId>,
    /// Absolute deadline of the current round's punch window.
    punch_deadline: Option<u64>,
    /// DCUtR rounds the holder started on this attempt's circuit.
    rounds: u32,
    /// When the Relayed path became usable; upgrade budgets count from it.
    relayed_at: u64,
    /// Waiting for the holder to start its first DCUtR round.
    start_deadline: Option<u64>,
    /// When the current DCUtR exchange started.
    exchange_started_at: u64,
    /// The current DCUtR exchange must reach SYNC by then.
    exchange_deadline: Option<u64>,
    /// The whole upgrade must finish by then.
    upgrade_deadline: Option<u64>,
    best: Option<Path>,
    /// The connection carrying `best`.
    path_conn: Option<ConnectionId>,
    last_error: Option<NatError>,
    done: bool,
}

impl ConnectAttempt {
    /// Starts the relay leg of an attempt. Never fails immediately: with no
    /// relay the attempt stays inactive until a direct connection lands or
    /// the caller cancels it.
    pub(crate) fn start(
        id: ConnectId,
        peer: PeerId,
        legs: ConnectLegs,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) -> Option<Self> {
        let untried = if legs.allow_relay {
            relay_order(&shared.config.relays, &legs.target_addrs)
        } else {
            VecDeque::new()
        };

        let mut attempt = Self {
            id,
            peer,
            relay: None,
            untried,
            leg: RelayLeg::Inactive,
            attempt_deadline: legs.deadline_ms,
            relay_budget_deadline: 0,
            relay_deadline: None,
            relay_started_at: 0,
            hop: None,
            dcutr: None,
            dcutr_stream: None,
            bridge_alive: false,
            bridge_released: false,
            promoted: None,
            promotion: None,
            bridge_remote_write_closed: false,
            bridge_pending_data: Vec::new(),
            punch_addrs: Vec::new(),
            punch_conns: BTreeSet::new(),
            punch_deadline: None,
            rounds: 0,
            relayed_at: 0,
            start_deadline: None,
            exchange_started_at: 0,
            exchange_deadline: None,
            upgrade_deadline: None,
            best: None,
            path_conn: None,
            last_error: None,
            done: false,
        };

        if !attempt.untried.is_empty() {
            let stagger = if shared.config.force_relay || !legs.direct_racing {
                0
            } else {
                shared.config.relay_stagger_ms
            };
            if stagger == 0 {
                attempt.try_next_relay(swarm, shared, now);
            } else {
                attempt.leg = RelayLeg::WaitStagger {
                    until: now.monotonic_ms + stagger,
                };
            }
        }

        if attempt.done {
            return None;
        }
        Some(attempt)
    }

    /// Whether `conn_id` is the circuit this attempt promoted.
    pub(crate) fn promotes(&self, conn_id: ConnectionId) -> bool {
        self.promoted == Some(conn_id)
    }

    /// HOP CONNECT sent, and the circuit not yet adopted by the host (which
    /// then counts it itself) nor given up.
    pub(crate) fn holds_circuit_slot(&self) -> bool {
        !self.done
            && self.promoted.is_none()
            && matches!(
                self.leg,
                RelayLeg::AwaitHopStatus { .. } | RelayLeg::Bridged { .. }
            )
    }

    pub(crate) fn is_done(&self) -> bool {
        self.done
    }

    /// Whether an inbound DCUtR stream on `conn_id` starts this attempt's
    /// next round: the holder may run up to [`MAX_DCUTR_ROUNDS`] on the
    /// circuit this attempt promoted, one at a time.
    pub(crate) fn accepts_dcutr(
        &self,
        peer: &PeerId,
        conn_id: ConnectionId,
        shared: &Shared,
    ) -> bool {
        !self.done
            && !shared.config.force_relay
            && &self.peer == peer
            && self.promoted == Some(conn_id)
            && self.upgrade_deadline.is_some()
            && self.dcutr_stream.is_none()
            && self.rounds < MAX_DCUTR_ROUNDS
    }

    /// The holder opened a DCUtR stream: a new round starts. A punch window
    /// still open from the previous round ends here, failed, and its unfinished
    /// dials are aborted.
    pub(crate) fn on_dcutr_stream_opened(
        &mut self,
        conn: ConnectionId,
        stream: StreamId,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        // Transport input can arrive before the tick that expires a budget.
        self.dcutr_stream = Some((conn, stream));
        if self.settle_if_budget_spent(swarm, shared, now) {
            return;
        }
        if self.punch_deadline.take().is_some() {
            shared.abort_attempt_dials(self.id, &self.peer, swarm);
            shared.push_event(NatEvent::HolePunchFailed {
                connect_id: self.id,
                attempt: self.rounds,
                reason: "the remote started the next round".into(),
            });
        }
        self.rounds += 1;
        self.start_deadline = None;
        self.exchange_started_at = now.monotonic_ms;
        self.exchange_deadline =
            Some(self.clip(now.monotonic_ms + shared.config.dcutr_exchange_timeout_ms));
        self.dcutr = Some(DcutrResponder::new(&shared.punch_candidates()));
    }

    pub(crate) fn on_dcutr_stream_input(
        &mut self,
        stream: StreamId,
        input: StreamInput<'_>,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        let Some((conn, _)) = self.dcutr_stream.filter(|(_, s)| *s == stream) else {
            return;
        };
        if self.settle_if_budget_spent(swarm, shared, now) {
            return;
        }
        let exchange_closed = matches!(input, StreamInput::RemoteWriteClosed | StreamInput::Closed);
        if matches!(input, StreamInput::Ready) {
            return;
        }
        let dcutr = match self.dcutr.as_mut() {
            Some(Ok(dcutr)) => dcutr,
            Some(Err(error)) => {
                let reason = error.to_string();
                self.fail_round(reason, swarm, shared, now);
                return;
            }
            None => return,
        };
        let fed = match input {
            StreamInput::Data(data) => dcutr.on_data(data),
            StreamInput::RemoteWriteClosed | StreamInput::Closed => dcutr.on_remote_write_closed(),
            StreamInput::Ready => return,
        };
        if let Err(error) = fed {
            self.fail_round(error.to_string(), swarm, shared, now);
            return;
        }
        let mut outputs = Vec::new();
        while let Some(output) = dcutr.poll_output() {
            outputs.push(output);
        }
        for output in outputs {
            match output {
                DcutrResponderOutput::Outbound(data) => {
                    send(swarm, &self.peer, conn, stream, data, now);
                }
                DcutrResponderOutput::Event(ResponderEvent::ConnectReceived {
                    remote_addrs,
                    ..
                }) => {
                    self.punch_addrs = select_global_punch_candidates(&remote_addrs);
                }
                DcutrResponderOutput::Event(ResponderEvent::SyncReceived) => {
                    // The exchange is done; only the punch window bounds
                    // the rest of the round.
                    self.exchange_deadline = None;
                    self.teardown_dcutr_stream(swarm, shared, now);
                    if self.punch_addrs.is_empty() {
                        self.round_failed(
                            "no dialable remote addresses in DCUtR CONNECT".into(),
                            swarm,
                            shared,
                            now,
                        );
                    } else {
                        self.issue_punch_dials(swarm, shared);
                        self.punch_deadline = Some(
                            self.clip_upgrade(now.monotonic_ms + shared.config.punch_deadline_ms),
                        );
                    }
                }
            }
        }
        if exchange_closed && self.dcutr_stream == Some((conn, stream)) {
            self.fail_round("DCUtR stream closed before SYNC".into(), swarm, shared, now);
        }
    }

    /// The current round's exchange failed before SYNC.
    fn fail_round(
        &mut self,
        reason: String,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        self.teardown_dcutr_stream(swarm, shared, now);
        self.round_failed(reason, swarm, shared, now);
    }

    /// The current round ended without a direct connection. The holder
    /// starts the next one; once it has run them all, or the circuit that
    /// carried them is gone, the attempt settles.
    fn round_failed(
        &mut self,
        reason: String,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        self.exchange_deadline = None;
        self.punch_deadline = None;
        // Punch dials left from this round must not land as a late
        // `Punched` path while the next round runs.
        shared.abort_attempt_dials(self.id, &self.peer, swarm);
        shared.push_event(NatEvent::HolePunchFailed {
            connect_id: self.id,
            attempt: self.rounds,
            reason,
        });
        if self.promoted.is_none() {
            let error = self
                .last_error
                .take()
                .unwrap_or(NatError::DialFailed("promoted circuit closed".into()));
            self.fail(error, swarm, shared, now);
        } else if self.rounds >= MAX_DCUTR_ROUNDS {
            self.settle_relayed(
                UpgradeStop::PunchFailed {
                    rounds: self.rounds,
                },
                swarm,
                shared,
                now,
            );
        }
    }

    /// Ends the attempt on its Relayed path: the circuit stays, the
    /// upgrade work goes.
    fn settle_relayed(
        &mut self,
        reason: UpgradeStop,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        shared.push_event(NatEvent::FellBackToRelay {
            connect_id: self.id,
            peer: self.peer.clone(),
            reason,
        });
        self.release(swarm, shared, now);
    }

    /// `at`, clipped to the attempt's deadline.
    fn clip(&self, at: u64) -> u64 {
        self.attempt_deadline
            .map_or(at, |deadline| deadline.min(at))
    }

    /// `at`, clipped to the whole-upgrade budget.
    fn clip_upgrade(&self, at: u64) -> u64 {
        self.upgrade_deadline
            .map_or(at, |deadline| deadline.min(at))
    }

    /// Earliest pending absolute deadline, for the driver's timer fold-in.
    pub(crate) fn next_deadline(&self) -> Option<u64> {
        if self.done {
            return None;
        }
        let stagger = match self.leg {
            RelayLeg::WaitStagger { until } => Some(until),
            _ => None,
        };
        [
            stagger,
            self.relay_deadline,
            self.punch_deadline,
            self.start_deadline,
            self.exchange_deadline,
            self.upgrade_deadline,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Abandons the attempt silently, cleaning up any held streams and
    /// closing its circuit.
    pub(crate) fn cancel(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        self.teardown_relay_leg(swarm, shared, now);
        self.done = true;
    }

    /// The host's engine settled the attempt on `kept`: drop everything the
    /// attempt still owns without closing that connection, and emit nothing
    /// more for it. A circuit the attempt promoted that is not `kept` closes.
    pub(crate) fn settled(
        &mut self,
        kept: ConnectionId,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        if self.promoted == Some(kept) {
            self.promoted = None;
        }
        self.cancel(swarm, shared, now);
    }

    /// Ends the attempt keeping its circuit: aborts punch dials, resets the
    /// DCUtR stream, and disarms every timer.
    fn release(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        self.promoted = None;
        self.teardown_relay_leg(swarm, shared, now);
        self.done = true;
    }

    // -----------------------------------------------------------------------
    // Inputs routed from the agent
    // -----------------------------------------------------------------------

    pub(crate) fn on_connection_established(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        is_circuit: bool,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        if self.done || *peer != self.peer {
            return;
        }
        if is_circuit {
            if self.promoted == Some(conn_id) {
                if let Some(relay) = self.relay_peer().cloned() {
                    shared.record_path(conn_id, Path::Relayed { relay }, Some(self.id));
                }
                self.relay_deadline = None;
                self.announce_relay_path(conn_id, shared, now);
                if shared.config.force_relay {
                    self.done = true;
                }
            }
            return;
        }
        // Classify punched iff this conn id was issued as a punch dial.
        let path = if self.punch_conns.contains(&conn_id) {
            Path::Punched
        } else {
            Path::Direct
        };
        match &self.best {
            None => {
                shared.record_path(conn_id, path.clone(), Some(self.id));
                self.best = Some(path.clone());
                self.path_conn = Some(conn_id);
                shared.push_event(NatEvent::PathEstablished {
                    connect_id: self.id,
                    peer: self.peer.clone(),
                    path,
                });
            }
            Some(Path::Relayed { .. }) => {
                shared.record_path(conn_id, path.clone(), Some(self.id));
                let from = self.best.replace(path.clone()).expect("checked Some above");
                if let Some(old_conn_id) = self.path_conn.replace(conn_id) {
                    shared.push_event(NatEvent::PathUpgraded {
                        connect_id: self.id,
                        peer: self.peer.clone(),
                        from,
                        to: path,
                        old_conn_id,
                        new_conn_id: conn_id,
                    });
                }
            }
            // A second direct connection replacing the first — nothing new.
            Some(_) => return,
        }
        self.punch_deadline = None;
        self.teardown_relay_leg(swarm, shared, now);
        self.done = true;
    }

    /// The target's connection `old` was replaced by `new` while the peer
    /// stays connected. Called after `new` was applied, so a direct `new`
    /// already settled the attempt. When `old` was the circuit this attempt
    /// promoted and `new` is another circuit, the attempt carries on over
    /// `new`: a punch in flight may still upgrade it, and otherwise it falls
    /// back to relay as usual. A DCUtR exchange lived on `old` and ends.
    ///
    /// When `new_owned` (another attempt or an inbound circuit promoted
    /// `new`), `new` stays its owner's and this attempt ends on the relayed
    /// path it already reported.
    #[expect(
        clippy::too_many_arguments,
        reason = "the replacement's two connections plus the call context"
    )]
    pub(crate) fn on_target_replaced(
        &mut self,
        peer: &PeerId,
        old: ConnectionId,
        new: ConnectionId,
        new_owned: bool,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        if self.done || *peer != self.peer || self.promoted != Some(old) {
            return;
        }
        // `old` retires with the swarm; there is nothing left to close.
        self.promoted = (!new_owned).then_some(new);
        if !new_owned {
            self.path_conn = Some(new);
        }
        // An adopted circuit carries the relayed path this attempt already
        // reported, so it takes that path record without a new path event.
        if !new_owned
            && new.is_circuit()
            && let Some(relay) = self.relay_peer().cloned()
        {
            shared.record_path(new, Path::Relayed { relay }, Some(self.id));
        }
        if new_owned {
            let reason = "another attempt's circuit took over the peer's connection".into();
            self.settle_relayed(UpgradeStop::Aborted { reason }, swarm, shared, now);
        } else if self.dcutr_stream.is_some() {
            // The round's exchange lived on `old`.
            self.fail_round("DCUtR circuit was replaced".into(), swarm, shared, now);
        }
    }

    pub(crate) fn on_connection_closed(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        if self.done {
            return;
        }
        if self.promoted == Some(conn_id) {
            let error = NatError::DialFailed("promoted circuit closed".into());
            if self.best.is_none() {
                // The circuit closed before it carried a path.
                self.fail_bridge(error, swarm, shared, now);
                return;
            }
            self.promoted = None;
            self.bridge_alive = false;
            // An open punch window may still land a direct connection; its
            // end fails the attempt otherwise.
            if self.punch_deadline.is_some() {
                self.last_error = Some(error);
                return;
            }
            self.fail(error, swarm, shared, now);
            return;
        }
        if !self.is_relay_peer(peer) {
            return;
        }
        // Only work on exactly this connection ends. Waiting for relay
        // readiness is not bound to a connection: a replacement's
        // `PeerReady` continues it, and a real loss is bounded by the relay
        // deadline.
        match self.leg {
            RelayLeg::WaitHopReady { conn, stream } | RelayLeg::AwaitHopStatus { conn, stream }
                if conn == conn_id =>
            {
                // The owning connection is terminal: release local state
                // without a reset.
                shared.release_stream(conn, stream);
                self.leg = RelayLeg::Failed;
                self.fail_relay_leg(
                    NatError::DialFailed("relay connection closed".into()),
                    swarm,
                    shared,
                    now,
                );
            }
            RelayLeg::Bridged { conn, .. } if conn == conn_id => {
                self.on_bridge_lost(swarm, shared, now);
            }
            _ => {}
        }
    }

    /// `PeerReady(conn)` for `peer`: a leg waiting on that relay opens its
    /// HOP stream when `conn` is still the relay's ready connection.
    pub(crate) fn on_peer_ready(
        &mut self,
        peer: &PeerId,
        conn: ConnectionId,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        if self.done || self.leg != RelayLeg::WaitRelayReady || !self.is_relay_peer(peer) {
            return;
        }
        if let Some(result) = acquire::on_ready(peer, conn, HOP_PROTOCOL_ID, swarm, now) {
            self.on_acquired(result, swarm, shared, now);
        }
    }

    /// A shared session dial toward this attempt's relay — owned by another
    /// machine — failed while this attempt was waiting on it. Re-issue the
    /// dial: nothing else re-enters the relay leg, so waiting out the leg
    /// deadline would forfeit the relay path over a dial that already
    /// failed. The pending-dial gate collapses simultaneous re-dials from
    /// several waiters back into one.
    pub(crate) fn on_session_dial_failed(
        &mut self,
        peer: &PeerId,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        if self.done || !self.is_relay_peer(peer) {
            return;
        }
        self.redrive_relay_leg(swarm, shared, now);
    }

    /// Re-issues the relay dial when the leg waits on a connection that no
    /// longer has a dial in flight — the shared dial failed, or its owner
    /// stalled and the entry expired. No-op while a dial is still pending,
    /// once the relay is connected, and past the leg's own deadline (the
    /// tick is about to fail the leg; a fresh dial would only gate other
    /// machines on a connection nobody is waiting for).
    fn redrive_relay_leg(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        if self.done || self.leg != RelayLeg::WaitRelayReady {
            return;
        }
        if self
            .relay_deadline
            .is_none_or(|deadline| now.monotonic_ms >= deadline)
        {
            return;
        }
        let Some(relay) = self.relay.clone() else {
            return;
        };
        if acquire::can_become_ready(relay.peer_id(), swarm, shared, now) {
            // The shared connection landed anyway, or an earlier-woken
            // waiter already re-dialed; keep waiting on that.
            return;
        }
        // The entry gets the full dial-flight lifetime even when this leg's
        // own deadline is nearer: it models the handshake in flight, not
        // the attempt's patience. A connection landing after the leg gives
        // up still lifts the gate (`ConnectionEstablished` clears the
        // peer's entries), whereas a shorter lifetime would re-open the
        // duplicate-dial window while the handshake is still under way.
        let deadline_ms = shared.config.relay_timeout_ms;
        let purpose = DialPurpose::Relay(self.id, relay.clone());
        if let Err(reason) = shared.session_dial(swarm, purpose, relay, now, deadline_ms) {
            self.fail_relay_leg(NatError::DialFailed(reason), swarm, shared, now);
        }
    }

    /// A parked dial of this attempt started its connection.
    pub(crate) fn on_dial_started(&mut self, purpose: &DialPurpose, conn_id: ConnectionId) {
        if !self.done && matches!(purpose, DialPurpose::Punch(_)) {
            self.punch_conns.insert(conn_id);
        }
    }

    /// A dial of this attempt failed after it was admitted (or its parked
    /// name could not be resolved).
    pub(crate) fn on_dial_failed(
        &mut self,
        purpose: &DialPurpose,
        reason: String,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        if self.done {
            return;
        }
        // A dial failure matters only while the leg waits on it: once
        // another connection to the relay landed (`PeerReady` or the
        // address deadline decides from there), or the leg moved on, the
        // failure is stale.
        match purpose {
            DialPurpose::Relay(_, dialed)
                if self.leg == RelayLeg::WaitRelayReady
                    && self.relay.as_ref() == Some(dialed)
                    && swarm.connection(dialed.peer_id()).is_none() =>
            {
                self.fail_relay_leg(NatError::DialFailed(reason), swarm, shared, now);
            }
            // An earlier address of the current relay gave up after the
            // leg moved on to this one, which was waiting on that dial:
            // dial this address now that nothing is in flight.
            DialPurpose::Relay(_, dialed) if self.is_relay_peer(dialed.peer_id()) => {
                self.redrive_relay_leg(swarm, shared, now);
            }
            _ => {}
        }
    }

    /// Applies one step of the HOP stream acquisition.
    fn on_acquired(
        &mut self,
        result: Result<Acquired, AcquireError>,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        if let Err(error) = self.take_acquired(result, shared) {
            self.fail_relay_leg(error, swarm, shared, now);
        }
    }

    /// Records an acquisition step, returning the leg's error if it failed.
    fn take_acquired(
        &mut self,
        result: Result<Acquired, AcquireError>,
        shared: &mut Shared,
    ) -> Result<(), NatError> {
        match result {
            Ok(Acquired::Waiting) => self.leg = RelayLeg::WaitRelayReady,
            Ok(Acquired::Opened(conn, stream)) => {
                if let Some(relay_peer) = self.relay_peer().cloned() {
                    shared.own_stream(&relay_peer, conn, stream, StreamRole::HopConnect(self.id));
                    self.leg = RelayLeg::WaitHopReady { conn, stream };
                    let hop = HopConnect::new(self.peer.to_bytes())
                        .map_err(|e| NatError::Protocol(e.to_string()))?;
                    self.hop = Some(hop);
                }
            }
            Err(AcquireError::Dial(reason)) => return Err(NatError::DialFailed(reason)),
            Err(AcquireError::Unsupported) => {
                return Err(NatError::Protocol(
                    "relay does not advertise the HOP protocol".into(),
                ));
            }
            Err(AcquireError::Open(reason)) => {
                return Err(NatError::Protocol(format!(
                    "opening HOP stream failed: {reason}"
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn on_stream_input(
        &mut self,
        stream: StreamId,
        input: StreamInput<'_>,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        if self.done {
            return;
        }
        match (self.leg, input) {
            (RelayLeg::WaitHopReady { conn, stream: s }, StreamInput::Ready) if s == stream => {
                self.flush_hop_connect(conn, stream, swarm, shared, now);
            }
            (RelayLeg::AwaitHopStatus { stream: s, .. }, StreamInput::Data(data))
                if s == stream =>
            {
                self.on_hop_input(|hop| hop.on_data(data), swarm, shared, now);
            }
            (RelayLeg::Bridged { stream: s, .. }, StreamInput::Data(data)) if s == stream => {
                self.bridge_pending_data.extend_from_slice(data);
            }
            (
                RelayLeg::WaitHopReady { stream: s, .. }
                | RelayLeg::AwaitHopStatus { stream: s, .. },
                StreamInput::RemoteWriteClosed,
            ) if s == stream => {
                // A remote half-close still permits local protocol writes.
                // Let the sans-I/O machine consume it rather than treating
                // it as a full circuit teardown; it may have a complete
                // frame buffered already.
                self.on_hop_input(HopConnect::on_remote_write_closed, swarm, shared, now);
            }
            (RelayLeg::Bridged { stream: s, .. }, StreamInput::RemoteWriteClosed)
                if s == stream =>
            {
                self.bridge_remote_write_closed = true;
            }
            (_, StreamInput::Closed) => {
                self.on_stream_closed(stream, swarm, shared, now);
            }
            _ => {}
        }
    }

    pub(crate) fn on_tick(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        if self.done {
            return;
        }

        if let RelayLeg::WaitStagger { until } = self.leg
            && now.monotonic_ms >= until
        {
            self.try_next_relay(swarm, shared, now);
        }

        if let Some(deadline) = self.relay_deadline
            && now.monotonic_ms >= deadline
        {
            self.on_relay_timeout(deadline, swarm, shared, now);
        }

        // A shared dial the leg was waiting on can vanish without a result
        // when its owner stalls: the entry expires exactly at the owner's
        // own flight deadline, so a tick is guaranteed to run then — this
        // re-drive is what keeps a stalled owner from stranding the leg.
        self.redrive_relay_leg(swarm, shared, now);

        // A budget that ran out keeps the Relayed path; the stage that was
        // waiting names why. It is checked before the punch window, so a
        // window the upgrade budget cut short is not reported as a failed
        // round.
        if self.settle_if_budget_spent(swarm, shared, now) {
            return;
        }

        if let Some(deadline) = self.punch_deadline
            && now.monotonic_ms >= deadline
        {
            self.punch_deadline = None;
            self.round_failed(
                "hole punch window elapsed without a direct connection".into(),
                swarm,
                shared,
                now,
            );
        }
    }

    /// Settles on the Relayed path when an upgrade budget ran out by `now`.
    fn settle_if_budget_spent(
        &mut self,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) -> bool {
        let Some(stop) = self.upgrade_stop(now) else {
            return false;
        };
        self.settle_relayed(stop, swarm, shared, now);
        true
    }

    /// The upgrade budget that ran out at `now`, while the circuit still
    /// carries the Relayed path.
    fn upgrade_stop(&self, now: Now) -> Option<UpgradeStop> {
        if self.done || self.promoted.is_none() {
            return None;
        }
        let due = |deadline: Option<u64>| deadline.is_some_and(|at| now.monotonic_ms >= at);
        let budget = |deadline: Option<u64>, from: u64| deadline.unwrap_or(0).saturating_sub(from);
        if due(self.start_deadline) {
            Some(UpgradeStop::StartTimeout {
                budget_ms: budget(self.start_deadline, self.relayed_at),
            })
        } else if due(self.exchange_deadline) {
            Some(UpgradeStop::ExchangeTimeout {
                round: self.rounds,
                budget_ms: budget(self.exchange_deadline, self.exchange_started_at),
            })
        } else if due(self.upgrade_deadline) {
            Some(UpgradeStop::UpgradeTimeout {
                budget_ms: budget(self.upgrade_deadline, self.relayed_at),
            })
        } else {
            None
        }
    }

    /// The current relay address ran out its budget in whatever step it
    /// was in.
    fn on_relay_timeout(
        &mut self,
        deadline: u64,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        let stage = match self.leg {
            RelayLeg::WaitHopReady { .. } => RelayStage::HopNegotiation,
            RelayLeg::AwaitHopStatus { .. } => RelayStage::HopStatus,
            // Bridged, or the bridge was lost with its promotion pending.
            _ if self.promotion.is_some() => RelayStage::CircuitHandshake,
            _ => RelayStage::RelayDial,
        };
        let error = NatError::Timeout {
            stage,
            relay: self.relay_peer().cloned(),
            elapsed_ms: now.monotonic_ms.saturating_sub(self.relay_started_at),
            budget_ms: deadline.saturating_sub(self.relay_started_at),
        };
        if self.promotion.is_some() {
            // The circuit never finished its handshake: close it and move
            // on like any other bridge failure.
            if let Some(conn_id) = self.promoted.take() {
                shared.push_action(NatAction::CloseCircuit { conn_id });
            }
            self.fail_bridge(error, swarm, shared, now);
        } else {
            self.fail_relay_leg(error, swarm, shared, now);
        }
    }

    // -----------------------------------------------------------------------
    // Relay leg
    // -----------------------------------------------------------------------

    /// Starts on the next untried relay entry. A relay reached for the first
    /// time gets [`NatConfig::relay_timeout_ms`](crate::NatConfig::relay_timeout_ms)
    /// (clipped by the attempt's deadline); its addresses split what is left
    /// of that. Callers check that one is left.
    ///
    /// Entries that fail at once (a refused dial or open) move straight on
    /// to the next one in this loop, so stack use stays flat however many
    /// relay addresses the host configured.
    fn try_next_relay(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        loop {
            let Some(relay) = self.untried.pop_front() else {
                return;
            };
            let relay_peer = relay.peer_id().clone();
            if !self.is_relay_peer(&relay_peer) {
                self.relay_budget_deadline =
                    self.clip(now.monotonic_ms + shared.config.relay_timeout_ms);
            }
            let addrs_left = 1 + self
                .untried
                .iter()
                .take_while(|entry| entry.peer_id() == &relay_peer)
                .count() as u64;
            let budget_left = self.relay_budget_deadline.saturating_sub(now.monotonic_ms);
            self.relay_deadline = Some(now.monotonic_ms + budget_left / addrs_left);
            self.relay_started_at = now.monotonic_ms;
            self.relay = Some(relay.clone());

            // Connected, or another machine (reservation, probe) is already
            // dialing this relay: the acquisition waits for `PeerReady` on that
            // connection instead of dialing again.
            let purpose = DialPurpose::Relay(self.id, relay.clone());
            let deadline_ms = shared.config.relay_timeout_ms;
            let result = acquire::start(
                &relay,
                HOP_PROTOCOL_ID,
                purpose,
                deadline_ms,
                swarm,
                shared,
                now,
            );
            // A relay refused at once never started a route: it reports
            // `RelayFailed` only, like a refused direct candidate.
            let Err(error) = self.take_acquired(result, shared) else {
                shared.push_event(NatEvent::RelayStarted {
                    connect_id: self.id,
                    relay,
                });
                return;
            };
            if !self.retire_relay(error, swarm, shared, now) {
                self.fail_if_no_legs_remain(swarm, shared, now);
                return;
            }
        }
    }

    /// The HOP stream finished multistream negotiation: reserve a circuit
    /// slot, then send CONNECT.
    ///
    /// The circuit limit is local, so no other relay would fare better: a
    /// full table fails the whole leg.
    fn flush_hop_connect(
        &mut self,
        conn: ConnectionId,
        stream: StreamId,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        let Some(relay_peer) = self.relay_peer().cloned() else {
            return;
        };
        if let Err(resource) = shared.reserve_circuit(swarm) {
            self.untried.clear();
            let error = NatError::ResourceExhausted { resource };
            self.fail_relay_leg(error, swarm, shared, now);
            return;
        }
        let Some(hop) = self.hop.as_mut() else {
            return;
        };
        while let Some(output) = hop.poll_output() {
            if let HopConnectOutput::Outbound(data) = output {
                send(swarm, &relay_peer, conn, stream, data, now);
            }
        }
        self.leg = RelayLeg::AwaitHopStatus { conn, stream };
    }

    /// Feeds the HOP CONNECT machine (response data or the remote's
    /// half-close) and applies what it decides.
    fn on_hop_input(
        &mut self,
        feed: impl FnOnce(&mut HopConnect) -> Result<(), RelayError>,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        let (RelayLeg::WaitHopReady { conn, stream } | RelayLeg::AwaitHopStatus { conn, stream }) =
            self.leg
        else {
            return;
        };
        let Some(hop) = self.hop.as_mut() else {
            return;
        };
        if let Err(e) = feed(hop) {
            let reason = e.to_string();
            self.fail_relay_leg(NatError::Protocol(reason), swarm, shared, now);
            return;
        }
        let mut outputs = Vec::new();
        while let Some(output) = hop.poll_output() {
            outputs.push(output);
        }
        self.capture_bridge_data(&outputs);
        for output in outputs {
            match output {
                HopConnectOutput::Outbound(data) => {
                    if let Some(relay_peer) = self.relay_peer().cloned() {
                        send(swarm, &relay_peer, conn, stream, data, now);
                    }
                }
                HopConnectOutput::Outcome(ConnectOutcome::Bridged { .. }) => {
                    self.on_bridged(shared);
                }
                HopConnectOutput::Outcome(ConnectOutcome::Refused { status, reason }) => {
                    self.fail_relay_leg(
                        NatError::RelayRefused(format!("{status:?}: {reason}")),
                        swarm,
                        shared,
                        now,
                    );
                    return;
                }
                HopConnectOutput::BridgeData(_) => {}
            }
        }
    }

    /// The relay bridged the circuit: promote the raw pipe through Noise and
    /// Yamux. DCUtR runs later on the established circuit connection.
    fn on_bridged(&mut self, shared: &mut Shared) {
        let RelayLeg::AwaitHopStatus { conn, stream } = self.leg else {
            return;
        };
        if self.relay_peer().is_none() {
            return;
        }
        // The relay's budget stays armed through the circuit handshake.
        self.leg = RelayLeg::Bridged { conn, stream };
        self.bridge_alive = true;
        self.hop = None;
        self.promote_bridge(shared);
    }

    /// Capture bytes coalesced behind STATUS:OK before processing the
    /// preceding `Outcome(Bridged)`, which queues the promotion action.
    fn capture_bridge_data(&mut self, outputs: &[HopConnectOutput]) {
        for output in outputs {
            if let HopConnectOutput::BridgeData(bytes) = output {
                self.bridge_pending_data.extend_from_slice(bytes);
            }
        }
    }

    fn issue_punch_dials(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared) {
        for addr in &self.punch_addrs {
            let Ok(peer_addr) = PeerAddr::new(addr.clone(), self.peer.clone()) else {
                continue;
            };
            // A refused punch dial just does not race; the window decides.
            if let Ok((_, Some(conn_id))) =
                shared.start_dial(swarm, DialPurpose::Punch(self.id), &peer_addr)
            {
                self.punch_conns.insert(conn_id);
            }
        }
    }

    /// Relinquishes the exact bridge stream to the circuit transport.
    fn promote_bridge(&mut self, shared: &mut Shared) {
        if self.bridge_released {
            return;
        }
        if let RelayLeg::Bridged {
            conn: inner_conn,
            stream,
        } = self.leg
            && let Some(relay_peer) = self.relay_peer().cloned()
        {
            self.bridge_released = true;
            shared.release_stream(inner_conn, stream);
            let token = shared.alloc_token(TokenPurpose::PromoteAttempt(self.id));
            self.promotion = Some(token);
            shared.push_action(NatAction::PromoteBridge {
                token,
                inner_conn,
                relay: relay_peer,
                stream_id: stream,
                remote_peer: self.peer.clone(),
                role: BridgeRole::Initiator,
                pending_data: core::mem::take(&mut self.bridge_pending_data),
                // Filled from the agent's held tails as the action drains.
                unsent_data: Vec::new(),
                remote_write_closed: self.bridge_remote_write_closed,
            });
        }
    }

    /// The circuit `conn_id` carries the attempt's first path; the upgrade
    /// budgets start counting.
    fn announce_relay_path(&mut self, conn_id: ConnectionId, shared: &mut Shared, now: Now) {
        if self.best.is_some() {
            return;
        }
        let Some(relay) = self.relay_peer().cloned() else {
            return;
        };
        let path = Path::Relayed { relay };
        self.best = Some(path.clone());
        self.path_conn = Some(conn_id);
        if !shared.config.force_relay {
            self.relayed_at = now.monotonic_ms;
            self.upgrade_deadline =
                Some(self.clip(now.monotonic_ms + shared.config.upgrade_timeout_ms));
            self.start_deadline =
                Some(self.clip_upgrade(now.monotonic_ms + shared.config.dcutr_start_timeout_ms));
        }
        shared.push_event(NatEvent::PathEstablished {
            connect_id: self.id,
            peer: self.peer.clone(),
            path,
        });
    }

    fn on_stream_closed(
        &mut self,
        stream: StreamId,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        match self.leg {
            RelayLeg::WaitHopReady { stream: s, .. }
            | RelayLeg::AwaitHopStatus { stream: s, .. }
                if s == stream =>
            {
                self.fail_relay_leg(
                    NatError::Protocol("HOP stream closed before the circuit was bridged".into()),
                    swarm,
                    shared,
                    now,
                );
            }
            RelayLeg::Bridged { stream: s, .. } if s == stream => {
                self.on_bridge_lost(swarm, shared, now);
            }
            _ => {}
        }
    }

    /// The bridge died (stream closed or relay connection lost).
    fn on_bridge_lost(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        if !self.bridge_alive {
            return;
        }
        self.bridge_alive = false;
        if let RelayLeg::Bridged { conn, stream } = self.leg
            && !self.bridge_released
        {
            shared.release_stream(conn, stream);
            self.bridge_released = true;
        }
        let error = NatError::DialFailed("relay bridge lost before the attempt settled".into());
        if self.best.is_none() && self.promotion.is_none() {
            // No path and no promotion outcome to wait for: this relay is done.
            self.fail_bridge(error, swarm, shared, now);
            return;
        }
        // A requested promotion still reports its outcome, which settles
        // the relay (see `on_promote_result`).
        self.leg = RelayLeg::Failed;
        self.last_error = Some(error);
        // If punch windows are already running, the punch itself may still
        // succeed via `ConnectionEstablished`; the window deadline settles
        // the rest.
    }

    pub(crate) fn on_promote_result(
        &mut self,
        token: NatToken,
        result: Result<ConnectionId, PromoteError>,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        // The leg gave up on this bridge while the promotion was in flight,
        // perhaps for a later relay's: the circuit it produced has no owner.
        if self.done || self.promotion != Some(token) {
            if let Ok(conn_id) = result {
                shared.push_action(NatAction::CloseCircuit { conn_id });
            }
            return;
        }
        match result {
            Ok(conn_id) => self.promoted = Some(conn_id),
            Err(PromoteError::PeerAlreadyDirect) => {
                // The peer is direct already; the relay has nothing left to
                // time out.
                self.bridge_alive = false;
                self.leg = RelayLeg::Failed;
                self.relay_deadline = None;
            }
            Err(error) => {
                self.fail_bridge(NatError::Protocol(error.to_string()), swarm, shared, now);
            }
        }
    }

    /// The bridge failed before the circuit carried a path. Clears the
    /// bridge state and fails the relay like any other relay-scoped failure,
    /// so the leg moves on while it has relays and time left.
    fn fail_bridge(
        &mut self,
        error: NatError,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        self.bridge_alive = false;
        self.bridge_released = false;
        self.promoted = None;
        self.promotion = None;
        self.bridge_remote_write_closed = false;
        self.bridge_pending_data.clear();
        self.fail_relay_leg(error, swarm, shared, now);
    }

    /// The current relay failed: move on to the next one while the attempt
    /// has time left, otherwise fail the leg with `error`.
    fn fail_relay_leg(
        &mut self,
        error: NatError,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        if self.retire_relay(error, swarm, shared, now) {
            self.try_next_relay(swarm, shared, now);
        } else {
            self.fail_if_no_legs_remain(swarm, shared, now);
        }
    }

    /// Ends the current relay entry with `error`, reporting it as
    /// [`NatEvent::RelayFailed`]. `true` when another entry is left to try
    /// within the attempt's deadline.
    ///
    /// Other addresses of the same relay stay eligible only while the relay
    /// is unreached: once connected, every entry for it would reuse that
    /// connection and repeat the same failure.
    fn retire_relay(
        &mut self,
        error: NatError,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) -> bool {
        if let Some(relay_peer) = self.relay_peer().cloned()
            && swarm.connection(&relay_peer).is_some()
        {
            self.untried.retain(|relay| relay.peer_id() != &relay_peer);
        }
        match self.leg {
            RelayLeg::WaitHopReady { conn, stream } | RelayLeg::AwaitHopStatus { conn, stream } => {
                shared.reset_owned_stream(swarm, conn, stream, now);
            }
            _ => {}
        }
        self.leg = RelayLeg::Failed;
        self.relay_deadline = None;
        self.hop = None;
        if let Some(relay) = self.relay.clone() {
            shared.push_event(NatEvent::RelayFailed {
                connect_id: self.id,
                relay,
                error: error.clone(),
            });
        }
        self.last_error = Some(error);
        !self.untried.is_empty()
            && self
                .attempt_deadline
                .is_none_or(|deadline| now.monotonic_ms < deadline)
    }

    fn fail_if_no_legs_remain(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        let relay_leg_dead = matches!(self.leg, RelayLeg::Failed);
        if self.best.is_none() && relay_leg_dead && !self.done {
            let error = self.last_error.take().unwrap_or(NatError::NoPathAvailable);
            self.fail(error, swarm, shared, now);
        }
    }

    fn fail(&mut self, error: NatError, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        self.teardown_relay_leg(swarm, shared, now);
        shared.push_event(NatEvent::ConnectFailed {
            connect_id: self.id,
            peer: self.peer.clone(),
            error,
        });
        self.done = true;
    }

    /// Cancels whatever the relay leg is doing and resets any stream it
    /// still holds (including a bridge the application was told about — the
    /// caller emits the explaining event first).
    fn teardown_relay_leg(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        shared.abort_attempt_dials(self.id, &self.peer, swarm);
        self.teardown_dcutr_stream(swarm, shared, now);
        match self.leg {
            RelayLeg::WaitHopReady { conn, stream } | RelayLeg::AwaitHopStatus { conn, stream } => {
                shared.reset_owned_stream(swarm, conn, stream, now);
            }
            RelayLeg::Bridged { conn, stream } => {
                if let Some(relay_peer) = self.relay_peer().cloned() {
                    if !self.bridge_released && self.bridge_alive {
                        reset(swarm, &relay_peer, conn, stream, now);
                    }
                    shared.release_stream(conn, stream);
                }
            }
            _ => {}
        }
        self.leg = RelayLeg::Inactive;
        self.relay_deadline = None;
        self.punch_deadline = None;
        self.hop = None;
        self.bridge_alive = false;
        if let Some(conn_id) = self.promoted.take() {
            shared.push_action(NatAction::CloseCircuit { conn_id });
        }
    }

    fn teardown_dcutr_stream(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        if let Some((conn, stream)) = self.dcutr_stream.take() {
            shared.reset_owned_stream(swarm, conn, stream, now);
        }
        self.dcutr = None;
    }

    fn relay_peer(&self) -> Option<&PeerId> {
        self.relay.as_ref().map(PeerAddr::peer_id)
    }

    fn is_relay_peer(&self, peer: &PeerId) -> bool {
        self.relay_peer() == Some(peer)
    }
}

/// The relay entries a leg tries, in order: configured relays that
/// `target_addrs` name in a `/p2p/<relay>/p2p-circuit` address first, then
/// the rest; each in config order and once. A relay listed under several
/// addresses keeps every entry, grouped at its first position, so an
/// unreachable address falls through to the next one within the relay's
/// share (see [`ConnectAttempt::try_next_relay`]).
fn relay_order(relays: &[PeerAddr], target_addrs: &[Multiaddr]) -> VecDeque<PeerAddr> {
    let reachable_through = |relay: &PeerId| {
        target_addrs.iter().any(|addr| {
            addr.protocols().windows(2).any(
                |pair| matches!(pair, [Protocol::P2p(id), Protocol::P2pCircuit] if id == relay),
            )
        })
    };
    let (hinted, rest): (Vec<_>, Vec<_>) = relays
        .iter()
        .partition(|relay| reachable_through(relay.peer_id()));
    let ordered: Vec<&PeerAddr> = hinted.into_iter().chain(rest).collect();
    let mut order: VecDeque<PeerAddr> = VecDeque::new();
    for relay in &ordered {
        if order.iter().any(|seen| seen.peer_id() == relay.peer_id()) {
            continue;
        }
        // Keep a relay's addresses together so it is tried as one run.
        for entry in ordered.iter().filter(|e| e.peer_id() == relay.peer_id()) {
            if !order.contains(entry) {
                order.push_back((*entry).clone());
            }
        }
    }
    order
}
