use alloc::collections::{BTreeSet, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use minip2p_core::{ConnectId, Multiaddr, PeerAddr, PeerId, Protocol, SansIoProtocol};
use minip2p_dcutr::{DcutrResponder, DcutrResponderInput, DcutrResponderOutput, ResponderEvent};
use minip2p_relay::{
    ConnectOutcome, HOP_PROTOCOL_ID, HopConnect, HopConnectInput, HopConnectOutput,
};
use minip2p_transport::{ConnectionId, StreamId};

use crate::acquire::{self, AcquireError, Acquired};
use crate::agent::{
    ConnectLegs, DialPurpose, Shared, StreamInput, StreamRole, TokenPurpose, reset, send,
};
use crate::events::{BridgeRole, NatAction, NatEvent};
use crate::inbound::select_global_punch_candidates;
use crate::swarm::NatSwarm;
use crate::types::{NatError, Now, Path, PromoteError};

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
/// engine; this machine only tracks a direct establishment so
/// [`Path::DirectDialed`] snapshots keep working.
///
/// The relay leg tries eligible relays one at a time. Each relay gets an
/// even share of the leg's remaining time (`remaining / relays left`), so
/// time a relay leaves unused by failing fast rolls over to the rest, and
/// the last relay runs out the leg deadline. A relay listed under several
/// addresses splits its share across them. Any relay-scoped failure before
/// the circuit carries a path, including a bridge that fails to promote,
/// moves on to the next relay; the leg fails with the last relay's error.
pub(crate) struct ConnectAttempt {
    id: ConnectId,
    peer: PeerId,
    /// The relay currently being tried.
    relay: Option<PeerAddr>,
    /// Relays still to try after `relay`, in order.
    untried: VecDeque<PeerAddr>,
    leg: RelayLeg,
    /// Absolute deadline for the whole relay leg to reach `Bridged`.
    leg_deadline: u64,
    /// The caller's deadline for the attempt, which caps `leg_deadline`.
    attempt_deadline: Option<u64>,
    /// Absolute end of the current relay's share, across all its addresses.
    share_deadline: u64,
    /// Absolute deadline for the current relay address: the end of its part
    /// of the relay's share.
    relay_deadline: Option<u64>,
    hop: Option<HopConnect>,
    dcutr: Option<DcutrResponder>,
    /// The inbound DCUtR stream, on the promoted circuit.
    dcutr_stream: Option<(ConnectionId, StreamId)>,
    /// The bridge exists and has not been torn down by a close/disconnect.
    bridge_alive: bool,
    /// The bridge stream has been handed to the circuit transport.
    bridge_released: bool,
    /// Circuit connection the host reported for the promotion.
    promoted: Option<ConnectionId>,
    /// Promotion has been requested and its result may be pending.
    promotion_requested: bool,
    /// The remote write half reached EOF while the bridge was agent-owned.
    bridge_remote_write_closed: bool,
    /// Secure-mux bytes coalesced behind the HOP success response. Passed to
    /// the circuit transport with `PromoteBridge`.
    bridge_pending_data: Vec<u8>,
    punch_addrs: Vec<Multiaddr>,
    punch_dials_issued: bool,
    /// Connections started by punch dials.
    punch_conns: BTreeSet<ConnectionId>,
    /// Absolute deadline of the current punch window.
    punch_deadline: Option<u64>,
    /// 1-based index of the current punch window.
    punch_window: u32,
    best: Option<Path>,
    /// All direct punch windows have settled; once the circuit establishes,
    /// it is the final path and `FellBackToRelay` may be emitted.
    punch_settled: bool,
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
            leg_deadline: 0,
            attempt_deadline: legs.deadline_ms,
            share_deadline: 0,
            relay_deadline: None,
            hop: None,
            dcutr: None,
            dcutr_stream: None,
            bridge_alive: false,
            bridge_released: false,
            promoted: None,
            promotion_requested: false,
            bridge_remote_write_closed: false,
            bridge_pending_data: Vec::new(),
            punch_addrs: Vec::new(),
            punch_dials_issued: false,
            punch_conns: BTreeSet::new(),
            punch_deadline: None,
            punch_window: 0,
            best: None,
            punch_settled: false,
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
                attempt.begin_relay_leg(swarm, shared, now);
            } else {
                attempt.leg = RelayLeg::WaitStagger {
                    until: now.mono_ms + stagger,
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

    pub(crate) fn is_done(&self) -> bool {
        self.done
    }

    pub(crate) fn accepts_dcutr(&self, peer: &PeerId, conn_id: ConnectionId) -> bool {
        !self.done
            && !self.punch_settled
            && !self.punch_dials_issued
            && &self.peer == peer
            && self.promoted == Some(conn_id)
            && self
                .best
                .as_ref()
                .is_some_and(|path| matches!(path, Path::Relayed { .. }))
            && self.dcutr_stream.is_none()
    }

    pub(crate) fn on_dcutr_stream_opened(
        &mut self,
        conn: ConnectionId,
        stream: StreamId,
        shared: &Shared,
    ) {
        self.dcutr_stream = Some((conn, stream));
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
        let exchange_closed = matches!(input, StreamInput::RemoteWriteClosed | StreamInput::Closed);
        let machine_input = match input {
            StreamInput::Data(data) => DcutrResponderInput::Data(data.to_vec()),
            StreamInput::RemoteWriteClosed | StreamInput::Closed => {
                DcutrResponderInput::RemoteWriteClosed
            }
            StreamInput::Ready => return,
        };
        let Some(dcutr) = self.dcutr.as_mut() else {
            return;
        };
        if let Err(error) = dcutr.handle_input(machine_input) {
            self.finish_failed_dcutr(error.to_string(), swarm, shared, now);
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
                    self.teardown_dcutr_stream(swarm, shared, now);
                    if self.punch_addrs.is_empty() {
                        self.punch_failed_permanently(
                            "no dialable remote addresses in DCUtR CONNECT".into(),
                            swarm,
                            shared,
                            now,
                        );
                    } else {
                        self.issue_punch_dials(swarm, shared);
                        self.punch_window = 1;
                        self.punch_deadline = Some(now.mono_ms + shared.config.punch_deadline_ms);
                    }
                }
            }
        }
        if exchange_closed && self.dcutr_stream == Some((conn, stream)) {
            self.finish_failed_dcutr("DCUtR stream closed before SYNC".into(), swarm, shared, now);
        }
    }

    fn finish_failed_dcutr(
        &mut self,
        reason: String,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        self.teardown_dcutr_stream(swarm, shared, now);
        shared.push_event(NatEvent::HolePunchFailed {
            connect_id: self.id,
            attempt: 1,
            reason,
        });
        self.punch_settled = true;
        shared.push_event(NatEvent::FellBackToRelay {
            connect_id: self.id,
            peer: self.peer.clone(),
        });
        self.done = true;
    }

    /// Earliest pending absolute deadline, for the driver's timer fold-in.
    pub(crate) fn next_deadline(&self) -> Option<u64> {
        if self.done {
            return None;
        }
        let mut due = None;
        if let RelayLeg::WaitStagger { until } = self.leg {
            due = Some(until);
        }
        for deadline in [self.relay_deadline, self.punch_deadline]
            .into_iter()
            .flatten()
        {
            due = Some(due.map_or(deadline, |current| current.min(deadline)));
        }
        due
    }

    /// Abandons the attempt silently, cleaning up any held streams.
    pub(crate) fn cancel(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
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
                    shared.record_origin(conn_id, Path::Relayed { relay }, Some(self.id));
                }
                self.announce_relay_path(shared);
                if shared.config.force_relay {
                    self.done = true;
                } else if self.punch_settled {
                    shared.push_event(NatEvent::FellBackToRelay {
                        connect_id: self.id,
                        peer: self.peer.clone(),
                    });
                    self.done = true;
                }
            }
            return;
        }
        // Classify punched iff this conn id was issued as a punch dial.
        let path = if self.punch_conns.contains(&conn_id) {
            Path::DirectPunched
        } else {
            Path::DirectDialed
        };
        match &self.best {
            None => {
                shared.record_origin(conn_id, path.clone(), Some(self.id));
                self.best = Some(path.clone());
                shared.push_event(NatEvent::PathEstablished {
                    connect_id: self.id,
                    peer: self.peer.clone(),
                    path,
                });
            }
            Some(Path::Relayed { .. }) => {
                shared.record_origin(conn_id, path.clone(), Some(self.id));
                let from = self.best.replace(path.clone()).expect("checked Some above");
                shared.push_event(NatEvent::PathUpgraded {
                    connect_id: self.id,
                    peer: self.peer.clone(),
                    from,
                    to: path,
                });
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
        // An adopted circuit carries the relayed path this attempt already
        // reported, so it takes that origin without a new path event.
        if !new_owned
            && new.is_circuit()
            && let Some(relay) = self.relay_peer().cloned()
        {
            shared.record_origin(new, Path::Relayed { relay }, Some(self.id));
        }
        if self.dcutr_stream.is_some() {
            self.finish_failed_dcutr("DCUtR circuit was replaced".into(), swarm, shared, now);
        } else if new_owned {
            shared.abort_attempt_dials(self.id);
            shared.push_event(NatEvent::FellBackToRelay {
                connect_id: self.id,
                peer: self.peer.clone(),
            });
            self.done = true;
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
                shared.release_stream(peer, stream);
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
            .is_none_or(|deadline| now.mono_ms >= deadline)
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
        let deadline_ms = shared.config.relay_leg_deadline_ms;
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
        match result {
            Ok(Acquired::Waiting) => self.leg = RelayLeg::WaitRelayReady,
            Ok(Acquired::Opened(conn, stream)) => {
                let Some(relay_peer) = self.relay_peer().cloned() else {
                    return;
                };
                self.hop = Some(HopConnect::new(self.peer.to_bytes()));
                shared.own_stream(&relay_peer, conn, stream, StreamRole::HopConnect(self.id));
                self.leg = RelayLeg::WaitHopReady { conn, stream };
            }
            Err(AcquireError::Dial(reason)) => {
                self.fail_relay_leg(NatError::DialFailed(reason), swarm, shared, now);
            }
            Err(AcquireError::Unsupported) => self.fail_relay_leg(
                NatError::Protocol("relay does not advertise the HOP protocol".into()),
                swarm,
                shared,
                now,
            ),
            Err(AcquireError::Open(reason)) => self.fail_relay_leg(
                NatError::Protocol(format!("opening HOP stream failed: {reason}")),
                swarm,
                shared,
                now,
            ),
        }
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
                self.on_hop_input(HopConnectInput::Data(data.to_vec()), swarm, shared, now);
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
                self.on_hop_input(HopConnectInput::RemoteWriteClosed, swarm, shared, now);
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
            && now.mono_ms >= until
        {
            self.begin_relay_leg(swarm, shared, now);
        }

        if let Some(deadline) = self.relay_deadline
            && now.mono_ms >= deadline
        {
            self.fail_relay_leg(NatError::Timeout, swarm, shared, now);
        }

        // A shared dial the leg was waiting on can vanish without a result
        // when its owner stalls: the entry expires exactly at the owner's
        // own flight deadline, so a tick is guaranteed to run then — this
        // re-drive is what keeps a stalled owner from stranding the leg.
        self.redrive_relay_leg(swarm, shared, now);

        if let Some(deadline) = self.punch_deadline
            && now.mono_ms >= deadline
        {
            self.on_punch_window_elapsed(swarm, shared, now);
        }
    }

    // -----------------------------------------------------------------------
    // Relay leg
    // -----------------------------------------------------------------------

    fn begin_relay_leg(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        let leg_deadline = now.mono_ms + shared.config.relay_leg_deadline_ms;
        self.leg_deadline = self
            .attempt_deadline
            .map_or(leg_deadline, |attempt| attempt.min(leg_deadline));
        self.try_next_relay(swarm, shared, now);
    }

    /// Starts on the next untried relay entry. A relay reached for the first
    /// time gets an even share of the leg's remaining time; its addresses
    /// split what is left of that share. Callers check that one is left.
    fn try_next_relay(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        let Some(relay) = self.untried.pop_front() else {
            return;
        };
        let relay_peer = relay.peer_id().clone();
        if !self.is_relay_peer(&relay_peer) {
            // `relay_order` keeps a relay's addresses together, so each
            // remaining peer appears once as a run.
            let mut peers_left = 1;
            let mut last = &relay_peer;
            for entry in &self.untried {
                if entry.peer_id() != last {
                    peers_left += 1;
                    last = entry.peer_id();
                }
            }
            let remaining = self.leg_deadline.saturating_sub(now.mono_ms);
            self.share_deadline = now.mono_ms + remaining / peers_left;
        }
        let addrs_left = 1 + self
            .untried
            .iter()
            .take_while(|entry| entry.peer_id() == &relay_peer)
            .count() as u64;
        let share_left = self.share_deadline.saturating_sub(now.mono_ms);
        self.relay_deadline = Some(now.mono_ms + share_left / addrs_left);
        self.relay = Some(relay.clone());

        // Connected, or another machine (reservation, probe) is already
        // dialing this relay: the acquisition waits for `PeerReady` on that
        // connection instead of dialing again.
        let purpose = DialPurpose::Relay(self.id, relay.clone());
        let deadline_ms = shared.config.relay_leg_deadline_ms;
        let result = acquire::start(
            &relay,
            HOP_PROTOCOL_ID,
            purpose,
            deadline_ms,
            swarm,
            shared,
            now,
        );
        self.on_acquired(result, swarm, shared, now);
    }

    /// The HOP stream finished multistream negotiation: send CONNECT.
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
        let Some(hop) = self.hop.as_mut() else {
            return;
        };
        if let Err(e) = hop.handle_input(HopConnectInput::Flush) {
            let reason = e.to_string();
            self.fail_relay_leg(NatError::Protocol(reason), swarm, shared, now);
            return;
        }
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
        input: HopConnectInput,
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
        if let Err(e) = hop.handle_input(input) {
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
        self.leg = RelayLeg::Bridged { conn, stream };
        self.relay_deadline = None;
        self.bridge_alive = true;
        self.hop = None;

        if shared.config.force_relay {
            self.punch_settled = true;
        }
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
        self.punch_dials_issued = true;
    }

    fn on_punch_window_elapsed(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        shared.push_event(NatEvent::HolePunchFailed {
            connect_id: self.id,
            attempt: self.punch_window,
            reason: "hole punch window elapsed without a direct connection".into(),
        });
        let total_windows = 1 + shared.config.punch_max_retries;
        if self.punch_window < total_windows {
            self.punch_window += 1;
            self.issue_punch_dials(swarm, shared);
            self.punch_deadline = Some(now.mono_ms + shared.config.punch_deadline_ms);
        } else {
            self.punch_deadline = None;
            self.settle_after_punch(swarm, shared, now);
        }
    }

    /// The punch can never succeed (protocol error, no addresses): emit one
    /// failure and settle immediately.
    fn punch_failed_permanently(
        &mut self,
        reason: String,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        shared.push_event(NatEvent::HolePunchFailed {
            connect_id: self.id,
            attempt: self.punch_window.max(1),
            reason,
        });
        self.punch_deadline = None;
        self.settle_after_punch(swarm, shared, now);
    }

    /// The punch is over without a direct connection. If the bridge is
    /// still standing, the relayed path is the final result; otherwise the
    /// attempt has nothing left.
    fn settle_after_punch(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        if self.done {
            return;
        }
        self.teardown_dcutr_stream(swarm, shared, now);
        if self.bridge_alive {
            self.punch_settled = true;
            if let RelayLeg::Bridged { .. } = self.leg {
                self.promote_bridge(shared);
                if self.best.is_some() {
                    shared.push_event(NatEvent::FellBackToRelay {
                        connect_id: self.id,
                        peer: self.peer.clone(),
                    });
                    // Keep the provisional circuit; drop punch dials so a
                    // late handshake cannot land after this attempt is reaped.
                    shared.abort_attempt_dials(self.id);
                    self.done = true;
                }
            }
        } else if self.best.is_some() {
            if self.punch_deadline.is_none() {
                let error = self
                    .last_error
                    .take()
                    .unwrap_or(NatError::DialFailed("promoted circuit closed".into()));
                self.fail(error, swarm, shared, now);
            }
        } else if self.punch_deadline.is_some() {
            // The relay leg is gone, but an active punch window can still
            // establish the first usable path.
        } else {
            let error = self
                .last_error
                .take()
                .unwrap_or(NatError::DialFailed("relay bridge lost".into()));
            self.fail(error, swarm, shared, now);
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
            shared.release_stream(&relay_peer, stream);
            let token = shared.alloc_token(TokenPurpose::PromoteAttempt(self.id));
            self.promotion_requested = true;
            shared.push_action(NatAction::PromoteBridge {
                token,
                inner_conn,
                relay: relay_peer,
                stream_id: stream,
                remote_peer: self.peer.clone(),
                role: BridgeRole::Initiator,
                pending_data: core::mem::take(&mut self.bridge_pending_data),
                remote_write_closed: self.bridge_remote_write_closed,
            });
        }
    }

    fn announce_relay_path(&mut self, shared: &mut Shared) {
        if self.best.is_some() {
            return;
        }
        let Some(relay) = self.relay_peer().cloned() else {
            return;
        };
        let path = Path::Relayed { relay };
        self.best = Some(path.clone());
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
        if let RelayLeg::Bridged { stream, .. } = self.leg
            && !self.bridge_released
            && let Some(relay_peer) = self.relay_peer().cloned()
        {
            shared.release_stream(&relay_peer, stream);
            self.bridge_released = true;
        }
        let error = NatError::DialFailed("relay bridge lost before the attempt settled".into());
        if self.best.is_none() && !self.promotion_requested {
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
        result: Result<ConnectionId, PromoteError>,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        match result {
            Ok(conn_id) => self.promoted = Some(conn_id),
            Err(PromoteError::PeerAlreadyDirect) => {
                self.bridge_alive = false;
                self.leg = RelayLeg::Failed;
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
        self.promotion_requested = false;
        self.bridge_remote_write_closed = false;
        self.bridge_pending_data.clear();
        self.fail_relay_leg(error, swarm, shared, now);
    }

    /// The current relay failed: move on to the next one while the leg has
    /// time left, otherwise fail the leg with `error`.
    ///
    /// Other addresses of the same relay stay eligible only while the relay
    /// is unreached: once connected, every entry for it would reuse that
    /// connection and repeat the same failure.
    fn fail_relay_leg(
        &mut self,
        error: NatError,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        if let Some(relay_peer) = self.relay_peer().cloned()
            && swarm.connection(&relay_peer).is_some()
        {
            self.untried.retain(|relay| relay.peer_id() != &relay_peer);
        }
        match self.leg {
            RelayLeg::WaitHopReady { stream, .. } | RelayLeg::AwaitHopStatus { stream, .. } => {
                if let Some(relay_peer) = self.relay_peer().cloned() {
                    shared.reset_owned_stream(swarm, &relay_peer, stream, now);
                }
            }
            _ => {}
        }
        self.leg = RelayLeg::Failed;
        self.relay_deadline = None;
        self.hop = None;
        self.last_error = Some(error);
        if !self.untried.is_empty() && now.mono_ms < self.leg_deadline {
            self.try_next_relay(swarm, shared, now);
        } else {
            self.fail_if_no_legs_remain(swarm, shared, now);
        }
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
        shared.abort_attempt_dials(self.id);
        self.teardown_dcutr_stream(swarm, shared, now);
        match self.leg {
            RelayLeg::WaitHopReady { stream, .. } | RelayLeg::AwaitHopStatus { stream, .. } => {
                if let Some(relay_peer) = self.relay_peer().cloned() {
                    shared.reset_owned_stream(swarm, &relay_peer, stream, now);
                }
            }
            RelayLeg::Bridged { conn, stream } => {
                if let Some(relay_peer) = self.relay_peer().cloned() {
                    if !self.bridge_released && self.bridge_alive {
                        reset(swarm, &relay_peer, conn, stream, now);
                    }
                    shared.release_stream(&relay_peer, stream);
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
        if let Some((_, stream_id)) = self.dcutr_stream.take() {
            shared.reset_owned_stream(swarm, &self.peer, stream_id, now);
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
