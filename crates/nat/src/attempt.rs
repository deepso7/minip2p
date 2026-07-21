use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use minip2p_core::{Multiaddr, PeerAddr, PeerId, SansIoProtocol, select_direct_candidates};
use minip2p_dcutr::{DcutrInitiator, DcutrInitiatorInput, DcutrInitiatorOutput, InitiatorOutcome};
use minip2p_relay::{
    ConnectOutcome, HOP_PROTOCOL_ID, HopConnect, HopConnectInput, HopConnectOutput,
};
use minip2p_transport::{ConnectionId, StreamId};

use crate::agent::{Shared, StreamInput, StreamRole, TokenPurpose};
use crate::events::{BridgeRole, NatAction, NatEvent};
use crate::types::{ConnectId, NatError, Now, Path, PromoteError};

/// Progress of the relay leg of a connect attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelayLeg {
    /// No relay configured, or the leg was cancelled after a direct win.
    Inactive,
    /// Waiting out the direct leg's head start.
    WaitStagger { until: u64 },
    /// Relay dial issued and/or waiting for `PeerReady` on the relay.
    WaitRelayReady,
    /// `OpenStream` for the HOP protocol issued; waiting for the stream id.
    OpeningHop,
    /// HOP stream allocated; waiting for multistream negotiation.
    WaitHopReady { stream: StreamId },
    /// HOP CONNECT sent; waiting for the relay's STATUS response.
    AwaitHopStatus { stream: StreamId },
    /// Circuit bridged; the stream carries DCUtR and then application bytes.
    Bridged { stream: StreamId },
    /// The leg failed; only the direct leg (if any) can still win.
    Failed,
}

/// Per-target dialer-race arbiter: direct candidate dials at `t0` racing a
/// staggered relay leg, with a DCUtR punch attempted over the bridge as soon
/// as it exists. The best path wins; improvements are announced as explicit
/// upgrades.
pub(crate) struct ConnectAttempt {
    id: ConnectId,
    peer: PeerId,
    connect_deadline: u64,
    /// Direct-candidate dials whose synchronous result has not come back as
    /// an error. Successful dials stay "live" until the connection appears
    /// or the connect deadline fires.
    direct_live: u32,
    relay: Option<PeerAddr>,
    leg: RelayLeg,
    /// Absolute deadline for the relay leg to reach `Bridged`.
    relay_deadline: Option<u64>,
    hop: Option<HopConnect>,
    dcutr: Option<DcutrInitiator>,
    dcutr_sent_at: Option<u64>,
    /// The bridge exists and has not been torn down by a close/disconnect.
    bridge_alive: bool,
    /// The bridge stream has been handed to the circuit transport.
    bridge_released: bool,
    /// Exact wrapped connection learned from the bridge stream's ready event.
    bridge_inner_conn: Option<ConnectionId>,
    /// Circuit connection returned by the promotion driver echo.
    promoted: Option<ConnectionId>,
    /// Promotion has been requested and its synchronous echo may be pending.
    promotion_requested: bool,
    /// The remote write half reached EOF while the bridge was agent-owned.
    bridge_remote_write_closed: bool,
    /// Application bytes coalesced behind the initiator-side DCUtR reply.
    /// Drained exactly once into the first relayed `PathEstablished` event.
    bridge_pending_data: Vec<u8>,
    punch_addrs: Vec<Multiaddr>,
    punch_dials_issued: bool,
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
    /// Starts an attempt: dials every validated direct candidate now and
    /// arms the relay leg. Returns `None` when the attempt failed instantly
    /// (the failure event is already queued).
    pub(crate) fn start(
        id: ConnectId,
        peer: PeerId,
        direct_addrs: Vec<Multiaddr>,
        shared: &mut Shared,
        now: Now,
    ) -> Option<Self> {
        let candidates = if shared.config.force_relay {
            Vec::new()
        } else {
            select_direct_candidates(&direct_addrs, None, None).into_addrs()
        };
        let relay = shared.config.relays.first().cloned();

        if candidates.is_empty() && relay.is_none() {
            shared.push_event(NatEvent::ConnectFailed {
                connect_id: id,
                peer,
                error: NatError::NoPathAvailable,
            });
            return None;
        }

        let mut attempt = Self {
            id,
            peer,
            connect_deadline: now.mono_ms + shared.config.connect_deadline_ms,
            direct_live: 0,
            relay,
            leg: RelayLeg::Inactive,
            relay_deadline: None,
            hop: None,
            dcutr: None,
            dcutr_sent_at: None,
            bridge_alive: false,
            bridge_released: false,
            bridge_inner_conn: None,
            promoted: None,
            promotion_requested: false,
            bridge_remote_write_closed: false,
            bridge_pending_data: Vec::new(),
            punch_addrs: Vec::new(),
            punch_dials_issued: false,
            punch_deadline: None,
            punch_window: 0,
            best: None,
            punch_settled: false,
            last_error: None,
            done: false,
        };

        for addr in candidates {
            // Candidates are validated pure transport addresses, so pairing
            // them with the target peer id cannot fail.
            let Ok(peer_addr) = PeerAddr::new(addr, attempt.peer.clone()) else {
                continue;
            };
            let token = shared.alloc_token(TokenPurpose::DirectDial(id));
            shared.push_action(NatAction::Dial {
                token,
                addr: peer_addr,
            });
            attempt.direct_live += 1;
        }

        if attempt.relay.is_some() {
            let stagger = if shared.config.force_relay {
                0
            } else {
                shared.config.relay_stagger_ms
            };
            if stagger == 0 || attempt.direct_live == 0 {
                // Nothing to give a head start to (or none requested).
                attempt.begin_relay_leg(shared, now);
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

    pub(crate) fn is_done(&self) -> bool {
        self.done
    }

    /// Earliest pending absolute deadline, for the driver's timer fold-in.
    pub(crate) fn next_deadline(&self) -> Option<u64> {
        if self.done {
            return None;
        }
        let mut due = self.connect_deadline;
        if let RelayLeg::WaitStagger { until } = self.leg {
            due = due.min(until);
        }
        for deadline in [self.relay_deadline, self.punch_deadline]
            .into_iter()
            .flatten()
        {
            due = due.min(deadline);
        }
        Some(due)
    }

    /// Abandons the attempt silently, cleaning up any held streams.
    pub(crate) fn cancel(&mut self, shared: &mut Shared) {
        self.teardown_relay_leg(shared);
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
        shared: &mut Shared,
        now: Now,
    ) {
        if self.done || *peer != self.peer {
            return;
        }
        if is_circuit {
            if self.promoted == Some(conn_id) {
                self.announce_relay_path(shared);
                if self.punch_settled || shared.config.force_relay {
                    shared.push_event(NatEvent::FellBackToRelay {
                        connect_id: self.id,
                        peer: self.peer.clone(),
                    });
                    self.done = true;
                }
            }
            return;
        }
        // `ConnectionEstablished` carries no dial/connection correlation.
        // If one of the original candidate dials is still live, classifying
        // this as punched would be a false claim: it may be that late
        // candidate connection. Only call it punched when the relay race was
        // the sole remaining source of a direct connection.
        let path = if self.punch_dials_issued && self.direct_live == 0 {
            Path::DirectPunched
        } else {
            Path::DirectDialed
        };
        match &self.best {
            None => {
                self.best = Some(path.clone());
                shared.push_event(NatEvent::PathEstablished {
                    connect_id: self.id,
                    peer: self.peer.clone(),
                    path,
                });
            }
            Some(Path::Relayed { .. }) => {
                let from = self.best.replace(path.clone()).expect("checked Some above");
                shared.push_event(NatEvent::PathUpgraded {
                    connect_id: self.id,
                    peer: self.peer.clone(),
                    from,
                    to: path,
                });
            }
            // A duplicate direct connection (QUIC supersede) — nothing new.
            Some(_) => return,
        }
        let _ = now;
        self.punch_deadline = None;
        self.teardown_relay_leg(shared);
        self.done = true;
    }

    pub(crate) fn on_connection_closed(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        shared: &mut Shared,
        now: Now,
    ) {
        if self.done {
            return;
        }
        if self.promoted == Some(conn_id) {
            self.promoted = None;
            self.bridge_alive = false;
            if self.best.is_none() && self.direct_live == 0 {
                self.fail(
                    shared,
                    NatError::DialFailed("promoted circuit closed".into()),
                );
            }
            return;
        }
        if !self.is_relay_peer(peer) || self.bridge_inner_conn.is_some_and(|id| id != conn_id) {
            return;
        }
        match self.leg {
            RelayLeg::WaitRelayReady | RelayLeg::OpeningHop => {
                self.leg = RelayLeg::Failed;
                self.relay_deadline = None;
                self.hop = None;
                self.last_error = Some(NatError::DialFailed("relay connection closed".into()));
                self.fail_if_no_legs_remain(shared);
            }
            RelayLeg::WaitHopReady { stream } | RelayLeg::AwaitHopStatus { stream } => {
                // The exact owning connection is terminal. Release local
                // state without a peer-scoped reset that could target its
                // eager replacement.
                shared.release_stream(peer, stream);
                self.leg = RelayLeg::Failed;
                self.relay_deadline = None;
                self.hop = None;
                self.last_error = Some(NatError::DialFailed("relay connection closed".into()));
                self.fail_if_no_legs_remain(shared);
            }
            RelayLeg::Bridged { .. } => self.on_bridge_lost(shared, now),
            _ => {}
        }
    }

    pub(crate) fn on_peer_ready(
        &mut self,
        peer: &PeerId,
        protocols: &[String],
        shared: &mut Shared,
        _now: Now,
    ) {
        if self.done || self.leg != RelayLeg::WaitRelayReady || !self.is_relay_peer(peer) {
            return;
        }
        if protocols.iter().any(|p| p == HOP_PROTOCOL_ID) {
            self.open_hop(shared);
        } else {
            self.fail_relay_leg(
                shared,
                NatError::Protocol("relay does not advertise the HOP protocol".into()),
            );
        }
    }

    /// A shared session dial toward this attempt's relay — owned by another
    /// machine — failed while this attempt was waiting on it. Re-issue the
    /// dial: nothing else re-enters the relay leg, so waiting out the leg
    /// deadline would forfeit the relay path over a dial that already
    /// failed. The pending-dial gate collapses simultaneous re-dials from
    /// several waiters back into one.
    pub(crate) fn on_session_dial_failed(&mut self, peer: &PeerId, shared: &mut Shared, now: Now) {
        if self.done || !self.is_relay_peer(peer) {
            return;
        }
        self.redrive_relay_leg(shared, now);
    }

    /// Re-issues the relay dial when the leg waits on a connection that no
    /// longer has a dial in flight — the shared dial failed, or its owner
    /// stalled and the entry expired. No-op while a dial is still pending,
    /// once the relay is connected, and past the leg's own deadline (the
    /// tick is about to fail the leg; a fresh dial would only gate other
    /// machines on a connection nobody is waiting for).
    fn redrive_relay_leg(&mut self, shared: &mut Shared, now: Now) {
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
        let relay_peer = relay.peer_id();
        if shared.is_connected(relay_peer) || shared.session_dial_pending(relay_peer, now) {
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
        shared.push_session_dial(TokenPurpose::RelayDial(self.id), relay, now, deadline_ms);
    }

    pub(crate) fn on_dial_result(
        &mut self,
        purpose: &TokenPurpose,
        result: Result<ConnectionId, String>,
        shared: &mut Shared,
        _now: Now,
    ) {
        if self.done {
            return;
        }
        let Err(reason) = result else {
            // A successful dial only means the handshake is under way; the
            // connection (or the connect deadline) tells the rest.
            return;
        };
        match purpose {
            TokenPurpose::DirectDial(_) => {
                self.direct_live = self.direct_live.saturating_sub(1);
                self.last_error = Some(NatError::DialFailed(reason));
                if self.direct_live == 0
                    && matches!(self.best, Some(Path::Relayed { .. }))
                    && self.dcutr.is_none()
                    && self.punch_deadline.is_none()
                {
                    self.settle_after_punch(shared);
                } else {
                    self.fail_if_no_legs_remain(shared);
                }
            }
            TokenPurpose::RelayDial(_) => {
                self.fail_relay_leg(shared, NatError::DialFailed(reason));
            }
            // Punch dials are expected to fail often; the punch window
            // deadline governs the retry/fallback flow.
            TokenPurpose::PunchDial(_) => {}
            _ => {}
        }
    }

    pub(crate) fn on_stream_open_result(
        &mut self,
        result: Result<StreamId, String>,
        shared: &mut Shared,
        _now: Now,
    ) {
        if self.done || self.leg != RelayLeg::OpeningHop {
            // Stale result (leg already failed); don't leak the stream.
            if let (Ok(stream), Some(relay_peer)) = (&result, self.relay_peer().cloned()) {
                shared.push_action(NatAction::ResetStream {
                    peer: relay_peer,
                    stream_id: *stream,
                });
            }
            return;
        }
        match result {
            Ok(stream) => {
                let Some(relay_peer) = self.relay_peer().cloned() else {
                    return;
                };
                self.hop = Some(HopConnect::new(self.peer.to_bytes()));
                shared.own_stream(&relay_peer, stream, StreamRole::HopConnect(self.id));
                self.leg = RelayLeg::WaitHopReady { stream };
            }
            Err(reason) => {
                self.fail_relay_leg(
                    shared,
                    NatError::Protocol(format!("opening HOP stream failed: {reason}")),
                );
            }
        }
    }

    pub(crate) fn on_stream_input(
        &mut self,
        conn_id: ConnectionId,
        stream: StreamId,
        input: StreamInput<'_>,
        shared: &mut Shared,
        now: Now,
    ) {
        if self.done {
            return;
        }
        if matches!(input, StreamInput::Ready) {
            self.bridge_inner_conn = Some(conn_id);
        }
        match (self.leg, input) {
            (RelayLeg::WaitHopReady { stream: s }, StreamInput::Ready) if s == stream => {
                self.flush_hop_connect(stream, shared);
            }
            (RelayLeg::AwaitHopStatus { stream: s }, StreamInput::Data(data)) if s == stream => {
                self.on_hop_data(stream, data, shared, now);
            }
            (RelayLeg::Bridged { stream: s }, StreamInput::Data(data)) if s == stream => {
                self.on_bridge_data(stream, data, shared, now);
            }
            (
                RelayLeg::WaitHopReady { stream: s } | RelayLeg::AwaitHopStatus { stream: s },
                StreamInput::RemoteWriteClosed,
            ) if s == stream => {
                self.on_hop_remote_write_closed(stream, shared, now);
            }
            (RelayLeg::Bridged { stream: s }, StreamInput::RemoteWriteClosed) if s == stream => {
                self.on_bridge_remote_write_closed(stream, shared, now);
            }
            (_, StreamInput::Closed) => {
                self.on_stream_closed(stream, shared, now);
            }
            _ => {}
        }
    }

    pub(crate) fn on_tick(&mut self, shared: &mut Shared, now: Now) {
        if self.done {
            return;
        }

        if let RelayLeg::WaitStagger { until } = self.leg
            && now.mono_ms >= until
        {
            self.begin_relay_leg(shared, now);
        }

        if let Some(deadline) = self.relay_deadline
            && now.mono_ms >= deadline
        {
            self.fail_relay_leg(shared, NatError::Timeout);
        }

        // A shared dial the leg was waiting on can vanish without a result
        // when its owner stalls: the entry expires exactly at the owner's
        // own flight deadline, so a tick is guaranteed to run then — this
        // re-drive is what keeps a stalled owner from stranding the leg.
        self.redrive_relay_leg(shared, now);

        if let Some(deadline) = self.punch_deadline
            && now.mono_ms >= deadline
        {
            self.on_punch_window_elapsed(shared, now);
        }

        if !self.done && now.mono_ms >= self.connect_deadline {
            if self.best.is_some() {
                // A relayed path exists but the punch never resolved; settle
                // on the relay.
                self.punch_deadline = None;
                self.settle_after_punch(shared);
            } else if self.promotion_requested {
                if let Some(conn_id) = self.promoted.take() {
                    shared.push_action(NatAction::CloseCircuit { conn_id });
                }
                self.fail(shared, NatError::Timeout);
            } else {
                self.fail(shared, NatError::Timeout);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Relay leg
    // -----------------------------------------------------------------------

    fn begin_relay_leg(&mut self, shared: &mut Shared, now: Now) {
        let Some(relay) = self.relay.clone() else {
            self.leg = RelayLeg::Inactive;
            return;
        };
        self.relay_deadline = Some(now.mono_ms + shared.config.relay_leg_deadline_ms);
        let relay_peer = relay.peer_id().clone();

        if let Some(protocols) = shared.ready.get(&relay_peer) {
            if protocols.iter().any(|p| p == HOP_PROTOCOL_ID) {
                self.open_hop(shared);
            } else {
                self.fail_relay_leg(
                    shared,
                    NatError::Protocol("relay does not advertise the HOP protocol".into()),
                );
            }
        } else if shared.is_connected(&relay_peer) || shared.session_dial_pending(&relay_peer, now)
        {
            // Connected, or another machine (reservation, probe) is already
            // dialing this relay: wait for `PeerReady` on that connection.
            self.leg = RelayLeg::WaitRelayReady;
        } else {
            let deadline_ms = shared.config.relay_leg_deadline_ms;
            shared.push_session_dial(TokenPurpose::RelayDial(self.id), relay, now, deadline_ms);
            self.leg = RelayLeg::WaitRelayReady;
        }
    }

    fn open_hop(&mut self, shared: &mut Shared) {
        let Some(relay_peer) = self.relay_peer().cloned() else {
            return;
        };
        let token = shared.alloc_token(TokenPurpose::OpenHop(self.id, relay_peer.clone()));
        shared.push_action(NatAction::OpenStream {
            token,
            peer: relay_peer,
            protocol_id: HOP_PROTOCOL_ID.into(),
        });
        self.leg = RelayLeg::OpeningHop;
    }

    /// The HOP stream finished multistream negotiation: send CONNECT.
    fn flush_hop_connect(&mut self, stream: StreamId, shared: &mut Shared) {
        let Some(relay_peer) = self.relay_peer().cloned() else {
            return;
        };
        let Some(hop) = self.hop.as_mut() else {
            return;
        };
        if let Err(e) = hop.handle_input(HopConnectInput::Flush) {
            let reason = e.to_string();
            self.fail_relay_leg(shared, NatError::Protocol(reason));
            return;
        }
        while let Some(output) = hop.poll_output() {
            if let HopConnectOutput::Outbound(data) = output {
                shared.push_action(NatAction::SendStream {
                    peer: relay_peer.clone(),
                    stream_id: stream,
                    data,
                });
            }
        }
        self.leg = RelayLeg::AwaitHopStatus { stream };
    }

    fn on_hop_data(&mut self, stream: StreamId, data: &[u8], shared: &mut Shared, now: Now) {
        let Some(hop) = self.hop.as_mut() else {
            return;
        };
        if let Err(e) = hop.handle_input(HopConnectInput::Data(data.to_vec())) {
            let reason = e.to_string();
            self.fail_relay_leg(shared, NatError::Protocol(reason));
            return;
        }
        let mut outputs = Vec::new();
        while let Some(output) = hop.poll_output() {
            outputs.push(output);
        }
        // `HopConnect` yields `Outcome(Bridged)` before any `BridgeData`, so
        // pipelined peer bytes reach the DCUtR machine created below inside
        // this same cascade — before any later `StreamData` event.
        for output in outputs {
            match output {
                HopConnectOutput::Outbound(data) => {
                    if let Some(relay_peer) = self.relay_peer().cloned() {
                        shared.push_action(NatAction::SendStream {
                            peer: relay_peer,
                            stream_id: stream,
                            data,
                        });
                    }
                }
                HopConnectOutput::Outcome(ConnectOutcome::Bridged { .. }) => {
                    self.on_bridged(stream, shared, now);
                }
                HopConnectOutput::Outcome(ConnectOutcome::Refused { status, reason }) => {
                    self.fail_relay_leg(
                        shared,
                        NatError::RelayRefused(format!("{status:?}: {reason}")),
                    );
                    return;
                }
                HopConnectOutput::BridgeData(bytes) => {
                    self.on_bridge_data(stream, &bytes, shared, now);
                }
            }
        }
    }

    /// The relay bridged the circuit: start the DCUtR punch immediately.
    /// The raw stream stays agent-owned until SYNC is sent, at which point it
    /// becomes safe to announce as an application-usable relayed path.
    fn on_bridged(&mut self, stream: StreamId, shared: &mut Shared, now: Now) {
        let RelayLeg::AwaitHopStatus { .. } = self.leg else {
            return;
        };
        let Some(relay_peer) = self.relay_peer().cloned() else {
            return;
        };
        self.leg = RelayLeg::Bridged { stream };
        self.relay_deadline = None;
        self.bridge_alive = true;
        self.hop = None;

        if shared.config.force_relay {
            self.punch_settled = true;
            self.promote_bridge(stream, shared);
            return;
        }

        let mut dcutr = DcutrInitiator::new(&shared.punch_candidates());
        if let Err(e) = dcutr.handle_input(DcutrInitiatorInput::Flush) {
            // Deferred construction error (e.g. oversized CONNECT): the
            // punch cannot even start, but the relayed path stands and is
            // already safe to hand to the application.
            self.promote_bridge(stream, shared);
            self.punch_failed_permanently(shared, e.to_string(), now);
            return;
        }
        while let Some(output) = dcutr.poll_output() {
            if let DcutrInitiatorOutput::Outbound(data) = output {
                shared.push_action(NatAction::SendStream {
                    peer: relay_peer.clone(),
                    stream_id: stream,
                    data,
                });
            }
        }
        self.dcutr_sent_at = Some(now.mono_ms);
        self.dcutr = Some(dcutr);
    }

    fn on_bridge_data(&mut self, stream: StreamId, data: &[u8], shared: &mut Shared, now: Now) {
        let Some(dcutr) = self.dcutr.as_mut() else {
            return;
        };
        let rtt_ms = now
            .mono_ms
            .saturating_sub(self.dcutr_sent_at.unwrap_or(now.mono_ms));
        if let Err(e) = dcutr.handle_input(DcutrInitiatorInput::Data {
            bytes: data.to_vec(),
            rtt_ms,
        }) {
            self.dcutr = None;
            self.punch_failed_permanently(shared, e.to_string(), now);
            return;
        }
        self.drain_dcutr_outputs(stream, shared, now);
    }

    fn drain_dcutr_outputs(&mut self, stream: StreamId, shared: &mut Shared, now: Now) {
        let Some(dcutr) = self.dcutr.as_mut() else {
            return;
        };
        let mut outputs = Vec::new();
        while let Some(output) = dcutr.poll_output() {
            outputs.push(output);
        }
        for output in outputs {
            match output {
                DcutrInitiatorOutput::Outbound(data) => {
                    if let Some(relay_peer) = self.relay_peer().cloned() {
                        shared.push_action(NatAction::SendStream {
                            peer: relay_peer,
                            stream_id: stream,
                            data,
                        });
                    }
                }
                DcutrInitiatorOutput::Outcome(InitiatorOutcome::DialNow {
                    remote_addrs, ..
                }) => {
                    self.on_dial_now(stream, remote_addrs, shared, now);
                }
            }
        }
    }

    /// A remote half-close still permits local protocol writes. Let the
    /// sans-I/O machine consume it rather than treating it as a full circuit
    /// teardown; it may have a complete frame buffered already.
    fn on_hop_remote_write_closed(&mut self, stream: StreamId, shared: &mut Shared, now: Now) {
        let Some(hop) = self.hop.as_mut() else {
            return;
        };
        if let Err(e) = hop.handle_input(HopConnectInput::RemoteWriteClosed) {
            self.fail_relay_leg(shared, NatError::Protocol(e.to_string()));
            return;
        }
        let mut outputs = Vec::new();
        while let Some(output) = hop.poll_output() {
            outputs.push(output);
        }
        for output in outputs {
            match output {
                HopConnectOutput::Outbound(data) => {
                    if let Some(relay_peer) = self.relay_peer().cloned() {
                        shared.push_action(NatAction::SendStream {
                            peer: relay_peer,
                            stream_id: stream,
                            data,
                        });
                    }
                }
                HopConnectOutput::Outcome(ConnectOutcome::Bridged { .. }) => {
                    self.on_bridged(stream, shared, now);
                }
                HopConnectOutput::Outcome(ConnectOutcome::Refused { status, reason }) => {
                    self.fail_relay_leg(
                        shared,
                        NatError::RelayRefused(format!("{status:?}: {reason}")),
                    );
                    return;
                }
                HopConnectOutput::BridgeData(bytes) => {
                    self.on_bridge_data(stream, &bytes, shared, now);
                }
            }
        }
    }

    fn on_bridge_remote_write_closed(&mut self, stream: StreamId, shared: &mut Shared, now: Now) {
        self.bridge_remote_write_closed = true;
        let Some(dcutr) = self.dcutr.as_mut() else {
            return;
        };
        if let Err(e) = dcutr.handle_input(DcutrInitiatorInput::RemoteWriteClosed) {
            self.dcutr = None;
            self.punch_failed_permanently(shared, e.to_string(), now);
            return;
        }
        self.drain_dcutr_outputs(stream, shared, now);
        if self.dcutr.is_some() {
            // No more inbound bytes can complete the CONNECT reply. Release
            // the still-writable relay bridge immediately, but keep original
            // direct candidate dials alive so a late direct path can upgrade
            // it before the connect deadline.
            self.dcutr = None;
            shared.push_event(NatEvent::HolePunchFailed {
                connect_id: self.id,
                attempt: self.punch_window.max(1),
                reason: "relay bridge reached EOF before the DCUtR reply completed".into(),
            });
            self.punch_deadline = None;
            self.promote_bridge(stream, shared);
            if self.direct_live == 0 {
                self.settle_after_punch(shared);
            }
        }
    }

    /// The remote's observed addresses arrived: dial them all, send SYNC,
    /// hand the bridge back to the application, and open the punch window.
    fn on_dial_now(
        &mut self,
        stream: StreamId,
        remote_addrs: Vec<Multiaddr>,
        shared: &mut Shared,
        now: Now,
    ) {
        self.punch_addrs = select_direct_candidates(&remote_addrs, None, None).into_addrs();

        // Per the spec the initiator dials first, then signals SYNC.
        if !self.punch_addrs.is_empty() {
            self.issue_punch_dials(shared);
        }

        let relay_peer = self.relay_peer().cloned();
        if let Some(dcutr) = self.dcutr.as_mut() {
            match dcutr.handle_input(DcutrInitiatorInput::SendSync) {
                Ok(()) => {
                    let mut sync_frames = Vec::new();
                    while let Some(output) = dcutr.poll_output() {
                        if let DcutrInitiatorOutput::Outbound(data) = output {
                            sync_frames.push(data);
                        }
                    }
                    if let Some(relay_peer) = relay_peer {
                        for data in sync_frames {
                            shared.push_action(NatAction::SendStream {
                                peer: relay_peer.clone(),
                                stream_id: stream,
                                data,
                            });
                        }
                    }
                    self.bridge_pending_data = dcutr.take_trailing_data().unwrap_or_default();
                }
                Err(e) => {
                    self.dcutr = None;
                    self.punch_failed_permanently(shared, e.to_string(), now);
                    return;
                }
            }
        }

        // No further DCUtR frames are expected: from here every byte on the
        // bridge belongs to the application.
        self.dcutr = None;
        self.promote_bridge(stream, shared);

        if self.punch_addrs.is_empty() {
            self.punch_failed_permanently(
                shared,
                "no dialable remote addresses in DCUtR reply".into(),
                now,
            );
            return;
        }
        self.punch_window = 1;
        self.punch_deadline = Some(now.mono_ms + shared.config.punch_deadline_ms);
    }

    fn issue_punch_dials(&mut self, shared: &mut Shared) {
        for addr in &self.punch_addrs {
            let Ok(peer_addr) = PeerAddr::new(addr.clone(), self.peer.clone()) else {
                continue;
            };
            let token = shared.alloc_token(TokenPurpose::PunchDial(self.id));
            shared.push_action(NatAction::Dial {
                token,
                addr: peer_addr,
            });
        }
        self.punch_dials_issued = true;
    }

    fn on_punch_window_elapsed(&mut self, shared: &mut Shared, now: Now) {
        shared.push_event(NatEvent::HolePunchFailed {
            connect_id: self.id,
            attempt: self.punch_window,
            reason: "hole punch window elapsed without a direct connection".into(),
        });
        let total_windows = 1 + shared.config.punch_max_retries;
        if self.punch_window < total_windows {
            self.punch_window += 1;
            self.issue_punch_dials(shared);
            self.punch_deadline = Some(now.mono_ms + shared.config.punch_deadline_ms);
        } else {
            self.punch_deadline = None;
            self.settle_after_punch(shared);
        }
    }

    /// The punch can never succeed (protocol error, no addresses): emit one
    /// failure and settle immediately.
    fn punch_failed_permanently(&mut self, shared: &mut Shared, reason: String, _now: Now) {
        shared.push_event(NatEvent::HolePunchFailed {
            connect_id: self.id,
            attempt: self.punch_window.max(1),
            reason,
        });
        self.punch_deadline = None;
        self.settle_after_punch(shared);
    }

    /// The punch is over without a direct connection. If the bridge is
    /// still standing, the relayed path is the final result; otherwise the
    /// attempt has nothing left.
    fn settle_after_punch(&mut self, shared: &mut Shared) {
        if self.done {
            return;
        }
        if self.bridge_alive {
            self.punch_settled = true;
            if let RelayLeg::Bridged { stream } = self.leg {
                self.promote_bridge(stream, shared);
                if self.best.is_some() {
                    shared.push_event(NatEvent::FellBackToRelay {
                        connect_id: self.id,
                        peer: self.peer.clone(),
                    });
                    self.done = true;
                }
            }
        } else {
            let error = self
                .last_error
                .take()
                .unwrap_or(NatError::DialFailed("relay bridge lost".into()));
            self.fail(shared, error);
        }
    }

    /// Relinquishes the exact bridge stream to the circuit transport.
    fn promote_bridge(&mut self, requested_stream: StreamId, shared: &mut Shared) {
        if self.bridge_released {
            return;
        }
        if let RelayLeg::Bridged { stream } = self.leg
            && stream == requested_stream
            && let Some(relay_peer) = self.relay_peer().cloned()
            && let Some(inner_conn) = self.bridge_inner_conn
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

    fn on_stream_closed(&mut self, stream: StreamId, shared: &mut Shared, now: Now) {
        match self.leg {
            RelayLeg::WaitHopReady { stream: s } | RelayLeg::AwaitHopStatus { stream: s }
                if s == stream =>
            {
                self.fail_relay_leg(
                    shared,
                    NatError::Protocol("HOP stream closed before the circuit was bridged".into()),
                );
            }
            RelayLeg::Bridged { stream: s } if s == stream => self.on_bridge_lost(shared, now),
            _ => {}
        }
    }

    /// The bridge died (stream closed or relay connection lost).
    fn on_bridge_lost(&mut self, shared: &mut Shared, now: Now) {
        if !self.bridge_alive {
            return;
        }
        self.bridge_alive = false;
        if let RelayLeg::Bridged { stream } = self.leg
            && !self.bridge_released
            && let Some(relay_peer) = self.relay_peer().cloned()
        {
            shared.release_stream(&relay_peer, stream);
            self.bridge_released = true;
        }
        self.leg = RelayLeg::Failed;
        self.last_error = Some(NatError::DialFailed(
            "relay bridge lost before the attempt settled".into(),
        ));
        if self.dcutr.is_some() {
            // The DCUtR exchange can never complete now.
            self.dcutr = None;
            self.punch_deadline = None;
            if self.direct_live == 0 {
                self.punch_failed_permanently(
                    shared,
                    "relay bridge lost during the DCUtR exchange".into(),
                    now,
                );
            }
        }
        // If punch windows are already running, the punch itself may still
        // succeed via `ConnectionEstablished`; the window deadline settles
        // the rest.
    }

    pub(crate) fn on_promote_result(
        &mut self,
        result: Result<ConnectionId, PromoteError>,
        shared: &mut Shared,
        _now: Now,
    ) {
        match result {
            Ok(conn_id) => self.promoted = Some(conn_id),
            Err(PromoteError::PeerAlreadyDirect) => {
                self.bridge_alive = false;
                self.leg = RelayLeg::Failed;
                if self.direct_live == 0 {
                    self.last_error = Some(NatError::DialFailed(
                        "direct connection won before circuit promotion".into(),
                    ));
                }
            }
            Err(error) => {
                self.bridge_alive = false;
                self.leg = RelayLeg::Failed;
                self.last_error = Some(NatError::Protocol(error.to_string()));
                self.fail_if_no_legs_remain(shared);
            }
        }
    }

    fn fail_relay_leg(&mut self, shared: &mut Shared, error: NatError) {
        match self.leg {
            RelayLeg::WaitHopReady { stream } | RelayLeg::AwaitHopStatus { stream } => {
                if let Some(relay_peer) = self.relay_peer().cloned() {
                    shared.push_action(NatAction::ResetStream {
                        peer: relay_peer.clone(),
                        stream_id: stream,
                    });
                    shared.release_stream(&relay_peer, stream);
                }
            }
            _ => {}
        }
        self.leg = RelayLeg::Failed;
        self.relay_deadline = None;
        self.hop = None;
        self.last_error = Some(error);
        self.fail_if_no_legs_remain(shared);
    }

    fn fail_if_no_legs_remain(&mut self, shared: &mut Shared) {
        let relay_leg_dead = matches!(self.leg, RelayLeg::Failed | RelayLeg::Inactive);
        if self.best.is_none() && self.direct_live == 0 && relay_leg_dead && !self.done {
            let error = self.last_error.take().unwrap_or(NatError::NoPathAvailable);
            self.fail(shared, error);
        }
    }

    fn fail(&mut self, shared: &mut Shared, error: NatError) {
        self.teardown_relay_leg(shared);
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
    fn teardown_relay_leg(&mut self, shared: &mut Shared) {
        match self.leg {
            RelayLeg::WaitHopReady { stream } | RelayLeg::AwaitHopStatus { stream } => {
                if let Some(relay_peer) = self.relay_peer().cloned() {
                    shared.push_action(NatAction::ResetStream {
                        peer: relay_peer.clone(),
                        stream_id: stream,
                    });
                    shared.release_stream(&relay_peer, stream);
                }
            }
            RelayLeg::Bridged { stream } => {
                if let Some(relay_peer) = self.relay_peer().cloned() {
                    if !self.bridge_released && self.bridge_alive {
                        shared.push_action(NatAction::ResetStream {
                            peer: relay_peer.clone(),
                            stream_id: stream,
                        });
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
        self.dcutr = None;
        self.bridge_alive = false;
        if let Some(conn_id) = self.promoted.take() {
            shared.push_action(NatAction::CloseCircuit { conn_id });
        }
    }

    fn relay_peer(&self) -> Option<&PeerId> {
        self.relay.as_ref().map(PeerAddr::peer_id)
    }

    fn is_relay_peer(&self, peer: &PeerId) -> bool {
        self.relay_peer() == Some(peer)
    }
}
