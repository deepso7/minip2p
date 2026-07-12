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
use crate::events::{NatAction, NatEvent};
use crate::types::{ConnectId, NatError, Now, Path};

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
    /// The bridge stream has been handed back to the application.
    bridge_released: bool,
    punch_addrs: Vec<Multiaddr>,
    punch_dials_issued: bool,
    /// Absolute deadline of the current punch window.
    punch_deadline: Option<u64>,
    /// 1-based index of the current punch window.
    punch_window: u32,
    best: Option<Path>,
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
        let candidates = select_direct_candidates(&direct_addrs, None, None).into_addrs();
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
            punch_addrs: Vec::new(),
            punch_dials_issued: false,
            punch_deadline: None,
            punch_window: 0,
            best: None,
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
            let stagger = shared.config.relay_stagger_ms;
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

    pub(crate) fn on_peer_connected(&mut self, peer: &PeerId, shared: &mut Shared, now: Now) {
        if self.done || *peer != self.peer {
            return;
        }
        let path = if self.punch_dials_issued {
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

    pub(crate) fn on_peer_disconnected(&mut self, peer: &PeerId, shared: &mut Shared, now: Now) {
        if self.done || !self.is_relay_peer(peer) {
            return;
        }
        match self.leg {
            RelayLeg::WaitRelayReady
            | RelayLeg::OpeningHop
            | RelayLeg::WaitHopReady { .. }
            | RelayLeg::AwaitHopStatus { .. } => {
                self.fail_relay_leg(
                    shared,
                    NatError::DialFailed("relay connection closed".into()),
                );
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
                self.fail_if_no_legs_remain(shared);
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
        stream: StreamId,
        input: StreamInput<'_>,
        shared: &mut Shared,
        now: Now,
    ) {
        if self.done {
            return;
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
            (_, StreamInput::Closed | StreamInput::RemoteWriteClosed) => {
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
        } else if shared.connected.contains(&relay_peer) {
            self.leg = RelayLeg::WaitRelayReady;
        } else {
            let token = shared.alloc_token(TokenPurpose::RelayDial(self.id));
            shared.push_action(NatAction::Dial { token, addr: relay });
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

    /// The relay bridged the circuit: announce the relayed path and start
    /// the DCUtR punch over it immediately, in parallel.
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

        if self.best.is_none() {
            let path = Path::Relayed {
                relay: relay_peer.clone(),
                stream_id: stream,
            };
            self.best = Some(path.clone());
            shared.push_event(NatEvent::PathEstablished {
                connect_id: self.id,
                peer: self.peer.clone(),
                path,
            });
        }

        let mut dcutr = DcutrInitiator::new(&shared.listen_addrs);
        if let Err(e) = dcutr.handle_input(DcutrInitiatorInput::Flush) {
            // Deferred construction error (e.g. oversized CONNECT): the
            // punch cannot even start, but the relayed path stands.
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

        if let Some(dcutr) = self.dcutr.as_mut() {
            match dcutr.handle_input(DcutrInitiatorInput::SendSync) {
                Ok(()) => {
                    let mut sync_frames = Vec::new();
                    while let Some(output) = dcutr.poll_output() {
                        if let DcutrInitiatorOutput::Outbound(data) = output {
                            sync_frames.push(data);
                        }
                    }
                    if let Some(relay_peer) = self.relay_peer().cloned() {
                        for data in sync_frames {
                            shared.push_action(NatAction::SendStream {
                                peer: relay_peer.clone(),
                                stream_id: stream,
                                data,
                            });
                        }
                    }
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
        self.release_bridge(shared);

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
            self.release_bridge(shared);
            shared.push_event(NatEvent::FellBackToRelay {
                connect_id: self.id,
                peer: self.peer.clone(),
            });
            self.done = true;
        } else {
            let error = self
                .last_error
                .take()
                .unwrap_or(NatError::DialFailed("relay bridge lost".into()));
            self.fail(shared, error);
        }
    }

    /// Stops consuming the bridge stream; subsequent `StreamData` on it is
    /// forwarded to the application by the driver.
    fn release_bridge(&mut self, shared: &mut Shared) {
        if self.bridge_released {
            return;
        }
        if let RelayLeg::Bridged { stream } = self.leg
            && let Some(relay_peer) = self.relay_peer().cloned()
        {
            self.bridge_released = true;
            shared.release_stream(&relay_peer, stream);
        }
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
            self.punch_failed_permanently(
                shared,
                "relay bridge lost during the DCUtR exchange".into(),
                now,
            );
        }
        // If punch windows are already running, the punch itself may still
        // succeed via `ConnectionEstablished`; the window deadline settles
        // the rest.
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
            RelayLeg::WaitHopReady { stream }
            | RelayLeg::AwaitHopStatus { stream }
            | RelayLeg::Bridged { stream } => {
                if let Some(relay_peer) = self.relay_peer().cloned() {
                    if self.bridge_alive || !matches!(self.leg, RelayLeg::Bridged { .. }) {
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
    }

    fn relay_peer(&self) -> Option<&PeerId> {
        self.relay.as_ref().map(PeerAddr::peer_id)
    }

    fn is_relay_peer(&self, peer: &PeerId) -> bool {
        self.relay_peer() == Some(peer)
    }
}
