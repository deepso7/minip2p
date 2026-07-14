//! Own-side housekeeping, independent of any connect attempt:
//!
//! - [`Prober`] — AutoNAT reachability probing with majority-of-N confidence
//!   over a sliding window of M verdicts. `AutoNatClient` is single-shot;
//!   the aggregation (and the never-flap-on-one-probe guarantee) lives here.
//! - [`ReservationManager`] — holds a relay reservation per the configured
//!   [`ReservationPolicy`], renewing ahead of the relay-reported `expire`
//!   and rotating relays (with backoff) on refusal or loss.

use alloc::string::String;
use alloc::vec::Vec;

use minip2p_autonat::{
    AUTONAT_PROTOCOL_ID, AutoNatClient, AutoNatClientInput, AutoNatClientOutput, Reachability,
};
use minip2p_core::{Multiaddr, PeerAddr, PeerId, SansIoProtocol, select_direct_candidates};
use minip2p_relay::{
    HOP_PROTOCOL_ID, HopReservation, HopReservationInput, HopReservationOutput, ReservationOutcome,
};
use minip2p_transport::{ConnectionId, StreamId};

use crate::ReservationPolicy;
use crate::agent::{Shared, StreamInput, StreamRole, TokenPurpose};
use crate::events::{NatAction, NatEvent};
use crate::types::{Now, ReachabilityState, ReservationInfo};

/// Progress of one outbound single-stream exchange (probe or reservation).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExchangeStage {
    /// Waiting for the server's connection to reach `PeerReady`
    /// (a dial may be in flight).
    WaitPeerReady,
    /// `OpenStream` issued; waiting for the stream id.
    Opening,
    /// Stream allocated; waiting for multistream negotiation.
    WaitStreamReady { stream: StreamId },
    /// Request sent; waiting for the response.
    AwaitResponse { stream: StreamId },
}

impl ExchangeStage {
    fn stream(&self) -> Option<StreamId> {
        match self {
            Self::WaitStreamReady { stream } | Self::AwaitResponse { stream } => Some(*stream),
            _ => None,
        }
    }
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

/// AutoNAT probing with an M-sample confidence window: the verdict flips
/// only when at least N of the last M samples agree, and each flip emits
/// exactly one [`NatEvent::ReachabilityChanged`].
pub(crate) struct Prober {
    verdict: ReachabilityState,
    /// Sliding window of recent samples (`true` = public).
    window: Vec<bool>,
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
            window: Vec::new(),
            public_addrs: Vec::new(),
            flight: None,
            // Without configured servers there is nothing to schedule, and
            // the agent must not report a phantom timeout.
            next_probe_at: has_servers.then_some(0),
            server_idx: 0,
        }
    }

    fn on_tick(&mut self, shared: &mut Shared, now: Now) {
        if let Some(flight) = &self.flight
            && now.mono_ms >= flight.deadline
        {
            self.abort_flight(shared, now);
        }
        if self.flight.is_none()
            && let Some(due) = self.next_probe_at
            && now.mono_ms >= due
        {
            self.start_probe(shared, now);
        }
    }

    /// Starts the next probe if the preconditions hold.
    fn start_probe(&mut self, shared: &mut Shared, now: Now) {
        if shared.config.autonat_servers.is_empty() || shared.listen_addrs.is_empty() {
            // Nothing to probe (yet); check again at the unsettled cadence.
            self.next_probe_at = Some(now.mono_ms + shared.config.probe_interval_unsettled_ms);
            return;
        }
        let servers = &shared.config.autonat_servers;
        let server = servers[self.server_idx % servers.len()].clone();
        let deadline = now.mono_ms + shared.config.probe_deadline_ms;
        let server_peer = server.peer_id().clone();

        let stage = if let Some(protocols) = shared.ready.get(&server_peer) {
            if protocols.iter().any(|p| p == AUTONAT_PROTOCOL_ID) {
                let token = shared.alloc_token(TokenPurpose::OpenProbe(server_peer.clone()));
                shared.push_action(NatAction::OpenStream {
                    token,
                    peer: server_peer,
                    protocol_id: AUTONAT_PROTOCOL_ID.into(),
                });
                ExchangeStage::Opening
            } else {
                // Wrong server; rotate and try the next one soon.
                self.server_idx += 1;
                self.next_probe_at = Some(now.mono_ms + shared.config.probe_interval_unsettled_ms);
                return;
            }
        } else if shared.connected.contains(&server_peer)
            || shared.session_dial_pending(&server_peer, now)
        {
            // Connected, or another machine is already dialing this peer
            // (an AutoNAT server can double as the configured relay).
            ExchangeStage::WaitPeerReady
        } else {
            let deadline_ms = shared.config.probe_deadline_ms;
            shared.push_session_dial(TokenPurpose::ProbeDial, server.clone(), now, deadline_ms);
            ExchangeStage::WaitPeerReady
        };

        self.flight = Some(ProbeFlight {
            server,
            stage,
            machine: None,
            deadline,
        });
        self.next_probe_at = None;
    }

    fn on_peer_ready(
        &mut self,
        peer: &PeerId,
        protocols: &[String],
        shared: &mut Shared,
        now: Now,
    ) {
        let Some(flight) = &mut self.flight else {
            return;
        };
        if flight.stage != ExchangeStage::WaitPeerReady || flight.server.peer_id() != peer {
            return;
        }
        if protocols.iter().any(|p| p == AUTONAT_PROTOCOL_ID) {
            let token = shared.alloc_token(TokenPurpose::OpenProbe(peer.clone()));
            shared.push_action(NatAction::OpenStream {
                token,
                peer: peer.clone(),
                protocol_id: AUTONAT_PROTOCOL_ID.into(),
            });
            flight.stage = ExchangeStage::Opening;
        } else {
            self.abort_flight(shared, now);
        }
    }

    fn on_peer_disconnected(&mut self, peer: &PeerId, shared: &mut Shared, now: Now) {
        if let Some(flight) = &self.flight
            && flight.server.peer_id() == peer
        {
            self.abort_flight(shared, now);
        }
    }

    fn on_peer_superseded(&mut self, peer: &PeerId, shared: &mut Shared, now: Now) {
        if self
            .flight
            .as_ref()
            .is_some_and(|flight| flight.server.peer_id() == peer)
        {
            // The old connection's stream ids are invalid, but resetting
            // them would target the replacement connection.
            self.flight = None;
            self.server_idx += 1;
            self.next_probe_at = Some(now.mono_ms + shared.config.probe_interval_unsettled_ms);
        }
    }

    fn on_dial_result(
        &mut self,
        result: &Result<ConnectionId, String>,
        shared: &mut Shared,
        now: Now,
    ) {
        if result.is_err()
            && self
                .flight
                .as_ref()
                .is_some_and(|f| f.stage == ExchangeStage::WaitPeerReady)
        {
            self.abort_flight(shared, now);
        }
    }

    fn on_stream_open_result(
        &mut self,
        server_peer: &PeerId,
        result: Result<StreamId, String>,
        shared: &mut Shared,
        now: Now,
    ) {
        let expecting = self.flight.as_ref().is_some_and(|f| {
            f.stage == ExchangeStage::Opening && f.server.peer_id() == server_peer
        });
        if !expecting {
            if let Ok(stream_id) = result {
                shared.push_action(NatAction::ResetStream {
                    peer: server_peer.clone(),
                    stream_id,
                });
            }
            return;
        }
        match result {
            Ok(stream) => {
                let flight = self.flight.as_mut().expect("checked above");
                shared.own_stream(server_peer, stream, StreamRole::AutonatProbe);
                flight.machine = Some(AutoNatClient::new(
                    &shared.local_peer_id,
                    &shared.listen_addrs,
                ));
                flight.stage = ExchangeStage::WaitStreamReady { stream };
            }
            Err(_) => self.abort_flight(shared, now),
        }
    }

    /// Routes a probe-stream event. Returns whether the verdict flipped.
    fn on_stream_input(
        &mut self,
        stream: StreamId,
        input: StreamInput<'_>,
        shared: &mut Shared,
        now: Now,
    ) -> bool {
        let Some(flight) = &mut self.flight else {
            return false;
        };
        if flight.stage.stream() != Some(stream) {
            return false;
        }
        match (flight.stage, input) {
            (ExchangeStage::WaitStreamReady { .. }, StreamInput::Ready) => {
                let server_peer = flight.server.peer_id().clone();
                let Some(machine) = flight.machine.as_mut() else {
                    return false;
                };
                if machine.handle_input(AutoNatClientInput::Flush).is_err() {
                    self.abort_flight(shared, now);
                    return false;
                }
                while let Some(output) = machine.poll_output() {
                    if let AutoNatClientOutput::Outbound(data) = output {
                        shared.push_action(NatAction::SendStream {
                            peer: server_peer.clone(),
                            stream_id: stream,
                            data,
                        });
                    }
                }
                flight.stage = ExchangeStage::AwaitResponse { stream };
                false
            }
            (ExchangeStage::AwaitResponse { .. }, StreamInput::Data(data)) => {
                let Some(machine) = flight.machine.as_mut() else {
                    return false;
                };
                if machine
                    .handle_input(AutoNatClientInput::Data(data.to_vec()))
                    .is_err()
                {
                    self.abort_flight(shared, now);
                    return false;
                }
                let mut sample = None;
                while let Some(output) = machine.poll_output() {
                    if let AutoNatClientOutput::Outcome(reachability) = output {
                        sample = Some(reachability);
                    }
                }
                match sample {
                    Some(reachability) => {
                        self.finish_flight(shared, now);
                        self.record_sample(&reachability, shared, now)
                    }
                    None => false,
                }
            }
            (ExchangeStage::AwaitResponse { .. }, StreamInput::RemoteWriteClosed) => {
                let Some(machine) = flight.machine.as_mut() else {
                    return false;
                };
                if machine
                    .handle_input(AutoNatClientInput::RemoteWriteClosed)
                    .is_err()
                {
                    self.abort_flight(shared, now);
                    return false;
                }
                let mut sample = None;
                while let Some(output) = machine.poll_output() {
                    if let AutoNatClientOutput::Outcome(reachability) = output {
                        sample = Some(reachability);
                    }
                }
                match sample {
                    Some(reachability) => {
                        self.finish_flight(shared, now);
                        self.record_sample(&reachability, shared, now)
                    }
                    None => false,
                }
            }
            (_, StreamInput::Closed) => {
                self.abort_flight(shared, now);
                false
            }
            _ => false,
        }
    }

    /// Records one probe verdict and applies the N-of-M confidence rule.
    /// Returns whether the verdict flipped.
    fn record_sample(
        &mut self,
        reachability: &Reachability,
        shared: &mut Shared,
        _now: Now,
    ) -> bool {
        let (sample, sample_addrs) = match reachability {
            Reachability::Public { addrs, .. } => {
                let selected = select_direct_candidates(addrs, None, None);
                // A successful dial-back is useful public evidence only when
                // it leaves the application with an address this QUIC-only
                // stack can actually advertise and accept. Counting an empty
                // selection could release a WhenPrivate reservation while
                // providing no direct replacement path.
                if selected.is_empty() {
                    return false;
                }
                (true, selected.into_addrs())
            }
            Reachability::Private { .. } => (false, Vec::new()),
            // No signal: never move the window on an inconclusive probe.
            Reachability::Unknown { .. } => return false,
        };
        let window = usize::from(shared.config.confidence_window.max(1));
        self.window.push(sample);
        if self.window.len() > window {
            self.window.remove(0);
        }

        // A threshold above the bounded window can never be reached. Treat
        // it as unanimity for the configured window instead of leaving
        // reachability permanently Unknown.
        let threshold = usize::from(shared.config.confidence_threshold.max(1)).min(window);
        let public_votes = self.window.iter().filter(|s| **s).count();
        let private_votes = self.window.len() - public_votes;
        let new = if public_votes >= threshold {
            ReachabilityState::Public
        } else if private_votes >= threshold {
            ReachabilityState::Private
        } else {
            self.verdict
        };
        if new == self.verdict {
            if new == ReachabilityState::Public && sample && sample_addrs != self.public_addrs {
                self.public_addrs = sample_addrs.clone();
                shared.push_event(NatEvent::PublicAddressesChanged {
                    addrs: sample_addrs,
                });
            }
            return false;
        }
        let old = core::mem::replace(&mut self.verdict, new);
        self.public_addrs = if new == ReachabilityState::Public && sample {
            sample_addrs
        } else {
            Vec::new()
        };
        shared.push_event(NatEvent::ReachabilityChanged {
            old,
            new,
            confirmed_addrs: self.public_addrs.clone(),
        });
        true
    }

    /// Ends the current flight cleanly (response consumed) and schedules
    /// the next probe.
    fn finish_flight(&mut self, shared: &mut Shared, now: Now) {
        if let Some(flight) = self.flight.take()
            && let Some(stream) = flight.stage.stream()
        {
            let peer = flight.server.peer_id();
            shared.push_action(NatAction::CloseStreamWrite {
                peer: peer.clone(),
                stream_id: stream,
            });
            shared.release_stream(peer, stream);
        }
        self.schedule_next(shared, now);
    }

    /// Ends the current flight without a sample (error/timeout/refusal),
    /// rotates servers, and schedules a quick retry.
    fn abort_flight(&mut self, shared: &mut Shared, now: Now) {
        if let Some(flight) = self.flight.take()
            && let Some(stream) = flight.stage.stream()
        {
            let peer = flight.server.peer_id();
            shared.push_action(NatAction::ResetStream {
                peer: peer.clone(),
                stream_id: stream,
            });
            shared.release_stream(peer, stream);
        }
        self.server_idx += 1;
        self.next_probe_at = Some(now.mono_ms + shared.config.probe_interval_unsettled_ms);
    }

    fn schedule_next(&mut self, shared: &mut Shared, now: Now) {
        let interval = if self.verdict == ReachabilityState::Unknown {
            shared.config.probe_interval_unsettled_ms
        } else {
            shared.config.probe_interval_settled_ms
        };
        self.next_probe_at = Some(now.mono_ms + interval);
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
    /// Reservation held; renewal fires at `info.renew_at_mono_ms`.
    Reserved {
        relay: PeerAddr,
        info: ReservationInfo,
    },
    /// Waiting out a failure/refusal before trying the (rotated) relay.
    Backoff { until: u64 },
}

/// Holds a relay reservation according to policy: `Wanted ↔ Reserved`, with
/// renewal scheduled from the relay's absolute `expire`, a default-TTL
/// fallback for missing expiries or clockless hosts, and relay rotation
/// plus backoff on refusal.
pub(crate) struct ReservationManager {
    state: ResState,
    relay_idx: usize,
    /// The initial policy reconciliation is an immediate timer source. Once
    /// it runs, later policy flips call `sync` directly from probe handling.
    needs_sync: bool,
    /// Set while renewing or reconnecting so a failure emits
    /// [`NatEvent::RelayReservationLost`] exactly once.
    held: Option<PeerId>,
}

impl ReservationManager {
    fn new(config: &crate::NatConfig) -> Self {
        Self {
            state: ResState::Idle,
            relay_idx: 0,
            needs_sync: !config.relays.is_empty()
                && config.reservation_policy != ReservationPolicy::Never,
            held: None,
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
    fn sync(&mut self, verdict: ReachabilityState, shared: &mut Shared, now: Now) {
        self.needs_sync = false;
        let wanted = self.wanted(shared, verdict);
        if !wanted {
            self.release(shared);
            return;
        }
        match &self.state {
            ResState::Idle => self.begin_acquire(shared, now),
            ResState::Backoff { until } if now.mono_ms >= *until => {
                self.begin_acquire(shared, now);
            }
            ResState::Reserved { info, .. } if now.mono_ms >= info.renew_at_mono_ms => {
                let relay_peer = info.relay.clone();
                self.held = Some(relay_peer);
                self.begin_acquire(shared, now);
            }
            ResState::Acquiring { deadline, .. } if now.mono_ms >= *deadline => {
                self.fail_acquire(shared, now);
            }
            _ => {}
        }
    }

    /// Drops any held reservation and stops acquiring (policy says no).
    fn release(&mut self, shared: &mut Shared) {
        match core::mem::replace(&mut self.state, ResState::Idle) {
            ResState::Reserved { relay, .. } => {
                shared.push_event(NatEvent::RelayReservationLost {
                    relay: relay.peer_id().clone(),
                });
            }
            ResState::Acquiring { relay, stage, .. } => {
                if let Some(stream) = stage.stream() {
                    let peer = relay.peer_id();
                    shared.push_action(NatAction::ResetStream {
                        peer: peer.clone(),
                        stream_id: stream,
                    });
                    shared.release_stream(peer, stream);
                }
                if let Some(held) = self.held.take() {
                    shared.push_event(NatEvent::RelayReservationLost { relay: held });
                }
            }
            _ => {}
        }
        self.held = None;
    }

    fn begin_acquire(&mut self, shared: &mut Shared, now: Now) {
        let relays = &shared.config.relays;
        if relays.is_empty() {
            self.state = ResState::Idle;
            return;
        }
        let relay = relays[self.relay_idx % relays.len()].clone();
        let relay_peer = relay.peer_id().clone();
        let deadline = now.mono_ms + shared.config.relay_leg_deadline_ms;

        let stage = if let Some(protocols) = shared.ready.get(&relay_peer) {
            if protocols.iter().any(|p| p == HOP_PROTOCOL_ID) {
                let token = shared.alloc_token(TokenPurpose::OpenReserve(relay_peer.clone()));
                shared.push_action(NatAction::OpenStream {
                    token,
                    peer: relay_peer,
                    protocol_id: HOP_PROTOCOL_ID.into(),
                });
                ExchangeStage::Opening
            } else {
                self.state = ResState::Idle;
                self.fail_acquire(shared, now);
                return;
            }
        } else if shared.connected.contains(&relay_peer)
            || shared.session_dial_pending(&relay_peer, now)
        {
            // Connected, or a connect attempt's relay leg is already dialing
            // this relay: share that connection instead of superseding it.
            ExchangeStage::WaitPeerReady
        } else {
            let deadline_ms = shared.config.relay_leg_deadline_ms;
            shared.push_session_dial(TokenPurpose::ReserveDial, relay.clone(), now, deadline_ms);
            ExchangeStage::WaitPeerReady
        };

        self.state = ResState::Acquiring {
            relay,
            stage,
            machine: None,
            deadline,
        };
    }

    /// The acquisition failed (dial error, refusal, timeout, machine
    /// error): emit `RelayReservationLost` if a reservation was being
    /// renewed, rotate relays, and back off.
    fn fail_acquire(&mut self, shared: &mut Shared, now: Now) {
        if let ResState::Acquiring { relay, stage, .. } =
            core::mem::replace(&mut self.state, ResState::Idle)
            && let Some(stream) = stage.stream()
        {
            let peer = relay.peer_id();
            shared.push_action(NatAction::ResetStream {
                peer: peer.clone(),
                stream_id: stream,
            });
            shared.release_stream(peer, stream);
        }
        if let Some(held) = self.held.take() {
            shared.push_event(NatEvent::RelayReservationLost { relay: held });
        }
        self.relay_idx += 1;
        self.state = ResState::Backoff {
            until: now.mono_ms + shared.config.reservation_retry_backoff_ms,
        };
    }

    fn on_peer_ready(
        &mut self,
        peer: &PeerId,
        protocols: &[String],
        shared: &mut Shared,
        now: Now,
    ) {
        let ResState::Acquiring { relay, stage, .. } = &mut self.state else {
            return;
        };
        if *stage != ExchangeStage::WaitPeerReady || relay.peer_id() != peer {
            return;
        }
        if protocols.iter().any(|p| p == HOP_PROTOCOL_ID) {
            let token = shared.alloc_token(TokenPurpose::OpenReserve(peer.clone()));
            shared.push_action(NatAction::OpenStream {
                token,
                peer: peer.clone(),
                protocol_id: HOP_PROTOCOL_ID.into(),
            });
            *stage = ExchangeStage::Opening;
        } else {
            self.fail_acquire(shared, now);
        }
    }

    fn on_peer_disconnected(&mut self, peer: &PeerId, shared: &mut Shared, now: Now) {
        match &self.state {
            ResState::Reserved { relay, .. } if relay.peer_id() == peer => {
                // The relay session carries inbound circuits; without it the
                // reservation is useless. Reacquire after a short backoff.
                shared.push_event(NatEvent::RelayReservationLost {
                    relay: peer.clone(),
                });
                self.relay_idx += 1;
                self.state = ResState::Backoff {
                    until: now.mono_ms + shared.config.reservation_retry_backoff_ms,
                };
            }
            ResState::Acquiring { relay, .. } if relay.peer_id() == peer => {
                self.fail_acquire(shared, now);
            }
            _ => {}
        }
    }

    fn on_peer_superseded(&mut self, peer: &PeerId, shared: &mut Shared, now: Now) {
        match &self.state {
            ResState::Reserved { relay, .. } if relay.peer_id() == peer => {
                shared.push_event(NatEvent::RelayReservationLost {
                    relay: peer.clone(),
                });
                self.relay_idx += 1;
                self.state = ResState::Backoff {
                    until: now.mono_ms + shared.config.reservation_retry_backoff_ms,
                };
            }
            ResState::Acquiring { relay, .. } if relay.peer_id() == peer => {
                // Do not reset the retired stream id on the new connection.
                // A renewal keeps the old reservation in `held` while its
                // replacement exchange runs. Superseding the relay connection
                // invalidates that reservation even though the exchange did
                // not fail through the normal stream path.
                if let Some(held) = self.held.take() {
                    shared.push_event(NatEvent::RelayReservationLost { relay: held });
                }
                self.relay_idx += 1;
                self.state = ResState::Backoff {
                    until: now.mono_ms + shared.config.reservation_retry_backoff_ms,
                };
            }
            _ => {}
        }
    }

    fn on_dial_result(
        &mut self,
        result: &Result<ConnectionId, String>,
        shared: &mut Shared,
        now: Now,
    ) {
        if result.is_err()
            && matches!(
                &self.state,
                ResState::Acquiring {
                    stage: ExchangeStage::WaitPeerReady,
                    ..
                }
            )
        {
            self.fail_acquire(shared, now);
        }
    }

    fn on_stream_open_result(
        &mut self,
        relay_peer: &PeerId,
        result: Result<StreamId, String>,
        shared: &mut Shared,
        now: Now,
    ) {
        let expecting = matches!(
            &self.state,
            ResState::Acquiring { relay, stage: ExchangeStage::Opening, .. }
                if relay.peer_id() == relay_peer
        );
        if !expecting {
            if let Ok(stream_id) = result {
                shared.push_action(NatAction::ResetStream {
                    peer: relay_peer.clone(),
                    stream_id,
                });
            }
            return;
        }
        match result {
            Ok(stream) => {
                shared.own_stream(relay_peer, stream, StreamRole::HopReserve);
                if let ResState::Acquiring { stage, machine, .. } = &mut self.state {
                    *machine = Some(HopReservation::new());
                    *stage = ExchangeStage::WaitStreamReady { stream };
                }
            }
            Err(_) => self.fail_acquire(shared, now),
        }
    }

    fn on_stream_input(
        &mut self,
        stream: StreamId,
        input: StreamInput<'_>,
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
        if stage.stream() != Some(stream) {
            return;
        }
        match (*stage, input) {
            (ExchangeStage::WaitStreamReady { .. }, StreamInput::Ready) => {
                let relay_peer = relay.peer_id().clone();
                let Some(machine) = machine.as_mut() else {
                    return;
                };
                if machine.handle_input(HopReservationInput::Flush).is_err() {
                    self.fail_acquire(shared, now);
                    return;
                }
                while let Some(output) = machine.poll_output() {
                    if let HopReservationOutput::Outbound(data) = output {
                        shared.push_action(NatAction::SendStream {
                            peer: relay_peer.clone(),
                            stream_id: stream,
                            data,
                        });
                    }
                }
                *stage = ExchangeStage::AwaitResponse { stream };
            }
            (ExchangeStage::AwaitResponse { .. }, StreamInput::Data(data)) => {
                let Some(m) = machine.as_mut() else {
                    return;
                };
                if m.handle_input(HopReservationInput::Data(data.to_vec()))
                    .is_err()
                {
                    self.fail_acquire(shared, now);
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
                        self.complete_acquire(relay, stream, expire, shared, now);
                    }
                    Some(ReservationOutcome::Refused { .. }) => {
                        self.fail_acquire(shared, now);
                    }
                    None => {}
                }
            }
            (ExchangeStage::AwaitResponse { .. }, StreamInput::RemoteWriteClosed) => {
                let Some(m) = machine.as_mut() else {
                    return;
                };
                if m.handle_input(HopReservationInput::RemoteWriteClosed)
                    .is_err()
                {
                    self.fail_acquire(shared, now);
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
                        self.complete_acquire(relay, stream, expire, shared, now);
                    }
                    Some(ReservationOutcome::Refused { .. }) => {
                        self.fail_acquire(shared, now);
                    }
                    None => {}
                }
            }
            (_, StreamInput::Closed) => {
                self.fail_acquire(shared, now);
            }
            _ => {}
        }
    }

    /// A reservation (initial or renewal) was accepted: compute the renewal
    /// time and announce it.
    fn complete_acquire(
        &mut self,
        relay: PeerAddr,
        stream: StreamId,
        expire_unix_secs: Option<u64>,
        shared: &mut Shared,
        now: Now,
    ) {
        let relay_peer = relay.peer_id().clone();
        shared.push_action(NatAction::CloseStreamWrite {
            peer: relay_peer.clone(),
            stream_id: stream,
        });
        shared.release_stream(&relay_peer, stream);
        self.held = None;

        let margin = shared.config.reservation_renewal_margin_secs;
        let default_ttl = shared.config.reservation_default_ttl_secs;
        // Renew `margin` seconds before the reported expiry when both the
        // expiry and a wall clock exist; otherwise assume the default TTL.
        // Clockless renewal is approximate by design.
        let renew_in_secs = match (expire_unix_secs, now.unix_secs) {
            (Some(expire), Some(unix_now)) => {
                let remaining = expire.saturating_sub(unix_now);
                remaining.saturating_sub(margin).max(1)
            }
            _ => default_ttl.saturating_sub(margin).max(1),
        };
        let info = ReservationInfo {
            relay: relay_peer.clone(),
            expires_unix_secs: expire_unix_secs,
            // The relay controls `expire`, so this conversion must not let a
            // large value wrap the monotonic renewal deadline.
            renew_at_mono_ms: now
                .mono_ms
                .saturating_add(renew_in_secs.saturating_mul(1_000)),
        };
        shared.push_event(NatEvent::RelayReserved {
            relay: relay_peer,
            expires_unix_secs: info.expires_unix_secs,
            renew_at_mono_ms: info.renew_at_mono_ms,
        });
        self.state = ResState::Reserved { relay, info };
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
            ResState::Reserved { info, .. } => Some(info.renew_at_mono_ms),
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
    pub(crate) fn new(config: &crate::NatConfig) -> Self {
        Self {
            prober: Prober::new(!config.autonat_servers.is_empty()),
            reservations: ReservationManager::new(config),
        }
    }

    pub(crate) fn reachability(&self) -> ReachabilityState {
        self.prober.verdict
    }

    pub(crate) fn active_reservation(&self) -> Option<&ReservationInfo> {
        self.reservations.active()
    }

    pub(crate) fn on_tick(&mut self, shared: &mut Shared, now: Now) {
        self.prober.on_tick(shared, now);
        self.reservations.sync(self.prober.verdict, shared, now);
    }

    pub(crate) fn on_peer_ready(
        &mut self,
        peer: &PeerId,
        protocols: &[String],
        shared: &mut Shared,
        now: Now,
    ) {
        self.prober.on_peer_ready(peer, protocols, shared, now);
        self.reservations
            .on_peer_ready(peer, protocols, shared, now);
    }

    pub(crate) fn on_peer_disconnected(&mut self, peer: &PeerId, shared: &mut Shared, now: Now) {
        self.prober.on_peer_disconnected(peer, shared, now);
        self.reservations.on_peer_disconnected(peer, shared, now);
    }

    pub(crate) fn on_peer_superseded(&mut self, peer: &PeerId, shared: &mut Shared, now: Now) {
        self.prober.on_peer_superseded(peer, shared, now);
        self.reservations.on_peer_superseded(peer, shared, now);
    }

    pub(crate) fn on_probe_dial_result(
        &mut self,
        result: &Result<ConnectionId, String>,
        shared: &mut Shared,
        now: Now,
    ) {
        self.prober.on_dial_result(result, shared, now);
    }

    pub(crate) fn on_reserve_dial_result(
        &mut self,
        result: &Result<ConnectionId, String>,
        shared: &mut Shared,
        now: Now,
    ) {
        self.reservations.on_dial_result(result, shared, now);
    }

    pub(crate) fn on_probe_open_result(
        &mut self,
        server_peer: &PeerId,
        result: Result<StreamId, String>,
        shared: &mut Shared,
        now: Now,
    ) {
        self.prober
            .on_stream_open_result(server_peer, result, shared, now);
    }

    pub(crate) fn on_reserve_open_result(
        &mut self,
        relay_peer: &PeerId,
        result: Result<StreamId, String>,
        shared: &mut Shared,
        now: Now,
    ) {
        self.reservations
            .on_stream_open_result(relay_peer, result, shared, now);
    }

    pub(crate) fn on_stream_input(
        &mut self,
        role: StreamRole,
        stream: StreamId,
        input: StreamInput<'_>,
        shared: &mut Shared,
        now: Now,
    ) {
        match role {
            StreamRole::AutonatProbe => {
                if self.prober.on_stream_input(stream, input, shared, now) {
                    // A verdict flip can change what the reservation policy
                    // wants; reconcile inside the same cascade.
                    self.reservations.sync(self.prober.verdict, shared, now);
                }
            }
            StreamRole::HopReserve => {
                self.reservations
                    .on_stream_input(stream, input, shared, now);
            }
            StreamRole::HopConnect(_) | StreamRole::StopInbound(_) | StreamRole::RejectedStop => {}
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
