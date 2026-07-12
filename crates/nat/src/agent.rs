use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::{Multiaddr, PeerId};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, StreamId};

use minip2p_relay::STOP_PROTOCOL_ID;

use crate::attempt::ConnectAttempt;
use crate::config::NatConfig;
use crate::events::{NatAction, NatEvent};
use crate::housekeeping::Housekeeping;
use crate::inbound::InboundCircuit;
use crate::types::{ConnectId, NatToken, Now, ReachabilityState, ReservationInfo};

/// Roles a stream owned by the agent can play. Streams not in the registry
/// belong to the application (`Released` is modeled as removal).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamRole {
    /// Outbound HOP CONNECT stream for a dialer-side attempt; after the
    /// relay reports `Bridged` the same stream carries the DCUtR exchange.
    HopConnect(ConnectId),
    /// Outbound HOP RESERVE stream (reservation manager).
    HopReserve,
    /// Outbound AutoNAT probe stream (reachability prober).
    AutonatProbe,
    /// Inbound STOP stream from a relay (responder-side circuit).
    StopInbound(u64),
}

/// What a pending `Dial` / `OpenStream` token was issued for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TokenPurpose {
    /// Dial of a caller-supplied direct candidate.
    DirectDial(ConnectId),
    /// Dial of the relay itself (to start a relay leg).
    RelayDial(ConnectId),
    /// Simultaneous-open dial of a DCUtR observed address.
    PunchDial(ConnectId),
    /// HOP stream open on the relay; the peer is kept so a result arriving
    /// after the attempt ended can still be cleaned up.
    OpenHop(ConnectId, PeerId),
    /// Dial of an AutoNAT server for a reachability probe.
    ProbeDial,
    /// AutoNAT probe stream open.
    OpenProbe(PeerId),
    /// Dial of the relay for a reservation.
    ReserveDial,
    /// HOP RESERVE stream open.
    OpenReserve(PeerId),
    /// Responder-side simultaneous-open dial of an initiator's observed
    /// address. Results are ignored; the punch window governs.
    InboundPunchDial,
}

impl TokenPurpose {
    fn connect_id(&self) -> Option<ConnectId> {
        match self {
            Self::DirectDial(id)
            | Self::RelayDial(id)
            | Self::PunchDial(id)
            | Self::OpenHop(id, _) => Some(*id),
            _ => None,
        }
    }
}

/// A stream-scoped input extracted from a [`SwarmEvent`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum StreamInput<'a> {
    Ready,
    Data(&'a [u8]),
    RemoteWriteClosed,
    Closed,
}

/// State shared between the agent shell and its attempt state machines.
pub(crate) struct Shared {
    pub(crate) local_peer_id: PeerId,
    pub(crate) config: NatConfig,
    pub(crate) actions: VecDeque<NatAction>,
    pub(crate) events: VecDeque<NatEvent>,
    /// Streams the agent currently owns, per peer. Peer-scoped because
    /// stream ids are only unique within one connection.
    pub(crate) registry: BTreeMap<PeerId, BTreeMap<StreamId, StreamRole>>,
    pub(crate) tokens: BTreeMap<NatToken, TokenPurpose>,
    next_token: u64,
    /// Peers with an established (identity-verified) connection. A QUIC
    /// supersede re-emits `ConnectionEstablished` and the retired connection
    /// emits no `ConnectionClosed`, so set semantics absorb both.
    pub(crate) connected: BTreeSet<PeerId>,
    /// Peers that reached `PeerReady`, with their advertised protocols.
    pub(crate) ready: BTreeMap<PeerId, Vec<String>>,
    /// Bridges released to the application but still participating in a
    /// direct-upgrade race. Data on these streams belongs to the app; only a
    /// terminal close is routed back to the owning attempt.
    released_bridges: BTreeMap<PeerId, BTreeMap<StreamId, ConnectId>>,
    /// Our validated external/listen addresses, advertised in DCUtR CONNECT.
    pub(crate) listen_addrs: Vec<Multiaddr>,
}

impl Shared {
    pub(crate) fn alloc_token(&mut self, purpose: TokenPurpose) -> NatToken {
        let token = NatToken(self.next_token);
        self.next_token += 1;
        self.tokens.insert(token, purpose);
        token
    }

    pub(crate) fn push_action(&mut self, action: NatAction) {
        self.actions.push_back(action);
    }

    pub(crate) fn push_event(&mut self, event: NatEvent) {
        self.events.push_back(event);
    }

    /// Registers `stream` (on `peer`'s connection) as agent-owned.
    pub(crate) fn own_stream(&mut self, peer: &PeerId, stream: StreamId, role: StreamRole) {
        self.registry
            .entry(peer.clone())
            .or_default()
            .insert(stream, role);
    }

    /// Releases `stream` back to the application (or forgets it entirely).
    pub(crate) fn release_stream(&mut self, peer: &PeerId, stream: StreamId) {
        if let Some(streams) = self.registry.get_mut(peer) {
            streams.remove(&stream);
            if streams.is_empty() {
                self.registry.remove(peer);
            }
        }
    }

    pub(crate) fn track_released_bridge(
        &mut self,
        peer: &PeerId,
        stream: StreamId,
        attempt: ConnectId,
    ) {
        self.released_bridges
            .entry(peer.clone())
            .or_default()
            .insert(stream, attempt);
    }

    pub(crate) fn take_released_bridge(
        &mut self,
        peer: &PeerId,
        stream: StreamId,
    ) -> Option<ConnectId> {
        let attempt = self
            .released_bridges
            .get_mut(peer)
            .and_then(|streams| streams.remove(&stream));
        if self
            .released_bridges
            .get(peer)
            .is_some_and(BTreeMap::is_empty)
        {
            self.released_bridges.remove(peer);
        }
        attempt
    }

    pub(crate) fn forget_released_bridge(&mut self, peer: &PeerId, stream: StreamId) {
        let _ = self.take_released_bridge(peer, stream);
    }
}

/// Sans-I/O NAT-traversal orchestrator.
///
/// Inputs arrive through [`handle_event`](Self::handle_event) (swarm events,
/// by reference), [`handle_tick`](Self::handle_tick) (time), and the
/// synchronous driver echoes [`dial_result`](Self::dial_result) /
/// [`stream_open_result`](Self::stream_open_result). Outputs drain through
/// [`poll_action`](Self::poll_action) and [`poll_event`](Self::poll_event);
/// drain both until `None` after every input, then sleep at most
/// [`next_timeout`](Self::next_timeout) before the next tick.
///
/// The driver must route stream events the agent owns
/// ([`owns_stream`](Self::owns_stream)) into the agent *only* — application
/// code must not see them — and forward everything else untouched.
pub struct NatAgent {
    shared: Shared,
    attempts: BTreeMap<ConnectId, ConnectAttempt>,
    housekeeping: Housekeeping,
    inbound: BTreeMap<u64, InboundCircuit>,
    next_connect_id: u64,
    next_inbound_id: u64,
}

impl NatAgent {
    /// Creates an agent for the node identified by `local_peer_id`.
    pub fn new(local_peer_id: PeerId, config: NatConfig) -> Self {
        let housekeeping = Housekeeping::new(&config);
        Self {
            shared: Shared {
                local_peer_id,
                config,
                actions: VecDeque::new(),
                events: VecDeque::new(),
                registry: BTreeMap::new(),
                tokens: BTreeMap::new(),
                next_token: 0,
                connected: BTreeSet::new(),
                ready: BTreeMap::new(),
                released_bridges: BTreeMap::new(),
                listen_addrs: Vec::new(),
            },
            attempts: BTreeMap::new(),
            housekeeping,
            inbound: BTreeMap::new(),
            next_connect_id: 0,
            next_inbound_id: 0,
        }
    }

    /// The local peer id the agent was constructed with.
    pub fn local_peer_id(&self) -> &PeerId {
        &self.shared.local_peer_id
    }

    /// Starts a connect attempt toward `peer`.
    ///
    /// `direct_addrs` are candidate transport addresses for the peer (from
    /// discovery, config, or out-of-band exchange); they are validated and
    /// deduplicated with the same policy as
    /// [`minip2p_core::select_direct_candidates`]. The relay leg uses the
    /// first configured relay in [`NatConfig::relays`].
    pub fn connect(&mut self, peer: PeerId, direct_addrs: Vec<Multiaddr>, now: Now) -> ConnectId {
        let id = ConnectId(self.next_connect_id);
        self.next_connect_id += 1;
        // A connection that is already identity-verified is the best path
        // available. Do not manufacture a new race which can only waste
        // work (and, with no candidates or relay, falsely report failure).
        if self.shared.connected.contains(&peer) {
            self.shared.push_event(NatEvent::PathEstablished {
                connect_id: id,
                peer,
                path: crate::types::Path::DirectDialed,
            });
            return id;
        }
        if let Some(attempt) = ConnectAttempt::start(id, peer, direct_addrs, &mut self.shared, now)
        {
            self.attempts.insert(id, attempt);
        }
        id
    }

    /// Abandons a connect attempt, resetting any streams it holds. No
    /// further events are emitted for `id`.
    pub fn cancel(&mut self, id: ConnectId, _now: Now) {
        if let Some(mut attempt) = self.attempts.remove(&id) {
            attempt.cancel(&mut self.shared);
        }
    }

    /// Updates the validated addresses advertised during DCUtR exchanges.
    pub fn set_listen_addrs(&mut self, addrs: &[Multiaddr]) {
        self.shared.listen_addrs = addrs.to_vec();
    }

    /// Feeds one swarm event. Events for streams the agent does not own are
    /// ignored with a single map lookup and zero clones.
    pub fn handle_event(&mut self, event: &SwarmEvent, now: Now) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id } => {
                self.shared.connected.insert(peer_id.clone());
                for attempt in self.attempts.values_mut() {
                    attempt.on_peer_connected(peer_id, &mut self.shared, now);
                }
                for circuit in self.inbound.values_mut() {
                    circuit.on_peer_connected(peer_id, &mut self.shared, now);
                }
            }
            SwarmEvent::ConnectionClosed { peer_id } => {
                self.shared.connected.remove(peer_id);
                self.shared.ready.remove(peer_id);
                for attempt in self.attempts.values_mut() {
                    attempt.on_peer_disconnected(peer_id, &mut self.shared, now);
                }
                self.housekeeping
                    .on_peer_disconnected(peer_id, &mut self.shared, now);
                for circuit in self.inbound.values_mut() {
                    circuit.on_relay_disconnected(peer_id, &mut self.shared);
                }
                // Streams on the closed connection are gone; drop any the
                // attempts have not already cleaned up.
                self.shared.registry.remove(peer_id);
                self.shared.released_bridges.remove(peer_id);
            }
            SwarmEvent::PeerReady { peer_id, protocols } => {
                self.shared.ready.insert(peer_id.clone(), protocols.clone());
                for attempt in self.attempts.values_mut() {
                    attempt.on_peer_ready(peer_id, protocols, &mut self.shared, now);
                }
                self.housekeeping
                    .on_peer_ready(peer_id, protocols, &mut self.shared, now);
            }
            SwarmEvent::StreamReady {
                peer_id,
                stream_id,
                protocol_id,
                initiated_locally,
            } => {
                if !initiated_locally && protocol_id == STOP_PROTOCOL_ID {
                    // STOP is a relay control protocol, but registration of
                    // its id makes it possible for any connected peer to
                    // negotiate it. Only relays explicitly configured by
                    // the application are trusted to request an inbound
                    // circuit; otherwise a peer could make us punch its
                    // chosen addresses.
                    if !self
                        .shared
                        .config
                        .relays
                        .iter()
                        .any(|relay| relay.peer_id() == peer_id)
                    {
                        return;
                    }
                    // A relay is bridging an inbound circuit to us: claim
                    // the stream and run the responder flow on it.
                    let id = self.next_inbound_id;
                    self.next_inbound_id += 1;
                    self.shared
                        .own_stream(peer_id, *stream_id, StreamRole::StopInbound(id));
                    self.inbound.insert(
                        id,
                        InboundCircuit::new(peer_id.clone(), *stream_id, &self.shared, now),
                    );
                } else {
                    self.route_stream(peer_id, *stream_id, StreamInput::Ready, now);
                }
            }
            SwarmEvent::StreamData {
                peer_id,
                stream_id,
                data,
            } => {
                self.route_stream(peer_id, *stream_id, StreamInput::Data(data), now);
            }
            SwarmEvent::StreamRemoteWriteClosed { peer_id, stream_id } => {
                self.route_stream(peer_id, *stream_id, StreamInput::RemoteWriteClosed, now);
            }
            SwarmEvent::StreamClosed { peer_id, stream_id } => {
                if let Some(id) = self.shared.take_released_bridge(peer_id, *stream_id) {
                    if let Some(attempt) = self.attempts.get_mut(&id) {
                        attempt.on_released_bridge_closed(*stream_id, &mut self.shared, now);
                    }
                } else {
                    self.route_stream(peer_id, *stream_id, StreamInput::Closed, now);
                }
                self.shared.release_stream(peer_id, *stream_id);
            }
            _ => {}
        }
        self.reap_done();
    }

    /// Advances time-based state: stagger expiry, leg deadlines, punch
    /// windows, connect deadlines.
    pub fn handle_tick(&mut self, now: Now) {
        for attempt in self.attempts.values_mut() {
            attempt.on_tick(&mut self.shared, now);
        }
        self.housekeeping.on_tick(&mut self.shared, now);
        for circuit in self.inbound.values_mut() {
            circuit.on_tick(&mut self.shared, now);
        }
        self.reap_done();
    }

    /// Reports the result of a [`NatAction::Dial`] the driver executed.
    pub fn dial_result(&mut self, token: NatToken, result: Result<ConnectionId, String>, now: Now) {
        let Some(purpose) = self.shared.tokens.remove(&token) else {
            return;
        };
        match &purpose {
            TokenPurpose::ProbeDial => {
                self.housekeeping
                    .on_probe_dial_result(&result, &mut self.shared, now);
            }
            TokenPurpose::ReserveDial => {
                self.housekeeping
                    .on_reserve_dial_result(&result, &mut self.shared, now);
            }
            _ => {
                if let Some(id) = purpose.connect_id()
                    && let Some(attempt) = self.attempts.get_mut(&id)
                {
                    attempt.on_dial_result(&purpose, result, &mut self.shared, now);
                }
            }
        }
        self.reap_done();
    }

    /// Reports the result of a [`NatAction::OpenStream`] the driver executed.
    pub fn stream_open_result(
        &mut self,
        token: NatToken,
        result: Result<StreamId, String>,
        now: Now,
    ) {
        let Some(purpose) = self.shared.tokens.remove(&token) else {
            return;
        };
        match purpose {
            TokenPurpose::OpenHop(id, relay_peer) => match self.attempts.get_mut(&id) {
                Some(attempt) => {
                    attempt.on_stream_open_result(result, &mut self.shared, now);
                    self.reap_done();
                }
                None => {
                    // The attempt ended (won, failed, or was cancelled) while
                    // the open was in flight; don't leak the stream.
                    if let Ok(stream_id) = result {
                        self.shared.push_action(NatAction::ResetStream {
                            peer: relay_peer,
                            stream_id,
                        });
                    }
                }
            },
            TokenPurpose::OpenProbe(server_peer) => {
                self.housekeeping
                    .on_probe_open_result(&server_peer, result, &mut self.shared, now);
            }
            TokenPurpose::OpenReserve(relay_peer) => {
                self.housekeeping.on_reserve_open_result(
                    &relay_peer,
                    result,
                    &mut self.shared,
                    now,
                );
            }
            _ => {}
        }
    }

    /// Returns the next queued command for the driver.
    pub fn poll_action(&mut self) -> Option<NatAction> {
        self.shared.actions.pop_front()
    }

    /// Returns the next application-visible event.
    pub fn poll_event(&mut self) -> Option<NatEvent> {
        self.shared.events.pop_front()
    }

    /// Milliseconds until the earliest pending deadline, if any. Drivers
    /// fold this into their poll budget, mirroring `SwarmCore::next_timeout`.
    pub fn next_timeout(&self, now_ms: u64) -> Option<u64> {
        self.attempts
            .values()
            .filter_map(ConnectAttempt::next_deadline)
            .chain(self.housekeeping.next_deadline())
            .chain(
                self.inbound
                    .values()
                    .filter_map(InboundCircuit::next_deadline),
            )
            .min()
            .map(|due| due.saturating_sub(now_ms))
    }

    /// Returns `true` if `stream_id` on `peer`'s connection currently
    /// belongs to the agent. The driver uses this to decide whether to
    /// consume or forward a stream event.
    pub fn owns_stream(&self, peer: &PeerId, stream_id: StreamId) -> bool {
        self.shared
            .registry
            .get(peer)
            .is_some_and(|streams| streams.contains_key(&stream_id))
    }

    /// Our current reachability verdict: majority-of-N confidence over the
    /// last M probe results, so it never flips on a single probe.
    pub fn reachability(&self) -> ReachabilityState {
        self.housekeeping.reachability()
    }

    /// The relay reservation currently held, if any.
    pub fn active_reservation(&self) -> Option<&ReservationInfo> {
        self.housekeeping.active_reservation()
    }

    /// Returns `true` when the agent has no queued outputs and no work in
    /// flight (a settled reservation or a scheduled future probe is not
    /// "work").
    pub fn is_idle(&self) -> bool {
        self.shared.actions.is_empty()
            && self.shared.events.is_empty()
            && self.attempts.is_empty()
            && self.inbound.is_empty()
            && self.housekeeping.is_quiet()
    }

    fn route_stream(&mut self, peer: &PeerId, stream: StreamId, input: StreamInput<'_>, now: Now) {
        // Guardrail: streams we don't own are none of our business.
        let Some(streams) = self.shared.registry.get(peer) else {
            return;
        };
        let Some(role) = streams.get(&stream).copied() else {
            return;
        };
        match role {
            StreamRole::HopConnect(id) => {
                if let Some(attempt) = self.attempts.get_mut(&id) {
                    attempt.on_stream_input(stream, input, &mut self.shared, now);
                }
            }
            StreamRole::HopReserve | StreamRole::AutonatProbe => {
                self.housekeeping
                    .on_stream_input(role, stream, input, &mut self.shared, now);
            }
            StreamRole::StopInbound(id) => {
                if let Some(circuit) = self.inbound.get_mut(&id) {
                    circuit.on_stream_input(stream, input, &mut self.shared, now);
                }
            }
        }
    }

    fn reap_done(&mut self) {
        self.attempts.retain(|_, attempt| !attempt.is_done());
        self.inbound.retain(|_, circuit| !circuit.is_done());
    }
}
