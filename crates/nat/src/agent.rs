use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::{Multiaddr, PeerAddr, PeerId, select_direct_candidates};
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
    /// Inbound STOP stream from an untrusted peer. Kept owned until terminal
    /// close so its reset lifecycle cannot leak into the application.
    RejectedStop,
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
    /// Our transport address as observed by trusted reporters (Identify's
    /// `observedAddr` from configured relays and AutoNAT servers). Behind a
    /// NAT this is the public mapping of our QUIC socket — the address that
    /// makes cross-NAT hole punching possible. Entries are dropped when the
    /// reporting peer disconnects, which keeps the map bounded by the
    /// configured-peer count.
    observed_addrs: BTreeMap<PeerId, Multiaddr>,
    /// Session dials in flight: relay-leg, reservation, and probe dials whose
    /// connection has not yet established. Concurrent machines targeting the
    /// same infrastructure peer wait on the first dial instead of issuing
    /// their own — a second connection to the same peer supersedes the first,
    /// and the supersede scrubs the winner's streams. Values carry the dialed
    /// peer and an expiry (`mono_ms`) so a handshake that never completes
    /// cannot suppress dialing forever.
    pending_session_dials: BTreeMap<NatToken, (PeerId, u64)>,
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

    /// Issues a session dial: allocates the token, records the in-flight
    /// entry consulted by [`Shared::session_dial_pending`], and pushes the
    /// `Dial` action. Punch dials must not go through here — simultaneous
    /// open intentionally dials a peer that is about to be connected.
    ///
    /// `deadline_ms` is the owning machine's flight deadline for this dial.
    /// The entry must stay visible for as long as the owner is still
    /// legitimately waiting — expiring earlier re-opens the duplicate-dial
    /// window this map exists to close.
    pub(crate) fn push_session_dial(
        &mut self,
        purpose: TokenPurpose,
        addr: PeerAddr,
        now: Now,
        deadline_ms: u64,
    ) {
        // Expired entries only accumulate when handshakes silently die;
        // prune them here so the map stays bounded without a timer.
        self.pending_session_dials
            .retain(|_, (_, expires)| *expires > now.mono_ms);
        let token = self.alloc_token(purpose);
        let expires = now.mono_ms + deadline_ms;
        self.pending_session_dials
            .insert(token, (addr.peer_id().clone(), expires));
        self.push_action(NatAction::Dial { token, addr });
    }

    /// Whether a session dial toward `peer` is still in flight (issued, not
    /// yet established, expiry not passed).
    pub(crate) fn session_dial_pending(&self, peer: &PeerId, now: Now) -> bool {
        self.pending_session_dials
            .values()
            .any(|(dialed, expires)| dialed == peer && *expires > now.mono_ms)
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

    /// Records `reporter`'s Identify claim of our transport address.
    ///
    /// Punch candidates are advertised to third parties, who dial them and
    /// blast random UDP at them during a punch — so only operator-configured
    /// peers (relays and AutoNAT servers) are believed. An arbitrary
    /// connected peer must not be able to plant an attacker-chosen address
    /// here; observed addresses are never dial-back verified the way AutoNAT
    /// addresses are.
    fn record_observed_addr(&mut self, reporter: &PeerId, observed: Option<&[u8]>) {
        let trusted = self
            .config
            .relays
            .iter()
            .chain(self.config.autonat_servers.iter())
            .any(|peer| peer.peer_id() == reporter);
        if !trusted {
            return;
        }
        let Some(Ok(addr)) = observed.map(Multiaddr::from_bytes) else {
            return;
        };
        let validated = select_direct_candidates(&[], Some(addr), None);
        if let Some(addr) = validated.into_addrs().pop() {
            self.observed_addrs.insert(reporter.clone(), addr);
        }
    }

    /// Addresses advertised in DCUtR exchanges: the validated listen/external
    /// set plus our peer-observed public mappings, deduplicated.
    pub(crate) fn punch_candidates(&self) -> Vec<Multiaddr> {
        let mut addrs = self.listen_addrs.clone();
        for addr in self.observed_addrs.values() {
            if !addrs.contains(addr) {
                addrs.push(addr.clone());
            }
        }
        addrs
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
                observed_addrs: BTreeMap::new(),
                pending_session_dials: BTreeMap::new(),
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
        let _ = self.handle_event_with_disposition(event, now);
    }

    /// Feeds one swarm event and reports whether it belongs to the NAT
    /// control plane even when the event did not leave a stream registered.
    /// Drivers use this to consume rejected inbound control streams.
    pub fn handle_event_with_disposition(&mut self, event: &SwarmEvent, now: Now) -> bool {
        let mut handled = false;
        let mut touched_state = false;
        match event {
            SwarmEvent::ConnectionEstablished { peer_id } => {
                touched_state = true;
                // Any session dial toward this peer has done its job (ours
                // landed, or another machine's did — either way the peer is
                // reachable now and further dials would supersede).
                self.shared
                    .pending_session_dials
                    .retain(|_, (dialed, _)| dialed != peer_id);
                let superseded = !self.shared.connected.insert(peer_id.clone());
                if superseded {
                    // The swarm's last-connection-wins policy emits a second
                    // establishment without closing the retired connection.
                    // Stream ids are peer-scoped here, so scrub them before
                    // any event from the replacement connection can collide.
                    self.shared.ready.remove(peer_id);
                    self.shared.registry.remove(peer_id);
                    self.shared.released_bridges.remove(peer_id);
                    self.shared.tokens.retain(|_, purpose| {
                        !matches!(
                            purpose,
                            TokenPurpose::OpenHop(_, peer)
                                | TokenPurpose::OpenProbe(peer)
                                | TokenPurpose::OpenReserve(peer)
                                if peer == peer_id
                        )
                    });
                    for attempt in self.attempts.values_mut() {
                        attempt.on_peer_superseded(peer_id, &mut self.shared, now);
                    }
                    self.housekeeping
                        .on_peer_superseded(peer_id, &mut self.shared, now);
                    for circuit in self.inbound.values_mut() {
                        circuit.on_relay_disconnected(peer_id, &mut self.shared);
                    }
                }
                for attempt in self.attempts.values_mut() {
                    attempt.on_peer_connected(peer_id, &mut self.shared, now);
                }
                for circuit in self.inbound.values_mut() {
                    circuit.on_peer_connected(peer_id, &mut self.shared, now);
                }
            }
            SwarmEvent::ConnectionClosed { peer_id } => {
                touched_state = true;
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
                self.shared.observed_addrs.remove(peer_id);
                self.shared
                    .pending_session_dials
                    .retain(|_, (dialed, _)| dialed != peer_id);
            }
            SwarmEvent::IdentifyReceived { peer_id, info } => {
                // The remote reports the transport address it sees us from.
                // Behind a NAT that is our public mapping — the only usable
                // DCUtR punch candidate, since bound addresses are private.
                // The event stays application-visible (`handled` = false),
                // and nothing here can complete a machine (`touched_state`
                // stays false).
                self.shared
                    .record_observed_addr(peer_id, info.observed_addr.as_deref());
            }
            SwarmEvent::PeerReady { peer_id, protocols } => {
                touched_state = true;
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
                        // STOP is registered only for the NAT control plane.
                        // Reject untrusted opens here instead of leaking them
                        // to the application and leaving their stream credit
                        // occupied until the remote closes them.
                        self.shared.push_action(NatAction::ResetStream {
                            peer: peer_id.clone(),
                            stream_id: *stream_id,
                        });
                        self.shared
                            .own_stream(peer_id, *stream_id, StreamRole::RejectedStop);
                        handled = true;
                    } else {
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
                        handled = true;
                    }
                } else {
                    handled = self.route_stream(peer_id, *stream_id, StreamInput::Ready, now);
                }
                touched_state = handled;
            }
            SwarmEvent::StreamData {
                peer_id,
                stream_id,
                data,
            } => {
                handled = self.route_stream(peer_id, *stream_id, StreamInput::Data(data), now);
                touched_state = handled;
            }
            SwarmEvent::StreamRemoteWriteClosed { peer_id, stream_id } => {
                handled =
                    self.route_stream(peer_id, *stream_id, StreamInput::RemoteWriteClosed, now);
                touched_state = handled;
            }
            SwarmEvent::StreamClosed { peer_id, stream_id } => {
                if let Some(id) = self.shared.take_released_bridge(peer_id, *stream_id) {
                    handled = true;
                    if let Some(attempt) = self.attempts.get_mut(&id) {
                        attempt.on_released_bridge_closed(*stream_id, &mut self.shared, now);
                    }
                } else {
                    handled = self.route_stream(peer_id, *stream_id, StreamInput::Closed, now);
                    if handled {
                        self.shared.release_stream(peer_id, *stream_id);
                    }
                }
                touched_state = handled;
            }
            _ => {}
        }
        // Foreign application stream events stop after their single registry
        // lookup. Only state that actually visited a NAT machine can make an
        // attempt or inbound circuit reapable.
        if touched_state {
            self.reap_done();
        }
        handled
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
        if result.is_err()
            && let Some((peer, _)) = self.shared.pending_session_dials.remove(&token)
        {
            // A rejected session dial is no longer in flight. Attempts that
            // were sharing it must issue their own dial now: nothing else
            // re-enters a waiting relay leg, so they would otherwise burn
            // their leg deadline on a dial that already failed. The owner
            // learns through its own routing below, and housekeeping
            // waiters fall back to their acquire/probe deadlines.
            let owner = purpose.connect_id();
            for (id, attempt) in self.attempts.iter_mut() {
                if owner.as_ref() != Some(id) {
                    attempt.on_session_dial_failed(&peer, &mut self.shared, now);
                }
            }
        }
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

    fn route_stream(
        &mut self,
        peer: &PeerId,
        stream: StreamId,
        input: StreamInput<'_>,
        now: Now,
    ) -> bool {
        // Guardrail: streams we don't own are none of our business.
        let Some(streams) = self.shared.registry.get(peer) else {
            return false;
        };
        let Some(role) = streams.get(&stream).copied() else {
            return false;
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
            StreamRole::RejectedStop => {}
        }
        true
    }

    fn reap_done(&mut self) {
        self.attempts.retain(|_, attempt| !attempt.is_done());
        self.inbound.retain(|_, circuit| !circuit.is_done());
    }
}
