//! Caller-driven NAT capability shared by standard and portable Endpoints.
//! Time and entropy are supplied by the host; I/O runs through SwarmRuntime.

use alloc::{
    collections::{BTreeMap, VecDeque},
    string::ToString,
    vec,
    vec::Vec,
};
use minip2p_platform::{EntropySource, Now as PlatformNow};

#[cfg(feature = "_circuit-driver")]
use minip2p_circuit::{AdoptError, BridgeAdoption, CircuitRole, CircuitTransport};
use minip2p_core::{ConnectId, Multiaddr, PeerId, Protocol, select_direct_addrs};
#[cfg(feature = "_circuit-driver")]
use minip2p_nat::BridgeRole;
use minip2p_nat::{
    ConnectLegs, NatAction, NatAgent, NatEvent, Now, Path, PromoteError, ReachabilityState,
};
use minip2p_swarm::{SwarmEvent, SwarmRuntime};
use minip2p_transport::{ConnectionId, StreamId, Transport};

use crate::EndpointEvent;
use crate::portable::connect::ConnectEngine;

/// Whether `path` still describes a live connection: the peer's
/// established `connections` include one of the path's kind (a circuit for
/// [`Path::Relayed`], a direct connection otherwise). A stale path is
/// dropped rather than rewritten to the kind that remains, whose origin
/// (relay, dialed or punched) is unknown.
pub(crate) fn path_is_live(
    path: &Path,
    mut connections: impl Iterator<Item = ConnectionId>,
) -> bool {
    let relayed = matches!(path, Path::Relayed { .. });
    connections.any(|id| id.is_circuit() == relayed)
}

/// Converts a host time sample into the agent's clock pair.
pub(crate) fn to_nat_now(now: PlatformNow) -> Now {
    Now {
        mono_ms: now.monotonic_ms,
        unix_secs: now.unix_seconds,
    }
}

/// `ConnectFailed` and `FellBackToRelay` are attempt terminals the
/// Connection-attempt engine already reports as `ConnectSettled`, so they
/// are not repeated to the application.
fn nat_event_reaches_application(event: &NatEvent) -> bool {
    !matches!(
        event,
        NatEvent::ConnectFailed { .. } | NatEvent::FellBackToRelay { .. }
    )
}

/// Drives a [`NatAgent`] against the endpoint's swarm.
pub(crate) struct NatDriver<E> {
    agent: NatAgent,
    /// NAT events awaiting the Endpoint event stream; the endpoint moves
    /// them out once the Connection-attempt engine has observed them.
    events: VecDeque<NatEvent>,
    entropy: E,
    addresses_changed: bool,
    /// Relays we hold a reservation on, for circuit-address advertising.
    reserved_relays: Vec<(PeerId, Multiaddr)>,
    /// Relay transport addresses by peer, captured at construction.
    relay_addrs: Vec<(PeerId, Multiaddr)>,
    /// Direct public addresses confirmed by AutoNAT.
    public_addrs: Vec<Multiaddr>,
    /// Exact adopted bridge keys mapped to their promoted circuit ids.
    promoted: BTreeMap<(ConnectionId, StreamId), ConnectionId>,
    /// Authoritative usable NAT-orchestrated path by remote peer; swept by
    /// [`path_is_live`] once its connection closes.
    paths: BTreeMap<PeerId, Path>,
    /// How many queued events the Connection engine has already observed.
    observed: usize,
    /// The bound-address revision the agent's `listen_addrs` were seeded
    /// from; callers can bind through any swarm path between driver turns.
    listen_addrs_revision: u64,
    #[cfg(all(test, feature = "nat", feature = "quic"))]
    pub(crate) bridge_reset_attempts: Vec<(ConnectionId, StreamId)>,
}

impl<E: EntropySource> NatDriver<E> {
    /// Creates a driver over `agent`. `relay_addrs` are the transport
    /// addresses of configured relays, retained so reservations can be
    /// advertised as circuit addresses.
    pub(crate) fn new(agent: NatAgent, relay_addrs: Vec<(PeerId, Multiaddr)>, entropy: E) -> Self {
        Self {
            agent,
            events: VecDeque::new(),
            entropy,
            addresses_changed: false,
            reserved_relays: Vec::new(),
            relay_addrs,
            public_addrs: Vec::new(),
            promoted: BTreeMap::new(),
            paths: BTreeMap::new(),
            observed: 0,
            // Matches a fresh runtime: seed only after a real `listen*`
            // call bumped the revision. Some transports report bound-but-
            // not-listening sockets from `local_addresses`, so syncing on
            // an untouched revision would advertise a dial-back address
            // that drops packets.
            listen_addrs_revision: 0,
            #[cfg(all(test, feature = "nat", feature = "quic"))]
            bridge_reset_attempts: Vec::new(),
        }
    }

    /// Cancels a pending connect's NAT leg; settled or unknown ids are a
    /// no-op.
    pub(crate) fn cancel(&mut self, id: ConnectId, now: PlatformNow) {
        self.agent.cancel(id, to_nat_now(now));
    }

    /// Cancels `id` in the Connection-attempt engine and, while the attempt
    /// is still pending, its NAT leg. Returns `true` when the leg was
    /// cancelled and the caller must `pump` the queued actions; pumping
    /// needs the composition's concrete [`NatTransport`], so it stays at
    /// the call site.
    ///
    /// The pending check runs before the engine cancel: `ConnectEngine`
    /// forgets the attempt once it settles, but the agent would still close
    /// a provisional relayed path the engine already settled on.
    pub(crate) fn cancel_leg<T: Transport, R: EntropySource>(
        &mut self,
        connect: &mut ConnectEngine,
        id: ConnectId,
        swarm: &mut SwarmRuntime<T, R>,
        now: PlatformNow,
    ) -> bool {
        let pending = connect.is_pending(id);
        connect.cancel(id, swarm);
        if pending {
            self.cancel(id, now);
        }
        pending
    }

    /// Registers a pending connect with the agent and immediately executes
    /// any resulting actions, so dial legs leave in the same driver turn.
    pub(crate) fn connect<T: NatTransport, R: EntropySource>(
        &mut self,
        id: ConnectId,
        peer: PeerId,
        legs: ConnectLegs,
        swarm: &mut SwarmRuntime<T, R>,
        sample: PlatformNow,
    ) {
        self.agent.connect(id, peer, legs, to_nat_now(sample));
        self.pump(swarm, sample);
    }

    /// How long the caller may idle before [`NatDriver::tick`] has work: `0`
    /// when queued events or agent timers are due, `None` when nothing is.
    pub(crate) fn next_timeout(&self, now: PlatformNow) -> Option<u64> {
        if !self.events.is_empty() {
            Some(0)
        } else {
            self.agent.next_timeout(now.monotonic_ms)
        }
    }

    /// Returns the current AutoNAT reachability verdict.
    pub(crate) fn reachability(&self) -> ReachabilityState {
        self.agent.reachability()
    }

    /// Returns the currently held relay reservation, when any.
    #[cfg(feature = "_circuit-driver")]
    pub(crate) fn active_reservation(&self) -> Option<&minip2p_nat::ReservationInfo> {
        self.agent.active_reservation()
    }

    /// Returns the advertised address set if it changed since the last call,
    /// for hosts that push it into the swarm once per poll.
    #[cfg(feature = "portable-autonat")]
    pub(crate) fn take_address_change(&mut self) -> Option<Vec<Multiaddr>> {
        if !core::mem::take(&mut self.addresses_changed) {
            return None;
        }
        Some(self.advertised_addrs())
    }

    /// Re-seeds the agent's advertised listen addresses when the listened
    /// set moved since the last driver turn. Revision-checked, so an
    /// unchanged set costs one integer compare and no transport read. Uses
    /// the runtime's recorded listen results rather than bound addresses —
    /// a transport can report sockets it never listened on.
    fn sync_listen_addrs<T: NatTransport, R: EntropySource>(&mut self, swarm: &SwarmRuntime<T, R>) {
        let revision = swarm.listened_addrs_revision();
        if revision == self.listen_addrs_revision {
            return;
        }
        self.agent
            .set_listen_addrs(&select_direct_addrs(swarm.listened_addrs(), None, None));
        self.listen_addrs_revision = revision;
    }

    /// Feeds one swarm event to the agent and executes its cascade.
    ///
    /// Returns `true` when the event belongs to the NAT control plane and
    /// must not be forwarded to the application. The agent's disposition is
    /// authoritative even when handling claims or releases the stream.
    pub(crate) fn ingest<T: NatTransport, R: EntropySource>(
        &mut self,
        event: &SwarmEvent,
        swarm: &mut SwarmRuntime<T, R>,
        sample: PlatformNow,
    ) -> bool {
        self.sync_listen_addrs(swarm);
        let now = to_nat_now(sample);
        if self.inject_straggler(event, swarm) {
            self.pump(swarm, sample);
            return true;
        }
        let is_circuit = match event {
            SwarmEvent::ConnectionEstablished { conn_id, .. }
            | SwarmEvent::ConnectionClosed { conn_id, .. } => conn_id.is_circuit(),
            _ => false,
        };
        let handled = self
            .agent
            .handle_event_with_disposition_classified(event, is_circuit, now);
        if let SwarmEvent::ConnectionClosed { conn_id, .. } = event {
            for &(inner_conn, stream_id) in self
                .promoted
                .keys()
                .filter(|(inner_conn, _)| inner_conn == conn_id)
            {
                swarm
                    .transport_mut()
                    .inject_bridge_closed(inner_conn, stream_id);
            }
            self.promoted
                .retain(|(inner_conn, _), circuit| inner_conn != conn_id && circuit != conn_id);
        }
        self.pump(swarm, sample);
        handled
    }

    /// Advances timers only when the agent reports a due deadline, then
    /// executes any resulting work.
    pub(crate) fn tick<T: NatTransport, R: EntropySource>(
        &mut self,
        swarm: &mut SwarmRuntime<T, R>,
        sample: PlatformNow,
    ) {
        // A fresh listen must seed even when the agent has no due work —
        // the seed is what arms the probe timers that would otherwise
        // keep this tick early-returning forever.
        self.sync_listen_addrs(swarm);
        let now = to_nat_now(sample);
        if self.agent.next_timeout(now.mono_ms) != Some(0) {
            return;
        }
        self.agent.handle_tick(now);
        self.pump(swarm, sample);
    }

    /// Drains agent actions into swarm calls (echoing synchronous results
    /// back) and collects application-visible NAT events.
    pub(crate) fn pump<T: NatTransport, R: EntropySource>(
        &mut self,
        swarm: &mut SwarmRuntime<T, R>,
        sample: PlatformNow,
    ) {
        self.sync_listen_addrs(swarm);
        loop {
            let mut progressed = false;
            while let Some(action) = self.agent.poll_action() {
                progressed = true;
                self.execute(action, swarm, sample);
            }
            while let Some(event) = self.agent.poll_event() {
                progressed = true;
                self.observe(&event);
                self.events.push_back(event);
            }
            if !progressed {
                break;
            }
        }
        // Sweeps promotions whose circuit vanished without a lifecycle
        // event. Runs per pump rather than per host poll — closures surface
        // through `ingest`'s ConnectionClosed branch regardless.
        self.promoted
            .retain(|_, id| swarm.transport().contains_circuit(*id));
        // Sweeps paths whose connection is gone. Per pump, not per
        // ConnectionClosed: a non-primary connection closes without one.
        // Groups connections by peer in one pass to stay linear.
        if !self.paths.is_empty() {
            let mut by_peer: BTreeMap<&PeerId, Vec<ConnectionId>> = BTreeMap::new();
            for (conn_id, peer) in swarm.established_connections() {
                by_peer.entry(peer).or_default().push(conn_id);
            }
            self.paths.retain(|peer, path| {
                path_is_live(path, by_peer.get(peer).into_iter().flatten().copied())
            });
        }
    }

    /// Queued events the Connection-attempt engine has not observed yet.
    pub(crate) fn unobserved_events(&self) -> impl Iterator<Item = &NatEvent> {
        self.events.iter().skip(self.observed)
    }

    /// Attaches the attempt's NAT leg while it is still pending. Compositions
    /// call this right after `admit_connect`; keeping the attach at the call
    /// site lets shared admission stay transport-agnostic while the leg
    /// needs the composition's concrete [`NatTransport`].
    pub(crate) fn attach_leg<T: NatTransport, R: EntropySource>(
        &mut self,
        connect: &ConnectEngine,
        id: ConnectId,
        peer: PeerId,
        allow_relay: bool,
        swarm: &mut SwarmRuntime<T, R>,
        sample: PlatformNow,
    ) {
        if connect.is_pending(id) {
            self.connect(
                id,
                peer,
                ConnectLegs {
                    direct_racing: connect.dialed_direct(id),
                    allow_relay,
                },
                swarm,
                sample,
            );
        }
    }

    /// Applies the work a `DiscoveryDriver` sweep queued: attaches legs for
    /// attempts automatic dialing admitted, then pumps once when a leg was
    /// cancelled. Call it right after the sweep.
    // The only `DiscoveryNatWork` readers; `PendingLeg`'s dead-code `expect`
    // in discovery.rs repeats this condition — keep them in sync.
    #[cfg(any(
        feature = "portable-autonat",
        all(feature = "nat", any(feature = "discovery", feature = "mdns"))
    ))]
    pub(crate) fn apply_sweep_work<T: NatTransport, R: EntropySource>(
        &mut self,
        work: crate::discovery::DiscoveryNatWork,
        connect: &ConnectEngine,
        swarm: &mut SwarmRuntime<T, R>,
        sample: PlatformNow,
    ) {
        for leg in work.legs {
            self.attach_leg(connect, leg.id, leg.peer, leg.allow_relay, swarm, sample);
        }
        if work.pump {
            self.pump(swarm, sample);
        }
    }

    /// Lets the Connection-attempt engine observe NAT output it has not seen
    /// yet, by reference; the events stay queued for the application.
    pub(crate) fn feed_unobserved_to_connect<T: NatTransport, R: EntropySource>(
        &mut self,
        connect: &mut ConnectEngine,
        swarm: &mut SwarmRuntime<T, R>,
        sample: PlatformNow,
    ) {
        let now_ms = sample.monotonic_ms;
        for event in self.unobserved_events() {
            connect.observe_nat(event, swarm, now_ms);
        }
        self.mark_observed();
    }

    /// Cancels the attempt's NAT leg when `event` is a failed or cancelled
    /// Connection-attempt terminal. Connected and unrelated events are a
    /// no-op: a settled provisional path is the leg to keep.
    pub(crate) fn cancel_leg_on_terminal<T: NatTransport, R: EntropySource>(
        &mut self,
        event: &EndpointEvent,
        swarm: &mut SwarmRuntime<T, R>,
        sample: PlatformNow,
    ) {
        let EndpointEvent::ConnectSettled {
            connect_id,
            outcome: crate::ConnectOutcome::Failed(_) | crate::ConnectOutcome::Cancelled,
            ..
        } = event
        else {
            return;
        };
        self.cancel(*connect_id, sample);
        self.pump(swarm, sample);
    }

    /// Marks every currently queued event as seen by the Connection engine.
    pub(crate) fn mark_observed(&mut self) {
        self.observed = self.events.len();
    }

    /// Returns the queued event at `index`, including ones the Connection
    /// engine has not observed yet.
    #[cfg(all(feature = "_nat-driver", feature = "_discovery-driver"))]
    pub(crate) fn event_at(&self, index: usize) -> Option<&NatEvent> {
        self.events.get(index)
    }

    /// Removes the queued event at `index`, keeping the observation cursor
    /// aligned. The discovery sweep uses this to claim attempt events.
    #[cfg(all(feature = "_nat-driver", feature = "_discovery-driver"))]
    pub(crate) fn remove_event(&mut self, index: usize) -> NatEvent {
        let event = self.events.remove(index).expect("queued NAT event");
        self.note_removed(index);
        event
    }

    /// All queued NAT events, observed or not.
    #[cfg(all(debug_assertions, any(feature = "discovery", feature = "mdns")))]
    pub(crate) fn queued_events(&self) -> impl Iterator<Item = &NatEvent> {
        self.events.iter()
    }

    /// Queues an event for the application drain as if the agent emitted it.
    #[cfg(all(test, feature = "nat"))]
    pub(crate) fn push_event(&mut self, event: NatEvent) {
        self.events.push_back(event);
    }

    /// Drains every queued event that reaches the Endpoint event stream,
    /// once the Connection-attempt engine has observed it.
    pub(crate) fn drain_application_events(&mut self) -> impl Iterator<Item = NatEvent> + '_ {
        self.observed = 0;
        self.events.drain(..).filter(nat_event_reaches_application)
    }

    /// Keeps the observation cursor aligned when the discovery sweep removes
    /// an attempt event it owns.
    #[cfg(all(feature = "_nat-driver", feature = "_discovery-driver"))]
    fn note_removed(&mut self, index: usize) {
        if index < self.observed {
            self.observed -= 1;
        }
        self.observed = self.observed.min(self.events.len());
    }

    /// Whether any relay is configured for reservations or circuit dialing.
    pub(crate) fn has_relay(&self) -> bool {
        self.agent.has_relay()
    }

    /// Whether connects skip direct racing and DCUtR.
    pub(crate) fn force_relay(&self) -> bool {
        self.agent.force_relay()
    }

    /// Returns the latest usable NAT-orchestrated path for `peer`. Checks
    /// liveness at read time too, so a close the next pump has not swept
    /// yet never surfaces a stale path.
    #[cfg(feature = "_circuit-driver")]
    pub(crate) fn path<T: NatTransport, R: EntropySource>(
        &self,
        peer: &PeerId,
        swarm: &SwarmRuntime<T, R>,
    ) -> Option<Path> {
        self.paths
            .get(peer)
            .filter(|path| {
                let connections = swarm
                    .established_connections()
                    .filter(|(_, owner)| *owner == peer)
                    .map(|(conn_id, _)| conn_id);
                path_is_live(path, connections)
            })
            .cloned()
    }

    /// Confirmed public addresses plus circuit addresses for every held
    /// relay reservation — the set Identify should advertise.
    pub(crate) fn advertised_addrs(&self) -> Vec<Multiaddr> {
        let mut addrs = self.public_addrs.clone();
        for (_, addr) in &self.reserved_relays {
            if !addrs.contains(addr) {
                addrs.push(addr.clone());
            }
        }
        addrs
    }

    /// Returns only the AutoNAT-confirmed public addresses, for relay-server
    /// advertisement.
    #[cfg(feature = "relay-server")]
    pub(crate) fn confirmed_public_addrs(&self) -> Vec<Multiaddr> {
        self.public_addrs.clone()
    }

    #[cfg(all(test, feature = "relay-server"))]
    pub(crate) fn set_test_public_addrs(&mut self, addrs: Vec<Multiaddr>) {
        self.public_addrs = addrs;
    }

    /// The listen addresses AutoNAT currently offers for dial-back.
    #[cfg(all(test, feature = "nat", feature = "quic"))]
    pub(crate) fn listen_addrs(&self) -> &[Multiaddr] {
        self.agent.listen_addrs()
    }

    /// The recorded path for `peer` before the liveness check, for test
    /// assertions on path bookkeeping.
    #[cfg(all(test, feature = "nat", feature = "quic"))]
    pub(crate) fn recorded_path(&self, peer: &PeerId) -> Option<&Path> {
        self.paths.get(peer)
    }

    /// The adopted-bridge to promoted-circuit map, for test assertions.
    #[cfg(all(test, feature = "nat", feature = "quic"))]
    pub(crate) fn promoted(&self) -> &BTreeMap<(ConnectionId, StreamId), ConnectionId> {
        &self.promoted
    }

    /// Executes one agent action against the swarm and echoes synchronous
    /// results back to the agent. Best-effort actions swallow errors; the
    /// agent's timeouts and the swarm's lifecycle events surface failures.
    pub(crate) fn execute<T: NatTransport, R: EntropySource>(
        &mut self,
        action: NatAction,
        swarm: &mut SwarmRuntime<T, R>,
        sample: PlatformNow,
    ) {
        let now = to_nat_now(sample);
        match action {
            NatAction::Dial { token, addr } => {
                let result = swarm.dial(&addr).map_err(|e| e.to_string());
                self.agent.dial_result(token, result, now);
            }
            NatAction::OpenStream {
                token,
                peer,
                protocol_id,
            } => {
                let result = swarm
                    .open_stream(&peer, &protocol_id, now.mono_ms)
                    .map_err(|e| e.to_string());
                self.agent.stream_open_result(token, result, now);
            }
            NatAction::SendStream {
                peer,
                stream_id,
                data,
            } => {
                // Failures surface through the agent's own timeouts and the
                // swarm's error events; nothing to echo synchronously.
                match swarm.send_stream(&peer, stream_id, data, now.mono_ms) {
                    Ok(()) | Err(_) => {}
                }
            }
            NatAction::CloseStreamWrite { peer, stream_id } => {
                // A stale close must not replace the lifecycle event that
                // triggered this action.
                match swarm.close_stream_write(&peer, stream_id, now.mono_ms) {
                    Ok(()) | Err(_) => {}
                }
            }
            NatAction::ResetStream { peer, stream_id } => {
                // Reset is cleanup, so a stream already gone is equivalent
                // to a successful reset.
                match swarm.reset_stream(&peer, stream_id, now.mono_ms) {
                    Ok(()) | Err(_) => {}
                }
            }
            NatAction::Disconnect { peer } => {
                // Connection loss remains visible through the normal swarm
                // lifecycle; a stale disconnect adds no second outcome.
                match swarm.disconnect(&peer, now.mono_ms) {
                    Ok(()) | Err(_) => {}
                }
            }
            NatAction::Ping { peer } => {
                // Relay liveness is re-established from lifecycle events;
                // a stale ping is not an application-visible failure.
                match swarm.ping(&peer, now.mono_ms) {
                    Ok(()) | Err(_) => {}
                }
            }
            NatAction::SendRandomUdp {
                target,
                payload_len,
            } => {
                let mut payload = vec![0u8; payload_len];
                // A failed entropy sample simply skips this one best-effort
                // hole-punch datagram.
                if let Ok(()) = self.entropy.fill_bytes(&mut payload) {
                    match swarm.transport_mut().send_datagram(&target, &payload) {
                        Ok(()) | Err(_) => {}
                    }
                }
            }
            NatAction::PromoteBridge {
                token,
                inner_conn,
                relay,
                stream_id,
                remote_peer,
                role,
                pending_data,
                remote_write_closed,
            } => {
                let key = (inner_conn, stream_id);
                if let Some(existing) = self.promoted.get(&key).copied() {
                    self.agent.promote_result(token, Ok(existing), now);
                    return;
                }
                #[cfg(not(feature = "_circuit-driver"))]
                {
                    let _ = (relay, remote_peer, role, pending_data, remote_write_closed);
                    self.agent.promote_result(
                        token,
                        Err(PromoteError::Failed("portable relay is not enabled".into())),
                        now,
                    );
                }
                #[cfg(feature = "_circuit-driver")]
                {
                    swarm.forget_stream(inner_conn, stream_id);
                    let adoption = BridgeAdoption {
                        inner_conn,
                        bridge_stream: stream_id,
                        relay,
                        remote_peer,
                        role: match role {
                            BridgeRole::Initiator => CircuitRole::Initiator,
                            BridgeRole::Responder => CircuitRole::Responder,
                        },
                        pending_data,
                        remote_write_closed,
                    };
                    match swarm.transport_mut().adopt_bridge(adoption) {
                        Ok(conn_id) => {
                            self.promoted.insert(key, conn_id);
                            self.agent.promote_result(token, Ok(conn_id), now);
                        }
                        Err(error) => {
                            let promote_error = match &error {
                                AdoptError::PeerAlreadyDirect => PromoteError::PeerAlreadyDirect,
                                AdoptError::UnknownConnection => PromoteError::UnknownConnection,
                                _ => PromoteError::Failed(error.to_string()),
                            };
                            self.agent.promote_result(token, Err(promote_error), now);
                            if !matches!(error, AdoptError::UnknownConnection) {
                                #[cfg(all(test, feature = "nat", feature = "quic"))]
                                self.bridge_reset_attempts.push((inner_conn, stream_id));
                                match swarm.transport_mut().reset_bridge(inner_conn, stream_id) {
                                    Ok(()) | Err(_) => {}
                                }
                            }
                        }
                    }
                }
            }
            NatAction::CloseCircuit { conn_id } => {
                match swarm.transport_mut().close(conn_id) {
                    Ok(()) | Err(minip2p_transport::TransportError::ConnectionNotFound { .. }) => {
                        self.promoted.retain(|_, id| *id != conn_id);
                    }
                    // A transport failure will emerge through its normal
                    // event path; retain the promotion until then.
                    Err(_) => {}
                }
            }
        }
    }

    fn inject_straggler<T: NatTransport, R: EntropySource>(
        &mut self,
        event: &SwarmEvent,
        swarm: &mut SwarmRuntime<T, R>,
    ) -> bool {
        let key = match event {
            SwarmEvent::StreamData {
                conn_id, stream_id, ..
            }
            | SwarmEvent::StreamRemoteWriteClosed {
                conn_id, stream_id, ..
            }
            | SwarmEvent::StreamClosed {
                conn_id, stream_id, ..
            } => (*conn_id, *stream_id),
            _ => return false,
        };
        if !self.promoted.contains_key(&key) {
            return false;
        }
        match event {
            SwarmEvent::StreamData { data, .. } => {
                swarm
                    .transport_mut()
                    .inject_bridge_data(key.0, key.1, data.clone());
            }
            SwarmEvent::StreamRemoteWriteClosed { .. } => swarm
                .transport_mut()
                .inject_bridge_remote_write_closed(key.0, key.1),
            SwarmEvent::StreamClosed { .. } => {
                swarm.transport_mut().inject_bridge_closed(key.0, key.1);
                self.promoted.remove(&key);
            }
            // `key` was extracted above only for these three stream events.
            // Keep this defensive if a new swarm event reaches this path.
            _ => return false,
        }
        true
    }

    /// Updates NAT's address contribution after a lifecycle event.
    pub(crate) fn observe(&mut self, event: &NatEvent) {
        match event {
            NatEvent::PathEstablished { peer, path, .. } => {
                self.paths.insert(peer.clone(), path.clone());
            }
            NatEvent::InboundPathEstablished { peer, path } => {
                self.paths.insert(peer.clone(), path.clone());
            }
            NatEvent::PathUpgraded { peer, to, .. } => {
                self.paths.insert(peer.clone(), to.clone());
            }
            NatEvent::InboundDirectUpgrade { peer } => {
                self.paths.insert(peer.clone(), Path::DirectPunched);
            }
            NatEvent::RelayReserved { relay, .. } => {
                if self.reserved_relays.iter().any(|(peer, _)| peer == relay) {
                    return; // renewal — already advertised
                }
                let Some((_, transport)) = self.relay_addrs.iter().find(|(p, _)| p == relay) else {
                    return;
                };
                let mut circuit = transport.clone();
                circuit.push(Protocol::P2p(relay.clone()));
                circuit.push(Protocol::P2pCircuit);
                self.reserved_relays.push((relay.clone(), circuit));
                self.addresses_changed = true;
            }
            NatEvent::RelayReservationLost { relay } => {
                let before = self.reserved_relays.len();
                self.reserved_relays.retain(|(peer, _)| peer != relay);
                self.addresses_changed |= before != self.reserved_relays.len();
            }
            NatEvent::ReachabilityChanged {
                confirmed_addrs: addrs,
                ..
            }
            | NatEvent::PublicAddressesChanged { addrs }
                if self.public_addrs != *addrs =>
            {
                self.public_addrs = addrs.clone();
                self.addresses_changed = true;
            }
            _ => {}
        }
    }
}

/// Optional circuit operations used by the NAT driver. AutoNAT-only TCP
/// transports keep the defaults; circuit transports implement adoption.
pub(crate) trait NatTransport: Transport {
    fn contains_circuit(&self, _id: ConnectionId) -> bool {
        false
    }
    fn inject_bridge_closed(&mut self, _conn: ConnectionId, _stream: StreamId) {}
    fn inject_bridge_remote_write_closed(&mut self, _conn: ConnectionId, _stream: StreamId) {}
    fn inject_bridge_data(&mut self, _conn: ConnectionId, _stream: StreamId, _data: Vec<u8>) {}
    #[cfg(feature = "_circuit-driver")]
    fn adopt_bridge(&mut self, _adoption: BridgeAdoption) -> Result<ConnectionId, AdoptError> {
        Err(AdoptError::UnknownConnection)
    }
    #[cfg(feature = "_circuit-driver")]
    fn reset_bridge(
        &mut self,
        conn: ConnectionId,
        stream: StreamId,
    ) -> Result<(), minip2p_transport::TransportError> {
        self.reset_stream(conn, stream)
    }
}

#[cfg(feature = "_circuit-driver")]
impl<T: Transport, E: EntropySource> NatTransport for CircuitTransport<T, E> {
    fn contains_circuit(&self, id: ConnectionId) -> bool {
        self.contains_circuit(id)
    }
    fn inject_bridge_closed(&mut self, conn: ConnectionId, stream: StreamId) {
        self.inject_bridge_closed(conn, stream);
    }
    fn inject_bridge_remote_write_closed(&mut self, conn: ConnectionId, stream: StreamId) {
        self.inject_bridge_remote_write_closed(conn, stream);
    }
    fn inject_bridge_data(&mut self, conn: ConnectionId, stream: StreamId, data: Vec<u8>) {
        self.inject_bridge_data(conn, stream, data);
    }
    fn adopt_bridge(&mut self, adoption: BridgeAdoption) -> Result<ConnectionId, AdoptError> {
        self.adopt_bridge(adoption)
    }
    fn reset_bridge(
        &mut self,
        conn: ConnectionId,
        stream: StreamId,
    ) -> Result<(), minip2p_transport::TransportError> {
        self.inner_mut().reset_stream(conn, stream)
    }
}

#[cfg(all(feature = "portable-autonat", not(feature = "portable-relay")))]
impl<P: minip2p_tcp::TcpProvider, E: EntropySource> NatTransport
    for minip2p_tcp::TcpTransport<P, E>
{
}
