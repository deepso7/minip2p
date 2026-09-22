//! Caller-driven NAT capability shared by standard and portable Endpoints.
//! Time and entropy are supplied by the host; I/O runs through SwarmRuntime.

use alloc::{
    collections::{BTreeMap, VecDeque},
    string::ToString,
    vec,
    vec::Vec,
};
use minip2p_platform::{EntropySource, Now as PlatformNow};

#[cfg(any(feature = "nat", feature = "portable-relay"))]
use minip2p_circuit::{AdoptError, BridgeAdoption, CircuitRole, CircuitTransport};
use minip2p_core::{Multiaddr, PeerId, Protocol};
#[cfg(any(feature = "nat", feature = "portable-relay"))]
use minip2p_nat::BridgeRole;
use minip2p_nat::{NatAction, NatAgent, NatEvent, Now, Path, PromoteError};
use minip2p_swarm::{SwarmEvent, SwarmRuntime};
use minip2p_transport::{ConnectionId, StreamId, Transport};

/// Converts a host time sample into the agent's clock pair.
pub(crate) fn to_nat_now(now: PlatformNow) -> Now {
    Now {
        mono_ms: now.monotonic_ms,
        unix_secs: now.unix_seconds,
    }
}

/// Drives a [`NatAgent`] against the endpoint's swarm.
pub(crate) struct NatDriver<E> {
    pub(crate) agent: NatAgent,
    /// NAT events awaiting the Endpoint event stream; the endpoint moves
    /// them out once the Connection-attempt engine has observed them.
    pub(crate) events: VecDeque<NatEvent>,
    entropy: E,
    addresses_changed: bool,
    /// Relays we hold a reservation on, for circuit-address advertising.
    reserved_relays: Vec<(PeerId, Multiaddr)>,
    /// Relay transport addresses by peer, captured at construction.
    relay_addrs: Vec<(PeerId, Multiaddr)>,
    /// Direct public addresses confirmed by AutoNAT.
    public_addrs: Vec<Multiaddr>,
    /// Exact adopted bridge keys mapped to their promoted circuit ids.
    pub(crate) promoted: BTreeMap<(ConnectionId, StreamId), ConnectionId>,
    /// Authoritative usable NAT-orchestrated path by remote peer.
    paths: BTreeMap<PeerId, Path>,
    /// How many queued events the Connection engine has already observed.
    observed: usize,
    #[cfg(all(test, feature = "nat", feature = "quic"))]
    pub(crate) bridge_reset_attempts: Vec<(ConnectionId, StreamId)>,
}

impl<E: EntropySource> NatDriver<E> {
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
            #[cfg(all(test, feature = "nat", feature = "quic"))]
            bridge_reset_attempts: Vec::new(),
        }
    }

    pub(crate) fn cancel(&mut self, id: minip2p_core::ConnectId, now: PlatformNow) {
        self.agent.cancel(id, to_nat_now(now));
    }

    pub(crate) fn next_timeout(&self, now: PlatformNow) -> Option<u64> {
        if !self.events.is_empty() {
            Some(0)
        } else {
            self.agent.next_timeout(now.monotonic_ms)
        }
    }

    #[cfg(feature = "portable-autonat")]
    pub(crate) fn take_address_change(&mut self) -> Option<Vec<Multiaddr>> {
        if !core::mem::take(&mut self.addresses_changed) {
            return None;
        }
        Some(self.advertised_addrs())
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
        if let SwarmEvent::ConnectionClosed {
            peer_id, conn_id, ..
        } = event
        {
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
            if swarm.connection_id(peer_id).is_none() {
                self.paths.remove(peer_id);
            }
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
        self.promoted
            .retain(|_, id| swarm.transport().contains_circuit(*id));
    }

    /// Queued events the Connection-attempt engine has not observed yet.
    pub(crate) fn unobserved_events(&self) -> impl Iterator<Item = &NatEvent> {
        self.events.iter().skip(self.observed)
    }

    pub(crate) fn mark_observed(&mut self) {
        self.observed = self.events.len();
    }

    /// Drains every queued event that reaches the Endpoint event stream,
    /// once the Connection-attempt engine has observed it.
    pub(crate) fn drain_application_events(&mut self) -> impl Iterator<Item = NatEvent> + '_ {
        self.observed = 0;
        self.events
            .drain(..)
            .filter(crate::portable::nat_event_reaches_application)
    }

    /// Keeps the observation cursor aligned when the discovery sweep removes
    /// an attempt event it owns.
    #[cfg(any(feature = "discovery", feature = "mdns"))]
    pub(crate) fn note_removed(&mut self, index: usize) {
        if index < self.observed {
            self.observed -= 1;
        }
        self.observed = self.observed.min(self.events.len());
    }
    pub(crate) fn has_relay(&self) -> bool {
        self.agent.has_relay()
    }

    /// Whether connects skip direct racing and DCUtR.
    pub(crate) fn force_relay(&self) -> bool {
        self.agent.force_relay()
    }

    /// Returns the latest usable NAT-orchestrated path for `peer`.
    #[cfg(any(feature = "nat", feature = "portable-relay"))]
    pub(crate) fn path(&self, peer: &PeerId) -> Option<Path> {
        self.paths.get(peer).cloned()
    }

    pub(crate) fn advertised_addrs(&self) -> Vec<Multiaddr> {
        let mut addrs = self.public_addrs.clone();
        for (_, addr) in &self.reserved_relays {
            if !addrs.contains(addr) {
                addrs.push(addr.clone());
            }
        }
        addrs
    }

    #[cfg(feature = "relay-server")]
    pub(crate) fn confirmed_public_addrs(&self) -> Vec<Multiaddr> {
        self.public_addrs.clone()
    }

    #[cfg(all(test, feature = "relay-server"))]
    pub(crate) fn set_test_public_addrs(&mut self, addrs: Vec<Multiaddr>) {
        self.public_addrs = addrs;
    }

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
                #[cfg(not(any(feature = "nat", feature = "portable-relay")))]
                {
                    let _ = (relay, remote_peer, role, pending_data, remote_write_closed);
                    self.agent.promote_result(
                        token,
                        Err(PromoteError::Failed("portable relay is not enabled".into())),
                        now,
                    );
                }
                #[cfg(any(feature = "nat", feature = "portable-relay"))]
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
    #[cfg(any(feature = "nat", feature = "portable-relay"))]
    fn adopt_bridge(&mut self, _adoption: BridgeAdoption) -> Result<ConnectionId, AdoptError> {
        Err(AdoptError::UnknownConnection)
    }
    #[cfg(any(feature = "nat", feature = "portable-relay"))]
    fn reset_bridge(
        &mut self,
        conn: ConnectionId,
        stream: StreamId,
    ) -> Result<(), minip2p_transport::TransportError> {
        self.reset_stream(conn, stream)
    }
}

#[cfg(any(feature = "nat", feature = "portable-relay"))]
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
