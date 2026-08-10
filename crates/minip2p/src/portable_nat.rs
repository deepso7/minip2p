//! Caller-driven wiring between `NatAgent` and a portable circuit transport.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::ToString;
use alloc::vec::Vec;

use minip2p_circuit::{AdoptError, BridgeAdoption, CircuitRole};
use minip2p_core::{Multiaddr, PeerId, Protocol};
use minip2p_nat::{
    BridgeRole, ConnectId, NatAction, NatAgent, NatEvent, Now as NatNow, Path, PromoteError,
    ReservationInfo,
};
use minip2p_platform::{EntropySource, Now, SharedEntropy};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, StreamId, Transport, TransportError};

use crate::{PortableEndpoint, SmoltcpComposedTransport, smoltcp};

type Endpoint<D, E> = PortableEndpoint<SmoltcpComposedTransport<D, E>, SharedEntropy<E>>;

pub(crate) struct PortableNatDriver {
    pub(crate) agent: NatAgent,
    pub(crate) events: VecDeque<NatEvent>,
    relay_addrs: Vec<(PeerId, Multiaddr)>,
    reserved_relays: Vec<(PeerId, Multiaddr)>,
    public_addrs: Vec<Multiaddr>,
    promoted: BTreeMap<(ConnectionId, StreamId), ConnectionId>,
    paths: BTreeMap<PeerId, Path>,
}

impl PortableNatDriver {
    pub(crate) fn new(agent: NatAgent, relay_addrs: Vec<(PeerId, Multiaddr)>) -> Self {
        Self {
            agent,
            events: VecDeque::new(),
            relay_addrs,
            reserved_relays: Vec::new(),
            public_addrs: Vec::new(),
            promoted: BTreeMap::new(),
            paths: BTreeMap::new(),
        }
    }

    pub(crate) fn now(now: Now) -> NatNow {
        NatNow {
            mono_ms: now.monotonic_ms,
            unix_secs: now.unix_seconds,
        }
    }

    pub(crate) fn connect(&mut self, peer: PeerId, now: Now) -> ConnectId {
        self.agent.connect(peer, Vec::new(), Self::now(now))
    }

    pub(crate) fn cancel(&mut self, id: ConnectId, now: Now) {
        self.agent.cancel(id, Self::now(now));
    }

    pub(crate) fn path(&self, peer: &PeerId) -> Option<Path> {
        self.paths.get(peer).cloned()
    }

    pub(crate) fn active_reservation(&self) -> Option<ReservationInfo> {
        self.agent.active_reservation().cloned()
    }

    pub(crate) fn ingest<D: smoltcp::phy::Device, E: EntropySource>(
        &mut self,
        event: &SwarmEvent,
        endpoint: &mut Endpoint<D, E>,
        now: Now,
    ) -> bool {
        if self.inject_straggler(event, endpoint) {
            self.pump(endpoint, now);
            return true;
        }
        let is_circuit = match event {
            SwarmEvent::ConnectionEstablished { conn_id, .. }
            | SwarmEvent::ConnectionClosed { conn_id, .. } => conn_id.is_circuit(),
            _ => false,
        };
        let handled =
            self.agent
                .handle_event_with_disposition_classified(event, is_circuit, Self::now(now));
        if let SwarmEvent::ConnectionClosed { peer_id, conn_id } = event {
            self.promoted
                .retain(|(inner_conn, _), circuit| inner_conn != conn_id && circuit != conn_id);
            if !endpoint.connected_peers().contains(peer_id) {
                self.paths.remove(peer_id);
            }
        }
        self.pump(endpoint, now);
        handled
    }

    pub(crate) fn tick<D: smoltcp::phy::Device, E: EntropySource>(
        &mut self,
        endpoint: &mut Endpoint<D, E>,
        now: Now,
    ) {
        if self.agent.next_timeout(now.monotonic_ms) == Some(0) {
            self.agent.handle_tick(Self::now(now));
        }
        self.pump(endpoint, now);
    }

    pub(crate) fn pump<D: smoltcp::phy::Device, E: EntropySource>(
        &mut self,
        endpoint: &mut Endpoint<D, E>,
        now: Now,
    ) {
        loop {
            let mut progressed = false;
            while let Some(action) = self.agent.poll_action() {
                progressed = true;
                self.execute(action, endpoint, now);
            }
            while let Some(event) = self.agent.poll_event() {
                progressed = true;
                self.observe(&event, endpoint);
                self.events.push_back(event);
            }
            if !progressed {
                break;
            }
        }
        let active: BTreeSet<_> = endpoint
            .runtime()
            .transport()
            .circuit_ids()
            .into_iter()
            .collect();
        self.promoted.retain(|_, id| active.contains(id));
    }

    fn execute<D: smoltcp::phy::Device, E: EntropySource>(
        &mut self,
        action: NatAction,
        endpoint: &mut Endpoint<D, E>,
        now: Now,
    ) {
        let nat_now = Self::now(now);
        match action {
            NatAction::Dial { token, addr } => {
                let result = endpoint.dial(&addr).map_err(|error| error.to_string());
                self.agent.dial_result(token, result, nat_now);
            }
            NatAction::OpenStream {
                token,
                peer,
                protocol_id,
            } => {
                let result = endpoint
                    .open_stream(&peer, &protocol_id, now)
                    .map_err(|error| error.to_string());
                self.agent.stream_open_result(token, result, nat_now);
            }
            NatAction::SendStream {
                peer,
                stream_id,
                data,
            } => {
                let _ = endpoint.send_stream(&peer, stream_id, data, now);
            }
            NatAction::CloseStreamWrite { peer, stream_id } => {
                let _ = endpoint.close_stream_write(&peer, stream_id, now);
            }
            NatAction::ResetStream { peer, stream_id } => {
                let _ = endpoint.reset_stream(&peer, stream_id, now);
            }
            NatAction::Disconnect { peer } => {
                let _ = endpoint.disconnect(&peer, now);
            }
            // The smoltcp TCP endpoint has no raw UDP transport. TCP-only
            // relay configurations never emit this; a defensive drop keeps
            // DCUtR explicitly unavailable instead of faking a punch.
            NatAction::SendRandomUdp { .. } => {}
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
                    self.agent.promote_result(token, Ok(existing), nat_now);
                    return;
                }
                endpoint.runtime_mut().forget_stream(inner_conn, stream_id);
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
                match endpoint
                    .runtime_mut()
                    .transport_mut()
                    .adopt_bridge(adoption)
                {
                    Ok(conn_id) => {
                        self.promoted.insert(key, conn_id);
                        self.agent.promote_result(token, Ok(conn_id), nat_now);
                    }
                    Err(error) => {
                        let promoted = match &error {
                            AdoptError::PeerAlreadyDirect => PromoteError::PeerAlreadyDirect,
                            AdoptError::UnknownConnection => PromoteError::UnknownConnection,
                            _ => PromoteError::Failed(error.to_string()),
                        };
                        self.agent.promote_result(token, Err(promoted), nat_now);
                        if !matches!(error, AdoptError::UnknownConnection) {
                            let _ = endpoint
                                .runtime_mut()
                                .transport_mut()
                                .inner_mut()
                                .reset_stream(inner_conn, stream_id);
                        }
                    }
                }
            }
            NatAction::CloseCircuit { conn_id } => {
                let result = endpoint.runtime_mut().transport_mut().close(conn_id);
                if result.is_ok()
                    || matches!(result, Err(TransportError::ConnectionNotFound { .. }))
                {
                    self.promoted.retain(|_, id| *id != conn_id);
                }
            }
        }
    }

    fn inject_straggler<D: smoltcp::phy::Device, E: EntropySource>(
        &mut self,
        event: &SwarmEvent,
        endpoint: &mut Endpoint<D, E>,
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
        let transport = endpoint.runtime_mut().transport_mut();
        match event {
            SwarmEvent::StreamData { data, .. } => {
                transport.inject_bridge_data(key.0, key.1, data.clone());
            }
            SwarmEvent::StreamRemoteWriteClosed { .. } => {
                transport.inject_bridge_remote_write_closed(key.0, key.1);
            }
            SwarmEvent::StreamClosed { .. } => {
                transport.inject_bridge_closed(key.0, key.1);
                self.promoted.remove(&key);
            }
            _ => unreachable!(),
        }
        true
    }

    fn observe<D: smoltcp::phy::Device, E: EntropySource>(
        &mut self,
        event: &NatEvent,
        endpoint: &mut Endpoint<D, E>,
    ) {
        match event {
            NatEvent::PathEstablished { peer, path, .. }
            | NatEvent::InboundPathEstablished { peer, path } => {
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
                    return;
                }
                let Some((_, transport)) = self.relay_addrs.iter().find(|(peer, _)| peer == relay)
                else {
                    return;
                };
                let mut circuit = transport.clone();
                circuit.push(Protocol::P2p(relay.clone()));
                circuit.push(Protocol::P2pCircuit);
                self.reserved_relays.push((relay.clone(), circuit));
                self.advertise(endpoint);
            }
            NatEvent::RelayReservationLost { relay } => {
                let before = self.reserved_relays.len();
                self.reserved_relays.retain(|(peer, _)| peer != relay);
                if self.reserved_relays.len() != before {
                    self.advertise(endpoint);
                }
            }
            NatEvent::ReachabilityChanged {
                confirmed_addrs: addrs,
                ..
            }
            | NatEvent::PublicAddressesChanged { addrs }
                if self.public_addrs != *addrs =>
            {
                self.public_addrs = addrs.clone();
                self.advertise(endpoint);
            }
            _ => {}
        }
    }

    fn advertise<D: smoltcp::phy::Device, E: EntropySource>(&self, endpoint: &mut Endpoint<D, E>) {
        let mut addrs = self.public_addrs.clone();
        for (_, address) in &self.reserved_relays {
            if !addrs.contains(address) {
                addrs.push(address.clone());
            }
        }
        endpoint.set_external_addresses(addrs);
    }
}
