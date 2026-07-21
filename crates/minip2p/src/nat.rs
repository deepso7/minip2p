//! Std wiring that pumps a sans-I/O [`NatAgent`] against the endpoint's
//! swarm: clock sampling, action execution, stream-event interception, and
//! circuit-address advertising.
//!
//! Available behind the `nat` cargo feature; see the `nat` methods on
//! [`Endpoint`](crate::Endpoint) and [`EndpointBuilder`](crate::EndpointBuilder).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use minip2p_circuit::{AdoptError, BridgeAdoption, CircuitRole, CircuitTransport};
use minip2p_core::{Multiaddr, PeerId, Protocol};
use minip2p_nat::{BridgeRole, NatAction, NatAgent, NatEvent, Now, PromoteError};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, StreamId, Transport};

use crate::EndpointSwarm;

/// Drives a [`NatAgent`] against the endpoint's swarm.
pub(crate) struct NatDriver {
    pub(crate) agent: NatAgent,
    /// NAT events awaiting the application (drained via
    /// `Endpoint::take_nat_events` / `next_nat_event` / `wait_path`).
    pub(crate) events: VecDeque<NatEvent>,
    /// Monotonic epoch for the agent's `mono_ms` clock.
    epoch: Instant,
    /// Relays we hold a reservation on, for circuit-address advertising.
    reserved_relays: Vec<(PeerId, Multiaddr)>,
    /// Relay transport addresses by peer, captured at construction.
    relay_addrs: Vec<(PeerId, Multiaddr)>,
    /// Direct public addresses confirmed by AutoNAT.
    public_addrs: Vec<Multiaddr>,
    /// Exact adopted bridge keys mapped to their promoted circuit ids.
    promoted: BTreeMap<(ConnectionId, StreamId), ConnectionId>,
    #[cfg(test)]
    bridge_reset_attempts: Vec<(ConnectionId, StreamId)>,
}

impl NatDriver {
    pub(crate) fn new(agent: NatAgent, relay_addrs: Vec<(PeerId, Multiaddr)>) -> Self {
        Self {
            agent,
            events: VecDeque::new(),
            epoch: Instant::now(),
            reserved_relays: Vec::new(),
            relay_addrs,
            public_addrs: Vec::new(),
            promoted: BTreeMap::new(),
            #[cfg(test)]
            bridge_reset_attempts: Vec::new(),
        }
    }

    /// Samples the driver's clocks for the agent.
    pub(crate) fn now(&self) -> Now {
        Now {
            mono_ms: self.epoch.elapsed().as_millis() as u64,
            unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs()),
        }
    }

    /// Feeds one swarm event to the agent and executes its cascade.
    ///
    /// Returns `true` when the event belongs to the NAT control plane and
    /// must not be forwarded to the application. The agent's disposition is
    /// authoritative even when handling claims or releases the stream.
    pub(crate) fn ingest(&mut self, event: &SwarmEvent, swarm: &mut EndpointSwarm) -> bool {
        let now = self.now();
        if self.inject_straggler(event, swarm) {
            self.pump(swarm);
            return true;
        }
        let is_circuit = match event {
            SwarmEvent::ConnectionEstablished { conn_id, .. }
            | SwarmEvent::ConnectionClosed { conn_id, .. } => CircuitTransport::<
                minip2p_quic::QuicEndpoint,
                minip2p_circuit::OsEntropy,
            >::is_circuit(*conn_id),
            _ => false,
        };
        let handled = self
            .agent
            .handle_event_with_disposition_classified(event, is_circuit, now);
        if let SwarmEvent::ConnectionClosed { conn_id, .. } = event {
            self.promoted
                .retain(|(inner_conn, _), circuit| inner_conn != conn_id && circuit != conn_id);
        }
        self.pump(swarm);
        handled
    }

    /// Advances timers only when the agent reports a due deadline, then
    /// executes any resulting work.
    pub(crate) fn tick(&mut self, swarm: &mut EndpointSwarm) {
        let now = self.now();
        if self.agent.next_timeout(now.mono_ms) != Some(0) {
            return;
        }
        self.agent.handle_tick(now);
        self.pump(swarm);
    }

    /// Drains agent actions into swarm calls (echoing synchronous results
    /// back) and collects application-visible NAT events.
    pub(crate) fn pump(&mut self, swarm: &mut EndpointSwarm) {
        loop {
            let mut progressed = false;
            while let Some(action) = self.agent.poll_action() {
                progressed = true;
                self.execute(action, swarm);
            }
            while let Some(event) = self.agent.poll_event() {
                progressed = true;
                self.observe(&event, swarm);
                self.events.push_back(event);
            }
            if !progressed {
                break;
            }
        }
        let active: BTreeSet<_> = swarm.transport().circuit_ids().into_iter().collect();
        self.promoted.retain(|_, id| active.contains(id));
    }

    fn execute(&mut self, action: NatAction, swarm: &mut EndpointSwarm) {
        let now = self.now();
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
                    .open_stream(&peer, &protocol_id)
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
                let _ = swarm.send_stream(&peer, stream_id, data);
            }
            NatAction::CloseStreamWrite { peer, stream_id } => {
                let _ = swarm.close_stream_write(&peer, stream_id);
            }
            NatAction::ResetStream { peer, stream_id } => {
                let _ = swarm.reset_stream(&peer, stream_id);
            }
            NatAction::Disconnect { peer } => {
                let _ = swarm.disconnect(&peer);
            }
            NatAction::SendRandomUdp {
                target,
                payload_len,
            } => {
                let mut payload = vec![0u8; payload_len];
                if getrandom::fill(&mut payload).is_ok() {
                    let _ = swarm.transport().inner().send_raw_udp(&target, &payload);
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
                            #[cfg(test)]
                            self.bridge_reset_attempts.push((inner_conn, stream_id));
                            let _ = swarm
                                .transport_mut()
                                .inner_mut()
                                .reset_stream(inner_conn, stream_id);
                        }
                    }
                }
            }
            NatAction::CloseCircuit { conn_id } => {
                let result = swarm.transport_mut().close(conn_id);
                if result.is_ok()
                    || matches!(
                        result,
                        Err(minip2p_transport::TransportError::ConnectionNotFound { .. })
                    )
                {
                    self.promoted.retain(|_, id| *id != conn_id);
                }
            }
        }
    }

    fn inject_straggler(&mut self, event: &SwarmEvent, swarm: &mut EndpointSwarm) -> bool {
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
            _ => unreachable!(),
        }
        true
    }

    /// Keeps Identify's advertised set in sync with reservation state: a
    /// held reservation advertises `<relay>/p2p/<relay-id>/p2p-circuit`.
    fn observe(&mut self, event: &NatEvent, swarm: &mut EndpointSwarm) {
        match event {
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
                self.advertise(swarm);
            }
            NatEvent::RelayReservationLost { relay } => {
                let before = self.reserved_relays.len();
                self.reserved_relays.retain(|(peer, _)| peer != relay);
                if self.reserved_relays.len() != before {
                    self.advertise(swarm);
                }
            }
            NatEvent::ReachabilityChanged {
                confirmed_addrs, ..
            } => {
                if self.public_addrs != *confirmed_addrs {
                    self.public_addrs = confirmed_addrs.clone();
                    self.advertise(swarm);
                }
            }
            NatEvent::PublicAddressesChanged { addrs } if self.public_addrs != *addrs => {
                self.public_addrs = addrs.clone();
                self.advertise(swarm);
            }
            _ => {}
        }
    }

    fn advertise(&self, swarm: &mut EndpointSwarm) {
        let mut addrs = self.public_addrs.clone();
        for (_, addr) in &self.reserved_relays {
            if !addrs.contains(addr) {
                addrs.push(addr.clone());
            }
        }
        swarm.set_external_addresses(addrs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ed25519Keypair, Endpoint, Event, NatConfig, ReachabilityState};
    use minip2p_nat::{NatToken, ReservationPolicy};
    use minip2p_relay::{HOP_PROTOCOL_ID, HopMessage, HopMessageType, Status, encode_frame};

    struct BridgePair {
        local: Endpoint,
        relay: Endpoint,
        local_addr: minip2p_core::PeerAddr,
        relay_addr: minip2p_core::PeerAddr,
        inner_conn: ConnectionId,
        stream: StreamId,
    }

    fn negotiated_bridge() -> BridgePair {
        let mut relay = Endpoint::builder()
            .identity(Ed25519Keypair::from_secret_key_bytes([72; 32]))
            .protocol(HOP_PROTOCOL_ID)
            .bind_quic("127.0.0.1:0")
            .expect("bind relay");
        let relay_addr = relay.listen().expect("relay listens");
        let mut local = Endpoint::builder()
            .identity(Ed25519Keypair::from_secret_key_bytes([71; 32]))
            .protocol(HOP_PROTOCOL_ID)
            .bind_quic("127.0.0.1:0")
            .expect("bind local");
        let local_addr = local.listen().expect("local listens");
        local.dial(&relay_addr).expect("dial relay");

        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let mut inner_conn = None;
        let mut local_ready = false;
        let mut relay_ready = false;
        while !local_ready || !relay_ready {
            assert!(
                Instant::now() < deadline,
                "relay session did not become ready"
            );
            if let Some(event) = local
                .next_event(std::time::Duration::from_millis(10))
                .expect("drive local")
            {
                match event {
                    Event::ConnectionEstablished { peer_id, conn_id }
                        if peer_id == *relay_addr.peer_id() =>
                    {
                        inner_conn = Some(conn_id);
                    }
                    Event::PeerReady { peer_id, .. } if peer_id == *relay_addr.peer_id() => {
                        local_ready = true;
                    }
                    _ => {}
                }
            }
            if let Some(Event::PeerReady { peer_id, .. }) = relay
                .next_event(std::time::Duration::from_millis(10))
                .expect("drive relay")
                && peer_id == *local.peer_id()
            {
                relay_ready = true;
            }
        }
        let inner_conn = inner_conn.expect("local connection id");
        let stream = local
            .open_stream(relay_addr.peer_id(), HOP_PROTOCOL_ID)
            .expect("open bridge stream");
        let mut local_stream_ready = false;
        let mut relay_stream_ready = false;
        while !local_stream_ready || !relay_stream_ready {
            assert!(Instant::now() < deadline, "bridge stream did not negotiate");
            if let Some(Event::StreamReady { stream_id, .. }) = local
                .next_event(std::time::Duration::from_millis(10))
                .expect("drive local stream")
                && stream_id == stream
            {
                local_stream_ready = true;
            }
            if let Some(Event::StreamReady { stream_id, .. }) = relay
                .next_event(std::time::Duration::from_millis(10))
                .expect("drive relay stream")
                && stream_id == stream
            {
                relay_stream_ready = true;
            }
        }
        BridgePair {
            local,
            relay,
            local_addr,
            relay_addr,
            inner_conn,
            stream,
        }
    }

    fn drain_actions(agent: &mut NatAgent) -> Vec<NatAction> {
        core::iter::from_fn(|| agent.poll_action()).collect()
    }

    fn only_dial_token(actions: &[NatAction]) -> NatToken {
        actions
            .iter()
            .find_map(|action| match action {
                NatAction::Dial { token, .. } => Some(*token),
                _ => None,
            })
            .expect("dial token")
    }

    fn only_open_token(actions: &[NatAction]) -> NatToken {
        actions
            .iter()
            .find_map(|action| match action {
                NatAction::OpenStream { token, .. } => Some(*token),
                _ => None,
            })
            .expect("open token")
    }

    fn promotion_driver(pair: &BridgePair, remote_write_closed: bool) -> (NatDriver, NatAction) {
        let target = Ed25519Keypair::from_secret_key_bytes([73; 32]).peer_id();
        let relay_peer = pair.relay_addr.peer_id().clone();
        let config = NatConfig {
            relays: vec![pair.relay_addr.clone()],
            force_relay: true,
            reservation_policy: ReservationPolicy::Never,
            ..NatConfig::default()
        };
        let mut agent = NatAgent::new(pair.local.peer_id().clone(), config);
        agent.connect(target, Vec::new(), Now::from_mono(0));
        let dial = drain_actions(&mut agent);
        agent.dial_result(
            only_dial_token(&dial),
            Ok(pair.inner_conn),
            Now::from_mono(1),
        );
        agent.handle_event(
            &SwarmEvent::ConnectionEstablished {
                peer_id: relay_peer.clone(),
                conn_id: pair.inner_conn,
            },
            Now::from_mono(2),
        );
        agent.handle_event(
            &SwarmEvent::PeerReady {
                peer_id: relay_peer.clone(),
                protocols: vec![HOP_PROTOCOL_ID.to_string()],
            },
            Now::from_mono(3),
        );
        let open = drain_actions(&mut agent);
        agent.stream_open_result(only_open_token(&open), Ok(pair.stream), Now::from_mono(4));
        agent.handle_event(
            &SwarmEvent::StreamReady {
                peer_id: relay_peer.clone(),
                conn_id: pair.inner_conn,
                stream_id: pair.stream,
                protocol_id: HOP_PROTOCOL_ID.to_string(),
                initiated_locally: true,
            },
            Now::from_mono(5),
        );
        drain_actions(&mut agent); // HOP CONNECT
        let status = HopMessage {
            kind: HopMessageType::Status,
            peer: None,
            reservation: None,
            limit: None,
            status: Some(Status::Ok),
        };
        agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: relay_peer.clone(),
                conn_id: pair.inner_conn,
                stream_id: pair.stream,
                data: encode_frame(&status.encode()),
            },
            Now::from_mono(6),
        );
        let mut promotion = drain_actions(&mut agent)
            .into_iter()
            .find(|action| matches!(action, NatAction::PromoteBridge { .. }))
            .expect("promotion action");
        if let NatAction::PromoteBridge {
            remote_write_closed: closed,
            ..
        } = &mut promotion
        {
            *closed = remote_write_closed;
        }
        let driver = NatDriver::new(
            agent,
            vec![(relay_peer, pair.relay_addr.transport().clone())],
        );
        (driver, promotion)
    }

    fn execute(driver: &mut NatDriver, action: NatAction, endpoint: &mut Endpoint) {
        driver.execute(action, &mut endpoint.swarm);
    }

    fn circuit_id(driver: &NatDriver, key: (ConnectionId, StreamId)) -> ConnectionId {
        *driver.promoted.get(&key).expect("promoted bridge entry")
    }

    #[test]
    fn confirmed_public_addresses_are_advertised_and_cleared() {
        let mut endpoint = Endpoint::builder()
            .nat_config(NatConfig::default())
            .bind_quic("127.0.0.1:0")
            .expect("bind endpoint");
        let public: Multiaddr = "/ip4/203.0.113.9/udp/4001/quic-v1"
            .parse()
            .expect("public addr");
        let Endpoint { swarm, nat, .. } = &mut endpoint;
        let driver = nat.as_mut().expect("NAT configured");

        driver.observe(
            &NatEvent::ReachabilityChanged {
                old: ReachabilityState::Unknown,
                new: ReachabilityState::Public,
                confirmed_addrs: vec![public.clone()],
            },
            swarm,
        );
        swarm.poll().expect("refresh identify addresses");
        assert!(swarm.core().local_addresses().contains(&public));

        driver.observe(
            &NatEvent::ReachabilityChanged {
                old: ReachabilityState::Public,
                new: ReachabilityState::Private,
                confirmed_addrs: Vec::new(),
            },
            swarm,
        );
        swarm.poll().expect("refresh identify addresses");
        assert!(!swarm.core().local_addresses().contains(&public));
    }

    #[test]
    fn driver_promotes_idempotently_routes_exact_stragglers_and_closes_idempotently() {
        let mut pair = negotiated_bridge();
        let key = (pair.inner_conn, pair.stream);
        let (mut driver, promotion) = promotion_driver(&pair, false);
        let duplicate = promotion.clone();

        execute(&mut driver, promotion, &mut pair.local);
        let promoted = circuit_id(&driver, key);
        assert_eq!(pair.local.swarm.transport().circuit_ids(), vec![promoted]);

        execute(&mut driver, duplicate, &mut pair.local);
        assert_eq!(driver.promoted.len(), 1);
        assert_eq!(pair.local.swarm.transport().circuit_ids(), vec![promoted]);
        assert!(driver.bridge_reset_attempts.is_empty());

        let mut header = vec![19];
        header.extend_from_slice(b"/multistream/1.0.0\n");
        assert!(driver.ingest(
            &SwarmEvent::StreamData {
                peer_id: pair.relay_addr.peer_id().clone(),
                conn_id: pair.inner_conn,
                stream_id: pair.stream,
                data: header,
            },
            &mut pair.local.swarm,
        ));
        assert!(driver.promoted.contains_key(&key));
        assert!(!driver.ingest(
            &SwarmEvent::StreamData {
                peer_id: pair.relay_addr.peer_id().clone(),
                conn_id: ConnectionId::new(pair.inner_conn.as_u64() + 100),
                stream_id: pair.stream,
                data: vec![1],
            },
            &mut pair.local.swarm,
        ));

        execute(
            &mut driver,
            NatAction::CloseCircuit { conn_id: promoted },
            &mut pair.local,
        );
        execute(
            &mut driver,
            NatAction::CloseCircuit { conn_id: promoted },
            &mut pair.local,
        );
        assert!(driver.promoted.is_empty());
        assert!(pair.local.swarm.transport().circuit_ids().is_empty());
        let _ = pair.relay.next_event(std::time::Duration::from_millis(10));
    }

    #[test]
    fn promotion_uses_action_connection_after_same_batch_relay_supersede() {
        let mut pair = negotiated_bridge();
        let old_conn = pair.inner_conn;
        let stream = pair.stream;
        let relay_peer = pair.relay_addr.peer_id().clone();
        let (mut driver, promotion) = promotion_driver(&pair, false);

        // Establish a replacement relay connection, but stop as soon as both
        // public Established events have been delivered. At this seam the
        // core points at B while its eager close of A is still deferred.
        pair.relay
            .dial(&pair.local_addr)
            .expect("relay dials replacement");
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let mut replacement = None;
        let mut relay_established = false;
        while replacement.is_none() || !relay_established {
            assert!(Instant::now() < deadline, "replacement did not establish");
            if replacement.is_none()
                && let Some(Event::ConnectionEstablished { peer_id, conn_id }) = pair
                    .local
                    .next_event(std::time::Duration::from_millis(10))
                    .expect("drive local replacement")
                && peer_id == relay_peer
                && conn_id != old_conn
            {
                replacement = Some(conn_id);
            }
            if !relay_established
                && let Some(Event::ConnectionEstablished { peer_id, .. }) = pair
                    .relay
                    .next_event(std::time::Duration::from_millis(10))
                    .expect("drive relay replacement")
                && peer_id == *pair.local.peer_id()
            {
                relay_established = true;
            }
        }
        let replacement = replacement.expect("replacement connection id");
        assert_eq!(
            pair.local.swarm.core().conn_for(&relay_peer),
            Some(replacement)
        );

        execute(&mut driver, promotion, &mut pair.local);
        assert!(driver.promoted.contains_key(&(old_conn, stream)));
        assert!(!driver.promoted.contains_key(&(replacement, stream)));
        assert!(!driver.ingest(
            &SwarmEvent::StreamData {
                peer_id: relay_peer,
                conn_id: replacement,
                stream_id: stream,
                data: vec![1],
            },
            &mut pair.local.swarm,
        ));
    }

    #[test]
    fn driver_resets_failed_adoptions_but_not_unknown_connections() {
        let mut failed_pair = negotiated_bridge();
        let failed_key = (failed_pair.inner_conn, failed_pair.stream);
        let (mut failed, action) = promotion_driver(&failed_pair, true);
        execute(&mut failed, action, &mut failed_pair.local);
        assert!(failed.promoted.is_empty());
        assert_eq!(failed.bridge_reset_attempts, vec![failed_key]);

        let mut unknown_pair = negotiated_bridge();
        let (mut unknown, mut action) = promotion_driver(&unknown_pair, false);
        let missing = ConnectionId::new(9_999);
        if let NatAction::PromoteBridge { inner_conn, .. } = &mut action {
            *inner_conn = missing;
        }
        execute(&mut unknown, action, &mut unknown_pair.local);
        assert!(unknown.promoted.is_empty());
        assert!(unknown.bridge_reset_attempts.is_empty());
        assert!(
            unknown_pair
                .local
                .swarm
                .transport()
                .circuit_ids()
                .is_empty()
        );
    }

    #[test]
    fn driver_prunes_promotions_on_every_external_cleanup_path() {
        // A remote bridge FIN is routed through the promoted transport even
        // though the raw stream was forgotten by the swarm at adoption.
        let mut fin_pair = negotiated_bridge();
        let (mut fin, action) = promotion_driver(&fin_pair, false);
        execute(&mut fin, action, &mut fin_pair.local);
        assert!(fin.ingest(
            &SwarmEvent::StreamRemoteWriteClosed {
                peer_id: fin_pair.relay_addr.peer_id().clone(),
                conn_id: fin_pair.inner_conn,
                stream_id: fin_pair.stream,
            },
            &mut fin_pair.local.swarm,
        ));

        // Exact bridge closure is terminal and removes the keyed adoption.
        let mut closed_pair = negotiated_bridge();
        let closed_key = (closed_pair.inner_conn, closed_pair.stream);
        let (mut closed, action) = promotion_driver(&closed_pair, false);
        execute(&mut closed, action, &mut closed_pair.local);
        assert!(closed.ingest(
            &SwarmEvent::StreamClosed {
                peer_id: closed_pair.relay_addr.peer_id().clone(),
                conn_id: closed_pair.inner_conn,
                stream_id: closed_pair.stream,
            },
            &mut closed_pair.local.swarm,
        ));
        assert!(!closed.promoted.contains_key(&closed_key));

        // An inner relay connection close drops every circuit riding it.
        let mut inner_pair = negotiated_bridge();
        let inner_key = (inner_pair.inner_conn, inner_pair.stream);
        let (mut inner, action) = promotion_driver(&inner_pair, false);
        execute(&mut inner, action, &mut inner_pair.local);
        inner.ingest(
            &SwarmEvent::ConnectionClosed {
                peer_id: inner_pair.relay_addr.peer_id().clone(),
                conn_id: inner_pair.inner_conn,
            },
            &mut inner_pair.local.swarm,
        );
        assert!(!inner.promoted.contains_key(&inner_key));

        // A circuit lifecycle close also removes its reverse map entry.
        let mut circuit_pair = negotiated_bridge();
        let circuit_key = (circuit_pair.inner_conn, circuit_pair.stream);
        let (mut circuit, action) = promotion_driver(&circuit_pair, false);
        execute(&mut circuit, action, &mut circuit_pair.local);
        let promoted = circuit_id(&circuit, circuit_key);
        circuit.ingest(
            &SwarmEvent::ConnectionClosed {
                peer_id: Ed25519Keypair::from_secret_key_bytes([73; 32]).peer_id(),
                conn_id: promoted,
            },
            &mut circuit_pair.local.swarm,
        );
        assert!(!circuit.promoted.contains_key(&circuit_key));

        // Reconciliation catches transport-side removal even if no lifecycle
        // event passed through the driver.
        let mut swept_pair = negotiated_bridge();
        let swept_key = (swept_pair.inner_conn, swept_pair.stream);
        let (mut swept, action) = promotion_driver(&swept_pair, false);
        execute(&mut swept, action, &mut swept_pair.local);
        let promoted = circuit_id(&swept, swept_key);
        swept_pair
            .local
            .swarm
            .transport_mut()
            .close(promoted)
            .expect("transport-side close");
        swept.pump(&mut swept_pair.local.swarm);
        assert!(swept.promoted.is_empty());
    }
}
