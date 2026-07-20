//! Facade wiring for pubsub discovery and NAT traversal.

use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

use minip2p_core::PeerId;
use minip2p_discovery::{DiscoveryAction, DiscoveryAgent, DiscoveryEvent};
use minip2p_nat::{ConnectId, NatEvent, Path};
use minip2p_pubsub::PubsubEvent;
use minip2p_quic::QuicEndpoint;
use minip2p_swarm::{Swarm, SwarmEvent};
use minip2p_transport::StreamId;

use crate::{Error, nat::NatDriver, pubsub::PubsubDriver};

/// Errors from discovery-focused endpoint waits.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// Discovery was not enabled with the endpoint builder.
    #[error("discovery is not enabled on this endpoint (EndpointBuilder::discovery)")]
    NotEnabled,
    /// The endpoint failed while driving the swarm.
    #[error(transparent)]
    Driver(#[from] Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BridgeState {
    Live {
        connect_id: ConnectId,
        target_peer: PeerId,
    },
    Tombstone,
}

/// Coordinates beacon traffic, automatic NAT connects, and released bridges.
pub(crate) struct DiscoveryDriver {
    pub(crate) agent: DiscoveryAgent,
    pub(crate) events: VecDeque<DiscoveryEvent>,
    epoch: Instant,
    pub(crate) inflight: BTreeMap<ConnectId, PeerId>,
    pub(crate) bridges: BTreeMap<(PeerId, StreamId), BridgeState>,
    last_local_addrs: Vec<minip2p_core::Multiaddr>,
}

impl DiscoveryDriver {
    pub(crate) fn new(agent: DiscoveryAgent) -> Self {
        Self {
            agent,
            events: VecDeque::new(),
            epoch: Instant::now(),
            inflight: BTreeMap::new(),
            bridges: BTreeMap::new(),
            last_local_addrs: Vec::new(),
        }
    }

    pub(crate) fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Observes lifecycle events regardless of which protocol driver claims them.
    pub(crate) fn observe(&mut self, event: &SwarmEvent) {
        let now = self.now_ms();
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                // A second establishment supersedes the relay connection that
                // owned any tracked stream ids.
                self.bridges.retain(|(relay, _), _| relay != peer_id);
                self.agent.peer_connected(peer_id, now);
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                self.bridges.retain(|(relay, _), _| relay != peer_id);
                self.agent.peer_disconnected(peer_id, now);
            }
            _ => {}
        }
    }

    /// Claims data and terminal events for released bridges discovery owns.
    pub(crate) fn ingest(&mut self, event: &SwarmEvent) -> bool {
        let key = match event {
            SwarmEvent::StreamData {
                peer_id, stream_id, ..
            }
            | SwarmEvent::StreamRemoteWriteClosed {
                peer_id, stream_id, ..
            }
            | SwarmEvent::StreamClosed {
                peer_id, stream_id, ..
            } => Some((peer_id.clone(), *stream_id)),
            _ => None,
        };
        let Some(key) = key else {
            return false;
        };
        if !self.bridges.contains_key(&key) {
            return false;
        }
        if matches!(event, SwarmEvent::StreamClosed { .. }) {
            self.bridges.remove(&key);
        }
        true
    }

    /// Runs all cross-driver work until no new work is produced.
    pub(crate) fn sweep(
        &mut self,
        pubsub: &mut PubsubDriver,
        nat: &mut NatDriver,
        swarm: &mut Swarm<QuicEndpoint>,
    ) {
        loop {
            let mut progressed = false;
            let now = self.now_ms();

            let local_addrs = swarm.core().local_addresses();
            if self.last_local_addrs != local_addrs {
                self.last_local_addrs = local_addrs.to_vec();
                self.agent.set_local_addrs(local_addrs, now);
                progressed = true;
            }

            let mut retained = VecDeque::new();
            while let Some(event) = pubsub.events.pop_front() {
                let consumed = match &event {
                    PubsubEvent::Message {
                        from,
                        topics,
                        data,
                        signed,
                        ..
                    } if topics.iter().any(|topic| topic == self.agent.topic()) => {
                        self.agent.handle_beacon(from, data, *signed, now);
                        true
                    }
                    PubsubEvent::PeerSubscribed { topic, .. }
                    | PubsubEvent::PeerUnsubscribed { topic, .. }
                        if topic == self.agent.topic() =>
                    {
                        true
                    }
                    _ => false,
                };
                if consumed {
                    progressed = true;
                } else {
                    retained.push_back(event);
                }
            }
            pubsub.events = retained;

            let mut retained = VecDeque::new();
            while let Some(event) = nat.events.pop_front() {
                let connect_id = nat_connect_id(&event);
                if connect_id.is_some_and(|id| self.inflight.contains_key(&id)) {
                    progressed = true;
                    self.handle_nat_event(event, nat, swarm, now);
                } else {
                    retained.push_back(event);
                }
            }
            nat.events = retained;

            if self.agent.next_timeout(now) == Some(0) {
                self.agent.handle_tick(now);
                progressed = true;
            }

            while let Some(action) = self.agent.poll_action() {
                progressed = true;
                match action {
                    DiscoveryAction::PublishBeacon { topic, payload } => {
                        let _ = pubsub.agent.publish(&topic, payload, pubsub.now_ms());
                        pubsub.pump(swarm);
                    }
                    DiscoveryAction::Dial { peer, addrs } => {
                        let id = nat.agent.connect(peer.clone(), addrs, nat.now());
                        nat.pump(swarm);
                        self.inflight.insert(id, peer);
                    }
                    DiscoveryAction::CancelDial { peer } => {
                        self.cancel_peer(&peer, nat, swarm);
                    }
                }
            }
            while let Some(event) = self.agent.poll_event() {
                progressed = true;
                self.events.push_back(event);
            }
            if !progressed {
                break;
            }
        }
    }

    fn handle_nat_event(
        &mut self,
        event: NatEvent,
        _nat: &mut NatDriver,
        swarm: &mut Swarm<QuicEndpoint>,
        now: u64,
    ) {
        match event {
            NatEvent::PathEstablished {
                connect_id,
                peer,
                path,
            } => match path {
                Path::DirectDialed | Path::DirectPunched => {
                    self.inflight.remove(&connect_id);
                    self.agent.dial_succeeded(&peer, now);
                }
                Path::Relayed {
                    relay, stream_id, ..
                } => {
                    self.bridges.insert(
                        (relay, stream_id),
                        BridgeState::Live {
                            connect_id,
                            target_peer: peer,
                        },
                    );
                }
            },
            NatEvent::PathUpgraded {
                connect_id,
                peer,
                from,
                ..
            } => {
                if let Path::Relayed {
                    relay, stream_id, ..
                } = from
                {
                    self.bridges
                        .insert((relay, stream_id), BridgeState::Tombstone);
                }
                self.inflight.remove(&connect_id);
                self.agent.dial_succeeded(&peer, now);
            }
            NatEvent::FellBackToRelay { connect_id, peer } => {
                let keys: Vec<_> = self
                    .bridges
                    .iter()
                    .filter(|(_, state)| {
                        matches!(state, BridgeState::Live { connect_id: id, .. } if *id == connect_id)
                    })
                    .map(|(key, _)| key.clone())
                    .collect();
                for key in keys {
                    if swarm.reset_stream(&key.0, key.1).is_ok() {
                        self.bridges.insert(key, BridgeState::Tombstone);
                    } else {
                        self.bridges.remove(&key);
                    }
                }
                self.inflight.remove(&connect_id);
                self.agent
                    .dial_failed(&peer, "relayed only; direct path required", now);
            }
            NatEvent::ConnectFailed {
                connect_id,
                peer,
                error,
            } => {
                self.inflight.remove(&connect_id);
                self.agent.dial_failed(&peer, &error.to_string(), now);
            }
            NatEvent::HolePunchFailed { .. } => {}
            // `sweep` currently calls this only for variants selected by
            // `nat_connect_id`. Ignore future correlated variants rather
            // than turning a harmless facade-version skew into a panic.
            _ => {}
        }
    }

    fn cancel_peer(&mut self, peer: &PeerId, nat: &mut NatDriver, swarm: &mut Swarm<QuicEndpoint>) {
        let active = self
            .inflight
            .iter()
            .find_map(|(id, candidate)| (candidate == peer).then_some(*id));
        if let Some(id) = active {
            nat.agent.cancel(id, nat.now());
            nat.pump(swarm);
            self.inflight.remove(&id);
            for state in self.bridges.values_mut() {
                if matches!(state, BridgeState::Live { connect_id, .. } if *connect_id == id) {
                    *state = BridgeState::Tombstone;
                }
            }
            return;
        }
        let keys = self.live_bridge_keys_for_peer(peer);
        for key in keys {
            if swarm.reset_stream(&key.0, key.1).is_ok() {
                self.bridges.insert(key, BridgeState::Tombstone);
            } else {
                self.bridges.remove(&key);
            }
        }
    }

    fn live_bridge_keys_for_peer(&self, peer: &PeerId) -> Vec<(PeerId, StreamId)> {
        self.bridges
            .iter()
            .filter(|(_, state)| {
                matches!(state, BridgeState::Live { target_peer, .. } if target_peer == peer)
            })
            .map(|(key, _)| key.clone())
            .collect()
    }

    /// Cancels attempts and suppresses every bridge before raw-swarm handoff.
    pub(crate) fn shutdown(&mut self, nat: &mut NatDriver, swarm: &mut Swarm<QuicEndpoint>) {
        let attempts: Vec<ConnectId> = self.inflight.keys().copied().collect();
        for id in attempts {
            nat.agent.cancel(id, nat.now());
            for state in self.bridges.values_mut() {
                if matches!(state, BridgeState::Live { connect_id, .. } if *connect_id == id) {
                    *state = BridgeState::Tombstone;
                }
            }
        }
        self.inflight.clear();
        nat.pump(swarm);
        let bridges: Vec<_> = self.bridges.keys().cloned().collect();
        for (relay, stream_id) in bridges {
            let _ = swarm.abandon_stream(&relay, stream_id);
        }
        self.bridges.clear();
        self.events.clear();
    }
}

fn nat_connect_id(event: &NatEvent) -> Option<ConnectId> {
    match event {
        NatEvent::PathEstablished { connect_id, .. }
        | NatEvent::PathUpgraded { connect_id, .. }
        | NatEvent::HolePunchFailed { connect_id, .. }
        | NatEvent::FellBackToRelay { connect_id, .. }
        | NatEvent::ConnectFailed { connect_id, .. } => Some(*connect_id),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::time::{Duration, Instant};

    use crate::{Endpoint, Event};
    use minip2p_discovery::DiscoveryConfig;
    use minip2p_identity::Ed25519Keypair;
    use minip2p_nat::{NatAgent, NatConfig, Now};

    fn driver() -> DiscoveryDriver {
        let keypair = Ed25519Keypair::generate();
        let agent = DiscoveryAgent::new(keypair.public_key(), DiscoveryConfig::default()).unwrap();
        DiscoveryDriver::new(agent)
    }

    fn endpoint_with_protocol(protocol: &str) -> Endpoint {
        Endpoint::builder()
            .protocol(protocol)
            .discovery_config(DiscoveryConfig {
                auto_dial: false,
                beacon_interval_ms: 100,
                peer_ttl_ms: 2_000,
                ..DiscoveryConfig::default()
            })
            .expect("valid discovery config")
            .bind_quic("127.0.0.1:0")
            .expect("bind endpoint")
    }

    fn connected_user_stream(protocol: &str) -> (Endpoint, Endpoint, StreamId) {
        let mut a = endpoint_with_protocol(protocol);
        let mut b = endpoint_with_protocol(protocol);
        a.listen().expect("a listens");
        let b_addr = b.listen().expect("b listens");
        let a_peer = a.peer_id().clone();
        let b_peer = b.peer_id().clone();
        a.dial(&b_addr).expect("a dials b");

        let connection_deadline = Instant::now() + Duration::from_secs(10);
        while !a.connected_peers().contains(&b_peer) || !b.connected_peers().contains(&a_peer) {
            assert!(Instant::now() < connection_deadline, "connection timed out");
            let _ = a.next_event(Duration::from_millis(20)).expect("a drives");
            let _ = b.next_event(Duration::from_millis(20)).expect("b drives");
        }

        let stream_id = a.open_stream(&b_peer, protocol).expect("open user stream");
        let ready_deadline = Instant::now() + Duration::from_secs(10);
        let mut a_ready = false;
        let mut b_ready = false;
        while !a_ready || !b_ready {
            assert!(Instant::now() < ready_deadline, "stream setup timed out");
            if let Some(event) = a.next_event(Duration::from_millis(20)).expect("a drives") {
                a_ready |= matches!(
                    event,
                    Event::StreamReady { stream_id: got, .. } if got == stream_id
                );
            }
            if let Some(event) = b.next_event(Duration::from_millis(20)).expect("b drives") {
                b_ready |= matches!(
                    event,
                    Event::StreamReady { stream_id: got, .. } if got == stream_id
                );
            }
        }
        (a, b, stream_id)
    }

    fn is_stream_event(event: &Event, peer: &PeerId, stream_id: StreamId) -> bool {
        matches!(
            event,
            Event::StreamReady { peer_id, stream_id: got, .. }
                | Event::StreamData { peer_id, stream_id: got, .. }
                | Event::StreamRemoteWriteClosed { peer_id, stream_id: got, .. }
                | Event::StreamClosed { peer_id, stream_id: got, .. }
                if peer_id == peer && *got == stream_id
        )
    }

    #[test]
    fn bridge_events_are_claimed_through_terminal_close() {
        let mut driver = driver();
        let relay = Ed25519Keypair::generate().peer_id();
        let target = Ed25519Keypair::generate().peer_id();
        let mut nat = NatAgent::new(driver.agent.local_peer_id().clone(), NatConfig::default());
        let connect_id = nat.connect(
            target.clone(),
            Vec::new(),
            Now {
                mono_ms: 0,
                unix_secs: None,
            },
        );
        let stream_id = StreamId::new(7);
        driver.bridges.insert(
            (relay.clone(), stream_id),
            BridgeState::Live {
                connect_id,
                target_peer: target,
            },
        );
        assert!(driver.ingest(&SwarmEvent::StreamData {
            peer_id: relay.clone(),
            conn_id: minip2p_transport::ConnectionId::new(1),
            stream_id,
            data: vec![1],
        }));
        assert!(driver.ingest(&SwarmEvent::StreamRemoteWriteClosed {
            peer_id: relay.clone(),
            conn_id: minip2p_transport::ConnectionId::new(1),
            stream_id,
        }));
        assert!(driver.ingest(&SwarmEvent::StreamClosed {
            peer_id: relay,
            conn_id: minip2p_transport::ConnectionId::new(1),
            stream_id,
        }));
        assert!(driver.bridges.is_empty());
    }

    #[test]
    fn relay_lifecycle_clears_live_and_tombstone_stream_ids() {
        let mut driver = driver();
        let relay = Ed25519Keypair::generate().peer_id();
        driver
            .bridges
            .insert((relay.clone(), StreamId::new(1)), BridgeState::Tombstone);
        driver.observe(&SwarmEvent::ConnectionEstablished {
            peer_id: relay.clone(),
            conn_id: minip2p_transport::ConnectionId::new(1),
        });
        assert!(driver.bridges.is_empty());
        driver
            .bridges
            .insert((relay.clone(), StreamId::new(2)), BridgeState::Tombstone);
        driver.observe(&SwarmEvent::ConnectionClosed {
            peer_id: relay,
            conn_id: minip2p_transport::ConnectionId::new(1),
        });
        assert!(driver.bridges.is_empty());
    }

    #[test]
    fn orphan_bridge_selection_is_scoped_to_target_peer() {
        let mut driver = driver();
        let target = Ed25519Keypair::generate().peer_id();
        let unrelated = Ed25519Keypair::generate().peer_id();
        let target_relay = Ed25519Keypair::generate().peer_id();
        let unrelated_relay = Ed25519Keypair::generate().peer_id();
        let mut nat = NatAgent::new(driver.agent.local_peer_id().clone(), NatConfig::default());
        let target_id = nat.connect(
            target.clone(),
            Vec::new(),
            Now {
                mono_ms: 0,
                unix_secs: None,
            },
        );
        let unrelated_id = nat.connect(
            unrelated.clone(),
            Vec::new(),
            Now {
                mono_ms: 1,
                unix_secs: None,
            },
        );
        driver.bridges.insert(
            (target_relay.clone(), StreamId::new(1)),
            BridgeState::Live {
                connect_id: target_id,
                target_peer: target.clone(),
            },
        );
        driver.bridges.insert(
            (unrelated_relay, StreamId::new(2)),
            BridgeState::Live {
                connect_id: unrelated_id,
                target_peer: unrelated,
            },
        );

        let selected = driver.live_bridge_keys_for_peer(&target);
        assert_eq!(selected, vec![(target_relay, StreamId::new(1))]);
    }

    #[test]
    fn fallback_and_both_cancel_arms_update_bridge_ownership() {
        let mut endpoint = endpoint_with_protocol("/test/discovery-driver/1");
        let relay = Ed25519Keypair::generate().peer_id();
        let target = Ed25519Keypair::generate().peer_id();
        let fallback_id = endpoint.nat.as_mut().expect("NAT enabled").agent.connect(
            target.clone(),
            Vec::new(),
            Now::from_mono(0),
        );
        {
            let Endpoint {
                swarm,
                nat,
                discovery,
                ..
            } = &mut endpoint;
            let nat = nat.as_mut().expect("NAT enabled");
            let discovery = discovery.as_mut().expect("discovery enabled");
            discovery.inflight.insert(fallback_id, target.clone());
            discovery.bridges.insert(
                (relay.clone(), StreamId::new(10)),
                BridgeState::Live {
                    connect_id: fallback_id,
                    target_peer: target.clone(),
                },
            );
            discovery.handle_nat_event(
                NatEvent::FellBackToRelay {
                    connect_id: fallback_id,
                    peer: target.clone(),
                },
                nat,
                swarm,
                1,
            );
            assert!(!discovery.inflight.contains_key(&fallback_id));
            assert!(
                !discovery
                    .bridges
                    .contains_key(&(relay.clone(), StreamId::new(10))),
                "a synchronous reset failure must drop the bridge"
            );
        }

        let active_target = Ed25519Keypair::generate().peer_id();
        let active_id = endpoint.nat.as_mut().expect("NAT enabled").agent.connect(
            active_target.clone(),
            Vec::new(),
            Now::from_mono(2),
        );
        {
            let Endpoint {
                swarm,
                nat,
                discovery,
                ..
            } = &mut endpoint;
            let nat = nat.as_mut().expect("NAT enabled");
            let discovery = discovery.as_mut().expect("discovery enabled");
            discovery.inflight.insert(active_id, active_target.clone());
            discovery.bridges.insert(
                (relay.clone(), StreamId::new(11)),
                BridgeState::Live {
                    connect_id: active_id,
                    target_peer: active_target.clone(),
                },
            );
            discovery.cancel_peer(&active_target, nat, swarm);
            assert!(!discovery.inflight.contains_key(&active_id));
            assert_eq!(
                discovery.bridges.get(&(relay.clone(), StreamId::new(11))),
                Some(&BridgeState::Tombstone),
                "the NAT attempt owns the active bridge reset"
            );
        }

        let orphan_target = Ed25519Keypair::generate().peer_id();
        let orphan_id = endpoint.nat.as_mut().expect("NAT enabled").agent.connect(
            orphan_target.clone(),
            Vec::new(),
            Now::from_mono(3),
        );
        let Endpoint {
            swarm,
            nat,
            discovery,
            ..
        } = &mut endpoint;
        let nat = nat.as_mut().expect("NAT enabled");
        let discovery = discovery.as_mut().expect("discovery enabled");
        discovery.bridges.insert(
            (relay.clone(), StreamId::new(12)),
            BridgeState::Live {
                connect_id: orphan_id,
                target_peer: orphan_target.clone(),
            },
        );
        discovery.cancel_peer(&orphan_target, nat, swarm);
        assert!(
            !discovery.bridges.contains_key(&(relay, StreamId::new(12))),
            "an orphan bridge with a rejected reset must be dropped"
        );
    }

    #[test]
    fn relayed_path_upgrade_tombstones_the_released_bridge() {
        let mut endpoint = endpoint_with_protocol("/test/discovery-upgrade/1");
        let relay = Ed25519Keypair::generate().peer_id();
        let target = Ed25519Keypair::generate().peer_id();
        let stream_id = StreamId::new(20);
        let connect_id = endpoint.nat.as_mut().expect("NAT enabled").agent.connect(
            target.clone(),
            Vec::new(),
            Now::from_mono(0),
        );
        let relayed = Path::Relayed {
            relay: relay.clone(),
            stream_id,
            pending_data: Vec::new(),
            remote_write_closed: false,
        };
        let Endpoint {
            swarm,
            nat,
            discovery,
            ..
        } = &mut endpoint;
        let nat = nat.as_mut().expect("NAT enabled");
        let discovery = discovery.as_mut().expect("discovery enabled");
        discovery.inflight.insert(connect_id, target.clone());
        discovery.handle_nat_event(
            NatEvent::PathEstablished {
                connect_id,
                peer: target.clone(),
                path: relayed.clone(),
            },
            nat,
            swarm,
            0,
        );
        assert!(matches!(
            discovery.bridges.get(&(relay.clone(), stream_id)),
            Some(BridgeState::Live { .. })
        ));

        discovery.handle_nat_event(
            NatEvent::PathUpgraded {
                connect_id,
                peer: target,
                from: relayed,
                to: Path::DirectPunched,
            },
            nat,
            swarm,
            1,
        );
        assert!(!discovery.inflight.contains_key(&connect_id));
        assert_eq!(
            discovery.bridges.get(&(relay, stream_id)),
            Some(&BridgeState::Tombstone)
        );
    }

    #[test]
    fn real_bridge_fallback_resets_and_claims_terminal_events() {
        const PROTOCOL: &str = "/test/discovery-real-bridge/1";
        let (mut owner, mut remote, stream_id) = connected_user_stream(PROTOCOL);
        let relay = remote.peer_id().clone();
        let target = Ed25519Keypair::generate().peer_id();
        let connect_id = owner.nat.as_mut().expect("NAT enabled").agent.connect(
            target.clone(),
            Vec::new(),
            Now::from_mono(0),
        );

        {
            let Endpoint {
                swarm,
                nat,
                discovery,
                ..
            } = &mut owner;
            let nat = nat.as_mut().expect("NAT enabled");
            let discovery = discovery.as_mut().expect("discovery enabled");
            discovery.inflight.insert(connect_id, target.clone());
            discovery.handle_nat_event(
                NatEvent::PathEstablished {
                    connect_id,
                    peer: target.clone(),
                    path: Path::Relayed {
                        relay: relay.clone(),
                        stream_id,
                        pending_data: Vec::new(),
                        remote_write_closed: false,
                    },
                },
                nat,
                swarm,
                0,
            );
        }
        remote
            .send_stream(owner.peer_id(), stream_id, b"bridge payload".to_vec())
            .expect("remote sends bridge data");
        remote
            .close_stream_write(owner.peer_id(), stream_id)
            .expect("remote closes bridge write side");
        {
            let Endpoint {
                swarm,
                nat,
                discovery,
                ..
            } = &mut owner;
            let nat = nat.as_mut().expect("NAT enabled");
            let discovery = discovery.as_mut().expect("discovery enabled");
            discovery.handle_nat_event(
                NatEvent::FellBackToRelay {
                    connect_id,
                    peer: target,
                },
                nat,
                swarm,
                1,
            );
            assert_eq!(
                discovery.bridges.get(&(relay.clone(), stream_id)),
                Some(&BridgeState::Tombstone),
                "the real stream reset must succeed"
            );
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            let _ = remote
                .next_event(Duration::from_millis(10))
                .expect("remote drives");
            if let Some(event) = owner
                .next_event(Duration::from_millis(10))
                .expect("owner drives")
            {
                assert!(
                    !is_stream_event(&event, &relay, stream_id),
                    "bridge event leaked after designation: {event:?}"
                );
            }
        }
    }

    #[test]
    fn into_swarm_suppresses_queued_and_future_bridge_events() {
        const PROTOCOL: &str = "/test/discovery-into-swarm/1";
        let (mut owner, mut remote, stream_id) = connected_user_stream(PROTOCOL);
        let relay = remote.peer_id().clone();
        let target = Ed25519Keypair::generate().peer_id();
        let connect_id = owner.nat.as_mut().expect("NAT enabled").agent.connect(
            target.clone(),
            Vec::new(),
            Now::from_mono(0),
        );
        owner
            .discovery
            .as_mut()
            .expect("discovery enabled")
            .bridges
            .insert(
                (relay.clone(), stream_id),
                BridgeState::Live {
                    connect_id,
                    target_peer: target,
                },
            );

        remote
            .send_stream(owner.peer_id(), stream_id, b"queued bridge data".to_vec())
            .expect("remote sends queued data");
        let saw_queued_stream_event = Cell::new(false);
        owner
            .swarm_mut()
            .run_until(Instant::now() + Duration::from_millis(500), |event| {
                if is_stream_event(event, &relay, stream_id) {
                    saw_queued_stream_event.set(true);
                }
                false
            })
            .expect("queue raw stream event");
        assert!(
            saw_queued_stream_event.get(),
            "the handoff test must begin with a queued bridge event"
        );

        let owner_peer = owner.peer_id().clone();
        let mut swarm = owner.into_swarm();
        let _ = remote.close_stream_write(&owner_peer, stream_id);
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            let _ = remote
                .next_event(Duration::from_millis(10))
                .expect("remote drives");
            if let Some(event) = swarm
                .poll_next(Duration::from_millis(10))
                .expect("raw swarm drives")
            {
                assert!(
                    !is_stream_event(&event, &relay, stream_id),
                    "abandoned bridge event leaked after handoff: {event:?}"
                );
            }
        }
    }

    #[test]
    fn endpoint_abandon_stream_purges_focused_wait_buffer_and_future_events() {
        const PROTOCOL: &str = "/test/endpoint-abandon/1";
        let (mut owner, mut remote, stream_id) = connected_user_stream(PROTOCOL);
        let remote_peer = remote.peer_id().clone();

        remote
            .send_stream(owner.peer_id(), stream_id, b"buffer me".to_vec())
            .expect("remote sends stream data");
        let buffer_deadline = Instant::now() + Duration::from_secs(2);
        while !owner
            .pending_events
            .iter()
            .any(|event| is_stream_event(event, &remote_peer, stream_id))
        {
            assert!(
                Instant::now() < buffer_deadline,
                "focused wait did not buffer the stream event"
            );
            let _ = remote
                .next_event(Duration::from_millis(10))
                .expect("remote drives");
            let _ = owner
                .next_discovery_event(Duration::from_millis(10))
                .expect("focused wait drives owner");
        }

        owner
            .abandon_stream(&remote_peer, stream_id)
            .expect("owner abandons stream");
        assert!(
            !owner.pending_events.iter().any(|event| is_stream_event(
                event,
                &remote_peer,
                stream_id
            )),
            "abandon must purge the endpoint-focused-wait buffer"
        );

        remote
            .close_stream_write(owner.peer_id(), stream_id)
            .expect("remote closes stream write side");
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            let _ = remote
                .next_event(Duration::from_millis(10))
                .expect("remote drives");
            if let Some(event) = owner
                .next_event(Duration::from_millis(10))
                .expect("owner drives")
            {
                assert!(
                    !is_stream_event(&event, &remote_peer, stream_id),
                    "abandoned stream event leaked through Endpoint: {event:?}"
                );
            }
        }
    }

    #[test]
    fn topic_bound_stays_in_lockstep_with_pubsub() {
        assert_eq!(
            minip2p_discovery::MAX_TOPIC_LEN,
            minip2p_pubsub::MAX_TOPIC_LEN
        );
    }
}
