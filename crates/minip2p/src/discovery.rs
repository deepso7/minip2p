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
            SwarmEvent::ConnectionEstablished { peer_id } => {
                // A second establishment supersedes the relay connection that
                // owned any tracked stream ids.
                self.bridges.retain(|(relay, _), _| relay != peer_id);
                self.agent.peer_connected(peer_id, now);
            }
            SwarmEvent::ConnectionClosed { peer_id } => {
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
            | SwarmEvent::StreamRemoteWriteClosed { peer_id, stream_id }
            | SwarmEvent::StreamClosed { peer_id, stream_id } => {
                Some((peer_id.clone(), *stream_id))
            }
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
            _ => unreachable!("only connect-correlated NAT events are harvested"),
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
    use minip2p_discovery::DiscoveryConfig;
    use minip2p_identity::Ed25519Keypair;
    use minip2p_nat::{NatAgent, NatConfig, Now};

    fn driver() -> DiscoveryDriver {
        let keypair = Ed25519Keypair::generate();
        let agent = DiscoveryAgent::new(keypair.public_key(), DiscoveryConfig::default()).unwrap();
        DiscoveryDriver::new(agent)
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
            stream_id,
            data: vec![1],
        }));
        assert!(driver.ingest(&SwarmEvent::StreamRemoteWriteClosed {
            peer_id: relay.clone(),
            stream_id,
        }));
        assert!(driver.ingest(&SwarmEvent::StreamClosed {
            peer_id: relay,
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
        });
        assert!(driver.bridges.is_empty());
        driver
            .bridges
            .insert((relay.clone(), StreamId::new(2)), BridgeState::Tombstone);
        driver.observe(&SwarmEvent::ConnectionClosed { peer_id: relay });
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
    fn topic_bound_stays_in_lockstep_with_pubsub() {
        assert_eq!(
            minip2p_discovery::MAX_TOPIC_LEN,
            minip2p_pubsub::MAX_TOPIC_LEN
        );
    }
}
