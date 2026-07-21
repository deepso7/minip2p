//! Facade wiring for pubsub discovery and NAT traversal.

use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

use minip2p_core::PeerId;
use minip2p_discovery::{DiscoveryAction, DiscoveryAgent, DiscoveryEvent};
use minip2p_nat::{ConnectId, NatEvent};
use minip2p_pubsub::PubsubEvent;
use minip2p_swarm::SwarmEvent;

use crate::EndpointSwarm;
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

/// Coordinates beacon traffic and automatic NAT connects.
pub(crate) struct DiscoveryDriver {
    pub(crate) agent: DiscoveryAgent,
    pub(crate) events: VecDeque<DiscoveryEvent>,
    epoch: Instant,
    pub(crate) inflight: BTreeMap<ConnectId, PeerId>,
    last_local_addrs: Vec<minip2p_core::Multiaddr>,
}

impl DiscoveryDriver {
    pub(crate) fn new(agent: DiscoveryAgent) -> Self {
        Self {
            agent,
            events: VecDeque::new(),
            epoch: Instant::now(),
            inflight: BTreeMap::new(),
            last_local_addrs: Vec::new(),
        }
    }

    pub(crate) fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Observes lifecycle events regardless of which protocol driver claims them.
    pub(crate) fn observe(&mut self, event: &SwarmEvent, swarm: &EndpointSwarm) {
        let now = self.now_ms();
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                self.agent.peer_connected(peer_id, now);
            }
            SwarmEvent::ConnectionClosed { peer_id, .. }
                if swarm.core().conn_for(peer_id).is_none() =>
            {
                // Eager supersession surfaces Closed(old) before
                // Established(new), but the core has already installed the
                // replacement. Preserve discovery continuity in that case.
                self.agent.peer_disconnected(peer_id, now);
            }
            _ => {}
        }
    }

    /// Runs all cross-driver work until no new work is produced.
    pub(crate) fn sweep(
        &mut self,
        pubsub: &mut PubsubDriver,
        nat: &mut NatDriver,
        swarm: &mut EndpointSwarm,
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
                    self.handle_nat_event(event, now);
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

    fn handle_nat_event(&mut self, event: NatEvent, now: u64) {
        match event {
            NatEvent::PathEstablished {
                connect_id, peer, ..
            }
            | NatEvent::PathUpgraded {
                connect_id, peer, ..
            }
            | NatEvent::FellBackToRelay { connect_id, peer } => {
                self.inflight.remove(&connect_id);
                self.agent.dial_succeeded(&peer, now);
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
            // `sweep` calls this only for variants selected by
            // `nat_connect_id`. Ignore future correlated variants rather
            // than turning harmless facade-version skew into a panic.
            _ => {}
        }
    }

    fn cancel_peer(&mut self, peer: &PeerId, nat: &mut NatDriver, swarm: &mut EndpointSwarm) {
        let active = self
            .inflight
            .iter()
            .find_map(|(id, candidate)| (candidate == peer).then_some(*id));
        if let Some(id) = active {
            nat.agent.cancel(id, nat.now());
            nat.pump(swarm);
            self.inflight.remove(&id);
        }
    }

    /// Cancels all discovery-owned attempts before raw-swarm handoff.
    pub(crate) fn shutdown(&mut self, nat: &mut NatDriver, swarm: &mut EndpointSwarm) {
        let attempts: Vec<ConnectId> = self.inflight.keys().copied().collect();
        for id in attempts {
            nat.agent.cancel(id, nat.now());
        }
        self.inflight.clear();
        nat.pump(swarm);
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
    use std::time::{Duration, Instant};

    use minip2p_discovery::{DiscoveryAction, DiscoveryConfig};
    use minip2p_identity::{Ed25519Keypair, PeerId as IdentityPeerId, PublicKey};
    use minip2p_nat::{NatAgent, NatConfig, Now, Path};
    use minip2p_transport::StreamId;

    use super::*;
    use crate::{Endpoint, Event};

    fn discovery_beacon(keypair: &Ed25519Keypair) -> (PeerId, Vec<u8>) {
        let mut agent = DiscoveryAgent::new(
            PublicKey::from(keypair),
            DiscoveryConfig {
                auto_dial: false,
                ..DiscoveryConfig::default()
            },
        )
        .expect("valid remote discovery agent");
        agent.set_local_addrs(
            &["/ip4/127.0.0.1/udp/4001/quic-v1"
                .parse()
                .expect("valid beacon address")],
            0,
        );
        agent.handle_tick(0);
        let payload = loop {
            match agent.poll_action() {
                Some(DiscoveryAction::PublishBeacon { payload, .. }) => break payload,
                Some(_) => continue,
                None => panic!("beacon was not published"),
            }
        };
        (IdentityPeerId::from(keypair), payload)
    }

    fn discovery_with_inflight() -> (DiscoveryDriver, ConnectId, PeerId, PeerId) {
        let local_key = Ed25519Keypair::from_secret_key_bytes([91; 32]);
        let remote_key = Ed25519Keypair::from_secret_key_bytes([92; 32]);
        let local = IdentityPeerId::from(&local_key);
        let (remote, payload) = discovery_beacon(&remote_key);
        let mut driver = DiscoveryDriver::new(
            DiscoveryAgent::new(
                PublicKey::from(&local_key),
                DiscoveryConfig {
                    dial_tie_break: false,
                    ..DiscoveryConfig::default()
                },
            )
            .expect("valid discovery agent"),
        );
        driver.agent.handle_beacon(&remote, &payload, true, 1);
        assert!(matches!(
            driver.agent.poll_event(),
            Some(DiscoveryEvent::PeerDiscovered { peer, .. }) if peer == remote
        ));
        assert!(matches!(
            driver.agent.poll_action(),
            Some(DiscoveryAction::Dial { peer, .. }) if peer == remote
        ));

        let mut nat = NatAgent::new(local, NatConfig::default());
        let connect_id = nat.connect(remote.clone(), Vec::new(), Now::from_mono(0));
        driver.inflight.insert(connect_id, remote.clone());
        let relay = PeerId::from_public_key_protobuf(
            &PublicKey::from(&Ed25519Keypair::from_secret_key_bytes([93; 32])).encode_protobuf(),
        );
        (driver, connect_id, remote, relay)
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

    #[test]
    fn relayed_success_variants_complete_discovery_owned_dials() {
        for fell_back in [false, true] {
            let (mut driver, connect_id, remote, relay) = discovery_with_inflight();
            let event = if fell_back {
                NatEvent::FellBackToRelay {
                    connect_id,
                    peer: remote.clone(),
                }
            } else {
                NatEvent::PathEstablished {
                    connect_id,
                    peer: remote.clone(),
                    path: Path::Relayed { relay },
                }
            };
            driver.handle_nat_event(event, 2);

            assert!(!driver.inflight.contains_key(&connect_id));
            driver.agent.dial_failed(&remote, "must already be idle", 3);
            assert!(
                driver.agent.poll_event().is_none(),
                "successful relayed completion must collapse the discovery dial state"
            );
        }
    }

    #[test]
    fn eager_supersede_close_preserves_discovery_connectivity() {
        let a_key = Ed25519Keypair::from_secret_key_bytes([94; 32]);
        let b_key = Ed25519Keypair::from_secret_key_bytes([95; 32]);
        let (b_peer, beacon) = discovery_beacon(&b_key);
        let config = DiscoveryConfig {
            dial_tie_break: false,
            beacon_interval_ms: 100,
            peer_ttl_ms: 2_000,
            ..DiscoveryConfig::default()
        };
        let mut a = Endpoint::builder()
            .identity(a_key)
            .discovery_config(config.clone())
            .expect("valid discovery config")
            .bind_quic("127.0.0.1:0")
            .expect("bind a");
        let mut b = Endpoint::builder()
            .identity(b_key)
            .discovery_config(config)
            .expect("valid discovery config")
            .bind_quic("127.0.0.1:0")
            .expect("bind b");
        a.listen().expect("a listens");
        let b_addr = b.listen().expect("b listens");
        a.dial(&b_addr).expect("first dial");

        let deadline = Instant::now() + Duration::from_secs(10);
        while !a.connected_peers().contains(&b_peer) {
            assert!(Instant::now() < deadline, "first connection timed out");
            let _ = a.next_event(Duration::from_millis(20)).expect("drive a");
            let _ = b.next_event(Duration::from_millis(20)).expect("drive b");
        }
        let discovery = a.discovery.as_mut().expect("discovery enabled");
        discovery.agent.handle_beacon(&b_peer, &beacon, true, 1);
        while discovery.agent.poll_event().is_some() {}
        assert!(discovery.agent.poll_action().is_none());

        a.dial(&b_addr).expect("replacement dial");
        let mut saw_old_close = false;
        while !saw_old_close {
            assert!(Instant::now() < deadline, "replacement timed out");
            if let Some(Event::ConnectionClosed { peer_id, .. }) =
                a.next_event(Duration::from_millis(20)).expect("drive a")
            {
                saw_old_close = peer_id == b_peer;
            }
            let _ = b.next_event(Duration::from_millis(20)).expect("drive b");
        }
        assert!(a.swarm.core().conn_for(&b_peer).is_some());

        let discovery = a.discovery.as_mut().expect("discovery enabled");
        discovery.agent.handle_beacon(&b_peer, &beacon, true, 2);
        assert!(
            discovery.agent.poll_action().is_none(),
            "Closed(old) must not make discovery redial while new is installed"
        );
    }
}
