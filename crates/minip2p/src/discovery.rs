//! Endpoint coordination for discovery sources and NAT traversal.

use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

use minip2p_core::PeerId;
#[cfg(feature = "discovery")]
use minip2p_discovery::{BeaconAction, BeaconAgent, BeaconEvent};
use minip2p_discovery::{DiscoveryAction, DiscoverySource, PeerDiscoveryAgent};
#[cfg(feature = "mdns")]
use minip2p_mdns::MdnsEvent;
use minip2p_nat::{ConnectId, NatEvent};
#[cfg(feature = "discovery")]
use minip2p_pubsub::PubsubEvent;
use minip2p_swarm::SwarmEvent;

use crate::EndpointSwarm;
#[cfg(feature = "mdns")]
use crate::mdns::MdnsDriver;
#[cfg(feature = "discovery")]
use crate::pubsub::PubsubDriver;
use crate::{Error, nat::NatDriver};

/// Errors from discovery-focused endpoint waits.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// No discovery source was enabled with the endpoint builder.
    #[error("discovery is not enabled on this endpoint")]
    NotEnabled,
    /// The endpoint failed while driving the swarm.
    #[error(transparent)]
    Driver(#[from] Error),
}

/// Coordinates source observations, the shared peer book, and automatic connects.
pub(crate) struct DiscoveryDriver {
    pub(crate) book: PeerDiscoveryAgent,
    #[cfg(feature = "discovery")]
    pub(crate) beacon: Option<BeaconAgent>,
    epoch: Instant,
    pub(crate) inflight: BTreeMap<ConnectId, PeerId>,
    #[cfg(feature = "discovery")]
    last_local_addrs: Vec<minip2p_core::Multiaddr>,
}

impl DiscoveryDriver {
    pub(crate) fn new(
        book: PeerDiscoveryAgent,
        #[cfg(feature = "discovery")] beacon: Option<BeaconAgent>,
    ) -> Self {
        Self {
            book,
            #[cfg(feature = "discovery")]
            beacon,
            epoch: Instant::now(),
            inflight: BTreeMap::new(),
            #[cfg(feature = "discovery")]
            last_local_addrs: Vec::new(),
        }
    }

    pub(crate) fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    #[cfg(feature = "discovery")]
    pub(crate) fn topic(&self) -> Option<&str> {
        self.beacon.as_ref().map(BeaconAgent::topic)
    }

    pub(crate) fn next_timeout(&self, now_ms: u64) -> Option<u64> {
        #[allow(unused_mut)]
        let mut timeout = self.book.next_timeout(now_ms);
        #[cfg(feature = "discovery")]
        if let Some(beacon) = self.beacon.as_ref()
            && let Some(beacon_timeout) = beacon.next_timeout(now_ms)
        {
            timeout = Some(
                timeout
                    .map(|book_timeout| book_timeout.min(beacon_timeout))
                    .unwrap_or(beacon_timeout),
            );
        }
        timeout
    }

    /// Observes lifecycle events regardless of which protocol driver claims them.
    pub(crate) fn observe(&mut self, event: &SwarmEvent, swarm: &EndpointSwarm) {
        let now = self.now_ms();
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                self.book.peer_connected(peer_id, now);
            }
            SwarmEvent::ConnectionClosed { peer_id, .. }
                if swarm.core().conn_for(peer_id).is_none() =>
            {
                self.book.peer_disconnected(peer_id, now);
            }
            _ => {}
        }
    }

    /// Runs all cross-driver work until no new work is produced.
    pub(crate) fn sweep(
        &mut self,
        #[cfg(feature = "discovery")] mut pubsub: Option<&mut PubsubDriver>,
        #[cfg(feature = "mdns")] mut mdns: Option<&mut MdnsDriver>,
        nat: &mut NatDriver,
        swarm: &mut EndpointSwarm,
    ) {
        loop {
            let mut progressed = false;
            let now = self.now_ms();

            #[cfg(feature = "discovery")]
            if let Some(beacon) = self.beacon.as_mut() {
                let local_addrs = swarm.core().local_addresses();
                if self.last_local_addrs != local_addrs {
                    self.last_local_addrs = local_addrs.to_vec();
                    beacon.set_local_addrs(local_addrs, now);
                    progressed = true;
                }
                if let Some(pubsub) = pubsub.as_deref_mut() {
                    let mut retained = VecDeque::new();
                    while let Some(event) = pubsub.events.pop_front() {
                        let consumed = match &event {
                            PubsubEvent::Message {
                                from,
                                topics,
                                data,
                                signed,
                                ..
                            } if topics.iter().any(|topic| topic == beacon.topic()) => {
                                beacon.handle_beacon(from, data, *signed);
                                true
                            }
                            PubsubEvent::PeerSubscribed { topic, .. }
                            | PubsubEvent::PeerUnsubscribed { topic, .. }
                                if topic == beacon.topic() =>
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
                }
            }

            #[cfg(feature = "mdns")]
            if let Some(mdns) = mdns.as_deref_mut() {
                while let Some(event) = mdns.events.pop_front() {
                    progressed = true;
                    self.handle_mdns_event(event, now);
                }
            }

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

            #[cfg(feature = "discovery")]
            if let Some(beacon) = self.beacon.as_mut()
                && beacon.next_timeout(now) == Some(0)
            {
                beacon.handle_tick(now);
                progressed = true;
            }
            if self.book.next_timeout(now) == Some(0) {
                self.book.handle_tick(now);
                progressed = true;
            }

            #[cfg(feature = "discovery")]
            if let Some(beacon) = self.beacon.as_mut() {
                while let Some(event) = beacon.poll_event() {
                    progressed = true;
                    match event {
                        BeaconEvent::Observation(observation) => {
                            self.book.observe_beacon(observation, now);
                        }
                        BeaconEvent::ProtocolViolation { peer, reason } => {
                            self.book.report_violation(
                                Some(peer),
                                DiscoverySource::SignedBeacon,
                                &reason,
                            );
                        }
                    }
                }
                while let Some(action) = beacon.poll_action() {
                    progressed = true;
                    match action {
                        BeaconAction::PublishBeacon { topic, payload } => {
                            if let Some(pubsub) = pubsub.as_deref_mut() {
                                let _ = pubsub.agent.publish(&topic, payload, pubsub.now_ms());
                                pubsub.pump(swarm);
                            }
                        }
                    }
                }
            }
            while let Some(action) = self.book.poll_action() {
                progressed = true;
                match action {
                    DiscoveryAction::Dial {
                        peer,
                        addrs,
                        source,
                    } => {
                        let id = match source {
                            DiscoverySource::SignedBeacon => {
                                nat.agent.connect(peer.clone(), addrs, nat.now())
                            }
                            DiscoverySource::Mdns => {
                                nat.agent.connect_direct(peer.clone(), addrs, nat.now())
                            }
                        };
                        nat.pump(swarm);
                        self.inflight.insert(id, peer);
                    }
                    DiscoveryAction::CancelDial { peer } => {
                        self.cancel_peer(&peer, nat, swarm);
                    }
                }
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
                self.book.dial_succeeded(&peer, now);
            }
            NatEvent::ConnectFailed {
                connect_id,
                peer,
                error,
            } => {
                self.inflight.remove(&connect_id);
                self.book.dial_failed(&peer, &error.to_string(), now);
            }
            NatEvent::HolePunchFailed { .. } => {}
            _ => {}
        }
    }

    #[cfg(feature = "mdns")]
    fn handle_mdns_event(&mut self, event: MdnsEvent, now: u64) {
        match event {
            MdnsEvent::PeerObserved { peer, addrs } => {
                self.book.observe_mdns(peer, addrs, now);
            }
            MdnsEvent::ProtocolViolation { peer, reason } => {
                self.book
                    .report_violation(peer, DiscoverySource::Mdns, &reason);
            }
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

    /// Cancels all discovery-owned attempts during endpoint shutdown.
    #[cfg(feature = "mdns")]
    pub(crate) fn shutdown(&mut self, nat: &mut NatDriver, swarm: &mut EndpointSwarm) {
        let attempts: Vec<ConnectId> = self.inflight.keys().copied().collect();
        for id in attempts {
            nat.agent.cancel(id, nat.now());
        }
        self.inflight.clear();
        self.book.reset_dials();
        nat.pump(swarm);
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

#[cfg(all(test, feature = "mdns"))]
mod tests {
    use super::*;
    use core::str::FromStr;
    use minip2p_core::Multiaddr;
    use minip2p_discovery::{DiscoveryEvent, PeerDiscoveryConfig};
    use minip2p_identity::{KeyType, PublicKey};

    fn peer(byte: u8) -> PeerId {
        PeerId::from_public_key(&PublicKey::new(KeyType::Ed25519, vec![byte; 32]))
    }

    #[test]
    fn mdns_events_feed_the_shared_book_without_multicast_io() {
        let config = PeerDiscoveryConfig {
            dial_tie_break: false,
            ..PeerDiscoveryConfig::default()
        };
        let book = PeerDiscoveryAgent::new(peer(1), config).expect("valid policy");
        let mut driver = DiscoveryDriver::new(
            book,
            #[cfg(feature = "discovery")]
            None,
        );
        let remote = peer(2);
        let addr = Multiaddr::from_str("/ip4/192.0.2.2/udp/4001/quic-v1")
            .expect("valid transport address");

        driver.handle_mdns_event(
            MdnsEvent::PeerObserved {
                peer: remote.clone(),
                addrs: vec![(addr.clone(), 1_000)],
            },
            0,
        );

        assert!(matches!(
            driver.book.poll_event(),
            Some(DiscoveryEvent::PeerDiscovered {
                peer,
                addrs,
                source: DiscoverySource::Mdns,
            }) if peer == remote && addrs == vec![addr]
        ));
        assert!(matches!(
            driver.book.poll_action(),
            Some(DiscoveryAction::Dial {
                peer,
                source: DiscoverySource::Mdns,
                ..
            }) if peer == remote
        ));

        driver.handle_mdns_event(
            MdnsEvent::ProtocolViolation {
                peer: Some(remote.clone()),
                reason: "invalid claim".into(),
            },
            1,
        );
        assert!(matches!(
            driver.book.poll_event(),
            Some(DiscoveryEvent::ProtocolViolation {
                peer: Some(peer),
                source: DiscoverySource::Mdns,
                ..
            }) if peer == remote
        ));
    }
}
