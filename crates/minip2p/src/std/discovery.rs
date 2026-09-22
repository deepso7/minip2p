//! Std endpoint coordination for discovery sources and NAT traversal.

use std::collections::BTreeMap;
#[cfg(feature = "discovery")]
use std::collections::VecDeque;
use std::time::Instant;

use minip2p_core::{ConnectId, PeerId};
#[cfg(feature = "discovery")]
use minip2p_discovery::{BeaconAction, BeaconAgent, BeaconEvent};
use minip2p_discovery::{DiscoveryAction, DiscoverySource, PeerDiscoveryAgent};
#[cfg(feature = "mdns")]
use minip2p_mdns::MdnsEvent;
use minip2p_nat::NatEvent;
#[cfg(feature = "discovery")]
use minip2p_pubsub::GossipsubEvent;
use minip2p_swarm::SwarmEvent;

use super::NatDriver;
#[cfg(feature = "mdns")]
use super::mdns::MdnsDriver;
#[cfg(feature = "discovery")]
use super::pubsub::GossipsubDriver;
use crate::portable::ConnectEngine;
use crate::{ConnectTarget, EndpointSwarm, Error};

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

    /// Whether `event` belongs to a discovery-owned attempt that the sweep
    /// must hide before the Endpoint drains NAT output.
    #[cfg(debug_assertions)]
    pub(crate) fn owns_nat_event(&self, event: &NatEvent) -> bool {
        nat_connect_id(event).is_some_and(|id| self.inflight.contains_key(&id))
    }

    #[cfg(feature = "discovery")]
    pub(crate) fn topic(&self) -> Option<&str> {
        self.beacon.as_ref().map(BeaconAgent::topic)
    }

    pub(crate) fn next_timeout(&self, now_ms: u64) -> Option<u64> {
        #[cfg_attr(
            not(feature = "discovery"),
            expect(
                unused_mut,
                reason = "the discovery beacon feature is the only configuration that refines the book timeout"
            )
        )]
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
        #[cfg(feature = "discovery")] mut pubsub: Option<&mut GossipsubDriver>,
        #[cfg(feature = "mdns")] mut mdns: Option<&mut MdnsDriver>,
        connect: &mut ConnectEngine,
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
                            GossipsubEvent::Message {
                                from,
                                topics,
                                data,
                                signed,
                                ..
                            } if topics.iter().any(|topic| topic == beacon.topic()) => {
                                beacon.handle_beacon(from, data, *signed);
                                true
                            }
                            GossipsubEvent::PeerSubscribed { topic, .. }
                            | GossipsubEvent::PeerUnsubscribed { topic, .. }
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
                while let Some(event) = mdns.poll_event() {
                    progressed = true;
                    self.handle_mdns_event(event, now);
                }
            }

            // Discovery-owned attempt events are hidden from the app, but the
            // engine must observe them first: `admit_connect` below can queue
            // a synchronous `ConnectFailed` in this same sweep after the
            // pre-sweep `feed_nat_to_connect` pass, and the next iteration
            // would otherwise discard it before the engine sees it.
            let now_ms = swarm.now().monotonic_ms;
            let mut i = 0;
            while let Some(event) = nat.events.get(i) {
                let connect_id = nat_connect_id(event);
                if connect_id.is_some_and(|id| self.inflight.contains_key(&id)) {
                    progressed = true;
                    let event = nat.events.remove(i).expect("inflight NAT event");
                    nat.note_removed(i);
                    connect.observe_nat(&event, swarm.runtime_mut(), now_ms);
                } else {
                    i += 1;
                }
            }

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
                                // The beacon is periodic, so a refused local
                                // publish is retried on its next tick.
                                if let Ok(()) =
                                    pubsub.agent.publish(&topic, payload, pubsub.now_ms())
                                {
                                    pubsub.pump(swarm);
                                }
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
                        let allow_relay = source == DiscoverySource::SignedBeacon;
                        let candidates: Vec<minip2p_core::PeerAddr> =
                            minip2p_core::select_direct_addrs(&addrs, None, None)
                                .into_iter()
                                .filter_map(|addr| {
                                    minip2p_core::PeerAddr::new(addr, peer.clone()).ok()
                                })
                                .collect();
                        let target = ConnectTarget::try_from(candidates)
                            .unwrap_or_else(|_| ConnectTarget::from(peer.clone()));
                        let id = super::admit_connect(
                            connect,
                            swarm,
                            Some(nat),
                            Some(&self.book),
                            target,
                            allow_relay,
                        );
                        self.inflight.insert(id, peer);
                    }
                    DiscoveryAction::CancelDial { peer } => {
                        self.cancel_peer(&peer, connect, nat, swarm);
                    }
                }
            }
            if !progressed {
                break;
            }
        }
    }

    fn cancel_peer(
        &mut self,
        peer: &PeerId,
        connect: &mut ConnectEngine,
        nat: &mut NatDriver,
        swarm: &mut EndpointSwarm,
    ) {
        let active = self
            .inflight
            .iter()
            .find_map(|(id, candidate)| (candidate == peer).then_some(*id));
        if let Some(id) = active {
            // Mirror `Endpoint::cancel_connect`: `ConnectEngine::cancel` is a
            // no-op after Connected, but `NatAgent::cancel` would still close a
            // provisional relayed path the engine already settled on.
            let cancel_leg = connect.is_pending(id);
            connect.cancel(id, swarm.runtime_mut());
            if cancel_leg {
                nat.cancel(id, swarm.now());
                let now = swarm.now();
                nat.pump(swarm.runtime_mut(), now);
            }
        }
    }

    /// Cancels all discovery-owned attempts during endpoint shutdown.
    #[cfg(feature = "mdns")]
    pub(crate) fn shutdown(
        &mut self,
        connect: &mut ConnectEngine,
        nat: &mut NatDriver,
        swarm: &mut EndpointSwarm,
    ) {
        let attempts: Vec<ConnectId> = self.inflight.keys().copied().collect();
        let mut cancelled_leg = false;
        for id in attempts {
            let cancel_leg = connect.is_pending(id);
            connect.cancel(id, swarm.runtime_mut());
            if cancel_leg {
                nat.cancel(id, swarm.now());
                cancelled_leg = true;
            }
        }
        self.inflight.clear();
        self.book.reset_dials();
        if cancelled_leg {
            let now = swarm.now();
            nat.pump(swarm.runtime_mut(), now);
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
            }) if peer == remote && addrs == vec![addr.clone()]
        ));
        assert_eq!(driver.book.known_addrs(&remote), vec![addr]);
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
