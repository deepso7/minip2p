//! Caller-driven Discovery capability shared by standard and portable
//! Endpoints: one bounded peer book fed by signed beacons and mDNS
//! observations, with automatic dialing routed through the Connection-attempt
//! engine. Time is supplied by the host; I/O runs through `SwarmCore`.

use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;

use minip2p_core::platform::{Deadline, EntropySource, Now};
use minip2p_core::{ConnectId, Multiaddr, PeerAddr, PeerId, select_direct_addrs};
#[cfg(feature = "pubsub")]
use minip2p_discovery::{BeaconAction, BeaconAgent, BeaconEvent};
use minip2p_discovery::{DiscoveryAction, DiscoverySource, PeerDiscoveryAgent};
#[cfg(feature = "mdns")]
use minip2p_mdns::MdnsEvent;
#[cfg(feature = "pubsub")]
use minip2p_pubsub::GossipsubEvent;
use minip2p_swarm::{SwarmCore, SwarmEvent};

use crate::connect::{ConnectAdmission, ConnectEngine, Legs};
use crate::names::Expander;
#[cfg(feature = "pubsub")]
use crate::pubsub::GossipsubDriver;
use crate::{ConnectOutcome, EndpointEvent};
use minip2p_transport::Transport;

/// Peer-ID targets resolve through the shared book; targets that already
/// carry complete candidates pass through unchanged.
pub(crate) fn resolve_book_candidates(
    book: Option<&PeerDiscoveryAgent>,
    peer: &PeerId,
    candidates: Vec<PeerAddr>,
) -> Vec<PeerAddr> {
    if !candidates.is_empty() {
        return candidates;
    }
    match book {
        Some(book) => direct_candidates(&book.known_addrs(peer), peer),
        None => Vec::new(),
    }
}

/// Directly dialable book addresses tagged as connection candidates for
/// `peer`.
fn direct_candidates(addrs: &[Multiaddr], peer: &PeerId) -> Vec<PeerAddr> {
    select_direct_addrs(addrs, None, None)
        .into_iter()
        .filter_map(|addr| PeerAddr::new(addr, peer.clone()).ok())
        .collect()
}

/// Coordinates source observations, the shared peer book, and automatic
/// connects. The endpoint engine owns one; only the clock sample and the
/// transport differ between the standard and portable endpoints.
pub(crate) struct DiscoveryDriver {
    /// Peer book; the endpoint drains its events into the Endpoint stream.
    pub(crate) book: PeerDiscoveryAgent,
    /// Signed-beacon agent, when the composition configured one.
    #[cfg(feature = "pubsub")]
    beacon: Option<BeaconAgent>,
    /// Connection-attempt ids owned by automatic dialing.
    inflight: BTreeMap<ConnectId, PeerId>,
    /// Bound/listened address set last pushed into the beacon.
    #[cfg(feature = "pubsub")]
    last_local_addrs: Vec<Multiaddr>,
}

impl DiscoveryDriver {
    pub(crate) fn new(
        book: PeerDiscoveryAgent,
        #[cfg(feature = "pubsub")] beacon: Option<BeaconAgent>,
    ) -> Self {
        Self {
            book,
            #[cfg(feature = "pubsub")]
            beacon,
            inflight: BTreeMap::new(),
            #[cfg(feature = "pubsub")]
            last_local_addrs: Vec::new(),
        }
    }

    /// Beacon topic, when signed beacons are configured, for the
    /// reserved-topic guard.
    #[cfg(feature = "pubsub")]
    pub(crate) fn topic(&self) -> Option<&str> {
        self.beacon.as_ref().map(BeaconAgent::topic)
    }

    /// Moves queued book events into `out` as Endpoint events.
    pub(crate) fn drain_events(&mut self, out: &mut impl Extend<EndpointEvent>) {
        out.extend(core::iter::from_fn(|| self.book.poll_event()).map(EndpointEvent::Discovery));
    }

    /// The earliest deadline across book and beacon.
    pub(crate) fn next_deadline(&self, now: Now) -> Option<Deadline> {
        #[cfg(feature = "pubsub")]
        let beacon = self
            .beacon
            .as_ref()
            .and_then(|beacon| beacon.next_deadline(now));
        #[cfg(not(feature = "pubsub"))]
        let beacon = None;
        Deadline::earliest_opt(self.book.next_deadline(now), beacon)
    }

    /// Whether automatic dialing owns attempt `id`: NAT routing consumes
    /// its NAT events after the Connection engine observes them, so they
    /// never reach the application.
    pub(crate) fn owns_attempt(&self, id: ConnectId) -> bool {
        self.inflight.contains_key(&id)
    }

    /// Observes connection lifecycle for the book, whichever driver claimed
    /// the event. A Connection replacement keeps the peer connected, so
    /// only the peer-level transitions matter. Events trail the swarm's
    /// state, so a close is a disconnect only if the peer has not already
    /// reconnected.
    pub(crate) fn observe<T: Transport, E: EntropySource>(
        &mut self,
        event: &SwarmEvent,
        core: &SwarmCore<T, E>,
        now_ms: u64,
    ) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                self.book.peer_connected(peer_id, now_ms);
            }
            SwarmEvent::ConnectionClosed { peer_id, .. }
                if core.connection_id(peer_id).is_none() =>
            {
                self.book.peer_disconnected(peer_id, now_ms);
            }
            _ => {}
        }
    }

    /// Feeds an mDNS observation into the book.
    #[cfg(feature = "mdns")]
    pub(crate) fn handle_mdns_event(&mut self, event: MdnsEvent, now_ms: u64) {
        match event {
            MdnsEvent::PeerObserved { peer, addrs } => {
                self.book.observe_mdns(peer, addrs, now_ms);
            }
            MdnsEvent::ProtocolViolation { peer, reason } => {
                self.book
                    .report_violation(peer, DiscoverySource::Mdns, &reason);
            }
            // The engine reports mDNS health to the application itself.
            MdnsEvent::Failed { .. } | MdnsEvent::Recovered => {}
        }
    }

    /// Claims a Connection-attempt terminal owned by automatic dialing:
    /// updates the book from the outcome and returns `true` so the endpoint
    /// does not forward the event to the application.
    pub(crate) fn claim_settled(&mut self, event: &EndpointEvent, now_ms: u64) -> bool {
        let EndpointEvent::ConnectSettled {
            connect_id,
            peer_id,
            outcome,
        } = event
        else {
            return false;
        };
        if self.inflight.remove(connect_id).is_none() {
            return false;
        }
        match outcome {
            ConnectOutcome::Connected { .. } => self.book.dial_succeeded(peer_id, now_ms),
            ConnectOutcome::Failed(failure) => {
                self.book.dial_failed(peer_id, &failure.to_string(), now_ms);
            }
            ConnectOutcome::Cancelled => {}
        }
        true
    }

    /// Runs all cross-driver work until no new work is produced.
    ///
    /// Feed queued mDNS observations with [`Self::handle_mdns_event`] first:
    /// they are part of the same fixpoint as beacon and book output.
    ///
    /// Automatic dials are admitted and cancelled through `connect`, relay
    /// legs included, as they happen; the endpoint routes the NAT events
    /// that produces afterwards. On the standard Endpoint `names` starts
    /// Name resolution off the driver, so a sweep never blocks on a lookup.
    pub(crate) fn sweep<T: Transport, E: EntropySource>(
        &mut self,
        #[cfg(feature = "pubsub")] mut pubsub: Option<&mut GossipsubDriver>,
        mut legs: Legs<'_, T>,
        connect: &mut ConnectEngine,
        runtime: &mut SwarmCore<T, E>,
        names: &mut dyn Expander,
        now: Now,
    ) {
        let now_ms = now.monotonic_ms;
        loop {
            let mut progressed = false;

            #[cfg(feature = "pubsub")]
            if let Some(beacon) = self.beacon.as_mut() {
                let local_addrs = runtime.local_addresses();
                if self.last_local_addrs != local_addrs {
                    self.last_local_addrs = local_addrs.to_vec();
                    beacon.set_local_addrs(local_addrs, now_ms);
                    progressed = true;
                }
                if let Some(pubsub) = pubsub.as_deref_mut() {
                    progressed |= pubsub.extract_events(|event| match event {
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
                    });
                }
            }

            #[cfg(feature = "pubsub")]
            if let Some(beacon) = self.beacon.as_mut()
                && beacon
                    .next_deadline(now)
                    .is_some_and(|due| due.is_expired_at(now))
            {
                beacon.handle_tick(now_ms);
                progressed = true;
            }
            if self
                .book
                .next_deadline(now)
                .is_some_and(|due| due.is_expired_at(now))
            {
                self.book.handle_tick(now_ms);
                progressed = true;
            }

            #[cfg(feature = "pubsub")]
            if let Some(beacon) = self.beacon.as_mut() {
                while let Some(event) = beacon.poll_event() {
                    progressed = true;
                    match event {
                        BeaconEvent::Observation(observation) => {
                            self.book.observe_beacon(observation, now_ms);
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
                                let _refused =
                                    pubsub.publish(&topic, payload, None, runtime, now_ms);
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
                        let id = connect.admit(
                            legs.reborrow(),
                            runtime,
                            ConnectAdmission {
                                candidates: direct_candidates(&addrs, &peer),
                                peer: peer.clone(),
                                allow_relay: source == DiscoverySource::SignedBeacon,
                                // Every address the source announced, circuit
                                // addresses included.
                                targets: addrs,
                            },
                            names,
                            now,
                        );
                        self.inflight.insert(id, peer);
                    }
                    DiscoveryAction::CancelDial { peer } => {
                        let active = self
                            .inflight
                            .iter()
                            .find_map(|(id, candidate)| (*candidate == peer).then_some(*id));
                        if let Some(id) = active {
                            connect.cancel(legs.reborrow(), runtime, id, now);
                        }
                    }
                }
            }
            if !progressed {
                break;
            }
        }
    }

    /// Cancels all discovery-owned attempts, relay legs included, during
    /// endpoint shutdown.
    #[cfg(feature = "mdns")]
    pub(crate) fn shutdown<T: Transport, E: EntropySource>(
        &mut self,
        connect: &mut ConnectEngine,
        mut legs: Legs<'_, T>,
        runtime: &mut SwarmCore<T, E>,
        now: Now,
    ) {
        for id in core::mem::take(&mut self.inflight).into_keys() {
            connect.cancel(legs.reborrow(), runtime, id, now);
        }
        self.book.reset_dials();
    }
}

#[cfg(all(test, feature = "mdns"))]
mod tests {
    use super::*;
    use alloc::vec;
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
            #[cfg(feature = "pubsub")]
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

    #[test]
    fn claim_settled_consumes_only_discovery_owned_attempts() {
        let book =
            PeerDiscoveryAgent::new(peer(1), PeerDiscoveryConfig::default()).expect("valid policy");
        let mut driver = DiscoveryDriver::new(
            book,
            #[cfg(feature = "pubsub")]
            None,
        );
        let remote = peer(2);
        let owned = ConnectId::from_u64(9);
        driver.inflight.insert(owned, remote.clone());

        let claimed = driver.claim_settled(
            &EndpointEvent::ConnectSettled {
                connect_id: owned,
                peer_id: remote.clone(),
                outcome: ConnectOutcome::Failed(crate::ConnectFailure::Timeout {
                    elapsed_ms: 30_000,
                    candidates: Vec::new(),
                    relays: Vec::new(),
                }),
            },
            100,
        );
        assert!(claimed, "a discovery-owned attempt settles into the book");
        assert!(!driver.inflight.contains_key(&owned));

        let foreign = driver.claim_settled(
            &EndpointEvent::ConnectSettled {
                connect_id: ConnectId::from_u64(10),
                peer_id: remote,
                outcome: ConnectOutcome::Cancelled,
            },
            101,
        );
        assert!(!foreign, "caller-owned attempts reach the application");
    }
}
