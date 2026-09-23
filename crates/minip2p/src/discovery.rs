//! Caller-driven Discovery capability shared by standard and portable
//! Endpoints: one bounded peer book fed by signed beacons and mDNS
//! observations, with automatic dialing routed through the Connection-attempt
//! engine. Time is supplied by the host; I/O runs through `SwarmRuntime`.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use minip2p_core::{ConnectId, Multiaddr, PeerAddr, PeerId, select_direct_addrs};
#[cfg(feature = "pubsub")]
use minip2p_discovery::{BeaconAction, BeaconAgent, BeaconEvent};
use minip2p_discovery::{DiscoveryAction, DiscoverySource, PeerDiscoveryAgent};
#[cfg(any(feature = "mdns", feature = "portable-mdns"))]
use minip2p_mdns::MdnsEvent;
#[cfg(all(debug_assertions, any(feature = "discovery", feature = "mdns")))]
use minip2p_nat::NatEvent;
use minip2p_platform::{EntropySource, Now};
#[cfg(feature = "pubsub")]
use minip2p_pubsub::GossipsubEvent;
use minip2p_swarm::{SwarmCore, SwarmEvent, SwarmRuntime};

#[cfg(feature = "_nat-driver")]
use crate::nat::NatDriver;
#[cfg(feature = "_nat-driver")]
use crate::portable::connect::cancel_attempt;
use crate::portable::connect::{ConnectAdmission, ConnectEngine, admit_connect};
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

/// An admitted attempt awaiting `NatDriver::attach_leg`.
#[cfg_attr(
    not(any(
        feature = "portable-autonat",
        all(feature = "nat", any(feature = "discovery", feature = "mdns"))
    )),
    expect(
        dead_code,
        reason = "only compositions applying DiscoveryNatWork read the fields"
    )
)]
pub(crate) struct PendingLeg {
    /// The admitted attempt.
    pub(crate) id: ConnectId,
    /// Its target peer.
    pub(crate) peer: PeerId,
    /// Whether a relay leg may race its direct dials.
    pub(crate) allow_relay: bool,
}

/// NAT-driver work a [`DiscoveryDriver::sweep`] or
/// [`DiscoveryDriver::shutdown`] queued. The composition drains it because
/// attaching legs and pumping actions needs its concrete transport while
/// the sweep itself only needs [`Transport`].
#[derive(Default)]
#[must_use = "apply with NatDriver::apply_sweep_work or the queued NAT work is lost"]
pub(crate) struct DiscoveryNatWork {
    /// Newly admitted attempts awaiting `NatDriver::attach_leg`.
    pub(crate) legs: Vec<PendingLeg>,
    /// A NAT leg was cancelled; `NatDriver::pump` must run once.
    #[cfg_attr(
        not(feature = "_nat-driver"),
        expect(dead_code, reason = "only NAT compositions pump after a cancelled leg")
    )]
    pub(crate) pump: bool,
}

/// Coordinates source observations, the shared peer book, and automatic
/// connects. The same driver backs the standard `Endpoint` and the portable
/// mDNS/smoltcp compositions; only the clock sample and transport differ.
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
    /// Last monotonic-ms sample fed to the book, so the endpoint can report
    /// the driver's own timebase without resampling the clock.
    last_now_ms: u64,
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
            last_now_ms: 0,
        }
    }

    /// The last host-supplied monotonic timestamp, matching `KnownPeer` ages.
    #[cfg(any(feature = "discovery", feature = "mdns"))]
    pub(crate) fn now_ms(&self) -> u64 {
        self.last_now_ms
    }

    /// Beacon topic, when signed beacons are configured. Only pubsub-capable
    /// endpoint compositions read it, for the reserved-topic guard.
    #[cfg(all(feature = "pubsub", any(feature = "discovery", feature = "smoltcp")))]
    pub(crate) fn topic(&self) -> Option<&str> {
        self.beacon.as_ref().map(BeaconAgent::topic)
    }

    /// Moves queued book events into `out` as Endpoint events.
    pub(crate) fn drain_events(&mut self, out: &mut Vec<EndpointEvent>) {
        while let Some(event) = self.book.poll_event() {
            out.push(EndpointEvent::Discovery(event));
        }
    }

    /// The earliest timeout across book and beacon at `now_ms`.
    pub(crate) fn next_timeout(&self, now_ms: u64) -> Option<u64> {
        #[cfg_attr(
            not(feature = "pubsub"),
            expect(unused_mut, reason = "the beacon timeout is the only mutation")
        )]
        let mut timeout = self.book.next_timeout(now_ms);
        #[cfg(feature = "pubsub")]
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

    /// Whether `event` belongs to a discovery-owned attempt that the sweep
    /// must hide before the Endpoint drains NAT output.
    #[cfg(all(debug_assertions, any(feature = "discovery", feature = "mdns")))]
    pub(crate) fn owns_nat_event(&self, event: &NatEvent) -> bool {
        event
            .connect_id()
            .is_some_and(|id| self.inflight.contains_key(&id))
    }

    /// Observes connection lifecycle for the book, whichever driver claimed
    /// the event.
    pub(crate) fn observe(&mut self, event: &SwarmEvent, core: &SwarmCore, now_ms: u64) {
        self.last_now_ms = now_ms;
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                self.book.peer_connected(peer_id, now_ms);
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } if core.conn_for(peer_id).is_none() => {
                self.book.peer_disconnected(peer_id, now_ms);
            }
            _ => {}
        }
    }

    /// Feeds an mDNS observation into the book.
    #[cfg(any(feature = "mdns", feature = "portable-mdns"))]
    pub(crate) fn handle_mdns_event(&mut self, event: MdnsEvent, now_ms: u64) {
        self.last_now_ms = now_ms;
        match event {
            MdnsEvent::PeerObserved { peer, addrs } => {
                self.book.observe_mdns(peer, addrs, now_ms);
            }
            MdnsEvent::ProtocolViolation { peer, reason } => {
                self.book
                    .report_violation(peer, DiscoverySource::Mdns, &reason);
            }
        }
    }

    /// Claims a Connection-attempt terminal owned by automatic dialing:
    /// updates the book from the outcome and returns `true` so the endpoint
    /// does not forward the event to the application.
    pub(crate) fn claim_settled(&mut self, event: &EndpointEvent, now_ms: u64) -> bool {
        self.last_now_ms = now_ms;
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

    /// Removes queued NAT events owned by automatic-dial attempts, feeding
    /// each to the Connection-attempt engine first. Returns `true` when any
    /// were claimed.
    ///
    /// The sweep calls this between actions; compositions must call it again
    /// after `NatDriver::apply_sweep_work`, because attaching a leg can queue
    /// a synchronous terminal (for example `ConnectFailed` from a relay that
    /// offers no HOP) after the sweep's own pass already ran.
    #[cfg(feature = "_nat-driver")]
    pub(crate) fn claim_nat_events<T: Transport, E: EntropySource>(
        &mut self,
        nat: &mut NatDriver<E>,
        connect: &mut ConnectEngine,
        runtime: &mut SwarmRuntime<T, E>,
        now_ms: u64,
    ) -> bool {
        let mut claimed = false;
        let mut i = 0;
        while let Some(event) = nat.event_at(i) {
            if event
                .connect_id()
                .is_some_and(|id| self.inflight.contains_key(&id))
            {
                claimed = true;
                let event = nat.remove_event(i);
                connect.observe_nat(&event, runtime, now_ms);
            } else {
                i += 1;
            }
        }
        claimed
    }

    /// Runs all cross-driver work until no new work is produced.
    ///
    /// Feed queued mDNS observations with [`Self::handle_mdns_event`] first:
    /// they are part of the same fixpoint as beacon and book output.
    ///
    /// NAT legs for attempts admitted here and pumps for cancelled legs are
    /// returned as [`DiscoveryNatWork`]; the composition applies them with
    /// `NatDriver::apply_sweep_work` against its concrete transport. On the
    /// standard Endpoint `expand` resolves DNS, so a sweep can block on
    /// resolution.
    pub(crate) fn sweep<T: Transport, E: EntropySource>(
        &mut self,
        #[cfg(feature = "pubsub")] mut pubsub: Option<&mut GossipsubDriver>,
        #[cfg(feature = "_nat-driver")] mut nat: Option<&mut NatDriver<E>>,
        connect: &mut ConnectEngine,
        runtime: &mut SwarmRuntime<T, E>,
        expand: &mut dyn FnMut(&PeerAddr) -> Result<Vec<PeerAddr>, String>,
        now: Now,
    ) -> DiscoveryNatWork {
        let mut work = DiscoveryNatWork::default();
        let now_ms = now.monotonic_ms;
        self.last_now_ms = now_ms;
        loop {
            let mut progressed = false;

            #[cfg(feature = "pubsub")]
            if let Some(beacon) = self.beacon.as_mut() {
                let local_addrs = runtime.core().local_addresses();
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

            // Discovery-owned attempt events are hidden from the app, but
            // the engine must observe them first: cancelled-leg pumps in
            // this same sweep can queue them after the pre-sweep
            // `feed_unobserved_to_connect` pass.
            #[cfg(feature = "_nat-driver")]
            if let Some(nat) = nat.as_deref_mut() {
                progressed |= self.claim_nat_events(nat, connect, runtime, now_ms);
            }

            #[cfg(feature = "pubsub")]
            if let Some(beacon) = self.beacon.as_mut()
                && beacon.next_timeout(now_ms) == Some(0)
            {
                beacon.handle_tick(now_ms);
                progressed = true;
            }
            if self.book.next_timeout(now_ms) == Some(0) {
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
                        let allow_relay = source == DiscoverySource::SignedBeacon;
                        let candidates = direct_candidates(&addrs, &peer);
                        let id = admit_connect(
                            connect,
                            runtime,
                            #[cfg(feature = "_nat-driver")]
                            nat.as_deref(),
                            ConnectAdmission {
                                peer: peer.clone(),
                                candidates,
                                allow_relay,
                            },
                            expand,
                            now_ms,
                        );
                        self.inflight.insert(id, peer.clone());
                        work.legs.push(PendingLeg {
                            id,
                            peer,
                            allow_relay,
                        });
                    }
                    DiscoveryAction::CancelDial { peer } => {
                        self.cancel_peer(
                            &peer,
                            connect,
                            #[cfg(feature = "_nat-driver")]
                            nat.as_deref_mut(),
                            runtime,
                            now,
                            &mut work,
                        );
                    }
                }
            }
            if !progressed {
                break;
            }
        }
        work
    }

    #[cfg_attr(
        not(feature = "_nat-driver"),
        expect(
            unused_variables,
            reason = "NAT leg cancellation is the only user of now and work"
        )
    )]
    fn cancel_peer<T: Transport, E: EntropySource>(
        &mut self,
        peer: &PeerId,
        connect: &mut ConnectEngine,
        #[cfg(feature = "_nat-driver")] nat: Option<&mut NatDriver<E>>,
        runtime: &mut SwarmRuntime<T, E>,
        now: Now,
        work: &mut DiscoveryNatWork,
    ) {
        let active = self
            .inflight
            .iter()
            .find_map(|(id, candidate)| (candidate == peer).then_some(*id));
        if let Some(id) = active {
            #[cfg(feature = "_nat-driver")]
            {
                work.pump |= cancel_attempt(connect, nat, id, runtime, now);
            }
            #[cfg(not(feature = "_nat-driver"))]
            connect.cancel(id, runtime);
        }
    }

    /// Cancels all discovery-owned attempts during endpoint shutdown. The
    /// returned work carries whether the NAT driver must pump afterwards.
    #[cfg(any(feature = "mdns", feature = "portable-mdns"))]
    #[cfg_attr(
        not(feature = "_nat-driver"),
        expect(
            unused_mut,
            unused_variables,
            reason = "NAT leg cancellation is the only user of now and pump"
        )
    )]
    pub(crate) fn shutdown<T: Transport, E: EntropySource>(
        &mut self,
        connect: &mut ConnectEngine,
        #[cfg(feature = "_nat-driver")] mut nat: Option<&mut NatDriver<E>>,
        runtime: &mut SwarmRuntime<T, E>,
        now: Now,
    ) -> DiscoveryNatWork {
        let mut work = DiscoveryNatWork::default();
        let attempts: Vec<ConnectId> = self.inflight.keys().copied().collect();
        for id in attempts {
            #[cfg(feature = "_nat-driver")]
            {
                work.pump |= cancel_attempt(connect, nat.as_deref_mut(), id, runtime, now);
            }
            #[cfg(not(feature = "_nat-driver"))]
            connect.cancel(id, runtime);
        }
        self.inflight.clear();
        self.book.reset_dials();
        work
    }
}

#[cfg(all(test, any(feature = "mdns", feature = "portable-mdns")))]
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
                    relay: None,
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
