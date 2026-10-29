//! Engine tests: the per-batch event order, run against both endpoint
//! types, and the private work counters.

use crate::ConnectionCloseReason;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
// Tests run on the host, so the harness's `std` is there even when the
// crate itself is `no_std`.
extern crate std;
use std::sync::{Mutex, PoisonError};

use minip2p_core::platform::{EntropyError, EntropySource, Now};
use minip2p_core::{Bytes, Multiaddr, PeerAddr, PeerId};
use minip2p_identity::Ed25519Keypair;
use minip2p_test_support::InMemoryTransport;
use minip2p_transport::{
    ConnectionEndpoint, ConnectionId, ConnectionNamespace, StreamId, Transport, TransportError,
    TransportEvent,
};

use crate::{ConnectOutcome, Endpoint, EndpointEvent};

struct CountingEntropy(u8);

impl EntropySource for CountingEntropy {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        for byte in output {
            self.0 = self.0.wrapping_add(1);
            *byte = self.0;
        }
        Ok(())
    }
}

/// Answers every dial with one connection to the dialed peer that comes up
/// and closes again within the same transport poll, so the batch carries
/// both lifecycle events. Counts its polls.
#[derive(Clone, Default)]
pub(crate) struct FlashTransport {
    queue: Arc<Mutex<VecDeque<TransportEvent>>>,
    polls: Arc<Mutex<usize>>,
    /// What `local_addresses` reports.
    local: Vec<Multiaddr>,
}

impl FlashTransport {
    #[cfg(feature = "mdns")]
    fn polls(&self) -> usize {
        *self.polls.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Transport for FlashTransport {
    fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        let id = ConnectionId::namespaced(ConnectionNamespace::TCP_IPV4, 1).expect("id");
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        queue.push_back(TransportEvent::Connected {
            id,
            endpoint: ConnectionEndpoint::with_peer_id(
                addr.transport().clone(),
                addr.peer_id().clone(),
            ),
        });
        queue.push_back(TransportEvent::Closed {
            id,
            reason: ConnectionCloseReason::Local,
        });
        Ok(id)
    }
    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        Ok(addr.clone())
    }
    fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
        Ok(StreamId::new(1))
    }
    fn send_stream(
        &mut self,
        _: ConnectionId,
        _: StreamId,
        _: Bytes,
    ) -> Result<(), TransportError> {
        Ok(())
    }
    fn close_stream_write(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Ok(())
    }
    fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Ok(())
    }
    fn ack_stream(&mut self, _: ConnectionId, _: StreamId, _: usize) -> Result<(), TransportError> {
        Ok(())
    }
    fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
        Ok(())
    }
    fn poll(&mut self, _: Now) -> Result<Vec<TransportEvent>, TransportError> {
        *self.polls.lock().unwrap_or_else(PoisonError::into_inner) += 1;
        Ok(self
            .queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
            .collect())
    }
    fn local_addresses(&self) -> Vec<Multiaddr> {
        self.local.clone()
    }
    fn local_addresses_revision(&self) -> Option<u64> {
        Some(0)
    }
}

#[cfg(feature = "std")]
impl minip2p_transport::PollSource for FlashTransport {
    fn attach(
        &mut self,
        _: minip2p_transport::mio::Registry,
        _: minip2p_transport::TokenSpace,
        _: Arc<minip2p_transport::mio::Waker>,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn dispatch(&mut self, _: &minip2p_transport::mio::event::Event) {}
}

fn target(peer: &PeerId) -> PeerAddr {
    PeerAddr::new(
        "/ip4/192.0.2.9/tcp/4001".parse().expect("addr"),
        peer.clone(),
    )
    .expect("target")
}

fn position(events: &[EndpointEvent], matches: impl Fn(&EndpointEvent) -> bool) -> usize {
    events
        .iter()
        .position(matches)
        .unwrap_or_else(|| panic!("missing event in {events:?}"))
}

/// The per-batch order both endpoint types promise: a connection that came
/// up and went down in one batch is reported first, its attempt's
/// `ConnectSettled` after both.
fn assert_lifecycle_before_settled(events: &[EndpointEvent], peer: &PeerId) {
    let established = position(
        events,
        |event| matches!(event, EndpointEvent::ConnectionEstablished { peer_id, .. } if peer_id == peer),
    );
    let closed = position(
        events,
        |event| matches!(event, EndpointEvent::ConnectionClosed { peer_id, .. } if peer_id == peer),
    );
    let settled = position(events, |event| {
        matches!(
            event,
            EndpointEvent::ConnectSettled {
                outcome: ConnectOutcome::Connected { .. },
                ..
            }
        )
    });
    assert!(
        established < closed && closed < settled,
        "swarm events first, then the terminal: {events:?}"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, EndpointEvent::ConnectSettled { .. }))
            .count(),
        1,
        "exactly one terminal: {events:?}"
    );
}

#[test]
fn portable_batches_report_lifecycle_before_connect_settled() {
    let identity = Ed25519Keypair::from_secret_key_bytes([31; 32]);
    let peer = Ed25519Keypair::from_secret_key_bytes([32; 32]).peer_id();
    let mut endpoint = Endpoint::portable(&identity, CountingEntropy(0))
        .build(FlashTransport::default())
        .expect("builds");
    let now = Now::from_millis(0);
    endpoint.connect(target(&peer), now).expect("admitted");
    let events = endpoint.poll(now).expect("poll");
    assert_lifecycle_before_settled(&events, &peer);
}

#[cfg(feature = "std")]
pub(crate) fn std_endpoint(builder: crate::EndpointBuilder, transport: FlashTransport) -> Endpoint {
    let mut set = minip2p_transport::TransportSet::new();
    set.insert(
        minip2p_core::TransportKind::Tcp,
        [ConnectionNamespace::TCP_IPV4],
        alloc::boxed::Box::new(transport),
    )
    .map_err(|rejected| rejected.error().clone())
    .expect("member");
    builder.bind_over(set).expect("builds")
}

#[cfg(feature = "std")]
#[test]
fn std_batches_report_lifecycle_before_connect_settled() {
    let peer = Ed25519Keypair::from_secret_key_bytes([33; 32]).peer_id();
    let mut endpoint = std_endpoint(Endpoint::builder(), FlashTransport::default());
    endpoint.connect(target(&peer)).expect("admitted");
    let events = endpoint.poll().expect("poll");
    assert_lifecycle_before_settled(&events, &peer);

    // `wait` hands the same batch out one event at a time, in that order.
    let peer = Ed25519Keypair::from_secret_key_bytes([34; 32]).peer_id();
    endpoint.connect(target(&peer)).expect("admitted");
    let mut waited = Vec::new();
    while let crate::EndpointWaitOutcome::Event(event) =
        endpoint.wait(std::time::Duration::ZERO).expect("wait")
    {
        waited.push(event);
    }
    assert_lifecycle_before_settled(&waited, &peer);
}

/// A NAT event that is routed only while the batch collects its terminals
/// (as one a terminal's cleanup produces would be) still reaches the
/// Connection engine and the application before the final drain: NAT
/// output first, the terminal it caused last, the NAT attempt terminal
/// never.
#[cfg(feature = "relay")]
fn assert_late_nat_events_settle_in_order<T: Transport, E: EntropySource, M: super::Carrier>(
    engine: &mut super::Engine<T, E, M>,
    connect_id: crate::ConnectId,
    peer: &PeerId,
) {
    use minip2p_nat::{NatError, NatEvent, ReachabilityState};
    assert!(
        engine.connect.is_pending(connect_id),
        "the relay leg is racing"
    );
    engine.events.clear();
    let nat = engine.nat.as_mut().expect("NAT configured");
    nat.push_event(NatEvent::ReachabilityChanged {
        old: ReachabilityState::Unknown,
        new: ReachabilityState::Private,
        confirmed_addrs: Vec::new(),
    });
    nat.push_event(NatEvent::ConnectFailed {
        connect_id,
        peer: peer.clone(),
        error: NatError::DialFailed("relay refused".into()),
    });
    engine.settle(Now::from_millis(1));
    let events: Vec<_> = engine.events.drain(..).collect();
    assert!(
        matches!(
            events.as_slice(),
            [
                EndpointEvent::Nat(NatEvent::ReachabilityChanged { .. }),
                EndpointEvent::ConnectSettled {
                    connect_id: settled,
                    outcome: ConnectOutcome::Failed(_),
                    ..
                },
            ] if *settled == connect_id
        ),
        "{events:?}"
    );
}

#[cfg(feature = "relay")]
fn forced_relay(relay: &PeerAddr) -> minip2p_nat::NatConfig {
    minip2p_nat::NatConfig {
        relays: vec![relay.clone()],
        force_relay: true,
        reservation_policy: minip2p_nat::ReservationPolicy::Never,
        ..minip2p_nat::NatConfig::default()
    }
}

#[cfg(all(feature = "std", feature = "relay"))]
#[test]
fn std_routes_late_nat_events_before_the_final_drain() {
    let relay = target(&Ed25519Keypair::from_secret_key_bytes([35; 32]).peer_id());
    let peer = Ed25519Keypair::from_secret_key_bytes([36; 32]).peer_id();
    let mut endpoint = std_endpoint(
        Endpoint::builder().nat_config(forced_relay(&relay)),
        FlashTransport::default(),
    );
    let id = endpoint.connect(peer.clone()).expect("admitted");
    assert_late_nat_events_settle_in_order(&mut endpoint.engine, id, &peer);
}

#[cfg(feature = "relay")]
#[test]
fn portable_routes_late_nat_events_before_the_final_drain() {
    let identity = Ed25519Keypair::from_secret_key_bytes([37; 32]);
    let relay = target(&Ed25519Keypair::from_secret_key_bytes([38; 32]).peer_id());
    let peer = Ed25519Keypair::from_secret_key_bytes([39; 32]).peer_id();
    let transport = minip2p_circuit::CircuitTransport::new(
        FlashTransport::default(),
        identity.clone(),
        CountingEntropy(9),
    );
    let mut endpoint = Endpoint::portable(&identity, CountingEntropy(0))
        .nat_config(forced_relay(&relay))
        .build_with_circuits(transport)
        .expect("builds");
    let id = endpoint
        .connect(peer.clone(), Now::from_millis(0))
        .expect("admitted");
    assert_late_nat_events_settle_in_order(&mut endpoint.engine, id, &peer);
}

/// Relay-server listener addresses come from the bound transports, not from
/// configuration: a set the agent rejects does not fail the build, and is
/// reported once as a capability event while the endpoint keeps running.
/// The relay server runs on the portable endpoint, as on std.
#[cfg(feature = "relay-server")]
#[test]
fn rejected_relay_listener_addresses_are_an_event_not_a_bind_error() {
    use minip2p_relay_server::{RelayServerAddrSource, RelayServerEvent};

    let transport = FlashTransport {
        local: vec![
            "/ip4/198.51.100.1/tcp/4001/p2p-circuit"
                .parse()
                .expect("addr"),
        ],
        ..FlashTransport::default()
    };
    let identity = Ed25519Keypair::from_secret_key_bytes([46; 32]);
    let mut endpoint = Endpoint::portable(&identity, CountingEntropy(0))
        .relay_server()
        .build(transport)
        .expect("a relay server builds over any transport");
    let rejections = |events: &[EndpointEvent]| {
        events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    EndpointEvent::RelayServer(RelayServerEvent::AddrsRejected {
                        source: RelayServerAddrSource::Listener,
                        ..
                    })
                )
            })
            .count()
    };
    assert_eq!(
        rejections(&endpoint.poll(Now::from_millis(0)).expect("poll")),
        1
    );
    assert_eq!(
        rejections(&endpoint.poll(Now::from_millis(1)).expect("poll")),
        0
    );
}

/// After the first batch warms the caches, one batch carrying many stream
/// chunks runs exactly one capability pass and recomputes no addresses,
/// with every capability compiled into this build configured on both
/// sides (NAT, Gossipsub, signed discovery), so their drivers are live.
#[test]
fn a_busy_batch_runs_one_capability_pass_and_no_address_refresh() {
    const PROTOCOL: &str = "/engine/bulk/1";
    // Each side names the other as its AutoNAT server; neither serves
    // AutoNAT, so the NAT agent is live but its probes go nowhere.
    let configure = |builder: crate::PortableEndpointBuilder<CountingEntropy>, server: PeerAddr| {
        let builder = builder.protocol(PROTOCOL);
        #[cfg(feature = "discovery")]
        let builder = builder.discovery();
        #[cfg(all(feature = "pubsub", not(feature = "discovery")))]
        let builder = builder.gossipsub();
        #[cfg(feature = "autonat")]
        let builder = builder.autonat_server(server);
        #[cfg(not(feature = "autonat"))]
        drop(server);
        builder
    };
    let a_identity = Ed25519Keypair::from_secret_key_bytes([42; 32]);
    let b_identity = Ed25519Keypair::from_secret_key_bytes([43; 32]);
    let (a_transport, b_transport) =
        InMemoryTransport::pair(a_identity.peer_id(), b_identity.peer_id());
    let address = |addr: &str, peer: &Ed25519Keypair| {
        PeerAddr::new(addr.parse().expect("address"), peer.peer_id()).expect("peer address")
    };
    let a_addr = address("/ip4/192.0.2.1/udp/4001/quic-v1", &a_identity);
    let b_addr = address("/ip4/192.0.2.2/udp/4002/quic-v1", &b_identity);
    let mut a = configure(Endpoint::portable(&a_identity, CountingEntropy(0)), b_addr)
        .build(a_transport)
        .expect("a");
    let mut b = configure(Endpoint::portable(&b_identity, CountingEntropy(1)), a_addr)
        .build(b_transport)
        .expect("b");
    let b_peer = b_identity.peer_id();
    let clock = core::cell::Cell::new(0);
    let tick = |a: &mut crate::PortableEndpoint<_, _>, b: &mut crate::PortableEndpoint<_, _>| {
        clock.set(clock.get() + 1);
        let now = Now::from_millis(clock.get());
        (a.poll(now).expect("a"), b.poll(now).expect("b"), now)
    };
    while !a.is_peer_ready(&b_peer) {
        tick(&mut a, &mut b);
    }
    let (conn, stream) = a
        .open_stream(&b_peer, PROTOCOL, Now::from_millis(clock.get()))
        .expect("open");
    let (mut a_ready, mut b_ready) = (false, false);
    while !(a_ready && b_ready) {
        let (a_events, b_events, _) = tick(&mut a, &mut b);
        let ready = |events: &[EndpointEvent]| {
            events
                .iter()
                .any(|event| matches!(event, EndpointEvent::StreamReady { .. }))
        };
        a_ready |= ready(&a_events);
        b_ready |= ready(&b_events);
    }
    let now = Now::from_millis(clock.get());
    for chunk in 0..8u8 {
        a.send_stream(conn, stream, vec![chunk; 16], now)
            .expect("send");
    }

    #[cfg(feature = "autonat")]
    assert!(b.engine.nat.is_some(), "NAT driver is live");
    #[cfg(feature = "pubsub")]
    assert!(b.engine.gossipsub.is_some(), "Gossipsub driver is live");
    #[cfg(feature = "discovery")]
    assert!(b.engine.discovery.is_some(), "discovery driver is live");
    let passes = b.engine.stats.capability_passes;
    let refreshes = b.engine.stats.address_refreshes;
    let events = b.poll(now).expect("b receives");
    let chunks = events
        .iter()
        .filter(|event| matches!(event, EndpointEvent::StreamData { .. }))
        .count();
    assert!(chunks > 1, "one batch carries the chunks: {events:?}");
    assert_eq!(b.engine.stats.capability_passes, passes + 1);
    assert_eq!(b.engine.stats.address_refreshes, refreshes);
}

/// An mDNS carrier that is always idle.
#[cfg(feature = "mdns")]
struct IdleCarrier(Arc<Mutex<usize>>);

#[cfg(feature = "mdns")]
impl minip2p_mdns::MdnsIo for IdleCarrier {
    fn interfaces(&self) -> &[minip2p_mdns::InterfaceSnapshot] {
        &[]
    }
    fn refresh(&mut self) -> Result<bool, minip2p_mdns::MdnsError> {
        Ok(false)
    }
    fn receive(
        &mut self,
        _: &mut [u8],
    ) -> Result<Option<minip2p_mdns::MdnsDatagram>, minip2p_mdns::MdnsError> {
        Ok(None)
    }
    fn send(&mut self, _: &minip2p_mdns::MdnsAction) -> Result<(), minip2p_mdns::MdnsError> {
        Ok(())
    }
    fn poll(&mut self, _: u64) -> Result<(), minip2p_mdns::MdnsError> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) += 1;
        Ok(())
    }
}

/// A carrier on the transport's stack can put bytes into its sockets, so
/// the batch polls the transport again after the mDNS tick.
#[cfg(feature = "mdns")]
#[test]
fn a_portable_mdns_batch_polls_the_transport_around_the_tick() {
    let identity = Ed25519Keypair::from_secret_key_bytes([44; 32]);
    let transport = FlashTransport::default();
    let carrier_polls = Arc::new(Mutex::new(0));
    let mut endpoint = Endpoint::portable(&identity, CountingEntropy(0))
        .mdns(
            IdleCarrier(Arc::clone(&carrier_polls)),
            minip2p_mdns::MdnsConfig::default(),
        )
        .build(transport.clone())
        .expect("builds");
    endpoint.poll(Now::from_millis(0)).expect("poll");
    assert_eq!(transport.polls(), 2, "once before and once after the tick");
    assert!(
        *carrier_polls.lock().unwrap_or_else(PoisonError::into_inner) > 0,
        "the box forwards poll"
    );
}

/// Portable capabilities need no smoltcp: Gossipsub, signed discovery, and
/// mDNS compose over any transport (the crate's `no_std` matrix runs this
/// with only `mdns,discovery`).
#[cfg(all(feature = "discovery", feature = "mdns"))]
#[test]
fn portable_capabilities_compose_over_a_plain_transport() {
    let identity = Ed25519Keypair::from_secret_key_bytes([45; 32]);
    let mut endpoint = Endpoint::portable(&identity, CountingEntropy(0))
        .discovery()
        .mdns(
            IdleCarrier(Arc::new(Mutex::new(0))),
            minip2p_mdns::MdnsConfig::default(),
        )
        .peer_discovery_config(crate::PeerDiscoveryConfig::default())
        .build(FlashTransport::default())
        .expect("builds");
    let now = Now::from_millis(0);
    endpoint.poll(now).expect("poll");
    assert!(endpoint.subscribe("app-topic", now).expect("gossipsub"));
    assert!(matches!(
        endpoint.unsubscribe(crate::DISCOVERY_TOPIC, now),
        Err(crate::GossipsubError::DiscoveryTopicReserved)
    ));
    assert!(endpoint.known_peers().is_empty());
}

/// A plain portable endpoint over `Send` parts can move to another thread:
/// only capabilities that need it (an `mdns` carrier, smoltcp's shared
/// entropy) make it single-threaded.
#[cfg(not(feature = "mdns"))]
const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<crate::PortableEndpoint<FlashTransport, CountingEntropy>>();
};
