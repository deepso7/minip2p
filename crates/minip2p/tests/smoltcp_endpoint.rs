//! Full portable-endpoint gate over two real smoltcp TCP stacks.
//!
//! Nothing below the virtual IP link is mocked: the endpoints perform TCP,
//! Noise XX, Yamux, Identify, Ping, and application-stream negotiation using
//! only caller-supplied devices, entropy, and time.

#![cfg(feature = "smoltcp")]

extern crate alloc;

use alloc::{collections::VecDeque, rc::Rc, vec, vec::Vec};
use core::cell::RefCell;

use minip2p::smoltcp::iface::{Config, Interface};
use minip2p::smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use minip2p::smoltcp::time::Instant;
use minip2p::smoltcp::wire::{HardwareAddress, IpCidr};
#[cfg(feature = "pubsub")]
use minip2p::{BeaconConfig, FloodsubConfig, PubsubEvent, SmoltcpPubsubError};
use minip2p::{
    DiscoveryEvent, Ed25519Keypair, Endpoint, EntropySource, Multiaddr, Now, PeerAddr, PeerId,
    PollDeadline, SmoltcpConfig, SmoltcpEvent, SmoltcpMdnsConfig, SmoltcpStack, SmoltcpTcpProvider,
    StreamId, SwarmEvent, TcpConfig, TcpTransport,
};
use minip2p_platform::EntropyError;

const DIALER_IP: &str = "192.168.1.1";
const LISTENER_IP: &str = "192.168.1.2";
const PROTOCOL: &str = "/minip2p/embedded-e2e/1.0.0";
const PAYLOAD: &[u8] = b"portable endpoint over smoltcp";
#[cfg(feature = "pubsub")]
const TOPIC: &str = "minip2p-embedded-test";
const MAX_STEPS: usize = 30_000;

struct CountingEntropy(u8);

impl EntropySource for CountingEntropy {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        for byte in output {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

#[derive(Clone, Default)]
struct Wire {
    dialer_out: Queue,
    listener_out: Queue,
}

impl Wire {
    fn dialer_device(&self) -> VirtualDevice {
        VirtualDevice {
            outbox: Rc::clone(&self.dialer_out),
            inbox: Rc::clone(&self.listener_out),
        }
    }

    fn listener_device(&self) -> VirtualDevice {
        VirtualDevice {
            outbox: Rc::clone(&self.listener_out),
            inbox: Rc::clone(&self.dialer_out),
        }
    }

    fn is_quiet(&self) -> bool {
        self.dialer_out.borrow().is_empty() && self.listener_out.borrow().is_empty()
    }
}

struct VirtualDevice {
    outbox: Queue,
    inbox: Queue,
}

struct RxFrame(Vec<u8>);

impl RxToken for RxFrame {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct TxSink(Queue);

impl TxToken for TxSink {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0; len];
        let result = f(&mut frame);
        self.0.borrow_mut().push_back(frame);
        result
    }
}

impl Device for VirtualDevice {
    type RxToken<'a>
        = RxFrame
    where
        Self: 'a;
    type TxToken<'a>
        = TxSink
    where
        Self: 'a;

    fn receive(&mut self, _now: Instant) -> Option<(RxFrame, TxSink)> {
        let frame = self.inbox.borrow_mut().pop_front()?;
        Some((RxFrame(frame), TxSink(Rc::clone(&self.outbox))))
    }

    fn transmit(&mut self, _now: Instant) -> Option<TxSink> {
        Some(TxSink(Rc::clone(&self.outbox)))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1500;
        capabilities
    }
}

type Provider = SmoltcpTcpProvider<VirtualDevice>;
type Transport = TcpTransport<Provider, CountingEntropy>;
type Portable = minip2p::PortableEndpoint<Transport, CountingEntropy>;

fn identity(seed: u8) -> Ed25519Keypair {
    Ed25519Keypair::from_secret_key_bytes([seed; 32])
}

fn stack(device: VirtualDevice, cidr: &str) -> SmoltcpStack<VirtualDevice> {
    let mut device = device;
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(cidr.parse::<IpCidr>().expect("valid test CIDR"))
            .expect("room for one address");
    });
    SmoltcpStack::new(device, interface)
}

fn transport(device: VirtualDevice, cidr: &str, identity: Ed25519Keypair, seed: u8) -> Transport {
    transport_on_stack(stack(device, cidr), identity, seed)
}

fn transport_on_stack(
    stack: SmoltcpStack<VirtualDevice>,
    identity: Ed25519Keypair,
    seed: u8,
) -> Transport {
    TcpTransport::with_config(
        SmoltcpTcpProvider::on_stack(stack, SmoltcpConfig::default()),
        identity,
        CountingEntropy(seed),
        TcpConfig::default(),
    )
}

fn endpoint(device: VirtualDevice, cidr: &str, identity: &Ed25519Keypair, seed: u8) -> Portable {
    Endpoint::portable(identity, CountingEntropy(seed.wrapping_add(1)))
        .protocol(PROTOCOL)
        .build(transport(device, cidr, identity.clone(), seed))
        .expect("portable endpoint builds")
}

#[test]
#[cfg(feature = "portable-autonat")]
fn portable_autonat_builds_without_relay_state() {
    let local = identity(120);
    let server = identity(121);
    let wire = Wire::default();
    let server_addr = PeerAddr::new(
        "/ip4/192.168.1.9/tcp/4001"
            .parse()
            .expect("valid AutoNAT address"),
        server.peer_id(),
    )
    .expect("valid AutoNAT peer address");

    let mut endpoint = Endpoint::portable(&local, CountingEntropy(122))
        .smoltcp(stack(wire.dialer_device(), &format!("{DIALER_IP}/24")))
        .listen(format!("/ip4/{DIALER_IP}/tcp/4001"))
        .autonat(server_addr)
        .build()
        .expect("portable AutoNAT endpoint builds");

    assert_eq!(endpoint.reachability(), minip2p::ReachabilityState::Unknown);
    assert_eq!(endpoint.stats().listen_addresses.len(), 1);

    let now = Now::from_millis(0);
    endpoint.poll(now).expect("AutoNAT schedules its probe");
    endpoint.poll(now).expect("scheduled probe drives TCP");
    assert!(
        !wire.is_quiet(),
        "AutoNAT must dial its configured server after receiving listen addresses"
    );
}

#[test]
#[cfg(feature = "portable-autonat")]
fn portable_nat_rejects_an_empty_policy() {
    let local = identity(123);
    let result = Endpoint::portable(&local, CountingEntropy(124))
        .smoltcp(stack(
            Wire::default().dialer_device(),
            &format!("{DIALER_IP}/24"),
        ))
        .portable_nat_config(minip2p::NatConfig::default())
        .build();
    let error = match result {
        Ok(_) => panic!("empty portable NAT policy must be invalid"),
        Err(error) => error,
    };

    assert!(
        error
            .to_string()
            .contains("at least one relay or AutoNAT server")
    );
}

#[test]
#[cfg(all(feature = "portable-autonat", not(feature = "portable-relay")))]
fn portable_autonat_rejects_relay_addresses_without_relay_support() {
    let local = identity(125);
    let relay = identity(126);
    let relay_addr = PeerAddr::new(
        "/ip4/192.168.1.10/tcp/4001".parse().unwrap(),
        relay.peer_id(),
    )
    .unwrap();
    let config = minip2p::NatConfig {
        relays: vec![relay_addr],
        force_relay: true,
        reservation_policy: minip2p::ReservationPolicy::Never,
        ..minip2p::NatConfig::default()
    };

    let result = Endpoint::portable(&local, CountingEntropy(127))
        .smoltcp(stack(
            Wire::default().dialer_device(),
            &format!("{DIALER_IP}/24"),
        ))
        .portable_nat_config(config)
        .build();
    let error = match result {
        Ok(_) => panic!("relay addresses must require portable-relay"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("relay addresses require the portable-relay feature")
    );
}

#[test]
#[cfg(feature = "portable-autonat")]
fn portable_autonat_rejects_reservation_policy_without_a_relay() {
    let local = identity(128);
    let server = identity(129);
    let config = minip2p::NatConfig {
        autonat_servers: vec![
            PeerAddr::new(
                "/ip4/192.168.1.9/tcp/4001".parse().unwrap(),
                server.peer_id(),
            )
            .unwrap(),
        ],
        reservation_policy: minip2p::ReservationPolicy::Always,
        ..minip2p::NatConfig::default()
    };

    let result = Endpoint::portable(&local, CountingEntropy(130))
        .smoltcp(stack(
            Wire::default().dialer_device(),
            &format!("{DIALER_IP}/24"),
        ))
        .portable_nat_config(config)
        .build();
    let error = match result {
        Ok(_) => panic!("reservation policy without a relay must be invalid"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("requires at least one relay"));
}

fn has_ready(events: &[SwarmEvent], peer: &PeerId) -> bool {
    events.iter().any(|event| {
        matches!(event, SwarmEvent::PeerReady { peer_id, protocols }
            if peer_id == peer && protocols.iter().any(|protocol| protocol == PROTOCOL))
    })
}

#[test]
fn portable_endpoints_complete_the_embedded_tcp_stack() {
    let wire = Wire::default();
    let dialer_identity = identity(1);
    let listener_identity = identity(2);
    let dialer_peer = dialer_identity.peer_id();
    let listener_peer = listener_identity.peer_id();
    let mut dialer = endpoint(
        wire.dialer_device(),
        &format!("{DIALER_IP}/24"),
        &dialer_identity,
        10,
    );
    let mut listener = endpoint(
        wire.listener_device(),
        &format!("{LISTENER_IP}/24"),
        &listener_identity,
        20,
    );

    let listen: Multiaddr = format!("/ip4/{LISTENER_IP}/tcp/4001")
        .parse()
        .expect("valid listen address");
    let bound = listener.listen(&listen).expect("listener binds");
    dialer
        .dial(&PeerAddr::new(bound, listener_peer.clone()).expect("valid peer address"))
        .expect("dial starts");

    let mut now_ms = 0;
    let mut dialer_events = Vec::new();
    let mut listener_events = Vec::new();
    let mut ping_started = false;
    let mut stream: Option<StreamId> = None;
    let mut payload_sent = false;

    for _ in 0..MAX_STEPS {
        let now = Now::from_millis(now_ms);
        dialer_events.extend(dialer.poll(now).expect("dialer polls"));
        listener_events.extend(listener.poll(now).expect("listener polls"));

        if has_ready(&dialer_events, &listener_peer)
            && has_ready(&listener_events, &dialer_peer)
            && !ping_started
        {
            dialer.ping(&listener_peer, now).expect("ping starts");
            stream = Some(
                dialer
                    .open_stream(&listener_peer, PROTOCOL, now)
                    .expect("application stream opens"),
            );
            ping_started = true;
        }

        if let Some(stream_id) = stream
            && !payload_sent
            && dialer_events.iter().any(|event| {
                matches!(event, SwarmEvent::StreamReady {
                    peer_id, stream_id: ready, protocol_id, initiated_locally: true, ..
                } if peer_id == &listener_peer && *ready == stream_id && protocol_id == PROTOCOL)
            })
        {
            dialer
                .send_stream(&listener_peer, stream_id, PAYLOAD.to_vec(), now)
                .expect("payload sends");
            dialer
                .close_stream_write(&listener_peer, stream_id, now)
                .expect("write side closes");
            payload_sent = true;
        }

        let ping_finished = dialer_events.iter().any(|event| {
            matches!(event, SwarmEvent::PingRttMeasured { peer_id, .. } if peer_id == &listener_peer)
        });
        let payload_received = stream.is_some_and(|stream_id| {
            listener_events.iter().any(|event| {
                matches!(event, SwarmEvent::StreamData {
                    peer_id, stream_id: received, data, ..
                } if peer_id == &dialer_peer && *received == stream_id && data == PAYLOAD)
            })
        });
        let write_closed = stream.is_some_and(|stream_id| {
            listener_events.iter().any(|event| {
                matches!(event, SwarmEvent::StreamRemoteWriteClosed {
                    peer_id, stream_id: closed, ..
                } if peer_id == &dialer_peer && *closed == stream_id)
            })
        });
        if ping_finished && payload_received && write_closed {
            assert_eq!(dialer.stats().ready_peers, 1);
            assert_eq!(listener.stats().ready_peers, 1);
            return;
        }

        if wire.is_quiet() {
            let deadline = PollDeadline::earliest_opt(
                dialer.next_deadline(now),
                listener.next_deadline(now),
            )
            .unwrap_or_else(|| {
                panic!(
                    "embedded endpoints wedged\n  dialer: {dialer_events:?}\n  listener: {listener_events:?}"
                )
            });
            now_ms = now_ms.max(deadline.as_millis());
        }
    }

    panic!(
        "embedded endpoint gate did not finish\n  dialer: {dialer_events:?}\n  listener: {listener_events:?}"
    );
}

#[test]
fn mdns_discovers_and_connects_portable_endpoints_on_one_shared_stack_each() {
    let wire = Wire::default();
    let a_identity = identity(31);
    let b_identity = identity(32);
    let a_peer = a_identity.peer_id();
    let b_peer = b_identity.peer_id();
    let a_stack = stack(wire.dialer_device(), &format!("{DIALER_IP}/24"));
    let b_stack = stack(wire.listener_device(), &format!("{LISTENER_IP}/24"));

    let carrier = SmoltcpMdnsConfig {
        enable_ipv6: false,
        ..SmoltcpMdnsConfig::default()
    };
    let a_builder = Endpoint::portable(&a_identity, CountingEntropy(40))
        .smoltcp(a_stack)
        .listen(format!("/ip4/{DIALER_IP}/tcp/4001"))
        .mdns()
        .mdns_carrier_config(carrier.clone());
    #[cfg(feature = "pubsub")]
    let a_builder = a_builder
        .pubsub_config(FloodsubConfig::default())
        .discovery();
    let mut a = a_builder
        .protocol(PROTOCOL)
        .build()
        .expect("a embedded endpoint builds");
    let b_builder = Endpoint::portable(&b_identity, CountingEntropy(50))
        .smoltcp(b_stack)
        .listen(format!("/ip4/{LISTENER_IP}/tcp/4001"))
        .mdns()
        .mdns_carrier_config(carrier);
    #[cfg(feature = "pubsub")]
    let b_builder = b_builder
        .pubsub_config(FloodsubConfig::default())
        .discovery();
    let mut b = b_builder
        .protocol(PROTOCOL)
        .build()
        .expect("b embedded endpoint builds");

    let mut now_ms = 0;
    let mut a_events = Vec::new();
    let mut b_events = Vec::new();
    let mut ping_started = false;
    for _ in 0..MAX_STEPS {
        let now = Now::from_millis(now_ms);
        a_events.extend(a.poll(now).expect("a polls"));
        b_events.extend(b.poll(now).expect("b polls"));

        let a_discovered = a_events.iter().any(|event| {
            matches!(event,
                SmoltcpEvent::Discovery(
                    DiscoveryEvent::PeerDiscovered { peer, addrs, source: minip2p::DiscoverySource::Mdns }
                    | DiscoveryEvent::PeerUpdated { peer, addrs, source: minip2p::DiscoverySource::Mdns }
                ) if peer == &b_peer && !addrs.is_empty())
        });
        let b_discovered = b_events.iter().any(|event| {
            matches!(event,
                SmoltcpEvent::Discovery(
                    DiscoveryEvent::PeerDiscovered { peer, addrs, source: minip2p::DiscoverySource::Mdns }
                    | DiscoveryEvent::PeerUpdated { peer, addrs, source: minip2p::DiscoverySource::Mdns }
                ) if peer == &a_peer && !addrs.is_empty())
        });
        let a_ready = a_events.iter().any(|event| {
            matches!(event, SmoltcpEvent::Endpoint(SwarmEvent::PeerReady { peer_id, .. })
                if peer_id == &b_peer)
        });
        let b_ready = b_events.iter().any(|event| {
            matches!(event, SmoltcpEvent::Endpoint(SwarmEvent::PeerReady { peer_id, .. })
                if peer_id == &a_peer)
        });
        if a_ready && b_ready && !ping_started {
            a.ping(&b_peer, now).expect("mDNS-discovered peer pings");
            ping_started = true;
        }
        let ping_finished = a_events.iter().any(|event| {
            matches!(event, SmoltcpEvent::Endpoint(SwarmEvent::PingRttMeasured { peer_id, .. })
                if peer_id == &b_peer)
        });
        #[cfg(feature = "pubsub")]
        let a_merged = a.known_peers().iter().any(|known| {
            known.peer == b_peer && !known.beacon_addrs.is_empty() && !known.mdns_addrs.is_empty()
        });
        #[cfg(feature = "pubsub")]
        let b_merged = b.known_peers().iter().any(|known| {
            known.peer == a_peer && !known.beacon_addrs.is_empty() && !known.mdns_addrs.is_empty()
        });
        #[cfg(not(feature = "pubsub"))]
        let (a_merged, b_merged) = (true, true);
        if a_discovered
            && b_discovered
            && a_ready
            && b_ready
            && ping_finished
            && a_merged
            && b_merged
        {
            assert_eq!(a.stats().ready_peers, 1);
            assert_eq!(b.stats().ready_peers, 1);
            return;
        }

        if wire.is_quiet() {
            let deadline = PollDeadline::earliest_opt(a.next_deadline(now), b.next_deadline(now))
                .unwrap_or_else(|| panic!("mDNS endpoints wedged"));
            now_ms = now_ms.max(deadline.as_millis());
        }
    }

    panic!("mDNS endpoint gate did not finish\n  a: {a_events:?}\n  b: {b_events:?}");
}

#[test]
#[cfg(feature = "pubsub")]
fn portable_pubsub_delivers_over_the_composed_smoltcp_endpoint() {
    let wire = Wire::default();
    let a_identity = identity(61);
    let b_identity = identity(62);
    let b_peer = b_identity.peer_id();
    let mut a = Endpoint::portable(&a_identity, CountingEntropy(70))
        .smoltcp(stack(wire.dialer_device(), &format!("{DIALER_IP}/24")))
        .pubsub_config(FloodsubConfig::default())
        .build()
        .expect("a endpoint builds");
    let mut b = Endpoint::portable(&b_identity, CountingEntropy(80))
        .smoltcp(stack(wire.listener_device(), &format!("{LISTENER_IP}/24")))
        .listen(format!("/ip4/{LISTENER_IP}/tcp/4001"))
        .pubsub_config(FloodsubConfig::default())
        .build()
        .expect("b endpoint builds");
    a.subscribe(TOPIC, Now::from_millis(0))
        .expect("a subscribes");
    b.subscribe(TOPIC, Now::from_millis(0))
        .expect("b subscribes");
    a.dial(
        &PeerAddr::new(
            format!("/ip4/{LISTENER_IP}/tcp/4001").parse().unwrap(),
            b_peer.clone(),
        )
        .unwrap(),
    )
    .expect("dial starts");

    let mut now_ms = 0;
    let mut published = false;
    let mut a_events = Vec::new();
    let mut b_events = Vec::new();
    for _ in 0..MAX_STEPS {
        let now = Now::from_millis(now_ms);
        a_events.extend(a.poll(now).expect("a polls"));
        b_events.extend(b.poll(now).expect("b polls"));
        let remote_subscribed = a_events.iter().any(|event| {
            matches!(event, SmoltcpEvent::Pubsub(PubsubEvent::PeerSubscribed { peer, topic })
                if peer == &b_peer && topic == TOPIC)
        });
        if remote_subscribed && !published {
            a.publish(TOPIC, PAYLOAD, now).expect("message publishes");
            published = true;
        }
        if b_events.iter().any(|event| {
            matches!(event, SmoltcpEvent::Pubsub(PubsubEvent::Message { topics, data, signed: true, .. })
                if topics.iter().any(|topic| topic == TOPIC) && data == PAYLOAD)
        }) {
            return;
        }
        if wire.is_quiet() {
            let deadline = PollDeadline::earliest_opt(a.next_deadline(now), b.next_deadline(now))
                .unwrap_or_else(|| panic!("pubsub endpoints wedged"));
            now_ms = now_ms.max(deadline.as_millis());
        }
    }
    panic!("portable pubsub did not deliver\n  a: {a_events:?}\n  b: {b_events:?}");
}

#[test]
#[cfg(feature = "pubsub")]
fn signed_discovery_reserves_its_pubsub_topic() {
    const RESERVED: &str = "/minip2p/test/reserved-discovery";
    let identity = identity(83);
    let mut endpoint = Endpoint::portable(&identity, CountingEntropy(84))
        .smoltcp(stack(
            Wire::default().dialer_device(),
            &format!("{DIALER_IP}/24"),
        ))
        .pubsub_config(FloodsubConfig::default())
        .beacon_config(BeaconConfig {
            topic: RESERVED.into(),
            ..BeaconConfig::default()
        })
        .build()
        .expect("discovery endpoint builds");
    let now = Now::from_millis(0);

    assert_eq!(
        endpoint.unsubscribe(RESERVED, now),
        Err(SmoltcpPubsubError::DiscoveryTopicReserved)
    );
    assert_eq!(
        endpoint.publish(RESERVED, b"not a beacon", now),
        Err(SmoltcpPubsubError::DiscoveryTopicReserved)
    );
}

#[test]
#[cfg(feature = "pubsub")]
fn beacon_backpressure_preserves_events_and_does_not_fail_poll() {
    let wire = Wire::default();
    let a_identity = identity(85);
    let b_identity = identity(86);
    let b_peer = b_identity.peer_id();
    let flood = FloodsubConfig {
        max_pending_per_peer: 0,
        ..FloodsubConfig::default()
    };
    let beacon = BeaconConfig {
        beacon_interval_ms: 1,
        ..BeaconConfig::default()
    };
    let mut a = Endpoint::portable(&a_identity, CountingEntropy(87))
        .smoltcp(stack(wire.dialer_device(), &format!("{DIALER_IP}/24")))
        .listen(format!("/ip4/{DIALER_IP}/tcp/4001"))
        .pubsub_config(flood.clone())
        .beacon_config(beacon.clone())
        .build()
        .expect("a endpoint builds");
    let mut b = Endpoint::portable(&b_identity, CountingEntropy(88))
        .smoltcp(stack(wire.listener_device(), &format!("{LISTENER_IP}/24")))
        .listen(format!("/ip4/{LISTENER_IP}/tcp/4001"))
        .pubsub_config(flood)
        .beacon_config(beacon)
        .build()
        .expect("b endpoint builds");
    a.subscribe(TOPIC, Now::from_millis(0))
        .expect("a subscribes to application topic");
    b.subscribe(TOPIC, Now::from_millis(0))
        .expect("b subscribes to application topic");
    a.dial(
        &PeerAddr::new(
            format!("/ip4/{LISTENER_IP}/tcp/4001").parse().unwrap(),
            b_peer.clone(),
        )
        .unwrap(),
    )
    .expect("dial starts");

    let mut now_ms = 0;
    for _ in 0..MAX_STEPS {
        let now = Now::from_millis(now_ms);
        let a_events = a.poll(now).expect("beacon backpressure is best-effort");
        let _ = b.poll(now).expect("b polls");
        if a_events.iter().any(|event| {
            matches!(event, SmoltcpEvent::Pubsub(PubsubEvent::PeerSubscribed { peer, topic })
                if peer == &b_peer && topic == TOPIC)
        }) {
            return;
        }
        if wire.is_quiet() {
            let deadline = PollDeadline::earliest_opt(a.next_deadline(now), b.next_deadline(now))
                .expect("connected discovery endpoints retain a deadline");
            now_ms = now_ms.max(deadline.as_millis());
        }
    }
    panic!("remote subscription was lost while beacon publication was backpressured");
}

#[test]
#[cfg(feature = "pubsub")]
fn signed_beacons_populate_discovery_without_mdns() {
    let wire = Wire::default();
    let a_identity = identity(91);
    let b_identity = identity(92);
    let a_peer = a_identity.peer_id();
    let b_peer = b_identity.peer_id();
    let mut a = Endpoint::portable(&a_identity, CountingEntropy(100))
        .smoltcp(stack(wire.dialer_device(), &format!("{DIALER_IP}/24")))
        .listen(format!("/ip4/{DIALER_IP}/tcp/4001"))
        .pubsub_config(FloodsubConfig::default())
        .discovery()
        .build()
        .expect("a endpoint builds");
    let mut b = Endpoint::portable(&b_identity, CountingEntropy(110))
        .smoltcp(stack(wire.listener_device(), &format!("{LISTENER_IP}/24")))
        .listen(format!("/ip4/{LISTENER_IP}/tcp/4001"))
        .pubsub_config(FloodsubConfig::default())
        .discovery()
        .build()
        .expect("b endpoint builds");
    a.dial(
        &PeerAddr::new(
            format!("/ip4/{LISTENER_IP}/tcp/4001").parse().unwrap(),
            b_peer.clone(),
        )
        .unwrap(),
    )
    .expect("bootstrap dial starts");

    let mut now_ms = 0;
    let mut a_events = Vec::new();
    let mut b_events = Vec::new();
    for _ in 0..MAX_STEPS {
        let now = Now::from_millis(now_ms);
        a_events.extend(a.poll(now).expect("a polls"));
        b_events.extend(b.poll(now).expect("b polls"));
        let a_saw_b = a_events.iter().any(|event| {
            matches!(event, SmoltcpEvent::Discovery(DiscoveryEvent::PeerDiscovered {
                peer, source: minip2p::DiscoverySource::SignedBeacon, ..
            }) if peer == &b_peer)
        });
        let b_saw_a = b_events.iter().any(|event| {
            matches!(event, SmoltcpEvent::Discovery(DiscoveryEvent::PeerDiscovered {
                peer, source: minip2p::DiscoverySource::SignedBeacon, ..
            }) if peer == &a_peer)
        });
        if a_saw_b && b_saw_a {
            assert!(a.known_peers().iter().any(|known| {
                known.peer == b_peer
                    && !known.beacon_addrs.is_empty()
                    && known.mdns_addrs.is_empty()
            }));
            assert!(b.known_peers().iter().any(|known| {
                known.peer == a_peer
                    && !known.beacon_addrs.is_empty()
                    && known.mdns_addrs.is_empty()
            }));
            return;
        }
        if wire.is_quiet() {
            let deadline = PollDeadline::earliest_opt(a.next_deadline(now), b.next_deadline(now))
                .unwrap_or_else(|| panic!("discovery endpoints wedged"));
            now_ms = now_ms.max(deadline.as_millis());
        }
    }
    panic!("signed discovery did not converge\n  a: {a_events:?}\n  b: {b_events:?}");
}
