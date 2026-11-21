//! Full portable-endpoint gate over two real smoltcp TCP stacks.
//!
//! Nothing below the virtual IP link is mocked: the endpoints perform TCP,
//! Noise XX, Yamux, Identify, Ping, and application-stream negotiation using
//! only caller-supplied devices, entropy, and time.

#![cfg(feature = "smoltcp")]

extern crate alloc;

use alloc::{collections::VecDeque, rc::Rc, vec, vec::Vec};
use core::cell::RefCell;

#[cfg(feature = "pubsub")]
use minip2p::GossipsubEvent;
use minip2p::smoltcp::iface::{Config, Interface};
use minip2p::smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use minip2p::smoltcp::time::Instant;
use minip2p::smoltcp::wire::{HardwareAddress, IpCidr};
#[cfg(feature = "discovery")]
use minip2p::{BeaconConfig, GossipsubError};
use minip2p::{
    ConnectOutcome, Deadline, DiscoveryEvent, Ed25519Keypair, EndpointEvent, EntropySource,
    ManualClock, Multiaddr, Now, PeerAddr, PeerId, PortableEndpointBuilder, SmoltcpConfig,
    SmoltcpMdnsConfig, SmoltcpStack, SmoltcpTcpProvider, StreamKey, TcpConfig, TcpTransport,
};
use minip2p_core::platform::EntropyError;

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
type Portable = minip2p::PortableEndpoint<Transport, CountingEntropy, ManualClock>;

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
    .expect("valid config")
}

fn endpoint(device: VirtualDevice, cidr: &str, identity: &Ed25519Keypair, seed: u8) -> Portable {
    PortableEndpointBuilder::new(
        identity,
        CountingEntropy(seed.wrapping_add(1)),
        ManualClock::default(),
    )
    .protocol(PROTOCOL)
    .build(transport(device, cidr, identity.clone(), seed))
    .expect("portable endpoint builds")
}

/// Options set before `.smoltcp(..)` carry over: protocols keep their
/// first-registration handles, set on either side of the step.
#[test]
fn shared_options_carry_across_the_smoltcp_step() {
    let local = identity(123);
    let wire = Wire::default();
    let endpoint =
        PortableEndpointBuilder::new(&local, CountingEntropy(124), ManualClock::default())
            .protocol("/a/1")
            .smoltcp(stack(wire.dialer_device(), &format!("{DIALER_IP}/24")))
            .manual_ack_protocol("/b/1")
            .protocol("/a/1")
            .build()
            .expect("smoltcp endpoint builds");
    let (a, b) = (endpoint.protocol_id("/a/1"), endpoint.protocol_id("/b/1"));
    assert!(a.is_some() && b.is_some() && a < b, "{a:?} {b:?}");
}

#[test]
#[cfg(feature = "autonat")]
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

    let mut endpoint =
        PortableEndpointBuilder::new(&local, CountingEntropy(122), ManualClock::default())
            .smoltcp(stack(wire.dialer_device(), &format!("{DIALER_IP}/24")))
            .listen(format!("/ip4/{DIALER_IP}/tcp/4001"))
            .autonat_server(server_addr)
            .build()
            .expect("portable AutoNAT endpoint builds");

    assert_eq!(endpoint.reachability(), minip2p::ReachabilityState::Unknown);
    assert_eq!(endpoint.stats().bound_addresses.len(), 1);

    let now = Now::from_millis(0);
    endpoint
        .at(now)
        .poll()
        .expect("AutoNAT schedules its probe");
    endpoint.at(now).poll().expect("scheduled probe drives TCP");
    assert!(
        !wire.is_quiet(),
        "AutoNAT must dial its configured server after receiving listen addresses"
    );
}

#[test]
#[cfg(feature = "autonat")]
fn autonat_picks_up_listen_addresses_bound_after_build() {
    let local = identity(140);
    let server = identity(141);
    let wire = Wire::default();
    let server_addr = PeerAddr::new(
        "/ip4/192.168.1.9/tcp/4001"
            .parse()
            .expect("valid AutoNAT address"),
        server.peer_id(),
    )
    .expect("valid AutoNAT peer address");

    let mut endpoint =
        PortableEndpointBuilder::new(&local, CountingEntropy(142), ManualClock::default())
            .smoltcp(stack(wire.dialer_device(), &format!("{DIALER_IP}/24")))
            .autonat_server(server_addr)
            .build()
            .expect("portable AutoNAT endpoint builds");

    // No listener yet: there are no dial-back addresses to probe, so the
    // endpoint must stay quiet no matter how long the host idles.
    let mut now_ms = 0;
    for _ in 0..100 {
        endpoint
            .at(Now::from_millis(now_ms))
            .poll()
            .expect("poll without listeners");
        assert!(wire.is_quiet(), "no listen address means no AutoNAT dial");
        now_ms += 100;
    }

    // A post-build listen must reach the agent too.
    endpoint
        .listen_on(
            &format!("/ip4/{DIALER_IP}/tcp/4001")
                .parse()
                .expect("valid listen address"),
        )
        .expect("post-build listen binds");

    for _ in 0..100 {
        endpoint
            .at(Now::from_millis(now_ms))
            .poll()
            .expect("poll after listen");
        if !wire.is_quiet() {
            return;
        }
        now_ms += 100;
    }
    panic!("AutoNAT never probed after a post-build listen");
}

fn has_ready(events: &[EndpointEvent], peer: &PeerId) -> bool {
    events.iter().any(|event| {
        matches!(event, EndpointEvent::PeerReady { peer_id, protocols, .. }
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
    let bound = listener.listen_on(&listen).expect("listener binds");
    dialer
        .at(Now::from_millis(0))
        .connect(PeerAddr::new(bound, listener_peer).expect("valid peer address"))
        .expect("connect starts");

    let mut now_ms = 0;
    let mut dialer_events = Vec::new();
    let mut listener_events = Vec::new();
    let mut ping_started = false;
    let mut stream: Option<StreamKey> = None;
    let mut payload_sent = false;

    for _ in 0..MAX_STEPS {
        let now = Now::from_millis(now_ms);
        dialer_events.extend(dialer.at(now).poll().expect("dialer polls"));
        listener_events.extend(listener.at(now).poll().expect("listener polls"));

        if has_ready(&dialer_events, &listener_peer)
            && has_ready(&listener_events, &dialer_peer)
            && !ping_started
        {
            dialer.at(now).ping(&listener_peer).expect("ping starts");
            stream = Some(
                dialer
                    .at(now)
                    .open_stream(&listener_peer, PROTOCOL)
                    .expect("application stream opens"),
            );
            ping_started = true;
        }

        if let Some(stream) = stream
            && !payload_sent
            && dialer_events.iter().any(|event| {
                matches!(event, EndpointEvent::StreamReady {
                    peer_id, stream: ready, protocol_id, initiated_locally: true, ..
                } if peer_id == &listener_peer && *ready == stream && protocol_id == PROTOCOL)
            })
        {
            dialer
                .at(now)
                .send_stream(stream, PAYLOAD.to_vec())
                .expect("payload sends");
            dialer
                .at(now)
                .close_stream_write(stream)
                .expect("write side closes");
            payload_sent = true;
        }

        let ping_finished = dialer_events.iter().any(|event| {
            matches!(event, EndpointEvent::PingRttMeasured { peer_id, .. } if peer_id == &listener_peer)
        });
        // Stream ids match across the two ends; connection ids need not.
        let payload_received = stream.is_some_and(|stream| {
            listener_events.iter().any(|event| {
                matches!(event, EndpointEvent::StreamData {
                    peer_id, stream: received, data,
                } if peer_id == &dialer_peer
                    && received.stream_id() == stream.stream_id()
                    && data == PAYLOAD)
            })
        });
        let write_closed = stream.is_some_and(|stream| {
            listener_events.iter().any(|event| {
                matches!(event, EndpointEvent::StreamRemoteWriteClosed {
                    peer_id, stream: closed,
                } if peer_id == &dialer_peer && closed.stream_id() == stream.stream_id())
            })
        });
        if ping_finished && payload_received && write_closed {
            assert_eq!(dialer.stats().ready_peers, 1);
            assert_eq!(listener.stats().ready_peers, 1);
            return;
        }

        if wire.is_quiet() {
            let deadline = Deadline::earliest_opt(
                dialer.at(now).next_deadline(),
                listener.at(now).next_deadline(),
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
fn portable_connect_settles_over_smoltcp_tcp() {
    let wire = Wire::default();
    let dialer_identity = identity(3);
    let listener_identity = identity(4);
    let listener_peer = listener_identity.peer_id();
    let mut dialer = endpoint(
        wire.dialer_device(),
        &format!("{DIALER_IP}/24"),
        &dialer_identity,
        11,
    );
    let mut listener = endpoint(
        wire.listener_device(),
        &format!("{LISTENER_IP}/24"),
        &listener_identity,
        21,
    );

    let listen: Multiaddr = format!("/ip4/{LISTENER_IP}/tcp/4001")
        .parse()
        .expect("valid listen address");
    let bound = listener.listen_on(&listen).expect("listener binds");
    let target = PeerAddr::new(bound, listener_peer).expect("valid peer address");
    let id = dialer
        .at(Now::from_millis(0))
        .connect(target)
        .expect("connect admitted");

    let mut now_ms = 0;
    let mut dialer_events = Vec::new();
    for _ in 0..MAX_STEPS {
        let now = Now::from_millis(now_ms);
        dialer_events.extend(dialer.at(now).poll().expect("dialer polls"));
        listener.at(now).poll().expect("listener polls");
        if dialer_events.iter().any(|event| {
            matches!(
                event,
                EndpointEvent::ConnectSettled {
                    connect_id,
                    outcome: ConnectOutcome::Connected { .. },
                    ..
                } if *connect_id == id
            )
        }) {
            assert!(dialer.connection_id(&listener_peer).is_some());
            return;
        }
        if wire.is_quiet() {
            let deadline = Deadline::earliest_opt(
                dialer.at(now).next_deadline(),
                listener.at(now).next_deadline(),
            )
            .unwrap_or_else(|| panic!("embedded connect wedged\n  dialer: {dialer_events:?}"));
            now_ms = now_ms.max(deadline.as_millis());
        }
    }
    panic!("portable connect did not settle\n  dialer: {dialer_events:?}");
}

/// Dropping or closing a connected portable endpoint sends its close: the
/// smoltcp provider owns the stack, so the teardown's final transport polls
/// put the FIN on the wire and the remote sees the connection end.
#[test]
fn dropping_a_portable_endpoint_closes_its_smoltcp_connections() {
    remote_sees_teardown(|endpoint, _| drop(endpoint));
}

#[test]
fn closing_a_portable_endpoint_closes_its_smoltcp_connections() {
    remote_sees_teardown(|endpoint, _| drop(endpoint.close()));
}

/// An application that disconnected the peer and already saw its
/// `ConnectionClosed` may drop at once: the close still reaches the wire.
#[test]
fn dropping_after_a_seen_disconnect_still_sends_the_close() {
    remote_sees_teardown(|mut endpoint, peer| {
        endpoint.disconnect(&peer).expect("disconnect");
        let closed = (0..MAX_STEPS).any(|_| {
            endpoint.poll().expect("poll").iter().any(
                |event| matches!(event, EndpointEvent::ConnectionClosed { peer_id, .. } if *peer_id == peer),
            )
        });
        assert!(closed, "the local close was reported");
        drop(endpoint);
    });
}

fn remote_sees_teardown(teardown: impl FnOnce(Portable, PeerId)) {
    let wire = Wire::default();
    let dialer_identity = identity(5);
    let listener_identity = identity(6);
    let dialer_peer = dialer_identity.peer_id();
    let listener_peer = listener_identity.peer_id();
    let mut dialer = endpoint(
        wire.dialer_device(),
        &format!("{DIALER_IP}/24"),
        &dialer_identity,
        31,
    );
    let mut listener = endpoint(
        wire.listener_device(),
        &format!("{LISTENER_IP}/24"),
        &listener_identity,
        41,
    );
    let listen: Multiaddr = format!("/ip4/{LISTENER_IP}/tcp/4001")
        .parse()
        .expect("valid listen address");
    let bound = listener.listen_on(&listen).expect("listener binds");
    let target = PeerAddr::new(bound, listener_peer).expect("valid peer address");
    dialer
        .at(Now::from_millis(0))
        .connect(target)
        .expect("connect admitted");

    let mut now_ms = 0;
    let mut connected = false;
    for _ in 0..MAX_STEPS {
        let now = Now::from_millis(now_ms);
        dialer.at(now).poll().expect("dialer polls");
        listener.at(now).poll().expect("listener polls");
        if dialer.connection_id(&listener_peer).is_some()
            && listener.connection_id(&dialer_peer).is_some()
        {
            connected = true;
            break;
        }
        if wire.is_quiet()
            && let Some(deadline) = Deadline::earliest_opt(
                dialer.at(now).next_deadline(),
                listener.at(now).next_deadline(),
            )
        {
            now_ms = now_ms.max(deadline.as_millis());
        }
    }
    assert!(connected, "the peers did not connect");
    let now = Now::from_millis(now_ms);

    teardown(dialer, listener_peer);
    // The clock stays put, so only the dialer's close can end the
    // connection here, never an idle timeout.
    let closed = (0..MAX_STEPS).any(|_| {
        listener
            .at(now)
            .poll()
            .expect("listener polls")
            .iter()
            .any(|event| {
                matches!(event, EndpointEvent::ConnectionClosed { peer_id, .. } if *peer_id == dialer_peer)
            })
    });
    assert!(
        closed,
        "the listener never saw the torn-down dialer's close"
    );
}

/// The host reconfigures a wildcard listener's interface through a stack
/// handle it kept, with no further `listen`: the endpoint's warmed address
/// cache must notice, so Identify advertises the new address.
#[test]
fn identify_follows_an_interface_address_change_under_a_wildcard_listener() {
    let wire = Wire::default();
    let dialer_identity = identity(5);
    let listener_identity = identity(6);
    let listener_peer = listener_identity.peer_id();
    let mut dialer = endpoint(
        wire.dialer_device(),
        &format!("{DIALER_IP}/24"),
        &dialer_identity,
        31,
    );
    let listener_stack = stack(wire.listener_device(), &format!("{LISTENER_IP}/24"));
    let mut listener = PortableEndpointBuilder::new(
        &listener_identity,
        CountingEntropy(42),
        ManualClock::default(),
    )
    .protocol(PROTOCOL)
    .build(transport_on_stack(
        listener_stack.clone(),
        listener_identity.clone(),
        41,
    ))
    .expect("listener builds");
    listener
        .listen_on(&"/ip4/0.0.0.0/tcp/4001".parse().expect("wildcard"))
        .expect("listener binds the wildcard");
    for now_ms in 0..3 {
        listener
            .at(Now::from_millis(now_ms))
            .poll()
            .expect("warm the cache");
    }

    let added: Multiaddr = "/ip4/192.168.1.50/tcp/4001".parse().expect("added address");
    listener_stack
        .borrow_mut()
        .interface
        .update_ip_addrs(|addrs| {
            addrs
                .push("192.168.1.50/24".parse::<IpCidr>().expect("cidr"))
                .expect("room for a second address");
        });

    let target = PeerAddr::new(
        format!("/ip4/{LISTENER_IP}/tcp/4001")
            .parse()
            .expect("listener address"),
        listener_peer,
    )
    .expect("peer address");
    dialer
        .at(Now::from_millis(3))
        .connect(target)
        .expect("admitted");
    let mut now_ms = 3;
    for _ in 0..MAX_STEPS {
        let now = Now::from_millis(now_ms);
        dialer.at(now).poll().expect("dialer polls");
        listener.at(now).poll().expect("listener polls");
        if let Some(info) = dialer.peer_info(&listener_peer) {
            assert!(
                info.listen_addrs.contains(&added.to_bytes()),
                "Identify still advertises the old interface addresses"
            );
            return;
        }
        if wire.is_quiet() {
            let deadline = Deadline::earliest_opt(
                dialer.at(now).next_deadline(),
                listener.at(now).next_deadline(),
            )
            .expect("connect wedged");
            now_ms = now_ms.max(deadline.as_millis());
        }
    }
    panic!("Identify never arrived");
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
    let a_builder =
        PortableEndpointBuilder::new(&a_identity, CountingEntropy(40), ManualClock::default())
            .smoltcp(a_stack)
            .listen(format!("/ip4/{DIALER_IP}/tcp/4001"))
            .mdns()
            .mdns_carrier_config(carrier.clone());
    #[cfg(feature = "discovery")]
    let a_builder = a_builder.gossipsub().discovery();
    let mut a = a_builder
        .protocol(PROTOCOL)
        .build()
        .expect("a embedded endpoint builds");
    let b_builder =
        PortableEndpointBuilder::new(&b_identity, CountingEntropy(50), ManualClock::default())
            .smoltcp(b_stack)
            .listen(format!("/ip4/{LISTENER_IP}/tcp/4001"))
            .mdns()
            .mdns_carrier_config(carrier);
    #[cfg(feature = "discovery")]
    let b_builder = b_builder.gossipsub().discovery();
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
        a_events.extend(a.at(now).poll().expect("a polls"));
        b_events.extend(b.at(now).poll().expect("b polls"));

        let a_discovered = a_events.iter().any(|event| {
            matches!(event,
                EndpointEvent::Discovery(
                    DiscoveryEvent::PeerDiscovered { peer, addrs, source: minip2p::DiscoverySource::Mdns }
                    | DiscoveryEvent::PeerUpdated { peer, addrs, source: minip2p::DiscoverySource::Mdns }
                ) if peer == &b_peer && !addrs.is_empty())
        });
        let b_discovered = b_events.iter().any(|event| {
            matches!(event,
                EndpointEvent::Discovery(
                    DiscoveryEvent::PeerDiscovered { peer, addrs, source: minip2p::DiscoverySource::Mdns }
                    | DiscoveryEvent::PeerUpdated { peer, addrs, source: minip2p::DiscoverySource::Mdns }
                ) if peer == &a_peer && !addrs.is_empty())
        });
        let a_ready = a_events.iter().any(|event| {
            matches!(event, EndpointEvent::PeerReady { peer_id, .. }
                if peer_id == &b_peer)
        });
        let b_ready = b_events.iter().any(|event| {
            matches!(event, EndpointEvent::PeerReady { peer_id, .. }
                if peer_id == &a_peer)
        });
        if a_ready && b_ready && !ping_started {
            a.at(now).ping(&b_peer).expect("mDNS-discovered peer pings");
            ping_started = true;
        }
        let ping_finished = a_events.iter().any(|event| {
            matches!(event, EndpointEvent::PingRttMeasured { peer_id, .. }
                if peer_id == &b_peer)
        });
        #[cfg(feature = "discovery")]
        let a_merged = a.known_peers().iter().any(|known| {
            known.peer == b_peer && !known.beacon_addrs.is_empty() && !known.mdns_addrs.is_empty()
        });
        #[cfg(feature = "discovery")]
        let b_merged = b.known_peers().iter().any(|known| {
            known.peer == a_peer && !known.beacon_addrs.is_empty() && !known.mdns_addrs.is_empty()
        });
        #[cfg(not(feature = "discovery"))]
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
            let deadline =
                Deadline::earliest_opt(a.at(now).next_deadline(), b.at(now).next_deadline())
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
    let mut a =
        PortableEndpointBuilder::new(&a_identity, CountingEntropy(70), ManualClock::default())
            .smoltcp(stack(wire.dialer_device(), &format!("{DIALER_IP}/24")))
            .gossipsub()
            .build()
            .expect("a endpoint builds");
    let mut b =
        PortableEndpointBuilder::new(&b_identity, CountingEntropy(80), ManualClock::default())
            .smoltcp(stack(wire.listener_device(), &format!("{LISTENER_IP}/24")))
            .listen(format!("/ip4/{LISTENER_IP}/tcp/4001"))
            .gossipsub()
            .build()
            .expect("b endpoint builds");
    a.at(Now::from_millis(0))
        .subscribe(TOPIC)
        .expect("a subscribes");
    b.at(Now::from_millis(0))
        .subscribe(TOPIC)
        .expect("b subscribes");
    a.at(Now::from_millis(0))
        .connect(
            PeerAddr::new(
                format!("/ip4/{LISTENER_IP}/tcp/4001").parse().unwrap(),
                b_peer,
            )
            .unwrap(),
        )
        .expect("connect starts");

    let mut now_ms = 0;
    let mut published = false;
    let mut a_events = Vec::new();
    let mut b_events = Vec::new();
    for _ in 0..MAX_STEPS {
        let now = Now::from_millis(now_ms);
        a_events.extend(a.at(now).poll().expect("a polls"));
        b_events.extend(b.at(now).poll().expect("b polls"));
        let remote_subscribed = a_events.iter().any(|event| {
            matches!(event, EndpointEvent::Gossipsub(GossipsubEvent::PeerSubscribed { peer, topic })
                if peer == &b_peer && topic == TOPIC)
        });
        if remote_subscribed && !published {
            a.at(now)
                .publish(TOPIC, PAYLOAD)
                .expect("message publishes");
            published = true;
        }
        if b_events.iter().any(|event| {
            matches!(event, EndpointEvent::Gossipsub(GossipsubEvent::Message { topics, data, signed: true, .. })
                if topics.iter().any(|topic| topic == TOPIC) && data == PAYLOAD)
        }) {
            return;
        }
        if wire.is_quiet() {
            let deadline =
                Deadline::earliest_opt(a.at(now).next_deadline(), b.at(now).next_deadline())
                    .unwrap_or_else(|| panic!("pubsub endpoints wedged"));
            now_ms = now_ms.max(deadline.as_millis());
        }
    }
    panic!("portable pubsub did not deliver\n  a: {a_events:?}\n  b: {b_events:?}");
}

#[test]
#[cfg(feature = "discovery")]
fn signed_discovery_reserves_its_pubsub_topic() {
    const RESERVED: &str = "/minip2p/test/reserved-discovery";
    let identity = identity(83);
    let mut endpoint =
        PortableEndpointBuilder::new(&identity, CountingEntropy(84), ManualClock::default())
            .smoltcp(stack(
                Wire::default().dialer_device(),
                &format!("{DIALER_IP}/24"),
            ))
            .gossipsub()
            .discovery_config(BeaconConfig {
                topic: RESERVED.into(),
                ..BeaconConfig::default()
            })
            .build()
            .expect("discovery endpoint builds");
    let now = Now::from_millis(0);

    assert!(matches!(
        endpoint.at(now).unsubscribe(RESERVED),
        Err(GossipsubError::DiscoveryTopicReserved)
    ));
    assert!(matches!(
        endpoint.at(now).publish(RESERVED, b"not a beacon"),
        Err(GossipsubError::DiscoveryTopicReserved)
    ));
}

#[test]
#[cfg(feature = "discovery")]
fn signed_beacons_populate_discovery_without_mdns() {
    let wire = Wire::default();
    let a_identity = identity(91);
    let b_identity = identity(92);
    let a_peer = a_identity.peer_id();
    let b_peer = b_identity.peer_id();
    let mut a =
        PortableEndpointBuilder::new(&a_identity, CountingEntropy(100), ManualClock::default())
            .smoltcp(stack(wire.dialer_device(), &format!("{DIALER_IP}/24")))
            .listen(format!("/ip4/{DIALER_IP}/tcp/4001"))
            .gossipsub()
            .discovery()
            .build()
            .expect("a endpoint builds");
    let mut b =
        PortableEndpointBuilder::new(&b_identity, CountingEntropy(110), ManualClock::default())
            .smoltcp(stack(wire.listener_device(), &format!("{LISTENER_IP}/24")))
            .listen(format!("/ip4/{LISTENER_IP}/tcp/4001"))
            .gossipsub()
            .discovery()
            .build()
            .expect("b endpoint builds");
    a.at(Now::from_millis(0))
        .connect(
            PeerAddr::new(
                format!("/ip4/{LISTENER_IP}/tcp/4001").parse().unwrap(),
                b_peer,
            )
            .unwrap(),
        )
        .expect("bootstrap dial starts");

    let mut now_ms = 0;
    let mut a_events = Vec::new();
    let mut b_events = Vec::new();
    for _ in 0..MAX_STEPS {
        let now = Now::from_millis(now_ms);
        a_events.extend(a.at(now).poll().expect("a polls"));
        b_events.extend(b.at(now).poll().expect("b polls"));
        let a_saw_b = a_events.iter().any(|event| {
            matches!(event, EndpointEvent::Discovery(DiscoveryEvent::PeerDiscovered {
                peer, source: minip2p::DiscoverySource::SignedBeacon, ..
            }) if peer == &b_peer)
        });
        let b_saw_a = b_events.iter().any(|event| {
            matches!(event, EndpointEvent::Discovery(DiscoveryEvent::PeerDiscovered {
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
            let deadline =
                Deadline::earliest_opt(a.at(now).next_deadline(), b.at(now).next_deadline())
                    .unwrap_or_else(|| panic!("discovery endpoints wedged"));
            now_ms = now_ms.max(deadline.as_millis());
        }
    }
    panic!("signed discovery did not converge\n  a: {a_events:?}\n  b: {b_events:?}");
}
