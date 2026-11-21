//! Three-node portable relay gate over a virtual smoltcp IP network.

#![cfg(all(feature = "smoltcp", feature = "relay"))]
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "the scripted three-node relay harness fails immediately when its fixed topology invariants break"
)]

extern crate alloc;

use alloc::{collections::VecDeque, rc::Rc, vec, vec::Vec};
use core::cell::RefCell;

use minip2p::smoltcp::iface::{Config, Interface};
use minip2p::smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use minip2p::smoltcp::time::Instant;
use minip2p::smoltcp::wire::{HardwareAddress, IpCidr};
use minip2p::{
    ConnectFailure, ConnectOutcome, DriverError, Ed25519Keypair, EndpointEvent, EntropySource,
    ManualClock, Multiaddr, NatConfig, NatEvent, Now, Path, PeerAddr, PeerId,
    PortableEndpointBuilder, ReservationPolicy, SmoltcpStack, StreamKey, SwarmError,
};
use minip2p_core::platform::EntropyError;
use minip2p_nat::{AUTONAT_PROTOCOL_ID, HOP_PROTOCOL_ID, STOP_PROTOCOL_ID};
use minip2p_test_support::{ConnectRequestOutcome, PendingConnectId, RelayEmulator};

const A_IP: &str = "192.168.42.1";
const B_IP: &str = "192.168.42.2";
const RELAY_IP: &str = "192.168.42.3";
const APP_PROTOCOL: &str = "/minip2p/embedded-relay/1.0.0";
const PAYLOAD: &[u8] = b"portable circuit over smoltcp tcp";
const MAX_STEPS: usize = 80_000;

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

#[derive(Clone)]
struct VirtualBus {
    queues: Rc<Vec<Queue>>,
}

impl VirtualBus {
    fn new(nodes: usize) -> Self {
        Self {
            queues: Rc::new((0..nodes).map(|_| Queue::default()).collect()),
        }
    }

    fn device(&self, node: usize) -> BusDevice {
        BusDevice {
            node,
            queues: Rc::clone(&self.queues),
        }
    }

    fn is_quiet(&self) -> bool {
        self.queues.iter().all(|queue| queue.borrow().is_empty())
    }
}

struct BusDevice {
    node: usize,
    queues: Rc<Vec<Queue>>,
}

struct RxFrame(Vec<u8>);

impl RxToken for RxFrame {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct BusTx {
    sender: usize,
    queues: Rc<Vec<Queue>>,
}

impl TxToken for BusTx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0; len];
        let result = f(&mut frame);
        for (node, queue) in self.queues.iter().enumerate() {
            if node != self.sender {
                queue.borrow_mut().push_back(frame.clone());
            }
        }
        result
    }
}

impl Device for BusDevice {
    type RxToken<'a>
        = RxFrame
    where
        Self: 'a;
    type TxToken<'a>
        = BusTx
    where
        Self: 'a;

    fn receive(&mut self, _now: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame = self.queues[self.node].borrow_mut().pop_front()?;
        Some((
            RxFrame(frame),
            BusTx {
                sender: self.node,
                queues: Rc::clone(&self.queues),
            },
        ))
    }

    fn transmit(&mut self, _now: Instant) -> Option<Self::TxToken<'_>> {
        Some(BusTx {
            sender: self.node,
            queues: Rc::clone(&self.queues),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1500;
        capabilities
    }
}

fn identity(seed: u8) -> Ed25519Keypair {
    Ed25519Keypair::from_secret_key_bytes([seed; 32])
}

fn stack(device: BusDevice, ip: &str) -> SmoltcpStack<BusDevice> {
    let mut device = device;
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(format!("{ip}/24").parse::<IpCidr>().unwrap())
            .unwrap();
    });
    SmoltcpStack::new(device, interface)
}

fn relay_config(relay: PeerAddr, reservation_policy: ReservationPolicy) -> NatConfig {
    NatConfig {
        relays: vec![relay],
        force_relay: true,
        reservation_policy,
        ..NatConfig::default()
    }
}

struct RelayService {
    emulator: RelayEmulator,
    a: PeerId,
    b: PeerId,
    b_reservation: Option<StreamKey>,
    a_bridge: Option<StreamKey>,
    b_stop: Option<StreamKey>,
    pending: Option<PendingConnectId>,
    bridged: bool,
}

impl RelayService {
    fn new(a: PeerId, b: PeerId) -> Self {
        Self {
            emulator: RelayEmulator::new(),
            a,
            b,
            b_reservation: None,
            a_bridge: None,
            b_stop: None,
            pending: None,
            bridged: false,
        }
    }

    fn handle(
        &mut self,
        endpoint: &mut minip2p::SmoltcpEndpoint<BusDevice, CountingEntropy, ManualClock>,
        event: EndpointEvent,
        now: Now,
    ) {
        match event {
            EndpointEvent::StreamReady {
                peer_id,
                stream,
                protocol_id,
                initiated_locally,
                ..
            } if protocol_id == HOP_PROTOCOL_ID && !initiated_locally => {
                if peer_id == self.b {
                    self.b_reservation = Some(stream);
                } else if peer_id == self.a {
                    self.a_bridge = Some(stream);
                }
            }
            EndpointEvent::StreamReady {
                peer_id,
                stream,
                protocol_id,
                initiated_locally: true,
                ..
            } if peer_id == self.b && protocol_id == STOP_PROTOCOL_ID => {
                self.b_stop = Some(stream);
                let request = self.emulator.drain_stop_bytes_for(&self.b);
                endpoint.at(now).send_stream(stream, request).unwrap();
            }
            EndpointEvent::StreamData {
                peer_id,
                stream,
                data,
            } if peer_id == self.b && Some(stream) == self.b_reservation => {
                self.emulator.on_reserve_request(&self.b, &data).unwrap();
                let response = self.emulator.drain_hop_bytes_for(&self.b);
                endpoint.at(now).send_stream(stream, response).unwrap();
            }
            EndpointEvent::StreamData {
                peer_id,
                stream,
                data,
            } if peer_id == self.a && Some(stream) == self.a_bridge && !self.bridged => {
                let mut response = Vec::new();
                let outcome = self
                    .emulator
                    .on_connect_request(&self.a, &data, &mut response)
                    .unwrap();
                let ConnectRequestOutcome::Bridging {
                    pending_id,
                    target,
                    trailing,
                } = outcome
                else {
                    panic!("reserved target must be bridgeable");
                };
                assert_eq!(target, self.b);
                assert!(trailing.is_empty());
                assert!(response.is_empty());
                self.pending = Some(pending_id);
                let stop = endpoint
                    .at(now)
                    .open_stream(&self.b, STOP_PROTOCOL_ID)
                    .unwrap();
                self.b_stop = Some(stop);
            }
            EndpointEvent::StreamData {
                peer_id,
                stream,
                data,
            } if peer_id == self.b && Some(stream) == self.b_stop && !self.bridged => {
                let mut response = Vec::new();
                let trailing = self
                    .emulator
                    .on_stop_ack_from_target(self.pending.unwrap(), &self.b, &data, &mut response)
                    .unwrap();
                self.bridged = true;
                let stream = self.a_bridge.unwrap();
                endpoint.at(now).send_stream(stream, response).unwrap();
                if !trailing.is_empty() {
                    let stream = self.a_bridge.unwrap();
                    endpoint.at(now).send_stream(stream, trailing).unwrap();
                }
            }
            EndpointEvent::StreamData {
                peer_id,
                stream,
                data,
            } if self.bridged && peer_id == self.a && Some(stream) == self.a_bridge => {
                let stream = self.b_stop.unwrap();
                endpoint.at(now).send_stream(stream, data).unwrap();
            }
            EndpointEvent::StreamData {
                peer_id,
                stream,
                data,
            } if self.bridged && peer_id == self.b && Some(stream) == self.b_stop => {
                let stream = self.a_bridge.unwrap();
                endpoint.at(now).send_stream(stream, data).unwrap();
            }
            EndpointEvent::StreamClosed { peer_id, stream }
                if (peer_id == self.a && Some(stream) == self.a_bridge)
                    || (peer_id == self.b && Some(stream) == self.b_stop) =>
            {
                self.bridged = false;
                self.a_bridge = None;
                self.b_stop = None;
                self.pending = None;
            }
            _ => {}
        }
    }
}

#[test]
fn tcp_smoltcp_peers_establish_and_use_a_relay_circuit() {
    let bus = VirtualBus::new(3);
    let a_identity = identity(121);
    let b_identity = identity(122);
    let relay_identity = identity(123);
    let a_peer = a_identity.peer_id();
    let b_peer = b_identity.peer_id();
    let relay_peer = relay_identity.peer_id();
    let relay_transport: Multiaddr = format!("/ip4/{RELAY_IP}/tcp/4001").parse().unwrap();
    let relay_addr = PeerAddr::new(relay_transport, relay_peer).unwrap();

    let mut a =
        PortableEndpointBuilder::new(&a_identity, CountingEntropy(10), ManualClock::default())
            .smoltcp(stack(bus.device(0), A_IP))
            .nat_config(relay_config(relay_addr.clone(), ReservationPolicy::Never))
            .protocol(APP_PROTOCOL)
            .build()
            .unwrap();
    let mut b =
        PortableEndpointBuilder::new(&b_identity, CountingEntropy(20), ManualClock::default())
            .smoltcp(stack(bus.device(1), B_IP))
            .nat_config(relay_config(relay_addr, ReservationPolicy::Always))
            .protocol(APP_PROTOCOL)
            .build()
            .unwrap();
    let mut relay =
        PortableEndpointBuilder::new(&relay_identity, CountingEntropy(30), ManualClock::default())
            .smoltcp(stack(bus.device(2), RELAY_IP))
            .listen(format!("/ip4/{RELAY_IP}/tcp/4001"))
            .protocol(HOP_PROTOCOL_ID)
            .protocol(STOP_PROTOCOL_ID)
            .build()
            .unwrap();
    let mut service = RelayService::new(a_peer, b_peer);

    let mut now_ms = 0;
    let mut connect_id = None;
    let mut a_events = Vec::new();
    let mut b_events = Vec::new();
    let mut app_stream = None;
    let mut sent = false;
    let mut relay_cut = false;
    let mut polls_after_circuit_close = 0;
    for _ in 0..MAX_STEPS {
        let now = Now::from_millis(now_ms);
        a_events.extend(a.at(now).poll().unwrap());
        b_events.extend(b.at(now).poll().unwrap());
        for event in relay.at(now).poll().unwrap() {
            service.handle(&mut relay, event, now);
        }

        let reserved = b_events.iter().any(|event| {
            matches!(event, EndpointEvent::Nat(NatEvent::RelayReserved { relay, .. })
                if relay == &relay_peer)
        });
        if reserved && connect_id.is_none() {
            connect_id = Some(a.at(now).connect(b_peer).unwrap());
        }
        let a_relayed = a_events.iter().any(|event| {
            matches!(event, EndpointEvent::Nat(NatEvent::PathEstablished {
                peer, path: Path::Relayed { relay }, ..
            }) if peer == &b_peer && relay == &relay_peer)
        });
        let b_relayed = b_events.iter().any(|event| {
            matches!(event, EndpointEvent::Nat(NatEvent::InboundPathEstablished {
                peer, path: Path::Relayed { relay }, ..
            }) if peer == &a_peer && relay == &relay_peer)
        });
        let a_settled = connect_id.is_some_and(|id| {
            a_events.iter().any(|event| {
                matches!(event, EndpointEvent::ConnectSettled {
                    connect_id: found,
                    outcome: ConnectOutcome::Connected { conn_id, .. },
                    ..
                } if *found == id && conn_id.is_circuit())
            })
        });
        if a_relayed && b_relayed && a_settled && app_stream.is_none() {
            app_stream = Some(a.at(now).open_stream(&b_peer, APP_PROTOCOL).unwrap());
        }
        if let Some(stream) = app_stream
            && !sent
            && a_events.iter().any(|event| {
                matches!(event, EndpointEvent::StreamReady {
                    peer_id, stream: id, initiated_locally: true, ..
                } if peer_id == &b_peer && *id == stream)
            })
        {
            a.at(now).send_stream(stream, PAYLOAD.to_vec()).unwrap();
            sent = true;
        }
        let b_conn = b_events.iter().rev().find_map(|event| match event {
            EndpointEvent::ConnectionEstablished { peer_id, conn_id } if peer_id == &a_peer => {
                Some(*conn_id)
            }
            EndpointEvent::ConnectionReplaced { peer_id, new, .. } if peer_id == &a_peer => {
                Some(*new)
            }
            _ => None,
        });
        let received = app_stream.is_some_and(|stream| {
            b_events.iter().any(|event| {
                matches!(event, EndpointEvent::StreamData {
                    peer_id, stream: id, data,
                } if peer_id == &a_peer && Some(id.conn_id()) == b_conn
                    && id.stream_id() == stream.stream_id() && data == PAYLOAD)
            })
        });
        if received && !relay_cut {
            assert!(
                matches!(a.path(&b_peer), Some(Path::Relayed { relay }) if relay == relay_peer)
            );
            assert!(
                matches!(b.path(&a_peer), Some(Path::Relayed { relay }) if relay == relay_peer)
            );
            a.at(now).disconnect(&relay_peer).unwrap();
            relay_cut = true;
        }

        let circuit_closes = a_events
            .iter()
            .filter(|event| {
                matches!(event, EndpointEvent::ConnectionClosed {
                    peer_id, conn_id, ..
                } if peer_id == &b_peer && conn_id.is_circuit())
            })
            .count();
        if circuit_closes > 0 {
            assert_eq!(circuit_closes, 1, "circuit closes exactly once");
            polls_after_circuit_close += 1;
            if polls_after_circuit_close == 100 {
                return;
            }
        }

        if bus.is_quiet() {
            let deadline = [
                a.at(now).next_deadline(),
                b.at(now).next_deadline(),
                relay.at(now).next_deadline(),
            ]
            .into_iter()
            .flatten()
            .min()
            .expect("relay world retains a deadline");
            now_ms = now_ms.max(deadline.as_millis());
        }
    }
    panic!(
        "relay circuit did not close after its relay link\n  a: {a_events:?}\n  b: {b_events:?}"
    );
}

/// A relay that is a path rather than a mode (`dcutr = false`,
/// `force_relay = false`, the default `WhenPrivate` policy) still reserves
/// while reachability is Unknown, accepts a peer's connection over the
/// circuit, and renews the reservation.
#[test]
fn a_raced_relay_reserves_carries_inbound_traffic_and_renews() {
    let bus = VirtualBus::new(3);
    let a_identity = identity(141);
    let b_identity = identity(142);
    let relay_identity = identity(143);
    let a_peer = a_identity.peer_id();
    let b_peer = b_identity.peer_id();
    let relay_peer = relay_identity.peer_id();
    let relay_addr = PeerAddr::new(
        format!("/ip4/{RELAY_IP}/tcp/4001").parse().unwrap(),
        relay_peer,
    )
    .unwrap();

    let mut a =
        PortableEndpointBuilder::new(&a_identity, CountingEntropy(60), ManualClock::default())
            .smoltcp(stack(bus.device(0), A_IP))
            .nat_config(relay_config(relay_addr.clone(), ReservationPolicy::Never))
            .protocol(APP_PROTOCOL)
            .build()
            .unwrap();
    let mut b =
        PortableEndpointBuilder::new(&b_identity, CountingEntropy(70), ManualClock::default())
            .smoltcp(stack(bus.device(1), B_IP))
            .nat_config(NatConfig {
                dcutr: false,
                reservation_default_ttl_secs: 4,
                ..NatConfig::default()
            })
            .relay(relay_addr)
            .protocol(APP_PROTOCOL)
            .build()
            .unwrap();
    let mut relay =
        PortableEndpointBuilder::new(&relay_identity, CountingEntropy(80), ManualClock::default())
            .smoltcp(stack(bus.device(2), RELAY_IP))
            .listen(format!("/ip4/{RELAY_IP}/tcp/4001"))
            .protocol(HOP_PROTOCOL_ID)
            .protocol(STOP_PROTOCOL_ID)
            .build()
            .unwrap();
    let mut service = RelayService::new(a_peer, b_peer);

    let mut now_ms = 0;
    let mut a_events = Vec::new();
    let mut b_events = Vec::new();
    let mut connect_id = None;
    let mut app_stream = None;
    let mut sent = false;
    for _ in 0..MAX_STEPS {
        let now = Now::from_millis(now_ms);
        a_events.extend(a.at(now).poll().unwrap());
        b_events.extend(b.at(now).poll().unwrap());
        for event in relay.at(now).poll().unwrap() {
            service.handle(&mut relay, event, now);
        }

        let reservations = b_events
            .iter()
            .filter(|event| {
                matches!(event, EndpointEvent::Nat(NatEvent::RelayReserved { relay, .. })
                    if relay == &relay_peer)
            })
            .count();
        if reservations > 0 && connect_id.is_none() {
            connect_id = Some(a.at(now).connect(b_peer).unwrap());
        }
        let a_settled = connect_id.is_some_and(|id| {
            a_events.iter().any(|event| {
                matches!(event, EndpointEvent::ConnectSettled {
                    connect_id: found,
                    outcome: ConnectOutcome::Connected { conn_id, .. },
                    ..
                } if *found == id && conn_id.is_circuit())
            })
        });
        if a_settled && app_stream.is_none() {
            app_stream = Some(a.at(now).open_stream(&b_peer, APP_PROTOCOL).unwrap());
        }
        if let Some(stream) = app_stream
            && !sent
            && a_events.iter().any(|event| {
                matches!(event, EndpointEvent::StreamReady {
                    peer_id, stream: id, initiated_locally: true, ..
                } if peer_id == &b_peer && *id == stream)
            })
        {
            a.at(now).send_stream(stream, PAYLOAD.to_vec()).unwrap();
            sent = true;
        }
        let received = b_events.iter().any(|event| {
            matches!(event, EndpointEvent::StreamData { peer_id, stream, data, .. }
                if peer_id == &a_peer && stream.conn_id().is_circuit() && data == PAYLOAD)
        });
        if received && reservations >= 2 {
            assert!(
                matches!(b.path(&a_peer), Some(Path::Relayed { relay }) if relay == relay_peer)
            );
            return;
        }

        if bus.is_quiet() {
            let deadline = [
                a.at(now).next_deadline(),
                b.at(now).next_deadline(),
                relay.at(now).next_deadline(),
            ]
            .into_iter()
            .flatten()
            .min()
            .expect("relay world retains a deadline");
            now_ms = now_ms.max(deadline.as_millis());
        }
    }
    panic!("no inbound circuit traffic and renewal\n  a: {a_events:?}\n  b: {b_events:?}");
}

#[test]
fn portable_relay_and_autonat_compose_and_register_their_protocols() {
    let bus = VirtualBus::new(1);
    let local = identity(126);
    let relay = identity(127);
    let server = identity(128);
    let remote = identity(129).peer_id();
    let relay_addr = PeerAddr::new(
        format!("/ip4/{RELAY_IP}/tcp/4001").parse().unwrap(),
        relay.peer_id(),
    )
    .unwrap();
    let server_addr = PeerAddr::new(
        "/ip4/192.168.42.4/tcp/4001".parse().unwrap(),
        server.peer_id(),
    )
    .unwrap();
    let config = NatConfig {
        relays: vec![relay_addr],
        autonat_servers: vec![server_addr],
        force_relay: true,
        reservation_policy: ReservationPolicy::Always,
        ..NatConfig::default()
    };
    let mut endpoint =
        PortableEndpointBuilder::new(&local, CountingEntropy(50), ManualClock::default())
            .smoltcp(stack(bus.device(0), A_IP))
            .nat_config(config)
            .build()
            .expect("relay and AutoNAT policy composes");

    for protocol in [AUTONAT_PROTOCOL_ID, HOP_PROTOCOL_ID] {
        assert!(matches!(
            endpoint
                .at(Now::from_millis(0))
                .open_stream(&remote, protocol),
            Err(DriverError::Swarm(SwarmError::NotConnected { .. }))
        ));
    }
    assert!(matches!(
        endpoint
            .at(Now::from_millis(0))
            .open_stream(&remote, STOP_PROTOCOL_ID),
        Err(DriverError::Swarm(SwarmError::ProtocolNotRegistered { .. }))
    ));
}

#[test]
fn peer_target_on_an_autonat_only_portable_endpoint_settles_no_usable_route() {
    let bus = VirtualBus::new(1);
    let local = identity(130);
    let server = identity(131);
    let server_addr = PeerAddr::new(
        "/ip4/192.168.42.4/tcp/4001".parse().unwrap(),
        server.peer_id(),
    )
    .unwrap();
    let mut endpoint =
        PortableEndpointBuilder::new(&local, CountingEntropy(51), ManualClock::default())
            .smoltcp(stack(bus.device(0), A_IP))
            .autonat_server(server_addr)
            .build()
            .expect("AutoNAT-only policy builds with relay code available");

    let peer = identity(132).peer_id();
    let id = endpoint.at(Now::from_millis(0)).connect(peer).unwrap();
    let events = endpoint.at(Now::from_millis(0)).poll().unwrap();
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                EndpointEvent::ConnectSettled {
                    connect_id,
                    outcome: ConnectOutcome::Failed(ConnectFailure::NoUsableRoute { .. }),
                    ..
                } if *connect_id == id
            )
        }),
        "expected NoUsableRoute, got {events:?}"
    );
}

#[test]
fn relay_preserves_an_explicit_reservation_policy() {
    let bus = VirtualBus::new(2);
    let local = identity(133);
    let relay = identity(134);
    let relay_addr = PeerAddr::new(
        format!("/ip4/{RELAY_IP}/tcp/4001").parse().unwrap(),
        relay.peer_id(),
    )
    .unwrap();
    let config = NatConfig {
        force_relay: true,
        reservation_policy: ReservationPolicy::Always,
        ..NatConfig::default()
    };
    let mut endpoint =
        PortableEndpointBuilder::new(&local, CountingEntropy(52), ManualClock::default())
            .smoltcp(stack(bus.device(0), A_IP))
            .nat_config(config)
            .relay(relay_addr)
            .build()
            .expect("adding a relay completes the reservation policy");

    let now = Now::from_millis(0);
    endpoint
        .at(now)
        .poll()
        .expect("reservation schedules a dial");
    endpoint
        .at(now)
        .poll()
        .expect("reservation dial drives TCP");
    assert!(
        !bus.is_quiet(),
        "ReservationPolicy::Always must survive the .relay() merge"
    );
}

#[test]
fn relay_attempt_uses_host_deadline_and_cancellation_settles_once() {
    for cancel in [false, true] {
        let bus = VirtualBus::new(1);
        let local = identity(135);
        let relay = PeerAddr::new(
            format!("/ip4/{RELAY_IP}/tcp/4001").parse().unwrap(),
            identity(136).peer_id(),
        )
        .unwrap();
        let peer = identity(137).peer_id();
        let mut endpoint =
            PortableEndpointBuilder::new(&local, CountingEntropy(53), ManualClock::default())
                .connect_deadline(core::time::Duration::from_millis(50))
                .smoltcp(stack(bus.device(0), A_IP))
                .nat_config(relay_config(relay, ReservationPolicy::Never))
                .build()
                .unwrap();

        let start = Now::from_millis(50_000);
        let id = endpoint.at(start).connect(peer).unwrap();
        let mut events = endpoint.at(start).poll().unwrap();
        assert!(!events.iter().any(|event| matches!(event,
            EndpointEvent::ConnectSettled { connect_id, .. } if *connect_id == id)));
        let due = endpoint
            .at(start)
            .next_deadline()
            .expect("pending attempt has a deadline");
        assert!(due.as_millis() > start.monotonic_ms);
        assert!(due.as_millis() <= 50_050);

        if cancel {
            endpoint.at(Now::from_millis(50_025)).cancel_connect(id);
            endpoint.at(Now::from_millis(50_025)).cancel_connect(id);
        }
        events.extend(endpoint.at(Now::from_millis(50_049)).poll().unwrap());
        if !cancel {
            assert!(!events.iter().any(|event| matches!(event,
                EndpointEvent::ConnectSettled { connect_id, .. } if *connect_id == id)));
        }
        events.extend(endpoint.at(Now::from_millis(50_050)).poll().unwrap());
        endpoint.at(Now::from_millis(50_050)).cancel_connect(id);
        events.extend(endpoint.at(Now::from_millis(100_000)).poll().unwrap());
        let outcomes: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                EndpointEvent::ConnectSettled {
                    connect_id,
                    outcome,
                    ..
                } if *connect_id == id => Some(outcome),
                _ => None,
            })
            .collect();
        assert_eq!(outcomes.len(), 1, "{events:?}");
        if cancel {
            assert_eq!(outcomes[0], &ConnectOutcome::Cancelled);
        } else {
            assert!(matches!(
                outcomes[0],
                ConnectOutcome::Failed(ConnectFailure::Timeout { elapsed_ms: 50, .. })
            ));
        }
        assert_eq!(endpoint.path(&peer), None);
    }
}
