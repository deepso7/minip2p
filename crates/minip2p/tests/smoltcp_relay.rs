//! Three-node portable relay gate over a virtual smoltcp IP network.

#![cfg(feature = "portable-relay")]

extern crate alloc;

use alloc::{collections::VecDeque, rc::Rc, vec, vec::Vec};
use core::cell::RefCell;

use minip2p::smoltcp::iface::{Config, Interface};
use minip2p::smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use minip2p::smoltcp::time::Instant;
use minip2p::smoltcp::wire::{HardwareAddress, IpCidr};
use minip2p::{
    Ed25519Keypair, Endpoint, EntropySource, Multiaddr, NatConfig, NatEvent, Now, Path, PeerAddr,
    PeerId, ReservationPolicy, SmoltcpEvent, SmoltcpStack, StreamId, SwarmEvent,
};
use minip2p_nat::{HOP_PROTOCOL_ID, STOP_PROTOCOL_ID};
use minip2p_platform::EntropyError;
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
    b_reservation: Option<StreamId>,
    a_bridge: Option<StreamId>,
    b_stop: Option<StreamId>,
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
        endpoint: &mut minip2p::SmoltcpEndpoint<BusDevice, CountingEntropy>,
        event: SmoltcpEvent,
        now: Now,
    ) {
        let SmoltcpEvent::Endpoint(event) = event else {
            return;
        };
        match event {
            SwarmEvent::StreamReady {
                peer_id,
                stream_id,
                protocol_id,
                initiated_locally,
                ..
            } if protocol_id == HOP_PROTOCOL_ID && !initiated_locally => {
                if peer_id == self.b {
                    self.b_reservation = Some(stream_id);
                } else if peer_id == self.a {
                    self.a_bridge = Some(stream_id);
                }
            }
            SwarmEvent::StreamReady {
                peer_id,
                stream_id,
                protocol_id,
                initiated_locally: true,
                ..
            } if peer_id == self.b && protocol_id == STOP_PROTOCOL_ID => {
                self.b_stop = Some(stream_id);
                let request = self.emulator.drain_stop_bytes_for(&self.b);
                endpoint
                    .send_stream(&self.b, stream_id, request, now)
                    .unwrap();
            }
            SwarmEvent::StreamData {
                peer_id,
                stream_id,
                data,
                ..
            } if peer_id == self.b && Some(stream_id) == self.b_reservation => {
                self.emulator.on_reserve_request(&self.b, &data).unwrap();
                let response = self.emulator.drain_hop_bytes_for(&self.b);
                endpoint
                    .send_stream(&self.b, stream_id, response, now)
                    .unwrap();
            }
            SwarmEvent::StreamData {
                peer_id,
                stream_id,
                data,
                ..
            } if peer_id == self.a && Some(stream_id) == self.a_bridge && !self.bridged => {
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
                    .open_stream(&self.b, STOP_PROTOCOL_ID, now)
                    .unwrap();
                self.b_stop = Some(stop);
            }
            SwarmEvent::StreamData {
                peer_id,
                stream_id,
                data,
                ..
            } if peer_id == self.b && Some(stream_id) == self.b_stop && !self.bridged => {
                let mut response = Vec::new();
                let trailing = self
                    .emulator
                    .on_stop_ack_from_target(self.pending.unwrap(), &self.b, &data, &mut response)
                    .unwrap();
                self.bridged = true;
                endpoint
                    .send_stream(&self.a, self.a_bridge.unwrap(), response, now)
                    .unwrap();
                if !trailing.is_empty() {
                    endpoint
                        .send_stream(&self.a, self.a_bridge.unwrap(), trailing, now)
                        .unwrap();
                }
            }
            SwarmEvent::StreamData {
                peer_id,
                stream_id,
                data,
                ..
            } if self.bridged && peer_id == self.a && Some(stream_id) == self.a_bridge => {
                endpoint
                    .send_stream(&self.b, self.b_stop.unwrap(), data, now)
                    .unwrap();
            }
            SwarmEvent::StreamData {
                peer_id,
                stream_id,
                data,
                ..
            } if self.bridged && peer_id == self.b && Some(stream_id) == self.b_stop => {
                endpoint
                    .send_stream(&self.a, self.a_bridge.unwrap(), data, now)
                    .unwrap();
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
    let relay_addr = PeerAddr::new(relay_transport, relay_peer.clone()).unwrap();

    let mut a = Endpoint::portable(&a_identity, CountingEntropy(10))
        .smoltcp(stack(bus.device(0), A_IP))
        .relay_config(relay_config(relay_addr.clone(), ReservationPolicy::Never))
        .protocol(APP_PROTOCOL)
        .build()
        .unwrap();
    let mut b = Endpoint::portable(&b_identity, CountingEntropy(20))
        .smoltcp(stack(bus.device(1), B_IP))
        .relay_config(relay_config(relay_addr, ReservationPolicy::Always))
        .protocol(APP_PROTOCOL)
        .build()
        .unwrap();
    let mut relay = Endpoint::portable(&relay_identity, CountingEntropy(30))
        .smoltcp(stack(bus.device(2), RELAY_IP))
        .listen(format!("/ip4/{RELAY_IP}/tcp/4001"))
        .protocol(HOP_PROTOCOL_ID)
        .protocol(STOP_PROTOCOL_ID)
        .build()
        .unwrap();
    let mut service = RelayService::new(a_peer.clone(), b_peer.clone());

    let mut now_ms = 0;
    let mut connect_started = false;
    let mut a_events = Vec::new();
    let mut b_events = Vec::new();
    let mut app_stream = None;
    let mut sent = false;
    for _ in 0..MAX_STEPS {
        let now = Now::from_millis(now_ms);
        a_events.extend(a.poll(now).unwrap());
        b_events.extend(b.poll(now).unwrap());
        for event in relay.poll(now).unwrap() {
            service.handle(&mut relay, event, now);
        }

        let reserved = b_events.iter().any(|event| {
            matches!(event, SmoltcpEvent::Nat(NatEvent::RelayReserved { relay, .. })
                if relay == &relay_peer)
        });
        if reserved && !connect_started {
            a.connect_relay(&b_peer, now).unwrap();
            connect_started = true;
        }
        let a_relayed = a_events.iter().any(|event| {
            matches!(event, SmoltcpEvent::Nat(NatEvent::PathEstablished {
                peer, path: Path::Relayed { relay }, ..
            }) if peer == &b_peer && relay == &relay_peer)
        });
        let b_relayed = b_events.iter().any(|event| {
            matches!(event, SmoltcpEvent::Nat(NatEvent::InboundPathEstablished {
                peer, path: Path::Relayed { relay }
            }) if peer == &a_peer && relay == &relay_peer)
        });
        if a_relayed && b_relayed && app_stream.is_none() {
            app_stream = Some(a.open_stream(&b_peer, APP_PROTOCOL, now).unwrap());
        }
        if let Some(stream) = app_stream
            && !sent
            && a_events.iter().any(|event| {
                matches!(event, SmoltcpEvent::Endpoint(SwarmEvent::StreamReady {
                    peer_id, stream_id, initiated_locally: true, ..
                }) if peer_id == &b_peer && *stream_id == stream)
            })
        {
            a.send_stream(&b_peer, stream, PAYLOAD.to_vec(), now)
                .unwrap();
            sent = true;
        }
        if app_stream.is_some_and(|stream| {
            b_events.iter().any(|event| {
                matches!(event, SmoltcpEvent::Endpoint(SwarmEvent::StreamData {
                    peer_id, stream_id, data, ..
                }) if peer_id == &a_peer && *stream_id == stream && data == PAYLOAD)
            })
        }) {
            assert!(
                matches!(a.path(&b_peer), Some(Path::Relayed { relay }) if relay == relay_peer)
            );
            assert!(
                matches!(b.path(&a_peer), Some(Path::Relayed { relay }) if relay == relay_peer)
            );
            return;
        }

        if bus.is_quiet() {
            let deadline = [
                a.next_deadline(now),
                b.next_deadline(now),
                relay.next_deadline(now),
            ]
            .into_iter()
            .flatten()
            .min()
            .expect("relay world retains a deadline");
            now_ms = now_ms.max(deadline.as_millis());
        }
    }
    panic!("relay circuit did not carry application data\n  a: {a_events:?}\n  b: {b_events:?}");
}

#[test]
fn portable_relay_rejects_udp_traversal_policy() {
    let bus = VirtualBus::new(1);
    let local = identity(124);
    let relay = identity(125);
    let relay_addr = PeerAddr::new(
        format!("/ip4/{RELAY_IP}/tcp/4001").parse().unwrap(),
        relay.peer_id(),
    )
    .unwrap();
    let mut config = relay_config(relay_addr, ReservationPolicy::Never);
    config.force_relay = false;

    let error = Endpoint::portable(&local, CountingEntropy(40))
        .smoltcp(stack(bus.device(0), A_IP))
        .relay_config(config)
        .build()
        .err()
        .expect("DCUtR policy is rejected");
    assert!(error.to_string().contains("DCUtR is QUIC-only"));
}
