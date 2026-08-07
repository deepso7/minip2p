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
use minip2p::{
    DiscoveryEvent, Ed25519Keypair, Endpoint, EntropySource, Multiaddr, Now, PeerAddr, PeerId,
    PollDeadline, PortableMdnsEvent, SmoltcpConfig, SmoltcpMdnsConfig, SmoltcpStack,
    SmoltcpTcpProvider, StreamId, SwarmEvent, TcpConfig, TcpTransport,
};
use minip2p_platform::EntropyError;

const DIALER_IP: &str = "192.168.1.1";
const LISTENER_IP: &str = "192.168.1.2";
const PROTOCOL: &str = "/minip2p/embedded-e2e/1.0.0";
const PAYLOAD: &[u8] = b"portable endpoint over smoltcp";
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
    let mut a = Endpoint::portable(&a_identity, CountingEntropy(40))
        .smoltcp(a_stack)
        .listen(format!("/ip4/{DIALER_IP}/tcp/4001"))
        .mdns()
        .mdns_carrier_config(carrier.clone())
        .protocol(PROTOCOL)
        .build()
        .expect("a embedded endpoint builds");
    let mut b = Endpoint::portable(&b_identity, CountingEntropy(50))
        .smoltcp(b_stack)
        .listen(format!("/ip4/{LISTENER_IP}/tcp/4001"))
        .mdns()
        .mdns_carrier_config(carrier)
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
            matches!(event, PortableMdnsEvent::Discovery(DiscoveryEvent::PeerDiscovered { peer, addrs, .. })
                if peer == &b_peer && !addrs.is_empty())
        });
        let b_discovered = b_events.iter().any(|event| {
            matches!(event, PortableMdnsEvent::Discovery(DiscoveryEvent::PeerDiscovered { peer, addrs, .. })
                if peer == &a_peer && !addrs.is_empty())
        });
        let a_ready = a_events.iter().any(|event| {
            matches!(event, PortableMdnsEvent::Endpoint(SwarmEvent::PeerReady { peer_id, .. })
                if peer_id == &b_peer)
        });
        let b_ready = b_events.iter().any(|event| {
            matches!(event, PortableMdnsEvent::Endpoint(SwarmEvent::PeerReady { peer_id, .. })
                if peer_id == &a_peer)
        });
        if a_ready && b_ready && !ping_started {
            a.ping(&b_peer, now).expect("mDNS-discovered peer pings");
            ping_started = true;
        }
        let ping_finished = a_events.iter().any(|event| {
            matches!(event, PortableMdnsEvent::Endpoint(SwarmEvent::PingRttMeasured { peer_id, .. })
                if peer_id == &b_peer)
        });
        if a_discovered && b_discovered && a_ready && b_ready && ping_finished {
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
