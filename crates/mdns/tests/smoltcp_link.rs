//! Drives two `MdnsDriver`s over real multicast, on a stack with no operating
//! system underneath it.
//!
//! The driver's own tests pin it against an `MdnsIo` written to satisfy it.
//! These pin it against one that was not: smoltcp does its own group
//! memberships, addressing, and framing, and the only thing between it and the
//! driver is `SmoltcpMdnsIo`. Whatever the seam actually promises rather than
//! merely describes has to hold here.
//!
//! The link is a shared bus of frames, so datagrams are real, multicast
//! delivery is real, and time is whatever the harness says it is.

#![cfg(feature = "smoltcp")]

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;

use minip2p_core::{Multiaddr, PeerId};
use minip2p_identity::{KeyType, PublicKey};
use minip2p_mdns::smoltcp::iface::{Config, Interface};
use minip2p_mdns::smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use minip2p_mdns::smoltcp::time::Instant;
use minip2p_mdns::smoltcp::wire::{HardwareAddress, IpCidr, Ipv4Address};
use minip2p_mdns::{
    InterfaceId, MdnsAction, MdnsAgent, MdnsConfig, MdnsDriver, MdnsError, MdnsEvent, MdnsIo,
    MdnsTarget, SmoltcpMdnsConfig, SmoltcpMdnsIo, SmoltcpStack,
};

/// Enough ticks for several announcement rounds; short enough that a livelock
/// fails rather than hangs.
const MAX_STEPS: usize = 4_000;

/// How far the harness clock moves per step.
const STEP_MS: u64 = 5;

// ---------------------------------------------------------------- the link

type Frames = Rc<RefCell<VecDeque<Vec<u8>>>>;

/// Whether a node's link is currently refusing frames, shared so a test can
/// stall one that has already been handed to a driver.
type Link = Rc<Cell<bool>>;

/// A shared bus: whatever one node sends, every other node receives.
///
/// Point-to-point queues would not do -- mDNS is multicast, and the thing
/// worth testing is that a datagram addressed to a group reaches a host that
/// joined it and nothing else.
#[derive(Clone, Default)]
struct Bus {
    inboxes: Rc<RefCell<Vec<Frames>>>,
}

impl Bus {
    /// Attaches a node, returning the device it drives.
    fn attach(&self) -> BusDevice {
        let inbox: Frames = Frames::default();
        self.inboxes.borrow_mut().push(Rc::clone(&inbox));
        BusDevice {
            bus: self.clone(),
            inbox,
            blocked: Link::default(),
        }
    }

    fn broadcast(&self, from: &Frames, frame: Vec<u8>) {
        for inbox in self.inboxes.borrow().iter() {
            // Not back to the sender: a real link does not hand a host its own
            // frame back, and an mDNS agent that heard itself would answer
            // its own queries.
            if Rc::ptr_eq(inbox, from) {
                continue;
            }
            inbox.borrow_mut().push_back(frame.clone());
        }
    }

    /// Throws away whatever is in flight, so a test can start from silence.
    fn drain(&self) {
        for inbox in self.inboxes.borrow().iter() {
            inbox.borrow_mut().clear();
        }
    }

    fn is_quiet(&self) -> bool {
        self.inboxes
            .borrow()
            .iter()
            .all(|inbox| inbox.borrow().is_empty())
    }
}

struct BusDevice {
    bus: Bus,
    inbox: Frames,
    /// A link that will not take a frame right now -- a radio mid-transmit, a
    /// driver with no descriptor free. Nothing about mDNS is broken while this
    /// is set; the frames simply have to wait.
    blocked: Link,
}

struct RxFrame(Vec<u8>);

impl RxToken for RxFrame {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct TxSink {
    bus: Bus,
    inbox: Frames,
}

impl TxToken for TxSink {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0u8; len];
        let result = f(&mut frame);
        self.bus.broadcast(&self.inbox, frame);
        result
    }
}

impl Device for BusDevice {
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
        Some((RxFrame(frame), self.sink()))
    }

    fn transmit(&mut self, _now: Instant) -> Option<TxSink> {
        if self.blocked.get() {
            return None;
        }
        Some(self.sink())
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1500;
        capabilities
    }
}

impl BusDevice {
    fn sink(&self) -> TxSink {
        TxSink {
            bus: self.bus.clone(),
            inbox: Rc::clone(&self.inbox),
        }
    }

    /// A handle on whether this link is taking frames, still usable once the
    /// device has been handed over.
    fn link(&self) -> Link {
        Rc::clone(&self.blocked)
    }

    /// Stops or resumes taking frames.
    fn block(&self, blocked: bool) {
        self.blocked.set(blocked);
    }
}

// ------------------------------------------------------------- the nodes

type Driver = MdnsDriver<SmoltcpMdnsIo<BusDevice>>;

fn peer(seed: u8) -> PeerId {
    PeerId::from_public_key(&PublicKey::new(KeyType::Ed25519, vec![seed; 32]))
}

fn addr(text: &str) -> Multiaddr {
    text.parse().expect("test address parses")
}

/// A bare carrier on the bus, holding exactly the addresses given.
fn carrier(bus: &Bus, addresses: &[Ipv4Address]) -> SmoltcpMdnsIo<BusDevice> {
    carrier_with(
        bus,
        addresses,
        SmoltcpMdnsConfig {
            enable_ipv6: false,
            ..SmoltcpMdnsConfig::default()
        },
    )
}

/// The same, for a test that has something to say about how it is sized.
fn carrier_with(
    bus: &Bus,
    addresses: &[Ipv4Address],
    config: SmoltcpMdnsConfig,
) -> SmoltcpMdnsIo<BusDevice> {
    let mut device = bus.attach();
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    iface.update_ip_addrs(|addrs| {
        for address in addresses {
            let _ = addrs.push(IpCidr::new((*address).into(), 24));
        }
    });
    SmoltcpMdnsIo::new(device, iface, config).expect("the interface takes the mDNS group")
}

/// The one interface a `SmoltcpMdnsIo` reports for IPv4.
const IPV4: InterfaceId = InterfaceId::new(1);

/// Something to put on the wire, small enough that only the slot count can
/// run out.
fn datagram() -> MdnsAction {
    MdnsAction::Send {
        interface: IPV4,
        target: MdnsTarget::Multicast,
        payload: vec![0x00; 12],
    }
}

/// One node on the bus: its driver, what it listens on, and what it has seen.
struct Node {
    driver: Driver,
    addrs: Vec<Multiaddr>,
    events: Vec<MdnsEvent>,
    /// Whether this node's link is taking frames.
    link: Link,
}

impl Node {
    /// A node holding exactly `address`, announcing a QUIC listener on it.
    fn new(bus: &Bus, address: Ipv4Address, seed: u8) -> Self {
        let mut device = bus.attach();
        let link = device.link();
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            Instant::from_millis(0),
        );
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(address.into(), 24));
        });
        let io = SmoltcpMdnsIo::new(
            device,
            iface,
            SmoltcpMdnsConfig {
                // IPv4 only: the bus carries whatever smoltcp puts on it, and
                // one family is enough to pin the seam.
                enable_ipv6: false,
                ..SmoltcpMdnsConfig::default()
            },
        )
        .expect("the interface takes the mDNS group");
        let agent = MdnsAgent::new(peer(seed), MdnsConfig::default(), [seed; 32])
            .expect("a valid configuration");
        Self {
            driver: MdnsDriver::new(agent, io, &MdnsConfig::default()),
            addrs: vec![addr(&format!("/ip4/{address}/udp/4001/quic-v1"))],
            events: Vec::new(),
            link,
        }
    }

    fn tick(&mut self, now_ms: u64) {
        self.driver.tick(now_ms, &self.addrs).expect("tick");
        while let Some(event) = self.driver.poll_event() {
            self.events.push(event);
        }
    }

    /// What this node learned about `wanted`, if anything.
    fn observed(&self, wanted: &PeerId) -> Option<Vec<(Multiaddr, u64)>> {
        self.events.iter().find_map(|event| match event {
            MdnsEvent::PeerObserved { peer, addrs } if peer == wanted => Some(addrs.clone()),
            _ => None,
        })
    }
}

/// Ticks both nodes until `done`, or panics with what was seen.
fn run_until(first: &mut Node, second: &mut Node, mut done: impl FnMut(&Node, &Node) -> bool) {
    for step in 0..MAX_STEPS {
        let now = step as u64 * STEP_MS;
        first.tick(now);
        second.tick(now);
        if done(first, second) {
            return;
        }
    }
    panic!(
        "nothing happened in {MAX_STEPS} steps:\n  {:?}\n  {:?}",
        first.events, second.events
    );
}

// ----------------------------------------------------------------- tests

#[test]
fn two_nodes_find_each_other_over_multicast() {
    let bus = Bus::default();
    let mut first = Node::new(&bus, Ipv4Address::new(192, 168, 1, 1), 1);
    let mut second = Node::new(&bus, Ipv4Address::new(192, 168, 1, 2), 2);

    run_until(&mut first, &mut second, |a, b| {
        a.observed(&peer(2)).is_some() && b.observed(&peer(1)).is_some()
    });

    // What each learned is what the other actually listens on -- the whole
    // point of the exchange, and the part no fake could have got right by
    // accident.
    for (learner, subject, id) in [(&first, &second, peer(2)), (&second, &first, peer(1))] {
        let learned = learner.observed(&id).expect("the other node was observed");
        assert!(
            learned
                .iter()
                .any(|(addr, ttl)| *addr == subject.addrs[0] && *ttl > 0),
            "expected {:?}, got {learned:?}",
            subject.addrs[0]
        );
    }
}

#[test]
fn a_node_that_leaves_says_so_on_the_wire() {
    let bus = Bus::default();
    let mut first = Node::new(&bus, Ipv4Address::new(192, 168, 1, 1), 1);
    let mut second = Node::new(&bus, Ipv4Address::new(192, 168, 1, 2), 2);
    run_until(&mut first, &mut second, |a, _| {
        a.observed(&peer(2)).is_some()
    });

    // A goodbye is a claim with a zero TTL, and it has to reach the peer: an
    // unsent one costs it a full TTL of pointing at a host that has gone.
    // The carrier is dropped as the shutdown ends, so anything still queued
    // in it then is lost.
    second.driver.shutdown(1_000).expect("goodbye");
    first.events.clear();
    for step in 0..200u64 {
        first.tick(1_000 + step * STEP_MS);
        let said_goodbye = first.events.iter().any(|event| {
            matches!(event, MdnsEvent::PeerObserved { peer: p, addrs }
                if *p == peer(2) && addrs.iter().all(|(_, ttl)| *ttl == 0))
        });
        if said_goodbye {
            return;
        }
    }
    panic!("no goodbye arrived: {:?}", first.events);
}

#[test]
fn an_idle_link_lets_the_host_sleep() {
    let bus = Bus::default();
    let mut first = Node::new(&bus, Ipv4Address::new(192, 168, 1, 1), 1);
    let mut second = Node::new(&bus, Ipv4Address::new(192, 168, 1, 2), 2);

    // Drive until nothing is left on the wire, then ask what is owed. A
    // device that runs on a battery sleeps between packets, and this is the
    // number that lets it.
    let mut idle_at = None;
    for step in 0..200u64 {
        let now = step * STEP_MS;
        first.tick(now);
        second.tick(now);
        if bus.is_quiet() {
            idle_at = Some(now);
            break;
        }
    }
    let now = idle_at.expect("the link never went quiet");

    // The answer is the soonest of everything the driver combines: its own
    // poll interval, its next interface re-enumeration, the agent's next
    // scheduled word, and whatever the carrier owes -- nothing, on an idle
    // link, but taken from the carrier rather than assumed, so a carrier that
    // claimed a deadline it did not have is caught shortening this instead of
    // breaking the comparison. Asserting the number rather than "more than
    // zero" is what makes this a bound; a driver that ignored the carrier's
    // deadlines would not be caught here at all, which is what the next test
    // is for.
    let config = MdnsConfig::default();
    let mut expected = config
        .socket_poll_interval_ms
        .min(config.interface_refresh_ms - now);
    if let Some(agent) = first.driver.agent().next_timeout(now) {
        expected = expected.min(agent);
    }
    if let Some(carrier) = first
        .driver
        .io()
        .and_then(|carrier| carrier.next_deadline(now))
    {
        expected = expected.min(carrier);
    }
    assert!(expected > 0, "an idle host has something to sleep on");
    assert_eq!(first.driver.next_timeout(now), Some(expected));
}

#[test]
fn a_carrier_that_still_owes_work_keeps_the_host_awake() {
    let bus = Bus::default();
    let mut only = Node::new(&bus, Ipv4Address::new(192, 168, 1, 1), 1);

    // A link that will not take a frame. The announcement is queued inside
    // smoltcp and goes nowhere, which is precisely when a host must not be
    // told it may sleep: nothing in this stack moves while it does.
    only.link.set(true);
    only.tick(0);
    assert_eq!(
        only.driver.next_timeout(0),
        Some(0),
        "a datagram stuck in the carrier is owed a poll now"
    );

    // And once it drains, the host is back to sleeping on mDNS's own schedule
    // -- so the zero above came from the carrier and not from something the
    // driver always says.
    only.link.set(false);
    only.tick(1);
    assert!(
        only.driver.next_timeout(1).unwrap_or(0) > 0,
        "with nothing left in the carrier there is something to sleep on"
    );
}

#[test]
fn a_datagram_queued_but_not_yet_on_the_wire_is_owed_now() {
    let bus = Bus::default();
    // A second node, so there is an inbox for a frame to arrive in.
    let _listener = carrier(&bus, &[Ipv4Address::new(192, 168, 1, 2)]);
    let mut io = carrier(&bus, &[Ipv4Address::new(192, 168, 1, 1)]);
    // Joining a group is itself something to say on the wire; this test is
    // about what happens after that.
    io.poll(0).expect("poll");
    bus.drain();

    io.send(&datagram()).expect("queue a datagram");

    // Queued is not sent: nothing leaves a stack like this until it is
    // driven, so a host told it could sleep would sleep on an unsent packet.
    assert_eq!(
        io.next_deadline(0),
        Some(0),
        "a queued datagram is owed a poll now, whatever smoltcp's own timers say"
    );
    assert!(bus.is_quiet(), "and it has not gone anywhere yet");

    io.poll(0).expect("poll");
    assert!(!bus.is_quiet(), "the poll is what puts it on the wire");
}

#[test]
fn an_ingress_flood_is_bounded_and_keeps_the_carrier_due() {
    let bus = Bus::default();
    let mut receiver = carrier(&bus, &[Ipv4Address::new(192, 168, 1, 2)]);
    let mut sender = carrier(&bus, &[Ipv4Address::new(192, 168, 1, 1)]);
    receiver.poll(0).expect("receiver joins");
    sender.poll(0).expect("sender joins");
    bus.drain();

    sender.send(&datagram()).expect("queue one valid frame");
    sender.poll(1).expect("put the frame on the bus");
    let receiver_inbox = Rc::clone(&bus.inboxes.borrow()[0]);
    let frame = receiver_inbox
        .borrow()
        .front()
        .cloned()
        .expect("receiver got the frame");
    for _ in 0..40 {
        receiver_inbox.borrow_mut().push_back(frame.clone());
    }

    receiver.poll(1).expect("bounded poll");
    assert!(
        !receiver_inbox.borrow().is_empty(),
        "one mDNS poll must not drain an unbounded link"
    );
    assert_eq!(
        receiver.next_deadline(1),
        Some(0),
        "work left by the ingress budget must be resumed immediately"
    );
}

#[test]
fn failed_shared_stack_setup_rolls_back_memberships_and_sockets() {
    let bus = Bus::default();
    let mut device = bus.attach();
    let iface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    let stack = SmoltcpStack::new(device, iface);
    let retained = [
        Ipv4Address::new(239, 0, 0, 1),
        Ipv4Address::new(239, 0, 0, 2),
        Ipv4Address::new(239, 0, 0, 3),
    ];
    {
        let mut shared = stack.borrow_mut();
        for group in retained {
            shared
                .interface
                .join_multicast_group(group)
                .expect("room before mDNS setup");
        }
    }

    let error = match SmoltcpMdnsIo::on_stack(stack.clone(), SmoltcpMdnsConfig::default()) {
        Ok(_) => panic!("IPv6 mDNS membership should exceed the final group slot"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("GroupTableFull"));

    let shared = stack.borrow();
    assert_eq!(
        shared.sockets.iter().count(),
        0,
        "the IPv4 socket rolled back"
    );
    assert!(
        !shared
            .interface
            .has_multicast_group(Ipv4Address::new(224, 0, 0, 251)),
        "the IPv4 mDNS membership rolled back"
    );
    for group in retained {
        assert!(
            shared.interface.has_multicast_group(group),
            "pre-existing memberships must survive rollback"
        );
    }
}

#[test]
fn a_send_ring_with_no_room_is_a_backlog_and_not_the_end_of_mdns() {
    let bus = Bus::default();
    let _listener = carrier(&bus, &[Ipv4Address::new(192, 168, 1, 2)]);
    let mut io = carrier(&bus, &[Ipv4Address::new(192, 168, 1, 1)]);
    io.poll(0).expect("poll");

    // A stack like this drains only when it is driven, so a burst queued
    // inside one tick fills the ring long before anything empties it. The
    // driver sends up to 128 datagrams a turn into four slots.
    io.stack().borrow_mut().device.block(true);
    let slots = SmoltcpMdnsConfig::default().packet_slots;
    for slot in 0..slots {
        io.send(&datagram())
            .unwrap_or_else(|error| panic!("slot {slot} of {slots} should be free: {error}"));
    }

    let error = io.send(&datagram()).expect_err("the ring is full");
    assert_eq!(
        error,
        MdnsError::Congested { interface: IPV4 },
        "a full ring is 'not yet', not 'never': anything else here ends mDNS \
         because a device spoke faster than its link could carry"
    );

    // And the datagram that would not fit fits once the link takes frames
    // again -- without the caller having polled, because a send that finds no
    // room drains the ring itself before giving up.
    io.stack().borrow_mut().device.block(false);
    io.send(&datagram())
        .expect("the drain inside the send made room");
    assert!(!bus.is_quiet(), "and the burst went out");
}

#[test]
fn a_datagram_bigger_than_the_send_buffer_is_never_going_to_fit() {
    let bus = Bus::default();
    let _listener = carrier(&bus, &[Ipv4Address::new(192, 168, 1, 2)]);
    // A device that shrank its buffers below what its own claims need. The
    // documented cost of that is a dropped claim, and the only thing that
    // makes it one is saying so differently from a ring that is merely full:
    // the driver comes back for congestion, so this would be retried forever.
    let mut io = carrier_with(
        &bus,
        &[Ipv4Address::new(192, 168, 1, 1)],
        SmoltcpMdnsConfig {
            tx_payload_bytes: 8,
            enable_ipv6: false,
            ..SmoltcpMdnsConfig::default()
        },
    );
    io.poll(0).expect("poll");

    let oversized = MdnsError::Oversized {
        interface: IPV4,
        len: 12,
        capacity: 8,
    };
    assert_eq!(
        io.send(&datagram()).expect_err("it will never fit"),
        oversized,
        "a buffer that could never hold it is not a buffer that is momentarily full"
    );

    // And a drain says nothing new about it, which is the whole difference: an
    // empty ring is exactly what a parked datagram would be waiting for.
    io.poll(1).expect("poll");
    assert_eq!(
        io.send(&datagram())
            .expect_err("an empty ring is no bigger"),
        oversized
    );
}

#[test]
fn a_socket_with_no_packet_slots_is_permanently_unable_to_send() {
    let bus = Bus::default();
    let mut io = carrier_with(
        &bus,
        &[Ipv4Address::new(192, 168, 1, 1)],
        SmoltcpMdnsConfig {
            packet_slots: 0,
            enable_ipv6: false,
            ..SmoltcpMdnsConfig::default()
        },
    );
    io.poll(0).expect("poll");

    assert!(
        matches!(io.send(&datagram()), Err(MdnsError::Oversized { .. })),
        "a zero-slot ring can never drain into room and must not be reported as temporary congestion"
    );
}

#[test]
fn a_send_buffer_below_this_hosts_own_claim_does_not_spin_the_driver() {
    // One node: what it cannot send, nobody has to receive.
    let bus = Bus::default();
    let io = carrier_with(
        &bus,
        &[Ipv4Address::new(192, 168, 1, 1)],
        SmoltcpMdnsConfig {
            // Smaller than any claim this host can encode, which is the
            // shrunk-to-fit device the configuration invites.
            tx_payload_bytes: 32,
            enable_ipv6: false,
            ..SmoltcpMdnsConfig::default()
        },
    );
    let agent =
        MdnsAgent::new(peer(1), MdnsConfig::default(), [1; 32]).expect("a valid configuration");
    let mut driver = MdnsDriver::new(agent, io, &MdnsConfig::default());
    let addrs = vec![addr("/ip4/192.168.1.1/udp/4001/quic-v1")];

    // The promise is a dropped claim, not a broken host: the driver keeps
    // running and, once the link is quiet, has something to sleep on. A
    // datagram parked as congestion instead would be handed back to the same
    // buffer every turn and keep this at zero for good.
    for step in 0..200u64 {
        let now = step * STEP_MS;
        driver
            .tick(now, &addrs)
            .expect("a claim that will never fit is not a fault");
        if bus.is_quiet() && driver.next_timeout(now).unwrap_or(0) > 0 {
            return;
        }
    }
    panic!("the driver never settled: an unsendable claim kept it awake");
}

#[test]
fn an_address_that_arrives_later_reaches_the_agent() {
    let bus = Bus::default();
    // An interface with nothing on it yet, which is where a host that waits
    // for DHCP or SLAAC starts.
    let mut io = carrier(&bus, &[]);

    // Not an interface mDNS can speak on: no source to claim, and nothing
    // on-link to accept.
    assert!(io.interfaces().is_empty());
    assert_eq!(
        io.send(&datagram())
            .expect_err("there is nowhere to send from"),
        MdnsError::UnknownInterface { interface: IPV4 },
        "a family with no address is gone as far as the driver is concerned, \
         and saying so is what makes it drop the packet instead of stopping"
    );

    // The lease lands. Nothing tells mDNS about it but the next refresh.
    io.stack().borrow_mut().interface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(Ipv4Address::new(192, 168, 1, 5).into(), 24));
    });
    assert!(
        io.refresh().expect("refresh"),
        "an address that arrived is a change the agent has to hear about"
    );
    assert_eq!(io.interfaces().len(), 1);
    let snapshot = &io.interfaces()[0];
    assert_eq!(snapshot.id, IPV4, "and it is the same interface it was");
    assert_eq!(snapshot.addrs.len(), 1);
    assert_eq!(
        snapshot.addrs[0].ip(),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))
    );
    assert_eq!(snapshot.addrs[0].prefix_len(), 24);
    io.send(&datagram())
        .expect("now there is somewhere to send from");
    assert!(
        !io.refresh().expect("refresh"),
        "and an interface that did not move is not a change"
    );

    // A lease that expires is the same story backwards.
    io.stack()
        .borrow_mut()
        .interface
        .update_ip_addrs(|addrs| addrs.clear());
    assert!(io.refresh().expect("refresh"));
    assert!(io.interfaces().is_empty());
    assert_eq!(
        io.send(&datagram()).expect_err("the address went away"),
        MdnsError::UnknownInterface { interface: IPV4 }
    );
}
