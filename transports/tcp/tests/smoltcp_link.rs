//! Drives two `TcpTransport`s over real TCP, on a stack with no operating
//! system underneath it.
//!
//! The virtual-link tests pin the transport against a provider written to
//! satisfy it. These pin it against one that was not: smoltcp does its own
//! handshaking, retransmission, and timing, and the only thing between it and
//! the transport is `SmoltcpTcpProvider`. Whatever the seam actually promises
//! rather than merely describes has to hold here.
//!
//! The link between the two nodes is a pair of frame queues, so segments are
//! real, ordering is real, and time is whatever the harness says it is.

#![cfg(feature = "smoltcp")]

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

use minip2p_core::{Multiaddr, PeerAddr};
use minip2p_identity::{Ed25519Keypair, PeerId};
use minip2p_platform::{Deadline, EntropyError, EntropySource, Now};
use minip2p_tcp::smoltcp::iface::{Config, Interface};
use minip2p_tcp::smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use minip2p_tcp::smoltcp::time::Instant;
use minip2p_tcp::smoltcp::wire::{HardwareAddress, IpCidr};
use minip2p_tcp::{
    SmoltcpConfig, SmoltcpTcpProvider, SocketHandle, TcpConfig, TcpEvent, TcpProvider, TcpTransport,
};
use minip2p_transport::{ConnectionId, StreamId, Transport, TransportEvent};

type Node = TcpTransport<SmoltcpTcpProvider<VirtualDevice>, CountingEntropy>;

/// Enough polls for a handshake plus several retransmit rounds; short enough
/// that a livelock fails rather than hangs.
const MAX_STEPS: usize = 20_000;

const DIALER_IP4: &str = "192.168.1.1";
const LISTENER_IP4: &str = "192.168.1.2";
const UNUSED_IP4: &str = "192.168.1.9";

/// Deterministic entropy, so a failing test reproduces exactly.
struct CountingEntropy(u8);

impl EntropySource for CountingEntropy {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        for byte in output.iter_mut() {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- the link

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

/// Which frames of a direction the link swallows.
///
/// Loss is scripted rather than random so a failing run reproduces, and it is
/// positional so a test can name the segment it wants gone -- the third one,
/// the acknowledgement -- rather than hoping.
#[derive(Default)]
struct Loss {
    deliver_first: Cell<usize>,
    then_drop: Cell<usize>,
}

impl Loss {
    /// Whether this frame reaches the other end, consuming one step of the
    /// script.
    fn delivers(&self) -> bool {
        if self.then_drop.get() == 0 {
            return true;
        }
        if self.deliver_first.get() > 0 {
            self.deliver_first.set(self.deliver_first.get() - 1);
            return true;
        }
        self.then_drop.set(self.then_drop.get() - 1);
        false
    }
}

/// A frame queue in each direction, plus the knobs a lossy link needs.
#[derive(Clone)]
struct Wire {
    dialer_out: Queue,
    listener_out: Queue,
    from_dialer: Rc<Loss>,
    from_listener: Rc<Loss>,
}

impl Wire {
    fn new() -> Self {
        Self {
            dialer_out: Queue::default(),
            listener_out: Queue::default(),
            from_dialer: Rc::default(),
            from_listener: Rc::default(),
        }
    }

    /// Swallows `count` frames the dialer sends, after letting `skip` through.
    fn lose_from_dialer(&self, skip: usize, count: usize) {
        self.from_dialer.deliver_first.set(skip);
        self.from_dialer.then_drop.set(count);
    }

    fn dialer_device(&self) -> VirtualDevice {
        VirtualDevice {
            outbox: Rc::clone(&self.dialer_out),
            inbox: Rc::clone(&self.listener_out),
            loss: Rc::clone(&self.from_dialer),
        }
    }

    fn listener_device(&self) -> VirtualDevice {
        VirtualDevice {
            outbox: Rc::clone(&self.listener_out),
            inbox: Rc::clone(&self.dialer_out),
            loss: Rc::clone(&self.from_listener),
        }
    }

    /// Whether anything is on the wire waiting to be picked up.
    fn is_quiet(&self) -> bool {
        self.dialer_out.borrow().is_empty() && self.listener_out.borrow().is_empty()
    }
}

/// One end of the link, as a smoltcp device.
struct VirtualDevice {
    outbox: Queue,
    inbox: Queue,
    loss: Rc<Loss>,
}

struct RxFrame(Vec<u8>);

impl RxToken for RxFrame {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct TxSink {
    outbox: Queue,
    loss: Rc<Loss>,
}

impl TxToken for TxSink {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0u8; len];
        let result = f(&mut frame);
        if self.loss.delivers() {
            self.outbox.borrow_mut().push_back(frame);
        }
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
        Some((RxFrame(frame), self.sink()))
    }

    fn transmit(&mut self, _now: Instant) -> Option<TxSink> {
        Some(self.sink())
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1500;
        capabilities
    }
}

impl VirtualDevice {
    fn sink(&self) -> TxSink {
        TxSink {
            outbox: Rc::clone(&self.outbox),
            loss: Rc::clone(&self.loss),
        }
    }
}

// ------------------------------------------------------------- the nodes

fn addr(text: &str) -> Multiaddr {
    text.parse().expect("test address parses")
}

fn identity(seed: u8) -> Ed25519Keypair {
    Ed25519Keypair::from_secret_key_bytes([seed; 32])
}

/// A provider on an interface holding exactly `address`.
fn provider(mut device: VirtualDevice, address: &str, config: SmoltcpConfig) -> Provider {
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::from_millis(0),
    );
    let cidr = address.parse::<IpCidr>().expect("test CIDR parses");
    iface.update_ip_addrs(|addrs| addrs.push(cidr).expect("room for one address"));
    SmoltcpTcpProvider::new(device, iface, config)
}

type Provider = SmoltcpTcpProvider<VirtualDevice>;

fn node(device: VirtualDevice, address: &str, key: Ed25519Keypair, seed: u8) -> Node {
    TcpTransport::with_config(
        provider(device, address, SmoltcpConfig::default()),
        key,
        CountingEntropy(seed),
        TcpConfig::default(),
    )
}

/// Polls both nodes until `done`, advancing a virtual clock.
///
/// The clock only ever moves when the wire is empty and neither node has
/// anything left to do at the current instant, so it advances to whichever
/// deadline the two report -- which makes every retransmit, delayed
/// acknowledgement, and timeout in these tests something
/// [`next_deadline`](Transport::next_deadline) had to ask for. A run that
/// reaches quiescence with no deadline and no result has genuinely wedged, and
/// says so rather than spinning.
fn run_until(
    wire: &Wire,
    a: &mut Node,
    b: &mut Node,
    a_events: &mut Vec<TransportEvent>,
    b_events: &mut Vec<TransportEvent>,
    mut done: impl FnMut(&[TransportEvent], &[TransportEvent]) -> bool,
) -> u64 {
    let mut now = 0u64;
    for _ in 0..MAX_STEPS {
        a_events.extend(a.poll(Now::from_millis(now)).expect("poll a"));
        b_events.extend(b.poll(Now::from_millis(now)).expect("poll b"));
        if done(a_events, b_events) {
            return now;
        }
        if !wire.is_quiet() {
            continue;
        }
        let next = Deadline::earliest_opt(a.next_deadline(), b.next_deadline())
            .expect("active providers must report a deadline when the wire is quiet");
        if next.as_millis() > now {
            now = next.as_millis();
        }
    }
    assert!(done(a_events, b_events), "providers never finished");
    now
}

struct Pair {
    wire: Wire,
    dialer: Node,
    listener: Node,
    dialer_peer: PeerId,
    listener_peer: PeerId,
    connection: ConnectionId,
    dialer_events: Vec<TransportEvent>,
    listener_events: Vec<TransportEvent>,
    /// Virtual milliseconds the upgrade took.
    elapsed: u64,
}

fn upgraded_pair(wire: Wire) -> Pair {
    upgraded_pair_on(wire, LISTENER_IP4, DIALER_IP4, 24)
}

fn upgraded_pair_on(wire: Wire, listener_ip: &str, dialer_ip: &str, prefix: u8) -> Pair {
    let dialer_key = identity(1);
    let listener_key = identity(2);
    let (dialer_peer, listener_peer) = (dialer_key.peer_id(), listener_key.peer_id());

    let mut dialer = node(
        wire.dialer_device(),
        &format!("{dialer_ip}/{prefix}"),
        dialer_key,
        10,
    );
    let mut listener = node(
        wire.listener_device(),
        &format!("{listener_ip}/{prefix}"),
        listener_key,
        20,
    );

    let bound = listener
        .listen(&host_port(listener_ip, 0))
        .expect("listener binds");
    let target = PeerAddr::new(bound, listener_peer.clone()).expect("dial target");
    let connection = dialer.dial(&target).expect("dial starts");

    let mut dialer_events = Vec::new();
    let mut listener_events = Vec::new();
    let elapsed = run_until(
        &wire,
        &mut dialer,
        &mut listener,
        &mut dialer_events,
        &mut listener_events,
        |a, b| connected(a).is_some() && connected(b).is_some(),
    );

    Pair {
        wire,
        dialer,
        listener,
        dialer_peer,
        listener_peer,
        connection,
        dialer_events,
        listener_events,
        elapsed,
    }
}

/// A `/ipX/tcp/port` address for an interface address written as a bare IP.
fn host_port(ip: &str, port: u16) -> Multiaddr {
    let family = if ip.contains(':') { "ip6" } else { "ip4" };
    addr(&format!("/{family}/{ip}/tcp/{port}"))
}

fn connected(events: &[TransportEvent]) -> Option<&PeerId> {
    events.iter().find_map(|event| match event {
        TransportEvent::Connected { endpoint, .. } => endpoint.peer_id(),
        _ => None,
    })
}

fn stream_data(events: &[TransportEvent], stream: StreamId) -> Vec<u8> {
    events
        .iter()
        .filter_map(|event| match event {
            TransportEvent::StreamData {
                stream_id, data, ..
            } if *stream_id == stream => Some(data.clone()),
            _ => None,
        })
        .flatten()
        .collect()
}

// -------------------------------------------------------------- the tests

#[test]
fn two_smoltcp_nodes_complete_the_libp2p_upgrade() {
    let pair = upgraded_pair(Wire::new());

    // The whole point of the seam: this is the same transport, session, and
    // handshake the hosted provider runs, over a stack that shares no code
    // with an operating system.
    assert_eq!(connected(&pair.dialer_events), Some(&pair.listener_peer));
    assert_eq!(connected(&pair.listener_events), Some(&pair.dialer_peer));

    let incoming = pair
        .listener_events
        .iter()
        .position(|event| matches!(event, TransportEvent::IncomingConnection { .. }))
        .expect("listener reports the inbound connection");
    let established = pair
        .listener_events
        .iter()
        .position(|event| matches!(event, TransportEvent::Connected { .. }))
        .expect("listener completes the upgrade");
    assert!(
        incoming < established,
        "IncomingConnection must precede Connected: {:?}",
        pair.listener_events
    );
}

#[test]
fn the_connected_endpoint_names_the_address_the_segments_came_from() {
    let pair = upgraded_pair(Wire::new());

    // smoltcp reports the peer of an established socket, and the provider
    // turns that into an address rather than echoing what was dialled.
    let sources = pair.listener.active_inbound_connection_sources();
    assert_eq!(sources.len(), 1, "one inbound connection: {sources:?}");
    let source = sources[0].to_string();
    assert!(
        source.starts_with(&format!("/ip4/{DIALER_IP4}/tcp/")),
        "the inbound source should be the dialer's address, got {source}"
    );
}

#[test]
fn a_stream_carries_bytes_both_ways_between_smoltcp_nodes() {
    let mut pair = upgraded_pair(Wire::new());
    let stream = pair
        .dialer
        .open_stream(pair.connection)
        .expect("dialer opens a stream");
    pair.dialer
        .send_stream(pair.connection, stream, b"ping over smoltcp".to_vec())
        .expect("dialer writes");

    run_until(
        &pair.wire,
        &mut pair.dialer,
        &mut pair.listener,
        &mut pair.dialer_events,
        &mut pair.listener_events,
        |_, b| !stream_data(b, stream).is_empty(),
    );
    assert_eq!(
        stream_data(&pair.listener_events, stream),
        b"ping over smoltcp"
    );

    pair.listener
        .send_stream(pair.connection, stream, b"pong".to_vec())
        .expect("listener writes");
    run_until(
        &pair.wire,
        &mut pair.dialer,
        &mut pair.listener,
        &mut pair.dialer_events,
        &mut pair.listener_events,
        |a, _| !stream_data(a, stream).is_empty(),
    );
    assert_eq!(stream_data(&pair.dialer_events, stream), b"pong");
}

#[test]
fn a_payload_larger_than_one_segment_arrives_whole_and_in_order() {
    let mut pair = upgraded_pair(Wire::new());
    let stream = pair
        .dialer
        .open_stream(pair.connection)
        .expect("dialer opens a stream");

    // Larger than the MTU and larger than a socket's transmit ring, so this
    // has to survive segmentation, short writes, and the peer's window.
    let payload: Vec<u8> = (0..40_000u32).map(|index| index as u8).collect();
    pair.dialer
        .send_stream(pair.connection, stream, payload.clone())
        .expect("dialer writes");

    run_until(
        &pair.wire,
        &mut pair.dialer,
        &mut pair.listener,
        &mut pair.dialer_events,
        &mut pair.listener_events,
        |_, b| stream_data(b, stream).len() >= payload.len(),
    );
    assert_eq!(stream_data(&pair.listener_events, stream), payload);
}

#[test]
fn a_lost_segment_is_retransmitted_on_the_deadline_the_transport_reported() {
    let clean = upgraded_pair(Wire::new());

    // The same handshake, with the dialer's first few frames swallowed. TCP
    // recovers by retransmitting -- but only if something asks it to, and the
    // only thing that can is the deadline the transport reports.
    let lossy = Wire::new();
    lossy.lose_from_dialer(0, 3);
    let dropped = upgraded_pair(lossy);

    assert_eq!(
        connected(&dropped.dialer_events),
        Some(&dropped.listener_peer)
    );
    assert_eq!(
        connected(&dropped.listener_events),
        Some(&dropped.dialer_peer)
    );
    let dial_timeout = SmoltcpConfig::default()
        .connect_timeout_ms
        .expect("a default dial timeout");
    assert!(
        dropped.elapsed > clean.elapsed,
        "recovering from loss has to wait for a retransmit timer, \
         but the lossy run took {}ms against {}ms clean",
        dropped.elapsed,
        clean.elapsed
    );
    // And it has to be the retransmit that recovered it, on a retransmit's
    // timescale. Reaching the dial timeout would mean the connection was
    // rebuilt from scratch rather than repaired, which is a different thing
    // passing for the same result.
    assert!(
        dropped.elapsed < dial_timeout,
        "loss should cost retransmits, not a whole dial timeout: {}ms of {dial_timeout}ms",
        dropped.elapsed
    );
}

#[test]
fn an_upgrade_over_ipv6_works_the_same() {
    let pair = upgraded_pair_on(Wire::new(), "fd00::2", "fd00::1", 64);

    assert_eq!(connected(&pair.dialer_events), Some(&pair.listener_peer));
    assert_eq!(connected(&pair.listener_events), Some(&pair.dialer_peer));
    let sources = pair.listener.active_inbound_connection_sources();
    assert!(
        sources[0].to_string().starts_with("/ip6/fd00::1/tcp/"),
        "an IPv6 link should report an /ip6 source, got {sources:?}"
    );
}

#[test]
fn closing_a_connection_ends_it_for_the_peer_too() {
    let mut pair = upgraded_pair(Wire::new());
    pair.dialer.close(pair.connection).expect("dialer closes");

    run_until(
        &pair.wire,
        &mut pair.dialer,
        &mut pair.listener,
        &mut pair.dialer_events,
        &mut pair.listener_events,
        |_, b| {
            b.iter()
                .any(|event| matches!(event, TransportEvent::Closed { .. }))
        },
    );
    assert!(
        !pair
            .listener_events
            .iter()
            .any(|event| matches!(event, TransportEvent::Error { .. })),
        "an orderly close is not a failure: {:?}",
        pair.listener_events
    );
}

#[test]
fn a_dial_nothing_answers_fails_once_the_connect_timeout_expires() {
    let wire = Wire::new();
    let mut dialer = node(
        wire.dialer_device(),
        &format!("{DIALER_IP4}/24"),
        identity(1),
        10,
    );
    // A peer that exists on the link but never speaks: its SYNs go nowhere,
    // and smoltcp on its own would retransmit them for as long as the socket
    // lives.
    let mut silent = node(
        wire.listener_device(),
        &format!("{LISTENER_IP4}/24"),
        identity(2),
        20,
    );

    let target =
        PeerAddr::new(host_port(UNUSED_IP4, 4001), identity(3).peer_id()).expect("dial target");
    dialer.dial(&target).expect("dial starts");

    let mut dialer_events = Vec::new();
    let mut other_events = Vec::new();
    let elapsed = run_until(
        &wire,
        &mut dialer,
        &mut silent,
        &mut dialer_events,
        &mut other_events,
        |a, _| {
            a.iter()
                .any(|event| matches!(event, TransportEvent::Closed { .. }))
        },
    );

    let failure = dialer_events
        .iter()
        .find_map(|event| match event {
            TransportEvent::Error { message, .. } => Some(message.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("the dial should say why it failed: {dialer_events:?}"));
    assert!(
        failure.contains("timed out"),
        "the failure should name the timeout, got {failure}"
    );

    let timeout = SmoltcpConfig::default()
        .connect_timeout_ms
        .expect("a default connect timeout");
    assert!(
        elapsed >= timeout,
        "a dial must not be abandoned before its timeout: gave up after {elapsed}ms"
    );
}

// ------------------------------------------------- straight at the provider
//
// Some of the seam is invisible from above: what an address is allowed to look
// like, what a listener reports, and what a ceiling does when it is reached.

mod provider {
    use super::*;

    /// Two providers on one wire, sharing a clock that only moves forwards.
    struct Duo {
        wire: Wire,
        dialer: Provider,
        listener: Provider,
        now: u64,
        dialer_events: Vec<TcpEvent>,
        listener_events: Vec<TcpEvent>,
    }

    impl Duo {
        fn new() -> Self {
            Self::with_config(SmoltcpConfig::default())
        }

        fn with_config(config: SmoltcpConfig) -> Self {
            let wire = Wire::new();
            Self {
                dialer: provider(
                    wire.dialer_device(),
                    &format!("{DIALER_IP4}/24"),
                    config.clone(),
                ),
                listener: provider(
                    wire.listener_device(),
                    &format!("{LISTENER_IP4}/24"),
                    config,
                ),
                wire,
                now: 0,
                dialer_events: Vec::new(),
                listener_events: Vec::new(),
            }
        }

        /// Polls both until nothing is left to do at the current instant.
        ///
        /// Deliberately does not advance the clock: everything these tests care
        /// about happens on packet arrival, and a harness that jumped forwards
        /// would quietly turn "the peer never heard" into "the peer heard on a
        /// retransmit".
        #[expect(
            clippy::panic,
            reason = "exhausting the test harness step budget is an invariant failure"
        )]
        fn drain(&mut self) {
            for _ in 0..MAX_STEPS {
                let now = Now::from_millis(self.now);
                self.dialer_events
                    .extend(self.dialer.poll(now).expect("poll dialer"));
                self.listener_events
                    .extend(self.listener.poll(now).expect("poll listener"));
                if !self.wire.is_quiet() {
                    continue;
                }
                let due = |deadline: Option<Deadline>| {
                    deadline.is_some_and(|deadline| deadline.as_millis() <= self.now)
                };
                if !due(self.dialer.next_deadline()) && !due(self.listener.next_deadline()) {
                    return;
                }
            }
            panic!("the providers never settled within the step budget")
        }

        /// Listens, dials, and drives the handshake to completion.
        fn connect(&mut self) -> SocketHandle {
            let bound = self
                .listener
                .listen(&host_port(LISTENER_IP4, 0))
                .expect("listener binds");
            let socket = self.dialer.connect(&bound).expect("dial starts");
            self.drain();
            assert!(
                self.dialer_events.iter().any(|event| matches!(
                    event,
                    TcpEvent::Connected { socket: found, .. } if *found == socket
                )),
                "the handshake should complete: {:?}",
                self.dialer_events
            );
            socket
        }

        fn forget(&mut self) {
            self.dialer_events.clear();
            self.listener_events.clear();
        }
    }

    fn lone_provider(config: SmoltcpConfig) -> Provider {
        let wire = Wire::new();
        provider(wire.dialer_device(), &format!("{DIALER_IP4}/24"), config)
    }

    #[test]
    fn a_name_cannot_be_dialed_without_a_resolver() {
        let mut provider = lone_provider(SmoltcpConfig::default());
        let error = provider
            .connect(&addr("/dns4/example.com/tcp/4001"))
            .expect_err("a name is not dialable here");
        let message = error.to_string();
        assert!(
            message.contains("name resolution"),
            "the error should say why a name cannot be used, got {message}"
        );
    }

    #[test]
    fn an_address_with_anything_trailing_is_refused() {
        let mut provider = lone_provider(SmoltcpConfig::default());
        // A `/p2p-circuit` suffix is somebody else's business; dialing it as if
        // the suffix were not there would connect somewhere nobody asked for.
        let error = provider
            .connect(&addr(&format!("/ip4/{LISTENER_IP4}/tcp/4001/p2p-circuit")))
            .expect_err("a decorated address is not a bare dial target");
        assert!(error.to_string().contains("bare"), "got {error}");
    }

    #[test]
    fn listening_on_port_zero_reports_the_port_it_picked() {
        let mut provider = lone_provider(SmoltcpConfig::default());
        let bound = provider
            .listen(&host_port(DIALER_IP4, 0))
            .expect("binds an ephemeral port");
        let text = bound.to_string();
        assert!(
            text.starts_with(&format!("/ip4/{DIALER_IP4}/tcp/")) && !text.ends_with("/tcp/0"),
            "an ephemeral listen has to resolve to a real port, got {text}"
        );
        assert_eq!(provider.local_addresses(), vec![bound]);
    }

    #[test]
    fn a_wildcard_listener_reports_every_address_the_interface_holds() {
        let wire = Wire::new();
        let mut device = wire.dialer_device();
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            Instant::from_millis(0),
        );
        iface.update_ip_addrs(|addrs| {
            addrs.push("192.168.1.1/24".parse().unwrap()).unwrap();
            addrs.push("10.0.0.1/8".parse().unwrap()).unwrap();
        });
        let mut provider = SmoltcpTcpProvider::new(device, iface, SmoltcpConfig::default());

        provider
            .listen(&addr("/ip4/0.0.0.0/tcp/4001"))
            .expect("binds the wildcard");
        // A wildcard really is reachable at both, so reporting only the one
        // `listen` happened to name would hide half the ways in.
        let reported: Vec<String> = provider
            .local_addresses()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            reported,
            vec!["/ip4/192.168.1.1/tcp/4001", "/ip4/10.0.0.1/tcp/4001"]
        );
    }

    #[test]
    fn listening_twice_on_one_port_is_refused() {
        let mut provider = lone_provider(SmoltcpConfig::default());
        provider
            .listen(&host_port(DIALER_IP4, 4001))
            .expect("first listener binds");
        let error = provider
            .listen(&host_port(DIALER_IP4, 4001))
            .expect_err("the port is taken");
        assert!(error.to_string().contains("already in use"), "got {error}");
    }

    #[test]
    fn two_listeners_share_a_port_when_their_addresses_differ() {
        let wire = Wire::new();
        let mut device = wire.dialer_device();
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            Instant::from_millis(0),
        );
        iface.update_ip_addrs(|addrs| {
            addrs.push("192.168.1.1/24".parse().unwrap()).unwrap();
            addrs.push("fd00::1/64".parse().unwrap()).unwrap();
        });
        let mut provider = SmoltcpTcpProvider::new(device, iface, SmoltcpConfig::default());

        // One port per address is two endpoints, not one taken twice: smoltcp
        // matches a segment on the local address as well as the port. A host
        // binding a fixed port on each family would otherwise be told the
        // second one was in use.
        provider
            .listen(&addr("/ip4/192.168.1.1/tcp/4001"))
            .expect("the first address binds");
        provider
            .listen(&addr("/ip6/fd00::1/tcp/4001"))
            .expect("the second address is a listener of its own");
        assert_eq!(provider.local_addresses().len(), 2);

        // A wildcard answers for every address on its port, so that one really
        // does collide with both.
        let error = provider
            .listen(&addr("/ip4/0.0.0.0/tcp/4001"))
            .expect_err("a wildcard overlaps what is already bound");
        assert!(error.to_string().contains("already in use"), "got {error}");
    }

    #[test]
    fn a_flooded_link_does_not_hold_a_poll_open() {
        let wire = Wire::new();
        let mut listener = provider(
            wire.listener_device(),
            &format!("{LISTENER_IP4}/24"),
            SmoltcpConfig::default(),
        );
        listener
            .listen(&host_port(LISTENER_IP4, 4001))
            .expect("listener binds");

        // Far more than one poll's worth, all of it already waiting: a poll
        // that drained the link would be doing unbounded work with nothing on
        // this host able to preempt it.
        let flood = 500;
        for _ in 0..flood {
            wire.dialer_out.borrow_mut().push_back(vec![0xff; 64]);
        }

        listener.poll(Now::from_millis(0)).expect("poll");
        let left = wire.dialer_out.borrow().len();
        assert!(
            left > 0,
            "one poll took the whole backlog: {left} left of {flood}"
        );
        assert_eq!(
            listener.next_deadline(),
            Some(Deadline::IMMEDIATE),
            "what did not fit is due now, or nothing would come back for it"
        );

        // And it does drain: a budget that stranded packets would be worse
        // than the flood.
        for step in 0..MAX_STEPS {
            if wire.dialer_out.borrow().is_empty() {
                break;
            }
            listener
                .poll(Now::from_millis(step as u64))
                .expect("poll again");
        }
        assert!(
            wire.dialer_out.borrow().is_empty(),
            "the backlog should clear over successive polls"
        );
    }

    #[test]
    fn listening_on_an_address_the_interface_does_not_hold_is_refused() {
        let mut provider = lone_provider(SmoltcpConfig::default());
        // smoltcp would take the endpoint and then never match a packet,
        // leaving a listener that silently hears nothing.
        let error = provider
            .listen(&host_port(LISTENER_IP4, 4001))
            .expect_err("not this interface's address");
        assert!(error.to_string().contains("interface"), "got {error}");
    }

    #[test]
    fn the_socket_ceiling_bounds_what_a_provider_allocates() {
        let mut provider = lone_provider(SmoltcpConfig {
            max_sockets: 3,
            backlog: 1,
            ..SmoltcpConfig::default()
        });
        provider
            .listen(&host_port(DIALER_IP4, 4001))
            .expect("the listener takes one socket");

        // Two left, then the ceiling: a device that budgeted for three sockets
        // gets three, not three plus however many dials it attempts.
        let target = host_port(LISTENER_IP4, 4001);
        provider.connect(&target).expect("first dial fits");
        provider.connect(&target).expect("second dial fits");
        let error = provider.connect(&target).expect_err("the ceiling holds");
        assert!(error.to_string().contains("tcp sockets"), "got {error}");
    }

    #[test]
    fn a_dial_that_cannot_be_started_leaves_no_port_behind() {
        let mut provider = lone_provider(SmoltcpConfig {
            max_sockets: 1,
            backlog: 1,
            // Two ports and one socket, so the second dial reserves a port and
            // then fails on the socket -- which is the only ordering in which a
            // leaked port is observable.
            ephemeral_ports: 51000..=51001,
            ..SmoltcpConfig::default()
        });
        let target = host_port(LISTENER_IP4, 4001);

        provider.connect(&target).expect("the one socket");
        let error = provider.connect(&target).expect_err("no socket left");
        assert!(error.to_string().contains("tcp sockets"), "got {error}");

        let again = provider.connect(&target).expect_err("still no socket");
        assert!(
            again.to_string().contains("tcp sockets"),
            "the refused dial held on to the port it reserved: {again}"
        );
    }

    #[test]
    fn a_handshake_still_in_flight_does_not_hold_the_backlog() {
        let mut duo = Duo::with_config(SmoltcpConfig {
            // One slot, so whether it is freed is the difference between a
            // second connection and none.
            backlog: 1,
            ..SmoltcpConfig::default()
        });
        let bound = duo
            .listener
            .listen(&host_port(LISTENER_IP4, 0))
            .expect("listener binds");

        // Swallow the dialer's acknowledgement, so the listener's socket is
        // left half-open: past `Listen`, not yet established, and going nowhere
        // until a retransmit. A backlog slot it still occupied would be a slot
        // any peer could take out of service by walking away mid-handshake.
        duo.wire.lose_from_dialer(1, 1);
        duo.dialer.connect(&bound).expect("first dial starts");
        duo.drain();
        duo.forget();

        duo.dialer.connect(&bound).expect("second dial starts");
        duo.drain();
        assert!(
            duo.listener_events
                .iter()
                .any(|event| matches!(event, TcpEvent::Accepted { .. })),
            "the backlog should have refilled behind the stalled handshake, got {:?}",
            duo.listener_events
        );
    }

    #[test]
    fn everything_written_before_a_half_close_arrives_before_the_end_of_stream() {
        let mut duo = Duo::new();
        let socket = duo.connect();
        duo.forget();

        let payload = vec![9u8; 12_000];
        let mut offset = 0;
        while offset < payload.len() {
            offset += duo.dialer.send(socket, &payload[offset..]).expect("write");
            duo.drain();
        }
        duo.dialer.close_write(socket).expect("half-closes");
        duo.drain();

        // `RemoteWriteClosed` promises no `Received` follows it. A provider
        // that read end-of-stream off the socket's state rather than off its
        // receive buffer would announce the end with bytes still in hand.
        let ended = duo
            .listener_events
            .iter()
            .position(|event| matches!(event, TcpEvent::RemoteWriteClosed { .. }))
            .expect("the peer sees end-of-stream");
        let delivered: Vec<u8> = duo.listener_events[..ended]
            .iter()
            .filter_map(|event| match event {
                TcpEvent::Received { data, .. } => Some(data.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(
            delivered, payload,
            "every byte has to arrive before the stream is declared over"
        );
    }

    /// Shorter than the default, so a test can wait one out.
    const BRIEF_TIMEOUT: u64 = 1_000;

    #[test]
    fn a_dial_made_after_a_long_idle_is_not_born_expired() {
        let mut duo = Duo::new();
        let bound = duo
            .listener
            .listen(&host_port(LISTENER_IP4, 0))
            .expect("listener binds");
        duo.drain();

        // The host had nothing to do for far longer than a dial is allowed to
        // take, and then dialled -- without polling first, which nothing
        // requires it to do. A countdown dated from the last poll's time sample
        // would already have run out before this dial reached the wire.
        duo.now = 10
            * SmoltcpConfig::default()
                .connect_timeout_ms
                .expect("a default dial timeout");
        let socket = duo.dialer.connect(&bound).expect("dial starts");
        duo.drain();

        assert!(
            duo.dialer_events.iter().any(|event| matches!(
                event,
                TcpEvent::Connected { socket: found, .. } if *found == socket
            )),
            "the dial should complete rather than expire on arrival: {:?}",
            duo.dialer_events
        );
    }

    #[test]
    fn an_inbound_attempt_that_dies_before_it_is_accepted_is_never_mentioned() {
        let mut duo = Duo::with_config(SmoltcpConfig {
            connect_timeout_ms: Some(BRIEF_TIMEOUT),
            ..SmoltcpConfig::default()
        });
        let bound = duo
            .listener
            .listen(&host_port(LISTENER_IP4, 0))
            .expect("listener binds");
        duo.drain();
        duo.forget();

        // A peer that sends a `SYN` and never acknowledges the reply. No handle
        // was ever handed over for it, so the listener has nothing to say: not
        // an `Accepted` for a connection that never existed, and not a `Closed`
        // against a handle its caller has never seen.
        duo.wire.lose_from_dialer(1, 1);
        duo.dialer.connect(&bound).expect("dial starts");
        duo.drain();
        duo.now += BRIEF_TIMEOUT + 1;
        duo.drain();

        assert!(
            duo.listener_events.is_empty(),
            "a stream that never came up is not the caller's to hear about: {:?}",
            duo.listener_events
        );
    }

    #[test]
    fn abandoned_inbound_handshakes_do_not_exhaust_the_socket_budget() {
        let mut duo = Duo::with_config(SmoltcpConfig {
            max_sockets: 4,
            backlog: 1,
            connect_timeout_ms: Some(BRIEF_TIMEOUT),
            ..SmoltcpConfig::default()
        });
        let bound = duo
            .listener
            .listen(&host_port(LISTENER_IP4, 0))
            .expect("listener binds");

        // Six peers that open a connection and walk away mid-handshake.
        // smoltcp retransmits its `SYN-ACK` for as long as the socket exists,
        // so a listener with no countdown of its own spends its entire socket
        // budget on connections that will never be -- and never gets it back.
        for _ in 0..6 {
            duo.wire.lose_from_dialer(1, 1);
            duo.dialer.connect(&bound).expect("dial starts");
            duo.drain();
            duo.now += BRIEF_TIMEOUT + 1;
            duo.drain();
            duo.forget();
        }

        duo.dialer.connect(&bound).expect("dial starts");
        duo.drain();
        assert!(
            duo.listener_events
                .iter()
                .any(|event| matches!(event, TcpEvent::Accepted { .. })),
            "the listener should still be answering, got {:?}",
            duo.listener_events
        );
    }

    #[test]
    fn a_retired_connection_gives_its_port_back() {
        let mut duo = Duo::with_config(SmoltcpConfig {
            // One port, so a connection that failed to return it is the
            // difference between dialing again and never dialing again.
            ephemeral_ports: 51000..=51000,
            ..SmoltcpConfig::default()
        });
        let first = duo.connect();
        duo.dialer.abort(first);
        duo.drain();

        let bound = duo.listener.local_addresses()[0].clone();
        duo.dialer
            .connect(&bound)
            .expect("the port comes back with the connection");
    }

    #[test]
    fn a_port_is_not_reused_while_time_wait_still_holds_it() {
        let mut duo = Duo::with_config(SmoltcpConfig {
            // One port, so whether it is free is observable rather than
            // statistical.
            ephemeral_ports: 51000..=51000,
            ..SmoltcpConfig::default()
        });
        let socket = duo.connect();
        let peer = duo
            .listener_events
            .iter()
            .find_map(|event| match event {
                TcpEvent::Accepted { socket, .. } => Some(*socket),
                _ => None,
            })
            .expect("the listener's handle");

        // Close from this end first, which is what leaves it in `TIME-WAIT`
        // holding the four-tuple.
        duo.dialer.close_write(socket).expect("half-closes");
        duo.drain();
        duo.listener.close_write(peer).expect("peer half-closes");
        duo.drain();

        // The connection is over as far as the caller is concerned, but the
        // stack is still absorbing what the old one might retransmit. Handing
        // its port to a fresh dial would put two connections on one tuple.
        let bound = duo.listener.local_addresses()[0].clone();
        let error = duo
            .dialer
            .connect(&bound)
            .expect_err("the port is not free yet");
        assert!(error.to_string().contains("ephemeral ports"), "got {error}");
    }

    #[test]
    fn a_queued_segment_makes_the_provider_ask_to_be_polled() {
        let mut duo = Duo::new();
        let bound = duo
            .listener
            .listen(&host_port(LISTENER_IP4, 0))
            .expect("listener binds");

        let socket = duo.dialer.connect(&bound).expect("dial starts");
        // The SYN is queued, not sent. A host that trusted the last poll's
        // deadline here would sleep on a connection that has not left the
        // building.
        assert_eq!(
            duo.dialer.next_deadline(),
            Some(Deadline::IMMEDIATE),
            "a queued segment is due now"
        );

        duo.drain();
        duo.dialer
            .send(socket, b"hello")
            .expect("write is accepted");
        assert_eq!(
            duo.dialer.next_deadline(),
            Some(Deadline::IMMEDIATE),
            "queued bytes are due now"
        );

        duo.drain();
        let delivered: Vec<u8> = duo
            .listener_events
            .iter()
            .filter_map(|event| match event {
                TcpEvent::Received { data, .. } => Some(data.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(
            delivered, b"hello",
            "and the poll is what puts them on the wire"
        );
    }

    #[test]
    fn an_aborted_stream_is_never_mentioned_again_but_the_peer_still_finds_out() {
        let mut duo = Duo::new();
        let socket = duo.connect();
        duo.forget();

        duo.dialer.abort(socket);
        // The reset is queued, not sent. A host asleep on the last poll's
        // deadline would leave the peer holding a connection to nobody.
        assert_eq!(
            duo.dialer.next_deadline(),
            Some(Deadline::IMMEDIATE),
            "a queued reset is due now"
        );
        duo.drain();

        assert!(
            duo.dialer_events.is_empty(),
            "an aborted handle is owed nothing further, got {:?}",
            duo.dialer_events
        );
        // The reset still has to reach the peer, or an abort is a leak on the
        // other end rather than a teardown.
        let closed: Vec<&TcpEvent> = duo
            .listener_events
            .iter()
            .filter(|event| matches!(event, TcpEvent::Closed { .. }))
            .collect();
        assert_eq!(
            closed.len(),
            1,
            "`Closed` is terminal, so it is said once: {:?}",
            duo.listener_events
        );

        // And the peer's handle is spent with it. A provider that reported the
        // end but kept the stream would hold its buffers for good.
        let peer_socket = duo
            .listener_events
            .iter()
            .find_map(|event| match event {
                TcpEvent::Closed { socket, .. } => Some(*socket),
                _ => None,
            })
            .expect("the peer's handle");
        let error = duo
            .listener
            .send(peer_socket, b"gone")
            .expect_err("a retired handle takes nothing");
        assert!(error.to_string().contains("is not open"), "got {error}");
    }

    #[test]
    fn a_refused_write_is_owed_a_writable_once_there_is_room() {
        let mut duo = Duo::with_config(SmoltcpConfig {
            tx_buffer: 4096,
            ..SmoltcpConfig::default()
        });
        let socket = duo.connect();
        duo.forget();

        let accepted = duo
            .dialer
            .send(socket, &vec![7u8; 64 * 1024])
            .expect("write");
        assert!(accepted < 64 * 1024, "the ring should refuse most of this");

        // `Writable` is a hint rather than a requirement, but a provider that
        // never offers it makes an idle host wait for a timer to discover what
        // the peer already told it.
        duo.drain();
        assert!(
            duo.dialer_events.iter().any(
                |event| matches!(event, TcpEvent::Writable { socket: found } if *found == socket)
            ),
            "the socket drained, so the refused write is owed a wake: {:?}",
            duo.dialer_events
        );
    }

    #[test]
    fn a_dial_to_a_port_nobody_is_listening_on_fails_without_waiting() {
        let mut duo = Duo::new();
        // The peer is there and answers -- with a reset, because nothing is
        // bound. That is a failure the dialer learns at once, rather than the
        // silence it would have to time out on.
        let socket = duo
            .dialer
            .connect(&host_port(LISTENER_IP4, 4001))
            .expect("dial starts");
        duo.drain();

        let reason = duo
            .dialer_events
            .iter()
            .find_map(|event| match event {
                TcpEvent::Closed {
                    socket: found,
                    reason,
                } if *found == socket => Some(reason.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("the dial should fail: {:?}", duo.dialer_events));
        assert_eq!(reason.as_deref(), Some("the connection attempt failed"));
        // Nothing was ever established, so nothing else may be claimed for it.
        assert!(
            !duo.dialer_events
                .iter()
                .any(|event| matches!(event, TcpEvent::Connected { .. })),
            "a refused dial never connected: {:?}",
            duo.dialer_events
        );
    }

    #[test]
    fn half_closing_reaches_the_peer_as_end_of_stream() {
        let mut duo = Duo::new();
        let socket = duo.connect();
        duo.forget();

        duo.dialer.close_write(socket).expect("half-closes");
        duo.drain();

        let ended = duo
            .listener_events
            .iter()
            .filter(|event| matches!(event, TcpEvent::RemoteWriteClosed { .. }))
            .count();
        assert_eq!(
            ended, 1,
            "the peer should see end-of-stream, once: {:?}",
            duo.listener_events
        );
        // Half-close is not a teardown: the peer may still write back.
        assert!(
            !duo.listener_events
                .iter()
                .any(|event| matches!(event, TcpEvent::Closed { .. })),
            "half-closing must not end the peer's connection: {:?}",
            duo.listener_events
        );
    }

    #[test]
    fn a_write_larger_than_the_transmit_ring_is_accepted_in_part() {
        let mut duo = Duo::with_config(SmoltcpConfig {
            tx_buffer: 4096,
            ..SmoltcpConfig::default()
        });
        let socket = duo.connect();

        // Short writes are the provider contract's first promise, and a ring
        // buffer is where they come from on this stack.
        let accepted = duo
            .dialer
            .send(socket, &vec![7u8; 64 * 1024])
            .expect("write");
        assert!(
            accepted > 0 && accepted <= 4096,
            "a 64 KiB write into a 4 KiB ring should be taken in part, got {accepted}"
        );
    }

    #[test]
    fn a_listener_keeps_accepting_after_the_first_connection() {
        let mut duo = Duo::new();
        let bound = duo
            .listener
            .listen(&host_port(LISTENER_IP4, 0))
            .expect("listener binds");

        // Each accepted socket is taken out of the backlog, so a listener that
        // did not refill it would serve exactly `backlog` connections and then
        // go quiet.
        for round in 0..4 {
            duo.forget();
            duo.dialer.connect(&bound).expect("dial starts");
            duo.drain();
            assert!(
                duo.listener_events
                    .iter()
                    .any(|event| matches!(event, TcpEvent::Accepted { .. })),
                "round {round} should be accepted, got {:?}",
                duo.listener_events
            );
        }
    }

    #[test]
    fn an_unknown_handle_is_rejected_rather_than_ignored() {
        let mut duo = Duo::new();
        let socket = duo.connect();
        duo.dialer.abort(socket);

        // The handle is spent. Taking a write against it would strand bytes
        // nobody can ever deliver.
        let error = duo
            .dialer
            .send(socket, b"gone")
            .expect_err("a spent handle takes nothing");
        assert!(error.to_string().contains("is not open"), "got {error}");
        // Aborting it again is a no-op, because the caller's intent is already
        // satisfied.
        duo.dialer.abort(socket);
    }
}
