//! Two peers that dial each other at once must settle on the same connection,
//! as must two of one peer's candidate dials that both complete, and a peer
//! whose old connection died silently must still get back in.

#![cfg(feature = "quic")]

use std::time::{Duration, Instant};

use minip2p::{
    ConnectOutcome, Ed25519Keypair, Endpoint, EndpointEvent, Multiaddr, Now, PeerAddr, PeerId,
    PollDeadline, PortableEndpoint, StreamId,
};
use minip2p_platform::{Clock, StdClock, StdEntropy};
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_transport::{Bytes, ConnectionId, Transport, TransportError, TransportEvent};

#[path = "../../../tests/support/endpoint.rs"]
mod endpoint_support;
use endpoint_support::NextEvent;

const QUIC: &str = "/ip4/127.0.0.1/udp/0/quic-v1";
/// Failure backstop, not a budget the test has to fit in.
const BACKSTOP: Duration = Duration::from_secs(10);
/// Comfortably past the swarm's 5 s `SIMULTANEOUS_DIAL_WINDOW_MS`.
const PAST_TIE_BREAK_WINDOW: Duration = Duration::from_millis(5_500);

fn bind(listen: &str, key: Ed25519Keypair) -> Endpoint {
    Endpoint::builder()
        .identity(key)
        .listen_on(listen)
        .expect("listen address")
        .bind()
        .expect("bind loopback")
}

/// Polls `endpoint` once and appends what it surfaced to `events`.
fn drive(endpoint: &mut Endpoint, events: &mut Vec<EndpointEvent>) {
    if let Some(event) = endpoint
        .next_event(Duration::from_millis(5))
        .expect("drive endpoint")
    {
        events.push(event);
    }
}

fn pinged(events: &[EndpointEvent], peer: &PeerId) -> bool {
    events.iter().any(
        |event| matches!(event, EndpointEvent::PingRttMeasured { peer_id, .. } if peer_id == peer),
    )
}

/// A and B `connect` to each other in the same tick, then ping both ways.
///
/// Each side registers its own dial first, so without the tie-break each
/// would replace it with the other's dial and close the one the other kept.
/// `ephemeral_dial_ports` is true when a dial leaves from a port other than
/// the listener's (TCP), so the kept connection's addresses show who dialed.
fn simultaneous_connect_keeps_one_shared_connection(listen: &str, ephemeral_dial_ports: bool) {
    let mut a = bind(listen, Ed25519Keypair::generate());
    let mut b = bind(listen, Ed25519Keypair::generate());
    let a_addr = a.listen().expect("a listens");
    let b_addr = b.listen().expect("b listens");
    let (a_peer, b_peer) = (a.peer_id().clone(), b.peer_id().clone());

    a.connect(&b_addr).expect("a connects");
    b.connect(&a_addr).expect("b connects");

    let (mut a_events, mut b_events) = (Vec::new(), Vec::new());
    let deadline = Instant::now() + BACKSTOP;
    while !a.is_peer_ready(&b_peer) || !b.is_peer_ready(&a_peer) {
        assert!(
            Instant::now() < deadline,
            "peers never both ready: a={a_events:?} b={b_events:?}"
        );
        drive(&mut a, &mut a_events);
        drive(&mut b, &mut b_events);
    }

    // A loser closed by the other side surfaces while the pings run.
    a.ping(&b_peer).expect("a pings");
    b.ping(&a_peer).expect("b pings");
    while !pinged(&a_events, &b_peer) || !pinged(&b_events, &a_peer) {
        assert!(
            Instant::now() < deadline,
            "pings never answered: a={a_events:?} b={b_events:?}"
        );
        drive(&mut a, &mut a_events);
        drive(&mut b, &mut b_events);
    }

    for (events, peer) in [(&a_events, &b_peer), (&b_events, &a_peer)] {
        assert!(
            !events.iter().any(|event| matches!(
                event,
                EndpointEvent::ConnectionClosed { peer_id, .. } if peer_id == peer
            )),
            "the peer must never disconnect: {events:?}"
        );
        // A losing dial completes as DialFailed, which the `connect` the
        // winner already settled absorbs.
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, EndpointEvent::DialFailed { .. })),
            "a settled connect must not surface its losing dial: {events:?}"
        );
    }
    assert!(a.is_peer_ready(&b_peer) && b.is_peer_ready(&a_peer));
    assert_eq!(a.connected_peers(), std::slice::from_ref(&b_peer));
    assert_eq!(b.connected_peers(), std::slice::from_ref(&a_peer));

    // Both keep the lower peer's dial: its remote end is the higher peer's
    // listener, while the higher peer sees it from the lower one's dial port.
    let (lower, higher, higher_addr, lower_addr, higher_peer, lower_peer) = if a_peer < b_peer {
        (&a, &b, &b_addr, &a_addr, &b_peer, &a_peer)
    } else {
        (&b, &a, &a_addr, &b_addr, &a_peer, &b_peer)
    };
    let kept_at_lower = lower.connection_id(higher_peer).expect("lower connected");
    assert_eq!(
        lower.connection_remote_addr(kept_at_lower),
        Some(higher_addr.transport()),
        "the lower peer keeps its own dial"
    );
    if ephemeral_dial_ports {
        let kept_at_higher = higher.connection_id(lower_peer).expect("higher connected");
        assert_ne!(
            higher.connection_remote_addr(kept_at_higher),
            Some(lower_addr.transport()),
            "the higher peer keeps the lower peer's dial, not its own"
        );
    }
}

#[test]
fn simultaneous_quic_connect_keeps_one_shared_connection() {
    simultaneous_connect_keeps_one_shared_connection(QUIC, false);
}

#[cfg(feature = "tcp")]
#[test]
fn simultaneous_tcp_connect_keeps_one_shared_connection() {
    simultaneous_connect_keeps_one_shared_connection("/ip4/127.0.0.1/tcp/0", true);
}

/// Holds back the first inbound connection's events until a second
/// connection comes up, then delivers the second first.
///
/// The contract leaves the order across connections open, so this is a legal
/// transport, and it makes the listener see two racing connections in the
/// order opposite to the one its own transport would report -- the order the
/// dialer most likely sees them in.
struct ReverseFirstTwo<T> {
    inner: T,
    held: Option<(ConnectionId, Vec<TransportEvent>)>,
    /// Holding is over, whether or not a second connection came.
    done: bool,
    /// A second connection came and was delivered ahead of the first.
    swapped: bool,
}

impl<T> ReverseFirstTwo<T> {
    /// Without `reverse`, passes every event straight through.
    fn new(inner: T, reverse: bool) -> Self {
        Self {
            inner,
            held: None,
            done: !reverse,
            swapped: false,
        }
    }
}

fn event_connection(event: &TransportEvent) -> Option<ConnectionId> {
    match event {
        TransportEvent::Connected { id, .. }
        | TransportEvent::StreamOpened { id, .. }
        | TransportEvent::IncomingStream { id, .. }
        | TransportEvent::StreamData { id, .. }
        | TransportEvent::StreamWritable { id, .. }
        | TransportEvent::StreamRemoteWriteClosed { id, .. }
        | TransportEvent::StreamWriteStopped { id, .. }
        | TransportEvent::StreamClosed { id, .. }
        | TransportEvent::Closed { id }
        | TransportEvent::Error { id, .. }
        | TransportEvent::IncomingConnection { id, .. }
        | TransportEvent::PeerIdentityVerified { id, .. } => Some(*id),
        TransportEvent::Listening { .. } => None,
    }
}

impl<T: Transport> Transport for ReverseFirstTwo<T> {
    fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        self.inner.dial(addr)
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        self.inner.listen(addr)
    }

    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        self.inner.open_stream(id)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
    ) -> Result<(), TransportError> {
        self.inner.send_stream(id, stream_id, data)
    }

    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        self.inner.close_stream_write(id, stream_id)
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        self.inner.reset_stream(id, stream_id)
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        self.inner.close(id)
    }

    fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        let mut out = Vec::new();
        for event in self.inner.poll(now)? {
            let conn = event_connection(&event);
            match &mut self.held {
                Some((held, buffered)) if conn == Some(*held) => {
                    let closed = matches!(event, TransportEvent::Closed { .. });
                    buffered.push(event);
                    if closed {
                        out.append(buffered);
                        self.held = None;
                        self.done = true;
                    }
                }
                Some(_) if matches!(event, TransportEvent::Connected { .. }) => {
                    out.push(event);
                    if let Some((_, buffered)) = self.held.take() {
                        out.extend(buffered);
                    }
                    self.done = true;
                    self.swapped = true;
                }
                None if !self.done && matches!(event, TransportEvent::Connected { .. }) => {
                    self.held = conn.map(|id| (id, vec![event]));
                }
                _ => out.push(event),
            }
        }
        Ok(out)
    }

    fn next_deadline(&self) -> Option<PollDeadline> {
        self.inner.next_deadline()
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        self.inner.local_addresses()
    }
}

/// A dials B with B's address twice, so both candidate dials race to B and
/// both complete. It runs once with B seeing them in its transport's order and
/// once reversed, so in one of the two runs B and A see them in opposite
/// orders, whichever order A's transport reports. Newest-wins would then leave
/// each side closing the connection the other kept. Both must keep the same
/// one (the lower connection token): a split would close both connections, so
/// both peers must still be connected, and answer pings, after the race has
/// had time to settle. `connect` must settle without a `DialFailed`.
///
/// `seamless` is whether A never loses its connection on the way. A QUIC
/// dialer sees both connections before the listener does, so it is. A TCP
/// listener sees both first and closes the loser at once, so A can lose the
/// connection it settled on just before its other dial lands and replaces
/// it -- a disconnect and reconnect, but on the connection both keep.
fn duplicate_candidates_keep_one_shared_connection<T: Transport>(
    transport: impl Fn(&Ed25519Keypair) -> T,
    listen: impl Fn(&T) -> Multiaddr,
    seamless: bool,
) {
    for reverse in [false, true] {
        duplicate_candidates_run(&transport, &listen, seamless, reverse);
    }
}

fn duplicate_candidates_run<T: Transport>(
    transport: &impl Fn(&Ed25519Keypair) -> T,
    listen: &impl Fn(&T) -> Multiaddr,
    seamless: bool,
    reverse: bool,
) {
    let (a_key, b_key) = (Ed25519Keypair::generate(), Ed25519Keypair::generate());
    let mut a = Endpoint::portable(&a_key, StdEntropy)
        .build(transport(&a_key))
        .expect("a builds");
    let b_transport = ReverseFirstTwo::new(transport(&b_key), reverse);
    let b_listen = listen(&b_transport.inner);
    let mut b = Endpoint::portable(&b_key, StdEntropy)
        .build(b_transport)
        .expect("b builds");
    let b_addr =
        PeerAddr::new(b.listen(&b_listen).expect("b listens"), b_key.peer_id()).expect("b address");
    let (a_peer, b_peer) = (a_key.peer_id(), b_key.peer_id());

    let mut clock = StdClock::new();
    let connect_id = a
        .connect(vec![b_addr.clone(), b_addr], clock.now())
        .expect("a connects");
    // Polls both once and returns the sample with what each surfaced.
    let mut drive = |a: &mut Portable<T>, b: &mut Portable<ReverseFirstTwo<T>>| {
        let now = clock.now();
        let a_new = a.poll(now).expect("a polls");
        let b_new = b.poll(now).expect("b polls");
        std::thread::sleep(Duration::from_millis(1));
        (now, a_new, b_new)
    };
    let (mut a_events, mut b_events) = (Vec::new(), Vec::new());
    let deadline = Instant::now() + BACKSTOP;
    while !a.is_peer_ready(&b_peer) || !b.is_peer_ready(&a_peer) {
        assert!(
            Instant::now() < deadline,
            "peers never both ready: a={a_events:?} b={b_events:?}"
        );
        let (_, a_new, b_new) = drive(&mut a, &mut b);
        a_events.extend(a_new);
        b_events.extend(b_new);
    }
    // A connection one side closed while the other kept it surfaces as a
    // disconnect while the pings run.
    let (now, a_new, b_new) = drive(&mut a, &mut b);
    a_events.extend(a_new);
    b_events.extend(b_new);
    a.ping(&b_peer, now).expect("a pings");
    b.ping(&a_peer, now).expect("b pings");
    while !pinged(&a_events, &b_peer) || !pinged(&b_events, &a_peer) {
        assert!(
            Instant::now() < deadline,
            "pings never answered: a={a_events:?} b={b_events:?}"
        );
        let (_, a_new, b_new) = drive(&mut a, &mut b);
        a_events.extend(a_new);
        b_events.extend(b_new);
    }

    // A split shows only once each side has closed the connection the other
    // kept: give the race time to settle, then both must still be connected
    // and answer pings on whatever they kept.
    let settle_until = Instant::now() + Duration::from_millis(300);
    while Instant::now() < settle_until {
        let (_, a_new, b_new) = drive(&mut a, &mut b);
        a_events.extend(a_new);
        b_events.extend(b_new);
    }
    let (now, a_new, b_new) = drive(&mut a, &mut b);
    let (mut a_later, mut b_later) = (a_new, b_new);
    a.ping(&b_peer, now).expect("a pings again");
    b.ping(&a_peer, now).expect("b pings again");
    while !pinged(&a_later, &b_peer) || !pinged(&b_later, &a_peer) {
        assert!(
            Instant::now() < deadline,
            "peers split onto different connections: a={a_later:?} b={b_later:?}"
        );
        let (_, a_new, b_new) = drive(&mut a, &mut b);
        a_later.extend(a_new);
        b_later.extend(b_new);
    }
    a_events.extend(a_later);
    b_events.extend(b_later);
    assert!(a.connection_id(&b_peer).is_some() && b.connection_id(&a_peer).is_some());

    assert_eq!(
        b.core().transport().swapped,
        reverse,
        "B saw two connections race"
    );
    for events in [&a_events, &b_events] {
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, EndpointEvent::DialFailed { .. })),
            "no surfaced dial failure: {events:?}"
        );
    }
    let settled = a_events.iter().find_map(|event| match event {
        EndpointEvent::ConnectSettled {
            connect_id: id,
            outcome,
            ..
        } if *id == connect_id => Some(outcome),
        _ => None,
    });
    assert!(
        matches!(settled, Some(ConnectOutcome::Connected { .. })),
        "connect settles connected: {a_events:?}"
    );
    if seamless {
        for events in [&a_events, &b_events] {
            assert!(
                !events
                    .iter()
                    .any(|event| matches!(event, EndpointEvent::ConnectionClosed { .. })),
                "the peer never disconnects: {events:?}"
            );
        }
        let kept = a.connection_id(&b_peer).expect("a connected");
        assert!(
            matches!(settled, Some(ConnectOutcome::Connected { conn_id }) if *conn_id == kept),
            "connect settles on the kept connection {kept}: {a_events:?}"
        );
    }
}

type Portable<T> = PortableEndpoint<T, StdEntropy>;

#[test]
fn duplicate_quic_candidates_keep_one_shared_connection() {
    duplicate_candidates_keep_one_shared_connection(
        |key| QuicTransport::new(QuicNodeConfig::new(key.clone()), "127.0.0.1:0").expect("bind"),
        QuicTransport::local_multiaddr,
        true,
    );
}

#[cfg(feature = "tcp")]
#[test]
fn duplicate_tcp_candidates_keep_one_shared_connection() {
    duplicate_candidates_keep_one_shared_connection(
        |key| {
            let provider = minip2p_tcp::StdTcpProvider::new().expect("tcp provider");
            minip2p_tcp::TcpTransport::new(provider, key.clone(), StdEntropy)
        },
        |_| "/ip4/127.0.0.1/tcp/0".parse().expect("tcp listen address"),
        false,
    );
}

/// A dials B and B dies without closing. A new B with the same identity dials
/// A after the tie-break window, and must replace the dead connection even
/// when A is the lower peer, whose own dial would win a simultaneous dial.
fn reconnect_after_silent_death(a_is_lower: bool) {
    let (a_key, b_key) = loop {
        let (a_key, b_key) = (Ed25519Keypair::generate(), Ed25519Keypair::generate());
        if (a_key.peer_id() < b_key.peer_id()) == a_is_lower {
            break (a_key, b_key);
        }
    };
    let mut a = bind(QUIC, a_key);
    let a_addr = a.listen().expect("a listens");
    let mut b = bind(QUIC, b_key.clone());
    let b_addr = b.listen().expect("b listens");
    let (a_peer, b_peer) = (a.peer_id().clone(), b.peer_id().clone());

    a.connect(&b_addr).expect("a connects");
    let mut ignored = Vec::new();
    let deadline = Instant::now() + BACKSTOP;
    while !a.is_peer_ready(&b_peer) || !b.is_peer_ready(&a_peer) {
        assert!(Instant::now() < deadline, "first connection never ready");
        drive(&mut a, &mut ignored);
        drive(&mut b, &mut ignored);
    }
    let dead = a.connection_id(&b_peer).expect("a connected");

    // No close reaches A: its connection to B only times out much later.
    #[expect(
        clippy::mem_forget,
        reason = "dropping the endpoint would close its connections"
    )]
    std::mem::forget(b);
    let window_end = Instant::now() + PAST_TIE_BREAK_WINDOW;
    while Instant::now() < window_end {
        drive(&mut a, &mut ignored);
    }
    assert_eq!(
        a.connection_id(&b_peer),
        Some(dead),
        "still holds the dead one"
    );

    let mut b = bind(QUIC, b_key);
    b.connect(&a_addr).expect("new b connects");
    let mut a_events = Vec::new();
    let deadline = Instant::now() + BACKSTOP;
    while !b.is_peer_ready(&a_peer)
        || !a.is_peer_ready(&b_peer)
        || a.connection_id(&b_peer) == Some(dead)
    {
        assert!(
            Instant::now() < deadline,
            "new b never got in: a={a_events:?}"
        );
        drive(&mut a, &mut a_events);
        drive(&mut b, &mut ignored);
    }
    assert!(
        a_events.iter().any(|event| matches!(
            event,
            EndpointEvent::ConnectionReplaced { peer_id, old, .. } if *peer_id == b_peer && *old == dead
        )),
        "a replaces the dead connection: {a_events:?}"
    );
}

#[test]
fn reconnect_after_silent_death_replaces_when_survivor_is_lower() {
    reconnect_after_silent_death(true);
}

#[test]
fn reconnect_after_silent_death_replaces_when_survivor_is_higher() {
    reconnect_after_silent_death(false);
}
