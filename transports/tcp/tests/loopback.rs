//! Drives two `TcpTransport`s over real loopback sockets.
//!
//! The virtual-link tests pin the transport's behaviour; these pin the seam
//! between it and an operating system -- partial writes, asynchronous connects,
//! readiness waits, and the addresses the kernel actually assigns.

#![cfg(feature = "std")]

use std::net::TcpListener as StdTcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use minip2p_core::{Multiaddr, PeerAddr};
use minip2p_identity::{Ed25519Keypair, PeerId};
use minip2p_platform::{Now, StdEntropy};
use minip2p_tcp::{StdTcpProvider, TcpTransport};
use minip2p_transport::{
    BlockingTransport, ConnectionId, StreamId, Transport, TransportError, TransportEvent,
    WaitOutcome,
};

type Node = TcpTransport<StdTcpProvider, StdEntropy>;

/// Long enough to absorb a loaded CI machine, short enough to fail a hang.
const PATIENCE: Duration = Duration::from_secs(20);

fn identity(seed: u8) -> Ed25519Keypair {
    Ed25519Keypair::from_secret_key_bytes([seed; 32])
}

fn node(key: Ed25519Keypair) -> Node {
    TcpTransport::new(
        StdTcpProvider::new().expect("a readiness registry"),
        key,
        StdEntropy,
    )
}

/// Polls both nodes until `done`, or panics with what it saw.
fn run_until(
    a: &mut Node,
    b: &mut Node,
    a_events: &mut Vec<TransportEvent>,
    b_events: &mut Vec<TransportEvent>,
    mut done: impl FnMut(&[TransportEvent], &[TransportEvent]) -> bool,
) {
    let start = Instant::now();
    loop {
        let now = Now::from_millis(u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX));
        a_events.extend(a.poll(now).expect("poll dialer"));
        b_events.extend(b.poll(now).expect("poll listener"));
        if done(a_events, b_events) {
            return;
        }
        assert!(
            start.elapsed() < PATIENCE,
            "timed out\n  dialer: {a_events:?}\n  listener: {b_events:?}"
        );
        // Sockets settle on their own schedule; yield rather than spin.
        thread::sleep(Duration::from_millis(1));
    }
}

/// Polls both nodes until neither has produced anything for a while.
///
/// Real sockets keep talking after the last event a test cares about -- Yamux
/// acknowledgements, window updates -- so "the assertion passed" is not the
/// same as "the wire is quiet". Anything asserting on an idle transport has to
/// establish that first.
fn settle(a: &mut Node, b: &mut Node) {
    let start = Instant::now();
    let mut quiet_rounds = 0;
    while quiet_rounds < 20 {
        let now = Now::from_millis(u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX));
        let from_a = a.poll(now).expect("poll a");
        let from_b = b.poll(now).expect("poll b");
        if from_a.is_empty() && from_b.is_empty() {
            quiet_rounds += 1;
        } else {
            quiet_rounds = 0;
        }
        assert!(start.elapsed() < PATIENCE, "the link never went quiet");
        thread::sleep(Duration::from_millis(1));
    }
}

fn connected_peer(events: &[TransportEvent]) -> Option<&PeerId> {
    events.iter().find_map(|event| match event {
        TransportEvent::Connected { endpoint, .. } => endpoint.peer_id(),
        _ => None,
    })
}

fn connection_id(events: &[TransportEvent]) -> Option<ConnectionId> {
    events.iter().find_map(|event| match event {
        TransportEvent::Connected { id, .. } => Some(*id),
        _ => None,
    })
}

fn is_connected(events: &[TransportEvent]) -> bool {
    events
        .iter()
        .any(|event| matches!(event, TransportEvent::Connected { .. }))
}

/// A listener bound to an ephemeral loopback port, and a dialer aimed at it.
struct Pair {
    dialer: Node,
    listener: Node,
    dialer_peer: PeerId,
    listener_peer: PeerId,
    dialer_events: Vec<TransportEvent>,
    listener_events: Vec<TransportEvent>,
    dialer_connection: ConnectionId,
    listener_connection: ConnectionId,
}

fn upgraded_pair() -> Pair {
    let dialer_key = identity(1);
    let listener_key = identity(2);
    let (dialer_peer, listener_peer) = (dialer_key.peer_id(), listener_key.peer_id());
    let mut dialer = node(dialer_key);
    let mut listener = node(listener_key);

    // Port 0 lets the kernel choose, and the bound address comes back concrete.
    let bound = listener
        .listen(&"/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>().expect("addr"))
        .expect("listener binds");
    assert!(bound.is_tcp_transport(), "unexpected bind address: {bound}");
    assert_ne!(
        bound.to_string(),
        "/ip4/127.0.0.1/tcp/0",
        "the kernel's chosen port must be reported back"
    );

    let target = PeerAddr::new(bound, listener_peer.clone()).expect("dial target");
    let dialer_connection = dialer.dial(&target).expect("dial starts");

    let mut dialer_events = Vec::new();
    let mut listener_events = Vec::new();
    run_until(
        &mut dialer,
        &mut listener,
        &mut dialer_events,
        &mut listener_events,
        |a, b| is_connected(a) && is_connected(b),
    );
    let listener_connection = connection_id(&listener_events).expect("listener connected");

    Pair {
        dialer,
        listener,
        dialer_peer,
        listener_peer,
        dialer_events,
        listener_events,
        dialer_connection,
        listener_connection,
    }
}

#[test]
fn two_nodes_upgrade_over_loopback_and_authenticate_each_other() {
    let pair = upgraded_pair();

    assert_eq!(
        connected_peer(&pair.dialer_events),
        Some(&pair.listener_peer)
    );
    assert_eq!(
        connected_peer(&pair.listener_events),
        Some(&pair.dialer_peer)
    );

    // The listener learns the dialer's ephemeral source port from the kernel.
    let inbound = pair.listener.active_inbound_connection_sources();
    assert_eq!(inbound.len(), 1);
    assert!(
        inbound[0].is_tcp_transport(),
        "unexpected inbound source: {inbound:?}"
    );
    assert!(
        pair.dialer.active_inbound_connection_sources().is_empty(),
        "a dialed connection is not an inbound source"
    );
}

#[test]
fn a_payload_larger_than_the_socket_buffer_arrives_intact() {
    let mut pair = upgraded_pair();
    let id = pair.dialer_connection;
    let stream = pair.dialer.open_stream(id).expect("open substream");

    // Comfortably past a loopback send buffer, so the kernel refuses part of it
    // and the transport has to carry the remainder across several polls.
    let payload: Vec<u8> = (0..512 * 1024u32).map(|byte| byte as u8).collect();
    pair.dialer
        .send_stream(id, stream, payload.clone())
        .expect("queue the payload");

    let mut received = Vec::new();
    run_until(
        &mut pair.dialer,
        &mut pair.listener,
        &mut pair.dialer_events,
        &mut pair.listener_events,
        |_, listener| {
            received = listener
                .iter()
                .filter_map(|event| match event {
                    TransportEvent::StreamData { data, .. } => Some(data.clone()),
                    _ => None,
                })
                .flatten()
                .collect();
            received.len() >= payload.len()
        },
    );
    assert_eq!(received, payload, "every byte, once, in order");
}

#[test]
fn substreams_carry_data_in_both_directions() {
    let mut pair = upgraded_pair();
    let dialer_id = pair.dialer_connection;
    let listener_id = pair.listener_connection;
    let stream = pair.dialer.open_stream(dialer_id).expect("open substream");
    pair.dialer
        .send_stream(dialer_id, stream, b"ping".to_vec())
        .expect("send");

    run_until(
        &mut pair.dialer,
        &mut pair.listener,
        &mut pair.dialer_events,
        &mut pair.listener_events,
        |_, listener| {
            listener.iter().any(
                |event| matches!(event, TransportEvent::StreamData { data, .. } if data == b"ping"),
            )
        },
    );

    pair.listener
        .send_stream(listener_id, stream, b"pong".to_vec())
        .expect("reply");
    run_until(
        &mut pair.dialer,
        &mut pair.listener,
        &mut pair.dialer_events,
        &mut pair.listener_events,
        |dialer, _| {
            dialer.iter().any(
                |event| matches!(event, TransportEvent::StreamData { data, .. } if data == b"pong"),
            )
        },
    );

    // A half-close leaves the reverse direction usable.
    pair.dialer
        .close_stream_write(dialer_id, stream)
        .expect("FIN");
    run_until(
        &mut pair.dialer,
        &mut pair.listener,
        &mut pair.dialer_events,
        &mut pair.listener_events,
        |_, listener| {
            listener
                .iter()
                .any(|event| matches!(event, TransportEvent::StreamRemoteWriteClosed { .. }))
        },
    );
}

#[test]
fn closing_a_connection_reaches_the_peer() {
    let mut pair = upgraded_pair();
    pair.dialer
        .close(pair.dialer_connection)
        .expect("graceful close");

    let listener_id = pair.listener_connection;
    run_until(
        &mut pair.dialer,
        &mut pair.listener,
        &mut pair.dialer_events,
        &mut pair.listener_events,
        |_, listener| {
            listener
                .iter()
                .any(|event| matches!(event, TransportEvent::Closed { id } if *id == listener_id))
        },
    );
    assert!(pair.dialer.connection_ids().is_empty());
    assert!(pair.listener.connection_ids().is_empty());
}

#[test]
fn a_refused_connect_is_reported_and_closed() {
    // Bind and drop, so the port is almost certainly unused and definitely not
    // listening.
    let probe = StdTcpListener::bind("127.0.0.1:0").expect("probe binds");
    let dead = probe.local_addr().expect("probe address");
    drop(probe);

    let listener_key = identity(2);
    let mut dialer = node(identity(1));
    let mut idle = node(identity(3));
    let target = PeerAddr::new(
        format!("/ip4/127.0.0.1/tcp/{}", dead.port())
            .parse()
            .expect("addr"),
        listener_key.peer_id(),
    )
    .expect("dial target");

    let id = dialer.dial(&target).expect("the dial starts");
    let mut dialer_events = Vec::new();
    let mut idle_events = Vec::new();
    run_until(
        &mut dialer,
        &mut idle,
        &mut dialer_events,
        &mut idle_events,
        |a, _| {
            a.iter()
                .any(|event| matches!(event, TransportEvent::Closed { .. }))
        },
    );

    assert!(
        dialer_events.iter().any(
            |event| matches!(event, TransportEvent::Error { id: failed, .. } if *failed == id)
        ),
        "a refused connect must say why: {dialer_events:?}"
    );
    assert!(
        !dialer_events.iter().any(is_connected_event),
        "a refused connect must never report Connected: {dialer_events:?}"
    );
    assert!(dialer.connection_ids().is_empty());
}

fn is_connected_event(event: &TransportEvent) -> bool {
    matches!(event, TransportEvent::Connected { .. })
}

#[test]
fn listening_needs_a_concrete_host_but_dialing_may_use_a_name() {
    let mut transport = node(identity(1));
    assert!(matches!(
        transport.listen(&"/dns/localhost/tcp/0".parse().expect("addr")),
        Err(TransportError::ListenFailed { .. })
    ));

    // The name resolves, so the dial gets as far as opening a socket; whether
    // anything answers is beside the point here.
    let target = PeerAddr::new(
        "/dns/localhost/tcp/1".parse().expect("addr"),
        identity(2).peer_id(),
    )
    .expect("dial target");
    assert!(
        transport.dial(&target).is_ok(),
        "a resolvable name must be dialable"
    );
}

#[test]
fn an_idle_wait_times_out_and_input_wakes_it() {
    let mut pair = upgraded_pair();
    let dialer_id = pair.dialer_connection;
    let listener_id = pair.listener_connection;
    let stream = pair.dialer.open_stream(dialer_id).expect("open substream");
    run_until(
        &mut pair.dialer,
        &mut pair.listener,
        &mut pair.dialer_events,
        &mut pair.listener_events,
        |_, listener| {
            listener
                .iter()
                .any(|event| matches!(event, TransportEvent::IncomingStream { .. }))
        },
    );

    settle(&mut pair.dialer, &mut pair.listener);

    // Nothing is in flight now, so the dialer's wait must run its full budget
    // rather than return spuriously.
    let started = Instant::now();
    let outcome = pair.dialer.wait_for_input(Duration::from_millis(150));
    assert_eq!(outcome, WaitOutcome::TimedOut);
    assert!(
        started.elapsed() >= Duration::from_millis(120),
        "an idle wait must actually sleep, took {:?}",
        started.elapsed()
    );

    // Now the peer writes, and the same wait returns early with the data.
    pair.listener
        .send_stream(listener_id, stream, b"wake up".to_vec())
        .expect("send");
    let _ = pair.listener.poll(Now::from_millis(0)).expect("flush");
    assert_eq!(
        pair.dialer.wait_for_input(PATIENCE),
        WaitOutcome::Ready,
        "arriving data must end the wait"
    );
    assert!(
        pair.dialer
            .poll(Now::from_millis(0))
            .expect("poll")
            .iter()
            .any(|event| matches!(
                event,
                TransportEvent::StreamData { data, .. } if data == b"wake up"
            )),
        "the wait must not have consumed the input"
    );
}

#[test]
fn a_drained_socket_wakes_a_driver_waiting_to_write() {
    let mut pair = upgraded_pair();
    let id = pair.dialer_connection;
    let stream = pair.dialer.open_stream(id).expect("open substream");
    settle(&mut pair.dialer, &mut pair.listener);

    // Fill the socket without the peer reading, so the write is refused and the
    // remainder sits in the transport's buffer.
    let payload = vec![7u8; 512 * 1024];
    pair.dialer
        .send_stream(id, stream, payload)
        .expect("queue more than the socket will take");
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(200) {
        let _ = pair.dialer.poll(Now::from_millis(0)).expect("poll dialer");
        thread::sleep(Duration::from_millis(1));
    }

    // Nothing to read and nowhere to write: the driver has to park.
    assert_eq!(
        pair.dialer.wait_for_input(Duration::from_millis(100)),
        WaitOutcome::TimedOut,
        "a full socket with an idle peer is nothing to wake for"
    );

    // The peer now reads, and the dialer must wake promptly rather than sleep
    // out its budget. Which readiness does it -- the socket having room again,
    // or the peer's Yamux acknowledgement arriving -- is not pinned here;
    // loopback buffering makes a socket that stays full unreliable to arrange.
    let _ = pair.listener.poll(Now::from_millis(0)).expect("peer reads");
    let began = Instant::now();
    assert_eq!(
        pair.dialer.wait_for_input(PATIENCE),
        WaitOutcome::Ready,
        "a drained socket must wake the writer"
    );
    assert!(
        began.elapsed() < Duration::from_secs(5),
        "the wake took {:?}",
        began.elapsed()
    );
}

#[test]
fn a_wait_handle_interrupts_a_blocked_wait() {
    let mut pair = upgraded_pair();
    let handle = pair.dialer.wait_handle();
    assert!(
        !handle.is_noop(),
        "a socket-backed transport must offer a real handle"
    );

    let (started, wait_started) = mpsc::channel();
    thread::spawn(move || {
        // Wait for the main thread to be inside its wait before nudging it.
        wait_started.recv().expect("the waiter starts");
        thread::sleep(Duration::from_millis(50));
        handle.interrupt();
    });

    started.send(()).expect("signal the interrupter");
    let began = Instant::now();
    let outcome = pair.dialer.wait_for_input(PATIENCE);

    assert_eq!(outcome, WaitOutcome::Interrupted);
    assert!(
        began.elapsed() < PATIENCE,
        "the interrupt must cut the wait short"
    );
}

#[test]
fn queued_events_are_never_slept_through() {
    let mut pair = upgraded_pair();
    let id = pair.dialer_connection;
    // `open_stream` queues `StreamOpened`, which a driver must see before it
    // parks on the socket.
    let _ = pair.dialer.open_stream(id).expect("open substream");

    let began = Instant::now();
    assert_eq!(
        pair.dialer.wait_for_input(PATIENCE),
        WaitOutcome::Ready,
        "a queued event must short-circuit the wait"
    );
    assert!(began.elapsed() < Duration::from_secs(1));
    assert!(matches!(
        pair.dialer
            .poll(Now::from_millis(0))
            .expect("poll")
            .as_slice(),
        [TransportEvent::StreamOpened { stream_id, .. }] if *stream_id == StreamId::new(1)
    ));
}
