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

use minip2p_core::{Multiaddr, PeerAddr, Protocol};
use minip2p_identity::{Ed25519Keypair, PeerId};
use minip2p_platform::{Now, StdEntropy};
use minip2p_tcp::{StdTcpProvider, TcpProvider, TcpTransport};
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
fn ipv4_and_ipv6_wildcard_listeners_can_share_a_port() {
    let mut provider = StdTcpProvider::new().expect("a readiness registry");
    let ipv4 = provider
        .listen(&"/ip4/0.0.0.0/tcp/0".parse().expect("IPv4 wildcard"))
        .expect("the IPv4 wildcard binds");
    let port = match ipv4.protocols().get(1) {
        Some(Protocol::Tcp(port)) => *port,
        protocols => panic!("bound address has no TCP port: {protocols:?}"),
    };
    let ipv6 = format!("/ip6/::/tcp/{port}")
        .parse()
        .expect("IPv6 wildcard");

    provider
        .listen(&ipv6)
        .expect("separate IPv4 and IPv6 wildcard listeners share a port");
    assert_eq!(provider.local_addresses(), vec![ipv4, ipv6]);
}

#[test]
fn listening_again_on_a_bound_address_is_the_same_listener() {
    let mut transport = node(identity(1));
    let bound = transport
        .listen(&"/ip4/127.0.0.1/tcp/0".parse().expect("addr"))
        .expect("the first listen binds");
    let mut events = transport.poll(Now::from_millis(0)).expect("poll");

    // Hosts bind first and then listen on what they bound -- the swarm's own
    // bind-then-listen does exactly that -- so the second call names a socket
    // this transport already owns. Binding a fresh one there would fail with
    // the address in use, on a request that had already been granted.
    for _ in 0..3 {
        transport
            .listen(&bound)
            .expect("listening again is not a second listener");
    }
    assert_eq!(
        transport.local_addresses(),
        vec![bound.clone()],
        "one address, one listener, however many times it was asked for"
    );

    // And announced once. Repeating it would have every re-listen add an event
    // the host has already seen, growing the queue for as long as a caller
    // keeps asking.
    events.extend(transport.poll(Now::from_millis(1)).expect("poll"));
    let announced: Vec<&TransportEvent> = events
        .iter()
        .filter(|event| matches!(event, TransportEvent::Listening { .. }))
        .collect();
    assert_eq!(
        announced,
        vec![&TransportEvent::Listening { addr: bound }],
        "the address is announced when it is bound, and not again"
    );
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
fn a_driver_with_buffered_writes_wakes_when_the_peer_acts() {
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

    // The peer now acts, and the dialer must wake promptly rather than sleep out
    // its budget. Which readiness does it -- the socket having room again, or
    // the peer's Yamux acknowledgement arriving -- is deliberately not claimed:
    // loopback buffering makes a socket that stays full unreliable to arrange,
    // so writability cannot be isolated from the bytes coming back.
    // One poll only takes a bounded bite, so keep the peer reading until it has
    // actually consumed enough to matter.
    let draining = Instant::now();
    while draining.elapsed() < Duration::from_millis(200) {
        let _ = pair.listener.poll(Now::from_millis(0)).expect("peer reads");
        thread::sleep(Duration::from_millis(1));
    }
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

/// Tests that drive `StdTcpProvider` directly.
///
/// Some of what a provider owes its caller cannot be seen through a
/// `TcpTransport`: an orderly shutdown of both halves, an interrupt that lands
/// between waits, and the shape of the addresses it will accept.
mod provider {
    use super::*;
    use minip2p_tcp::{BlockingTcpProvider, SocketHandle, TcpError, TcpEvent, TcpProvider};
    use std::io::Read;

    /// Polls both providers until `found` matches, collecting everything seen.
    fn pump_until(
        a: &mut StdTcpProvider,
        b: &mut StdTcpProvider,
        a_seen: &mut Vec<TcpEvent>,
        b_seen: &mut Vec<TcpEvent>,
        mut found: impl FnMut(&[TcpEvent], &[TcpEvent]) -> bool,
    ) {
        let start = Instant::now();
        loop {
            a_seen.extend(a.poll(Now::from_millis(0)).expect("poll a"));
            b_seen.extend(b.poll(Now::from_millis(0)).expect("poll b"));
            if found(a_seen, b_seen) {
                return;
            }
            assert!(
                start.elapsed() < PATIENCE,
                "timed out\n  a: {a_seen:?}\n  b: {b_seen:?}"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    /// Connects two providers, returning both ends of the stream.
    fn linked() -> (StdTcpProvider, SocketHandle, StdTcpProvider, SocketHandle) {
        let mut server = StdTcpProvider::new().expect("server");
        let mut client = StdTcpProvider::new().expect("client");
        let bound = server
            .listen(&"/ip4/127.0.0.1/tcp/0".parse().expect("addr"))
            .expect("bind");
        let outbound = client.connect(&bound).expect("connect starts");

        let (mut server_seen, mut client_seen) = (Vec::new(), Vec::new());
        pump_until(
            &mut server,
            &mut client,
            &mut server_seen,
            &mut client_seen,
            |server, client| {
                server
                    .iter()
                    .any(|event| matches!(event, TcpEvent::Accepted { .. }))
                    && client
                        .iter()
                        .any(|event| matches!(event, TcpEvent::Connected { .. }))
            },
        );
        let accepted = server_seen
            .iter()
            .find_map(|event| match event {
                TcpEvent::Accepted { socket, .. } => Some(*socket),
                _ => None,
            })
            .expect("accepted");
        (server, accepted, client, outbound)
    }

    #[test]
    fn a_connecting_socket_accepts_no_bytes_before_connected() {
        let mut server = StdTcpProvider::new().expect("server");
        let mut client = StdTcpProvider::new().expect("client");
        let bound = server
            .listen(&"/ip4/127.0.0.1/tcp/0".parse().expect("addr"))
            .expect("bind");
        let outbound = client.connect(&bound).expect("connect starts");

        assert_eq!(
            client.send(outbound, b"too early").expect("short write"),
            0,
            "the provider must preserve the Connected gate even if the kernel connected quickly"
        );

        let (mut server_seen, mut client_seen) = (Vec::new(), Vec::new());
        pump_until(
            &mut server,
            &mut client,
            &mut server_seen,
            &mut client_seen,
            |server, client| {
                server
                    .iter()
                    .any(|event| matches!(event, TcpEvent::Accepted { .. }))
                    && client
                        .iter()
                        .any(|event| matches!(event, TcpEvent::Connected { .. }))
            },
        );
        assert!(
            !server_seen
                .iter()
                .any(|event| matches!(event, TcpEvent::Received { .. })),
            "a pre-Connected send must not reach the peer"
        );
    }

    #[test]
    fn a_queued_close_prevents_waiting() {
        let (mut server, server_socket, mut client, client_socket) = linked();
        server.close_write(server_socket).expect("server FIN");

        let (mut server_seen, mut client_seen) = (Vec::new(), Vec::new());
        pump_until(
            &mut server,
            &mut client,
            &mut server_seen,
            &mut client_seen,
            |_, client| {
                client
                    .iter()
                    .any(|event| matches!(event, TcpEvent::RemoteWriteClosed { .. }))
            },
        );
        client_seen.clear();

        // With the peer FIN already consumed, this retires the socket and
        // queues Closed synchronously. A blocking driver must poll it rather
        // than park waiting for readiness that will never come.
        client.close_write(client_socket).expect("client FIN");
        assert_eq!(
            client.wait_for_input(PATIENCE),
            WaitOutcome::Ready,
            "a queued terminal event is immediate work"
        );
        assert!(matches!(
            client.poll(Now::from_millis(0)).expect("poll").as_slice(),
            [TcpEvent::Closed { socket, .. }] if *socket == client_socket
        ));
    }

    #[test]
    fn a_stream_closed_from_both_ends_is_retired() {
        let (mut server, server_socket, mut client, client_socket) = linked();

        // Each side shuts its write half. Once a socket has read the peer's FIN
        // and shut its own, nothing can arrive on it again -- so the provider
        // has to let go of the descriptor rather than hold it for a caller that
        // has already been told the stream ended.
        client.close_write(client_socket).expect("client FIN");
        let (mut server_seen, mut client_seen) = (Vec::new(), Vec::new());
        pump_until(
            &mut server,
            &mut client,
            &mut server_seen,
            &mut client_seen,
            |server, _| {
                server
                    .iter()
                    .any(|event| matches!(event, TcpEvent::RemoteWriteClosed { .. }))
            },
        );

        server.close_write(server_socket).expect("server FIN");
        pump_until(
            &mut server,
            &mut client,
            &mut server_seen,
            &mut client_seen,
            |server, client| {
                server
                    .iter()
                    .any(|event| matches!(event, TcpEvent::Closed { .. }))
                    && client
                        .iter()
                        .any(|event| matches!(event, TcpEvent::Closed { .. }))
            },
        );

        // Both retirements are orderly, not faults.
        for seen in [&server_seen, &client_seen] {
            assert!(
                seen.iter()
                    .any(|event| matches!(event, TcpEvent::Closed { reason: None, .. })),
                "an orderly shutdown must not be reported as a failure: {seen:?}"
            );
        }
    }

    #[test]
    fn an_interrupt_absorbed_by_a_poll_is_not_lost() {
        let (mut server, _server_socket, mut client, _client_socket) = linked();

        // Nudge the client while nobody is waiting, then poll -- which is what
        // absorbs the wake. The next wait still has to honour it, or a handle
        // could lose its wakeup to that race.
        client.wait_handle().interrupt();
        let _ = client.poll(Now::from_millis(0)).expect("poll absorbs it");
        let _ = server
            .poll(Now::from_millis(0))
            .expect("keep the peer quiet");

        let began = Instant::now();
        assert_eq!(
            client.wait_for_input(Duration::from_secs(5)),
            WaitOutcome::Interrupted,
            "an interrupt absorbed by a poll must still end the next wait"
        );
        assert!(began.elapsed() < Duration::from_secs(5));

        // And it is consumed, not sticky.
        assert_eq!(
            client.wait_for_input(Duration::from_millis(50)),
            WaitOutcome::TimedOut,
            "the interrupt must not fire twice"
        );
    }

    #[test]
    fn bytes_already_delivered_survive_the_retirement_that_follows() {
        let (mut server, server_socket, mut client, client_socket) = linked();

        // The server has already finished writing, so the client's FIN is the
        // last thing the socket is waiting on: reading it retires the stream in
        // the same pass that delivered the bytes ahead of it.
        server.close_write(server_socket).expect("server FIN");
        let payload = b"the last thing said".to_vec();
        let mut offset = 0;
        while offset < payload.len() {
            offset += client
                .send(client_socket, &payload[offset..])
                .expect("send");
        }
        client.close_write(client_socket).expect("client FIN");

        let (mut server_seen, mut client_seen) = (Vec::new(), Vec::new());
        pump_until(
            &mut server,
            &mut client,
            &mut server_seen,
            &mut client_seen,
            |server, _| {
                server
                    .iter()
                    .any(|event| matches!(event, TcpEvent::Closed { .. }))
            },
        );

        let received: Vec<u8> = server_seen
            .iter()
            .filter_map(|event| match event {
                TcpEvent::Received { data, .. } => Some(data.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(
            received, payload,
            "a stream that ends still handed over what it delivered: {server_seen:?}"
        );

        let position = |wanted: fn(&TcpEvent) -> bool| {
            server_seen
                .iter()
                .position(&wanted)
                .unwrap_or_else(|| panic!("missing event in {server_seen:?}"))
        };
        let data = position(|event| matches!(event, TcpEvent::Received { .. }));
        let fin = position(|event| matches!(event, TcpEvent::RemoteWriteClosed { .. }));
        let closed = position(|event| matches!(event, TcpEvent::Closed { .. }));
        assert!(data < fin && fin < closed, "out of order: {server_seen:?}");
    }

    /// Fills a socket's buffers without reading, and reports how much went in.
    #[cfg(target_os = "linux")]
    fn stuff(peer: &mut std::net::TcpStream) -> usize {
        use std::io::Write as _;

        peer.set_nonblocking(true).expect("non-blocking");
        let chunk = vec![0u8; 64 * 1024];
        let mut total = 0;
        loop {
            match peer.write(&chunk) {
                Ok(0) => break,
                Ok(written) => total += written,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        total
    }

    // This test needs the loopback send buffer to exceed the provider's fixed
    // 128 KiB read budget. Linux guarantees that in the CI configurations we
    // exercise; default buffers on macOS and Windows can be smaller, which
    // would test an OS tuning choice rather than provider fairness.
    #[cfg(target_os = "linux")]
    #[test]
    fn one_busy_socket_cannot_monopolise_a_poll() {
        let mut server = StdTcpProvider::new().expect("server");
        let bound = server
            .listen(&"/ip4/127.0.0.1/tcp/0".parse().expect("addr"))
            .expect("bind");
        let port = bound
            .to_string()
            .rsplit('/')
            .next()
            .expect("port")
            .to_string();
        let mut peer = std::net::TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");

        let start = Instant::now();
        while server
            .poll(Now::from_millis(0))
            .expect("poll")
            .iter()
            .all(|event| !matches!(event, TcpEvent::Accepted { .. }))
        {
            assert!(
                start.elapsed() < PATIENCE,
                "the connection was never accepted"
            );
            thread::sleep(Duration::from_millis(1));
        }

        // The peer writes as much as the kernel will hold and then stops, so
        // nothing further will announce itself: whatever the provider does not
        // take now has to be remembered rather than waited for.
        let buffered = stuff(&mut peer);
        assert!(
            buffered > 128 * 1024,
            "the kernel held only {buffered} bytes, too little to outlast one poll's budget"
        );
        thread::sleep(Duration::from_millis(50));

        let batch = server.poll(Now::from_millis(0)).expect("poll");
        let taken: usize = batch
            .iter()
            .map(|event| match event {
                TcpEvent::Received { data, .. } => data.len(),
                _ => 0,
            })
            .sum();
        assert!(taken > 0, "the poll must make progress");
        assert!(
            taken <= 128 * 1024,
            "one poll took {taken} bytes, past its budget"
        );
        assert!(taken < buffered, "the budget must actually have bitten");

        // Readiness has nothing left to say, so a driver that parked here would
        // strand the remainder.
        assert_eq!(
            server.wait_for_input(Duration::from_secs(5)),
            WaitOutcome::Ready,
            "work held back by the budget must not be slept through"
        );

        // And the rest arrives on the polls that follow.
        let mut rest = 0;
        while rest + taken < buffered {
            let more: usize = server
                .poll(Now::from_millis(0))
                .expect("poll")
                .iter()
                .map(|event| match event {
                    TcpEvent::Received { data, .. } => data.len(),
                    _ => 0,
                })
                .sum();
            rest += more;
            assert!(start.elapsed() < PATIENCE, "the remainder never arrived");
        }
    }

    #[test]
    fn a_burst_of_connections_cannot_monopolise_a_poll() {
        let mut server = StdTcpProvider::new().expect("server");
        let bound = server
            .listen(&"/ip4/127.0.0.1/tcp/0".parse().expect("addr"))
            .expect("bind");
        let port = bound
            .to_string()
            .rsplit('/')
            .next()
            .expect("port")
            .to_string();

        // One more than a poll will take, so the backlog has to outlive it.
        let burst = 40;
        let peers: Vec<_> = (0..burst)
            .map(|_| std::net::TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect"))
            .collect();
        thread::sleep(Duration::from_millis(100));

        let accepted = server
            .poll(Now::from_millis(0))
            .expect("poll")
            .iter()
            .filter(|event| matches!(event, TcpEvent::Accepted { .. }))
            .count();
        assert!(accepted > 0, "the poll must make progress");
        assert!(
            accepted <= 32,
            "one poll accepted {accepted} connections, past its budget"
        );
        assert_eq!(
            server.wait_for_input(Duration::from_secs(5)),
            WaitOutcome::Ready,
            "a backlog held back by the budget must not be slept through"
        );
        drop(peers);
    }

    /// The port of a bound `/ipX/tcp/port` address.
    fn port_of(addr: &Multiaddr) -> u16 {
        addr.to_string()
            .rsplit('/')
            .next()
            .expect("port")
            .parse()
            .expect("a numeric port")
    }

    /// Counts the connections one poll accepted.
    fn accepted_in(provider: &mut StdTcpProvider) -> usize {
        provider
            .poll(Now::from_millis(0))
            .expect("poll")
            .iter()
            .filter(|event| matches!(event, TcpEvent::Accepted { .. }))
            .count()
    }

    /// Whether the far side has closed this connection.
    ///
    /// The server under test never writes, so anything other than `WouldBlock`
    /// means the connection ended rather than that bytes arrived.
    fn peer_saw_the_end(peer: &mut std::net::TcpStream) -> bool {
        peer.set_nonblocking(true).expect("non-blocking");
        let mut byte = [0u8; 1];
        match peer.read(&mut byte) {
            Ok(0) => true,
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(_) => true,
        }
    }

    #[test]
    fn a_connection_past_the_accept_budget_is_deferred_not_dropped() {
        let mut server = StdTcpProvider::new().expect("server");
        let bound = server
            .listen(&"/ip4/127.0.0.1/tcp/0".parse().expect("addr"))
            .expect("bind");
        let target = format!("127.0.0.1:{}", port_of(&bound));

        // More than one poll's budget, so the backlog has to outlive the poll
        // that fills it.
        let burst = 40;
        let mut peers: Vec<std::net::TcpStream> = (0..burst)
            .map(|_| std::net::TcpStream::connect(&target).expect("connect"))
            .collect();
        thread::sleep(Duration::from_millis(200));

        let first = accepted_in(&mut server);
        assert_eq!(
            first, 32,
            "the budget has to have bitten for this test to prove anything"
        );

        // What the budget held back is still queued. A connection taken off the
        // kernel's queue and then dropped is one peer's dial killed for
        // somebody else's flood, which is not what deferring work means.
        thread::sleep(Duration::from_millis(50));
        for (index, peer) in peers.iter_mut().enumerate() {
            assert!(
                !peer_saw_the_end(peer),
                "peer {index} had its connection torn down rather than deferred"
            );
        }

        let start = Instant::now();
        let mut total = first;
        while total < burst {
            total += accepted_in(&mut server);
            assert!(
                start.elapsed() < PATIENCE,
                "only {total} of {burst} connections were ever accepted"
            );
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(total, burst, "every queued connection is owed an accept");
    }

    #[test]
    fn a_flooded_listener_cannot_starve_a_later_bind() {
        let mut server = StdTcpProvider::new().expect("server");
        // Bound first, so it is the one a naive walk over the listeners always
        // reaches first.
        let busy = server
            .listen(&"/ip4/127.0.0.1/tcp/0".parse().expect("addr"))
            .expect("bind the busy listener");
        let quiet = server
            .listen(&"/ip4/127.0.0.1/tcp/0".parse().expect("addr"))
            .expect("bind the quiet listener");
        let busy_target = format!("127.0.0.1:{}", port_of(&busy));

        // One lonely dial at the listener that bound second. The kernel tells
        // the server which ephemeral port it came from, which is how the
        // accepted connection is recognised.
        let lonely = std::net::TcpStream::connect(format!("127.0.0.1:{}", port_of(&quiet)))
            .expect("dial the quiet listener");
        let lonely_source = format!("/tcp/{}", lonely.local_addr().expect("local addr").port());

        let mut served = false;
        for _ in 0..6 {
            // Replenish the busy listener past a whole poll's budget every
            // round, so it never stops being a flood. The client ends are let
            // go of immediately: the handshake is complete, so the connection
            // sits in the kernel's accept queue regardless, and holding 240
            // sockets open would only risk the process's descriptor limit.
            for _ in 0..40 {
                let _ = std::net::TcpStream::connect(&busy_target).expect("flood connect");
            }
            thread::sleep(Duration::from_millis(50));

            let batch = server.poll(Now::from_millis(0)).expect("poll");
            served = batch.iter().any(|event| {
                matches!(event, TcpEvent::Accepted { remote, .. }
                    if remote.to_string().ends_with(&lonely_source))
            });
            if served {
                break;
            }
            // Let go of the flood, so a starvation test cannot itself run out
            // of descriptors.
            for event in &batch {
                if let TcpEvent::Accepted { socket, .. } = event {
                    server.abort(*socket);
                }
            }
        }

        assert!(
            served,
            "a listener bound after a flooded one was never given a turn"
        );
        drop(lonely);
    }

    #[test]
    fn an_aborted_stream_is_never_mentioned_again_but_the_peer_still_finds_out() {
        let (mut server, server_socket, mut client, client_socket) = linked();

        // Something in flight, so this is a teardown mid-conversation rather
        // than an idle handle being tidied away.
        client.send(client_socket, b"never mind").expect("send");
        client.abort(client_socket);

        let (mut server_seen, mut client_seen) = (Vec::new(), Vec::new());
        pump_until(
            &mut server,
            &mut client,
            &mut server_seen,
            &mut client_seen,
            |server, _| {
                server.iter().any(|event| {
                    matches!(
                        event,
                        TcpEvent::RemoteWriteClosed { .. } | TcpEvent::Closed { .. }
                    )
                })
            },
        );
        // Give a late event somewhere to turn up before claiming there is none.
        for _ in 0..50 {
            client_seen.extend(client.poll(Now::from_millis(0)).expect("poll client"));
            server_seen.extend(server.poll(Now::from_millis(0)).expect("poll server"));
            thread::sleep(Duration::from_millis(1));
        }

        assert!(
            client_seen.is_empty(),
            "an aborted handle is owed nothing further, got {client_seen:?}"
        );

        // The teardown still has to reach the peer, or an abort is a leak on
        // the other end rather than a close.
        assert!(
            server_seen.iter().any(|event| matches!(
                event,
                TcpEvent::RemoteWriteClosed { socket } if *socket == server_socket
            )),
            "the peer must observe the stream ending: {server_seen:?}"
        );

        // And the peer's own half then retires normally, so nothing is left
        // holding a descriptor for a stream that is gone.
        server.close_write(server_socket).expect("peer FIN");
        pump_until(
            &mut server,
            &mut client,
            &mut server_seen,
            &mut client_seen,
            |server, _| {
                server.iter().any(
                    |event| matches!(event, TcpEvent::Closed { socket, .. } if *socket == server_socket),
                )
            },
        );
        let error = server
            .send(server_socket, b"gone")
            .expect_err("a retired handle takes nothing");
        assert!(error.to_string().contains("is not open"), "got {error}");
    }

    #[test]
    fn an_abort_that_races_a_retirement_discards_it_too() {
        let (mut server, server_socket, mut client, client_socket) = linked();

        // The peer finishes first, so the client's own `close_write` is what
        // retires the stream -- queueing a `Closed` the caller has not
        // collected yet.
        server.close_write(server_socket).expect("peer FIN");
        let (mut server_seen, mut client_seen) = (Vec::new(), Vec::new());
        pump_until(
            &mut server,
            &mut client,
            &mut server_seen,
            &mut client_seen,
            |_, client| {
                client
                    .iter()
                    .any(|event| matches!(event, TcpEvent::RemoteWriteClosed { .. }))
            },
        );
        client.close_write(client_socket).expect("client FIN");

        // The caller aborts before collecting that retirement. It asked for the
        // teardown, so it is owed no report of it -- including one already
        // sitting in the queue.
        client.abort(client_socket);
        let after = client.poll(Now::from_millis(0)).expect("poll");
        assert!(
            after.is_empty(),
            "an aborted handle is owed nothing further, got {after:?}"
        );
    }

    #[test]
    fn a_dns4_dial_reaches_an_ipv4_address() {
        let mut server = StdTcpProvider::new().expect("server");
        let mut client = StdTcpProvider::new().expect("client");
        let bound = server
            .listen(&"/ip4/127.0.0.1/tcp/0".parse().expect("addr"))
            .expect("bind");
        let port = bound
            .to_string()
            .rsplit('/')
            .next()
            .expect("port")
            .to_string();

        let named: Multiaddr = format!("/dns4/localhost/tcp/{port}").parse().expect("addr");
        let _ = client
            .connect(&named)
            .expect("a dns4 name resolves and dials");

        let (mut server_seen, mut client_seen) = (Vec::new(), Vec::new());
        pump_until(
            &mut server,
            &mut client,
            &mut server_seen,
            &mut client_seen,
            |_, client| {
                client
                    .iter()
                    .any(|event| matches!(event, TcpEvent::Connected { .. }))
            },
        );

        let reached = client_seen
            .iter()
            .find_map(|event| match event {
                TcpEvent::Connected { remote, .. } => Some(remote.clone()),
                _ => None,
            })
            .expect("connected");
        // The filter is the point: `/dns4` must not settle on a v6 answer.
        assert!(
            reached.to_string().starts_with("/ip4/"),
            "a /dns4 dial must reach an IPv4 address, got {reached}"
        );
    }

    #[test]
    fn addresses_must_be_a_bare_host_and_port() {
        let mut provider = StdTcpProvider::new().expect("provider");
        // A trailing component means the address is not this provider's to
        // dial; connecting anyway would reach somewhere the caller did not ask
        // for.
        let suffixed: Multiaddr =
            "/ip4/127.0.0.1/tcp/1/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"
                .parse()
                .expect("addr");
        assert!(matches!(
            provider.connect(&suffixed),
            Err(TcpError::Address { .. })
        ));
        assert!(matches!(
            provider.listen(&suffixed),
            Err(TcpError::Address { .. })
        ));

        // A bare host with no port is equally not dialable.
        assert!(matches!(
            provider.connect(&"/ip4/127.0.0.1".parse().expect("addr")),
            Err(TcpError::Address { .. })
        ));
    }
}
