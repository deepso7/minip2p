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
    use std::io::Write;

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
    fn stuff(peer: &mut std::net::TcpStream) -> usize {
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
