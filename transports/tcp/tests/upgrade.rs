//! Drives two `TcpTransport`s against each other over a virtual link.
//!
//! Everything here is asserted through the public
//! [`Transport`](minip2p_transport::Transport) contract, which is what a swarm
//! actually sees, rather than through the transport's internals.

mod support;

use minip2p_core::{Multiaddr, PeerAddr};
use minip2p_identity::{Ed25519Keypair, PeerId};
use minip2p_platform::{Deadline, EntropySource, Now};
use minip2p_tcp::{TcpConfig, TcpTransport};
use minip2p_transport::{
    ConnectionId, ConnectionNamespace, StreamId, Transport, TransportError, TransportEvent,
};
use support::{BrokenEntropy, CountingEntropy, FlakyEntropy, VirtualNetwork, VirtualProvider};

type Node = TcpTransport<VirtualProvider, CountingEntropy>;

const LISTEN_ADDR: &str = "/ip4/127.0.0.1/tcp/4001";

fn addr(text: &str) -> Multiaddr {
    text.parse().expect("test address parses")
}

fn identity(seed: u8) -> Ed25519Keypair {
    Ed25519Keypair::from_secret_key_bytes([seed; 32])
}

fn node(net: &VirtualNetwork, key: Ed25519Keypair, seed: u8) -> Node {
    TcpTransport::new(net.provider(), key, CountingEntropy(seed))
}

fn node_with(net: &VirtualNetwork, key: Ed25519Keypair, seed: u8, config: TcpConfig) -> Node {
    TcpTransport::with_config(net.provider(), key, CountingEntropy(seed), config)
}

/// Polls both nodes until the network goes quiet, collecting every event.
///
/// Quiescence is a property of the link, not of the event feed: the upgrade
/// takes several round trips that produce no transport event at all, so a
/// harness that stopped at "neither node reported anything" would abandon the
/// handshake half-finished.
fn drive<A: EntropySource, B: EntropySource>(
    net: &VirtualNetwork,
    a: &mut TcpTransport<VirtualProvider, A>,
    b: &mut TcpTransport<VirtualProvider, B>,
) -> (Vec<TransportEvent>, Vec<TransportEvent>) {
    let mut a_events = Vec::new();
    let mut b_events = Vec::new();
    // Generous: a deliberately tiny peer buffer needs one round per few dozen
    // bytes, and the bound only has to rule out a genuine livelock.
    for _ in 0..2048 {
        let from_a = a.poll(Now::from_millis(0)).expect("drive a");
        let from_b = b.poll(Now::from_millis(0)).expect("drive b");
        let quiet = from_a.is_empty()
            && from_b.is_empty()
            && net.is_quiet()
            && a.next_deadline().is_none()
            && b.next_deadline().is_none();
        a_events.extend(from_a);
        b_events.extend(from_b);
        if quiet {
            return (a_events, b_events);
        }
    }
    panic!("the virtual link never went quiet");
}

/// A listener and a dialer, driven until the upgrade completes.
struct Pair {
    net: VirtualNetwork,
    dialer: Node,
    listener: Node,
    dialer_peer: PeerId,
    listener_peer: PeerId,
    connection: ConnectionId,
    dialer_events: Vec<TransportEvent>,
    listener_events: Vec<TransportEvent>,
}

fn upgraded_pair() -> Pair {
    upgraded_pair_with(TcpConfig::default(), TcpConfig::default())
}

fn upgraded_pair_with(dialer_config: TcpConfig, listener_config: TcpConfig) -> Pair {
    let net = VirtualNetwork::new();
    let dialer_key = identity(1);
    let listener_key = identity(2);
    let (dialer_peer, listener_peer) = (dialer_key.peer_id(), listener_key.peer_id());

    let mut dialer = node_with(&net, dialer_key, 10, dialer_config);
    let mut listener = node_with(&net, listener_key, 20, listener_config);
    listener.listen(&addr(LISTEN_ADDR)).expect("listener binds");

    let target = PeerAddr::new(addr(LISTEN_ADDR), listener_peer.clone()).expect("dial target");
    let connection = dialer.dial(&target).expect("dial starts");
    let (dialer_events, listener_events) = drive(&net, &mut dialer, &mut listener);

    Pair {
        net,
        dialer,
        listener,
        dialer_peer,
        listener_peer,
        connection,
        dialer_events,
        listener_events,
    }
}

fn connected_peer(events: &[TransportEvent], id: ConnectionId) -> Option<&PeerId> {
    events.iter().find_map(|event| match event {
        TransportEvent::Connected {
            id: found,
            endpoint,
        } if *found == id => endpoint.peer_id(),
        _ => None,
    })
}

fn position<F: Fn(&TransportEvent) -> bool>(events: &[TransportEvent], test: F) -> Option<usize> {
    events.iter().position(test)
}

fn is_stream_event(event: &TransportEvent) -> bool {
    matches!(
        event,
        TransportEvent::StreamOpened { .. }
            | TransportEvent::IncomingStream { .. }
            | TransportEvent::StreamData { .. }
            | TransportEvent::StreamRemoteWriteClosed { .. }
            | TransportEvent::StreamClosed { .. }
    )
}

#[test]
fn two_nodes_complete_the_upgrade_and_authenticate_each_other() {
    let pair = upgraded_pair();

    // Each side learns the other's real identity, not its own.
    assert_eq!(
        connected_peer(&pair.dialer_events, pair.connection),
        Some(&pair.listener_peer)
    );
    assert_eq!(
        connected_peer(&pair.listener_events, pair.connection),
        Some(&pair.dialer_peer)
    );

    // The listener announces the inbound connection before it is usable.
    let incoming = position(&pair.listener_events, |event| {
        matches!(event, TransportEvent::IncomingConnection { .. })
    })
    .expect("listener reports the inbound connection");
    let connected = position(&pair.listener_events, |event| {
        matches!(event, TransportEvent::Connected { .. })
    })
    .expect("listener completes the upgrade");
    assert!(
        incoming < connected,
        "IncomingConnection must precede Connected: {:?}",
        pair.listener_events
    );

    // The contract forbids stream events before Connected. Nothing about a
    // substream may surface from an upgrade at all -- if the session ever
    // leaked what a pipelined remainder produced, it would show up here.
    for events in [&pair.dialer_events, &pair.listener_events] {
        assert!(
            !events.iter().any(is_stream_event),
            "an upgrade must publish nothing about substreams: {events:?}"
        );
    }
}

#[test]
fn connected_precedes_the_substream_a_peer_opens_immediately() {
    let net = VirtualNetwork::new();
    let dialer_key = identity(1);
    let listener_key = identity(2);
    let listener_peer = listener_key.peer_id();
    let mut dialer = node(&net, dialer_key, 10);
    let mut listener = node(&net, listener_key, 20);
    listener.listen(&addr(LISTEN_ADDR)).expect("listener binds");

    let target = PeerAddr::new(addr(LISTEN_ADDR), listener_peer).expect("dial target");
    let id = dialer.dial(&target).expect("dial starts");

    // Stop as soon as the listener is up, while the dialer has not yet read
    // the confirmation that would finish its own upgrade.
    let mut settled = false;
    for _ in 0..64 {
        let _ = dialer.poll(Now::from_millis(0)).expect("drive dialer");
        let _ = listener.poll(Now::from_millis(0)).expect("drive listener");
        if !listener.connection_ids().is_empty() && listener.open_stream(id).is_ok() {
            settled = true;
            break;
        }
    }
    assert!(settled, "the listener must establish first");

    // Its substream frames now sit behind that unread confirmation, so the
    // dialer decrypts both together and must still report Connected first.
    listener
        .send_stream(id, StreamId::new(2), b"eager".to_vec())
        .expect("send on the fresh substream");
    let (dialer_events, _) = drive(&net, &mut dialer, &mut listener);

    let connected = position(&dialer_events, |event| {
        matches!(event, TransportEvent::Connected { .. })
    })
    .expect("the dialer completes its upgrade");
    let first_stream = position(&dialer_events, is_stream_event)
        .expect("the peer's substream must arrive in this batch, or this proves nothing");
    assert!(
        connected < first_stream,
        "no stream event may precede Connected: {dialer_events:?}"
    );
}

#[test]
fn substreams_carry_data_half_close_and_reset() {
    let mut pair = upgraded_pair();
    let id = pair.connection;

    let stream = pair.dialer.open_stream(id).expect("open substream");
    assert_eq!(stream.as_u64() % 2, 1, "dialer substreams are odd");
    pair.dialer
        .send_stream(id, stream, b"hello".to_vec())
        .expect("send");
    let (_, listener_events) = drive(&pair.net, &mut pair.dialer, &mut pair.listener);

    let incoming = position(&listener_events, |event| {
        matches!(event, TransportEvent::IncomingStream { stream_id, .. } if *stream_id == stream)
    })
    .expect("listener sees the substream");
    let data = position(
        &listener_events,
        |event| matches!(event, TransportEvent::StreamData { data, .. } if data == b"hello"),
    )
    .expect("listener sees the payload");
    assert!(
        incoming < data,
        "IncomingStream must precede StreamData: {listener_events:?}"
    );

    // Half-close leaves the reverse direction open.
    pair.dialer.close_stream_write(id, stream).expect("FIN");
    let (_, listener_events) = drive(&pair.net, &mut pair.dialer, &mut pair.listener);
    assert!(
        listener_events.iter().any(|event| matches!(
            event,
            TransportEvent::StreamRemoteWriteClosed { stream_id, .. } if *stream_id == stream
        )),
        "half close must surface remotely: {listener_events:?}"
    );
    pair.listener
        .send_stream(id, stream, b"reply".to_vec())
        .expect("reverse direction stays open");
    let (dialer_events, _) = drive(&pair.net, &mut pair.dialer, &mut pair.listener);
    assert!(
        dialer_events.iter().any(|event| matches!(
            event,
            TransportEvent::StreamData { data, .. } if data == b"reply"
        )),
        "reply must arrive: {dialer_events:?}"
    );

    // Reset closes both directions, once per side.
    pair.listener.reset_stream(id, stream).expect("reset");
    let (dialer_events, listener_events) = drive(&pair.net, &mut pair.dialer, &mut pair.listener);
    for events in [&dialer_events, &listener_events] {
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(
                    event,
                    TransportEvent::StreamClosed { stream_id, .. } if *stream_id == stream
                ))
                .count(),
            1,
            "exactly one StreamClosed per side: {events:?}"
        );
    }
}

#[test]
fn a_mismatched_expected_peer_fails_the_dial() {
    let net = VirtualNetwork::new();
    let mut dialer = node(&net, identity(1), 10);
    let mut listener = node(&net, identity(2), 20);
    listener.listen(&addr(LISTEN_ADDR)).expect("listener binds");

    // Dial the listener's address while demanding an identity it cannot prove.
    let impostor = identity(3).peer_id();
    let target = PeerAddr::new(addr(LISTEN_ADDR), impostor).expect("dial target");
    let id = dialer.dial(&target).expect("dial starts");
    let (dialer_events, _) = drive(&net, &mut dialer, &mut listener);

    assert!(
        dialer_events.iter().any(
            |event| matches!(event, TransportEvent::Error { id: failed, .. } if *failed == id)
        ),
        "the wrong identity must be reported: {dialer_events:?}"
    );
    assert!(
        dialer_events
            .iter()
            .any(|event| matches!(event, TransportEvent::Closed { id: closed } if *closed == id)),
        "the connection must close: {dialer_events:?}"
    );
    assert!(
        !dialer_events
            .iter()
            .any(|event| matches!(event, TransportEvent::Connected { .. })),
        "a mismatched peer must never connect: {dialer_events:?}"
    );
    assert!(dialer.connection_ids().is_empty());
}

#[test]
fn a_dial_that_fails_outright_never_hands_its_id_to_another_connection() {
    let net = VirtualNetwork::new();
    let listener_key = identity(2);
    let listener_peer = listener_key.peer_id();
    let mut dialer = node(&net, identity(1), 10);
    let mut listener = node(&net, listener_key, 20);
    listener.listen(&addr(LISTEN_ADDR)).expect("listener binds");

    let target = PeerAddr::new(addr(LISTEN_ADDR), listener_peer).expect("dial target");
    dialer.provider_mut().fail_connect(true);
    let failed = match dialer.dial(&target) {
        Err(TransportError::DialFailed { id, .. }) => id,
        other => panic!("expected the dial to fail outright, got {other:?}"),
    };
    assert!(dialer.connection_ids().is_empty());

    // That id already named a failure the caller was told about, so a later
    // dial must not answer to it as well.
    dialer.provider_mut().fail_connect(false);
    let second = dialer.dial(&target).expect("second dial starts");
    assert_ne!(
        second, failed,
        "an id that named a failed dial must not be reused"
    );

    let (dialer_events, _) = drive(&net, &mut dialer, &mut listener);
    assert!(
        dialer_events
            .iter()
            .any(|event| matches!(event, TransportEvent::Connected { id, .. } if *id == second)),
        "the second dial must still succeed: {dialer_events:?}"
    );
}

#[test]
fn a_refused_connect_reports_error_then_closed() {
    let net = VirtualNetwork::new();
    let mut dialer = node(&net, identity(1), 10);
    let mut unused = node(&net, identity(2), 20);

    let target =
        PeerAddr::new(addr("/ip4/127.0.0.1/tcp/9"), identity(2).peer_id()).expect("dial target");
    let id = dialer
        .dial(&target)
        .expect("dial is accepted, then fails asynchronously");
    let (dialer_events, _) = drive(&net, &mut dialer, &mut unused);

    assert!(
        matches!(
            dialer_events.as_slice(),
            [
                TransportEvent::Error { id: failed, message },
                TransportEvent::Closed { id: closed },
            ] if *failed == id && *closed == id && message.contains("refused")
        ),
        "a refused connect must report why, then close: {dialer_events:?}"
    );
    assert!(dialer.connection_ids().is_empty());
}

#[test]
fn a_full_socket_buffers_and_drains_as_the_peer_reads() {
    let net = VirtualNetwork::new();
    let listener_key = identity(2);
    let listener_peer = listener_key.peer_id();
    let mut dialer = node(&net, identity(1), 10);
    let mut listener = node(&net, listener_key, 20);
    listener.listen(&addr(LISTEN_ADDR)).expect("listener binds");

    let target = PeerAddr::new(addr(LISTEN_ADDR), listener_peer).expect("dial target");
    let id = dialer.dial(&target).expect("dial starts");
    // The socket exists now, so a tiny peer buffer constrains the whole
    // conversation: 64 unread bytes and the socket accepts nothing more.
    dialer.provider_mut().set_in_flight_capacity(Some(64));

    // A transport that dropped the remainder of a partial write, or that never
    // retried it, could not finish the upgrade at all.
    let (dialer_events, _) = drive(&net, &mut dialer, &mut listener);
    assert!(
        dialer_events
            .iter()
            .any(|event| matches!(event, TransportEvent::Connected { .. })),
        "64 bytes at a time must still complete the upgrade: {dialer_events:?}"
    );

    let stream = dialer.open_stream(id).expect("open substream");
    let payload: Vec<u8> = (0..4096u32).map(|byte| byte as u8).collect();
    dialer
        .send_stream(id, stream, payload.clone())
        .expect("queue a payload far larger than the peer's buffer");

    // Drain the queued `StreamOpened` first, so buffered bytes are the only
    // thing left that could make the transport urgent. This poll also fills the
    // peer's 64 bytes and stops, leaving the rest waiting on writability --
    // which is exactly what a driver must not sleep through.
    let queued = dialer
        .poll(Now::from_millis(0))
        .expect("drain queued events");
    assert_eq!(
        queued,
        [TransportEvent::StreamOpened {
            id,
            stream_id: stream
        }]
    );
    assert_eq!(
        dialer.next_deadline(),
        Some(Deadline::IMMEDIATE),
        "a socket still taking bytes must keep the driver coming back"
    );

    let (_, listener_events) = drive(&net, &mut dialer, &mut listener);
    let received: Vec<u8> = listener_events
        .iter()
        .filter_map(|event| match event {
            TransportEvent::StreamData { data, .. } => Some(data.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(
        received, payload,
        "every byte must arrive exactly once, in order"
    );
    assert_eq!(dialer.provider().bytes_in_flight_to_peer(), 0);
    assert_eq!(dialer.next_deadline(), None, "nothing is left buffered");
}

#[test]
fn buffered_writes_drain_even_without_a_writable_event() {
    let net = VirtualNetwork::new();
    let listener_key = identity(2);
    let listener_peer = listener_key.peer_id();
    let mut dialer = node(&net, identity(1), 10);
    let mut listener = node(&net, listener_key, 20);
    listener.listen(&addr(LISTEN_ADDR)).expect("listener binds");

    let target = PeerAddr::new(addr(LISTEN_ADDR), listener_peer).expect("dial target");
    let id = dialer.dial(&target).expect("dial starts");
    dialer.provider_mut().set_in_flight_capacity(Some(64));
    // This provider never says when the socket frees up, so every retry has to
    // come from the transport polling again on its own.
    dialer.provider_mut().suppress_writable();

    let (dialer_events, _) = drive(&net, &mut dialer, &mut listener);
    assert!(
        dialer_events
            .iter()
            .any(|event| matches!(event, TransportEvent::Connected { .. })),
        "the upgrade must survive coarse readiness reporting: {dialer_events:?}"
    );

    let stream = dialer.open_stream(id).expect("open substream");
    let payload: Vec<u8> = (0..2048u32).map(|byte| byte as u8).collect();
    dialer
        .send_stream(id, stream, payload.clone())
        .expect("queue a payload far larger than the peer's buffer");
    let (_, listener_events) = drive(&net, &mut dialer, &mut listener);

    let received: Vec<u8> = listener_events
        .iter()
        .filter_map(|event| match event {
            TransportEvent::StreamData { data, .. } => Some(data.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(received, payload, "every byte must still arrive, in order");
}

#[test]
fn closing_a_socket_that_cannot_flush_aborts_instead_of_truncating() {
    let mut pair = upgraded_pair();
    let id = pair.connection;
    let stream = pair.dialer.open_stream(id).expect("open substream");
    drive(&pair.net, &mut pair.dialer, &mut pair.listener);
    let close_writes_before = pair.dialer.provider().close_write_calls();

    // Fill the peer's buffer, then queue more than fits and close. A half-close
    // now would put a FIN in front of bytes the peer never received, so the
    // socket has to be discarded instead.
    pair.dialer.provider_mut().set_in_flight_capacity(Some(64));
    pair.dialer
        .send_stream(id, stream, vec![7u8; 8 * 1024])
        .expect("queue more than the peer can take");
    let aborts_before = pair.dialer.provider().abort_calls();

    pair.dialer.close(id).expect("close with bytes outstanding");
    assert_eq!(
        pair.dialer.provider().close_write_calls(),
        close_writes_before,
        "a FIN must not jump ahead of unflushed bytes"
    );
    assert_eq!(
        pair.dialer.provider().abort_calls(),
        aborts_before + 1,
        "the socket must be discarded instead"
    );
    assert!(pair.dialer.connection_ids().is_empty());
}

#[test]
fn a_stalled_socket_stops_claiming_urgency_and_recovers() {
    let mut pair = upgraded_pair();
    let id = pair.connection;
    let stream = pair.dialer.open_stream(id).expect("open substream");
    drive(&pair.net, &mut pair.dialer, &mut pair.listener);

    // The peer stops reading. What is queued stays well under the ceiling, so
    // the connection lives on -- and must not keep telling the driver to come
    // straight back, which would spin for as long as the peer stays silent.
    pair.dialer.provider_mut().set_in_flight_capacity(Some(0));
    pair.dialer
        .send_stream(id, stream, vec![3u8; 1024])
        .expect("queue bytes the socket will refuse");
    let _ = pair
        .dialer
        .poll(Now::from_millis(0))
        .expect("attempt a flush");

    assert_eq!(
        pair.dialer.next_deadline(),
        Some(Deadline::from_millis(30_000)),
        "a refused socket must be waited on, not spun on"
    );
    assert_eq!(
        pair.dialer.connection_ids(),
        vec![id],
        "a stall well inside the timeout is not fatal"
    );

    // The peer reads again, so the stall clears and the bytes go out.
    pair.dialer.provider_mut().set_in_flight_capacity(None);
    let (_, listener_events) = drive(&pair.net, &mut pair.dialer, &mut pair.listener);
    let delivered: usize = listener_events
        .iter()
        .filter_map(|event| match event {
            TransportEvent::StreamData { data, .. } => Some(data.len()),
            _ => None,
        })
        .sum();
    assert_eq!(delivered, 1024, "the queued payload must survive the stall");
    assert_eq!(pair.dialer.next_deadline(), None);
}

#[test]
fn a_stall_is_measured_from_when_it_started_not_from_an_older_one() {
    let mut pair = upgraded_pair();
    let id = pair.connection;
    let stream = pair.dialer.open_stream(id).expect("open substream");
    drive(&pair.net, &mut pair.dialer, &mut pair.listener);

    // Stall early.
    pair.dialer.provider_mut().set_in_flight_capacity(Some(0));
    pair.dialer
        .send_stream(id, stream, vec![1u8; 512])
        .expect("queue bytes");
    let _ = pair.dialer.poll(Now::from_millis(0)).expect("first stall");

    // Recover through a send rather than a poll, so the backlog drains inside
    // that call and no poll ever observes the buffer shrinking. Only noticing
    // the drained buffer itself clears the mark on this path.
    pair.dialer.provider_mut().set_in_flight_capacity(None);
    pair.dialer
        .send_stream(id, stream, vec![9u8; 16])
        .expect("this send flushes the backlog too");
    let _ = pair
        .dialer
        .poll(Now::from_millis(1_000))
        .expect("observe the drained buffer");
    drive(&pair.net, &mut pair.dialer, &mut pair.listener);

    // Long after that first stall would have expired, stall again. The clock
    // for the new one starts now; carrying the old mark forward would fail the
    // connection on its very first refused write.
    let much_later = Now::from_millis(10 * 60 * 1000);
    pair.dialer.provider_mut().set_in_flight_capacity(Some(0));
    pair.dialer
        .send_stream(id, stream, vec![2u8; 512])
        .expect("queue more bytes");
    let events = pair.dialer.poll(much_later).expect("second stall");

    assert!(
        events.is_empty(),
        "a fresh stall must not be treated as an expired one: {events:?}"
    );
    assert_eq!(pair.dialer.connection_ids(), vec![id]);
    assert_eq!(
        pair.dialer.next_deadline(),
        Some(Deadline::from_millis(10 * 60 * 1000 + 30_000))
    );
}

#[test]
fn a_socket_that_never_recovers_fails_once_the_stall_timeout_passes() {
    let mut pair = upgraded_pair();
    let id = pair.connection;
    let stream = pair.dialer.open_stream(id).expect("open substream");
    drive(&pair.net, &mut pair.dialer, &mut pair.listener);

    pair.dialer.provider_mut().set_in_flight_capacity(Some(0));
    pair.dialer
        .send_stream(id, stream, vec![4u8; 512])
        .expect("queue bytes");
    let _ = pair
        .dialer
        .poll(Now::from_millis(1_000))
        .expect("stall starts");
    assert_eq!(pair.dialer.connection_ids(), vec![id]);

    // Still refusing a full timeout later: the peer is gone, not busy.
    let events = pair
        .dialer
        .poll(Now::from_millis(1_000 + 30_000))
        .expect("stall expires");
    assert!(
        matches!(
            events.as_slice(),
            [
                TransportEvent::Error { id: failed, message },
                TransportEvent::Closed { id: closed },
            ] if *failed == id && *closed == id && message.contains("not reading")
        ),
        "an unrecoverable stall must be reported, then closed: {events:?}"
    );
    assert!(pair.dialer.connection_ids().is_empty());
}

#[test]
fn a_peer_that_stops_reading_fails_the_connection() {
    let config = TcpConfig {
        max_buffered_send: 4096,
        ..TcpConfig::default()
    };
    let mut pair = upgraded_pair_with(config, TcpConfig::default());
    let id = pair.connection;
    let stream = pair.dialer.open_stream(id).expect("open substream");
    drive(&pair.net, &mut pair.dialer, &mut pair.listener);

    // The peer stops reading, so its buffer stays full and the socket takes
    // nothing more.
    pair.dialer.provider_mut().set_in_flight_capacity(Some(64));
    // Yamux's own limits are far higher, so it is the socket buffer's ceiling
    // that gives way here, not the session's.
    let error = pair
        .dialer
        .send_stream(id, stream, vec![0u8; 16 * 1024])
        .expect_err("the outbound ceiling must reject this");
    assert!(matches!(
        error,
        TransportError::StreamSendFailed { id: failed, .. } if failed == id
    ));

    let events = pair.dialer.poll(Now::from_millis(0)).expect("teardown");
    assert_eq!(
        events,
        [TransportEvent::Closed { id }],
        "the caller already has the error, so only Closed goes out"
    );
    assert!(pair.dialer.connection_ids().is_empty());
}

#[test]
fn listen_and_dial_reject_addresses_another_transport_owns() {
    let net = VirtualNetwork::new();
    let mut transport = node(&net, identity(1), 10);
    let quic = addr("/ip4/127.0.0.1/udp/4001/quic-v1");

    assert!(matches!(
        transport.listen(&quic),
        Err(TransportError::InvalidAddress {
            context: "tcp listen",
            ..
        })
    ));
    let target = PeerAddr::new(quic, identity(2).peer_id()).expect("dial target");
    assert!(matches!(
        transport.dial(&target),
        Err(TransportError::InvalidAddress {
            context: "tcp dial",
            ..
        })
    ));
    assert!(transport.connection_ids().is_empty());
}

#[test]
fn a_dial_that_cannot_draw_entropy_opens_no_socket() {
    let net = VirtualNetwork::new();
    let mut dialer = TcpTransport::new(net.provider(), identity(1), BrokenEntropy);
    let mut listener = node(&net, identity(2), 20);
    listener.listen(&addr(LISTEN_ADDR)).expect("listener binds");

    // Consume the listener's own `Listening` so what follows is only the dial.
    assert!(matches!(
        listener
            .poll(Now::from_millis(0))
            .expect("bind event")
            .as_slice(),
        [TransportEvent::Listening { .. }]
    ));

    let target = PeerAddr::new(addr(LISTEN_ADDR), identity(2).peer_id()).expect("dial target");
    assert!(matches!(
        dialer.dial(&target),
        Err(TransportError::PollError { .. })
    ));
    assert!(dialer.connection_ids().is_empty());

    // Entropy is drawn before the connect, so the listener never saw anything:
    // a failed dial leaves no half-open socket behind.
    let events = listener.poll(Now::from_millis(0)).expect("listener idle");
    assert!(events.is_empty(), "unexpected listener events: {events:?}");
}

#[test]
fn close_shuts_the_peer_down_without_reporting_an_error() {
    let mut pair = upgraded_pair();
    let id = pair.connection;
    let stream = pair.dialer.open_stream(id).expect("open substream");
    drive(&pair.net, &mut pair.dialer, &mut pair.listener);

    pair.dialer.close(id).expect("graceful close");
    let local = pair.dialer.poll(Now::from_millis(0)).expect("local close");
    assert_eq!(
        local,
        [
            TransportEvent::StreamClosed {
                id,
                stream_id: stream
            },
            TransportEvent::Closed { id },
        ],
        "closing must close the open substream first"
    );
    assert!(pair.dialer.connection_ids().is_empty());
    assert_eq!(
        pair.dialer.close(id),
        Err(TransportError::ConnectionNotFound { id })
    );

    let (_, listener_events) = drive(&pair.net, &mut pair.dialer, &mut pair.listener);
    assert_eq!(
        listener_events,
        [TransportEvent::Closed { id }],
        "an orderly shutdown is not an error on the peer: {listener_events:?}"
    );
    assert!(pair.listener.connection_ids().is_empty());
}

#[test]
fn a_truncated_stream_is_a_fault_not_an_orderly_close() {
    let mut pair = upgraded_pair();
    let id = pair.connection;

    // The peer stops writing without ever sending a Yamux GoAway. libp2p needs
    // the stream in both directions, so this ends the connection -- and unlike
    // a real shutdown it is a failure the host should hear about.
    pair.listener.provider_mut().half_close_all();
    let (dialer_events, _) = drive(&pair.net, &mut pair.dialer, &mut pair.listener);

    assert!(
        matches!(
            dialer_events.as_slice(),
            [
                TransportEvent::Error { id: failed, .. },
                TransportEvent::Closed { id: closed },
            ] if *failed == id && *closed == id
        ),
        "a truncated stream must be reported, then closed: {dialer_events:?}"
    );
    assert!(pair.dialer.connection_ids().is_empty());
}

#[test]
fn a_rejected_inbound_connection_is_reported_and_never_reuses_its_id() {
    let net = VirtualNetwork::new();
    let listener_key = identity(2);
    let listener_peer = listener_key.peer_id();
    let mut dialer = node(&net, identity(1), 10);
    // The first draw fails, so the first inbound connection is refused and the
    // second succeeds.
    let mut listener = TcpTransport::with_config(
        net.provider(),
        listener_key,
        FlakyEntropy::new(1, 20),
        TcpConfig::default(),
    );
    listener.listen(&addr(LISTEN_ADDR)).expect("listener binds");

    let target = PeerAddr::new(addr(LISTEN_ADDR), listener_peer).expect("dial target");
    dialer.dial(&target).expect("first dial starts");
    let (_, listener_events) = drive(&net, &mut dialer, &mut listener);

    let refused = listener_events
        .iter()
        .find_map(|event| match event {
            TransportEvent::Error { id, message } if message.contains("rejected") => Some(*id),
            _ => None,
        })
        .expect("the refusal must be reported: {listener_events:?}");
    assert!(
        !listener_events
            .iter()
            .any(|event| matches!(event, TransportEvent::IncomingConnection { .. })),
        "a connection the listener cannot secure must never be announced: {listener_events:?}"
    );
    assert!(listener.connection_ids().is_empty());

    // The refused id was already spent on an event the host saw, so the next
    // connection must not answer to it as well.
    dialer.dial(&target).expect("second dial starts");
    let (_, listener_events) = drive(&net, &mut dialer, &mut listener);
    let accepted = listener_events
        .iter()
        .find_map(|event| match event {
            TransportEvent::IncomingConnection { id, .. } => Some(*id),
            _ => None,
        })
        .expect("the second connection is accepted");
    assert_ne!(
        accepted, refused,
        "an id that named a failure must not be reused"
    );
    assert_eq!(listener.connection_ids(), vec![accepted]);
}

#[test]
fn unknown_connections_and_substreams_are_rejected() {
    let mut pair = upgraded_pair();
    let id = pair.connection;
    let unknown =
        ConnectionId::namespaced(ConnectionNamespace::TCP_IPV4, 4242).expect("id in range");
    let stream = StreamId::new(7);

    assert!(matches!(
        pair.dialer.open_stream(unknown),
        Err(TransportError::ConnectionNotFound { id: missing }) if missing == unknown
    ));
    assert!(matches!(
        pair.dialer.send_stream(unknown, stream, vec![1]),
        Err(TransportError::ConnectionNotFound { id: missing }) if missing == unknown
    ));
    assert_eq!(
        pair.dialer.close(unknown),
        Err(TransportError::ConnectionNotFound { id: unknown })
    );

    // An unknown substream on a live connection is a stream error, not a
    // connection error.
    assert!(matches!(
        pair.dialer.send_stream(id, stream, vec![1]),
        Err(TransportError::StreamSendFailed { id: failed, stream_id, .. })
            if failed == id && stream_id == stream
    ));

    // An id congruent to a live substream modulo 2^32 must be rejected rather
    // than truncated onto it.
    let live = pair.dialer.open_stream(id).expect("open substream");
    let aliased = StreamId::new(live.as_u64() + (1u64 << 32));
    assert_eq!(
        pair.dialer.send_stream(id, aliased, vec![1]),
        Err(TransportError::StreamNotFound {
            id,
            stream_id: aliased
        })
    );

    // An empty write is a no-op on a live connection, but is not a way to
    // address one that does not exist.
    assert_eq!(pair.dialer.send_stream(id, live, Vec::new()), Ok(()));
    assert_eq!(
        pair.dialer.send_stream(unknown, live, Vec::new()),
        Err(TransportError::ConnectionNotFound { id: unknown })
    );
}

#[test]
fn addresses_and_inbound_sources_are_reported_through_the_provider() {
    let pair = upgraded_pair();

    assert_eq!(pair.listener.local_addresses(), vec![addr(LISTEN_ADDR)]);
    assert!(
        pair.dialer.local_addresses().is_empty(),
        "an outbound-only node binds nothing"
    );

    // Only accepted connections count: a hole-punch responder uses this to tell
    // a real inbound packet from its own simultaneous dial.
    let sources = pair.listener.active_inbound_connection_sources();
    assert_eq!(sources.len(), 1);
    assert!(
        sources[0].is_tcp_transport(),
        "unexpected source: {sources:?}"
    );
    assert!(
        pair.dialer.active_inbound_connection_sources().is_empty(),
        "a dialed connection is not an inbound source"
    );
}

#[test]
fn connection_ids_come_from_the_configured_namespace() {
    let config = TcpConfig {
        namespace: ConnectionNamespace::TCP_IPV6,
        ..TcpConfig::default()
    };
    let pair = upgraded_pair_with(config.clone(), config);

    assert_eq!(pair.connection.namespace(), ConnectionNamespace::TCP_IPV6);
    for id in pair.listener.connection_ids() {
        assert_eq!(id.namespace(), ConnectionNamespace::TCP_IPV6);
    }
}

#[test]
fn an_idle_transport_reports_no_deadline_of_its_own() {
    let net = VirtualNetwork::new();
    let transport = node(&net, identity(1), 10);
    assert_eq!(transport.next_deadline(), None);

    let pair = upgraded_pair();
    assert_eq!(
        pair.dialer.next_deadline(),
        None,
        "a drained connection has nothing pending"
    );
}
