//! The QUIC memory budget: connections and streams reserve against
//! `QuicLimits::memory_budget_bytes`, and what does not fit is refused.

use super::*;
use crate::test_peer::{
    RawPeer, accept, deliver_then_close, drive_until, listening_server, loopback, now,
    stream_bytes, take_datagrams,
};
use minip2p_transport::ConnectionCloseReason;

fn quic_addr(addr: &str) -> Multiaddr {
    socket_addr_to_multiaddr(addr.parse().expect("socket addr"))
}

#[test]
fn a_budget_that_cannot_fit_one_connection_and_one_stream_is_rejected() {
    let limits = QuicLimits::default();
    // One socket's retry queue, one connection and one stream.
    let smallest = limits.datagram_queue_reservation_bytes()
        + limits.connection_reservation_bytes()
        + limits.stream_reservation_bytes();
    let bind = |memory_budget_bytes| {
        QuicTransport::bind(
            QuicNodeConfig::generate().with_limits(QuicLimits {
                memory_budget_bytes,
                ..QuicLimits::default()
            }),
            &[quic_addr("127.0.0.1:0")],
        )
    };
    assert!(matches!(
        bind(smallest - 1),
        Err(QuicBindError::InvalidLimit {
            field: "memory_budget_bytes",
            ..
        })
    ));
    assert!(
        matches!(
            QuicTransport::bind(
                QuicNodeConfig::generate().with_limits(QuicLimits {
                    memory_budget_bytes: usize::MAX,
                    max_pending_connection_bytes: usize::MAX / 2 + 1,
                    ..QuicLimits::default()
                }),
                &[quic_addr("127.0.0.1:0")],
            ),
            Err(QuicBindError::InvalidLimit {
                field: "memory_budget_bytes",
                ..
            })
        ),
        "a reservation that overflows never fits"
    );
    let transport = bind(smallest).expect("one connection and one stream fit");
    assert_eq!(transport.budget.reserved(), 0);
}

#[test]
fn a_dual_stack_transport_reserves_both_retry_queues() {
    let limits = QuicLimits::default();
    let one_socket = limits.datagram_queue_reservation_bytes()
        + limits.connection_reservation_bytes()
        + limits.stream_reservation_bytes();
    let tight = QuicNodeConfig::generate().with_limits(QuicLimits {
        memory_budget_bytes: one_socket,
        ..limits
    });
    QuicTransport::bind(tight.clone(), &[quic_addr("127.0.0.1:0")]).expect("one socket fits");
    assert!(matches!(
        QuicTransport::dual_stack(tight),
        Err(QuicBindError::InvalidLimit {
            field: "memory_budget_bytes",
            ..
        })
    ));
}

#[test]
fn a_connection_reserves_twice_its_send_queue_beside_its_windows() {
    // 2 × 1 MiB queue (a queued slice may pin twice what it counts) +
    // 1216 KiB send window + 5 MiB connection window.
    let limits = QuicLimits::default();
    assert_eq!(limits.connection_reservation_bytes(), 8384 * 1024);
    assert_eq!(limits.stream_reservation_bytes(), 1536 * 1024);
}

#[test]
fn the_default_budget_admits_64_connections_with_a_stream_each() {
    // Dual-stack: both sockets' retry queues come out of the budget first.
    let limits = QuicLimits::default();
    assert!(
        2 * limits.datagram_queue_reservation_bytes()
            + 64 * (limits.connection_reservation_bytes() + limits.stream_reservation_bytes())
            <= limits.memory_budget_bytes
    );
}

/// Limits whose budget fits one socket's retry queue, `connections` fixed
/// parts and `streams` stream reservations, and nothing more.
fn budget_for(connections: usize, streams: usize) -> QuicLimits {
    let limits = QuicLimits::default();
    QuicLimits {
        memory_budget_bytes: limits.datagram_queue_reservation_bytes()
            + connections * limits.connection_reservation_bytes()
            + streams * limits.stream_reservation_bytes(),
        ..limits
    }
}

fn target() -> PeerAddr {
    PeerAddr::new(
        quic_addr("127.0.0.1:9"),
        minip2p_identity::Ed25519Keypair::generate().peer_id(),
    )
    .expect("peer addr")
}

const EXHAUSTED: TransportError = TransportError::ResourceExhausted {
    resource: "QUIC memory budget",
};

#[test]
fn a_dial_that_does_not_fit_the_budget_is_refused() {
    let mut transport = loopback(QuicNodeConfig::generate().with_limits(budget_for(1, 1)));
    transport
        .dial(&target())
        .expect("the first connection fits");
    assert_eq!(transport.dial(&target()), Err(EXHAUSTED));
}

#[test]
fn a_stream_open_that_does_not_fit_the_budget_is_refused() {
    let mut server = listening_server(budget_for(1, 1));
    let (_peer, id) = accept(&mut server, &mut [], |_| {});
    server.open_stream(id).expect("the first stream fits");
    assert_eq!(server.open_stream(id), Err(EXHAUSTED));
}

/// Pumps `peer` and polls `node` a few times, giving loopback time to
/// deliver.
fn pump_both(node: &mut QuicTransport, peer: &mut RawPeer) -> Vec<TransportEvent> {
    let mut events = Vec::new();
    for _ in 0..5 {
        std::thread::sleep(Duration::from_millis(5));
        peer.pump();
        events.extend(node.poll(now()).expect("poll"));
    }
    events
}

#[test]
fn a_validated_connection_that_does_not_fit_is_refused() {
    let mut server = listening_server(budget_for(1, 1));
    let (_first, _) = accept(&mut server, &mut [], |_| {});

    // Retry validates the address first; only then is it told.
    let mut second = RawPeer::connect(server.local_addr(), |_| {});
    let mut events = Vec::new();
    let start = Instant::now();
    while !second.is_closed() {
        assert!(start.elapsed() < Duration::from_secs(5), "never refused");
        events.extend(pump_both(&mut server, &mut second));
    }
    assert!(
        second.events.iter().any(|event| matches!(
            event,
            quinn_proto::Event::ConnectionLost {
                reason: quinn_proto::ConnectionError::ConnectionClosed(close),
            } if close.error_code == quinn_proto::TransportErrorCode::CONNECTION_REFUSED
        )),
        "{:?}",
        second.events
    );
    assert_eq!(server.connections.len(), 1, "{events:?}");
}

#[test]
fn an_unvalidated_connection_that_does_not_fit_gets_no_reply() {
    let mut server = listening_server(QuicLimits {
        require_address_validation: false,
        ..budget_for(1, 1)
    });
    let (_first, _) = accept(&mut server, &mut [], |_| {});

    let second = RawPeer::connect(server.local_addr(), |_| {});
    let mut events = Vec::new();
    for _ in 0..5 {
        std::thread::sleep(Duration::from_millis(5));
        events.extend(server.poll(now()).expect("poll"));
    }
    assert!(take_datagrams(&second.socket).is_empty(), "{events:?}");
    assert_eq!(server.connections.len(), 1);
}

/// Drives `server` and `peer` until the server stops `stream`, as it does a
/// refused peer stream. Returns the server's events.
fn until_stopped(
    server: &mut QuicTransport,
    peer: &mut RawPeer,
    stream: u64,
) -> Vec<TransportEvent> {
    let mut events = Vec::new();
    let start = Instant::now();
    while !peer.events.iter().any(|event| {
        matches!(event, quinn_proto::Event::Stream(quinn_proto::StreamEvent::Stopped { id, .. })
            if u64::from(*id) == stream)
    }) {
        assert!(start.elapsed() < Duration::from_secs(5), "never refused");
        events.extend(pump_both(server, peer));
    }
    events
}

#[test]
fn an_inbound_stream_that_does_not_fit_is_refused() {
    let mut server = listening_server(budget_for(1, 1));
    let (mut peer, _) = accept(&mut server, &mut [], |_| {});
    let admitted = peer.open();
    let refused = peer.open();
    peer.write(admitted, b"in");
    peer.write(refused, b"out");

    let events = until_stopped(&mut server, &mut peer, refused);
    assert_eq!(stream_bytes(&events, admitted), b"in");
    let incoming: Vec<u64> = events
        .iter()
        .filter_map(|event| match event {
            TransportEvent::IncomingStream { stream_id, .. } => Some(stream_id.as_u64()),
            _ => None,
        })
        .collect();
    assert_eq!(incoming, [admitted], "{events:?}");
}

#[test]
fn a_stream_reset_before_the_peer_grants_credit_returns_its_reservation() {
    let limits = budget_for(1, 1);
    let connection = limits.connection_reservation_bytes();
    let mut server = listening_server(limits);
    let (_peer, id) = accept(&mut server, &mut [], |config| {
        config.max_concurrent_bidi_streams(VarInt::from_u32(0));
    });
    let pending = server
        .open_stream(id)
        .expect("opens while waiting for credit");
    assert_eq!(server.open_stream(id), Err(EXHAUSTED));
    server.reset_stream(id, pending).expect("reset");
    assert_eq!(server.budget.reserved(), connection);
    server
        .open_stream(id)
        .expect("its reservation is free again");
}

#[test]
fn connection_and_stream_churn_returns_the_budget_to_zero() {
    let limits = QuicLimits::default();
    let (connection, stream) = (
        limits.connection_reservation_bytes(),
        limits.stream_reservation_bytes(),
    );
    let mut server = listening_server(limits);
    for round in 0..3 {
        // A local stream reset while live settles at once.
        let (mut peer, id) = accept(&mut server, &mut [], |_| {});
        let local = server.open_stream(id).expect("open");
        assert_eq!(server.budget.reserved(), connection + stream);
        server.reset_stream(id, local).expect("reset");
        pump_both(&mut server, &mut peer);
        assert_eq!(server.budget.reserved(), connection);
        peer.conn()
            .close(Instant::now(), VarInt::from_u32(0), Bytes::new());
        let mut events = Vec::new();
        drive_until(
            &mut server,
            &mut [&mut peer],
            &mut events,
            "close",
            |events| {
                events.contains(&TransportEvent::Closed {
                    id,
                    reason: ConnectionCloseReason::Remote { code: 0 },
                })
            },
        );
        assert_eq!(server.budget.reserved(), 0);

        // A peer stream whose bytes outlive the connection keeps only its
        // own reservation, until it settles.
        let (id, held) = deliver_then_close(&mut server);
        assert_eq!(server.budget.reserved(), stream, "the fixed part is gone");
        if round % 2 == 0 {
            server.ack_stream(id, held, 4).expect("ack after close");
        } else {
            server.reset_stream(id, held).expect("abandon after close");
        }
        assert_eq!(server.budget.reserved(), 0, "round {round}");
    }
}

#[test]
fn a_stalled_reader_across_close_and_reconnect_stays_within_the_budget() {
    let limits = budget_for(1, 2);
    // What connections and streams may reserve, past the socket's queue.
    let budget = limits.memory_budget_bytes - limits.datagram_queue_reservation_bytes();
    let stream = limits.stream_reservation_bytes();
    let mut server = listening_server(limits);

    // The reader acknowledges nothing; each closed connection leaves one
    // stream's reservation behind.
    let held: Vec<_> = (1..=2)
        .map(|cycle| {
            let held = deliver_then_close(&mut server);
            assert_eq!(server.budget.reserved(), cycle * stream);
            held
        })
        .collect();

    // A reconnect still fits its fixed part, but the bytes held from closed
    // connections leave no room for its stream.
    let (mut peer, _) = accept(&mut server, &mut [], |_| {});
    assert_eq!(server.budget.reserved(), budget);
    let refused = peer.open();
    peer.write(refused, b"more");
    let events = until_stopped(&mut server, &mut peer, refused);
    assert!(stream_bytes(&events, refused).is_empty(), "{events:?}");
    assert_eq!(server.budget.reserved(), budget);

    // Settling the held bytes makes room again.
    for (id, stream_id) in held {
        server
            .ack_stream(id, stream_id, 4)
            .expect("ack after close");
    }
    let admitted = peer.open();
    peer.write(admitted, b"now");
    let mut events = Vec::new();
    drive_until(
        &mut server,
        &mut [&mut peer],
        &mut events,
        "data",
        |events| stream_bytes(events, admitted) == b"now",
    );
}
