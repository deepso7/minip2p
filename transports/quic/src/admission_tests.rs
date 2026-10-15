//! Inbound admission: nothing before `listen`, the connection limit before
//! Retry, and Retry's address validation.

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use minip2p_identity::Ed25519Keypair;
use quinn_proto::{TimeSource, TokenStore};

use super::*;
use crate::test_peer::{
    RawPeer, accept, client_config, deliver_then_close, drive_until, listening_server, loopback,
    now, peer_addr, take_datagrams,
};

/// Whether `datagram` is a QUIC v1 Retry packet.
fn is_retry(datagram: &[u8]) -> bool {
    datagram.first().is_some_and(|first| first & 0xf0 == 0xf0)
}

/// Polls `node` a few times, giving loopback time to deliver.
fn settle(node: &mut QuicTransport) -> Vec<TransportEvent> {
    let mut events = Vec::new();
    for _ in 0..5 {
        std::thread::sleep(Duration::from_millis(5));
        events.extend(node.poll(now()).expect("poll"));
    }
    events
}

fn no_incoming(events: &[TransportEvent]) -> bool {
    !events
        .iter()
        .any(|event| matches!(event, TransportEvent::IncomingConnection { .. }))
}

#[test]
fn before_listen_an_initial_gets_no_reply_while_dials_still_work() {
    let mut node = loopback(QuicNodeConfig::generate());
    // The endpoint has no server config yet, so it would answer this Initial
    // with a stateless reset; a node that is not listening sends nothing.
    let client = RawPeer::connect(node.local_addr(), |_| {});
    let events = settle(&mut node);
    assert!(no_incoming(&events), "{events:?}");
    assert!(node.connections.is_empty());
    assert!(take_datagrams(&client.socket).is_empty());

    // The same socket still dials out.
    let keypair = Ed25519Keypair::generate();
    let mut listener = RawPeer::listen(&keypair);
    let addr = PeerAddr::new(
        socket_addr_to_multiaddr(listener.local_addr()),
        keypair.peer_id(),
    )
    .expect("peer addr");
    let id = node.dial(&addr).expect("dial");
    let mut events = Vec::new();
    drive_until(
        &mut node,
        &mut [&mut listener],
        &mut events,
        "outbound handshake",
        |events| {
            events.iter().any(|event| matches!(event, TransportEvent::Connected { id: connected, .. } if *connected == id))
        },
    );
}

#[test]
fn at_the_connection_limit_an_initial_gets_no_retry_and_no_state() {
    let mut server = listening_server(QuicLimits {
        max_connections: 1,
        ..QuicLimits::default()
    });
    let (_first, _) = accept(&mut server, &mut [], |_| {});

    let second = RawPeer::connect(server.local_addr(), |_| {});
    let events = settle(&mut server);
    assert!(no_incoming(&events), "{events:?}");
    assert_eq!(server.connections.len(), 1);
    assert!(
        take_datagrams(&second.socket).is_empty(),
        "capacity is checked before Retry"
    );
}

#[test]
fn an_initial_without_a_token_gets_a_retry_and_no_state() {
    let mut server = listening_server(QuicLimits::default());
    let client = RawPeer::connect(server.local_addr(), |_| {});
    let events = settle(&mut server);
    assert!(no_incoming(&events), "{events:?}");
    assert!(server.connections.is_empty());
    let replies = take_datagrams(&client.socket);
    assert!(
        replies.len() == 1 && is_retry(&replies[0]),
        "one Retry: {replies:?}"
    );
}

/// Hands out one garbage token, as a client might replay a stale one.
struct GarbageToken(Mutex<Option<Bytes>>);

impl TokenStore for GarbageToken {
    fn insert(&self, _: &str, _: Bytes) {}

    fn take(&self, _: &str) -> Option<Bytes> {
        self.0.lock().expect("token lock").take()
    }
}

#[test]
fn a_garbage_token_gets_a_retry_and_no_state() {
    let mut server = listening_server(QuicLimits::default());
    let mut config = client_config(|_| {});
    config.token_store(Arc::new(GarbageToken(Mutex::new(Some(Bytes::from(
        vec![0xcc; 64],
    ))))));
    let client = RawPeer::connect_with(server.local_addr(), config);
    let events = settle(&mut server);
    assert!(no_incoming(&events), "{events:?}");
    assert!(server.connections.is_empty());
    let replies = take_datagrams(&client.socket);
    assert!(
        replies.len() == 1 && is_retry(&replies[0]),
        "an undecodable token counts as none: {replies:?}"
    );
}

/// System time plus an offset the test moves forward.
#[derive(Default)]
struct ShiftedTime(Mutex<Duration>);

impl ShiftedTime {
    fn advance(&self, by: Duration) {
        *self.0.lock().expect("time lock") += by;
    }
}

impl TimeSource for ShiftedTime {
    fn now(&self) -> SystemTime {
        SystemTime::now() + *self.0.lock().expect("time lock")
    }
}

#[test]
fn an_expired_retry_token_creates_no_state() {
    let mut server = listening_server(QuicLimits::default());
    let time = Arc::new(ShiftedTime::default());
    server.update_server_config(|config| {
        config.time_source(Arc::clone(&time) as Arc<dyn TimeSource>);
    });

    let mut client = RawPeer::connect(server.local_addr(), |_| {});
    settle(&mut server);
    // The Retry is waiting on the client's socket; its token expires before
    // the client answers.
    time.advance(RETRY_TOKEN_LIFETIME + Duration::from_secs(1));
    client.pump();
    let mut events = settle(&mut server);
    let start = Instant::now();
    while !client.is_closed() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the client never learned its token was refused"
        );
        std::thread::sleep(Duration::from_millis(2));
        client.pump();
        events.extend(server.poll(now()).expect("poll"));
    }
    assert!(no_incoming(&events), "{events:?}");
    assert!(server.connections.is_empty());
}

#[test]
fn the_handshake_completes_through_retry() {
    let mut server = listening_server(QuicLimits::default());
    let mut client = RawPeer::connect(server.local_addr(), |_| {});
    let mut events = settle(&mut server);
    assert!(no_incoming(&events), "{events:?}");
    let mut first = [0u8; 1];
    client.socket.peek_from(&mut first).expect("a reply");
    assert!(is_retry(&first), "the first reply is a Retry");

    drive_until(
        &mut server,
        &mut [&mut client],
        &mut events,
        "handshake through Retry",
        |events| {
            events
                .iter()
                .any(|event| matches!(event, TransportEvent::Connected { .. }))
        },
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, TransportEvent::IncomingConnection { .. }))
            .count(),
        1
    );
}

#[test]
fn a_closed_connection_keeps_its_slot_until_its_delivered_bytes_settle() {
    // ADR 0012 (#356): the receive bound outlives the connection, so a reader
    // that never acknowledges holds the slot, and acknowledging or
    // abandoning after close releases it.
    let mut server = listening_server(QuicLimits {
        max_connections: 1,
        ..QuicLimits::default()
    });
    let (id, stream) = deliver_then_close(&mut server);
    assert!(server.connections.is_empty(), "only the counts survive");

    let refused = |server: &mut QuicTransport| {
        let elsewhere = peer_addr(&loopback(QuicNodeConfig::generate()));
        assert!(matches!(
            server.dial(&elsewhere),
            Err(TransportError::ResourceExhausted { .. })
        ));
        let _knock = RawPeer::connect(server.local_addr(), |_| {});
        let events = settle(server);
        assert!(no_incoming(&events), "a full transport refuses: {events:?}");
    };
    refused(&mut server);

    server
        .ack_stream(id, stream, 2)
        .expect("a partial ack after close");
    refused(&mut server);
    assert_eq!(
        server.ack_stream(id, stream, 3),
        Err(TransportError::AckExceedsDelivered {
            id,
            stream_id: stream,
            acked: 3,
            unacked: 2,
        })
    );
    server.ack_stream(id, stream, 2).expect("the final ack");
    server.ack_stream(id, stream, 1).expect("settled: a no-op");

    // The slot is free again; this time abandon the bytes instead.
    let (id, stream) = deliver_then_close(&mut server);
    refused(&mut server);
    server
        .reset_stream(id, stream)
        .expect("abandoning after close settles");
    let _ = deliver_then_close(&mut server);
}
