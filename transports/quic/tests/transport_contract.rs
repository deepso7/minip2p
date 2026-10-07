//! Transport contract conformance tests.
//!
//! These tests verify the guarantees documented on the `Transport` trait.
//! They run against the QUIC adapter but should pass for any conforming
//! transport implementation.

use minip2p_core::{PeerAddr, Protocol};
use minip2p_platform::{Deadline, Now};
use minip2p_quic::{
    QuicEndpoint, QuicLimits, QuicNodeConfig, QuicTransport, STREAM_RECEIVE_WINDOW,
};
use minip2p_transport::{
    BlockingTransport, Bytes, ConnectionId, ConnectionToken, StreamId, Transport, TransportError,
    TransportEvent, WaitOutcome,
};

mod common;
use common::{drive_pair_once, setup_pair};

fn setup_pair_with_client_limits(limits: QuicLimits) -> (QuicTransport, QuicTransport, PeerAddr) {
    let mut server = QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").expect("server");
    let client = QuicTransport::new(
        QuicNodeConfig::generate().with_limits(limits),
        "127.0.0.1:0",
    )
    .expect("client");

    server.listen_on_bound_addr().expect("listen");
    let peer_addr = server.local_peer_addr().expect("peer addr");
    (server, client, peer_addr)
}

#[test]
fn dual_stack_endpoint_exposes_ipv4_and_ipv6_local_addresses() {
    let endpoint = QuicEndpoint::dual_stack(QuicNodeConfig::generate()).expect("dual stack bind");
    let addrs = endpoint.local_addresses();

    assert!(
        addrs
            .iter()
            .any(|addr| matches!(addr.protocols().first(), Some(Protocol::Ip4(_)))),
        "dual-stack endpoint should expose an IPv4 address: {addrs:?}"
    );
    assert!(
        addrs
            .iter()
            .any(|addr| matches!(addr.protocols().first(), Some(Protocol::Ip6(_)))),
        "dual-stack endpoint should expose an IPv6 address: {addrs:?}"
    );
}

/// Drives the pair until both sides report Connected, collecting all events.
fn connect_pair(
    server: &mut QuicTransport,
    client: &mut QuicTransport,
    peer_addr: &PeerAddr,
) -> (
    ConnectionId,
    ConnectionId,
    Vec<TransportEvent>,
    Vec<TransportEvent>,
) {
    let client_conn = client.dial(peer_addr).expect("dial");

    let mut all_server_events = Vec::new();
    let mut all_client_events = Vec::new();
    let mut server_conn = None;
    let mut server_connected = false;
    let mut client_connected = false;

    for _ in 0..100 {
        let (se, ce) = drive_pair_once(server, client);
        for e in &se {
            match e {
                TransportEvent::IncomingConnection { id, .. } => {
                    if server_conn.is_none() {
                        server_conn = Some(*id);
                    }
                }
                TransportEvent::Connected { id, .. } => {
                    if server_conn.is_none() {
                        server_conn = Some(*id);
                    }
                    if server_conn == Some(*id) {
                        server_connected = true;
                    }
                }
                _ => {}
            }
        }
        for e in &ce {
            if let TransportEvent::Connected { id, .. } = e
                && *id == client_conn
            {
                client_connected = true;
            }
        }
        all_server_events.extend(se);
        all_client_events.extend(ce);
        if client_connected && server_connected {
            break;
        }
    }

    assert!(client_connected, "client must connect");
    assert!(server_connected, "server must connect");
    let server_conn = server_conn.expect("server must accept");
    (
        server_conn,
        client_conn,
        all_server_events,
        all_client_events,
    )
}

// ---------------------------------------------------------------------------
// Connection lifecycle
// ---------------------------------------------------------------------------

#[test]
fn listen_returns_the_resolved_listen_address_and_event_matches() {
    let mut listener =
        QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").expect("listener");
    let requested = listener.local_multiaddr();

    let resolved = listener.listen(&requested).expect("listen");
    assert_eq!(resolved, requested);

    let events = listener.poll(common::now()).expect("poll");
    assert!(
        events
            .iter()
            .any(|event| matches!(event, TransportEvent::Listening { addr } if addr == &resolved))
    );
}

#[test]
fn connected_is_emitted_exactly_once_after_dial() {
    let (mut server, mut client, peer_addr) = setup_pair();
    let (_, _, _, client_events) = connect_pair(&mut server, &mut client, &peer_addr);

    let connected_count = client_events
        .iter()
        .filter(|e| matches!(e, TransportEvent::Connected { .. }))
        .count();
    assert_eq!(connected_count, 1, "Connected must be emitted exactly once");
}

/// The token on `conn`'s `Connected` endpoint.
fn connected_token(events: &[TransportEvent], conn: ConnectionId) -> Option<ConnectionToken> {
    events.iter().find_map(|event| match event {
        TransportEvent::Connected { id, endpoint } if *id == conn => endpoint.token(),
        _ => None,
    })
}

#[test]
fn both_ends_of_a_connection_share_its_token() {
    // The default config validates addresses with a Retry, so this also
    // covers the dialer switching to the Retry's connection id.
    let (mut server, mut client, peer_addr) = setup_pair();
    let (server_conn, client_conn, server_events, client_events) =
        connect_pair(&mut server, &mut client, &peer_addr);
    let token = connected_token(&client_events, client_conn).expect("dialer token");
    assert_eq!(connected_token(&server_events, server_conn), Some(token));

    // A second connection between the same pair gets a token of its own.
    let (second_server, second_client, server_events, client_events) =
        connect_pair(&mut server, &mut client, &peer_addr);
    let second = connected_token(&client_events, second_client).expect("second token");
    assert_eq!(connected_token(&server_events, second_server), Some(second));
    assert_ne!(second, token);
}

#[test]
fn incoming_connection_precedes_connected_on_server() {
    let (mut server, mut client, peer_addr) = setup_pair();
    let (server_conn, _, server_events, _) = connect_pair(&mut server, &mut client, &peer_addr);

    let incoming_idx = server_events.iter().position(
        |e| matches!(e, TransportEvent::IncomingConnection { id, .. } if *id == server_conn),
    );
    let connected_idx = server_events
        .iter()
        .position(|e| matches!(e, TransportEvent::Connected { id, .. } if *id == server_conn));

    assert!(
        incoming_idx.is_some(),
        "server must emit IncomingConnection"
    );
    assert!(connected_idx.is_some(), "server must emit Connected");
    assert!(
        incoming_idx.unwrap() < connected_idx.unwrap(),
        "IncomingConnection must precede Connected"
    );
}

#[test]
fn no_stream_events_before_connected() {
    let (mut server, mut client, peer_addr) = setup_pair();
    let (_, _, _, client_events) = connect_pair(&mut server, &mut client, &peer_addr);

    let connected_idx = client_events
        .iter()
        .position(|e| matches!(e, TransportEvent::Connected { .. }))
        .expect("must have Connected");

    for event in client_events
        .get(..connected_idx)
        .expect("the connected event index is within the collected events")
    {
        assert!(
            !matches!(
                event,
                TransportEvent::StreamOpened { .. }
                    | TransportEvent::IncomingStream { .. }
                    | TransportEvent::StreamData { .. }
                    | TransportEvent::StreamRemoteWriteClosed { .. }
                    | TransportEvent::StreamClosed { .. }
            ),
            "stream event {event:?} emitted before Connected"
        );
    }
}

#[test]
fn outbound_dial_allocates_unique_ids() {
    let (mut server, mut client, peer_addr) = setup_pair();
    let first = client.dial(&peer_addr).expect("first dial");
    let second = client.dial(&peer_addr).expect("second dial");

    assert_ne!(
        first, second,
        "transport must allocate unique connection ids"
    );

    // Drive to avoid dangling state.
    for _ in 0..20 {
        drive_pair_once(&mut server, &mut client);
    }
}

#[test]
fn local_stream_limit_is_enforced_before_allocating_state() {
    let limits = QuicLimits {
        max_streams_per_connection: 1,
        ..QuicLimits::default()
    };
    let (mut server, mut client, peer_addr) = setup_pair_with_client_limits(limits);
    let (_, client_conn, _, _) = connect_pair(&mut server, &mut client, &peer_addr);

    client.open_stream(client_conn).expect("first stream");
    let error = client
        .open_stream(client_conn)
        .expect_err("second stream must exceed limit");
    assert!(matches!(
        error,
        TransportError::ResourceExhausted {
            resource: "local QUIC bidirectional streams"
        }
    ));
}

#[test]
fn local_stream_limit_is_released_after_stream_gc() {
    let limits = QuicLimits {
        max_streams_per_connection: 1,
        ..QuicLimits::default()
    };
    let (mut server, mut client, peer_addr) = setup_pair_with_client_limits(limits);
    let (_, client_conn, _, _) = connect_pair(&mut server, &mut client, &peer_addr);
    let first = client.open_stream(client_conn).expect("first stream");
    client
        .send_stream(client_conn, first, Bytes::from_static(b"data"))
        .expect("send first stream");
    for _ in 0..10 {
        drive_pair_once(&mut server, &mut client);
    }
    client
        .reset_stream(client_conn, first)
        .expect("reset first");
    client
        .poll(common::now())
        .expect("collect and gc reset stream");

    let second = client
        .open_stream(client_conn)
        .expect("closed stream must release concurrent capacity");
    assert_ne!(second, first);
}

#[test]
fn stream_operations_reject_ids_not_allocated_by_transport() {
    let (mut server, mut client, peer_addr) = setup_pair();
    let (_, client_conn, _, _) = connect_pair(&mut server, &mut client, &peer_addr);
    let forged = StreamId::new(0);

    let send_error = client
        .send_stream(client_conn, forged, Bytes::from_static(b"bypass"))
        .expect_err("send must require open_stream");
    assert!(matches!(send_error, TransportError::StreamNotFound { .. }));
    let close_error = client
        .close_stream_write(client_conn, forged)
        .expect_err("close must require open_stream");
    assert!(matches!(close_error, TransportError::StreamNotFound { .. }));

    assert_eq!(
        client.open_stream(client_conn).expect("legitimate open"),
        forged,
        "rejected forged operations must not consume the allocator"
    );
}

#[test]
fn zero_pending_limits_are_rejected() {
    let zero_datagrams = QuicLimits {
        max_pending_datagrams: 0,
        ..QuicLimits::default()
    };
    let zero_stream_bytes = QuicLimits {
        max_pending_stream_bytes: 0,
        ..QuicLimits::default()
    };
    for (limits, field) in [
        (zero_datagrams, "max_pending_datagrams"),
        (zero_stream_bytes, "max_pending_stream_bytes"),
    ] {
        let result = QuicTransport::new(
            QuicNodeConfig::generate().with_limits(limits),
            "127.0.0.1:0",
        );
        let error = match result {
            Ok(_) => panic!("zero {field} must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            TransportError::InvalidConfig { ref reason } if reason.contains(field)
        ));
    }
}

#[test]
fn write_larger_than_queue_cap_succeeds_when_quiche_accepts_it() {
    let limits = QuicLimits {
        max_pending_stream_bytes: 8,
        ..QuicLimits::default()
    };
    let (mut server, mut client, peer_addr) = setup_pair_with_client_limits(limits);
    let (server_conn, client_conn, _, _) = connect_pair(&mut server, &mut client, &peer_addr);
    let stream = client.open_stream(client_conn).expect("open stream");

    // 9 bytes exceed the queue cap but fit quiche's send capacity on an idle
    // connection, so the write goes straight to quiche instead of failing.
    client
        .send_stream(client_conn, stream, Bytes::from(vec![7; 9]))
        .expect("write above the queue cap must succeed via direct send");

    let mut received = 0;
    for _ in 0..50 {
        let (se, _) = drive_pair_once(&mut server, &mut client);
        received += se
            .iter()
            .filter_map(|e| match e {
                TransportEvent::StreamData { id, data, .. } if *id == server_conn => {
                    Some(data.len())
                }
                _ => None,
            })
            .sum::<usize>();
        if received >= 9 {
            break;
        }
    }
    assert_eq!(received, 9, "server must receive the full direct write");
}

#[test]
fn a_write_past_the_pending_cap_is_full_and_resumes_on_writable() {
    let limits = QuicLimits {
        max_pending_stream_bytes: 8,
        ..QuicLimits::default()
    };
    let (mut server, mut client, peer_addr) = setup_pair_with_client_limits(limits);
    let (server_conn, client_conn, _, _) = connect_pair(&mut server, &mut client, &peer_addr);
    let stream = client.open_stream(client_conn).expect("open stream");

    // Far beyond quiche's fresh-connection send capacity plus the queue cap:
    // the transport keeps what fits and hands back exactly the rest.
    let payload: Vec<u8> = (0..256 * 1024u32).map(|i| (i % 251) as u8).collect();
    let error = client
        .send_stream(client_conn, stream, Bytes::from(payload.clone()))
        .expect_err("a write past the queue cap is Full");
    let TransportError::Full {
        id,
        stream_id,
        unsent,
    } = error
    else {
        panic!("expected Full, got {error:?}");
    };
    assert_eq!((id, stream_id), (client_conn, stream));
    assert!(
        !unsent.is_empty() && unsent.len() < payload.len(),
        "part of the write was accepted, the rest handed back"
    );
    assert_eq!(&unsent[..], &payload[payload.len() - unsent.len()..]);

    // Resend the tail each time the stream reports writable; the server must
    // see the original byte stream exactly once.
    let mut held = Some(unsent);
    let mut received = Vec::new();
    let mut remote_closed = false;
    for _ in 0..2000 {
        let (server_events, client_events) = drive_pair_once(&mut server, &mut client);
        for event in client_events {
            if event
                == (TransportEvent::StreamWritable {
                    id: client_conn,
                    stream_id: stream,
                })
                && let Some(tail) = held.take()
            {
                match client.send_stream(client_conn, stream, tail) {
                    Ok(()) => client
                        .close_stream_write(client_conn, stream)
                        .expect("close write"),
                    Err(error) => held = Some(error.into_unsent().expect("only Full")),
                }
            }
        }
        for event in server_events {
            match event {
                TransportEvent::StreamData { id, data, .. } if id == server_conn => {
                    received.extend_from_slice(&data);
                }
                TransportEvent::StreamRemoteWriteClosed { id, .. } if id == server_conn => {
                    remote_closed = true;
                }
                _ => {}
            }
        }
        if remote_closed {
            break;
        }
    }
    assert!(remote_closed, "the whole write must eventually go out");
    assert_eq!(received, payload, "every byte, once, in order");
}

/// Resends `held` on the stream's Writable; closes the write side once it
/// is all accepted.
fn resend_on_writable(
    client: &mut QuicTransport,
    events: Vec<TransportEvent>,
    conn: ConnectionId,
    stream: StreamId,
    held: &mut Option<Bytes>,
) {
    for event in events {
        if event
            == (TransportEvent::StreamWritable {
                id: conn,
                stream_id: stream,
            })
            && let Some(tail) = held.take()
        {
            match client.send_stream(conn, stream, tail) {
                Ok(()) => client.close_stream_write(conn, stream).expect("close"),
                Err(error) => *held = Some(error.into_unsent().expect("only Full")),
            }
        }
    }
}

#[test]
fn a_reader_that_never_acks_stalls_its_sender_until_it_does() {
    let limits = QuicLimits {
        max_pending_stream_bytes: 64 * 1024,
        ..QuicLimits::default()
    };
    let (mut server, mut client, peer_addr) = setup_pair_with_client_limits(limits);
    let (server_conn, client_conn, _, _) = connect_pair(&mut server, &mut client, &peer_addr);
    let stream = client.open_stream(client_conn).expect("open stream");
    let payload: Vec<u8> = (0..4 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let mut held = client
        .send_stream(client_conn, stream, Bytes::from(payload.clone()))
        .err()
        .and_then(TransportError::into_unsent);

    // The reader takes what arrives and acknowledges none of it: one window
    // is delivered, quiche buffers at most another, and the sender stalls.
    let mut received = Vec::new();
    let mut quiet_rounds = 0;
    while quiet_rounds < 40 {
        let (server_events, client_events) = drive_pair_once(&mut server, &mut client);
        resend_on_writable(&mut client, client_events, client_conn, stream, &mut held);
        let before = received.len();
        for event in server_events {
            if let TransportEvent::StreamData { data, .. } = event {
                received.extend_from_slice(&data);
            }
        }
        quiet_rounds = if received.len() == before {
            quiet_rounds + 1
        } else {
            0
        };
    }
    assert_eq!(received.len(), STREAM_RECEIVE_WINDOW, "exactly one budget");
    assert!(held.is_some(), "the sender still holds its tail");

    // One acknowledgement resumes delivery at once, without another packet.
    server
        .ack_stream(server_conn, stream, received.len())
        .expect("ack");
    let resumed = server.poll(common::now()).expect("poll");
    assert!(
        resumed
            .iter()
            .any(|event| matches!(event, TransportEvent::StreamData { .. })),
        "quiche's buffered bytes are read on the ack"
    );
    let mut events = resumed;
    let mut remote_closed = false;
    for _ in 0..4000 {
        for event in events {
            match event {
                TransportEvent::StreamData {
                    id,
                    stream_id,
                    data,
                } => {
                    received.extend_from_slice(&data);
                    server.ack_stream(id, stream_id, data.len()).expect("ack");
                }
                TransportEvent::StreamRemoteWriteClosed { .. } => remote_closed = true,
                _ => {}
            }
        }
        if remote_closed {
            break;
        }
        let (server_events, client_events) = drive_pair_once(&mut server, &mut client);
        resend_on_writable(&mut client, client_events, client_conn, stream, &mut held);
        events = server_events;
    }
    assert!(remote_closed, "the transfer completes once the reader acks");
    assert_eq!(received, payload, "every byte, once, in order");
}

#[test]
fn an_unsettled_stream_holds_its_slot_and_over_acks_fail() {
    let mut server = QuicTransport::new(
        QuicNodeConfig::generate().with_limits(QuicLimits {
            max_streams_per_connection: 1,
            ..QuicLimits::default()
        }),
        "127.0.0.1:0",
    )
    .expect("server");
    let mut client = QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").expect("client");
    server.listen_on_bound_addr().expect("listen");
    let peer_addr = server.local_peer_addr().expect("peer addr");
    let (server_conn, client_conn, _, _) = connect_pair(&mut server, &mut client, &peer_addr);

    // A stream that delivers ten bytes and closes in both directions, unread.
    let first = client.open_stream(client_conn).expect("open");
    client
        .send_stream(client_conn, first, Bytes::from_static(b"0123456789"))
        .expect("send");
    client.close_stream_write(client_conn, first).expect("fin");
    let mut closed = false;
    for _ in 0..200 {
        let (server_events, _) = drive_pair_once(&mut server, &mut client);
        for event in server_events {
            match event {
                TransportEvent::StreamRemoteWriteClosed { id, stream_id } => {
                    server.close_stream_write(id, stream_id).expect("close");
                }
                TransportEvent::StreamClosed { .. } => closed = true,
                _ => {}
            }
        }
        if closed {
            break;
        }
    }
    assert!(closed, "the first stream closed on the server");
    assert_eq!(
        server.ack_stream(server_conn, first, 11),
        Err(TransportError::AckExceedsDelivered {
            id: server_conn,
            stream_id: first,
            acked: 11,
            unacked: 10,
        })
    );

    // Unsettled, it keeps the only slot: the next inbound stream is refused.
    // quiche itself already freed the slot, so the client can open and write;
    // it is the transport that refuses.
    assert_eq!(
        open_and_watch(&mut server, &mut client, client_conn),
        (true, false),
        "an unsettled stream holds its slot"
    );

    // Acknowledging the closed stream releases it, and the slot with it.
    server.ack_stream(server_conn, first, 10).expect("ack");
    server
        .ack_stream(server_conn, first, 10)
        .expect("settled: a no-op");
    assert_eq!(
        open_and_watch(&mut server, &mut client, client_conn),
        (true, true),
        "the settled stream's slot takes a new stream"
    );
}

/// Opens a stream from `client` and writes to it; reports whether that
/// worked, and whether the server announced the stream.
fn open_and_watch(
    server: &mut QuicTransport,
    client: &mut QuicTransport,
    client_conn: ConnectionId,
) -> (bool, bool) {
    let mut stream = None;
    for _ in 0..100 {
        if stream.is_none()
            && let Ok(opened) = client.open_stream(client_conn)
            && client
                .send_stream(client_conn, opened, Bytes::from_static(b"hi"))
                .is_ok()
        {
            stream = Some(opened);
        }
        let (server_events, _) = drive_pair_once(server, client);
        if server_events
            .iter()
            .any(|event| matches!(event, TransportEvent::IncomingStream { stream_id, .. } if Some(*stream_id) == stream))
        {
            return (true, true);
        }
    }
    (stream.is_some(), false)
}

#[test]
fn queued_stream_writes_preserve_order_behind_direct_sends() {
    let (mut server, mut client, peer_addr) = setup_pair();
    let (server_conn, client_conn, _, _) = connect_pair(&mut server, &mut client, &peer_addr);
    let stream = client.open_stream(client_conn).expect("open stream");

    // The first write exceeds the initial congestion window, so part of it
    // queues; the second write must land behind that queued remainder.
    let first: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let second = vec![0xEEu8; 1_000];
    client
        .send_stream(client_conn, stream, Bytes::from(first.clone()))
        .expect("first write");
    client
        .send_stream(client_conn, stream, Bytes::from(second.clone()))
        .expect("second write");
    client
        .close_stream_write(client_conn, stream)
        .expect("close write");

    let mut received = Vec::new();
    let mut remote_closed = false;
    for _ in 0..1000 {
        let (se, _) = drive_pair_once(&mut server, &mut client);
        for e in se {
            match e {
                TransportEvent::StreamData { id, data, .. } if id == server_conn => {
                    received.extend_from_slice(&data);
                }
                TransportEvent::StreamRemoteWriteClosed { id, .. } if id == server_conn => {
                    remote_closed = true;
                }
                _ => {}
            }
        }
        if remote_closed {
            break;
        }
    }

    let mut expected = first;
    expected.extend_from_slice(&second);
    assert!(remote_closed, "server must observe the FIN");
    assert_eq!(
        received, expected,
        "bytes must arrive exactly in write order"
    );
}

#[test]
fn dial_enforces_max_connections() {
    let limits = QuicLimits {
        max_connections: 1,
        ..QuicLimits::default()
    };
    let (_server, mut client, peer_addr) = setup_pair_with_client_limits(limits);

    client.dial(&peer_addr).expect("first dial fits the limit");
    let error = client
        .dial(&peer_addr)
        .expect_err("second dial must exceed the connection limit");
    assert!(matches!(
        error,
        TransportError::ResourceExhausted {
            resource: "QUIC connections"
        }
    ));
}

#[test]
fn quic_deadline_is_exposed_and_driven_without_socket_input() {
    // Long enough that a stall between the handshake and the check below
    // cannot expire the connection and leave no timer armed. What this proves
    // is that the timer fires without socket input, not how soon.
    let limits = QuicLimits {
        idle_timeout_ms: 1_000,
        ..QuicLimits::default()
    };
    let (mut server, mut client, peer_addr) = setup_pair_with_client_limits(limits);
    let (_, conn_id, _, _) = connect_pair(&mut server, &mut client, &peer_addr);
    assert!(
        client.next_deadline().is_some(),
        "connected QUIC session must arm a timer"
    );

    // The close is what this waits for, so the loop ends when it arrives. The
    // cap is a failure backstop: under load the idle timer is driven by however
    // many polls this thread gets, not by how long it sat here.
    let backstop = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut closed = false;
    while !closed && std::time::Instant::now() < backstop {
        closed |= client
            .poll(common::now())
            .expect("poll")
            .into_iter()
            .any(|event| matches!(event, TransportEvent::Closed { id, .. } if id == conn_id));
        let sleep = client
            .next_deadline()
            .map(|deadline| std::time::Duration::from_millis(deadline.millis_until(common::now())))
            .unwrap_or(std::time::Duration::from_millis(1))
            .min(std::time::Duration::from_millis(5));
        if !sleep.is_zero() {
            std::thread::sleep(sleep);
        }
    }
    assert!(closed, "QUIC timeout must close a silent dial");
}

#[test]
fn quiet_pair_stays_up_past_idle_timeout() {
    // The window has to outlast quiche's effective idle timeout,
    // max(idle, 3×PTO), for the test to prove anything. This test runs alone
    // (see `.config/nextest.toml`), which keeps PTO near loopback scale and so
    // the effective timeout near the configured one, and keeps a descheduled
    // thread from expiring the connection. That is mitigation, not a bound: a
    // pause from outside the suite during the handshake can still stretch PTO.
    const IDLE_MS: u64 = 1_000;
    /// Twice the idle timeout: reaching the end of it without a close is
    /// itself the proof that the keepalive held the pair up.
    const OBSERVE: std::time::Duration = std::time::Duration::from_millis(2 * IDLE_MS);

    let limits = QuicLimits {
        idle_timeout_ms: IDLE_MS,
        ..QuicLimits::default()
    };
    let (mut server, mut client, peer_addr) = setup_pair_with_client_limits(limits);
    let (server_id, client_id, _, _) = connect_pair(&mut server, &mut client, &peer_addr);

    let deadline = std::time::Instant::now() + OBSERVE;
    let mut closed = false;
    while std::time::Instant::now() < deadline {
        closed |= server
            .poll(common::now())
            .expect("server poll")
            .into_iter()
            .any(|event| matches!(event, TransportEvent::Closed { id, .. } if id == server_id));
        closed |= client
            .poll(common::now())
            .expect("client poll")
            .into_iter()
            .any(|event| matches!(event, TransportEvent::Closed { id, .. } if id == client_id));
        if closed {
            break;
        }
        let sleep = Deadline::earliest_opt(server.next_deadline(), client.next_deadline())
            .map(|deadline| std::time::Duration::from_millis(deadline.millis_until(common::now())))
            .unwrap_or(std::time::Duration::from_millis(5))
            .min(std::time::Duration::from_millis(10));
        if !sleep.is_zero() {
            std::thread::sleep(sleep);
        }
    }

    // A stall can carry the loop past its deadline, leaving a `Closed` that
    // arrived during the stall unread. Poll once more before judging, or the
    // test passes exactly when it should fail.
    for (node, id) in [(&mut server, server_id), (&mut client, client_id)] {
        closed |= node
            .poll(common::now())
            .expect("final poll")
            .into_iter()
            .any(|event| matches!(event, TransportEvent::Closed { id: closed_id, .. } if closed_id == id));
    }

    assert!(
        !closed,
        "ack-eliciting keepalive must keep a quiet pair past the idle timeout"
    );
}

#[test]
fn close_rejects_further_stream_operations() {
    let (mut server, mut client, peer_addr) = setup_pair();
    let (_, client_conn, _, _) = connect_pair(&mut server, &mut client, &peer_addr);

    // Open a stream first so we can test send after close.
    let stream_id = client.open_stream(client_conn).expect("open stream");
    client
        .send_stream(client_conn, stream_id, Bytes::from_static(b"data"))
        .expect("send before close");

    client.close(client_conn).expect("close");

    // After close(), the connection is in Closing state. Opening new streams
    // or sending on existing ones should fail.
    let err = client.open_stream(client_conn);
    assert!(err.is_err(), "open_stream must fail after close");
}

// ---------------------------------------------------------------------------
// Stream lifecycle
// ---------------------------------------------------------------------------

#[test]
fn open_stream_emits_stream_opened() {
    let (mut server, mut client, peer_addr) = setup_pair();
    let (_, client_conn, _, _) = connect_pair(&mut server, &mut client, &peer_addr);

    let stream_id = client.open_stream(client_conn).expect("open stream");

    let (_, ce) = drive_pair_once(&mut server, &mut client);
    let found = ce
        .iter()
        .any(|e| matches!(e, TransportEvent::StreamOpened { id, stream_id: sid } if *id == client_conn && *sid == stream_id));

    assert!(
        found
            || client
                .poll(common::now())
                .unwrap()
                .iter()
                .any(|e| matches!(e, TransportEvent::StreamOpened { .. })),
        "StreamOpened must be emitted"
    );
}

#[test]
fn incoming_stream_precedes_stream_data() {
    let (mut server, mut client, peer_addr) = setup_pair();
    let (server_conn, client_conn, _, _) = connect_pair(&mut server, &mut client, &peer_addr);

    let stream_id = client.open_stream(client_conn).expect("open stream");
    client
        .send_stream(client_conn, stream_id, Bytes::from_static(b"hello"))
        .expect("send");

    let mut server_events = Vec::new();
    for _ in 0..50 {
        let (se, _) = drive_pair_once(&mut server, &mut client);
        server_events.extend(se);
        if server_events
            .iter()
            .any(|e| matches!(e, TransportEvent::StreamData { .. }))
        {
            break;
        }
    }

    let incoming_idx = server_events
        .iter()
        .position(|e| matches!(e, TransportEvent::IncomingStream { id, .. } if *id == server_conn));
    let data_idx = server_events
        .iter()
        .position(|e| matches!(e, TransportEvent::StreamData { id, .. } if *id == server_conn));

    assert!(incoming_idx.is_some(), "must emit IncomingStream");
    assert!(data_idx.is_some(), "must emit StreamData");
    assert!(
        incoming_idx.unwrap() < data_idx.unwrap(),
        "IncomingStream must precede StreamData"
    );
}

#[test]
fn close_stream_write_produces_remote_write_closed() {
    let (mut server, mut client, peer_addr) = setup_pair();
    let (server_conn, client_conn, _, _) = connect_pair(&mut server, &mut client, &peer_addr);

    let stream_id = client.open_stream(client_conn).expect("open stream");
    client
        .send_stream(client_conn, stream_id, Bytes::from_static(b"data"))
        .expect("send");
    client
        .close_stream_write(client_conn, stream_id)
        .expect("close write");

    let mut saw_remote_write_closed = false;
    for _ in 0..50 {
        let (se, _) = drive_pair_once(&mut server, &mut client);
        if se.iter().any(|e| {
            matches!(e, TransportEvent::StreamRemoteWriteClosed { id, .. } if *id == server_conn)
        }) {
            saw_remote_write_closed = true;
            break;
        }
    }
    assert!(
        saw_remote_write_closed,
        "server must see StreamRemoteWriteClosed"
    );
}

#[test]
fn reset_stream_emits_stream_closed() {
    let (mut server, mut client, peer_addr) = setup_pair();
    let (_, client_conn, _, _) = connect_pair(&mut server, &mut client, &peer_addr);

    let stream_id = client.open_stream(client_conn).expect("open stream");

    client
        .send_stream(client_conn, stream_id, Bytes::from_static(b"hello"))
        .expect("send");

    for _ in 0..10 {
        drive_pair_once(&mut server, &mut client);
    }

    client.reset_stream(client_conn, stream_id).expect("reset");

    let mut saw_closed = false;
    let events = client.poll(common::now()).unwrap();
    if events.iter().any(|e| {
        matches!(e, TransportEvent::StreamClosed { id, stream_id: sid } if *id == client_conn && *sid == stream_id)
    }) {
        saw_closed = true;
    }

    if !saw_closed {
        for _ in 0..20 {
            let (_, ce) = drive_pair_once(&mut server, &mut client);
            if ce.iter().any(|e| {
                matches!(e, TransportEvent::StreamClosed { id, stream_id: sid } if *id == client_conn && *sid == stream_id)
            }) {
                saw_closed = true;
                break;
            }
        }
    }
    assert!(saw_closed, "reset_stream must emit StreamClosed");
}

// ---------------------------------------------------------------------------
// Error conditions
// ---------------------------------------------------------------------------

#[test]
fn open_stream_on_unknown_connection_returns_not_found() {
    let mut transport =
        QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").expect("bind");

    let err = transport
        .open_stream(ConnectionId::new(999))
        .expect_err("must fail");
    assert!(matches!(err, TransportError::ConnectionNotFound { .. }));
}

#[test]
fn send_on_unknown_connection_returns_not_found() {
    let mut transport =
        QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").expect("bind");

    let err = transport
        .send_stream(
            ConnectionId::new(999),
            0.into(),
            Bytes::from_static(b"data"),
        )
        .expect_err("must fail");
    assert!(matches!(err, TransportError::ConnectionNotFound { .. }));
}

/// Events queued between polls must present as work: a host that calls
/// `listen` and then consults the transport before its first `poll` has to be
/// told to come back, or the `Listening` event sits undelivered until some
/// unrelated packet happens to wake the driver.
#[test]
fn events_buffered_outside_poll_report_as_due_work() {
    let mut transport =
        QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").expect("bind");
    transport.listen_on_bound_addr().expect("listen");

    // No time sample has been taken (no `poll` yet) and no datagram is
    // queued, so the buffered event is the only thing that can answer here.
    let deadline = transport
        .next_deadline()
        .expect("a queued event must arm a deadline before the first poll");
    assert!(
        deadline.is_expired_at(Now::from_millis(0)),
        "a buffered event is due on any timeline, got {deadline:?}"
    );
    assert_eq!(
        transport.wait_for_input(std::time::Duration::ZERO),
        WaitOutcome::Ready,
        "wait_for_input must not park while an event is buffered"
    );

    // And the event really is there to collect.
    let events = transport.poll(common::now()).expect("poll");
    assert!(
        events
            .iter()
            .any(|event| matches!(event, TransportEvent::Listening { .. })),
        "the promised work must be the buffered Listening event: {events:?}"
    );

    // Once drained, the idle transport goes back to reporting no work.
    assert_eq!(
        transport.wait_for_input(std::time::Duration::ZERO),
        WaitOutcome::TimedOut,
        "a drained, idle transport must be free to park"
    );
}

/// The dual-stack endpoint does not delegate to the per-family
/// `wait_for_input`, so it needs the same guarantee wired up separately.
#[test]
fn dual_stack_endpoint_reports_buffered_events_as_due_work() {
    let mut endpoint =
        QuicEndpoint::dual_stack(QuicNodeConfig::generate()).expect("dual stack bind");
    let listen_addr = endpoint
        .local_addresses()
        .into_iter()
        .next()
        .expect("bound address");
    endpoint.listen(&listen_addr).expect("listen");

    let deadline = endpoint
        .next_deadline()
        .expect("a queued event must arm a deadline before the first poll");
    assert!(
        deadline.is_expired_at(Now::from_millis(0)),
        "a buffered event is due on any timeline, got {deadline:?}"
    );
    assert_eq!(
        endpoint.wait_for_input(std::time::Duration::ZERO),
        WaitOutcome::Ready,
        "wait_for_input must not park while either family has an event buffered"
    );
}

#[test]
fn poll_returns_empty_when_idle() {
    let mut transport =
        QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").expect("bind");

    let events = transport.poll(common::now()).expect("poll");
    assert!(events.is_empty(), "idle poll must return empty vec");
}
