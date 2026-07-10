//! Transport contract conformance tests.
//!
//! These tests verify the guarantees documented on the `Transport` trait.
//! They run against the QUIC adapter but should pass for any conforming
//! transport implementation.

use minip2p_core::{PeerAddr, Protocol};
use minip2p_quic::{QuicEndpoint, QuicLimits, QuicNodeConfig, QuicTransport};
use minip2p_transport::{ConnectionId, Transport, TransportError, TransportEvent};

// ---------------------------------------------------------------------------
// Helpers (shared with two_peer.rs; duplicated to keep test files independent)
// ---------------------------------------------------------------------------

fn setup_pair() -> (QuicTransport, QuicTransport, PeerAddr) {
    let mut server = QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").expect("server");
    let client = QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").expect("client");

    server.listen_on_bound_addr().expect("listen");
    let peer_addr = server.local_peer_addr().expect("peer addr");

    (server, client, peer_addr)
}

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

fn drive_pair_once(
    server: &mut QuicTransport,
    client: &mut QuicTransport,
) -> (Vec<TransportEvent>, Vec<TransportEvent>) {
    std::thread::sleep(std::time::Duration::from_millis(5));
    let s = server.poll().expect("server poll");
    let c = client.poll().expect("client poll");
    (s, c)
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
    let requested = listener.local_multiaddr().expect("local multiaddr");

    let resolved = listener.listen(&requested).expect("listen");
    assert_eq!(resolved, requested);

    let events = listener.poll().expect("poll");
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

    for event in &client_events[..connected_idx] {
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
fn pending_stream_byte_limit_rejects_oversized_write() {
    let limits = QuicLimits {
        max_pending_stream_bytes: 8,
        ..QuicLimits::default()
    };
    let (mut server, mut client, peer_addr) = setup_pair_with_client_limits(limits);
    let (_, client_conn, _, _) = connect_pair(&mut server, &mut client, &peer_addr);
    let stream = client.open_stream(client_conn).expect("open stream");

    let error = client
        .send_stream(client_conn, stream, vec![0; 9])
        .expect_err("oversized queued write must fail");
    assert!(matches!(
        error,
        TransportError::ResourceExhausted {
            resource: "queued QUIC stream bytes"
        }
    ));
}

#[test]
fn quic_deadline_is_exposed_and_driven_without_socket_input() {
    let limits = QuicLimits {
        idle_timeout_ms: 50,
        ..QuicLimits::default()
    };
    let (mut server, mut client, peer_addr) = setup_pair_with_client_limits(limits);
    let (_, conn_id, _, _) = connect_pair(&mut server, &mut client, &peer_addr);
    assert!(
        client.next_timeout().is_some(),
        "connected QUIC session must arm a timer"
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    let mut closed = false;
    while std::time::Instant::now() < deadline {
        closed |= client
            .poll()
            .expect("poll")
            .into_iter()
            .any(|event| matches!(event, TransportEvent::Closed { id, .. } if id == conn_id));
        if closed {
            break;
        }
        let sleep = client
            .next_timeout()
            .unwrap_or(std::time::Duration::from_millis(1))
            .min(std::time::Duration::from_millis(5));
        if !sleep.is_zero() {
            std::thread::sleep(sleep);
        }
    }
    assert!(closed, "QUIC timeout must close a silent dial");
}

#[test]
fn close_rejects_further_stream_operations() {
    let (mut server, mut client, peer_addr) = setup_pair();
    let (_, client_conn, _, _) = connect_pair(&mut server, &mut client, &peer_addr);

    // Open a stream first so we can test send after close.
    let stream_id = client.open_stream(client_conn).expect("open stream");
    client
        .send_stream(client_conn, stream_id, b"data".to_vec())
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
                .poll()
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
        .send_stream(client_conn, stream_id, b"hello".to_vec())
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
        .send_stream(client_conn, stream_id, b"data".to_vec())
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
        .send_stream(client_conn, stream_id, b"hello".to_vec())
        .expect("send");

    for _ in 0..10 {
        drive_pair_once(&mut server, &mut client);
    }

    client.reset_stream(client_conn, stream_id).expect("reset");

    let mut saw_closed = false;
    let events = client.poll().unwrap();
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
        .send_stream(ConnectionId::new(999), 0.into(), b"data".to_vec())
        .expect_err("must fail");
    assert!(matches!(err, TransportError::ConnectionNotFound { .. }));
}

#[test]
fn poll_returns_empty_when_idle() {
    let mut transport =
        QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").expect("bind");

    let events = transport.poll().expect("poll");
    assert!(events.is_empty(), "idle poll must return empty vec");
}
