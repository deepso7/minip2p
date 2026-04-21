//! Transport contract conformance tests.
//!
//! These tests verify the guarantees documented on the `Transport` trait.
//! They run against the QUIC adapter but should pass for any conforming
//! transport implementation.

use minip2p_core::PeerAddr;
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_transport::{ConnectionId, Transport, TransportError, TransportEvent};

// ---------------------------------------------------------------------------
// Helpers (shared with two_peer.rs; duplicated to keep test files independent)
// ---------------------------------------------------------------------------

fn setup_pair() -> (QuicTransport, QuicTransport, PeerAddr) {
    let mut server =
        QuicTransport::new(QuicNodeConfig::dev_listener(), "127.0.0.1:0").expect("server");
    let client =
        QuicTransport::new(QuicNodeConfig::dev_dialer(), "127.0.0.1:0").expect("client");

    server.listen_on_bound_addr().expect("listen");
    let peer_addr = server.local_peer_addr().expect("peer addr");

    (server, client, peer_addr)
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
) -> (ConnectionId, ConnectionId, Vec<TransportEvent>, Vec<TransportEvent>) {
    let client_conn = ConnectionId::new(1);
    client.dial(client_conn, peer_addr).expect("dial");

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
            if let TransportEvent::Connected { id, .. } = e {
                if *id == client_conn {
                    client_connected = true;
                }
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
    (server_conn, client_conn, all_server_events, all_client_events)
}

// ---------------------------------------------------------------------------
// Connection lifecycle
// ---------------------------------------------------------------------------

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

    let incoming_idx = server_events
        .iter()
        .position(|e| matches!(e, TransportEvent::IncomingConnection { id, .. } if *id == server_conn));
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
fn dial_with_duplicate_id_returns_connection_exists() {
    let (mut server, mut client, peer_addr) = setup_pair();
    let id = ConnectionId::new(42);
    client.dial(id, &peer_addr).expect("first dial");

    let err = client.dial(id, &peer_addr).expect_err("duplicate must fail");
    assert!(
        matches!(err, TransportError::ConnectionExists { .. }),
        "expected ConnectionExists, got {err:?}"
    );

    // Drive to avoid dangling state.
    for _ in 0..20 {
        drive_pair_once(&mut server, &mut client);
    }
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
    assert!(
        err.is_err(),
        "open_stream must fail after close"
    );
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

    client
        .reset_stream(client_conn, stream_id)
        .expect("reset");

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
        QuicTransport::new(QuicNodeConfig::dev_listener(), "127.0.0.1:0").expect("bind");

    let err = transport
        .open_stream(ConnectionId::new(999))
        .expect_err("must fail");
    assert!(matches!(err, TransportError::ConnectionNotFound { .. }));
}

#[test]
fn send_on_unknown_connection_returns_not_found() {
    let mut transport =
        QuicTransport::new(QuicNodeConfig::dev_listener(), "127.0.0.1:0").expect("bind");

    let err = transport
        .send_stream(ConnectionId::new(999), 0.into(), b"data".to_vec())
        .expect_err("must fail");
    assert!(matches!(err, TransportError::ConnectionNotFound { .. }));
}

#[test]
fn poll_returns_empty_when_idle() {
    let mut transport =
        QuicTransport::new(QuicNodeConfig::dev_listener(), "127.0.0.1:0").expect("bind");

    let events = transport.poll().expect("poll");
    assert!(events.is_empty(), "idle poll must return empty vec");
}
