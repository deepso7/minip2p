use minip2p_core::PeerAddr;
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_transport::{ConnectionId, StreamId, Transport, TransportError, TransportEvent};

fn setup_pair() -> (QuicTransport, QuicTransport, PeerAddr) {
    let mut server =
        QuicTransport::new(QuicNodeConfig::dev_listener(), "127.0.0.1:0").expect("server bind");
    let client =
        QuicTransport::new(QuicNodeConfig::dev_dialer(), "127.0.0.1:0").expect("client bind");

    server.listen_on_bound_addr().expect("server listen");
    let peer_addr = server.local_peer_addr().expect("peer addr");

    (server, client, peer_addr)
}

fn drive_pair_once(
    server: &mut QuicTransport,
    client: &mut QuicTransport,
) -> (Vec<TransportEvent>, Vec<TransportEvent>) {
    std::thread::sleep(std::time::Duration::from_millis(5));
    let server_events = server.poll().expect("server poll");
    let client_events = client.poll().expect("client poll");
    (server_events, client_events)
}

fn wait_for_connection(
    server: &mut QuicTransport,
    client: &mut QuicTransport,
    expected_client_conn: ConnectionId,
    expected_peer: &PeerAddr,
    max_iters: usize,
) -> Option<ConnectionId> {
    let mut server_conn = None;
    let mut client_connected = false;

    for _ in 0..max_iters {
        let (server_events, client_events) = drive_pair_once(server, client);

        for event in server_events {
            match event {
                TransportEvent::IncomingConnection { id, endpoint } => {
                    assert!(endpoint.peer_id().is_none());
                    server_conn = Some(id);
                }
                TransportEvent::Connected { id, .. } => {
                    if server_conn.is_none() {
                        server_conn = Some(id);
                    }
                }
                _ => {}
            }
        }

        for event in client_events {
            if let TransportEvent::Connected { id, endpoint } = event {
                if id == expected_client_conn {
                    assert_eq!(endpoint.peer_id(), Some(expected_peer.peer_id()));
                    client_connected = true;
                }
            }
        }

        if client_connected && server_conn.is_some() {
            return server_conn;
        }
    }

    None
}

#[test]
fn two_peers_open_stream_and_exchange_data() {
    let (mut server, mut client, peer_addr) = setup_pair();

    let client_conn_id = ConnectionId::new(1);
    client
        .dial(client_conn_id, &peer_addr)
        .expect("client dial");

    let server_conn_id =
        wait_for_connection(&mut server, &mut client, client_conn_id, &peer_addr, 250)
            .expect("server should observe incoming connection");

    let client_stream = client.open_stream(client_conn_id).expect("open stream");
    client
        .send_stream(client_conn_id, client_stream, b"hello from client".to_vec())
        .expect("send stream data");

    let mut server_stream = None;
    for _ in 0..250 {
        let (server_events, client_events) = drive_pair_once(&mut server, &mut client);
        for event in client_events {
            if let TransportEvent::StreamOpened { id, stream_id } = event {
                if id == client_conn_id {
                    assert_eq!(stream_id, client_stream);
                }
            }
        }

        for event in server_events {
            match event {
                TransportEvent::IncomingStream { id, stream_id } => {
                    assert_eq!(id, server_conn_id);
                    server_stream = Some(stream_id);
                }
                TransportEvent::StreamData {
                    id,
                    stream_id,
                    data,
                } => {
                    assert_eq!(id, server_conn_id);
                    assert_eq!(data, b"hello from client");
                    server_stream = Some(stream_id);
                }
                _ => {}
            }
        }

        if server_stream.is_some() {
            break;
        }
    }

    let server_stream = server_stream.expect("server should see stream and data");
    server
        .send_stream(server_conn_id, server_stream, b"hello from server".to_vec())
        .expect("server response");

    for _ in 0..250 {
        let (_, client_events) = drive_pair_once(&mut server, &mut client);
        for event in client_events {
            if let TransportEvent::StreamData {
                id,
                stream_id,
                data,
            } = event
            {
                if id == client_conn_id && stream_id == client_stream {
                    assert_eq!(data, b"hello from server");
                    return;
                }
            }
        }
    }

    panic!("client did not receive server stream data in time");
}

#[test]
fn close_stream_write_emits_remote_write_closed() {
    let (mut server, mut client, peer_addr) = setup_pair();

    let client_conn_id = ConnectionId::new(5);
    client.dial(client_conn_id, &peer_addr).expect("dial");

    let server_conn_id =
        wait_for_connection(&mut server, &mut client, client_conn_id, &peer_addr, 250)
            .expect("server connection");

    let client_stream = client.open_stream(client_conn_id).expect("open stream");
    client
        .send_stream(client_conn_id, client_stream, b"payload".to_vec())
        .expect("send payload");
    client
        .close_stream_write(client_conn_id, client_stream)
        .expect("close write");

    let mut server_saw_remote_write_closed = false;
    let mut server_stream = None;

    for _ in 0..250 {
        let (server_events, _) = drive_pair_once(&mut server, &mut client);
        for event in server_events {
            match event {
                TransportEvent::IncomingStream { stream_id, .. } => {
                    server_stream = Some(stream_id);
                }
                TransportEvent::StreamRemoteWriteClosed { id, stream_id } => {
                    assert_eq!(id, server_conn_id);
                    server_stream = Some(stream_id);
                    server_saw_remote_write_closed = true;
                }
                _ => {}
            }
        }

        if server_saw_remote_write_closed {
            break;
        }
    }

    assert!(
        server_saw_remote_write_closed,
        "server should observe remote write close"
    );

    let server_stream = server_stream.expect("server stream id should be known");
    server
        .close_stream_write(server_conn_id, server_stream)
        .expect("server close write");

    for _ in 0..250 {
        let (_, client_events) = drive_pair_once(&mut server, &mut client);
        if client_events.iter().any(|event| {
            matches!(
                event,
                TransportEvent::StreamRemoteWriteClosed { id, stream_id }
                if *id == client_conn_id && *stream_id == client_stream
            )
        }) {
            return;
        }
    }

    panic!("client should observe server close stream write");
}

#[test]
fn listen_without_tls_returns_config_error_and_no_listening_event() {
    let config = QuicNodeConfig::new();
    let mut transport = QuicTransport::new(config, "127.0.0.1:0").expect("bind");

    let err = transport
        .listen_on_bound_addr()
        .expect_err("listen should fail");
    assert!(matches!(err, TransportError::InvalidConfig { .. }));

    let events = transport.poll().expect("poll should still work");
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TransportEvent::Listening { .. })),
        "listening event must not be emitted on failed listen"
    );
}

#[test]
fn listener_rejects_dialer_without_mtls_identity() {
    let mut server =
        QuicTransport::new(QuicNodeConfig::dev_listener(), "127.0.0.1:0").expect("server bind");
    let mut anonymous_client =
        QuicTransport::new(QuicNodeConfig::new(), "127.0.0.1:0").expect("client bind");

    server.listen_on_bound_addr().expect("server listen");
    let peer_addr = server.local_peer_addr().expect("peer addr");

    let err = anonymous_client
        .dial(ConnectionId::new(77), &peer_addr)
        .expect_err("anonymous client must not start mTLS dial");
    assert!(matches!(err, TransportError::InvalidConfig { .. }));

    let server_events = server.poll().expect("server poll");
    assert!(
        server_events.iter().all(|event| !matches!(
            event,
            TransportEvent::IncomingConnection { .. }
                | TransportEvent::Connected { .. }
                | TransportEvent::PeerIdentityVerified { .. }
        )),
        "anonymous dial must not reach the listener"
    );
}

#[test]
fn mtls_verifies_listener_side_client_identity_and_updates_peer_index() {
    let (mut server, mut client, peer_addr) = setup_pair();
    let client_peer_id = client.local_peer_id().expect("client peer id");

    let client_conn_id = ConnectionId::new(42);
    client
        .dial(client_conn_id, &peer_addr)
        .expect("client dial");

    let mut verified_event = None;

    for _ in 0..250 {
        let (server_events, client_events) = drive_pair_once(&mut server, &mut client);

        for event in server_events {
            if let TransportEvent::PeerIdentityVerified {
                id,
                endpoint,
                previous_peer_id,
            } = event
            {
                verified_event = Some((id, endpoint, previous_peer_id));
            }
        }

        let client_connected = client_events.iter().any(
            |event| matches!(event, TransportEvent::Connected { id, .. } if *id == client_conn_id),
        );

        if verified_event.is_some() && client_connected {
            break;
        }
    }

    let verified_event = verified_event.expect("peer identity verified event");

    assert_eq!(verified_event.1.peer_id(), Some(&client_peer_id));
    assert!(verified_event.2.is_none());

    let indexed = server.connection_ids_for_peer(&client_peer_id);
    assert_eq!(indexed, vec![verified_event.0]);
}

#[test]
fn dial_supports_dns4_target_for_quic_transport() {
    let (mut server, mut client, peer_addr) = setup_pair();

    let port = match peer_addr.transport().protocols().get(1) {
        Some(minip2p_core::Protocol::Udp(port)) => *port,
        _ => panic!("peer transport must contain udp port"),
    };

    let dns_transport = minip2p_core::Multiaddr::from_protocols(vec![
        minip2p_core::Protocol::Dns4("localhost".to_string()),
        minip2p_core::Protocol::Udp(port),
        minip2p_core::Protocol::QuicV1,
    ]);
    let dns_peer_addr =
        PeerAddr::new(dns_transport, peer_addr.peer_id().clone()).expect("dns peer addr");

    let conn_id = ConnectionId::new(77);
    client.dial(conn_id, &dns_peer_addr).expect("dial via dns4");

    let connected = wait_for_connection(&mut server, &mut client, conn_id, &dns_peer_addr, 250);
    assert!(connected.is_some(), "client should connect via dns4 target");
}

#[test]
fn listen_rejects_address_mismatch_with_bound_socket() {
    let config = QuicNodeConfig::dev_listener();
    let mut transport = QuicTransport::new(config, "127.0.0.1:0").expect("bind");

    let local = transport.local_addr().expect("local addr");
    let mismatched_port = if local.port() == u16::MAX {
        local.port() - 1
    } else {
        local.port() + 1
    };

    let listen_ma = minip2p_core::Multiaddr::from_protocols(vec![
        minip2p_core::Protocol::Ip4([127, 0, 0, 1]),
        minip2p_core::Protocol::Udp(mismatched_port),
        minip2p_core::Protocol::QuicV1,
    ]);
    let err = transport
        .listen(&listen_ma)
        .expect_err("listen with mismatched address should fail");

    assert!(matches!(
        err,
        TransportError::InvalidAddress {
            context: "listen address",
            ..
        }
    ));

    let events = transport.poll().expect("poll should still work");
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TransportEvent::Listening { .. })),
        "listening event must not be emitted on failed listen"
    );
}

#[test]
fn open_stream_before_connected_returns_invalid_state() {
    let mut listener =
        QuicTransport::new(QuicNodeConfig::dev_listener(), "127.0.0.1:0").expect("listener");
    listener.listen_on_bound_addr().expect("listen");
    let peer_addr = listener.local_peer_addr().expect("peer addr");

    let mut dialer =
        QuicTransport::new(QuicNodeConfig::dev_dialer(), "127.0.0.1:0").expect("dialer");

    let conn_id = ConnectionId::new(999);
    dialer.dial(conn_id, &peer_addr).expect("dial");

    let err = dialer
        .open_stream(conn_id)
        .expect_err("open stream before connected should fail");
    assert!(matches!(err, TransportError::InvalidState { .. }));
}

#[test]
fn stream_id_round_trips_as_u64() {
    let id = StreamId::new(1234);
    assert_eq!(id.as_u64(), 1234);
}
