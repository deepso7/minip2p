use std::net::UdpSocket;

use minip2p_core::PeerAddr;
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_transport::{ConnectionId, StreamId, Transport, TransportError, TransportEvent};
use quiche::ConnectionId as QuicConnectionId;

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
fn dialer_rejects_listener_with_unexpected_peer_id() {
    let mut listener_a =
        QuicTransport::new(QuicNodeConfig::dev_listener(), "127.0.0.1:0").expect("listener a");
    let mut listener_b =
        QuicTransport::new(QuicNodeConfig::dev_listener(), "127.0.0.1:0").expect("listener b");
    let mut dialer =
        QuicTransport::new(QuicNodeConfig::dev_dialer(), "127.0.0.1:0").expect("dialer");

    listener_a.listen_on_bound_addr().expect("listen a");
    listener_b.listen_on_bound_addr().expect("listen b");

    let listener_a_addr = listener_a.local_peer_addr().expect("listener a addr");
    let listener_b_peer = listener_b.local_peer_id().expect("listener b peer id");
    let wrong_peer_addr =
        PeerAddr::new(listener_a_addr.transport().clone(), listener_b_peer).expect("peer addr");

    let conn_id = ConnectionId::new(88);
    dialer.dial(conn_id, &wrong_peer_addr).expect("dial starts");

    let mut saw_mismatch = false;
    let mut saw_connected = false;

    for _ in 0..100 {
        std::thread::sleep(std::time::Duration::from_millis(5));
        let _ = listener_a.poll().expect("listener a poll");
        let events = dialer.poll().expect("dialer poll");

        saw_mismatch |= events.iter().any(|event| {
            matches!(event, TransportEvent::Error { message, .. } if message.contains("peer id mismatch"))
        });
        saw_connected |= events
            .iter()
            .any(|event| matches!(event, TransportEvent::Connected { .. }));

        if saw_mismatch {
            break;
        }
    }

    assert!(saw_mismatch, "dialer must report peer id mismatch");
    assert!(!saw_connected, "dialer must not connect wrong peer id");
}

#[test]
fn listener_rejects_dialer_with_invalid_libp2p_cert() {
    let mut server =
        QuicTransport::new(QuicNodeConfig::dev_listener(), "127.0.0.1:0").expect("server bind");
    server.listen_on_bound_addr().expect("server listen");
    let server_addr = server.local_addr().expect("server socket addr");

    let client_socket = UdpSocket::bind("127.0.0.1:0").expect("client socket");
    client_socket
        .set_nonblocking(true)
        .expect("client socket nonblocking");
    let client_addr = client_socket.local_addr().expect("client local addr");

    let mut config = vanilla_tls_quiche_config();
    let scid = QuicConnectionId::from_vec(vec![0x42; quiche::MAX_CONN_ID_LEN]);
    let mut conn = quiche::connect(None, &scid, client_addr, server_addr, &mut config)
        .expect("raw quiche connect");

    flush_raw_quiche_client(&mut conn, &client_socket);

    let mut saw_incoming = false;
    let mut saw_cert_error = false;
    let mut saw_connected = false;
    let mut saw_verified = false;

    for _ in 0..100 {
        std::thread::sleep(std::time::Duration::from_millis(5));

        for event in server.poll().expect("server poll") {
            saw_incoming |= matches!(event, TransportEvent::IncomingConnection { .. });
            saw_cert_error |= matches!(
                event,
                TransportEvent::Error { ref message, .. }
                    if message.contains("peer TLS certificate verification failed")
            );
            saw_connected |= matches!(event, TransportEvent::Connected { .. });
            saw_verified |= matches!(event, TransportEvent::PeerIdentityVerified { .. });
        }

        drain_raw_quiche_client(&mut conn, &client_socket, client_addr);
        flush_raw_quiche_client(&mut conn, &client_socket);

        if saw_cert_error || conn.is_closed() {
            break;
        }
    }

    assert!(
        saw_incoming,
        "listener may surface pre-auth incoming connection"
    );
    assert!(saw_cert_error, "listener must reject invalid libp2p cert");
    assert!(
        !saw_connected,
        "listener must not connect invalid libp2p cert"
    );
    assert!(
        !saw_verified,
        "listener must not verify invalid libp2p cert"
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

fn vanilla_tls_quiche_config() -> quiche::Config {
    use boring::asn1::Asn1Time;
    use boring::hash::MessageDigest;
    use boring::nid::Nid;
    use boring::pkey::PKey;
    use boring::rsa::Rsa;
    use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyMode};
    use boring::x509::{X509, X509Name};

    let rsa = Rsa::generate(2048).expect("rsa key");
    let pkey = PKey::from_rsa(rsa).expect("pkey");

    let mut name = X509Name::builder().expect("name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, "invalid-libp2p-cert")
        .expect("common name");
    let name = name.build();

    let mut cert = X509::builder().expect("x509 builder");
    cert.set_version(2).expect("version");
    cert.set_subject_name(&name).expect("subject");
    cert.set_issuer_name(&name).expect("issuer");
    cert.set_not_before(&Asn1Time::days_from_now(0).expect("not before"))
        .expect("set not before");
    cert.set_not_after(&Asn1Time::days_from_now(365).expect("not after"))
        .expect("set not after");
    cert.set_pubkey(&pkey).expect("pubkey");
    cert.sign(&pkey, MessageDigest::sha256())
        .expect("sign cert");
    let cert = cert.build();

    let mut tls = SslContextBuilder::new(SslMethod::tls()).expect("tls context");
    tls.set_verify_callback(
        SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        |_preverify_ok, _ctx| true,
    );
    tls.set_certificate(&cert).expect("set cert");
    tls.set_private_key(&pkey).expect("set key");
    tls.check_private_key().expect("check key");

    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls)
        .expect("quiche config");
    config.set_application_protos(&[b"libp2p"]).expect("alpn");
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
    config
}

fn flush_raw_quiche_client(conn: &mut quiche::Connection, socket: &UdpSocket) {
    let mut out = [0u8; 1350];
    loop {
        match conn.send(&mut out) {
            Ok((written, send_info)) => {
                socket
                    .send_to(&out[..written], send_info.to)
                    .expect("raw client send");
            }
            Err(quiche::Error::Done) => break,
            Err(e) => panic!("raw client send failed: {e}"),
        }
    }
}

fn drain_raw_quiche_client(
    conn: &mut quiche::Connection,
    socket: &UdpSocket,
    local: std::net::SocketAddr,
) {
    let mut buf = [0u8; 65535];
    loop {
        let (len, from) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("raw client recv failed: {e}"),
        };
        let recv_info = quiche::RecvInfo { from, to: local };
        match conn.recv(&mut buf[..len], recv_info) {
            Ok(_) | Err(quiche::Error::Done) => {}
            Err(e) => panic!("raw client quiche recv failed: {e}"),
        }
    }
}
