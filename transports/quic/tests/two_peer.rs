use minip2p_core::{Multiaddr, PeerAddr};
use minip2p_identity::Ed25519Keypair;
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_transport::{
    Bytes, ConnectionCloseReason, ConnectionId, StreamId, Transport, TransportError, TransportEvent,
};

mod common;
#[path = "common/raw.rs"]
#[expect(dead_code, reason = "stream helpers serve the routing tests")]
mod raw;
use common::{drive_pair_once, loopback, peer_addr, setup_pair};
use raw::{Identity, RawPeer};

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
                TransportEvent::Connected { id, .. } if server_conn.is_none() => {
                    server_conn = Some(id);
                }
                _ => {}
            }
        }

        for event in client_events {
            if let TransportEvent::Connected { id, endpoint } = event
                && id == expected_client_conn
            {
                assert_eq!(endpoint.peer_id(), Some(expected_peer.peer_id()));
                client_connected = true;
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

    let client_conn_id = client.dial(&peer_addr).expect("client dial");

    let server_conn_id =
        wait_for_connection(&mut server, &mut client, client_conn_id, &peer_addr, 250)
            .expect("server should observe incoming connection");

    let client_stream = client.open_stream(client_conn_id).expect("open stream");
    client
        .send_stream(
            client_conn_id,
            client_stream,
            Bytes::from_static(b"hello from client"),
        )
        .expect("send stream data");

    let mut server_stream = None;
    for _ in 0..250 {
        let (server_events, client_events) = drive_pair_once(&mut server, &mut client);
        for event in client_events {
            if let TransportEvent::StreamOpened { id, stream_id } = event
                && id == client_conn_id
            {
                assert_eq!(stream_id, client_stream);
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
                    assert_eq!(&data[..], b"hello from client");
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
        .send_stream(
            server_conn_id,
            server_stream,
            Bytes::from_static(b"hello from server"),
        )
        .expect("server response");

    for _ in 0..250 {
        let (_, client_events) = drive_pair_once(&mut server, &mut client);
        for event in client_events {
            if let TransportEvent::StreamData {
                id,
                stream_id,
                data,
            } = event
                && id == client_conn_id
                && stream_id == client_stream
            {
                assert_eq!(&data[..], b"hello from server");
                return;
            }
        }
    }

    panic!("client did not receive server stream data in time");
}

#[test]
fn stream_data_is_preserved_across_connections_and_streams() {
    let (mut server, mut client, peer_addr) = setup_pair();
    let client_connections = [
        client.dial(&peer_addr).expect("first dial"),
        client.dial(&peer_addr).expect("second dial"),
    ];
    let mut connected_client = Vec::new();
    let mut connected_server = Vec::new();

    for _ in 0..250 {
        let (server_events, client_events) = drive_pair_once(&mut server, &mut client);
        for event in server_events {
            if let TransportEvent::Connected { id, .. } = event
                && !connected_server.contains(&id)
            {
                connected_server.push(id);
            }
        }
        for event in client_events {
            if let TransportEvent::Connected { id, .. } = event
                && client_connections.contains(&id)
                && !connected_client.contains(&id)
            {
                connected_client.push(id);
            }
        }
        if connected_client.len() == client_connections.len()
            && connected_server.len() == client_connections.len()
        {
            break;
        }
    }
    assert_eq!(connected_client.len(), client_connections.len());
    assert_eq!(connected_server.len(), client_connections.len());

    let payloads = [
        b"first connection, first stream".to_vec(),
        b"first connection, second stream".to_vec(),
        b"second connection, first stream".to_vec(),
        b"second connection, second stream".to_vec(),
    ];
    for (connection_index, connection) in client_connections.into_iter().enumerate() {
        for stream_index in 0..2 {
            let stream = client.open_stream(connection).expect("open stream");
            client
                .send_stream(
                    connection,
                    stream,
                    Bytes::from(payloads[connection_index * 2 + stream_index].clone()),
                )
                .expect("send stream data");
        }
    }

    let mut received = Vec::new();
    for _ in 0..250 {
        let (server_events, _) = drive_pair_once(&mut server, &mut client);
        for event in server_events {
            if let TransportEvent::StreamData { id, data, .. } = event
                && connected_server.contains(&id)
            {
                received.push(data);
            }
        }
        if received.len() == payloads.len() {
            break;
        }
    }
    received.sort();
    let mut expected = payloads.to_vec();
    expected.sort();
    assert_eq!(received, expected);
}

#[test]
fn close_stream_write_emits_remote_write_closed() {
    let (mut server, mut client, peer_addr) = setup_pair();

    let client_conn_id = client.dial(&peer_addr).expect("dial");

    let server_conn_id =
        wait_for_connection(&mut server, &mut client, client_conn_id, &peer_addr, 250)
            .expect("server connection");

    let client_stream = client.open_stream(client_conn_id).expect("open stream");
    client
        .send_stream(
            client_conn_id,
            client_stream,
            Bytes::from_static(b"payload"),
        )
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
fn close_connection_is_idempotent_after_close_started() {
    let (mut server, mut client, peer_addr) = setup_pair();

    let client_conn_id = client.dial(&peer_addr).expect("dial");
    wait_for_connection(&mut server, &mut client, client_conn_id, &peer_addr, 250)
        .expect("server connection");

    client.close(client_conn_id).expect("first close");
    client
        .close(client_conn_id)
        .expect("a second close is a no-op");
}

/// Polls `transport` and pumps `raw` until the transport reports `Closed`,
/// returning every event it saw.
fn events_until_closed(transport: &mut QuicTransport, raw: &mut RawPeer) -> Vec<TransportEvent> {
    let mut events = Vec::new();
    for _ in 0..1_000 {
        std::thread::sleep(std::time::Duration::from_millis(2));
        raw.pump();
        events.extend(transport.poll(common::now()).expect("poll"));
        raw.pump();
        if events
            .iter()
            .any(|event| matches!(event, TransportEvent::Closed { .. }))
        {
            break;
        }
    }
    events
}

/// The handshake failed inside TLS: the local caller saw `Closed` with an
/// `Error` reason carrying `reason`, and never `Connected` or an identity.
fn assert_rejected(events: &[TransportEvent], reason: &str) {
    assert!(
        events.iter().any(|event| matches!(
            event,
            TransportEvent::Closed { reason: ConnectionCloseReason::Error(message), .. }
                if message.contains(reason)
        )),
        "expected Closed with Error({reason}): {events:?}"
    );
    assert!(
        !events.iter().any(|event| matches!(
            event,
            TransportEvent::Connected { .. } | TransportEvent::PeerIdentityVerified { .. }
        )),
        "a rejected peer must never connect: {events:?}"
    );
}

/// A listener, and a raw client dialing it as `identity`.
fn listener_and_raw_client(identity: Option<Identity>) -> (QuicTransport, RawPeer) {
    let mut server = loopback(QuicNodeConfig::generate());
    server.listen_on_bound_addrs().expect("server listen");
    let mut client = RawPeer::bind(None);
    client.connect(
        server.local_socket_addrs().remove(0),
        raw::client_config(identity),
    );
    (server, client)
}

#[test]
fn listener_rejects_dialer_without_mtls_identity() {
    let (mut server, mut client) = listener_and_raw_client(None);
    let events = events_until_closed(&mut server, &mut client);
    assert_rejected(&events, "peer sent no certificates");
}

#[test]
fn dialer_rejects_listener_with_unexpected_peer_id() {
    let mut listener_a = loopback(QuicNodeConfig::generate());
    let listener_b = loopback(QuicNodeConfig::generate());
    let mut dialer = loopback(QuicNodeConfig::generate());
    listener_a.listen_on_bound_addrs().expect("listen a");

    let listener_a_addr = peer_addr(&listener_a);
    let wrong_peer_addr = PeerAddr::new(
        listener_a_addr.transport().clone(),
        listener_b.local_peer_id(),
    )
    .expect("peer addr");
    dialer.dial(&wrong_peer_addr).expect("dial starts");

    let mut events = Vec::new();
    for _ in 0..1_000 {
        std::thread::sleep(std::time::Duration::from_millis(2));
        listener_a.poll(common::now()).expect("listener a poll");
        events.extend(dialer.poll(common::now()).expect("dialer poll"));
        if events
            .iter()
            .any(|event| matches!(event, TransportEvent::Closed { .. }))
        {
            break;
        }
    }
    assert_rejected(&events, "peer id mismatch");
}

#[test]
fn listener_rejects_dialer_with_invalid_libp2p_cert() {
    let (mut server, mut client) = listener_and_raw_client(Some(Identity::invalid()));
    let events = events_until_closed(&mut server, &mut client);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, TransportEvent::IncomingConnection { .. })),
        "the listener may surface the pre-auth incoming connection: {events:?}"
    );
    assert_rejected(&events, "peer TLS certificate verification failed");
}

#[test]
fn listener_rejects_dialer_presenting_certificate_chain() {
    let (mut server, mut client) =
        listener_and_raw_client(Some(Identity::chain(&Ed25519Keypair::generate())));
    let events = events_until_closed(&mut server, &mut client);
    assert_rejected(&events, "presented 2 certificates");
    client.pump();
    assert!(client.closed(0), "the listener must close the connection");
}

#[test]
fn dialer_rejects_listener_presenting_certificate_chain() {
    let keypair = Ed25519Keypair::generate();
    let mut server = RawPeer::bind(Some(raw::server_config(Identity::chain(&keypair))));
    let mut dialer = loopback(QuicNodeConfig::generate());
    dialer
        .dial(&server.peer_addr(&keypair))
        .expect("dial starts");

    let events = events_until_closed(&mut dialer, &mut server);
    assert_rejected(&events, "presented 2 certificates");
    server.pump();
    assert!(server.closed(0), "the dialer must close the connection");
}

#[test]
fn mtls_verifies_listener_side_client_identity() {
    let (mut server, mut client, peer_addr) = setup_pair();
    let client_peer_id = client.local_peer_id();

    let client_conn_id = client.dial(&peer_addr).expect("client dial");

    let mut verified_event = None;
    let mut server_connected = None;

    for _ in 0..250 {
        let (server_events, client_events) = drive_pair_once(&mut server, &mut client);

        for event in server_events {
            match event {
                TransportEvent::PeerIdentityVerified {
                    id,
                    endpoint,
                    previous_peer_id,
                } => verified_event = Some((id, endpoint, previous_peer_id)),
                TransportEvent::Connected { id, endpoint } => {
                    server_connected = Some((id, endpoint));
                }
                _ => {}
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

    // `Connected` already carries the verified identity.
    let (connected_id, endpoint) = server_connected.expect("server connected");
    assert_eq!(connected_id, verified_event.0);
    assert_eq!(endpoint.peer_id(), Some(&client_peer_id));
}

#[test]
fn listen_rejects_address_mismatch_with_bound_socket() {
    let config = QuicNodeConfig::generate();
    let mut transport = loopback(config);

    let local = transport.local_socket_addrs().remove(0);
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

    let events = transport
        .poll(common::now())
        .expect("poll should still work");
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TransportEvent::Listening { .. })),
        "listening event must not be emitted on failed listen"
    );
}

#[test]
fn open_stream_before_connected_returns_invalid_state() {
    let mut listener = loopback(QuicNodeConfig::generate());
    listener.listen_on_bound_addrs().expect("listen");
    let peer_addr = peer_addr(&listener);

    let mut dialer = loopback(QuicNodeConfig::generate());

    let conn_id = dialer.dial(&peer_addr).expect("dial");

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

/// Native WebTransport is not dialable or listenable yet: both say so with
/// `Unsupported`, which callers choosing between candidates read as "not
/// here", and point at the `/quic-v1` address instead.
#[test]
fn webtransport_addresses_are_unsupported_with_a_quic_v1_hint() {
    let (mut server, mut client, server_addr) = setup_pair();
    let webtransport = |transport: &Multiaddr| {
        format!("{transport}/webtransport/certhash/uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g")
            .parse::<Multiaddr>()
            .expect("webtransport multiaddr")
    };
    let target = PeerAddr::new(
        webtransport(server_addr.transport()),
        server_addr.peer_id().clone(),
    )
    .expect("peer addr");

    let err = client.dial(&target).expect_err("dial must refuse");
    assert!(
        matches!(err, TransportError::Unsupported { .. }),
        "dial: {err:?}"
    );
    assert!(err.to_string().contains("/quic-v1"), "dial: {err}");

    let listen = webtransport(server_addr.transport()).without_certhashes();
    let err = server.listen(&listen).expect_err("listen must refuse");
    assert!(
        matches!(err, TransportError::Unsupported { .. }),
        "listen: {err:?}"
    );
    assert!(err.to_string().contains("/quic-v1"), "listen: {err}");
}
