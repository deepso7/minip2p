//! ALPN dispatch: which protocols a socket offers, and that only an
//! authenticated libp2p connection ever surfaces events.

use std::time::{Duration, Instant};

use minip2p_identity::Ed25519Keypair;
use minip2p_transport::ConnectionCloseReason;
use quinn_proto::crypto::rustls::HandshakeData;
use quinn_proto::{ConnectionError, Dir, Event, StreamEvent};

use super::*;
use crate::test_peer::{
    AnyServer, RawPeer, accept, drive_until, foreign_client_config, loopback, now,
};

const H3: &[u8] = b"h3";
const LIBP2P: &[u8] = b"libp2p";

/// A listening transport on loopback without WebTransport.
fn quic_v1_server() -> QuicTransport {
    let mut server = loopback(QuicNodeConfig::generate());
    server.listen_on_bound_addrs().expect("listen");
    server
}

/// Pumps until the raw peer's connection is gone; returns the server's
/// events.
fn drive_until_peer_closed(server: &mut QuicTransport, peer: &mut RawPeer) -> Vec<TransportEvent> {
    let mut events = Vec::new();
    let start = Instant::now();
    while !peer.is_closed() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "the peer was never closed; server events: {events:?}"
        );
        std::thread::sleep(Duration::from_millis(1));
        peer.pump();
        events.extend(server.poll(now()).expect("poll"));
    }
    events
}

/// The error the raw peer's connection was lost with.
fn lost_reason(peer: &RawPeer) -> ConnectionError {
    peer.events
        .iter()
        .find_map(|event| match event {
            Event::ConnectionLost { reason } => Some(reason.clone()),
            _ => None,
        })
        .expect("a ConnectionLost")
}

/// The TLS alert a handshake failure carried, as QUIC's CRYPTO_ERROR range.
fn crypto_alert(reason: &ConnectionError) -> Option<u8> {
    match reason {
        ConnectionError::ConnectionClosed(close) => {
            let code = u64::from(close.error_code);
            (0x100..0x200).contains(&code).then(|| (code - 0x100) as u8)
        }
        _ => None,
    }
}

#[test]
fn a_quic_v1_only_socket_offers_only_libp2p() {
    let mut server = quic_v1_server();
    let mut h3 = RawPeer::connect_with(
        server.local_addr(),
        foreign_client_config(&[H3], None, Arc::default()),
    );
    let events = drive_until_peer_closed(&mut server, &mut h3);
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TransportEvent::Connected { .. })),
        "{events:?}"
    );
    // TLS's no_application_protocol alert.
    assert_eq!(crypto_alert(&lost_reason(&h3)), Some(120), "{events:?}");
}

/// `quic-v1` and WebTransport bound on one loopback socket.
fn dual_loopback(config: QuicNodeConfig) -> QuicTransport {
    let addrs = [
        "/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("multiaddr"),
        "/ip4/127.0.0.1/udp/0/quic-v1/webtransport"
            .parse()
            .expect("multiaddr"),
    ];
    QuicTransport::bind(config, &addrs).expect("bind")
}

/// A listening transport on loopback that also serves WebTransport.
fn dual_server() -> QuicTransport {
    let mut server = dual_loopback(QuicNodeConfig::generate());
    server.listen_on_bound_addrs().expect("listen");
    server
}

/// Pumps a client until its side of the handshake completes, then has
/// `queue` write into the engine before the client's final flight leaves, so
/// the server receives it with the client's Finished.
fn handshake_then(
    peer: &mut RawPeer,
    server: &mut QuicTransport,
    queue: impl FnOnce(&mut RawPeer),
) -> Vec<TransportEvent> {
    let mut events = Vec::new();
    let start = Instant::now();
    loop {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "no handshake: {events:?}"
        );
        std::thread::sleep(Duration::from_millis(1));
        events.extend(server.poll(now()).expect("poll"));
        peer.receive();
        peer.run_engine();
        if peer
            .events
            .iter()
            .any(|event| matches!(event, Event::Connected))
        {
            queue(peer);
            peer.service();
            return events;
        }
        peer.service();
    }
}

/// Opens a unidirectional stream; panics without peer credit.
fn open_uni(peer: &mut RawPeer) -> u64 {
    u64::from(
        peer.conn()
            .streams()
            .open(Dir::Uni)
            .expect("unidirectional credit"),
    )
}

/// The ALPN the raw peer's handshake negotiated.
fn negotiated(peer: &mut RawPeer) -> Option<Vec<u8>> {
    peer.conn()
        .crypto_session()
        .handshake_data()?
        .downcast::<HandshakeData>()
        .ok()?
        .protocol
}

/// Drives until the server reports `Closed`, which it must.
fn drive_until_server_closed(
    server: &mut QuicTransport,
    peer: &mut RawPeer,
    events: &mut Vec<TransportEvent>,
) {
    drive_until(server, &mut [peer], events, "Closed", |events| {
        events
            .iter()
            .any(|event| matches!(event, TransportEvent::Closed { .. }))
    });
}

/// Asserts the server surfaced nothing for the connection but its arrival
/// and its `Closed`.
fn assert_only_arrival_and_close(events: &[TransportEvent]) {
    assert!(
        events.iter().all(|event| matches!(
            event,
            TransportEvent::Listening { .. }
                | TransportEvent::IncomingConnection { .. }
                | TransportEvent::Closed { .. }
        )),
        "{events:?}"
    );
}

#[test]
fn a_libp2p_peer_without_a_certificate_never_connects_on_a_dual_alpn_socket() {
    let mut server = dual_server();
    let mut peer = RawPeer::connect_with(
        server.local_addr(),
        foreign_client_config(&[LIBP2P], None, Arc::default()),
    );
    let mut events = handshake_then(&mut peer, &mut server, |peer| {
        let stream = peer.open();
        assert_eq!(peer.write(stream, b"early"), 5);
        let uni = open_uni(peer);
        assert_eq!(peer.write(uni, b"early"), 5);
    });
    assert_eq!(negotiated(&mut peer).as_deref(), Some(LIBP2P));
    drive_until_server_closed(&mut server, &mut peer, &mut events);
    assert_only_arrival_and_close(&events);
}

#[test]
fn a_client_offering_both_alpns_without_a_certificate_is_negotiated_as_libp2p_and_rejected() {
    let mut server = dual_server();
    let mut peer = RawPeer::connect_with(
        server.local_addr(),
        foreign_client_config(&[H3, LIBP2P], None, Arc::default()),
    );
    let mut events = handshake_then(&mut peer, &mut server, |_| {});
    assert_eq!(
        negotiated(&mut peer).as_deref(),
        Some(LIBP2P),
        "the server's preference wins"
    );
    drive_until_server_closed(&mut server, &mut peer, &mut events);
    assert_only_arrival_and_close(&events);
}

#[test]
fn an_h3_client_gets_the_webtransport_certificate_and_no_connection_before_noise() {
    let keypair = Ed25519Keypair::generate();
    let mut server = dual_loopback(QuicNodeConfig::new(keypair.clone()));
    server.listen_on_bound_addrs().expect("listen");
    let seen = Arc::new(AnyServer::default());
    let mut peer = RawPeer::connect_with(
        server.local_addr(),
        foreign_client_config(&[H3], None, Arc::clone(&seen)),
    );
    let mut events = handshake_then(&mut peer, &mut server, |_| {});
    assert_eq!(negotiated(&mut peer).as_deref(), Some(H3));
    let period = minip2p_tls::webtransport::period_at(tls::system_time().as_secs());
    let (expected, _) =
        minip2p_tls::webtransport::webtransport_certificate(&keypair, period).expect("cert");
    assert_eq!(seen.seen(), Some(expected));

    // A client that never authenticates is never reported.
    peer.conn().close(
        Instant::now(),
        quinn_proto::VarInt::from_u32(0),
        Bytes::new(),
    );
    drive_until_server_closed(&mut server, &mut peer, &mut events);
    assert_only_arrival_and_close(&events);
}

#[test]
fn an_h3_only_socket_offers_only_h3() {
    let addr = "/ip4/127.0.0.1/udp/0/quic-v1/webtransport"
        .parse()
        .expect("multiaddr");
    let mut server = QuicTransport::bind(QuicNodeConfig::generate(), &[addr]).expect("bind");
    server.listen_on_bound_addrs().expect("listen");
    let mut libp2p = RawPeer::connect(server.local_addr(), |_| {});
    let events = drive_until_peer_closed(&mut server, &mut libp2p);
    // TLS's no_application_protocol alert.
    assert_eq!(crypto_alert(&lost_reason(&libp2p)), Some(120), "{events:?}");
}

#[test]
fn an_invalid_libp2p_certificate_under_h3_is_rejected_inside_the_handshake() {
    let mut server = dual_server();
    // A well-formed certificate without the libp2p extension.
    let invalid =
        minip2p_tls::webtransport::webtransport_certificate(&Ed25519Keypair::generate(), 1)
            .expect("cert");
    let mut peer = RawPeer::connect_with(
        server.local_addr(),
        foreign_client_config(&[H3], Some(invalid), Arc::default()),
    );
    let mut events = drive_until_peer_closed(&mut server, &mut peer);
    // TLS's certificate_unknown alert, not the application close a failed
    // check after the handshake would send.
    assert_eq!(crypto_alert(&lost_reason(&peer)), Some(46), "{events:?}");
    drive_until_server_closed(&mut server, &mut peer, &mut events);
    assert_only_arrival_and_close(&events);
}

#[test]
fn a_quic_v1_only_socket_grants_no_unidirectional_streams_or_datagrams() {
    let mut server = quic_v1_server();
    let (mut peer, _) = accept(&mut server, &mut [], |_| {});
    assert!(peer.conn().streams().open(Dir::Uni).is_none());
    assert_eq!(peer.conn().datagrams().max_size(), None);
}

#[test]
fn a_peer_unidirectional_stream_on_a_libp2p_connection_is_stopped_and_never_surfaced() {
    let mut server = dual_server();
    // The peer enables DATAGRAM itself, or it may not send any.
    let (mut peer, id) = accept(&mut server, &mut [], |config| {
        config.datagram_receive_buffer_size(Some(1024));
    });
    let uni = open_uni(&mut peer);
    assert_eq!(peer.write(uni, b"control"), 7);
    // Datagrams are drained and dropped.
    peer.conn()
        .datagrams()
        .send(Bytes::from_static(b"datagram"), true)
        .expect("the socket advertises DATAGRAM");

    let mut events = Vec::new();
    let start = Instant::now();
    while !peer.events.iter().any(|event| {
        matches!(event, Event::Stream(StreamEvent::Stopped { id, .. }) if u64::from(*id) == uni)
    }) {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "no STOP_SENDING; server events: {events:?}"
        );
        std::thread::sleep(Duration::from_millis(1));
        peer.pump();
        events.extend(server.poll(now()).expect("poll"));
    }
    assert!(events.is_empty(), "{events:?}");
    let conn = server.connections.get_mut(&id).expect("still connected");
    assert!(conn.engine().datagrams().recv().is_none());
}

/// A peer that opened streams with data (`uni` too) that the server's
/// engine has received but not yet surfaced when the server closes yields
/// only `Closed`.
fn close_racing_incoming_streams(mut server: QuicTransport, uni: bool) {
    let (mut peer, id) = accept(&mut server, &mut [], |_| {});
    let stream = peer.open();
    assert_eq!(peer.write(stream, b"racing"), 6);
    if uni {
        let uni = open_uni(&mut peer);
        assert_eq!(peer.write(uni, b"racing"), 6);
    }
    peer.service();
    std::thread::sleep(Duration::from_millis(20));
    // Into the engine without a service, so the stream events are still
    // queued there when the close runs one.
    server.recv_batch(Instant::now(), 0).expect("receive");
    server.close(id).expect("close");

    let mut events = Vec::new();
    drive_until(
        &mut server,
        &mut [&mut peer],
        &mut events,
        "Closed",
        |events| {
            events
                .iter()
                .any(|event| matches!(event, TransportEvent::Closed { .. }))
        },
    );
    assert_eq!(
        events,
        [TransportEvent::Closed {
            id,
            reason: ConnectionCloseReason::Local
        }]
    );
}

#[test]
fn close_racing_an_incoming_stream_and_data_yields_only_closed() {
    close_racing_incoming_streams(quic_v1_server(), false);
}

#[test]
fn close_racing_incoming_streams_on_a_dual_alpn_socket_yields_only_closed() {
    close_racing_incoming_streams(dual_server(), true);
}
