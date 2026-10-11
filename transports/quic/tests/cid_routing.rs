//! Datagram routing for connections that share one peer address.
//!
//! One raw quinn-proto endpoint on a single socket opens two connections to
//! one `QuicTransport`, so both connections arrive from the same address.
//! Routing must key on connection IDs, never on that shared address.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;
use std::time::Instant;

use minip2p_identity::Ed25519Keypair;
use minip2p_platform::{Clock, Now, StdClock};
use minip2p_quic::{QuicLimits, QuicNodeConfig, QuicTransport};
use minip2p_transport::{Bytes, ConnectionId, Transport, TransportEvent};

#[path = "common/raw.rs"]
#[expect(dead_code, reason = "the rejection helpers serve the handshake tests")]
mod raw;
use raw::{Identity, RawPeer};

static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

fn now() -> Now {
    StdClock::with_epoch(*EPOCH).now()
}

/// A listening transport and one raw endpoint with two established
/// connections to it, both from the endpoint's single socket. Returns the
/// transport's id for each raw connection, in order.
fn connect_twice() -> (QuicTransport, RawPeer, [ConnectionId; 2]) {
    let mut server = QuicTransport::new(
        QuicNodeConfig::generate().with_limits(QuicLimits {
            // Accept each Initial directly, so connection order is creation
            // order.
            require_address_validation: false,
            ..QuicLimits::default()
        }),
        "127.0.0.1:0",
    )
    .expect("server bind");
    server.listen_on_bound_addr().expect("listen");
    let mut client = RawPeer::bind(None);
    for _ in 0..2 {
        client.connect(
            server.local_addr(),
            raw::client_config(Some(Identity::libp2p(&Ed25519Keypair::generate()))),
        );
    }

    let mut connected = Vec::new();
    for _ in 0..500 {
        std::thread::sleep(std::time::Duration::from_millis(2));
        client.pump();
        for event in server.poll(now()).expect("server poll") {
            if let TransportEvent::Connected { id, .. } = event {
                connected.push(id);
            }
        }
        if connected.len() == 2 {
            break;
        }
    }
    let ids: [ConnectionId; 2] = connected.try_into().expect("both connections establish");
    (server, client, ids)
}

#[test]
fn each_connection_from_a_shared_address_gets_only_its_own_data() {
    let (mut server, mut client, _) = connect_twice();

    // Each client connection names itself on a stream; the transport must
    // deliver each label on a different connection.
    for index in 0..2 {
        client.send(index, format!("connection {index}").as_bytes());
    }
    let mut labels: BTreeMap<ConnectionId, (u64, Vec<u8>)> = BTreeMap::new();
    for _ in 0..500 {
        std::thread::sleep(std::time::Duration::from_millis(2));
        client.pump();
        for event in server.poll(now()).expect("server poll") {
            if let TransportEvent::StreamData {
                id,
                stream_id,
                data,
            } = event
            {
                let entry = labels.entry(id).or_insert((stream_id.as_u64(), Vec::new()));
                entry.1.extend_from_slice(&data);
            }
        }
        if labels.len() == 2 && labels.values().all(|(_, label)| label.len() == 12) {
            break;
        }
    }
    let received: BTreeSet<Vec<u8>> = labels.values().map(|(_, label)| label.clone()).collect();
    assert_eq!(
        received,
        BTreeSet::from([b"connection 0".to_vec(), b"connection 1".to_vec()]),
        "each label arrives once, on its own connection"
    );

    // Each connection's reply reaches only the client connection that sent
    // the label.
    for (id, (stream, label)) in &labels {
        let mut reply = b"reply to ".to_vec();
        reply.extend_from_slice(label);
        server
            .send_stream(*id, (*stream).into(), Bytes::from(reply))
            .expect("reply");
    }
    let mut replies = [Vec::new(), Vec::new()];
    for _ in 0..500 {
        std::thread::sleep(std::time::Duration::from_millis(2));
        client.pump();
        server.poll(now()).expect("server poll");
        for (index, reply) in replies.iter_mut().enumerate() {
            reply.extend(client.read(index, 0));
        }
        if replies.iter().all(|reply| reply.len() == 21) {
            break;
        }
    }
    assert_eq!(replies[0], b"reply to connection 0");
    assert_eq!(replies[1], b"reply to connection 1");
}

#[test]
fn unknown_cid_datagrams_from_a_shared_address_leave_both_connections_intact() {
    let (mut server, mut client, ids) = connect_twice();
    let server_addr = server.local_addr();

    // Short header with an unknown DCID (answered with a stateless reset at
    // most), unparseable bytes, and a runt, all from the shared address.
    for junk in [&[0x40u8; 64][..], &[0xff; 64], &[0x00]] {
        client.socket.send_to(junk, server_addr).expect("send junk");
    }
    for _ in 0..10 {
        std::thread::sleep(std::time::Duration::from_millis(2));
        client.pump();
        for event in server.poll(now()).expect("server poll") {
            assert!(
                !matches!(
                    event,
                    TransportEvent::Closed { .. } | TransportEvent::Error { .. }
                ),
                "stray datagrams must not affect any connection: {event:?}"
            );
        }
    }

    for index in 0..2 {
        client.send(index, b"still here");
    }
    let mut delivered = BTreeSet::new();
    for _ in 0..500 {
        std::thread::sleep(std::time::Duration::from_millis(2));
        client.pump();
        for event in server.poll(now()).expect("server poll") {
            if let TransportEvent::StreamData { id, data, .. } = event {
                assert_eq!(&data[..], b"still here");
                delivered.insert(id);
            }
        }
        if delivered.len() == 2 {
            break;
        }
    }
    assert_eq!(
        delivered,
        BTreeSet::from(ids),
        "both connections still deliver data"
    );
    assert!(!client.closed(0) && !client.closed(1));
}
