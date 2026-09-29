//! Datagram routing for connections that share one peer address.
//!
//! A raw quiche server on a single socket accepts two connections from one
//! `QuicTransport`, so both connections see the same remote address. Routing
//! must key on connection IDs (or the peer's stateless reset token), never on
//! that shared address.

use std::collections::BTreeSet;
use std::net::{SocketAddr, UdpSocket};
use std::sync::LazyLock;
use std::time::Instant;

use minip2p_core::PeerAddr;
use minip2p_identity::Ed25519Keypair;
use minip2p_platform::{Clock, Now, StdClock};
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_transport::{ConnectionId, Transport, TransportEvent};
use quiche::ConnectionId as QuicConnectionId;

static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

fn now() -> Now {
    StdClock::with_epoch(*EPOCH).now()
}

/// Stateless reset token the raw server advertises on its `index`th connection.
fn reset_token(index: usize) -> u128 {
    0x5eed_0000_0000_0000_0000_0000_0000_0000 + index as u128
}

/// A minimal quiche server with a libp2p identity, advertising a distinct
/// stateless reset token per accepted connection.
struct RawServer {
    socket: UdpSocket,
    config: quiche::Config,
    peer_addr: PeerAddr,
    /// Each connection with the client's original destination CID, which the
    /// client keeps using until it learns the server's CID.
    conns: Vec<(Vec<u8>, quiche::Connection)>,
}

impl RawServer {
    fn bind() -> Self {
        use boring::pkey::PKey;
        use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyMode};
        use boring::x509::X509;

        let keypair = Ed25519Keypair::generate();
        let (cert_der, key_der) =
            minip2p_tls::generate_certificate(&keypair).expect("libp2p certificate");
        let mut tls = SslContextBuilder::new(SslMethod::tls()).expect("tls context");
        tls.set_verify_callback(
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
            |_preverify_ok, _ctx| true,
        );
        tls.set_certificate(&X509::from_der(&cert_der).expect("cert"))
            .expect("set cert");
        tls.set_private_key(&PKey::private_key_from_der(&key_der).expect("key"))
            .expect("set key");

        let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls)
            .expect("quiche config");
        config.set_application_protos(&[b"libp2p"]).expect("alpn");
        config.set_initial_max_data(1_000_000);
        config.set_initial_max_stream_data_bidi_local(100_000);
        config.set_initial_max_stream_data_bidi_remote(100_000);
        config.set_initial_max_streams_bidi(10);

        let socket = UdpSocket::bind("127.0.0.1:0").expect("raw server socket");
        socket.set_nonblocking(true).expect("nonblocking");
        let port = socket.local_addr().expect("local addr").port();
        let peer_addr = format!(
            "/ip4/127.0.0.1/udp/{port}/quic-v1/p2p/{}",
            keypair.peer_id()
        )
        .parse()
        .expect("peer addr");

        Self {
            socket,
            config,
            peer_addr,
            conns: Vec::new(),
        }
    }

    /// Accepts, feeds, and flushes every connection once.
    fn pump(&mut self) {
        let local = self.socket.local_addr().expect("local addr");
        let mut buf = [0u8; 65535];
        while let Ok((len, from)) = self.socket.recv_from(&mut buf) {
            let packet = buf.get_mut(..len).expect("received length fits");
            let Ok(header) = quiche::Header::from_slice(packet, quiche::MAX_CONN_ID_LEN) else {
                continue;
            };
            let dcid = header.dcid.as_ref().to_vec();
            let known = self.conns.iter().position(|(odcid, conn)| {
                *odcid == dcid || conn.source_ids().any(|id| id.as_ref() == dcid.as_slice())
            });
            let index = match known {
                Some(index) => index,
                None if header.ty == quiche::Type::Initial => {
                    let index = self.conns.len();
                    self.config
                        .set_stateless_reset_token(Some(reset_token(index)));
                    let scid = QuicConnectionId::from_vec(vec![index as u8 + 1; 20]);
                    let conn = quiche::accept(&scid, None, local, from, &mut self.config)
                        .expect("raw accept");
                    self.conns.push((dcid, conn));
                    index
                }
                None => continue,
            };
            let (_, conn) = self.conns.get_mut(index).expect("known connection");
            let result = conn.recv(packet, quiche::RecvInfo { from, to: local });
            assert!(
                matches!(result, Ok(_) | Err(quiche::Error::Done)),
                "raw server recv failed: {result:?}"
            );
        }

        let mut out = [0u8; 1350];
        for (_, conn) in &mut self.conns {
            while let Ok((written, info)) = conn.send(&mut out) {
                self.socket
                    .send_to(out.get(..written).expect("written fits"), info.to)
                    .expect("raw server send");
            }
        }
    }

    fn send(&self, bytes: &[u8], to: SocketAddr) {
        self.socket.send_to(bytes, to).expect("raw server send");
    }

    /// A stateless reset: a short-header lookalike with an unknown DCID whose
    /// last 16 bytes are `token`.
    fn stateless_reset(token: u128) -> Vec<u8> {
        let mut packet = vec![0x4a; 48];
        packet.extend_from_slice(&token.to_be_bytes());
        packet
    }
}

/// Dials the raw server twice from one client transport and waits until both
/// connections are established. Both connections share the server's address.
fn connect_twice() -> (QuicTransport, RawServer, BTreeSet<ConnectionId>) {
    let mut server = RawServer::bind();
    let mut client =
        QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").expect("client bind");
    let dialed: BTreeSet<_> = (0..2)
        .map(|_| client.dial(&server.peer_addr).expect("dial"))
        .collect();

    let mut connected = BTreeSet::new();
    for _ in 0..200 {
        std::thread::sleep(std::time::Duration::from_millis(5));
        server.pump();
        for event in client.poll(now()).expect("client poll") {
            if let TransportEvent::Connected { id, .. } = event {
                connected.insert(id);
            }
        }
        if connected == dialed {
            break;
        }
    }
    assert_eq!(connected, dialed, "both connections should establish");
    (client, server, dialed)
}

#[test]
fn stateless_reset_closes_the_connection_whose_token_it_carries() {
    let (mut client, mut server, ids) = connect_twice();
    let client_addr = client.local_addr();

    for index in 0..2 {
        server.send(&RawServer::stateless_reset(reset_token(index)), client_addr);
    }

    let mut closed = BTreeSet::new();
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(5));
        server.pump();
        for event in client.poll(now()).expect("client poll") {
            if let TransportEvent::Closed { id } = event {
                closed.insert(id);
            }
        }
        if closed == ids {
            break;
        }
    }
    assert_eq!(closed, ids, "each reset should close its own connection");
}

/// quiche silently discards these packets even when misrouted, so this pins
/// that stray datagrams cannot disturb either connection; the reset test above
/// is the one that fails if routing by source address returns.
#[test]
fn unknown_cid_datagrams_from_a_shared_peer_address_leave_both_connections_intact() {
    let (mut client, mut server, ids) = connect_twice();
    let client_addr = client.local_addr();

    // Short header with an unknown DCID, unparseable bytes, a runt, and a
    // reset carrying a token no connection advertised.
    server.send(&[0x40; 64], client_addr);
    server.send(&[0xff; 64], client_addr);
    server.send(&[0x00], client_addr);
    server.send(&RawServer::stateless_reset(reset_token(7)), client_addr);

    for _ in 0..10 {
        std::thread::sleep(std::time::Duration::from_millis(5));
        server.pump();
        for event in client.poll(now()).expect("client poll") {
            assert!(
                !matches!(
                    event,
                    TransportEvent::Closed { .. } | TransportEvent::Error { .. }
                ),
                "stray datagrams must not affect any connection: {event:?}"
            );
        }
    }

    // Both connections still carry data from the server.
    for (_, conn) in &mut server.conns {
        conn.stream_send(1, b"still here", true)
            .expect("server stream send");
    }
    let mut delivered = BTreeSet::new();
    for _ in 0..100 {
        std::thread::sleep(std::time::Duration::from_millis(5));
        server.pump();
        for event in client.poll(now()).expect("client poll") {
            if let TransportEvent::StreamData { id, data, .. } = event {
                assert_eq!(data, b"still here");
                delivered.insert(id);
            }
        }
        if delivered == ids {
            break;
        }
    }
    assert_eq!(delivered, ids, "both connections should still deliver data");
}
