//! A bare quinn-proto peer with hand-built rustls configs, for tests that
//! need a peer the transport would never be: one presenting no certificate,
//! a chain, or an invalid libp2p certificate.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Instant;

use bytes::BytesMut;
use minip2p_core::PeerAddr;
use minip2p_identity::Ed25519Keypair;
use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn_proto::{
    ClientConfig, Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig,
    Event, ServerConfig, StreamId, VarInt,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

/// Accepts any peer, so the transport under test is the only judge.
#[derive(Debug)]
struct AcceptAnything;

impl ServerCertVerifier for AcceptAnything {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ClientCertVerifier for AcceptAnything {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::ring::default_provider()
}

/// A certificate chain and the key that signs the handshake.
pub struct Identity {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

impl Identity {
    /// A valid libp2p certificate for `keypair`.
    pub fn libp2p(keypair: &Ed25519Keypair) -> Self {
        let (cert, key) = minip2p_tls::generate_certificate(keypair).expect("certificate");
        Self {
            chain: vec![CertificateDer::from(cert)],
            key: PrivateKeyDer::try_from(key).expect("pkcs8 key"),
        }
    }

    /// A valid libp2p leaf followed by a second certificate.
    pub fn chain(keypair: &Ed25519Keypair) -> Self {
        let mut identity = Self::libp2p(keypair);
        let (extra, _) =
            minip2p_tls::generate_certificate(&Ed25519Keypair::generate()).expect("extra");
        identity.chain.push(CertificateDer::from(extra));
        identity
    }

    /// A libp2p certificate whose self-signature no longer verifies.
    pub fn invalid() -> Self {
        let mut identity = Self::libp2p(&Ed25519Keypair::generate());
        let mut cert = identity.chain.first().expect("leaf").to_vec();
        *cert.last_mut().expect("non-empty certificate") ^= 0x01;
        identity.chain = vec![CertificateDer::from(cert)];
        identity
    }

    fn certified(self) -> Arc<rustls::sign::CertifiedKey> {
        let key = provider()
            .key_provider
            .load_private_key(self.key)
            .expect("signing key");
        Arc::new(rustls::sign::CertifiedKey::new(self.chain, key))
    }
}

/// A client config presenting `identity`, or no certificate at all.
pub fn client_config(identity: Option<Identity>) -> ClientConfig {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnything));
    let mut tls = match identity {
        Some(identity) => builder.with_client_cert_resolver(Arc::new(
            rustls::sign::SingleCertAndKey::from(identity.certified()),
        )),
        None => builder.with_no_client_auth(),
    };
    tls.alpn_protocols = vec![b"libp2p".to_vec()];
    ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).expect("quic client tls"),
    ))
}

/// A server config presenting `identity` and accepting any client.
pub fn server_config(identity: Identity) -> ServerConfig {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .with_client_cert_verifier(Arc::new(AcceptAnything))
        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
            identity.certified(),
        )));
    tls.alpn_protocols = vec![b"libp2p".to_vec()];
    ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(tls).expect("quic server tls"),
    ))
}

/// A quinn-proto endpoint on one loopback socket, with any number of
/// connections, pumped by hand.
pub struct RawPeer {
    pub socket: UdpSocket,
    endpoint: Endpoint,
    pub conns: Vec<(ConnectionHandle, Connection)>,
}

impl RawPeer {
    pub fn bind(server: Option<ServerConfig>) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind raw peer");
        socket.set_nonblocking(true).expect("nonblocking");
        Self {
            socket,
            endpoint: Endpoint::new(
                Arc::new(EndpointConfig::default()),
                server.map(Arc::new),
                true,
                None,
            ),
            conns: Vec::new(),
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr().expect("local addr")
    }

    /// A `PeerAddr` naming this peer as `keypair`'s identity.
    pub fn peer_addr(&self, keypair: &Ed25519Keypair) -> PeerAddr {
        format!(
            "/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{}",
            self.local_addr().port(),
            keypair.peer_id()
        )
        .parse()
        .expect("peer addr")
    }

    /// Starts a connection to `server`; returns its index in `conns`.
    pub fn connect(&mut self, server: SocketAddr, config: ClientConfig) -> usize {
        let (handle, conn) = self
            .endpoint
            .connect(Instant::now(), config, server, "l")
            .expect("connect");
        self.conns.push((handle, conn));
        self.pump();
        self.conns.len() - 1
    }

    /// Receives everything queued, accepting new connections, then services
    /// every connection and sends its output.
    pub fn pump(&mut self) {
        let now = Instant::now();
        let mut buf = vec![0u8; 65_535];
        let mut reply = Vec::new();
        while let Ok((len, from)) = self.socket.recv_from(&mut buf) {
            reply.clear();
            match self.endpoint.handle(
                now,
                from,
                None,
                None,
                BytesMut::from(buf.get(..len).expect("received length fits")),
                &mut reply,
            ) {
                Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                    if let Some((_, conn)) = self.conns.iter_mut().find(|(h, _)| *h == handle) {
                        conn.handle_event(event);
                    }
                }
                Some(DatagramEvent::NewConnection(incoming)) => {
                    if let Ok(accepted) = self.endpoint.accept(incoming, now, &mut reply, None) {
                        self.conns.push(accepted);
                    }
                }
                Some(DatagramEvent::Response(transmit)) => {
                    send(&self.socket, &reply, &transmit);
                }
                None => {}
            }
        }
        for (handle, conn) in &mut self.conns {
            if conn.poll_timeout().is_some_and(|timeout| timeout <= now) {
                conn.handle_timeout(now);
            }
            while let Some(event) = conn.poll() {
                if let Event::Stream(quinn_proto::StreamEvent::Opened { .. }) = event {
                    while conn.streams().accept(Dir::Bi).is_some() {}
                }
            }
            while let Some(event) = conn.poll_endpoint_events() {
                if let Some(event) = self.endpoint.handle_event(*handle, event) {
                    conn.handle_event(event);
                }
            }
            loop {
                reply.clear();
                let Some(transmit) = conn.poll_transmit(now, 1, &mut reply) else {
                    break;
                };
                send(&self.socket, &reply, &transmit);
            }
        }
    }

    /// Writes `data` and FIN on a new stream of connection `index`.
    pub fn send(&mut self, index: usize, data: &[u8]) {
        let conn = self.conn(index);
        let stream = conn.streams().open(Dir::Bi).expect("stream credit");
        assert_eq!(
            conn.send_stream(stream).write(data).expect("write"),
            data.len()
        );
        conn.send_stream(stream).finish().expect("finish");
    }

    /// Everything readable on stream `raw` of connection `index`.
    pub fn read(&mut self, index: usize, raw: u64) -> Vec<u8> {
        let conn = self.conn(index);
        let id = StreamId::from(VarInt::from_u64(raw).expect("stream id"));
        let mut data = Vec::new();
        let mut recv = conn.recv_stream(id);
        if let Ok(mut chunks) = recv.read(true) {
            while let Ok(Some(chunk)) = chunks.next(usize::MAX) {
                data.extend_from_slice(&chunk.bytes);
            }
            let _credit = chunks.finalize();
        }
        data
    }

    fn conn(&mut self, index: usize) -> &mut Connection {
        &mut self.conns.get_mut(index).expect("connection index").1
    }

    /// Whether connection `index` has closed or been lost.
    pub fn closed(&self, index: usize) -> bool {
        self.conns
            .get(index)
            .is_some_and(|(_, conn)| conn.is_closed())
    }
}

/// Sends a transmit the engine wrote into `buf`.
fn send(socket: &UdpSocket, buf: &[u8], transmit: &quinn_proto::Transmit) {
    socket
        .send_to(
            buf.get(..transmit.size).expect("transmit fits its buffer"),
            transmit.destination,
        )
        .expect("raw send");
}
