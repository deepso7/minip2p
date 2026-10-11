//! A minimal caller-driven quinn-proto peer over one non-blocking UDP socket.
//!
//! No async: the caller samples time, calls `drive(now)`, and waits on the
//! socket until `next_timeout()`.

use std::collections::{HashMap, VecDeque};
use std::io::IoSliceMut;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use minip2p_core::PeerId;
use minip2p_identity::Ed25519Keypair;
use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn_proto::{
    ClientConfig, Connection, ConnectionHandle, DatagramEvent, Endpoint, EndpointConfig, Event,
    ServerConfig, Transmit, TransportConfig, VarInt,
};

use crate::tls;

pub struct Options {
    /// Use quinn-udp (GSO/GRO, recvmmsg-style batching, ECN) instead of
    /// plain `send_to`/`recv_from`.
    pub quinn_udp: bool,
    /// Stateless Retry on every new connection.
    pub require_address_validation: bool,
}

pub struct Peer {
    pub socket: UdpSocket,
    udp: Option<quinn_udp::UdpSocketState>,
    endpoint: Endpoint,
    conns: HashMap<ConnectionHandle, Connection>,
    client_config: ClientConfig,
    require_address_validation: bool,
    pub events: VecDeque<(ConnectionHandle, Event)>,
    pub closed: Vec<ConnectionHandle>,
    send_buf: Vec<u8>,
    recv_buf: Vec<u8>,
    /// Datagrams held after `WouldBlock`.
    pending: VecDeque<(Vec<u8>, SocketAddr, Option<usize>)>,
    max_gso: usize,
    recv_saturated: bool,
    pub stats: PeerStats,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct PeerStats {
    pub send_calls: u64,
    pub datagrams_sent: u64,
    pub recv_calls: u64,
    pub datagrams_received: u64,
}

pub fn transport_config() -> TransportConfig {
    let mut t = TransportConfig::default();
    // Same pinned windows as the quiche adapter (ADR 0012).
    t.stream_receive_window(VarInt::from_u32(1_000_000));
    t.receive_window(VarInt::from_u32(10_000_000));
    t.send_window(10_000_000);
    t.max_concurrent_bidi_streams(VarInt::from_u32(256));
    t.max_concurrent_uni_streams(VarInt::from_u32(0));
    t.max_idle_timeout(Some(VarInt::from_u32(30_000).into()));
    t.keep_alive_interval(Some(Duration::from_secs(15)));
    if let Ok(mtu) = std::env::var("QMTU") {
        // Fixed payload size, no PMTU discovery: matches quiche's 1350.
        let mtu: u16 = mtu.parse().expect("QMTU");
        t.initial_mtu(mtu).min_mtu(mtu).mtu_discovery_config(None);
    }
    t
}

impl Peer {
    pub fn new(keypair: &Ed25519Keypair, bind: &str, opts: Options) -> Self {
        let socket = UdpSocket::bind(bind).expect("bind");
        socket.set_nonblocking(true).expect("nonblocking");
        let udp = opts
            .quinn_udp
            .then(|| quinn_udp::UdpSocketState::new((&socket).into()).expect("udp state"));
        let max_gso = udp.as_ref().map_or(1, |u| u.max_gso_segments().min(10));

        let transport = Arc::new(transport_config());
        let mut server = ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(tls::server_config(keypair)).expect("quic server cfg"),
        ));
        server.transport_config(transport.clone());
        let mut client = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(tls::client_config(keypair)).expect("quic client cfg"),
        ));
        client.transport_config(transport);

        let endpoint = Endpoint::new(
            Arc::new(EndpointConfig::default()),
            Some(Arc::new(server)),
            true,
            None,
        );
        Self {
            socket,
            udp,
            endpoint,
            conns: HashMap::new(),
            client_config: client,
            require_address_validation: opts.require_address_validation,
            events: VecDeque::new(),
            closed: Vec::new(),
            send_buf: Vec::with_capacity(64 * 1024),
            recv_buf: vec![0; 64 * 1024],
            pending: VecDeque::new(),
            max_gso,
            recv_saturated: false,
            stats: PeerStats::default(),
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr().expect("local addr")
    }

    pub fn connect(&mut self, now: Instant, remote: SocketAddr) -> ConnectionHandle {
        let (ch, conn) = self
            .endpoint
            .connect(now, self.client_config.clone(), remote, "l")
            .expect("connect");
        self.conns.insert(ch, conn);
        ch
    }

    pub fn conn(&mut self, ch: ConnectionHandle) -> &mut Connection {
        self.conns.get_mut(&ch).expect("live connection")
    }

    pub fn has_conn(&self, ch: ConnectionHandle) -> bool {
        self.conns.contains_key(&ch)
    }

    /// The peer id proven by the handshake's single certificate.
    pub fn peer_id(&self, ch: ConnectionHandle) -> Option<PeerId> {
        let identity = self.conns.get(&ch)?.crypto_session().peer_identity()?;
        let certs = identity
            .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
            .ok()?;
        let [leaf] = certs.as_slice() else { return None };
        minip2p_tls::verify_libp2p_certificate(leaf, unix_now()).ok()
    }

    /// Same value on both ends, bound to the TLS session.
    pub fn connection_token(&self, ch: ConnectionHandle) -> Option<[u8; 32]> {
        let mut out = [0u8; 32];
        self.conns
            .get(&ch)?
            .crypto_session()
            .export_keying_material(&mut out, b"minip2p connection token", b"")
            .ok()?;
        Some(out)
    }

    pub fn next_timeout(&mut self) -> Option<Instant> {
        if self.recv_saturated || !self.pending.is_empty() || !self.events.is_empty() {
            return Some(Instant::now());
        }
        self.conns.values_mut().filter_map(Connection::poll_timeout).min()
    }

    /// One poll: receive a bounded batch, then service every connection.
    pub fn drive(&mut self, now: Instant) {
        self.flush_pending();
        self.recv_batch(now);
        let handles: Vec<ConnectionHandle> = self.conns.keys().copied().collect();
        for ch in handles {
            self.service(ch, now);
        }
    }

    fn recv_batch(&mut self, now: Instant) {
        self.recv_saturated = true;
        for _ in 0..128 {
            let (len, from, stride) = match &self.udp {
                Some(udp) => {
                    let mut meta = [quinn_udp::RecvMeta::default()];
                    let mut bufs = [IoSliceMut::new(&mut self.recv_buf)];
                    match udp.recv((&self.socket).into(), &mut bufs, &mut meta) {
                        Ok(_) => (meta[0].len, meta[0].addr, meta[0].stride),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => { self.recv_saturated = false; break }
                        Err(e) => panic!("recv: {e}"),
                    }
                }
                None => match self.socket.recv_from(&mut self.recv_buf) {
                    Ok((len, from)) => (len, from, len),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => { self.recv_saturated = false; break }
                    Err(e) => panic!("recv: {e}"),
                },
            };
            self.stats.recv_calls += 1;
            let mut data = BytesMut::from(&self.recv_buf[..len]);
            while !data.is_empty() {
                let datagram = data.split_to(stride.min(data.len()));
                self.stats.datagrams_received += 1;
                self.handle_datagram(now, from, datagram);
            }
        }
    }

    fn handle_datagram(&mut self, now: Instant, from: SocketAddr, data: BytesMut) {
        let mut buf = Vec::new();
        match self.endpoint.handle(now, from, None, None, data, &mut buf) {
            Some(DatagramEvent::ConnectionEvent(ch, event)) => {
                if let Some(conn) = self.conns.get_mut(&ch) {
                    conn.handle_event(event);
                }
            }
            Some(DatagramEvent::NewConnection(incoming)) => {
                if self.require_address_validation && !incoming.remote_address_validated() {
                    let t = self.endpoint.retry(incoming, &mut buf).expect("retry");
                    self.send(&t, &buf.clone());
                    return;
                }
                match self.endpoint.accept(incoming, now, &mut buf, None) {
                    Ok((ch, conn)) => {
                        self.conns.insert(ch, conn);
                    }
                    Err(err) => {
                        if let Some(t) = err.response {
                            self.send(&t, &buf.clone());
                        }
                    }
                }
            }
            Some(DatagramEvent::Response(t)) => self.send(&t, &buf.clone()),
            None => {}
        }
    }

    fn service(&mut self, ch: ConnectionHandle, now: Instant) {
        let Some(mut conn) = self.conns.remove(&ch) else { return };
        if conn.poll_timeout().is_some_and(|t| t <= now) {
            conn.handle_timeout(now);
        }
        while let Some(event) = conn.poll() {
            self.events.push_back((ch, event));
        }
        loop {
            if !self.pending.is_empty() {
                break;
            }
            let mut buf = std::mem::take(&mut self.send_buf);
            buf.clear();
            let Some(t) = conn.poll_transmit(now, self.max_gso, &mut buf) else {
                self.send_buf = buf;
                break;
            };
            self.send(&t, &buf);
            self.send_buf = buf;
        }
        while let Some(ev) = conn.poll_endpoint_events() {
            if let Some(cev) = self.endpoint.handle_event(ch, ev) {
                conn.handle_event(cev);
            }
        }
        if conn.is_drained() {
            self.closed.push(ch);
        } else {
            self.conns.insert(ch, conn);
        }
    }

    /// Re-services `ch` after the caller acted on it (wrote, read, opened).
    pub fn kick(&mut self, ch: ConnectionHandle, now: Instant) {
        self.service(ch, now);
    }

    fn send(&mut self, t: &Transmit, buf: &[u8]) {
        let contents = &buf[..t.size];
        if !self.pending.is_empty() || !self.try_send(contents, t.destination, t.segment_size) {
            self.pending
                .push_back((contents.to_vec(), t.destination, t.segment_size));
        }
    }

    fn try_send(&mut self, contents: &[u8], dest: SocketAddr, segment_size: Option<usize>) -> bool {
        self.stats.send_calls += 1;
        let datagrams = segment_size.map_or(1, |s| contents.len().div_ceil(s)) as u64;
        let result = match &self.udp {
            Some(udp) => udp.try_send(
                (&self.socket).into(),
                &quinn_udp::Transmit {
                    destination: dest,
                    ecn: None,
                    contents,
                    segment_size,
                    src_ip: None,
                },
            ),
            None => self.socket.send_to(contents, dest).map(|_| ()),
        };
        match result {
            Ok(()) => {
                self.stats.datagrams_sent += datagrams;
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(_) => true, // treat as lost
        }
    }

    fn flush_pending(&mut self) {
        while let Some((bytes, dest, seg)) = self.pending.pop_front() {
            if !self.try_send(&bytes, dest, seg) {
                self.pending.push_front((bytes, dest, seg));
                break;
            }
        }
    }
}

pub fn unix_now() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
}
