//! A bare quinn-proto peer on its own loopback socket, pumped by hand.
//!
//! Tests use it where a second `QuicTransport` could not do what they need:
//! send STOP_SENDING without resetting the read half, put frames in one
//! packet, shape the credit it grants, or hold packets back.

use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use minip2p_core::PeerAddr;
use minip2p_identity::Ed25519Keypair;
use minip2p_platform::Now;
use minip2p_transport::{ConnectionId, Transport, TransportEvent};
use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn_proto::{
    ClientConfig, Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig,
    Event, ServerConfig, StreamId, TransportConfig, VarInt,
};

use crate::tls::{HostTime, TlsIdentity};
use crate::{QuicLimits, QuicNodeConfig, QuicTransport, transport_config};

static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Samples the shared test clock.
pub(crate) fn now() -> Now {
    Now::from_millis(EPOCH.elapsed().as_millis() as u64)
}

/// The engine id of a raw stream id.
pub(crate) fn sid(raw: u64) -> StreamId {
    VarInt::from_u64(raw).expect("small stream id").into()
}

pub(crate) struct RawPeer {
    pub(crate) socket: UdpSocket,
    endpoint: Endpoint,
    handle: Option<ConnectionHandle>,
    conn: Option<Connection>,
    /// Application events the engine raised, oldest first.
    pub(crate) events: VecDeque<Event>,
    /// When set, `pump` and `flush` send nothing.
    pub(crate) mute: bool,
}

/// The default engine transport parameters, as the transport itself uses.
pub(crate) fn default_transport() -> TransportConfig {
    transport_config(&QuicLimits::default()).expect("transport config")
}

impl RawPeer {
    fn bind(server_config: Option<Arc<ServerConfig>>) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind raw peer");
        socket.set_nonblocking(true).expect("nonblocking");
        Self {
            socket,
            endpoint: Endpoint::new(
                Arc::new(EndpointConfig::default()),
                server_config,
                true,
                None,
            ),
            handle: None,
            conn: None,
            events: VecDeque::new(),
            mute: false,
        }
    }

    /// Starts a handshake to `server` with a libp2p identity; `tune` adjusts
    /// the credit and limits the peer grants.
    pub(crate) fn connect(server: SocketAddr, tune: impl FnOnce(&mut TransportConfig)) -> Self {
        Self::connect_with(server, client_config(tune))
    }

    /// Starts a handshake to `server` with an arbitrary client config.
    pub(crate) fn connect_with(server: SocketAddr, config: ClientConfig) -> Self {
        let mut peer = Self::bind(None);
        let (handle, conn) = peer
            .endpoint
            .connect(Instant::now(), config, server, "l")
            .expect("connect");
        peer.handle = Some(handle);
        peer.conn = Some(conn);
        peer.pump();
        peer
    }

    /// A listener with a libp2p identity that accepts one connection.
    pub(crate) fn listen(keypair: &Ed25519Keypair) -> Self {
        let tls = TlsIdentity::new(keypair, Arc::new(HostTime::default())).expect("identity");
        let crypto = QuicServerConfig::try_from(tls.server_config().expect("server tls"))
            .expect("quic server tls");
        let mut config = ServerConfig::with_crypto(Arc::new(crypto));
        config.transport_config(Arc::new(default_transport()));
        Self::bind(Some(Arc::new(config)))
    }

    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr().expect("peer addr")
    }

    pub(crate) fn conn(&mut self) -> &mut Connection {
        self.conn.as_mut().expect("a connection")
    }

    /// Receives everything queued on the socket, then services the
    /// connection and sends its output.
    pub(crate) fn pump(&mut self) -> usize {
        let received = self.receive();
        self.service();
        received
    }

    /// Hands every queued datagram to the engine without answering; returns
    /// how many arrived.
    pub(crate) fn receive(&mut self) -> usize {
        let mut buf = vec![0u8; 65_535];
        let mut reply = Vec::new();
        let mut count = 0;
        while let Ok((len, from)) = self.socket.recv_from(&mut buf) {
            count += 1;
            reply.clear();
            let data = BytesMut::from(&buf[..len]);
            match self
                .endpoint
                .handle(Instant::now(), from, None, None, data, &mut reply)
            {
                Some(DatagramEvent::ConnectionEvent(_, event)) => {
                    if let Some(conn) = self.conn.as_mut() {
                        conn.handle_event(event);
                    }
                }
                Some(DatagramEvent::NewConnection(incoming)) => {
                    if self.conn.is_some() {
                        self.endpoint.ignore(incoming);
                        continue;
                    }
                    if let Ok((handle, conn)) =
                        self.endpoint
                            .accept(incoming, Instant::now(), &mut reply, None)
                    {
                        self.handle = Some(handle);
                        self.conn = Some(conn);
                    }
                }
                Some(DatagramEvent::Response(transmit)) if !self.mute => {
                    self.socket
                        .send_to(&reply[..transmit.size], transmit.destination)
                        .expect("peer send");
                }
                Some(DatagramEvent::Response(_)) | None => {}
            }
        }
        count
    }

    /// Services the connection's timers, events and endpoint events, and
    /// sends its output, without receiving anything.
    pub(crate) fn service(&mut self) {
        self.run_engine();
        let Some(conn) = self.conn.as_mut() else {
            return;
        };
        let now = Instant::now();
        let mut buf = Vec::new();
        loop {
            buf.clear();
            let Some(transmit) = conn.poll_transmit(now, 1, &mut buf) else {
                break;
            };
            if !self.mute {
                self.socket
                    .send_to(&buf[..transmit.size], transmit.destination)
                    .expect("peer send");
            }
        }
    }

    /// Runs due timers and collects events, leaving output in the engine.
    pub(crate) fn run_engine(&mut self) {
        let Some(conn) = self.conn.as_mut() else {
            return;
        };
        let now = Instant::now();
        if conn.poll_timeout().is_some_and(|timeout| timeout <= now) {
            conn.handle_timeout(now);
        }
        while let Some(event) = conn.poll() {
            if matches!(
                event,
                Event::Stream(quinn_proto::StreamEvent::Opened { .. })
            ) {
                while conn.streams().accept(Dir::Bi).is_some() {}
            }
            self.events.push_back(event);
        }
        let handle = self.handle.expect("handle");
        while let Some(event) = conn.poll_endpoint_events() {
            if let Some(event) = self.endpoint.handle_event(handle, event) {
                conn.handle_event(event);
            }
        }
    }

    /// Opens the next bidirectional stream; panics without peer credit.
    pub(crate) fn open(&mut self) -> u64 {
        u64::from(self.conn().streams().open(Dir::Bi).expect("stream credit"))
    }

    /// Writes what the stream accepts now.
    pub(crate) fn write(&mut self, stream: u64, data: &[u8]) -> usize {
        self.conn()
            .send_stream(sid(stream))
            .write(data)
            .unwrap_or(0)
    }

    pub(crate) fn finish(&mut self, stream: u64) {
        self.conn()
            .send_stream(sid(stream))
            .finish()
            .expect("finish");
    }

    /// Sends STOP_SENDING; the peer's other half is untouched.
    pub(crate) fn stop(&mut self, stream: u64, code: u32) {
        self.conn()
            .recv_stream(sid(stream))
            .stop(VarInt::from_u32(code))
            .expect("stop");
    }

    /// RESET_STREAM on our send half.
    pub(crate) fn reset(&mut self, stream: u64, code: u32) {
        self.conn()
            .send_stream(sid(stream))
            .reset(VarInt::from_u32(code))
            .expect("reset");
    }

    /// Reads everything readable on `stream`, returning the bytes and FIN.
    pub(crate) fn read(&mut self, stream: u64) -> (Vec<u8>, bool) {
        let mut data = Vec::new();
        let mut recv = self.conn().recv_stream(sid(stream));
        let Ok(mut chunks) = recv.read(true) else {
            return (data, false);
        };
        let fin = loop {
            match chunks.next(usize::MAX) {
                Ok(Some(chunk)) => data.extend_from_slice(&chunk.bytes),
                Ok(None) => break true,
                Err(_) => break false,
            }
        };
        let _credit = chunks.finalize();
        (data, fin)
    }

    /// Whether the connection is closed or gone.
    pub(crate) fn is_closed(&mut self) -> bool {
        self.conn.as_mut().is_none_or(|conn| conn.is_closed())
    }
}

/// A client config with a fresh libp2p identity; `tune` adjusts the credit
/// and limits the peer grants.
pub(crate) fn client_config(tune: impl FnOnce(&mut TransportConfig)) -> ClientConfig {
    let tls = TlsIdentity::new(&Ed25519Keypair::generate(), Arc::new(HostTime::default()))
        .expect("identity");
    let crypto = QuicClientConfig::try_from(tls.client_config(None).expect("client tls"))
        .expect("quic client tls");
    let mut transport = default_transport();
    tune(&mut transport);
    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport));
    config
}

/// Datagrams waiting on `socket`, taken.
pub(crate) fn take_datagrams(socket: &UdpSocket) -> Vec<Vec<u8>> {
    let mut buf = [0u8; 65_535];
    let mut datagrams = Vec::new();
    while let Ok((len, _)) = socket.recv_from(&mut buf) {
        datagrams.push(buf[..len].to_vec());
    }
    datagrams
}

/// A transport bound to one IPv4 loopback socket.
pub(crate) fn loopback(config: QuicNodeConfig) -> QuicTransport {
    let addr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("multiaddr");
    QuicTransport::bind(config, &[addr]).expect("bind loopback")
}

/// The first address other nodes can dial `transport` at.
pub(crate) fn peer_addr(transport: &QuicTransport) -> PeerAddr {
    transport
        .local_peer_addrs()
        .expect("peer addrs")
        .into_iter()
        .next()
        .expect("a bound socket")
}

/// A listening transport on loopback with `limits`.
pub(crate) fn listening_server(limits: QuicLimits) -> QuicTransport {
    let mut server = loopback(QuicNodeConfig::generate().with_limits(limits));
    server.listen_on_bound_addrs().expect("listen");
    server
}

/// A listening transport whose connections idle out after `idle_timeout_ms`.
pub(crate) fn server_with_idle_timeout(idle_timeout_ms: u64) -> QuicTransport {
    listening_server(QuicLimits {
        idle_timeout_ms,
        ..QuicLimits::default()
    })
}

/// Polls the server and pumps the peers until `done` accepts the events seen
/// so far. Every poll must succeed.
pub(crate) fn drive_until(
    server: &mut QuicTransport,
    peers: &mut [&mut RawPeer],
    events: &mut Vec<TransportEvent>,
    what: &str,
    mut done: impl FnMut(&[TransportEvent]) -> bool,
) {
    let start = Instant::now();
    while !done(events) {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timed out waiting for {what}; events: {events:?}"
        );
        std::thread::sleep(Duration::from_millis(1));
        for peer in peers.iter_mut() {
            peer.pump();
        }
        events.extend(server.poll(now()).expect("poll must not fail"));
        for peer in peers.iter_mut() {
            peer.pump();
        }
    }
}

/// Connects a raw peer and returns the server-side connection id.
pub(crate) fn accept(
    server: &mut QuicTransport,
    others: &mut [&mut RawPeer],
    tune: impl FnOnce(&mut TransportConfig),
) -> (RawPeer, ConnectionId) {
    let mut peer = RawPeer::connect(server.local_addr(), tune);
    let mut events = Vec::new();
    let mut peers: Vec<&mut RawPeer> = others.iter_mut().map(|p| &mut **p).collect();
    peers.push(&mut peer);
    drive_until(server, &mut peers, &mut events, "handshake", |events| {
        events
            .iter()
            .any(|event| matches!(event, TransportEvent::Connected { .. }))
    });
    let id = events
        .iter()
        .find_map(|event| match event {
            TransportEvent::Connected { id, .. } => Some(*id),
            _ => None,
        })
        .expect("connected");
    // Let the handshake's trailing packets settle.
    for _ in 0..3 {
        std::thread::sleep(Duration::from_millis(2));
        peer.pump();
        server.poll(now()).expect("poll");
    }
    (peer, id)
}

/// Every `StreamData` byte on `stream` in `events`, in order.
pub(crate) fn stream_bytes(events: &[TransportEvent], stream: u64) -> Vec<u8> {
    events
        .iter()
        .filter_map(|event| match event {
            TransportEvent::StreamData {
                stream_id, data, ..
            } if stream_id.as_u64() == stream => Some(&data[..]),
            _ => None,
        })
        .flatten()
        .copied()
        .collect()
}

/// The size of the allocation behind `data`, which must own it alone.
pub(crate) fn allocation_len(data: Bytes) -> usize {
    data.try_into_mut()
        .map(|unique| unique.capacity())
        .expect("copied stream data owns its allocation")
}
