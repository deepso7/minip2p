use std::net::UdpSocket;
use std::sync::atomic::{AtomicU64, Ordering};

use minip2p_core::{Multiaddr, PeerAddr, Protocol};
use minip2p_transport::{ConnectionId, ConnectionState, Transport, TransportError, TransportEvent};
use quiche::ConnectionId as QuicConnectionId;

mod config;
mod connection;

pub use config::QuicConfig;

use connection::QuicConnection;

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

fn next_connection_id() -> ConnectionId {
    ConnectionId::new(NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed))
}

fn extract_socket_addr(multiaddr: &Multiaddr) -> Result<std::net::SocketAddr, TransportError> {
    let protocols = multiaddr.protocols();
    let mut ip: Option<std::net::IpAddr> = None;
    let mut port: Option<u16> = None;

    for proto in protocols {
        match proto {
            Protocol::Ip4(bytes) => {
                ip = Some(std::net::IpAddr::from(*bytes));
            }
            Protocol::Ip6(bytes) => {
                ip = Some(std::net::IpAddr::from(*bytes));
            }
            Protocol::Udp(p) => {
                port = Some(*p);
            }
            _ => {}
        }
    }

    let ip = ip.ok_or_else(|| TransportError::DialFailed {
        id: ConnectionId::new(0),
        reason: "no ip address in multiaddr".into(),
    })?;
    let port = port.ok_or_else(|| TransportError::DialFailed {
        id: ConnectionId::new(0),
        reason: "no udp port in multiaddr".into(),
    })?;

    Ok(std::net::SocketAddr::new(ip, port))
}

pub struct QuicTransport {
    socket: UdpSocket,
    quiche_config: quiche::Config,
    connections: std::collections::HashMap<ConnectionId, QuicConnection>,
    pending_events: Vec<TransportEvent>,
    listen_addr: Option<std::net::SocketAddr>,
    config: QuicConfig,
}

impl QuicTransport {
    pub fn new(config: QuicConfig, bind_addr: &str) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(bind_addr).map_err(|e| {
            TransportError::ListenFailed {
                reason: format!("failed to bind udp socket: {e}"),
            }
        })?;
        socket.set_nonblocking(true).map_err(|e| {
            TransportError::ListenFailed {
                reason: format!("failed to set nonblocking: {e}"),
            }
        })?;

        let mut quiche_config = quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|e| {
            TransportError::ListenFailed {
                reason: format!("failed to create quiche config: {e}"),
            }
        })?;

        quiche_config
            .set_application_protos(&[b"libp2p"])
            .map_err(|e| TransportError::ListenFailed {
                reason: format!("failed to set alpn: {e}"),
            })?;

        quiche_config.set_initial_max_data(10_000_000);
        quiche_config.set_initial_max_stream_data_bidi_local(1_000_000);
        quiche_config.set_initial_max_stream_data_bidi_remote(1_000_000);
        quiche_config.set_initial_max_streams_bidi(100);
        quiche_config.set_max_recv_udp_payload_size(1350);
        quiche_config.set_max_send_udp_payload_size(1350);
        quiche_config.verify_peer(config.verify_peer);

        if let Some(cert_path) = &config.cert_chain_path {
            quiche_config
                .load_cert_chain_from_pem_file(cert_path)
                .map_err(|e| TransportError::ListenFailed {
                    reason: format!("failed to load cert chain: {e}"),
                })?;
        }

        if let Some(key_path) = &config.priv_key_path {
            quiche_config
                .load_priv_key_from_pem_file(key_path)
                .map_err(|e| TransportError::ListenFailed {
                    reason: format!("failed to load private key: {e}"),
                })?;
        }

        Ok(Self {
            socket,
            quiche_config,
            connections: std::collections::HashMap::new(),
            pending_events: Vec::new(),
            listen_addr: None,
            config,
        })
    }

    pub fn local_addr(&self) -> Result<std::net::SocketAddr, TransportError> {
        self.socket.local_addr().map_err(|e| TransportError::PollError {
            reason: format!("failed to get local addr: {e}"),
        })
    }

    fn generate_scid() -> QuicConnectionId<'static> {
        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
        getrandom::fill(&mut scid).expect("rng failure");
        QuicConnectionId::from_vec(scid.to_vec())
    }
}

impl Transport for QuicTransport {
    fn dial(&mut self, id: ConnectionId, addr: &PeerAddr) -> Result<(), TransportError> {
        if self.connections.contains_key(&id) {
            return Err(TransportError::ConnectionExists { id });
        }

        let peer_socket = extract_socket_addr(addr.transport())?;
        let local_socket = self.local_addr()?;

        let scid = Self::generate_scid();
        let mut quiche_conn = quiche::connect(
            None,
            &scid,
            local_socket,
            peer_socket,
            &mut self.quiche_config,
        )
        .map_err(|e| TransportError::DialFailed {
            id,
            reason: format!("quiche connect error: {e}"),
        })?;

        let mut out = [0u8; 1350];
        loop {
            let (written, send_info) = match quiche_conn.send(&mut out) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    return Err(TransportError::DialFailed {
                        id,
                        reason: format!("initial send error: {e}"),
                    });
                }
            };

            self.socket
                .send_to(&out[..written], send_info.to)
                .map_err(|e| TransportError::DialFailed {
                    id,
                    reason: format!("udp send error: {e}"),
                })?;
        }

        let conn = QuicConnection::new(id, quiche_conn, peer_socket);
        self.connections.insert(id, conn);

        Ok(())
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<(), TransportError> {
        let _socket_addr = extract_socket_addr(addr)?;
        self.listen_addr = Some(_socket_addr);

        if self.config.cert_chain_path.is_none() || self.config.priv_key_path.is_none() {
            return Err(TransportError::ListenFailed {
                reason: "server requires cert_chain_path and priv_key_path".into(),
            });
        }

        self.pending_events.push(TransportEvent::Listening {
            addr: addr.clone(),
        });

        Ok(())
    }

    fn send(&mut self, id: ConnectionId, data: Vec<u8>) -> Result<(), TransportError> {
        let conn = self
            .connections
            .get_mut(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;

        if conn.state() != ConnectionState::Connected {
            return Err(TransportError::InvalidState {
                id,
                state: conn.state(),
                expected: ConnectionState::Connected,
            });
        }

        conn.send_data(&data, &self.socket)?;

        Ok(())
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        let conn = self
            .connections
            .get_mut(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;

        conn.close(&self.socket)?;

        Ok(())
    }

    fn poll(&mut self) -> Result<Vec<TransportEvent>, TransportError> {
        let mut buf = [0u8; 65535];
        let mut events = std::mem::take(&mut self.pending_events);

        loop {
            let (len, from) = match self.socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    return Err(TransportError::PollError {
                        reason: format!("udp recv error: {e}"),
                    });
                }
            };

            let local_addr = self.local_addr()?;

            if let Some(_listen_addr) = &self.listen_addr {
                let pkt = &mut buf[..len];
                if let Ok(hdr) = quiche::Header::from_slice(pkt, quiche::MAX_CONN_ID_LEN) {
                    let is_known = self
                        .connections
                        .values()
                        .any(|c| c.matches_dcid(&hdr.dcid));

                    if !is_known && hdr.ty == quiche::Type::Initial {
                        let scid = Self::generate_scid();
                        let mut quiche_conn = quiche::accept(
                            &scid,
                            None,
                            local_addr,
                            from,
                            &mut self.quiche_config,
                        )
                        .map_err(|e| TransportError::PollError {
                            reason: format!("quiche accept error: {e}"),
                        })?;

                        {
                            let mut out = [0u8; 1350];
                            loop {
                                let (written, send_info) = match quiche_conn.send(&mut out) {
                                    Ok(v) => v,
                                    Err(quiche::Error::Done) => break,
                                    Err(e) => {
                                        return Err(TransportError::PollError {
                                            reason: format!("accept send error: {e}"),
                                        });
                                    }
                                };
                                self.socket
                                    .send_to(&out[..written], send_info.to)
                                    .map_err(|e| TransportError::PollError {
                                        reason: format!("udp send error: {e}"),
                                    })?;
                            }
                        }

                        let id = next_connection_id();
                        let peer_addr = build_peer_addr(from)?;

                        let conn = QuicConnection::new(id, quiche_conn, from);
                        self.connections.insert(id, conn);

                        events.push(TransportEvent::IncomingConnection { id, addr: peer_addr });
                    }
                }
            }

            for (_, conn) in self.connections.iter_mut() {
                if !conn.matches_peer(from) {
                    continue;
                }

                conn.recv_packet(&mut buf[..len], from, local_addr, &self.socket, &mut events)?;
            }
        }

        let mut to_remove = Vec::new();
        for (&id, conn) in self.connections.iter_mut() {
            conn.poll_streams(&mut events, &self.socket)?;

            if conn.is_closed() {
                to_remove.push(id);
            }
        }

        for id in to_remove {
            self.connections.remove(&id);
            events.push(TransportEvent::Closed { id });
        }

        Ok(events)
    }
}

fn build_peer_addr(sock_addr: std::net::SocketAddr) -> Result<PeerAddr, TransportError> {
    let transport = match sock_addr {
        std::net::SocketAddr::V4(v4) => Multiaddr::from_protocols(vec![
            Protocol::Ip4(v4.ip().octets()),
            Protocol::Udp(v4.port()),
            Protocol::QuicV1,
        ]),
        std::net::SocketAddr::V6(v6) => Multiaddr::from_protocols(vec![
            Protocol::Ip6(v6.ip().octets()),
            Protocol::Udp(v6.port()),
            Protocol::QuicV1,
        ]),
    };

    let dummy_peer_id = minip2p_identity::PeerId::from_bytes(&[0x00, 0x04, 0x01, 0x02, 0x03, 0x04])
        .map_err(|e| TransportError::PollError {
            reason: format!("peer id error: {e}"),
        })?;

    PeerAddr::new(transport, dummy_peer_id).map_err(|e| TransportError::PollError {
        reason: format!("peer addr error: {e}"),
    })
}
