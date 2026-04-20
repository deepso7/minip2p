use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr, UdpSocket};

use minip2p_core::{Multiaddr, PeerAddr, PeerId, Protocol};
use minip2p_transport::{
    ConnectionEndpoint, ConnectionId, ConnectionState, PeerSendPolicy, Transport, TransportError,
    TransportEvent,
};
use quiche::ConnectionId as QuicConnectionId;

mod config;
mod connection;

pub use config::QuicConfig;

use connection::QuicConnection;

fn extract_socket_addr(
    multiaddr: &Multiaddr,
    context: &'static str,
) -> Result<SocketAddr, TransportError> {
    if !multiaddr.is_quic_transport() {
        return Err(TransportError::InvalidAddress {
            context,
            reason: "expected /<host>/udp/<port>/quic-v1".into(),
        });
    }

    let protocols = multiaddr.protocols();
    let mut ip: Option<IpAddr> = None;
    let mut port: Option<u16> = None;

    for proto in protocols {
        match proto {
            Protocol::Ip4(bytes) => {
                ip = Some(IpAddr::from(*bytes));
            }
            Protocol::Ip6(bytes) => {
                ip = Some(IpAddr::from(*bytes));
            }
            Protocol::Udp(p) => {
                port = Some(*p);
            }
            _ => {}
        }
    }

    let ip = ip.ok_or_else(|| TransportError::InvalidAddress {
        context,
        reason: "missing host component".into(),
    })?;

    let port = port.ok_or_else(|| TransportError::InvalidAddress {
        context,
        reason: "missing udp port".into(),
    })?;

    Ok(SocketAddr::new(ip, port))
}

fn socket_addr_to_multiaddr(addr: SocketAddr) -> Multiaddr {
    match addr {
        SocketAddr::V4(v4) => Multiaddr::from_protocols(vec![
            Protocol::Ip4(v4.ip().octets()),
            Protocol::Udp(v4.port()),
            Protocol::QuicV1,
        ]),
        SocketAddr::V6(v6) => Multiaddr::from_protocols(vec![
            Protocol::Ip6(v6.ip().octets()),
            Protocol::Udp(v6.port()),
            Protocol::QuicV1,
        ]),
    }
}

pub struct QuicTransport {
    socket: UdpSocket,
    quiche_config: quiche::Config,
    connections: HashMap<ConnectionId, QuicConnection>,
    cid_to_connection: HashMap<Vec<u8>, ConnectionId>,
    peer_connections: HashMap<PeerId, BTreeSet<ConnectionId>>,
    pending_events: Vec<TransportEvent>,
    listen_addr: Option<SocketAddr>,
    next_connection_id: u64,
    config: QuicConfig,
}

impl QuicTransport {
    pub fn new(config: QuicConfig, bind_addr: &str) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(bind_addr).map_err(|e| TransportError::ListenFailed {
            reason: format!("failed to bind udp socket: {e}"),
        })?;

        socket
            .set_nonblocking(true)
            .map_err(|e| TransportError::ListenFailed {
                reason: format!("failed to set nonblocking: {e}"),
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
            connections: HashMap::new(),
            cid_to_connection: HashMap::new(),
            peer_connections: HashMap::new(),
            pending_events: Vec::new(),
            listen_addr: None,
            next_connection_id: 1,
            config,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.socket
            .local_addr()
            .map_err(|e| TransportError::PollError {
                reason: format!("failed to get local addr: {e}"),
            })
    }

    pub fn dial_auto(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        let id = self.allocate_connection_id()?;
        self.dial(id, addr)?;
        Ok(id)
    }

    pub fn connection_ids_for_peer(&self, peer_id: &PeerId) -> Vec<ConnectionId> {
        self.peer_connections
            .get(peer_id)
            .map(|ids| ids.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn primary_connection_for_peer(&self, peer_id: &PeerId) -> Option<ConnectionId> {
        self.select_connection_for_peer(peer_id, PeerSendPolicy::Primary)
    }

    pub fn verify_connection_peer_id(
        &mut self,
        id: ConnectionId,
        peer_id: PeerId,
    ) -> Result<(), TransportError> {
        let (previous_peer_id, endpoint) = {
            let conn = self
                .connections
                .get_mut(&id)
                .ok_or(TransportError::ConnectionNotFound { id })?;

            let previous_peer_id = conn.endpoint().peer_id().cloned();
            if previous_peer_id.as_ref() == Some(&peer_id) {
                return Ok(());
            }

            conn.set_peer_id(peer_id.clone());
            (previous_peer_id, conn.endpoint().clone())
        };

        if let Some(previous) = previous_peer_id.as_ref() {
            self.remove_peer_connection(previous, id);
        }

        self.index_peer_connection(peer_id, id);
        self.pending_events
            .push(TransportEvent::PeerIdentityVerified {
                id,
                endpoint,
                previous_peer_id,
            });

        Ok(())
    }

    pub fn send_to_peer(
        &mut self,
        peer_id: &PeerId,
        data: Vec<u8>,
        policy: PeerSendPolicy,
    ) -> Result<ConnectionId, TransportError> {
        let connection_id = self
            .select_connection_for_peer(peer_id, policy)
            .ok_or_else(|| TransportError::PeerNotConnected {
                peer_id: peer_id.clone(),
            })?;

        self.send(connection_id, data)?;
        Ok(connection_id)
    }

    fn allocate_connection_id(&mut self) -> Result<ConnectionId, TransportError> {
        let start = self.next_connection_id;

        loop {
            let raw = self.next_connection_id;
            self.next_connection_id = self.next_connection_id.wrapping_add(1);

            if raw != 0 {
                let id = ConnectionId::new(raw);
                if !self.connections.contains_key(&id) {
                    return Ok(id);
                }
            }

            if self.next_connection_id == start {
                break;
            }
        }

        Err(TransportError::ResourceExhausted {
            resource: "connection ids",
        })
    }

    fn generate_scid() -> Result<QuicConnectionId<'static>, getrandom::Error> {
        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
        getrandom::fill(&mut scid)?;
        Ok(QuicConnectionId::from_vec(scid.to_vec()))
    }

    fn index_peer_connection(&mut self, peer_id: PeerId, id: ConnectionId) {
        self.peer_connections.entry(peer_id).or_default().insert(id);
    }

    fn remove_peer_connection(&mut self, peer_id: &PeerId, id: ConnectionId) {
        let mut remove_entry = false;

        if let Some(ids) = self.peer_connections.get_mut(peer_id) {
            ids.remove(&id);
            remove_entry = ids.is_empty();
        }

        if remove_entry {
            self.peer_connections.remove(peer_id);
        }
    }

    fn select_connection_for_peer(
        &self,
        peer_id: &PeerId,
        policy: PeerSendPolicy,
    ) -> Option<ConnectionId> {
        let ids = self.peer_connections.get(peer_id)?;

        let is_connected = |id: &ConnectionId| {
            self.connections
                .get(id)
                .is_some_and(QuicConnection::is_connected)
        };

        match policy {
            PeerSendPolicy::Primary | PeerSendPolicy::OldestConnected => {
                ids.iter().find(|id| is_connected(id)).copied()
            }
            PeerSendPolicy::NewestConnected => {
                ids.iter().rev().find(|id| is_connected(id)).copied()
            }
        }
    }

    fn unindex_connection(&mut self, id: ConnectionId, peer_id: Option<PeerId>) {
        self.cid_to_connection.retain(|_, mapped| *mapped != id);

        if let Some(peer_id) = peer_id {
            self.remove_peer_connection(&peer_id, id);
        }
    }
}

impl Transport for QuicTransport {
    fn dial(&mut self, id: ConnectionId, addr: &PeerAddr) -> Result<(), TransportError> {
        if self.connections.contains_key(&id) {
            return Err(TransportError::ConnectionExists { id });
        }

        let peer_socket = extract_socket_addr(addr.transport(), "dial target")?;
        let local_socket = self.local_addr()?;

        let scid = Self::generate_scid().map_err(|e| TransportError::DialFailed {
            id,
            reason: format!("failed to generate connection id: {e}"),
        })?;

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

        let conn = QuicConnection::new(
            id,
            quiche_conn,
            peer_socket,
            ConnectionEndpoint::from_peer_addr(addr),
        );
        let source_cid = conn.source_cid_bytes();

        if self.connections.insert(id, conn).is_some() {
            return Err(TransportError::ConnectionExists { id });
        }

        self.cid_to_connection.insert(source_cid, id);
        self.index_peer_connection(addr.peer_id().clone(), id);

        Ok(())
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<(), TransportError> {
        let socket_addr = extract_socket_addr(addr, "listen address")?;

        if self.config.cert_chain_path.is_none() || self.config.priv_key_path.is_none() {
            return Err(TransportError::InvalidConfig {
                reason: "server mode requires cert_chain_path and priv_key_path".into(),
            });
        }

        self.listen_addr = Some(socket_addr);
        self.pending_events
            .push(TransportEvent::Listening { addr: addr.clone() });

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
            let packet = &mut buf[..len];

            let parsed_header = quiche::Header::from_slice(packet, quiche::MAX_CONN_ID_LEN)
                .ok()
                .map(|header| (header.ty, header.dcid.as_ref().to_vec()));

            let mut target_conn_id = parsed_header
                .as_ref()
                .and_then(|(_, dcid)| self.cid_to_connection.get(dcid).copied());

            if target_conn_id.is_none() {
                if self.listen_addr.is_some()
                    && parsed_header
                        .as_ref()
                        .is_some_and(|(ty, _)| *ty == quiche::Type::Initial)
                {
                    let scid = Self::generate_scid().map_err(|e| TransportError::PollError {
                        reason: format!("failed to generate server connection id: {e}"),
                    })?;

                    let mut quiche_conn =
                        quiche::accept(&scid, None, local_addr, from, &mut self.quiche_config)
                            .map_err(|e| TransportError::PollError {
                                reason: format!("quiche accept error: {e}"),
                            })?;

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

                    let id = self.allocate_connection_id()?;
                    let endpoint = ConnectionEndpoint::new(socket_addr_to_multiaddr(from));
                    let conn = QuicConnection::new(id, quiche_conn, from, endpoint.clone());
                    let source_cid = conn.source_cid_bytes();

                    if self.connections.insert(id, conn).is_some() {
                        return Err(TransportError::PollError {
                            reason: format!("connection id collision for incoming connection {id}"),
                        });
                    }

                    self.cid_to_connection.insert(source_cid, id);
                    events.push(TransportEvent::IncomingConnection { id, endpoint });
                    target_conn_id = Some(id);
                }
            }

            if target_conn_id.is_none() {
                target_conn_id = self
                    .connections
                    .iter()
                    .find(|(_, conn)| conn.matches_peer(from))
                    .map(|(id, _)| *id);
            }

            if let Some(id) = target_conn_id {
                let mut source_cid: Option<Vec<u8>> = None;
                if let Some(conn) = self.connections.get_mut(&id) {
                    conn.recv_packet(packet, from, local_addr, &self.socket, &mut events)?;
                    source_cid = Some(conn.source_cid_bytes());
                }

                if let Some(source_cid) = source_cid {
                    self.cid_to_connection.insert(source_cid, id);
                }
            }
        }

        let mut to_remove = Vec::new();
        let mut cid_updates = Vec::new();

        for (&id, conn) in self.connections.iter_mut() {
            conn.poll_streams(&mut events, &self.socket)?;
            cid_updates.push((conn.source_cid_bytes(), id));

            if conn.is_closed() {
                to_remove.push(id);
            }
        }

        for (cid, id) in cid_updates {
            self.cid_to_connection.insert(cid, id);
        }

        for id in to_remove {
            if let Some(conn) = self.connections.remove(&id) {
                self.unindex_connection(id, conn.endpoint().peer_id().cloned());
            }
            events.push(TransportEvent::Closed { id });
        }

        Ok(events)
    }
}
