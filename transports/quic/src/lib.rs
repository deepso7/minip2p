//! Synchronous QUIC transport adapter for minip2p, powered by Cloudflare's `quiche`.
//!
//! Implements [`Transport`] with a poll-driven, non-blocking UDP socket.
//! No async runtime required.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};

use minip2p_core::{Multiaddr, PeerAddr, PeerId, Protocol};
use minip2p_transport::{
    ConnectionEndpoint, ConnectionId, StreamId, Transport, TransportError, TransportEvent,
};
use quiche::ConnectionId as QuicConnectionId;

mod config;
mod connection;

pub use config::QuicNodeConfig;

use connection::QuicConnection;

/// Parses a QUIC multiaddr into (host protocol, port), validating the /host/udp/port/quic-v1 shape.
fn extract_quic_host_and_port(
    multiaddr: &Multiaddr,
    context: &'static str,
) -> Result<(Protocol, u16), TransportError> {
    if !multiaddr.is_quic_transport() {
        return Err(TransportError::InvalidAddress {
            context,
            reason: "expected /<host>/udp/<port>/quic-v1".into(),
        });
    }

    let protocols = multiaddr.protocols();

    let host = protocols
        .first()
        .ok_or_else(|| TransportError::InvalidAddress {
            context,
            reason: "missing host component".into(),
        })?;

    let port = match protocols.get(1) {
        Some(Protocol::Udp(port)) => *port,
        _ => {
            return Err(TransportError::InvalidAddress {
                context,
                reason: "missing udp port".into(),
            });
        }
    };

    Ok((host.clone(), port))
}

/// Like `extract_quic_host_and_port` but only accepts IP hosts (rejects DNS -- DNS is dial-only).
fn extract_listen_socket_addr(
    multiaddr: &Multiaddr,
    context: &'static str,
) -> Result<SocketAddr, TransportError> {
    let (host, port) = extract_quic_host_and_port(multiaddr, context)?;

    let ip = match host {
        Protocol::Ip4(bytes) => IpAddr::from(bytes),
        Protocol::Ip6(bytes) => IpAddr::from(bytes),
        Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) => {
            return Err(TransportError::InvalidAddress {
                context,
                reason: "listen requires /ip4 or /ip6 host (dns names are dial-only)".into(),
            });
        }
        _ => {
            return Err(TransportError::InvalidAddress {
                context,
                reason: "missing host component".into(),
            });
        }
    };

    Ok(SocketAddr::new(ip, port))
}

/// Resolves a QUIC multiaddr to a socket address, performing synchronous DNS resolution for /dns* hosts.
fn resolve_dial_socket_addr(
    multiaddr: &Multiaddr,
    context: &'static str,
) -> Result<SocketAddr, TransportError> {
    let (host, port) = extract_quic_host_and_port(multiaddr, context)?;

    match host {
        Protocol::Ip4(bytes) => Ok(SocketAddr::new(IpAddr::from(bytes), port)),
        Protocol::Ip6(bytes) => Ok(SocketAddr::new(IpAddr::from(bytes), port)),
        Protocol::Dns(host) => {
            let query = format!("{host}:{port}");
            let mut resolved =
                query
                    .to_socket_addrs()
                    .map_err(|e| TransportError::InvalidAddress {
                        context,
                        reason: format!("dns resolution failed for {query}: {e}"),
                    })?;

            resolved
                .next()
                .ok_or_else(|| TransportError::InvalidAddress {
                    context,
                    reason: format!("dns resolution returned no usable address for {query}"),
                })
        }
        Protocol::Dns4(host) => {
            let query = format!("{host}:{port}");
            let mut resolved = query
                .to_socket_addrs()
                .map_err(|e| TransportError::InvalidAddress {
                    context,
                    reason: format!("dns resolution failed for {query}: {e}"),
                })?
                .filter(SocketAddr::is_ipv4);

            resolved
                .next()
                .ok_or_else(|| TransportError::InvalidAddress {
                    context,
                    reason: format!("dns resolution returned no ipv4 address for {query}"),
                })
        }
        Protocol::Dns6(host) => {
            let query = format!("{host}:{port}");
            let mut resolved = query
                .to_socket_addrs()
                .map_err(|e| TransportError::InvalidAddress {
                    context,
                    reason: format!("dns resolution failed for {query}: {e}"),
                })?
                .filter(SocketAddr::is_ipv6);

            resolved
                .next()
                .ok_or_else(|| TransportError::InvalidAddress {
                    context,
                    reason: format!("dns resolution returned no ipv6 address for {query}"),
                })
        }
        _ => Err(TransportError::InvalidAddress {
            context,
            reason: "missing host component".into(),
        }),
    }
}

/// Validates that the requested listen address matches the already-bound UDP socket.
fn ensure_listen_matches_bound_socket(
    requested: SocketAddr,
    bound: SocketAddr,
) -> Result<(), TransportError> {
    if requested == bound {
        return Ok(());
    }

    Err(TransportError::InvalidAddress {
        context: "listen address",
        reason: format!(
            "listen address {requested} does not match bound socket {bound}; use the bound local_addr()"
        ),
    })
}

/// Converts a socket address to a /ipX/udp/port/quic-v1 multiaddr.
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

/// QUIC transport backed by a non-blocking UDP socket and `quiche`.
pub struct QuicTransport {
    /// Non-blocking UDP socket for all QUIC traffic.
    socket: UdpSocket,
    /// Shared quiche configuration for all connections.
    quiche_config: quiche::Config,
    /// Active connections keyed by connection id.
    connections: HashMap<ConnectionId, QuicConnection>,
    /// Maps QUIC connection-id bytes to logical connection ids for packet routing.
    cid_to_connection: HashMap<Vec<u8>, ConnectionId>,
    /// Maps peer ids to their set of connection ids.
    peer_connections: HashMap<PeerId, BTreeSet<ConnectionId>>,
    /// Events queued between poll() calls.
    pending_events: Vec<TransportEvent>,
    /// The socket address we're listening on, if any.
    listen_addr: Option<SocketAddr>,
    /// Auto-incrementing connection id counter.
    next_connection_id: u64,
    /// Retained node configuration.
    node_config: QuicNodeConfig,
    /// Temp files for the auto-generated TLS cert/key. Held here to keep them
    /// alive for the lifetime of the transport (quiche reads from file paths).
    _tls_temp_files: Option<(tempfile::NamedTempFile, tempfile::NamedTempFile)>,
}

impl QuicTransport {
    /// Creates a new QUIC transport bound to the given address.
    pub fn new(node_config: QuicNodeConfig, bind_addr: &str) -> Result<Self, TransportError> {
        use std::io::Write;

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
        quiche_config.verify_peer(false);

        // Auto-generate libp2p TLS cert from Ed25519 keypair.
        //
        // NOTE: quiche only supports loading certs/keys from PEM file paths
        // (no in-memory API in the default build). We write to temp files as a
        // workaround. The files are auto-deleted when the transport is dropped.
        // To avoid this, quiche would need the `boringssl-boring-crate` feature
        // for in-memory cert loading via `SslContextBuilder`.
        let tls_temp_files = if let Some(keypair) = node_config.keypair() {
            let (cert_der, key_der) =
                minip2p_tls::generate_certificate(keypair).map_err(|e| {
                    TransportError::InvalidConfig {
                        reason: format!("failed to generate libp2p TLS certificate: {e}"),
                    }
                })?;

            let cert_pem = minip2p_tls::cert_to_pem(&cert_der);
            let key_pem = minip2p_tls::private_key_to_pem(&key_der);

            let mut cert_file = tempfile::NamedTempFile::new().map_err(|e| {
                TransportError::InvalidConfig {
                    reason: format!("failed to create temp cert file: {e}"),
                }
            })?;
            cert_file.write_all(cert_pem.as_bytes()).map_err(|e| {
                TransportError::InvalidConfig {
                    reason: format!("failed to write temp cert file: {e}"),
                }
            })?;

            let mut key_file = tempfile::NamedTempFile::new().map_err(|e| {
                TransportError::InvalidConfig {
                    reason: format!("failed to create temp key file: {e}"),
                }
            })?;
            key_file.write_all(key_pem.as_bytes()).map_err(|e| {
                TransportError::InvalidConfig {
                    reason: format!("failed to write temp key file: {e}"),
                }
            })?;

            let cert_path = cert_file.path().to_str().ok_or(TransportError::InvalidConfig {
                reason: "temp cert file path is not valid UTF-8".into(),
            })?;
            quiche_config
                .load_cert_chain_from_pem_file(cert_path)
                .map_err(|e| TransportError::InvalidConfig {
                    reason: format!("failed to load generated cert into quiche: {e}"),
                })?;

            let key_path = key_file.path().to_str().ok_or(TransportError::InvalidConfig {
                reason: "temp key file path is not valid UTF-8".into(),
            })?;
            quiche_config
                .load_priv_key_from_pem_file(key_path)
                .map_err(|e| TransportError::InvalidConfig {
                    reason: format!("failed to load generated key into quiche: {e}"),
                })?;

            Some((cert_file, key_file))
        } else {
            None
        };

        Ok(Self {
            socket,
            quiche_config,
            connections: HashMap::new(),
            cid_to_connection: HashMap::new(),
            peer_connections: HashMap::new(),
            pending_events: Vec::new(),
            listen_addr: None,
            next_connection_id: 1,
            node_config,
            _tls_temp_files: tls_temp_files,
        })
    }

    /// Returns the local socket address this transport is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.socket
            .local_addr()
            .map_err(|e| TransportError::PollError {
                reason: format!("failed to get local addr: {e}"),
            })
    }

    /// Sends a raw UDP packet to the given multiaddr, bypassing QUIC.
    ///
    /// This is intended for NAT hole-punch signaling (e.g. DCUtR), where a
    /// peer needs to send stray UDP bytes to open a NAT binding for inbound
    /// QUIC packets from a remote peer.
    ///
    /// The multiaddr must be of the form `/ip4|ip6|dns*/udp/<port>/quic-v1`.
    /// DNS names are resolved synchronously.
    pub fn send_raw_udp(&self, target: &Multiaddr, payload: &[u8]) -> Result<(), TransportError> {
        let addr = resolve_dial_socket_addr(target, "raw udp target")?;
        self.socket
            .send_to(payload, addr)
            .map_err(|e| TransportError::PollError {
                reason: format!("raw udp send to {addr} failed: {e}"),
            })?;
        Ok(())
    }

    /// Exposes the bound local socket address as a multiaddr for external use.
    pub fn local_multiaddr(&self) -> Result<Multiaddr, TransportError> {
        Ok(socket_addr_to_multiaddr(self.local_addr()?))
    }

    /// Returns this node's `PeerId`, derived from the configured keypair.
    ///
    /// Returns `None` if no keypair was configured.
    pub fn local_peer_id(&self) -> Option<PeerId> {
        self.node_config.peer_id()
    }

    /// Returns a `PeerAddr` that other nodes can use to dial this transport.
    ///
    /// Combines the bound socket address with this node's `PeerId`. Only
    /// available after the transport has a keypair configured.
    pub fn local_peer_addr(&self) -> Result<PeerAddr, TransportError> {
        let addr = self.local_addr()?;
        let peer_id = self.local_peer_id().ok_or(TransportError::InvalidConfig {
            reason: "no keypair configured; cannot derive local PeerAddr".into(),
        })?;
        let multiaddr = socket_addr_to_multiaddr(addr);
        PeerAddr::new(multiaddr, peer_id).map_err(|e| TransportError::InvalidConfig {
            reason: format!("failed to build local PeerAddr: {e}"),
        })
    }

    /// Starts listening on the already-bound socket address.
    ///
    /// Convenience wrapper around [`listen`](Transport::listen) that uses the
    /// address the UDP socket is bound to, avoiding manual `Multiaddr`
    /// construction.
    pub fn listen_on_bound_addr(&mut self) -> Result<(), TransportError> {
        let addr = self.local_addr()?;
        let multiaddr = socket_addr_to_multiaddr(addr);
        self.listen(&multiaddr)
    }

    /// Dials a peer, automatically allocating a connection id.
    pub fn dial_auto(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        let id = self.allocate_connection_id()?;
        self.dial(id, addr)?;
        Ok(id)
    }

    /// Returns all active connection ids for the given peer.
    pub fn connection_ids_for_peer(&self, peer_id: &PeerId) -> Vec<ConnectionId> {
        self.peer_connections
            .get(peer_id)
            .map(|ids| ids.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Binds a peer identity to a connection, emitting a `PeerIdentityVerified` event.
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

    /// Allocates the next unused connection id, skipping 0 and wrapping on overflow.
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

    /// Generates a random QUIC source connection id using OS randomness.
    fn generate_scid() -> Result<QuicConnectionId<'static>, getrandom::Error> {
        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
        getrandom::fill(&mut scid)?;
        Ok(QuicConnectionId::from_vec(scid.to_vec()))
    }

    /// Adds a connection to the peer-to-connections index.
    fn index_peer_connection(&mut self, peer_id: PeerId, id: ConnectionId) {
        self.peer_connections.entry(peer_id).or_default().insert(id);
    }

    /// Removes a connection from the peer-to-connections index, cleaning up empty entries.
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

    /// Removes all index entries (CID and peer) for a connection.
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

        let peer_socket = resolve_dial_socket_addr(addr.transport(), "dial target")?;
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
        let socket_addr = extract_listen_socket_addr(addr, "listen address")?;

        if !self.node_config.can_listen() {
            return Err(TransportError::InvalidConfig {
                reason: "listener role requires an Ed25519 keypair; use QuicNodeConfig::with_keypair(...) or QuicNodeConfig::dev_listener()".into(),
            });
        }

        let local_addr = self.local_addr()?;
        ensure_listen_matches_bound_socket(socket_addr, local_addr)?;

        self.listen_addr = Some(local_addr);
        self.pending_events.push(TransportEvent::Listening {
            addr: socket_addr_to_multiaddr(local_addr),
        });

        Ok(())
    }

    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        let conn = self
            .connections
            .get_mut(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;

        let stream_id = conn.open_stream()?;
        self.pending_events
            .push(TransportEvent::StreamOpened { id, stream_id });
        Ok(stream_id)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        let conn = self
            .connections
            .get_mut(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;

        conn.send_stream(stream_id, data, &self.socket, &mut self.pending_events)?;

        Ok(())
    }

    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        let conn = self
            .connections
            .get_mut(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;

        conn.close_stream_write(stream_id, &self.socket, &mut self.pending_events)?;

        Ok(())
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        let conn = self
            .connections
            .get_mut(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;

        conn.reset_stream(stream_id, &mut self.pending_events)?;

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
