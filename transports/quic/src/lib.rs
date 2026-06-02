//! Synchronous QUIC transport adapter for minip2p, powered by Cloudflare's `quiche`.
//!
//! Implements [`Transport`] with a poll-driven, non-blocking UDP socket.
//! No async runtime required.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use boring::pkey::PKey;
use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyMode};
use boring::x509::X509;
use minip2p_core::{Multiaddr, PeerAddr, PeerId, Protocol};
use minip2p_transport::{
    ConnectionEndpoint, ConnectionId, StreamId, Transport, TransportError, TransportEvent,
};
use quiche::ConnectionId as QuicConnectionId;

mod config;
mod connection;

pub use config::QuicNodeConfig;

use connection::QuicConnection;

const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS_RESPONSE: u16 = 0x0101;
const STUN_MAGIC_COOKIE: u32 = 0x2112_a442;
const STUN_HEADER_LEN: usize = 20;
const STUN_TRANSACTION_ID_LEN: usize = 12;
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const MAX_BUFFERED_UDP_DATAGRAMS: usize = 256;

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

/// Builds the shared QUIC TLS configuration.
fn build_quiche_config(node_config: &QuicNodeConfig) -> Result<quiche::Config, TransportError> {
    let mut tls_builder =
        SslContextBuilder::new(SslMethod::tls()).map_err(|e| TransportError::ListenFailed {
            reason: format!("failed to create BoringSSL context: {e}"),
        })?;

    // Require peer certificates on server handshakes and request them on client
    // handshakes. BoringSSL's chain validation is intentionally bypassed here
    // because libp2p TLS uses self-signed certificates with identity proof in a
    // custom extension; the transport verifies that extension after QUIC reports
    // the peer certificate.
    tls_builder.set_verify_callback(
        SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        |_preverify_ok, _ctx| true,
    );

    let (cert_der, key_der) =
        minip2p_tls::generate_certificate(node_config.keypair()).map_err(|e| {
            TransportError::InvalidConfig {
                reason: format!("failed to generate libp2p TLS certificate: {e}"),
            }
        })?;

    let cert = X509::from_der(&cert_der).map_err(|e| TransportError::InvalidConfig {
        reason: format!("failed to parse generated TLS certificate: {e}"),
    })?;
    tls_builder
        .set_certificate(&cert)
        .map_err(|e| TransportError::InvalidConfig {
            reason: format!("failed to load generated cert into BoringSSL: {e}"),
        })?;

    let private_key =
        PKey::private_key_from_der(&key_der).map_err(|e| TransportError::InvalidConfig {
            reason: format!("failed to parse generated TLS private key: {e}"),
        })?;
    tls_builder
        .set_private_key(&private_key)
        .map_err(|e| TransportError::InvalidConfig {
            reason: format!("failed to load generated key into BoringSSL: {e}"),
        })?;
    tls_builder
        .check_private_key()
        .map_err(|e| TransportError::InvalidConfig {
            reason: format!("generated TLS private key does not match certificate: {e}"),
        })?;

    let mut quiche_config =
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls_builder)
            .map_err(|e| TransportError::ListenFailed {
                reason: format!("failed to create quiche config: {e}"),
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

    Ok(quiche_config)
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
    /// Non-STUN datagrams seen while running a synchronous STUN probe.
    buffered_datagrams: VecDeque<(Vec<u8>, SocketAddr)>,
    /// The socket address we're listening on, if any.
    listen_addr: Option<SocketAddr>,
    /// Auto-incrementing connection id counter.
    next_connection_id: u64,
    /// Retained node configuration.
    node_config: QuicNodeConfig,
}

impl QuicTransport {
    /// Creates a new QUIC transport bound to the given address.
    pub fn new(node_config: QuicNodeConfig, bind_addr: &str) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(bind_addr).map_err(|e| TransportError::ListenFailed {
            reason: format!("failed to bind udp socket: {e}"),
        })?;

        socket
            .set_nonblocking(true)
            .map_err(|e| TransportError::ListenFailed {
                reason: format!("failed to set nonblocking: {e}"),
            })?;

        let quiche_config = build_quiche_config(&node_config)?;

        Ok(Self {
            socket,
            quiche_config,
            connections: HashMap::new(),
            cid_to_connection: HashMap::new(),
            peer_connections: HashMap::new(),
            pending_events: Vec::new(),
            buffered_datagrams: VecDeque::new(),
            listen_addr: None,
            next_connection_id: 1,
            node_config,
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

    /// Sends a STUN binding request from this transport's UDP socket and
    /// returns the discovered external QUIC multiaddr.
    ///
    /// This is a std/runtime helper. The STUN result is not automatically
    /// advertised or confirmed; callers decide whether to feed it into DCUtR,
    /// AutoNAT, or an external-address book.
    pub fn discover_external_addr_stun(
        &mut self,
        server: &str,
        timeout: Duration,
    ) -> Result<Multiaddr, TransportError> {
        let local_addr = self.local_addr()?;
        let mut resolved =
            server
                .to_socket_addrs()
                .map_err(|e| TransportError::InvalidAddress {
                    context: "stun server",
                    reason: format!("resolution failed for {server}: {e}"),
                })?;
        let server_addr = select_stun_server_addr(&mut resolved, local_addr).ok_or_else(|| {
            TransportError::InvalidAddress {
                context: "stun server",
                reason: format!(
                    "resolution returned no address matching local socket family for {server}"
                ),
            }
        })?;

        let mut transaction_id = [0u8; STUN_TRANSACTION_ID_LEN];
        getrandom::fill(&mut transaction_id).map_err(|e| TransportError::PollError {
            reason: format!("failed to generate STUN transaction id: {e}"),
        })?;

        let request = stun_binding_request(transaction_id);
        self.socket
            .send_to(&request, server_addr)
            .map_err(|e| TransportError::PollError {
                reason: format!("STUN send to {server_addr} failed: {e}"),
            })?;

        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; 65535];
        loop {
            match self.socket.recv_from(&mut buf) {
                Ok((n, from)) => {
                    if let Some(addr) = parse_stun_binding_response(&buf[..n], &transaction_id) {
                        return Ok(socket_addr_to_multiaddr(addr));
                    }
                    self.buffer_udp_datagram(buf[..n].to_vec(), from);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(TransportError::PollError {
                            reason: format!("STUN timeout waiting for {server_addr}"),
                        });
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => {
                    return Err(TransportError::PollError {
                        reason: format!("STUN receive failed: {e}"),
                    });
                }
            }
        }
    }

    /// Exposes the bound local socket address as a multiaddr for external use.
    pub fn local_multiaddr(&self) -> Result<Multiaddr, TransportError> {
        Ok(socket_addr_to_multiaddr(self.local_addr()?))
    }

    /// Returns this node's `PeerId`, derived from the configured keypair.
    pub fn local_peer_id(&self) -> PeerId {
        self.node_config.peer_id()
    }

    /// Returns a `PeerAddr` that other nodes can use to dial this transport.
    ///
    /// Combines the bound socket address with this node's `PeerId`.
    pub fn local_peer_addr(&self) -> Result<PeerAddr, TransportError> {
        let addr = self.local_addr()?;
        let peer_id = self.local_peer_id();
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
    pub fn listen_on_bound_addr(&mut self) -> Result<Multiaddr, TransportError> {
        let addr = self.local_addr()?;
        let multiaddr = socket_addr_to_multiaddr(addr);
        self.listen(&multiaddr)
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

    fn buffer_udp_datagram(&mut self, data: Vec<u8>, from: SocketAddr) {
        if self.buffered_datagrams.len() >= MAX_BUFFERED_UDP_DATAGRAMS {
            self.buffered_datagrams.pop_front();
        }
        self.buffered_datagrams.push_back((data, from));
    }

    fn recv_udp_datagram(
        &mut self,
        buf: &mut [u8],
    ) -> Result<Option<(usize, SocketAddr)>, TransportError> {
        if let Some((data, from)) = self.buffered_datagrams.pop_front() {
            if data.len() > buf.len() {
                return Err(TransportError::PollError {
                    reason: format!(
                        "buffered udp datagram too large: {} > {}",
                        data.len(),
                        buf.len()
                    ),
                });
            }
            buf[..data.len()].copy_from_slice(&data);
            return Ok(Some((data.len(), from)));
        }

        match self.socket.recv_from(buf) {
            Ok(v) => Ok(Some(v)),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(TransportError::PollError {
                reason: format!("udp recv error: {e}"),
            }),
        }
    }
}

fn stun_binding_request(transaction_id: [u8; STUN_TRANSACTION_ID_LEN]) -> [u8; STUN_HEADER_LEN] {
    let mut out = [0u8; STUN_HEADER_LEN];
    out[..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    out[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    out[8..].copy_from_slice(&transaction_id);
    out
}

fn select_stun_server_addr(
    addrs: impl IntoIterator<Item = SocketAddr>,
    local_addr: SocketAddr,
) -> Option<SocketAddr> {
    addrs
        .into_iter()
        .find(|addr| addr.is_ipv4() == local_addr.is_ipv4())
}

fn parse_stun_binding_response(
    bytes: &[u8],
    transaction_id: &[u8; STUN_TRANSACTION_ID_LEN],
) -> Option<SocketAddr> {
    if bytes.len() < STUN_HEADER_LEN {
        return None;
    }
    let msg_type = u16::from_be_bytes([bytes[0], bytes[1]]);
    if msg_type != STUN_BINDING_SUCCESS_RESPONSE {
        return None;
    }
    let msg_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) != STUN_MAGIC_COOKIE {
        return None;
    }
    if &bytes[8..20] != transaction_id {
        return None;
    }
    let end = STUN_HEADER_LEN.checked_add(msg_len)?;
    if end > bytes.len() {
        return None;
    }

    let mut offset = STUN_HEADER_LEN;
    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let attr_len = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        offset += 4;
        let attr_end = offset.checked_add(attr_len)?;
        if attr_end > end {
            return None;
        }
        let attr = &bytes[offset..attr_end];
        match attr_type {
            STUN_ATTR_XOR_MAPPED_ADDRESS => {
                if let Some(addr) = parse_stun_address(attr, true, transaction_id) {
                    return Some(addr);
                }
            }
            STUN_ATTR_MAPPED_ADDRESS => {
                if let Some(addr) = parse_stun_address(attr, false, transaction_id) {
                    return Some(addr);
                }
            }
            _ => {}
        }
        offset = attr_end + padding_for(attr_len);
    }

    None
}

fn parse_stun_address(
    bytes: &[u8],
    xor: bool,
    transaction_id: &[u8; STUN_TRANSACTION_ID_LEN],
) -> Option<SocketAddr> {
    if bytes.len() < 4 || bytes[0] != 0 {
        return None;
    }
    let family = bytes[1];
    let mut port = u16::from_be_bytes([bytes[2], bytes[3]]);
    if xor {
        port ^= (STUN_MAGIC_COOKIE >> 16) as u16;
    }

    match family {
        0x01 => {
            if bytes.len() < 8 {
                return None;
            }
            let mut ip = [bytes[4], bytes[5], bytes[6], bytes[7]];
            if xor {
                let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
                for (byte, mask) in ip.iter_mut().zip(cookie) {
                    *byte ^= mask;
                }
            }
            Some(SocketAddr::new(IpAddr::from(ip), port))
        }
        0x02 => {
            if bytes.len() < 20 {
                return None;
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&bytes[4..20]);
            if xor {
                let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
                for idx in 0..4 {
                    ip[idx] ^= cookie[idx];
                }
                for idx in 0..STUN_TRANSACTION_ID_LEN {
                    ip[idx + 4] ^= transaction_id[idx];
                }
            }
            Some(SocketAddr::new(IpAddr::from(ip), port))
        }
        _ => None,
    }
}

fn padding_for(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

#[cfg(test)]
mod stun_tests {
    use super::*;

    #[test]
    fn parses_xor_mapped_ipv4_response() {
        let transaction_id = [7u8; STUN_TRANSACTION_ID_LEN];
        let expected = SocketAddr::from(([203, 0, 113, 7], 4242));
        let response = stun_response_with_xor_mapped_ipv4(transaction_id, expected);

        let parsed = parse_stun_binding_response(&response, &transaction_id).unwrap();

        assert_eq!(parsed, expected);
    }

    #[test]
    fn ignores_response_with_wrong_transaction_id() {
        let transaction_id = [7u8; STUN_TRANSACTION_ID_LEN];
        let response = stun_response_with_xor_mapped_ipv4(
            transaction_id,
            SocketAddr::from(([203, 0, 113, 7], 4242)),
        );

        assert!(parse_stun_binding_response(&response, &[8u8; STUN_TRANSACTION_ID_LEN]).is_none());
    }

    #[test]
    fn parses_mapped_ipv4_response_fallback() {
        let transaction_id = [9u8; STUN_TRANSACTION_ID_LEN];
        let expected = SocketAddr::from(([198, 51, 100, 12], 3478));
        let mut response = Vec::new();
        response.extend_from_slice(&STUN_BINDING_SUCCESS_RESPONSE.to_be_bytes());
        response.extend_from_slice(&12u16.to_be_bytes());
        response.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&transaction_id);
        response.extend_from_slice(&STUN_ATTR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&8u16.to_be_bytes());
        response.extend_from_slice(&[0, 1]);
        response.extend_from_slice(&expected.port().to_be_bytes());
        response.extend_from_slice(&[198, 51, 100, 12]);

        let parsed = parse_stun_binding_response(&response, &transaction_id).unwrap();

        assert_eq!(parsed, expected);
    }

    #[test]
    fn selects_stun_server_matching_bound_socket_family() {
        let resolved = [
            SocketAddr::from(([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1], 3478)),
            SocketAddr::from(([203, 0, 113, 10], 3478)),
        ];

        let selected = select_stun_server_addr(resolved, SocketAddr::from(([0, 0, 0, 0], 0)));

        assert_eq!(selected, Some(SocketAddr::from(([203, 0, 113, 10], 3478))));
    }

    #[test]
    fn stun_probe_buffers_unmatched_datagrams() {
        let keypair = minip2p_identity::Ed25519Keypair::generate();
        let mut transport =
            QuicTransport::new(QuicNodeConfig::new(keypair), "127.0.0.1:0").unwrap();
        let transport_addr = transport.local_addr().unwrap();
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let mut request = [0u8; STUN_HEADER_LEN];
            let (n, from) = server.recv_from(&mut request).unwrap();
            assert_eq!(n, STUN_HEADER_LEN);
            assert_eq!(from, transport_addr);
            server.send_to(b"not-stun", from).unwrap();

            let mut transaction_id = [0u8; STUN_TRANSACTION_ID_LEN];
            transaction_id.copy_from_slice(&request[8..20]);
            let response = stun_response_with_xor_mapped_ipv4(transaction_id, from);
            server.send_to(&response, from).unwrap();
        });

        let discovered = transport
            .discover_external_addr_stun(&server_addr.to_string(), Duration::from_secs(1))
            .unwrap();

        handle.join().unwrap();
        assert_eq!(discovered, socket_addr_to_multiaddr(transport_addr));
        let (data, from) = transport.buffered_datagrams.pop_front().unwrap();
        assert_eq!(data, b"not-stun");
        assert_eq!(from, server_addr);
    }

    fn stun_response_with_xor_mapped_ipv4(
        transaction_id: [u8; STUN_TRANSACTION_ID_LEN],
        addr: SocketAddr,
    ) -> Vec<u8> {
        let SocketAddr::V4(addr) = addr else {
            panic!("test helper expects ipv4");
        };
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        let xored_port = addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        let mut xored_ip = addr.ip().octets();
        for idx in 0..4 {
            xored_ip[idx] ^= cookie[idx];
        }

        let mut response = Vec::new();
        response.extend_from_slice(&STUN_BINDING_SUCCESS_RESPONSE.to_be_bytes());
        response.extend_from_slice(&12u16.to_be_bytes());
        response.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&transaction_id);
        response.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&8u16.to_be_bytes());
        response.extend_from_slice(&[0, 1]);
        response.extend_from_slice(&xored_port.to_be_bytes());
        response.extend_from_slice(&xored_ip);
        response
    }
}

impl Transport for QuicTransport {
    fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        let id = self.allocate_connection_id()?;
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

        self.connections.insert(id, conn);
        self.cid_to_connection.insert(source_cid, id);
        self.index_peer_connection(addr.peer_id().clone(), id);

        Ok(id)
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        let socket_addr = extract_listen_socket_addr(addr, "listen address")?;

        let local_addr = self.local_addr()?;
        ensure_listen_matches_bound_socket(socket_addr, local_addr)?;

        let listen_addr = socket_addr_to_multiaddr(local_addr);
        self.listen_addr = Some(local_addr);
        self.pending_events.push(TransportEvent::Listening {
            addr: listen_addr.clone(),
        });

        Ok(listen_addr)
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

    fn local_addresses(&self) -> Vec<Multiaddr> {
        // If the socket isn't bound for some reason (shouldn't happen in
        // normal usage -- we bind at construction time), return empty
        // rather than propagate the error. The swarm uses this only to
        // enrich Identify; a missing value is never fatal.
        self.local_multiaddr()
            .map(|addr| vec![addr])
            .unwrap_or_default()
    }

    fn active_connection_count(&self) -> usize {
        self.connections.len()
    }

    fn active_connection_sources(&self) -> Vec<Multiaddr> {
        self.connections
            .values()
            .map(|conn| conn.endpoint().transport().clone())
            .collect()
    }

    fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
        self.connections
            .values()
            .filter(|conn| conn.is_server())
            .map(|conn| conn.endpoint().transport().clone())
            .collect()
    }

    fn poll(&mut self) -> Result<Vec<TransportEvent>, TransportError> {
        let mut buf = [0u8; 65535];
        let mut events = std::mem::take(&mut self.pending_events);

        loop {
            let Some((len, from)) = self.recv_udp_datagram(&mut buf)? else {
                break;
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
                let mut identity_update: Option<(Option<PeerId>, ConnectionEndpoint)> = None;
                if let Some(conn) = self.connections.get_mut(&id) {
                    let previous_peer_id = conn.endpoint().peer_id().cloned();
                    conn.recv_packet(packet, from, local_addr, &self.socket, &mut events)?;
                    source_cid = Some(conn.source_cid_bytes());
                    if conn.endpoint().peer_id() != previous_peer_id.as_ref() {
                        identity_update = Some((previous_peer_id, conn.endpoint().clone()));
                    }
                }

                if let Some(source_cid) = source_cid {
                    self.cid_to_connection.insert(source_cid, id);
                }

                if let Some((previous_peer_id, endpoint)) = identity_update {
                    if let Some(previous) = previous_peer_id.as_ref() {
                        self.remove_peer_connection(previous, id);
                    }

                    if let Some(peer_id) = endpoint.peer_id() {
                        self.index_peer_connection(peer_id.clone(), id);
                    }

                    events.push(TransportEvent::PeerIdentityVerified {
                        id,
                        endpoint,
                        previous_peer_id,
                    });
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
