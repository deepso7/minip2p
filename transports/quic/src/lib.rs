//! Synchronous QUIC transport adapter for minip2p, powered by Cloudflare's `quiche`.
//!
//! Implements [`Transport`] with a poll-driven, non-blocking UDP socket.
//! No async runtime required.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};

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

const DEFAULT_IPV4_BIND: &str = "0.0.0.0:0";
const DEFAULT_IPV6_BIND: &str = "[::]:0";

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
    resolve_dial_socket_addrs(multiaddr, context)?
        .into_iter()
        .next()
        .ok_or_else(|| TransportError::InvalidAddress {
            context,
            reason: "dial target resolved to no usable addresses".into(),
        })
}

/// Resolves a QUIC multiaddr to all usable socket addresses.
fn resolve_dial_socket_addrs(
    multiaddr: &Multiaddr,
    context: &'static str,
) -> Result<Vec<SocketAddr>, TransportError> {
    let (host, port) = extract_quic_host_and_port(multiaddr, context)?;

    match host {
        Protocol::Ip4(bytes) => Ok(vec![SocketAddr::new(IpAddr::from(bytes), port)]),
        Protocol::Ip6(bytes) => Ok(vec![SocketAddr::new(IpAddr::from(bytes), port)]),
        Protocol::Dns(host) => {
            let query = format!("{host}:{port}");
            let resolved = query
                .to_socket_addrs()
                .map_err(|e| TransportError::InvalidAddress {
                    context,
                    reason: format!("dns resolution failed for {query}: {e}"),
                })?
                .collect::<Vec<_>>();

            if resolved.is_empty() {
                return Err(TransportError::InvalidAddress {
                    context,
                    reason: format!("dns resolution returned no usable address for {query}"),
                });
            }
            Ok(resolved)
        }
        Protocol::Dns4(host) => {
            let query = format!("{host}:{port}");
            let resolved = query
                .to_socket_addrs()
                .map_err(|e| TransportError::InvalidAddress {
                    context,
                    reason: format!("dns resolution failed for {query}: {e}"),
                })?
                .filter(SocketAddr::is_ipv4)
                .collect::<Vec<_>>();

            if resolved.is_empty() {
                return Err(TransportError::InvalidAddress {
                    context,
                    reason: format!("dns resolution returned no ipv4 address for {query}"),
                });
            }
            Ok(resolved)
        }
        Protocol::Dns6(host) => {
            let query = format!("{host}:{port}");
            let resolved = query
                .to_socket_addrs()
                .map_err(|e| TransportError::InvalidAddress {
                    context,
                    reason: format!("dns resolution failed for {query}: {e}"),
                })?
                .filter(SocketAddr::is_ipv6)
                .collect::<Vec<_>>();

            if resolved.is_empty() {
                return Err(TransportError::InvalidAddress {
                    context,
                    reason: format!("dns resolution returned no ipv6 address for {query}"),
                });
            }
            Ok(resolved)
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
    /// The socket address we're listening on, if any.
    listen_addr: Option<SocketAddr>,
    /// Auto-incrementing connection id counter.
    next_connection_id: u64,
    /// Retained node configuration.
    node_config: QuicNodeConfig,
}

/// QUIC endpoint that can be backed by one socket or a dual-stack pair.
///
/// This is the DX-oriented transport entrypoint. Use [`QuicEndpoint::bind`]
/// when an application wants one explicit bind address, or
/// [`QuicEndpoint::dual_stack`] to listen and dial over both IPv4 and IPv6.
pub enum QuicEndpoint {
    Single(Box<QuicTransport>),
    Dual(Box<DualQuicTransport>),
}

/// QUIC transport backed by separate IPv4 and IPv6 sockets.
pub struct DualQuicTransport {
    ipv4: QuicTransport,
    ipv6: QuicTransport,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    fn name(self) -> &'static str {
        match self {
            AddressFamily::Ipv4 => "ipv4",
            AddressFamily::Ipv6 => "ipv6",
        }
    }
}

fn family_for_socket_addr(addr: SocketAddr) -> AddressFamily {
    if addr.is_ipv6() {
        AddressFamily::Ipv6
    } else {
        AddressFamily::Ipv4
    }
}

fn peer_addr_for_family(
    addr: &PeerAddr,
    family: AddressFamily,
) -> Result<PeerAddr, TransportError> {
    let socket_addrs = resolve_dial_socket_addrs(addr.transport(), "dial target")?;
    let Some(socket_addr) = socket_addrs
        .into_iter()
        .find(|socket_addr| family_for_socket_addr(*socket_addr) == family)
    else {
        return Err(TransportError::InvalidAddress {
            context: "dial target",
            reason: format!("no {} target resolved", family.name()),
        });
    };

    let transport = socket_addr_to_multiaddr(socket_addr);
    PeerAddr::new(transport, addr.peer_id().clone()).map_err(|e| TransportError::InvalidAddress {
        context: "dial target",
        reason: format!("resolved address was not a peer addr: {e}"),
    })
}

impl QuicEndpoint {
    /// Binds one QUIC socket to `bind_addr`.
    pub fn bind(node_config: QuicNodeConfig, bind_addr: &str) -> Result<Self, TransportError> {
        QuicTransport::new(node_config, bind_addr)
            .map(|transport| Self::Single(Box::new(transport)))
    }

    /// Binds one QUIC socket to the IP/UDP address represented by `addr`.
    pub fn bind_multiaddr(
        node_config: QuicNodeConfig,
        addr: &Multiaddr,
    ) -> Result<Self, TransportError> {
        let bind = extract_listen_socket_addr(addr, "bind address")?;
        Self::bind(node_config, &bind.to_string())
    }

    /// Binds IPv4 and IPv6 wildcard UDP sockets.
    pub fn dual_stack(node_config: QuicNodeConfig) -> Result<Self, TransportError> {
        DualQuicTransport::new(node_config).map(|transport| Self::Dual(Box::new(transport)))
    }

    /// Dials `addr` using every applicable local socket and returns the
    /// allocated connection ids.
    ///
    /// A dual-stack endpoint tries both IPv4 and IPv6 for `/dns` targets when
    /// DNS resolution provides both families. Family-specific addresses such
    /// as `/ip4`, `/ip6`, `/dns4`, and `/dns6` only use their matching socket.
    pub fn dial_all(&mut self, addr: &PeerAddr) -> Result<Vec<ConnectionId>, TransportError> {
        match self {
            Self::Single(transport) => transport.dial(addr).map(|id| vec![id]),
            Self::Dual(transport) => transport.dial_all(addr),
        }
    }

    /// Dials `addr` with the IPv4 socket.
    pub fn dial_ip4(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        match self {
            Self::Single(transport) => single_dial_family(transport, addr, AddressFamily::Ipv4),
            Self::Dual(transport) => transport.dial_family(addr, AddressFamily::Ipv4),
        }
    }

    /// Dials `addr` with the IPv6 socket.
    pub fn dial_ip6(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        match self {
            Self::Single(transport) => single_dial_family(transport, addr, AddressFamily::Ipv6),
            Self::Dual(transport) => transport.dial_family(addr, AddressFamily::Ipv6),
        }
    }

    /// Sends a raw UDP packet to `target`, bypassing QUIC.
    pub fn send_raw_udp(&self, target: &Multiaddr, payload: &[u8]) -> Result<(), TransportError> {
        match self {
            Self::Single(transport) => transport.send_raw_udp(target, payload),
            Self::Dual(transport) => transport.send_raw_udp(target, payload),
        }
    }
}

fn single_dial_family(
    transport: &mut QuicTransport,
    addr: &PeerAddr,
    family: AddressFamily,
) -> Result<ConnectionId, TransportError> {
    let local_family = family_for_socket_addr(transport.local_addr()?);
    if local_family != family {
        return Err(TransportError::InvalidAddress {
            context: "dial target",
            reason: format!(
                "endpoint is bound to {}, cannot dial {} target",
                local_family.name(),
                family.name()
            ),
        });
    }

    let addr = peer_addr_for_family(addr, family)?;
    transport.dial(&addr)
}

impl DualQuicTransport {
    /// Binds IPv4 and IPv6 wildcard UDP sockets.
    pub fn new(node_config: QuicNodeConfig) -> Result<Self, TransportError> {
        let ipv4 = QuicTransport::new(node_config.clone(), DEFAULT_IPV4_BIND)?;
        let ipv6 = QuicTransport::new(node_config, DEFAULT_IPV6_BIND)?;
        Ok(Self { ipv4, ipv6 })
    }

    /// Sends a raw UDP packet to `target`, bypassing QUIC.
    pub fn send_raw_udp(&self, target: &Multiaddr, payload: &[u8]) -> Result<(), TransportError> {
        let target = resolve_dial_socket_addr(target, "raw udp target")?;
        let family = family_for_socket_addr(target);
        self.transport(family)
            .send_raw_udp(&socket_addr_to_multiaddr(target), payload)
    }

    fn transport(&self, family: AddressFamily) -> &QuicTransport {
        match family {
            AddressFamily::Ipv4 => &self.ipv4,
            AddressFamily::Ipv6 => &self.ipv6,
        }
    }

    fn transport_mut(&mut self, family: AddressFamily) -> &mut QuicTransport {
        match family {
            AddressFamily::Ipv4 => &mut self.ipv4,
            AddressFamily::Ipv6 => &mut self.ipv6,
        }
    }

    fn dial_all(&mut self, addr: &PeerAddr) -> Result<Vec<ConnectionId>, TransportError> {
        let targets = self.dial_targets(addr)?;
        let mut ids = Vec::with_capacity(targets.len());
        let mut last_err = None;
        for (family, addr) in targets {
            match self.transport_mut(family).dial(&addr) {
                Ok(id) => ids.push(Self::external_id(family, id)),
                Err(err) => last_err = Some(err),
            }
        }

        if ids.is_empty() {
            return Err(last_err.unwrap_or_else(|| TransportError::InvalidAddress {
                context: "dial target",
                reason: "no usable ipv4 or ipv6 dial target".into(),
            }));
        }

        Ok(ids)
    }

    fn dial_family(
        &mut self,
        addr: &PeerAddr,
        family: AddressFamily,
    ) -> Result<ConnectionId, TransportError> {
        let targets = self.dial_targets(addr)?;
        let Some((_, addr)) = targets
            .into_iter()
            .find(|(target_family, _)| *target_family == family)
        else {
            return Err(TransportError::InvalidAddress {
                context: "dial target",
                reason: format!("no {} target resolved", family.name()),
            });
        };

        let id = self.transport_mut(family).dial(&addr)?;
        Ok(Self::external_id(family, id))
    }

    fn dial_targets(
        &self,
        addr: &PeerAddr,
    ) -> Result<Vec<(AddressFamily, PeerAddr)>, TransportError> {
        let socket_addrs = resolve_dial_socket_addrs(addr.transport(), "dial target")?;
        let mut seen = BTreeSet::new();
        let mut targets = Vec::new();
        for socket_addr in socket_addrs {
            let family = family_for_socket_addr(socket_addr);
            if !seen.insert(family) {
                continue;
            }
            let transport = socket_addr_to_multiaddr(socket_addr);
            let peer_addr = PeerAddr::new(transport, addr.peer_id().clone()).map_err(|e| {
                TransportError::InvalidAddress {
                    context: "dial target",
                    reason: format!("resolved address was not a peer addr: {e}"),
                }
            })?;
            targets.push((family, peer_addr));
        }
        Ok(targets)
    }

    fn family_for_addr(addr: &Multiaddr) -> AddressFamily {
        match addr.protocols().first() {
            Some(Protocol::Ip6(_) | Protocol::Dns6(_)) => AddressFamily::Ipv6,
            _ => AddressFamily::Ipv4,
        }
    }

    fn external_id(family: AddressFamily, id: ConnectionId) -> ConnectionId {
        let raw = id.as_u64();
        match family {
            AddressFamily::Ipv4 => ConnectionId::new(raw.saturating_mul(2).saturating_sub(1)),
            AddressFamily::Ipv6 => ConnectionId::new(raw.saturating_mul(2)),
        }
    }

    fn internal_id(id: ConnectionId) -> (AddressFamily, ConnectionId) {
        let raw = id.as_u64();
        if raw.is_multiple_of(2) {
            (AddressFamily::Ipv6, ConnectionId::new(raw / 2))
        } else {
            (AddressFamily::Ipv4, ConnectionId::new(raw.div_ceil(2)))
        }
    }

    fn map_event(family: AddressFamily, event: TransportEvent) -> TransportEvent {
        let map = |id| Self::external_id(family, id);
        match event {
            TransportEvent::Connected { id, endpoint } => TransportEvent::Connected {
                id: map(id),
                endpoint,
            },
            TransportEvent::StreamOpened { id, stream_id } => TransportEvent::StreamOpened {
                id: map(id),
                stream_id,
            },
            TransportEvent::IncomingStream { id, stream_id } => TransportEvent::IncomingStream {
                id: map(id),
                stream_id,
            },
            TransportEvent::StreamData {
                id,
                stream_id,
                data,
            } => TransportEvent::StreamData {
                id: map(id),
                stream_id,
                data,
            },
            TransportEvent::StreamRemoteWriteClosed { id, stream_id } => {
                TransportEvent::StreamRemoteWriteClosed {
                    id: map(id),
                    stream_id,
                }
            }
            TransportEvent::StreamClosed { id, stream_id } => TransportEvent::StreamClosed {
                id: map(id),
                stream_id,
            },
            TransportEvent::Closed { id } => TransportEvent::Closed { id: map(id) },
            TransportEvent::Error { id, message } => TransportEvent::Error {
                id: map(id),
                message,
            },
            TransportEvent::IncomingConnection { id, endpoint } => {
                TransportEvent::IncomingConnection {
                    id: map(id),
                    endpoint,
                }
            }
            TransportEvent::PeerIdentityVerified {
                id,
                endpoint,
                previous_peer_id,
            } => TransportEvent::PeerIdentityVerified {
                id: map(id),
                endpoint,
                previous_peer_id,
            },
            TransportEvent::Listening { addr } => TransportEvent::Listening { addr },
        }
    }
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

            if target_conn_id.is_none()
                && self.listen_addr.is_some()
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

impl Transport for QuicEndpoint {
    fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        match self {
            Self::Single(transport) => transport.dial(addr),
            Self::Dual(transport) => transport.dial(addr),
        }
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        match self {
            Self::Single(transport) => transport.listen(addr),
            Self::Dual(transport) => transport.listen(addr),
        }
    }

    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        match self {
            Self::Single(transport) => transport.open_stream(id),
            Self::Dual(transport) => transport.open_stream(id),
        }
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        match self {
            Self::Single(transport) => transport.send_stream(id, stream_id, data),
            Self::Dual(transport) => transport.send_stream(id, stream_id, data),
        }
    }

    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        match self {
            Self::Single(transport) => transport.close_stream_write(id, stream_id),
            Self::Dual(transport) => transport.close_stream_write(id, stream_id),
        }
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        match self {
            Self::Single(transport) => transport.reset_stream(id, stream_id),
            Self::Dual(transport) => transport.reset_stream(id, stream_id),
        }
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        match self {
            Self::Single(transport) => transport.close(id),
            Self::Dual(transport) => transport.close(id),
        }
    }

    fn poll(&mut self) -> Result<Vec<TransportEvent>, TransportError> {
        match self {
            Self::Single(transport) => transport.poll(),
            Self::Dual(transport) => transport.poll(),
        }
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        match self {
            Self::Single(transport) => transport.local_addresses(),
            Self::Dual(transport) => transport.local_addresses(),
        }
    }

    fn active_connection_count(&self) -> usize {
        match self {
            Self::Single(transport) => transport.active_connection_count(),
            Self::Dual(transport) => transport.active_connection_count(),
        }
    }

    fn active_connection_sources(&self) -> Vec<Multiaddr> {
        match self {
            Self::Single(transport) => transport.active_connection_sources(),
            Self::Dual(transport) => transport.active_connection_sources(),
        }
    }

    fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
        match self {
            Self::Single(transport) => transport.active_inbound_connection_sources(),
            Self::Dual(transport) => transport.active_inbound_connection_sources(),
        }
    }
}

impl Transport for DualQuicTransport {
    fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        let (family, addr) = self.dial_targets(addr)?.into_iter().next().ok_or_else(|| {
            TransportError::InvalidAddress {
                context: "dial target",
                reason: "no usable ipv4 or ipv6 dial target".into(),
            }
        })?;
        let id = self.transport_mut(family).dial(&addr)?;
        Ok(Self::external_id(family, id))
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        let family = Self::family_for_addr(addr);
        self.transport_mut(family).listen(addr)
    }

    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        let (family, id) = Self::internal_id(id);
        self.transport_mut(family).open_stream(id)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        let (family, id) = Self::internal_id(id);
        self.transport_mut(family).send_stream(id, stream_id, data)
    }

    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        let (family, id) = Self::internal_id(id);
        self.transport_mut(family).close_stream_write(id, stream_id)
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        let (family, id) = Self::internal_id(id);
        self.transport_mut(family).reset_stream(id, stream_id)
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        let (family, id) = Self::internal_id(id);
        self.transport_mut(family).close(id)
    }

    fn poll(&mut self) -> Result<Vec<TransportEvent>, TransportError> {
        let mut events = Vec::new();
        events.extend(
            self.ipv4
                .poll()?
                .into_iter()
                .map(|event| Self::map_event(AddressFamily::Ipv4, event)),
        );
        events.extend(
            self.ipv6
                .poll()?
                .into_iter()
                .map(|event| Self::map_event(AddressFamily::Ipv6, event)),
        );
        Ok(events)
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        let mut addrs = self.ipv4.local_addresses();
        addrs.extend(self.ipv6.local_addresses());
        addrs
    }

    fn active_connection_count(&self) -> usize {
        self.ipv4.active_connection_count() + self.ipv6.active_connection_count()
    }

    fn active_connection_sources(&self) -> Vec<Multiaddr> {
        let mut addrs = self.ipv4.active_connection_sources();
        addrs.extend(self.ipv6.active_connection_sources());
        addrs
    }

    fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
        let mut addrs = self.ipv4.active_inbound_connection_sources();
        addrs.extend(self.ipv6.active_inbound_connection_sources());
        addrs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minip2p_identity::Ed25519Keypair;

    fn localhost_peer_addr(port: u16) -> PeerAddr {
        let keypair = Ed25519Keypair::generate();
        let transport = Multiaddr::from_protocols(vec![
            Protocol::Dns("localhost".to_string()),
            Protocol::Udp(port),
            Protocol::QuicV1,
        ]);
        PeerAddr::new(transport, keypair.peer_id()).expect("peer addr")
    }

    fn localhost_families(port: u16) -> BTreeSet<AddressFamily> {
        let transport = Multiaddr::from_protocols(vec![
            Protocol::Dns("localhost".to_string()),
            Protocol::Udp(port),
            Protocol::QuicV1,
        ]);
        resolve_dial_socket_addrs(&transport, "test dns")
            .expect("localhost resolves")
            .into_iter()
            .map(family_for_socket_addr)
            .collect()
    }

    #[test]
    fn dual_stack_dial_all_uses_every_resolved_dns_family() {
        let families = localhost_families(9);
        let mut endpoint = QuicEndpoint::dual_stack(QuicNodeConfig::generate()).expect("bind");
        let peer_addr = localhost_peer_addr(9);

        let ids = endpoint.dial_all(&peer_addr).expect("dial all");

        assert_eq!(ids.len(), families.len());
        assert_eq!(
            ids.iter().any(|id| !id.as_u64().is_multiple_of(2)),
            families.contains(&AddressFamily::Ipv4)
        );
        assert_eq!(
            ids.iter().any(|id| id.as_u64().is_multiple_of(2)),
            families.contains(&AddressFamily::Ipv6)
        );
    }

    #[test]
    fn dual_stack_explicit_family_dials_only_that_family() {
        let families = localhost_families(9);
        let peer_addr = localhost_peer_addr(9);

        if families.contains(&AddressFamily::Ipv4) {
            let mut endpoint = QuicEndpoint::dual_stack(QuicNodeConfig::generate()).expect("bind");
            let id = endpoint.dial_ip4(&peer_addr).expect("dial ipv4");
            assert!(!id.as_u64().is_multiple_of(2));
        }

        if families.contains(&AddressFamily::Ipv6) {
            let mut endpoint = QuicEndpoint::dual_stack(QuicNodeConfig::generate()).expect("bind");
            let id = endpoint.dial_ip6(&peer_addr).expect("dial ipv6");
            assert!(id.as_u64().is_multiple_of(2));
        }
    }

    #[test]
    fn peer_addr_for_family_filters_dns_targets() {
        let families = localhost_families(9);
        let peer_addr = localhost_peer_addr(9);

        if families.contains(&AddressFamily::Ipv4) {
            let addr = peer_addr_for_family(&peer_addr, AddressFamily::Ipv4).expect("ipv4 addr");
            assert!(matches!(
                addr.transport().protocols().first(),
                Some(Protocol::Ip4(_))
            ));
        }

        if families.contains(&AddressFamily::Ipv6) {
            let addr = peer_addr_for_family(&peer_addr, AddressFamily::Ipv6).expect("ipv6 addr");
            assert!(matches!(
                addr.transport().protocols().first(),
                Some(Protocol::Ip6(_))
            ));
        }
    }

    #[test]
    fn single_endpoint_explicit_family_rejects_mismatched_socket() {
        let families = localhost_families(9);
        if !families.contains(&AddressFamily::Ipv6) {
            return;
        }

        let mut endpoint =
            QuicEndpoint::bind(QuicNodeConfig::generate(), DEFAULT_IPV4_BIND).expect("bind ipv4");
        let peer_addr = localhost_peer_addr(9);
        let err = endpoint
            .dial_ip6(&peer_addr)
            .expect_err("ipv4 endpoint must not dial ipv6");

        assert!(matches!(
            err,
            TransportError::InvalidAddress {
                context: "dial target",
                ..
            }
        ));
    }
}
