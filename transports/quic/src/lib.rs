//! Synchronous QUIC transport adapter for minip2p, on the quinn-proto engine
//! with rustls (ring) for libp2p TLS.
//!
//! Implements [`Transport`] with a poll-driven, non-blocking UDP socket,
//! driven through quinn-udp for segmentation and receive offload, ECN and
//! packet info where the platform has them. The engine owns no I/O: the
//! adapter feeds it datagrams and a time sample, and sends what it produces.
//! No async runtime required.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use minip2p_core::platform::{Deadline, Now};
use minip2p_core::{Multiaddr, PeerAddr, PeerId, Protocol};
use minip2p_transport::mio::{self, Interest, Registry, Waker, event::Event};
use minip2p_transport::{
    Bytes, ConnectionEndpoint, ConnectionId, ConnectionNamespace, PollSource, StreamId, TokenSpace,
    Transport, TransportError, TransportEvent, UnsettledConnections,
};
use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn_proto::{
    ClientConfig, ConnectionHandle, DatagramEvent, EndpointConfig, IdleTimeout, Incoming,
    ServerConfig, TransportConfig, ValidationTokenConfig, VarInt,
};
use socket2::{Domain, Protocol as SocketProtocol, Socket as RawSocket, Type};

#[cfg(test)]
mod admission_tests;
mod budget;
#[cfg(test)]
mod budget_tests;
mod config;
mod connection;
mod diagnostics;
mod error;
#[cfg(test)]
mod recv_batch_tests;
mod socket;
#[cfg(test)]
mod socket_tests;
#[cfg(test)]
mod stream_send_tests;
#[cfg(test)]
mod stream_tests;
#[cfg(test)]
mod test_peer;
mod tls;
#[cfg(test)]
mod write_fairness_tests;

pub use config::{QuicLimits, QuicNodeConfig};
#[cfg(feature = "diagnostics")]
pub use diagnostics::{
    ConnectionDiagnostics, DatagramCounters, SocketBuffers, datagram_counters, socket_buffers,
};
pub use error::{QuicBindError, QuicTlsStage};

use budget::MemoryBudget;
use connection::{Cx, QuicConnection};
use diagnostics::{ConnectionCounters, DatagramTally};
use socket::{Received, Socket, Sockets};
use tls::{HostTime, TlsIdentity};

/// How long a Retry token stays valid.
const RETRY_TOKEN_LIFETIME: Duration = Duration::from_secs(10);
/// Server name every dial presents; libp2p peers authenticate by certificate,
/// not by name.
const SERVER_NAME: &str = "l";
/// Maximum UDP datagrams drained from the socket per `poll()` call.
///
/// Bounding the drain keeps a packet flood from starving the connection
/// timers (loss recovery, idle timeouts) that only run after the recv loop.
/// A batch that hits the bound reports `Deadline::IMMEDIATE`, so the driver
/// polls again at once: no fresh readiness edge will announce the leftovers.
const MAX_DATAGRAMS_PER_POLL: usize = 128;
/// Largest UDP payload a single datagram can carry.
const RECV_BUFFER_SIZE: usize = 65_535;

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

/// The socket address a QUIC dial or raw UDP send targets.
///
/// Only `/ip4` and `/ip6` hosts are accepted. Name resolution blocks, so it
/// never happens here: the std `Endpoint` resolves `/dns*` candidates off its
/// driver thread, and a direct caller must resolve the name itself first.
fn dial_socket_addr(
    multiaddr: &Multiaddr,
    context: &'static str,
) -> Result<SocketAddr, TransportError> {
    let (host, port) = extract_quic_host_and_port(multiaddr, context)?;

    match host {
        Protocol::Ip4(bytes) => Ok(SocketAddr::new(IpAddr::from(bytes), port)),
        Protocol::Ip6(bytes) => Ok(SocketAddr::new(IpAddr::from(bytes), port)),
        Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) => {
            Err(TransportError::InvalidAddress {
                context,
                reason: format!(
                    "{multiaddr} names a host; resolve it to /ip4 or /ip6 first \
                     (the QUIC transport does not resolve names)"
                ),
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

/// The engine's transport parameters for `limits`, every default the
/// adapter relies on set explicitly.
fn transport_config(limits: &QuicLimits) -> Result<TransportConfig, QuicBindError> {
    let invalid = |field, requirement| QuicBindError::InvalidLimit { field, requirement };
    if limits.max_pending_datagrams == 0 {
        return Err(invalid(
            "max_pending_datagrams",
            "must be greater than zero",
        ));
    }
    // A zero queue could never free half of itself, so a Full write would
    // never be told it can retry; nor could an application stream whose
    // whole connection queue is the control reserve.
    if limits.max_pending_bytes_per_stream == 0 {
        return Err(invalid(
            "max_pending_bytes_per_stream",
            "must be greater than zero",
        ));
    }
    if limits.max_pending_connection_bytes <= limits.control_stream_reserve_bytes {
        return Err(invalid(
            "control_stream_reserve_bytes",
            "must be less than max_pending_connection_bytes",
        ));
    }
    // QUIC treats a zero idle timeout as "no timeout", which would keep dead
    // connections alive forever -- the opposite of what a limit promises --
    // so reject it up front.
    if limits.idle_timeout_ms == 0 {
        return Err(invalid("idle_timeout_ms", "must be greater than zero"));
    }
    for (field, window) in [
        ("stream_receive_window", limits.stream_receive_window),
        (
            "connection_receive_window",
            limits.connection_receive_window,
        ),
        ("send_window", limits.send_window),
    ] {
        if window == 0 {
            return Err(invalid(field, "must be greater than zero"));
        }
    }
    let too_large = |field| invalid(field, "is too large for QUIC");
    let var_int = |field, value: usize| {
        u64::try_from(value)
            .ok()
            .and_then(|value| VarInt::from_u64(value).ok())
            .ok_or_else(|| too_large(field))
    };
    let max_streams = VarInt::from_u64(limits.max_streams_per_connection)
        .map_err(|_bounds| too_large("max_streams_per_connection"))?;
    let idle_timeout =
        VarInt::from_u64(limits.idle_timeout_ms).map_err(|_bounds| too_large("idle_timeout_ms"))?;
    let stream_window = var_int("stream_receive_window", limits.stream_receive_window)?;
    let connection_window = var_int(
        "connection_receive_window",
        limits.connection_receive_window,
    )?;
    let send_window =
        u64::try_from(limits.send_window).map_err(|_overflow| too_large("send_window"))?;

    let mut config = TransportConfig::default();
    config
        .stream_receive_window(stream_window)
        .receive_window(connection_window)
        .send_window(send_window)
        .max_concurrent_bidi_streams(max_streams)
        // libp2p uses bidirectional streams only.
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        // QUIC DATAGRAM is not advertised.
        .datagram_receive_buffer_size(None)
        .max_idle_timeout(Some(IdleTimeout::from(idle_timeout)))
        .keep_alive_interval(Some(Duration::from_millis(keepalive_interval_ms(
            limits.idle_timeout_ms,
        ))));
    Ok(config)
}

/// QUIC transport over one or two non-blocking UDP sockets -- at most one per
/// IP family -- and one quinn-proto endpoint serving both.
///
/// Bind one family with [`bind`](Self::bind) and one address, both with two
/// addresses (one `/ip4`, one `/ip6`), or both on wildcard addresses with
/// [`dual_stack`](Self::dual_stack). Each transmit leaves from the socket of
/// its destination's family. Connections get ids and queue retained datagrams
/// per socket, and are counted against [`QuicLimits::max_connections`] and
/// the QUIC memory budget ([`QuicLimits::memory_budget_bytes`]) across the
/// whole transport.
pub struct QuicTransport {
    /// The sockets, IPv4 first, with their per-socket state.
    sockets: Sockets,
    /// Clones of the sockets registered with the host's shared poll, once
    /// attached. Every poll reads every socket until `WouldBlock` (or its
    /// receive bound, which reports itself as due now), so readiness only
    /// has to wake the host.
    registered: Vec<mio::net::UdpSocket>,
    /// Readiness was dispatched since the last poll. Reported as due now, so
    /// a host that skips this transport's poll for a turn (a `TransportSet`
    /// handing over held-back events first) cannot park on an edge that will
    /// not come again.
    dispatched: bool,
    /// The engine's endpoint: routes datagrams to connections by connection
    /// id and answers what no connection owns.
    endpoint: quinn_proto::Endpoint,
    /// Installed on the endpoint by the first `listen`; until then it
    /// accepts nothing.
    server_config: Arc<ServerConfig>,
    transport_config: Arc<TransportConfig>,
    tls: TlsIdentity,
    /// The host's wall-clock time, shared with the TLS verifiers.
    host_time: Arc<HostTime>,
    /// Active connections keyed by connection id.
    connections: HashMap<ConnectionId, QuicConnection>,
    /// Ended connections whose delivered bytes are not settled yet (unsettled
    /// connections). Each still counts against the connection limit, and its
    /// streams keep their memory reservations (ADR 0012).
    unsettled: UnsettledConnections,
    /// Memory reservations of every connection and stream, live or
    /// unsettled.
    budget: MemoryBudget,
    /// The engine's handle for each connection.
    handles: HashMap<ConnectionHandle, ConnectionId>,
    /// Events queued between poll() calls.
    pending_events: Vec<TransportEvent>,
    /// Reused by every receive.
    recv_buf: Vec<u8>,
    /// Reused by every receive: the slots one receive call filled.
    recv_slots: Vec<Received>,
    /// Reused by every transmit and stateless reply.
    send_buf: Vec<u8>,
    /// Connections the current poll routed datagrams to, or accepted,
    /// possibly repeated; reused so routing allocates nothing per poll.
    received: Vec<ConnectionId>,
    /// Every connection's cached engine timeout, earliest first, so a poll
    /// finds the due ones and `next_deadline` the next one without visiting
    /// every connection.
    timers: BTreeSet<(Instant, ConnectionId)>,
    /// Connections whose last service left work that no packet or timer
    /// will prompt, such as output the socket pushed back on.
    unfinished: BTreeSet<ConnectionId>,
    /// Reused for the connections one poll services.
    due: Vec<ConnectionId>,
    /// Connection services run, for tests that check idle polls do none.
    #[cfg(test)]
    services: usize,
    /// Retained node configuration.
    node_config: QuicNodeConfig,
    /// The last poll's host sample and the engine instant taken with it, so
    /// `next_deadline` maps engine timeouts onto the host's timeline. `None`
    /// until the first `poll`.
    clock: Option<(Now, Instant)>,
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

/// Binds an IPv4 UDP socket to `addr`.
fn bind_ipv4_udp(addr: SocketAddr) -> Result<UdpSocket, QuicBindError> {
    UdpSocket::bind(addr).map_err(|e| QuicBindError::socket(addr, "bind", &e))
}

/// Binds an IPv6-only UDP socket, so an IPv4 wildcard can share its port.
fn bind_ipv6_only_udp(addr: SocketAddr) -> Result<UdpSocket, QuicBindError> {
    RawSocket::new(Domain::IPV6, Type::DGRAM, Some(SocketProtocol::UDP))
        .and_then(|socket| {
            socket.set_only_v6(true)?;
            socket.bind(&addr.into())?;
            Ok(socket.into())
        })
        .map_err(|e| QuicBindError::socket(addr, "bind ipv6-only", &e))
}

/// The address error for a target whose family has no bound socket.
fn missing_family(context: &'static str, addr: SocketAddr) -> TransportError {
    TransportError::InvalidAddress {
        context,
        reason: format!(
            "{addr} is an {} address, but no {} socket is bound",
            family_for_socket_addr(addr).name(),
            family_for_socket_addr(addr).name()
        ),
    }
}

impl QuicTransport {
    /// Binds one UDP socket per address: one `/ip4/<ip>/udp/<port>/quic-v1`,
    /// one `/ip6/...`, or one of each. Hosts must be numeric; port 0 picks an
    /// ephemeral port. An IPv6 socket is IPv6-only.
    pub fn bind(node_config: QuicNodeConfig, addrs: &[Multiaddr]) -> Result<Self, QuicBindError> {
        let mut binds = addrs
            .iter()
            .map(|addr| {
                extract_listen_socket_addr(addr, "bind address").map_err(|error| {
                    QuicBindError::InvalidAddress {
                        addr: addr.clone(),
                        reason: match error {
                            TransportError::InvalidAddress { reason, .. } => reason,
                            other => other.to_string(),
                        },
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        binds.sort_by_key(|addr| addr.is_ipv6());
        match binds.as_slice() {
            [_] => {}
            [first, second] if first.is_ipv6() != second.is_ipv6() => {}
            _ => {
                return Err(QuicBindError::AddressFamilies { count: addrs.len() });
            }
        }
        // Checked before any socket is bound.
        let transport_config = transport_config(node_config.limits())?;
        let budget = MemoryBudget::new(node_config.limits(), binds.len()).ok_or(
            QuicBindError::InvalidLimit {
                field: "memory_budget_bytes",
                requirement: "must fit each socket's datagram_queue_reservation_bytes() plus one \
                     connection_reservation_bytes() and one stream_reservation_bytes()",
            },
        )?;
        let sockets = binds
            .into_iter()
            .map(|addr| {
                if addr.is_ipv6() {
                    bind_ipv6_only_udp(addr).map(|udp| (addr, udp))
                } else {
                    bind_ipv4_udp(addr).map(|udp| (addr, udp))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_sockets(node_config, transport_config, budget, sockets)
    }

    /// Binds an IPv4 and an IPv6 wildcard socket, each on its own ephemeral
    /// port.
    pub fn dual_stack(node_config: QuicNodeConfig) -> Result<Self, QuicBindError> {
        let wildcards = [
            socket_addr_to_multiaddr(SocketAddr::from(([0, 0, 0, 0], 0))),
            socket_addr_to_multiaddr(SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))),
        ];
        Self::bind(node_config, &wildcards)
    }

    fn from_sockets(
        node_config: QuicNodeConfig,
        transport_config: TransportConfig,
        budget: MemoryBudget,
        udps: Vec<(SocketAddr, UdpSocket)>,
    ) -> Result<Self, QuicBindError> {
        let transport_config = Arc::new(transport_config);
        let tally = DatagramTally::register(&node_config.peer_id());
        let max_pending_datagrams = node_config.limits().max_pending_datagrams;
        let sockets = udps
            .into_iter()
            .map(|(requested, udp)| {
                udp.set_nonblocking(true)
                    .map_err(|e| QuicBindError::socket(requested, "set non-blocking", &e))?;
                let local_addr = udp
                    .local_addr()
                    .map_err(|e| QuicBindError::socket(requested, "read local address", &e))?;
                Socket::new(udp, local_addr, max_pending_datagrams, tally.clone())
                    .map_err(|e| QuicBindError::socket(local_addr, "configure", &e))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let host_time = Arc::new(HostTime::default());
        let tls = TlsIdentity::new(node_config.keypair(), Arc::clone(&host_time))?;
        let server_tls = tls
            .server_config()
            .map_err(|error| QuicBindError::tls(QuicTlsStage::ServerConfig, error))?;
        let crypto = QuicServerConfig::try_from(server_tls)
            .map_err(|error| QuicBindError::tls(QuicTlsStage::QuicCipherSuites, error))?;
        let mut server_config = ServerConfig::with_crypto(Arc::new(crypto));
        let mut validation_tokens = ValidationTokenConfig::default();
        // Retry stays the only address validation: no NEW_TOKEN is issued.
        validation_tokens.sent(0);
        server_config
            .transport_config(Arc::clone(&transport_config))
            .retry_token_lifetime(RETRY_TOKEN_LIFETIME)
            .validation_token_config(validation_tokens);

        let endpoint_config = EndpointConfig::default();
        let max_payload =
            usize::try_from(endpoint_config.get_max_udp_payload_size()).unwrap_or(RECV_BUFFER_SIZE);
        let recv_buf_len = sockets
            .iter()
            .map(|socket| socket.recv_buffer_len(max_payload))
            .max()
            .unwrap_or(RECV_BUFFER_SIZE);
        // Path MTU discovery needs datagrams the network drops rather than
        // fragments when they are too large.
        let allow_mtu_discovery = sockets.iter().all(|socket| !socket.may_fragment());
        Ok(Self {
            sockets: Sockets::new(sockets),
            registered: Vec::new(),
            dispatched: false,
            // No server config until `listen`: the endpoint accepts nothing.
            endpoint: quinn_proto::Endpoint::new(
                Arc::new(endpoint_config),
                None,
                allow_mtu_discovery,
                None,
            ),
            server_config: Arc::new(server_config),
            transport_config,
            tls,
            host_time,
            connections: HashMap::new(),
            unsettled: UnsettledConnections::new(),
            budget,
            handles: HashMap::new(),
            pending_events: Vec::new(),
            recv_buf: vec![0; recv_buf_len],
            recv_slots: Vec::new(),
            send_buf: Vec::new(),
            received: Vec::new(),
            timers: BTreeSet::new(),
            unfinished: BTreeSet::new(),
            due: Vec::new(),
            #[cfg(test)]
            services: 0,
            node_config,
            clock: None,
        })
    }

    /// The bound socket addresses, IPv4 first.
    pub fn local_socket_addrs(&self) -> Vec<SocketAddr> {
        self.sockets
            .iter()
            .map(|socket| socket.local_addr)
            .collect()
    }

    /// The [`ConnectionNamespace`]s this transport allocates connection ids
    /// in: one per bound family. A host routing several transports needs this
    /// to say which ids are QUIC's -- see `minip2p_transport::TransportSet`.
    pub fn namespaces(&self) -> Vec<ConnectionNamespace> {
        self.sockets
            .iter()
            .map(|socket| socket.ids.namespace())
            .collect()
    }

    /// Returns this node's `PeerId`, derived from the configured keypair.
    pub fn local_peer_id(&self) -> PeerId {
        self.node_config.peer_id()
    }

    /// A live connection's diagnostic counters (`diagnostics` feature).
    #[cfg(feature = "diagnostics")]
    pub fn connection_diagnostics(&self, id: ConnectionId) -> Option<ConnectionDiagnostics> {
        self.connections.get(&id).map(QuicConnection::diagnostics)
    }

    /// A `PeerAddr` other nodes can dial for each bound socket.
    pub fn local_peer_addrs(&self) -> Result<Vec<PeerAddr>, TransportError> {
        let peer_id = self.local_peer_id();
        self.sockets
            .iter()
            .map(|socket| {
                let addr = socket_addr_to_multiaddr(socket.local_addr);
                PeerAddr::new(addr.clone(), peer_id.clone())
                    .map_err(|error| TransportError::LocalPeerAddr { addr, error })
            })
            .collect()
    }

    /// Listens on every bound socket's address; returns them.
    ///
    /// Convenience wrapper around [`listen`](Transport::listen), avoiding
    /// manual `Multiaddr` construction.
    pub fn listen_on_bound_addrs(&mut self) -> Result<Vec<Multiaddr>, TransportError> {
        self.local_addresses()
            .iter()
            .map(|addr| self.listen(addr))
            .collect()
    }

    /// The first bound socket's address, for tests on one socket.
    #[cfg(test)]
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_socket_addrs()[0]
    }

    /// The first bound socket, for tests on one socket.
    #[cfg(test)]
    pub(crate) fn socket(&mut self) -> &mut Socket {
        self.sockets.get_mut(0).expect("a bound socket")
    }

    /// Connection slots held: live connections plus unsettled ones.
    fn slots_held(&self) -> usize {
        self.connections.len() + self.unsettled.len()
    }

    /// A dial's engine config: this node's identity, and a verifier that
    /// rejects any listener not proving `expected`.
    ///
    /// Both steps fail only for a crypto provider without TLS 1.3 or QUIC's
    /// cipher suites, which the listener's config already proved this one has.
    fn client_config(&self, expected: &PeerId) -> Result<ClientConfig, TransportError> {
        let unsupported = || TransportError::Unsupported {
            operation: "a TLS 1.3 QUIC client configuration",
        };
        let tls = self
            .tls
            .client_config(Some(expected.clone()))
            .map_err(|_no_tls13| unsupported())?;
        let crypto = QuicClientConfig::try_from(tls).map_err(|_no_quic_suite| unsupported())?;
        let mut config = ClientConfig::new(Arc::new(crypto));
        config.transport_config(Arc::clone(&self.transport_config));
        Ok(config)
    }

    /// Reads from socket `index` until [`MAX_DATAGRAMS_PER_POLL`] logical
    /// datagrams have arrived, and hands each to the engine. Connections only
    /// queue output here; the sweep sends it.
    ///
    /// What one receive call read (several datagrams where the platform
    /// batches receives, a GRO batch where it coalesces them) is always
    /// handled to the end, so the bound can be overshot by less than one
    /// call's worth.
    fn recv_batch(&mut self, now: Instant, index: usize) -> Result<(), TransportError> {
        let mut slots = std::mem::take(&mut self.recv_slots);
        let result = self.recv_into(now, index, &mut slots);
        self.recv_slots = slots;
        result
    }

    /// [`Self::recv_batch`], with `slots` as scratch for what each receive
    /// call filled.
    fn recv_into(
        &mut self,
        now: Instant,
        index: usize,
        slots: &mut Vec<Received>,
    ) -> Result<(), TransportError> {
        let mut datagrams = 0;
        let mut saturated = true;
        while datagrams < MAX_DATAGRAMS_PER_POLL {
            let Some(socket) = self.sockets.get_mut(index) else {
                return Ok(());
            };
            slots.clear();
            // Through the registered clone's `try_io` once attached: on
            // Windows mio only re-arms readiness when it sees the
            // `WouldBlock` itself, and a receive on the original socket would
            // hide it, leaving later datagrams with no wakeup.
            let recv_buf = &mut self.recv_buf;
            let read = match self.registered.get(index) {
                Some(registered) => registered
                    .try_io(|| {
                        socket
                            .recv(recv_buf, slots)?
                            .then_some(())
                            .ok_or_else(|| std::io::ErrorKind::WouldBlock.into())
                    })
                    .map(|()| true)
                    .or_else(|error| {
                        if error.kind() == std::io::ErrorKind::WouldBlock {
                            Ok(false)
                        } else {
                            Err(error)
                        }
                    }),
                None => socket.recv(recv_buf, slots),
            };
            match read {
                Ok(true) => {}
                Ok(false) => {
                    saturated = false;
                    break;
                }
                Err(e) => {
                    socket.saturated = false;
                    return Err(TransportError::io("receiving UDP datagrams", &e));
                }
            }
            // One allocation per receive call, whatever it read; each
            // datagram is a slice of it.
            let mut data = BytesMut::with_capacity(slots.iter().map(|slot| slot.len).sum());
            for slot in slots.iter() {
                data.extend_from_slice(
                    self.recv_buf
                        .get(slot.offset..slot.offset + slot.len)
                        .expect("UDP receive lengths fit their slots"),
                );
            }
            for slot in slots.iter() {
                datagrams += slot.datagrams();
                let mut rest = data.split_to(slot.len);
                while !rest.is_empty() {
                    let datagram = rest.split_to(slot.stride.min(rest.len()));
                    self.handle_datagram(now, index, slot, datagram);
                }
            }
        }
        if let Some(socket) = self.sockets.get_mut(index) {
            socket.saturated = saturated;
        }
        Ok(())
    }

    /// Routes one datagram that arrived on socket `index`. The endpoint
    /// routes by connection id, never by source address, and drops what it
    /// cannot parse.
    fn handle_datagram(
        &mut self,
        now: Instant,
        index: usize,
        received: &Received,
        datagram: BytesMut,
    ) {
        let mut buf = std::mem::take(&mut self.send_buf);
        buf.clear();
        match self.endpoint.handle(
            now,
            received.from,
            received.dst_ip,
            received.ecn,
            datagram,
            &mut buf,
        ) {
            Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                if let Some((&id, conn)) = self
                    .handles
                    .get_key_value(&handle)
                    .and_then(|(_, id)| self.connections.get_mut(id).map(|conn| (id, conn)))
                {
                    conn.handle_event(event);
                    // `service_due` dedups; this only keeps a burst to one
                    // connection from repeating it.
                    if self.received.last() != Some(&id) {
                        self.received.push(id);
                    }
                }
            }
            Some(DatagramEvent::NewConnection(incoming)) => {
                self.admit(now, index, incoming, &mut buf);
            }
            // A reply to a datagram no connection owns. The endpoint answers
            // an unknown Initial with a stateless reset even before `listen`;
            // a socket that is not listening sends nothing at all.
            Some(DatagramEvent::Response(transmit)) => {
                if let Some(socket) = self.sockets.get_mut(index).filter(|s| s.listening) {
                    send_stateless(socket, &buf, &transmit);
                }
            }
            None => {}
        }
        self.send_buf = buf;
    }

    /// Admits a new inbound connection on socket `index`: ignored unless the
    /// socket listens, refused silently at the connection limit (before any
    /// Retry), sent a Retry while its address is unvalidated and validation
    /// is required, refused when its memory reservation does not fit (with
    /// `CONNECTION_REFUSED` from a validated address, silently otherwise),
    /// accepted otherwise.
    fn admit(&mut self, now: Instant, index: usize, incoming: Incoming, buf: &mut Vec<u8>) {
        let limits = self.node_config.limits().clone();
        let has_slot = self.slots_held() < limits.max_connections;
        let fits = self.budget.fits_connection();
        let Some(socket) = self
            .sockets
            .get_mut(index)
            .filter(|socket| socket.listening && has_slot)
        else {
            self.endpoint.ignore(incoming);
            return;
        };
        if limits.require_address_validation && !incoming.remote_address_validated() {
            match self.endpoint.retry(incoming, buf) {
                Ok(transmit) => send_stateless(socket, buf, &transmit),
                Err(error) => self.endpoint.ignore(error.into_incoming()),
            }
            return;
        }
        if !fits {
            // Only a validated address is told: refusing an unvalidated one
            // would let a spoofed source turn this node into a reflector.
            if incoming.remote_address_validated() {
                let transmit = self.endpoint.refuse(incoming, buf);
                send_stateless(socket, buf, &transmit);
            } else {
                self.endpoint.ignore(incoming);
            }
            return;
        }
        let Ok(id) = socket.ids.allocate() else {
            self.endpoint.ignore(incoming);
            return;
        };
        match self.endpoint.accept(incoming, now, buf, None) {
            Ok((handle, conn)) => {
                self.budget.reserve_connection();
                // The accepted Initial never passes through `handle_event`.
                let mut counters = ConnectionCounters::default();
                counters.datagram_received();
                let endpoint =
                    ConnectionEndpoint::new(socket_addr_to_multiaddr(conn.remote_address()));
                let conn =
                    QuicConnection::new(id, handle, conn, endpoint.clone(), &limits, counters);
                self.connections.insert(id, conn);
                self.handles.insert(handle, id);
                self.received.push(id);
                self.pending_events
                    .push(TransportEvent::IncomingConnection { id, endpoint });
            }
            Err(error) => {
                if let Some(transmit) = error.response {
                    send_stateless(socket, buf, &transmit);
                }
            }
        }
    }

    /// Services the connections with work: those this poll routed datagrams
    /// to, those whose timer is due, and those a previous service left
    /// unfinished. Idle connections are not visited.
    fn service_due(&mut self, now: Instant) {
        let mut due = std::mem::take(&mut self.due);
        due.clear();
        due.append(&mut self.received);
        due.extend(self.unfinished.iter().copied());
        due.extend(
            self.timers
                .iter()
                .take_while(|(timeout, _)| *timeout <= now)
                .map(|&(_, id)| id),
        );
        due.sort_unstable();
        due.dedup();
        for &id in &due {
            self.service(id, now);
        }
        self.due = due;
    }

    /// Runs one connection's engine and sends its output, keeps the timer
    /// index current, and retires the connection once it drained. Returns
    /// the first hard socket error its output hit.
    fn service(&mut self, id: ConnectionId, now: Instant) -> Option<std::io::Error> {
        let conn = self.connections.get_mut(&id)?;
        let before = conn.timeout();
        let mut cx = Cx {
            endpoint: &mut self.endpoint,
            sockets: &mut self.sockets,
            send_buf: &mut self.send_buf,
            events: &mut self.pending_events,
            budget: &mut self.budget,
        };
        let failure = conn.service(now, &mut cx);
        let (after, unfinished, drained) =
            (conn.timeout(), conn.is_unfinished(), conn.is_drained());
        #[cfg(test)]
        {
            self.services += 1;
        }
        if before != after {
            if let Some(timeout) = before {
                self.timers.remove(&(timeout, id));
            }
            if let Some(timeout) = after {
                self.timers.insert((timeout, id));
            }
        }
        if unfinished {
            self.unfinished.insert(id);
        } else {
            self.unfinished.remove(&id);
        }
        if drained {
            self.remove_connection(id);
        }
        failure
    }

    /// Replaces the server config, also on the endpoint once listening.
    #[cfg(test)]
    fn update_server_config(&mut self, update: impl FnOnce(&mut ServerConfig)) {
        update(Arc::make_mut(&mut self.server_config));
        if self.sockets.iter().any(|socket| socket.listening) {
            self.endpoint
                .set_server_config(Some(Arc::clone(&self.server_config)));
        }
    }

    /// Forgets a drained connection, releases its fixed reservation, and
    /// reports it closed. One whose streams still hold delivered,
    /// unacknowledged bytes keeps only those counts, their stream
    /// reservations, and its connection slot until they settle.
    fn remove_connection(&mut self, id: ConnectionId) {
        let Some(conn) = self.connections.remove(&id) else {
            return;
        };
        self.handles.remove(&conn.handle());
        if let Some(timeout) = conn.timeout() {
            self.timers.remove(&(timeout, id));
        }
        self.unfinished.remove(&id);
        self.received.retain(|&received| received != id);
        let held = self.unsettled.streams();
        self.unsettled.insert(id, conn.unsettled_streams());
        let kept = self.unsettled.streams() - held;
        self.budget.release_connection();
        self.budget.release_streams(conn.stream_count() - kept);
        self.pending_events.push(TransportEvent::Closed { id });
    }

    /// Settles held streams of ended connections through `settle`, releasing
    /// the reservations of every stream it settled. Returns what `settle`
    /// did.
    fn settle_unsettled<R>(&mut self, settle: impl FnOnce(&mut UnsettledConnections) -> R) -> R {
        let held = self.unsettled.streams();
        let result = settle(&mut self.unsettled);
        self.budget.release_streams(held - self.unsettled.streams());
        result
    }

    /// Discards a connection that never got going: closed, with its close
    /// period run out at once, so the engine forgets it without a packet.
    fn abandon(&mut self, id: ConnectionId, now: Instant) {
        if let Some(conn) = self.connections.get_mut(&id) {
            conn.close(now);
            conn.expire();
        }
        self.service(id, now);
        // Nothing was reported for it; the caller learns from the error.
        self.pending_events.retain(|event| match event {
            TransportEvent::Error { id: event_id, .. }
            | TransportEvent::Closed { id: event_id } => *event_id != id,
            _ => true,
        });
    }
}

/// Sends a stateless reply the endpoint wrote into `buf`.
fn send_stateless(socket: &mut Socket, buf: &[u8], transmit: &quinn_proto::Transmit) {
    if let Some(contents) = buf.get(..transmit.size) {
        socket.send_stateless(transmit, contents);
    }
}

impl Transport for QuicTransport {
    fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        let peer_socket = dial_socket_addr(addr.transport(), "dial target")?;
        let max_connections = self.node_config.limits().max_connections;
        let slots_held = self.slots_held();
        let socket = self
            .sockets
            .for_addr(peer_socket)
            .ok_or_else(|| missing_family("dial target", peer_socket))?;
        // The connection limit and the memory budget count inbound and
        // outbound alike, across sockets; admission enforces the same bounds
        // for incoming Initials.
        if slots_held >= max_connections {
            return Err(TransportError::ResourceExhausted {
                resource: "QUIC connections",
            });
        }
        if !self.budget.fits_connection() {
            return Err(MemoryBudget::exhausted());
        }
        let id = socket.ids.allocate()?;
        let config = self.client_config(addr.peer_id())?;
        let now = Instant::now();
        let (handle, conn) = self
            .endpoint
            .connect(now, config, peer_socket, SERVER_NAME)
            .map_err(|e| TransportError::DialFailed {
                id,
                reason: format!("QUIC connect error: {e}"),
            })?;
        self.budget.reserve_connection();
        let conn = QuicConnection::new(
            id,
            handle,
            conn,
            ConnectionEndpoint::from_peer_addr(addr),
            self.node_config.limits(),
            ConnectionCounters::default(),
        );
        self.connections.insert(id, conn);
        self.handles.insert(handle, id);

        // A first flight the socket refuses outright (no route) fails the
        // dial now rather than at the handshake timeout.
        if let Some(error) = self.service(id, now) {
            self.abandon(id, now);
            return Err(TransportError::DialFailed {
                id,
                reason: format!("udp send error: {error}"),
            });
        }
        Ok(id)
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        let requested = extract_listen_socket_addr(addr, "listen address")?;
        let socket = self
            .sockets
            .for_addr(requested)
            .ok_or_else(|| missing_family("listen address", requested))?;
        ensure_listen_matches_bound_socket(requested, socket.local_addr)?;
        let listen_addr = socket_addr_to_multiaddr(socket.local_addr);
        // Listening again is the same listener: report the address without
        // announcing it twice (the endpoint listens at bind, and callers may
        // still ask `listen` for the address afterwards).
        if std::mem::replace(&mut socket.listening, true) {
            return Ok(listen_addr);
        }
        // One endpoint serves both sockets; admission checks that the socket
        // an Initial arrived on is listening.
        self.endpoint
            .set_server_config(Some(Arc::clone(&self.server_config)));
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

        let stream_id = conn.open_stream(&mut self.budget)?;
        self.pending_events
            .push(TransportEvent::StreamOpened { id, stream_id });
        self.service(id, Instant::now());
        Ok(stream_id)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
    ) -> Result<(), TransportError> {
        let conn = self
            .connections
            .get_mut(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;

        let result = conn.send_stream(stream_id, data, &mut self.pending_events);
        self.service(id, Instant::now());
        result
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

        let result = conn.close_stream_write(stream_id);
        // Writable never follows the end of a write side, even one a Full
        // queued before its call returned.
        self.pending_events
            .retain(|event| *event != TransportEvent::StreamWritable { id, stream_id });
        self.service(id, Instant::now());
        result
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        let Some(conn) = self.connections.get_mut(&id) else {
            // Abandoning a stream of an ended connection only settles it.
            if self.settle_unsettled(|unsettled| unsettled.abandon(id, stream_id)) {
                return Ok(());
            }
            return Err(TransportError::ConnectionNotFound { id });
        };

        let result = conn.reset_stream(stream_id, &mut self.budget, &mut self.pending_events);
        self.pending_events
            .retain(|event| *event != TransportEvent::StreamWritable { id, stream_id });
        self.service(id, Instant::now());
        result
    }

    fn ack_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        bytes: usize,
    ) -> Result<(), TransportError> {
        let Some(conn) = self.connections.get_mut(&id) else {
            // An ended connection's bytes are released without credit.
            self.settle_unsettled(|unsettled| unsettled.ack(id, stream_id, bytes))?;
            return Ok(());
        };
        // A stream that had spent its budget resumes now, not when the next
        // packet happens to arrive: the engine already holds what it can read.
        let result = conn.ack_stream(stream_id, bytes, &mut self.pending_events);
        self.service(id, Instant::now());
        result
    }

    fn set_control_stream(&mut self, id: ConnectionId, stream_id: StreamId, control: bool) {
        if let Some(conn) = self.connections.get_mut(&id) {
            conn.set_control_stream(stream_id, control, &mut self.pending_events);
        }
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        let conn = self
            .connections
            .get_mut(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;

        conn.close(Instant::now());
        // Nor may one a Full queued before the close.
        self.pending_events.retain(
            |event| !matches!(event, TransportEvent::StreamWritable { id: event_id, .. } if *event_id == id),
        );
        self.service(id, Instant::now());
        Ok(())
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        self.sockets
            .iter()
            .map(|socket| socket_addr_to_multiaddr(socket.local_addr))
            .collect()
    }

    /// Sockets are bound once, at construction, so the set never changes.
    fn local_addresses_revision(&self) -> Option<u64> {
        Some(0)
    }

    fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
        self.connections
            .values()
            .filter(|conn| conn.is_server())
            .map(|conn| conn.endpoint().transport().clone())
            .collect()
    }

    /// Sends one raw UDP datagram to an `/ip4|ip6/<addr>/udp/<port>/quic-v1`
    /// target, for NAT hole punching (e.g. DCUtR): it leaves from the socket
    /// later QUIC packets will arrive on. `/dns*` hosts are rejected, so
    /// resolve names first.
    fn send_datagram(&mut self, target: &Multiaddr, payload: &[u8]) -> Result<(), TransportError> {
        let addr = dial_socket_addr(target, "raw udp target")?;
        let socket = self
            .sockets
            .for_addr(addr)
            .ok_or_else(|| missing_family("raw udp target", addr))?;
        socket
            .udp
            .send_to(payload, addr)
            .map_err(|e| TransportError::io("sending a raw UDP datagram", &e))?;
        socket.tally.sent(1, payload.len());
        Ok(())
    }

    fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        // The engine runs on a fine-grained `Instant` sampled once per poll;
        // the host's millisecond sample anchors `next_deadline` and is never
        // handed to the engine as time.
        let instant = Instant::now();
        self.clock = Some((now, instant));
        self.host_time.set(now.unix_seconds);
        self.dispatched = false;
        // Events accumulate in `self.pending_events` for the whole poll and
        // are only taken at the very end, so an error path leaves the batch
        // queued for the next call instead of dropping it.
        for socket in self.sockets.iter_mut() {
            socket.flush();
        }
        // Each socket gets its own receive bound, so one family's traffic
        // cannot starve the other. The service below runs whatever ended a
        // batch: connections defer their output to it.
        let mut received = Ok(());
        for index in 0..self.sockets.len() {
            let batch = self.recv_batch(instant, index);
            if received.is_ok() {
                received = batch;
            }
        }
        self.service_due(instant);
        received?;
        Ok(std::mem::take(&mut self.pending_events))
    }

    fn next_deadline(&self) -> Option<Deadline> {
        // Events buffered outside a poll -- `listen`, `open_stream`,
        // `send_stream`, `close_stream_write` and `reset_stream` all queue
        // here between polls -- are due regardless of what the clock reads,
        // and nothing else would wake a host idling on `None`. A receive
        // batch cut off by its bound may have left input with no fresh
        // readiness edge to report it.
        if self.dispatched
            || !self.pending_events.is_empty()
            || self.sockets.iter().any(|socket| socket.saturated)
        {
            return Some(Deadline::IMMEDIATE);
        }

        // Datagrams stuck on socket writability can't be woken by a readable
        // peek; return a near deadline so the driver retries the flush soon.
        // Checked before the retained sample: `dial` queues datagrams before
        // the first `poll`, and a host that idled on `None` there would never
        // come back to flush them. `IMMEDIATE` is due on any timeline.
        // Connections a service left unfinished (most often behind those
        // datagrams) need another the same way.
        if self.sockets.iter().any(Socket::has_pending) || !self.unfinished.is_empty() {
            return Some(
                self.clock
                    .map_or(Deadline::IMMEDIATE, |(now, _)| now.deadline_after(1)),
            );
        }

        // No sample yet means no timeline to answer on.
        let (now, instant) = self.clock?;
        self.timers.first().map(|&(timeout, _)| {
            deadline_for_timeout(now, timeout.saturating_duration_since(instant))
        })
    }
}

/// Quiet connections send an ack-eliciting packet at half the idle timeout,
/// matching rust-libp2p / quic-go's "keep-alive at idle/2" rule.
fn keepalive_interval_ms(idle_timeout_ms: u64) -> u64 {
    idle_timeout_ms.max(2) / 2
}

/// Converts the delay until an engine timeout into a deadline on the host's
/// timeline.
///
/// The delay is measured from the `Instant` sampled with the poll's `Now`, so
/// it maps onto the host's timeline exactly, give or take the sub-millisecond
/// gap between the two samples.
///
/// [`Deadline`] has millisecond granularity while engine timeouts routinely
/// land under a millisecond on loopback. Truncating those to zero would report
/// "already due", which drives the swarm's budget loop to a zero-length sleep
/// and spins the thread until wall time catches up. Any non-zero delay is
/// therefore rounded *up* to the next millisecond; the sub-millisecond delay
/// that adds sits well inside the driver's own 1ms idle cadence.
fn deadline_for_timeout(now: Now, timeout: Duration) -> Deadline {
    if timeout.is_zero() {
        // Genuinely due: let the driver poll again without idling.
        return now.as_deadline();
    }
    let millis = u64::try_from(timeout.as_nanos().div_ceil(1_000_000)).unwrap_or(u64::MAX);
    now.deadline_after(millis.max(1))
}

impl Drop for QuicTransport {
    fn drop(&mut self) {
        // Nothing polls after this, so every connection's CONNECTION_CLOSE
        // leaves now. Drain the retry queues first so a full one has room to
        // retain them; closing an already-closed connection is a no-op.
        for socket in self.sockets.iter_mut() {
            socket.flush();
        }
        let ids: Vec<ConnectionId> = self.connections.keys().copied().collect();
        for id in ids {
            match self.close(id) {
                Ok(()) | Err(_) => {}
            }
        }
        for socket in self.sockets.iter_mut() {
            socket.flush();
            socket.clear();
        }
    }
}

/// Registers a clone of every socket, one token each, and receives through
/// it. Dispatch only records that something arrived: every poll reads every
/// socket until `WouldBlock`, and until that poll runs `next_deadline` reports
/// due now, as does a receive batch cut off by its bound, so an edge is never
/// needed twice.
impl PollSource for QuicTransport {
    fn attach(
        &mut self,
        registry: Registry,
        tokens: TokenSpace,
        _waker: Arc<Waker>,
    ) -> std::io::Result<()> {
        let mut registered = Vec::with_capacity(self.sockets.len());
        let result = self
            .sockets
            .iter()
            .enumerate()
            .try_for_each(|(index, socket)| {
                let token = tokens
                    .token(index)
                    .ok_or_else(|| std::io::Error::other("no token left for a QUIC socket"))?;
                let mut clone = mio::net::UdpSocket::from_std(socket.udp.try_clone()?);
                registry.register(&mut clone, token, Interest::READABLE)?;
                registered.push(clone);
                Ok(())
            });
        if let Err(error) = result {
            // All or nothing: a clone shares the socket's file description,
            // so dropping it would not drop the registration.
            for mut clone in registered {
                drop(registry.deregister(&mut clone));
            }
            return Err(error);
        }
        self.registered = registered;
        Ok(())
    }

    fn dispatch(&mut self, _event: &Event) {
        self.dispatched = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_peer::loopback;
    use minip2p_identity::Ed25519Keypair;

    fn quic_addr(addr: &str) -> Multiaddr {
        socket_addr_to_multiaddr(addr.parse().expect("socket addr"))
    }

    fn target(addr: &str) -> PeerAddr {
        PeerAddr::new(quic_addr(addr), Ed25519Keypair::generate().peer_id()).expect("peer addr")
    }

    fn socket(transport: &mut QuicTransport, ipv6: bool) -> &mut Socket {
        let addr = if ipv6 { "[::1]:1" } else { "127.0.0.1:1" };
        transport
            .sockets
            .for_addr(addr.parse().expect("addr"))
            .expect("a socket of that family")
    }

    #[test]
    fn the_bound_address_is_exposed_as_a_transport_multiaddr() {
        let transport = loopback(QuicNodeConfig::generate());
        let bound = transport.local_addr();
        assert_ne!(bound.port(), 0, "the OS must resolve the ephemeral port");
        assert_eq!(
            Transport::local_addresses(&transport),
            vec![Multiaddr::from_protocols(vec![
                Protocol::Ip4([127, 0, 0, 1]),
                Protocol::Udp(bound.port()),
                Protocol::QuicV1,
            ])]
        );
    }

    #[test]
    fn one_socket_per_family_binds_and_anything_else_is_refused() {
        let ipv4 = quic_addr("127.0.0.1:0");
        let ipv6 = quic_addr("[::1]:0");
        for (addrs, namespaces) in [
            (vec![ipv4.clone()], vec![ConnectionNamespace::QUIC_IPV4]),
            (vec![ipv6.clone()], vec![ConnectionNamespace::QUIC_IPV6]),
            (
                vec![ipv6.clone(), ipv4.clone()],
                vec![
                    ConnectionNamespace::QUIC_IPV4,
                    ConnectionNamespace::QUIC_IPV6,
                ],
            ),
        ] {
            let transport = QuicTransport::bind(QuicNodeConfig::generate(), &addrs)
                .unwrap_or_else(|e| panic!("{addrs:?}: {e}"));
            assert_eq!(transport.namespaces(), namespaces, "{addrs:?}");
            assert_eq!(transport.local_addresses().len(), addrs.len());
        }

        let named: Multiaddr = "/dns4/localhost/udp/0/quic-v1".parse().expect("dns addr");
        for addrs in [
            vec![],
            vec![ipv4.clone(), quic_addr("127.0.0.2:0")],
            vec![ipv4.clone(), ipv6.clone(), quic_addr("127.0.0.2:0")],
            vec![named],
        ] {
            assert!(
                matches!(
                    QuicTransport::bind(QuicNodeConfig::generate(), &addrs),
                    Err(QuicBindError::AddressFamilies { .. }
                        | QuicBindError::InvalidAddress { .. })
                ),
                "{addrs:?} must be refused"
            );
        }
    }

    #[test]
    fn best_effort_datagram_queue_drops_overflow_without_error() {
        let limits = QuicLimits {
            max_pending_datagrams: 2,
            ..QuicLimits::default()
        };
        let mut transport = loopback(QuicNodeConfig::generate().with_limits(limits));
        let destination = transport.local_addr();
        let socket = socket(&mut transport, false);
        for payload in [&[1u8][..], &[2u8][..], &[3u8][..]] {
            socket.retain_datagram(payload, destination);
        }
        assert_eq!(
            socket.retained(),
            2,
            "queue must cap at the limit and silently drop the overflow"
        );
    }

    #[test]
    fn zero_limits_are_rejected_at_construction() {
        // A zero idle timeout would disable expiry entirely (QUIC treats 0
        // as "no timeout"), and a zero datagram queue could never retain a
        // packet; both must fail fast instead of silently misbehaving.
        for limits in [
            QuicLimits {
                idle_timeout_ms: 0,
                ..QuicLimits::default()
            },
            QuicLimits {
                max_pending_datagrams: 0,
                ..QuicLimits::default()
            },
        ] {
            let result = QuicTransport::bind(
                QuicNodeConfig::generate().with_limits(limits),
                &[quic_addr("127.0.0.1:0")],
            );
            assert!(matches!(result, Err(QuicBindError::InvalidLimit { .. })));
        }
    }

    #[test]
    fn poll_drains_a_bounded_number_of_datagrams_per_call() {
        let mut transport = loopback(QuicNodeConfig::generate());
        let destination = transport.local_addr();

        let sender = UdpSocket::bind("127.0.0.1:0").expect("sender");
        for _ in 0..MAX_DATAGRAMS_PER_POLL + 8 {
            sender.send_to(&[0u8; 8], destination).expect("send");
        }

        // Wait for the kernel to queue the first datagram, then give the
        // rest a moment to land before polling.
        let udp = socket(&mut transport, false)
            .udp
            .try_clone()
            .expect("clone");
        let start = std::time::Instant::now();
        while !socket::has_queued_input(&udp) {
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "datagrams never arrived"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(50));

        transport.poll(Now::from_millis(0)).expect("poll");
        assert!(
            socket::has_queued_input(&udp),
            "one poll must leave datagrams beyond the per-poll bound in the kernel buffer"
        );
        assert_eq!(
            transport.next_deadline(),
            Some(Deadline::IMMEDIATE),
            "a saturated batch has the driver poll again at once"
        );

        // Follow-up polls drain the remainder.
        let start = std::time::Instant::now();
        while socket::has_queued_input(&udp) {
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "overflow never drained"
            );
            transport.poll(Now::from_millis(0)).expect("poll");
        }
    }

    #[test]
    fn poisoned_queued_datagram_is_dropped_without_failing_the_poll() {
        let mut transport = loopback(QuicNodeConfig::generate());
        let addr = transport.local_addresses().remove(0);
        transport
            .pending_events
            .push(TransportEvent::Listening { addr: addr.clone() });

        // An IPv6 destination on an IPv4 socket makes the datagram send fail
        // with a hard error. A dead route affects only that packet's
        // destination, so the poll must drop it and carry on rather than
        // abort the whole endpoint.
        let good_destination = transport.local_addr();
        let socket = socket(&mut transport, false);
        socket.retain_datagram(&[0u8; 4], "[::1]:9".parse().expect("socket addr"));
        socket.retain_datagram(&[0u8; 4], good_destination);

        let events = transport.poll(Now::from_millis(0)).expect("poll");
        assert!(
            events
                .iter()
                .any(|event| matches!(event, TransportEvent::Listening { addr: a } if *a == addr)),
            "events queued before the poisoned datagram must still be delivered"
        );
        assert!(
            !transport.sockets.iter().any(Socket::has_pending),
            "the poisoned datagram must be dropped and the one behind it sent"
        );
    }

    #[test]
    fn sub_millisecond_timeouts_never_report_as_already_due() {
        let now = Now::from_millis(10_000);

        // The regression: truncating to whole milliseconds turned "due in
        // 300us" into "due now", so the driver took a zero-length budget and
        // span until wall time caught up.
        for timeout in [
            Duration::from_nanos(1),
            Duration::from_micros(1),
            Duration::from_micros(300),
            Duration::from_micros(999),
            Duration::from_millis(1),
        ] {
            let deadline = deadline_for_timeout(now, timeout);
            assert_eq!(
                deadline.millis_until(now),
                1,
                "{timeout:?} must round up to a whole millisecond"
            );
        }

        // Partial milliseconds round up rather than truncating down.
        assert_eq!(
            deadline_for_timeout(now, Duration::from_micros(1_500)).millis_until(now),
            2
        );
        assert_eq!(
            deadline_for_timeout(now, Duration::from_millis(5)).millis_until(now),
            5
        );

        // Zero really is due now: the driver should re-poll without idling.
        assert_eq!(
            deadline_for_timeout(now, Duration::ZERO).millis_until(now),
            0
        );
        assert!(deadline_for_timeout(now, Duration::ZERO).is_expired_at(now));
    }

    #[test]
    fn queued_datagrams_are_reported_before_the_first_poll() {
        let mut transport = loopback(QuicNodeConfig::generate());
        assert_eq!(transport.next_deadline(), None, "idle and never polled");

        // `dial` can queue a datagram before any poll has taken a sample. A
        // host that idled on `None` here would never flush it.
        let destination = transport.local_addr();
        socket(&mut transport, false).retain_datagram(&[0u8; 4], destination);

        let deadline = transport.next_deadline().expect("queued work must be due");
        assert!(
            deadline.is_expired_at(Now::from_millis(0)),
            "with no retained sample the deadline must be due on any timeline"
        );
    }

    #[test]
    fn next_deadline_is_near_while_outbound_work_is_queued() {
        let mut transport = loopback(QuicNodeConfig::generate());
        // Never polled, so there is no host timeline to answer on yet.
        assert_eq!(transport.next_deadline(), None);

        let now = Now::from_millis(10_000);
        transport.poll(now).expect("poll");
        assert_eq!(
            transport.next_deadline(),
            None,
            "an idle transport arms no timer"
        );

        let destination = transport.local_addr();
        socket(&mut transport, false).retain_datagram(&[0u8; 4], destination);
        assert_eq!(
            transport.next_deadline(),
            Some(now.deadline_after(1)),
            "queued datagrams must keep the driver polling"
        );
    }

    #[test]
    fn explicit_dual_stack_wildcards_can_share_one_port() {
        let reservation = UdpSocket::bind("0.0.0.0:0").expect("reserve port");
        let port = reservation.local_addr().expect("reserved addr").port();
        drop(reservation);
        let transport = QuicTransport::bind(
            QuicNodeConfig::generate(),
            &[
                quic_addr(&format!("0.0.0.0:{port}")),
                quic_addr(&format!("[::]:{port}")),
            ],
        )
        .expect("same-port wildcard pair");
        assert_eq!(transport.local_addresses().len(), 2);
    }

    /// Sends one datagram to `transport`'s socket of `family` from loopback
    /// and returns once the kernel has queued it.
    fn deliver(transport: &mut QuicTransport, ipv6: bool) {
        let socket = socket(transport, ipv6);
        let port = socket.local_addr.port();
        let sender = UdpSocket::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" }).expect("sender");
        sender
            .send_to(&[1u8; 4], loopback_addr(ipv6, port))
            .expect("send datagram");
        let start = std::time::Instant::now();
        while !socket::has_queued_input(&socket.udp) {
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "datagram never arrived"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn loopback_addr(ipv6: bool, port: u16) -> SocketAddr {
        if ipv6 {
            SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port))
        } else {
            SocketAddr::from(([127, 0, 0, 1], port))
        }
    }

    #[test]
    fn an_attached_dual_stack_transport_wakes_a_shared_poll_for_either_family() {
        // The best of three is held to the bound, so one descheduled thread
        // on a busy runner cannot fail it.
        for ipv6 in [false, true] {
            let mut latencies = Vec::new();
            for delay_ms in [3, 13, 23] {
                let mut transport =
                    QuicTransport::dual_stack(QuicNodeConfig::generate()).expect("bind");
                let mut poll = minip2p_transport::SharedPoll::new().expect("poll");
                poll.attach(&mut transport).expect("attach");
                let target = loopback_addr(ipv6, socket(&mut transport, ipv6).local_addr.port());
                let sender = std::thread::spawn(move || {
                    let sender = UdpSocket::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })
                        .expect("sender");
                    std::thread::sleep(Duration::from_millis(delay_ms));
                    let sent = std::time::Instant::now();
                    sender.send_to(&[7u8; 4], target).expect("send datagram");
                    sent
                });

                let events = poll
                    .harvest(&mut transport, Duration::from_secs(5))
                    .expect("harvest");
                let woke = std::time::Instant::now();
                let sent = sender.join().expect("sender thread");

                assert!(events > 0, "ipv6 {ipv6}: woke without readiness");
                latencies.push(woke.saturating_duration_since(sent));
                // Readiness consumed nothing: the datagram is still there.
                assert!(socket::has_queued_input(&socket(&mut transport, ipv6).udp));
            }
            let best = latencies.iter().min().expect("three trials");
            assert!(
                *best < Duration::from_millis(5),
                "ipv6 {ipv6}: woke after {latencies:?}"
            );
        }
    }

    /// Each datagram after a full drain raises a fresh edge (on Windows that
    /// needs the drain's `WouldBlock` to reach mio), and readiness that has
    /// been dispatched but not polled yet keeps the transport due.
    #[test]
    fn every_arrival_after_a_drain_wakes_the_poll_and_stays_due_until_polled() {
        let mut transport = loopback(QuicNodeConfig::generate());
        let mut poll = minip2p_transport::SharedPoll::new().expect("poll");
        poll.attach(&mut transport).expect("attach");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("sender");
        let now = Now::from_millis(0);
        for round in 0..3 {
            sender
                .send_to(&[round; 4], transport.local_addr())
                .expect("send");
            let events = poll
                .harvest(&mut transport, Duration::from_secs(5))
                .expect("harvest");
            assert!(events > 0, "round {round}: no wakeup after the drain");
            assert_eq!(
                transport.next_deadline(),
                Some(Deadline::IMMEDIATE),
                "round {round}: dispatched readiness is due until polled"
            );
            transport.poll(now).expect("poll drains");
            assert!(
                transport
                    .next_deadline()
                    .is_none_or(|deadline| !deadline.is_expired_at(now)),
                "round {round}: nothing left owed once polled"
            );
        }
    }

    #[test]
    fn an_unattached_transport_reads_every_socket_when_polled() {
        // A `SwarmCore` host never attaches; polling alone must still drain
        // both families.
        let mut transport = QuicTransport::dual_stack(QuicNodeConfig::generate()).expect("bind");
        for ipv6 in [false, true] {
            deliver(&mut transport, ipv6);
        }
        transport.poll(Now::from_millis(0)).expect("poll");
        for ipv6 in [false, true] {
            assert!(
                !socket::has_queued_input(&socket(&mut transport, ipv6).udp),
                "ipv6 {ipv6}: left unread"
            );
        }
    }

    #[test]
    fn dns_hosts_are_refused_with_a_resolve_first_error() {
        // A lookup here would block the driver thread for the resolver's
        // timeout, so a name is an address error that says what to do.
        let named = PeerAddr::new(
            "/dns4/localhost/udp/9/quic-v1".parse().expect("dns addr"),
            Ed25519Keypair::generate().peer_id(),
        )
        .expect("peer addr");
        let assert_resolve_first = |result: Result<(), TransportError>| {
            assert!(
                matches!(&result, Err(TransportError::InvalidAddress { reason, .. })
                    if reason.contains("resolve it to /ip4 or /ip6 first")),
                "got {result:?}"
            );
        };

        let mut transport = QuicTransport::dual_stack(QuicNodeConfig::generate()).expect("bind");
        assert_resolve_first(transport.dial(&named).map(drop));
        assert_resolve_first(transport.send_datagram(named.transport(), b"x"));
    }

    #[test]
    fn dual_stack_dials_and_datagrams_leave_from_the_matching_family() {
        let mut transport = QuicTransport::dual_stack(QuicNodeConfig::generate()).expect("bind");
        for (ipv6, namespace) in [
            (false, ConnectionNamespace::QUIC_IPV4),
            (true, ConnectionNamespace::QUIC_IPV6),
        ] {
            let receiver =
                UdpSocket::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" }).expect("receiver");
            let target_addr = receiver.local_addr().expect("receiver addr");
            let id = transport
                .dial(&target(&target_addr.to_string()))
                .expect("dial");
            assert_eq!(id.namespace(), namespace);
            transport
                .send_datagram(&quic_addr(&target_addr.to_string()), b"punch")
                .expect("datagram");

            // Both the Initial and the datagram left from that family's socket.
            let port = socket(&mut transport, ipv6).local_addr.port();
            let mut buf = [0u8; 2048];
            receiver
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("timeout");
            for _ in 0..2 {
                let (_, from) = receiver.recv_from(&mut buf).expect("a datagram");
                assert_eq!(from.port(), port, "ipv6 {ipv6}");
            }
        }
    }

    #[test]
    fn a_single_family_transport_names_the_missing_family() {
        let mut transport = loopback(QuicNodeConfig::generate());
        for result in [
            transport.dial(&target("[::1]:9")).map(drop),
            transport.send_datagram(&quic_addr("[::1]:9"), b"x"),
            transport.listen(&quic_addr("[::1]:9")).map(drop),
        ] {
            assert!(
                matches!(&result, Err(TransportError::InvalidAddress { reason, .. })
                    if reason.contains("no ipv6 socket")),
                "got {result:?}"
            );
        }
    }

    #[test]
    fn the_connection_limit_holds_across_sockets() {
        let limits = QuicLimits {
            max_connections: 2,
            ..QuicLimits::default()
        };
        let mut transport =
            QuicTransport::dual_stack(QuicNodeConfig::generate().with_limits(limits))
                .expect("bind");
        transport.dial(&target("127.0.0.1:9")).expect("ipv4");
        transport.dial(&target("[::1]:9")).expect("ipv6");
        for family in ["127.0.0.1:9", "[::1]:9"] {
            assert_eq!(
                transport.dial(&target(family)),
                Err(TransportError::ResourceExhausted {
                    resource: "QUIC connections"
                }),
                "{family}: both sockets share the limit"
            );
        }
    }

    #[test]
    fn ids_from_another_transport_are_unknown() {
        let mut transport = QuicTransport::dual_stack(QuicNodeConfig::generate()).expect("bind");
        let foreign =
            ConnectionId::namespaced(ConnectionNamespace::TCP_IPV4, 1).expect("id in range");
        assert_eq!(
            transport.open_stream(foreign),
            Err(TransportError::ConnectionNotFound { id: foreign })
        );
        assert_eq!(
            transport.close(foreign),
            Err(TransportError::ConnectionNotFound { id: foreign })
        );
    }
}
