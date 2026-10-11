//! Synchronous QUIC transport adapter for minip2p, on the quinn-proto engine
//! with rustls (ring) for libp2p TLS.
//!
//! Implements [`Transport`] with a poll-driven, non-blocking UDP socket. The
//! engine owns no I/O: the adapter feeds it datagrams and a time sample, and
//! sends what it produces. No async runtime required.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use minip2p_core::{Multiaddr, PeerAddr, PeerId, Protocol};
use minip2p_platform::{Deadline, Now};
use minip2p_transport::{
    BlockingTransport, Bytes, ConnectionEndpoint, ConnectionId, ConnectionIdAllocator,
    ConnectionNamespace, StreamId, Transport, TransportError, TransportEvent, WaitHandle,
    WaitOutcome,
};
use mio::{Events, Interest, Poll, Token, Waker};
use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn_proto::{
    ClientConfig, ConnectionHandle, DatagramEvent, EndpointConfig, IdleTimeout, Incoming,
    ServerConfig, TransportConfig, ValidationTokenConfig, VarInt,
};
use socket2::{Domain, Protocol as SocketProtocol, Socket as RawSocket, Type};

mod config;
mod connection;
mod diagnostics;
#[cfg(test)]
mod recv_batch_tests;
mod socket;
#[cfg(test)]
mod stream_send_tests;
#[cfg(test)]
mod test_peer;
mod tls;

pub use config::{QuicLimits, QuicNodeConfig};
#[cfg(feature = "diagnostics")]
pub use diagnostics::{ConnectionDiagnostics, DatagramCounters, datagram_counters};

use connection::{Cx, QuicConnection};
use diagnostics::{ConnectionCounters, DatagramTally};
use socket::Socket;
use tls::{HostTime, TlsIdentity};

const DEFAULT_IPV4_BIND: &str = "0.0.0.0:0";
const DEFAULT_IPV6_BIND: &str = "[::]:0";
/// Per-stream receive window, and each stream's receive budget: the most
/// delivered bytes it holds unacknowledged (ADR 0012).
///
/// Fixed, as is the connection window, so the engine buffers at most one more
/// window behind a reader that is not acknowledging.
pub const STREAM_RECEIVE_WINDOW: usize = 1_000_000;
/// Per-connection receive window, fixed like [`STREAM_RECEIVE_WINDOW`].
const CONNECTION_RECEIVE_WINDOW: u32 = 10_000_000;
/// Bytes the engine buffers per connection for sending and retransmission.
const SEND_WINDOW: u64 = 10_000_000;
/// How long a Retry token stays valid.
const RETRY_TOKEN_LIFETIME: Duration = Duration::from_secs(10);
/// Server name every dial presents; libp2p peers authenticate by certificate,
/// not by name.
const SERVER_NAME: &str = "l";
/// Maximum UDP datagrams drained from the socket per `poll()` call.
///
/// Bounding the drain keeps a packet flood from starving the connection
/// timers (loss recovery, idle timeouts) that only run after the recv loop.
/// A batch that hits the bound reports `Deadline::IMMEDIATE`, and
/// `wait_for_input` reports leftover packets as ready, so the driver polls
/// again at once.
const MAX_DATAGRAMS_PER_POLL: usize = 128;
/// Largest UDP payload a receive accepts.
const RECV_BUFFER_SIZE: usize = 65_535;
/// The [`Waker`]'s token; sockets are registered from `Token(1)` up.
const INTERRUPT_TOKEN: Token = Token(0);

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
fn transport_config(limits: &QuicLimits) -> Result<TransportConfig, TransportError> {
    if limits.max_pending_datagrams == 0 {
        return Err(TransportError::InvalidConfig {
            reason: "max_pending_datagrams must be greater than zero".into(),
        });
    }
    // A zero queue could never free half of itself, so a Full write would
    // never be told it can retry.
    if limits.max_pending_stream_bytes == 0 {
        return Err(TransportError::InvalidConfig {
            reason: "max_pending_stream_bytes must be greater than zero".into(),
        });
    }
    // QUIC treats a zero idle timeout as "no timeout", which would keep dead
    // connections alive forever -- the opposite of what a limit promises --
    // so reject it up front.
    if limits.idle_timeout_ms == 0 {
        return Err(TransportError::InvalidConfig {
            reason: "idle_timeout_ms must be greater than zero".into(),
        });
    }
    let too_large = |field: &str| TransportError::InvalidConfig {
        reason: format!("{field} is too large for QUIC"),
    };
    let max_streams = VarInt::from_u64(limits.max_streams_per_connection)
        .map_err(|_bounds| too_large("max_streams_per_connection"))?;
    let idle_timeout =
        VarInt::from_u64(limits.idle_timeout_ms).map_err(|_bounds| too_large("idle_timeout_ms"))?;

    let mut config = TransportConfig::default();
    config
        .stream_receive_window(VarInt::from_u32(STREAM_RECEIVE_WINDOW as u32))
        .receive_window(VarInt::from_u32(CONNECTION_RECEIVE_WINDOW))
        .send_window(SEND_WINDOW)
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

fn tls_config_error(error: impl std::fmt::Display) -> TransportError {
    TransportError::InvalidConfig {
        reason: format!("failed to build the QUIC TLS configuration: {error}"),
    }
}

/// QUIC transport backed by a non-blocking UDP socket and quinn-proto.
pub struct QuicTransport {
    /// Non-blocking UDP socket for all QUIC traffic, with its retry queue.
    socket: Socket,
    /// Poll registration used to wait for socket readability or an external
    /// driver interrupt without consuming a datagram. `None` for a half of a
    /// [`DualQuicTransport`], which waits on both sockets with one poll.
    readiness: Option<ReadinessWait>,
    /// The engine's endpoint: routes datagrams to connections by connection
    /// id and answers what no connection owns.
    endpoint: quinn_proto::Endpoint,
    /// Installed on the endpoint by `listen`; until then it accepts nothing.
    server_config: Arc<ServerConfig>,
    transport_config: Arc<TransportConfig>,
    tls: TlsIdentity,
    /// The host's wall-clock time, shared with the TLS verifiers.
    host_time: Arc<HostTime>,
    /// Active connections keyed by connection id.
    connections: HashMap<ConnectionId, QuicConnection>,
    /// The engine's handle for each connection.
    handles: HashMap<ConnectionHandle, ConnectionId>,
    /// Maps peer ids to their set of connection ids.
    peer_connections: HashMap<PeerId, BTreeSet<ConnectionId>>,
    /// Events queued between poll() calls.
    pending_events: Vec<TransportEvent>,
    /// Reused by every receive.
    recv_buf: Vec<u8>,
    /// Reused by every transmit and stateless reply.
    send_buf: Vec<u8>,
    /// Reused for the connection sweep.
    sweep_ids: Vec<ConnectionId>,
    /// Whether `listen` installed the server config.
    listening: bool,
    /// The last receive batch hit [`MAX_DATAGRAMS_PER_POLL`], so input may be
    /// waiting with no fresh readiness edge to report it.
    recv_saturated: bool,
    /// Connection ids for this socket, namespaced by the family it is bound to
    /// so a dual-stack pair's two id spaces stay disjoint.
    connection_ids: ConnectionIdAllocator,
    /// Retained node configuration.
    node_config: QuicNodeConfig,
    /// The last poll's host sample and the engine instant taken with it, so
    /// `next_deadline` maps engine timeouts onto the host's timeline. `None`
    /// until the first `poll`.
    clock: Option<(Now, Instant)>,
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
///
/// Both sockets share one readiness [`Poll`], so a wait blocks on either
/// family at once and a datagram on either wakes it straight away.
pub struct DualQuicTransport {
    ipv4: QuicTransport,
    ipv6: QuicTransport,
    readiness: ReadinessWait,
}

/// One mio [`Poll`] watching one or more UDP sockets and a [`Waker`].
///
/// Every registration is edge-triggered, so a harvest that finds nothing
/// leaves the poll's own fd unreadable: that is what lets an enclosing
/// level-triggered `poll(2)` block on it (see
/// [`BlockingTransport::readiness_fd`]). Socket readiness itself is not kept
/// here; [`wait_for_sockets`] asks the sockets instead.
struct ReadinessWait {
    poll: Poll,
    events: Events,
    _sockets: Vec<mio::net::UdpSocket>,
    waker: Arc<Waker>,
}

impl ReadinessWait {
    fn new(sockets: &[&UdpSocket]) -> std::io::Result<Self> {
        let poll = Poll::new()?;
        let mut registered = Vec::with_capacity(sockets.len());
        for (index, socket) in sockets.iter().enumerate() {
            let mut clone = mio::net::UdpSocket::from_std(socket.try_clone()?);
            poll.registry()
                .register(&mut clone, Token(index + 1), Interest::READABLE)?;
            registered.push(clone);
        }
        let waker = Arc::new(Waker::new(poll.registry(), INTERRUPT_TOKEN)?);
        Ok(Self {
            poll,
            events: Events::with_capacity(sockets.len() + 1),
            _sockets: registered,
            waker,
        })
    }

    /// Waits up to `timeout`, harvesting whatever the poll has queued.
    /// `None` if the poll failed, which leaves what it holds unknown.
    fn wait(&mut self, timeout: Duration) -> Option<WaitOutcome> {
        self.events.clear();
        self.poll.poll(&mut self.events, Some(timeout)).ok()?;
        Some(
            if self
                .events
                .iter()
                .any(|event| event.token() == INTERRUPT_TOKEN)
            {
                WaitOutcome::Interrupted
            } else if self.events.is_empty() {
                WaitOutcome::TimedOut
            } else {
                WaitOutcome::Ready
            },
        )
    }

    /// The selector's fd, for [`BlockingTransport::readiness_fd`].
    ///
    /// mio exposes it only where its selector is a real fd (epoll, kqueue,
    /// event ports); elsewhere a set holding this transport takes turns.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "illumos",
        target_os = "solaris"
    ))]
    fn fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        use std::os::fd::AsFd;
        Some(self.poll.registry().as_fd())
    }

    #[cfg(all(
        unix,
        not(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly",
            target_os = "illumos",
            target_os = "solaris"
        ))
    ))]
    fn fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        None
    }

    /// A handle that wakes this poll's one [`Waker`].
    fn wait_handle(&self) -> WaitHandle {
        let waker = Arc::clone(&self.waker);
        WaitHandle::new(move || {
            if let Err(error) = waker.wake() {
                // A closed readiness source needs no further interrupt.
                drop(error);
            }
        })
    }
}

/// [`BlockingTransport::wait_for_input`] over sockets watched by `readiness`.
///
/// `has_input` reports buffered events or queued datagrams. The poll is
/// harvested before it is asked, so a `TimedOut` answer never leaves stale
/// readiness behind (the drain-before-block invariant of
/// [`BlockingTransport::readiness_fd`]); anything that arrives after the
/// harvest is fresh readiness, which a later wait sees.
fn wait_for_sockets(
    readiness: &mut ReadinessWait,
    has_input: impl Fn() -> bool,
    timeout: Duration,
) -> WaitOutcome {
    match readiness.wait(Duration::ZERO) {
        Some(WaitOutcome::Interrupted) => return WaitOutcome::Interrupted,
        // A failed harvest may have left readiness behind, so `TimedOut`
        // could break the invariant; let the caller poll and ask again.
        None => return WaitOutcome::Ready,
        // Socket readiness is the sockets' to report, below.
        Some(_) => {}
    }
    if has_input() {
        return WaitOutcome::Ready;
    }
    if timeout.is_zero() {
        return WaitOutcome::TimedOut;
    }
    // A failed wait is not a reason to sleep; let the caller poll.
    readiness.wait(timeout).unwrap_or(WaitOutcome::Ready)
}

fn readiness_error(error: std::io::Error) -> TransportError {
    TransportError::ListenFailed {
        reason: format!("failed to create readiness poll: {error}"),
    }
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

/// `addr` itself when its host is in `family`; an address error otherwise.
fn peer_addr_for_family(
    addr: &PeerAddr,
    family: AddressFamily,
) -> Result<PeerAddr, TransportError> {
    let socket_addr = dial_socket_addr(addr.transport(), "dial target")?;
    if family_for_socket_addr(socket_addr) != family {
        return Err(TransportError::InvalidAddress {
            context: "dial target",
            reason: format!("{} is not an {} target", addr.transport(), family.name()),
        });
    }
    Ok(addr.clone())
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

    /// Binds one IPv4 and one IPv6 QUIC socket to exact multiaddresses.
    pub fn bind_dual_multiaddr(
        node_config: QuicNodeConfig,
        first: &Multiaddr,
        second: &Multiaddr,
    ) -> Result<Self, TransportError> {
        let first = extract_listen_socket_addr(first, "first dual-stack bind address")?;
        let second = extract_listen_socket_addr(second, "second dual-stack bind address")?;
        let (ipv4, ipv6) = match (
            family_for_socket_addr(first),
            family_for_socket_addr(second),
        ) {
            (AddressFamily::Ipv4, AddressFamily::Ipv6) => (first, second),
            (AddressFamily::Ipv6, AddressFamily::Ipv4) => (second, first),
            _ => {
                return Err(TransportError::InvalidConfig {
                    reason: "dual-stack QUIC requires one IPv4 and one IPv6 bind address".into(),
                });
            }
        };
        DualQuicTransport::bind(node_config, &ipv4.to_string(), &ipv6.to_string())
            .map(|transport| Self::Dual(Box::new(transport)))
    }

    /// Binds IPv4 and IPv6 wildcard UDP sockets.
    pub fn dual_stack(node_config: QuicNodeConfig) -> Result<Self, TransportError> {
        DualQuicTransport::new(node_config).map(|transport| Self::Dual(Box::new(transport)))
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

    /// A live connection's diagnostic counters (`diagnostics` feature).
    #[cfg(feature = "diagnostics")]
    pub fn connection_diagnostics(&self, id: ConnectionId) -> Option<ConnectionDiagnostics> {
        match self {
            Self::Single(transport) => transport.connection_diagnostics(id),
            Self::Dual(transport) => transport.connection_diagnostics(id),
        }
    }

    /// Returns a cloneable handle that can interrupt this endpoint's current
    /// readiness wait from another thread.
    pub fn wait_handle(&self) -> WaitHandle {
        BlockingTransport::wait_handle(self)
    }

    /// The [`ConnectionNamespace`]s this endpoint allocates connection ids in.
    ///
    /// One socket mints ids in the namespace of the family it is bound to; a
    /// dual-stack pair mints in both and keeps the split to itself. A host
    /// routing several transports needs this to say which ids are QUIC's --
    /// see `minip2p_transport::TransportSet`.
    pub fn namespaces(&self) -> Vec<ConnectionNamespace> {
        match self {
            Self::Single(transport) => vec![transport.namespace()],
            Self::Dual(_) => vec![
                ConnectionNamespace::QUIC_IPV4,
                ConnectionNamespace::QUIC_IPV6,
            ],
        }
    }
}

fn single_dial_family(
    transport: &mut QuicTransport,
    addr: &PeerAddr,
    family: AddressFamily,
) -> Result<ConnectionId, TransportError> {
    let local_family = family_for_socket_addr(transport.local_addr());
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
        Self::bind(node_config, DEFAULT_IPV4_BIND, DEFAULT_IPV6_BIND)
    }

    /// Binds exact IPv4 and IPv6 socket addresses as one dual transport.
    pub fn bind(
        node_config: QuicNodeConfig,
        ipv4_bind: &str,
        ipv6_bind: &str,
    ) -> Result<Self, TransportError> {
        let ipv4 = QuicTransport::from_socket(node_config.clone(), bind_udp(ipv4_bind)?)?;
        let ipv6 = QuicTransport::from_socket(node_config, bind_ipv6_only_udp(ipv6_bind)?)?;
        if ipv4.namespace() != ConnectionNamespace::QUIC_IPV4
            || ipv6.namespace() != ConnectionNamespace::QUIC_IPV6
        {
            return Err(TransportError::InvalidConfig {
                reason: "dual-stack QUIC requires IPv4 then IPv6 bind addresses".into(),
            });
        }
        let readiness =
            ReadinessWait::new(&[&ipv4.socket.udp, &ipv6.socket.udp]).map_err(readiness_error)?;
        Ok(Self {
            ipv4,
            ipv6,
            readiness,
        })
    }

    /// Sends a raw UDP packet to `target`, bypassing QUIC.
    pub fn send_raw_udp(&self, target: &Multiaddr, payload: &[u8]) -> Result<(), TransportError> {
        let family = family_for_socket_addr(dial_socket_addr(target, "raw udp target")?);
        self.transport(family).send_raw_udp(target, payload)
    }

    /// A live connection's diagnostic counters (`diagnostics` feature).
    #[cfg(feature = "diagnostics")]
    pub fn connection_diagnostics(&self, id: ConnectionId) -> Option<ConnectionDiagnostics> {
        self.transport(Self::family_for_id(id).ok()?)
            .connection_diagnostics(id)
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

    fn dial_family(
        &mut self,
        addr: &PeerAddr,
        family: AddressFamily,
    ) -> Result<ConnectionId, TransportError> {
        let addr = peer_addr_for_family(addr, family)?;
        self.transport_mut(family).dial(&addr)
    }

    fn family_for_addr(addr: &Multiaddr) -> AddressFamily {
        match addr.protocols().first() {
            Some(Protocol::Ip6(_) | Protocol::Dns6(_)) => AddressFamily::Ipv6,
            _ => AddressFamily::Ipv4,
        }
    }

    /// Routes an id back to the socket that minted it.
    ///
    /// Each half allocates in its own [`ConnectionNamespace`], so the id needs
    /// no rewriting on the way in or out.
    fn family_for_id(id: ConnectionId) -> Result<AddressFamily, TransportError> {
        let namespace = id.namespace();
        if namespace == ConnectionNamespace::QUIC_IPV4 {
            Ok(AddressFamily::Ipv4)
        } else if namespace == ConnectionNamespace::QUIC_IPV6 {
            Ok(AddressFamily::Ipv6)
        } else {
            Err(TransportError::ConnectionNotFound { id })
        }
    }
}

/// Binds a UDP socket to `bind_addr`.
fn bind_udp(bind_addr: &str) -> Result<UdpSocket, TransportError> {
    UdpSocket::bind(bind_addr).map_err(|e| TransportError::ListenFailed {
        reason: format!("failed to bind udp socket: {e}"),
    })
}

/// Binds an IPv6-only UDP socket, so an IPv4 wildcard can share its port.
fn bind_ipv6_only_udp(bind_addr: &str) -> Result<UdpSocket, TransportError> {
    let bind_addr =
        bind_addr
            .parse::<SocketAddr>()
            .map_err(|e| TransportError::InvalidAddress {
                context: "ipv6 bind address",
                reason: e.to_string(),
            })?;
    if !bind_addr.is_ipv6() {
        return Err(TransportError::InvalidAddress {
            context: "ipv6 bind address",
            reason: "expected an IPv6 socket address".into(),
        });
    }
    RawSocket::new(Domain::IPV6, Type::DGRAM, Some(SocketProtocol::UDP))
        .and_then(|socket| {
            socket.set_only_v6(true)?;
            socket.bind(&bind_addr.into())?;
            Ok(socket.into())
        })
        .map_err(|e| TransportError::ListenFailed {
            reason: format!("failed to bind ipv6-only udp socket: {e}"),
        })
}

impl QuicTransport {
    /// Creates a new QUIC transport bound to the given address.
    pub fn new(node_config: QuicNodeConfig, bind_addr: &str) -> Result<Self, TransportError> {
        let mut transport = Self::from_socket(node_config, bind_udp(bind_addr)?)?;
        transport.readiness =
            Some(ReadinessWait::new(&[&transport.socket.udp]).map_err(readiness_error)?);
        Ok(transport)
    }

    /// A transport over `socket` with no readiness wait of its own: a
    /// standalone one gets it from [`new`](Self::new), a dual-stack half from
    /// its pair.
    fn from_socket(node_config: QuicNodeConfig, socket: UdpSocket) -> Result<Self, TransportError> {
        let transport_config = Arc::new(transport_config(node_config.limits())?);
        socket
            .set_nonblocking(true)
            .map_err(|e| TransportError::ListenFailed {
                reason: format!("failed to set nonblocking: {e}"),
            })?;

        // The bound family fixes this socket's id namespace, so the two halves
        // of a dual-stack pair mint disjoint ids without any remapping.
        let local_addr = socket
            .local_addr()
            .map_err(|e| TransportError::ListenFailed {
                reason: format!("failed to get local addr: {e}"),
            })?;
        let namespace = match family_for_socket_addr(local_addr) {
            AddressFamily::Ipv4 => ConnectionNamespace::QUIC_IPV4,
            AddressFamily::Ipv6 => ConnectionNamespace::QUIC_IPV6,
        };

        let host_time = Arc::new(HostTime::default());
        let tls = TlsIdentity::new(node_config.keypair(), Arc::clone(&host_time))
            .map_err(|reason| TransportError::InvalidConfig { reason })?;
        let crypto = QuicServerConfig::try_from(tls.server_config().map_err(tls_config_error)?)
            .map_err(tls_config_error)?;
        let mut server_config = ServerConfig::with_crypto(Arc::new(crypto));
        let mut validation_tokens = ValidationTokenConfig::default();
        // Retry stays the only address validation: no NEW_TOKEN is issued.
        validation_tokens.sent(0);
        server_config
            .transport_config(Arc::clone(&transport_config))
            .retry_token_lifetime(RETRY_TOKEN_LIFETIME)
            .validation_token_config(validation_tokens);

        let tally = DatagramTally::register(&node_config.peer_id());
        let max_pending_datagrams = node_config.limits().max_pending_datagrams;
        Ok(Self {
            socket: Socket::new(socket, local_addr, max_pending_datagrams, tally),
            readiness: None,
            // No server config until `listen`: the endpoint accepts nothing.
            endpoint: quinn_proto::Endpoint::new(
                Arc::new(EndpointConfig::default()),
                None,
                true,
                None,
            ),
            server_config: Arc::new(server_config),
            transport_config,
            tls,
            host_time,
            connections: HashMap::new(),
            handles: HashMap::new(),
            peer_connections: HashMap::new(),
            pending_events: Vec::new(),
            recv_buf: vec![0; RECV_BUFFER_SIZE],
            send_buf: Vec::new(),
            sweep_ids: Vec::new(),
            listening: false,
            recv_saturated: false,
            connection_ids: ConnectionIdAllocator::new(namespace),
            node_config,
            clock: None,
        })
    }

    /// Returns the local socket address this transport is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr
    }

    /// Sends a raw UDP packet to the given multiaddr, bypassing QUIC.
    ///
    /// This is intended for NAT hole-punch signaling (e.g. DCUtR), where a
    /// peer needs to send stray UDP bytes to open a NAT binding for inbound
    /// QUIC packets from a remote peer.
    ///
    /// The multiaddr must be of the form `/ip4|ip6/<addr>/udp/<port>/quic-v1`;
    /// `/dns*` hosts are rejected, so resolve names before calling this.
    pub fn send_raw_udp(&self, target: &Multiaddr, payload: &[u8]) -> Result<(), TransportError> {
        let addr = dial_socket_addr(target, "raw udp target")?;
        self.socket
            .udp
            .send_to(payload, addr)
            .map_err(|e| TransportError::PollError {
                reason: format!("raw udp send to {addr} failed: {e}"),
            })?;
        self.socket.tally.sent(payload.len());
        Ok(())
    }

    /// The namespace this socket's connection ids carry, fixed by the family
    /// it is bound to.
    pub fn namespace(&self) -> ConnectionNamespace {
        self.connection_ids.namespace()
    }

    /// Exposes the bound local socket address as a multiaddr for external use.
    pub fn local_multiaddr(&self) -> Multiaddr {
        socket_addr_to_multiaddr(self.local_addr())
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

    /// Returns a `PeerAddr` that other nodes can use to dial this transport.
    ///
    /// Combines the bound socket address with this node's `PeerId`.
    pub fn local_peer_addr(&self) -> Result<PeerAddr, TransportError> {
        let addr = self.local_addr();
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
        let addr = self.local_addr();
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

    /// Allocates the next connection id in this socket's namespace.
    ///
    /// Sequence numbers are never reused, so there is no need to check the
    /// live connection table for a collision.
    fn allocate_connection_id(&mut self) -> Result<ConnectionId, TransportError> {
        let id = self.connection_ids.allocate()?;
        debug_assert!(
            !self.connections.contains_key(&id),
            "allocator handed out a live connection id"
        );
        Ok(id)
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

    /// A dial's engine config: this node's identity, and a verifier that
    /// rejects any listener not proving `expected`.
    fn client_config(&self, expected: &PeerId) -> Result<ClientConfig, TransportError> {
        let tls = self
            .tls
            .client_config(Some(expected.clone()))
            .map_err(tls_config_error)?;
        let crypto = QuicClientConfig::try_from(tls).map_err(tls_config_error)?;
        let mut config = ClientConfig::new(Arc::new(crypto));
        config.transport_config(Arc::clone(&self.transport_config));
        Ok(config)
    }

    /// Reads up to [`MAX_DATAGRAMS_PER_POLL`] datagrams and hands each to the
    /// engine. Connections only queue output here; the sweep sends it.
    fn recv_batch(&mut self, now: Instant) -> Result<(), TransportError> {
        self.recv_saturated = false;
        for _ in 0..MAX_DATAGRAMS_PER_POLL {
            let (len, from) = match self.socket.udp.recv_from(&mut self.recv_buf) {
                Ok(received) => received,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => {
                    return Err(TransportError::PollError {
                        reason: format!("udp recv error: {e}"),
                    });
                }
            };
            self.socket.tally.received(len);
            let datagram = BytesMut::from(
                self.recv_buf
                    .get(..len)
                    .expect("UDP receive lengths fit the supplied buffer"),
            );
            self.handle_datagram(now, from, datagram);
        }
        self.recv_saturated = true;
        Ok(())
    }

    /// Routes one datagram. The endpoint routes by connection id, never by
    /// source address, and drops what it cannot parse.
    fn handle_datagram(&mut self, now: Instant, from: SocketAddr, datagram: BytesMut) {
        let mut buf = std::mem::take(&mut self.send_buf);
        buf.clear();
        match self
            .endpoint
            .handle(now, from, None, None, datagram, &mut buf)
        {
            Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                if let Some(conn) = self
                    .handles
                    .get(&handle)
                    .and_then(|id| self.connections.get_mut(id))
                {
                    conn.handle_event(event);
                }
            }
            Some(DatagramEvent::NewConnection(incoming)) => self.admit(now, incoming, &mut buf),
            // A reply to a datagram no connection owns. Before `listen` the
            // endpoint still answers an unknown Initial with a stateless
            // reset; a node that is not listening sends nothing at all.
            Some(DatagramEvent::Response(transmit)) if self.listening => {
                send_stateless(&mut self.socket, &buf, &transmit);
            }
            Some(DatagramEvent::Response(_)) | None => {}
        }
        self.send_buf = buf;
    }

    /// Admits a new inbound connection: refused silently at the connection
    /// limit (before any Retry), sent a Retry while its address is
    /// unvalidated and validation is required, accepted otherwise.
    fn admit(&mut self, now: Instant, incoming: Incoming, buf: &mut Vec<u8>) {
        let limits = self.node_config.limits().clone();
        if !self.listening || self.connections.len() >= limits.max_connections {
            self.endpoint.ignore(incoming);
            return;
        }
        if limits.require_address_validation && !incoming.remote_address_validated() {
            match self.endpoint.retry(incoming, buf) {
                Ok(transmit) => send_stateless(&mut self.socket, buf, &transmit),
                Err(error) => self.endpoint.ignore(error.into_incoming()),
            }
            return;
        }
        let Ok(id) = self.allocate_connection_id() else {
            self.endpoint.ignore(incoming);
            return;
        };
        match self.endpoint.accept(incoming, now, buf, None) {
            Ok((handle, conn)) => {
                let endpoint =
                    ConnectionEndpoint::new(socket_addr_to_multiaddr(conn.remote_address()));
                let conn = QuicConnection::new(
                    id,
                    handle,
                    conn,
                    endpoint.clone(),
                    limits.max_streams_per_connection,
                    limits.max_pending_stream_bytes,
                    ConnectionCounters::default(),
                );
                self.connections.insert(id, conn);
                self.handles.insert(handle, id);
                self.pending_events
                    .push(TransportEvent::IncomingConnection { id, endpoint });
            }
            Err(error) => {
                if let Some(transmit) = error.response {
                    send_stateless(&mut self.socket, buf, &transmit);
                }
            }
        }
    }

    /// Services every connection.
    fn sweep(&mut self, now: Instant) {
        let mut ids = std::mem::take(&mut self.sweep_ids);
        ids.clear();
        ids.extend(self.connections.keys().copied());
        for &id in &ids {
            self.service(id, now);
        }
        self.sweep_ids = ids;
    }

    /// Runs one connection's engine and sends its output; then keeps the
    /// peer index current and retires the connection once it drained.
    /// Returns the first hard socket error its output hit.
    fn service(&mut self, id: ConnectionId, now: Instant) -> Option<std::io::Error> {
        let conn = self.connections.get_mut(&id)?;
        let mut cx = Cx {
            endpoint: &mut self.endpoint,
            socket: &mut self.socket,
            send_buf: &mut self.send_buf,
            events: &mut self.pending_events,
            unix_now: self.host_time.now(),
        };
        let failure = conn.service(now, &mut cx);
        if let Some(previous) = conn.take_identity_change() {
            let current = conn.endpoint().peer_id().cloned();
            if let Some(previous) = previous {
                self.remove_peer_connection(&previous, id);
            }
            if let Some(current) = current {
                self.index_peer_connection(current, id);
            }
        }
        if self
            .connections
            .get(&id)
            .is_some_and(QuicConnection::is_drained)
        {
            self.remove_connection(id);
        }
        failure
    }

    /// Forgets a drained connection and reports it closed.
    fn remove_connection(&mut self, id: ConnectionId) {
        let Some(conn) = self.connections.remove(&id) else {
            return;
        };
        self.handles.remove(&conn.handle());
        if let Some(peer_id) = conn.endpoint().peer_id() {
            self.remove_peer_connection(peer_id, id);
        }
        self.pending_events.push(TransportEvent::Closed { id });
    }
}

/// Sends a stateless reply the endpoint wrote into `buf`.
fn send_stateless(socket: &mut Socket, buf: &[u8], transmit: &quinn_proto::Transmit) {
    if let Some(datagram) = buf.get(..transmit.size) {
        socket.send_stateless(datagram, transmit.destination);
    }
}

impl Transport for QuicTransport {
    fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        // The connection limit counts inbound and outbound alike; admission
        // enforces the same bound for incoming Initials.
        if self.connections.len() >= self.node_config.limits().max_connections {
            return Err(TransportError::ResourceExhausted {
                resource: "QUIC connections",
            });
        }

        let id = self.allocate_connection_id()?;
        let peer_socket = dial_socket_addr(addr.transport(), "dial target")?;
        let config = self.client_config(addr.peer_id())?;
        let now = Instant::now();
        let (handle, conn) = self
            .endpoint
            .connect(now, config, peer_socket, SERVER_NAME)
            .map_err(|e| TransportError::DialFailed {
                id,
                reason: format!("QUIC connect error: {e}"),
            })?;
        let limits = self.node_config.limits().clone();
        let conn = QuicConnection::new(
            id,
            handle,
            conn,
            ConnectionEndpoint::from_peer_addr(addr),
            limits.max_streams_per_connection,
            limits.max_pending_stream_bytes,
            ConnectionCounters::default(),
        );
        self.connections.insert(id, conn);
        self.handles.insert(handle, id);
        self.index_peer_connection(addr.peer_id().clone(), id);

        // A first flight the socket refuses outright (no route, wrong family)
        // fails the dial now rather than at the handshake timeout.
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
        let socket_addr = extract_listen_socket_addr(addr, "listen address")?;

        let local_addr = self.local_addr();
        ensure_listen_matches_bound_socket(socket_addr, local_addr)?;

        let listen_addr = socket_addr_to_multiaddr(local_addr);
        self.endpoint
            .set_server_config(Some(Arc::clone(&self.server_config)));
        self.listening = true;
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
        let conn = self
            .connections
            .get_mut(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;

        let result = conn.reset_stream(stream_id, &mut self.pending_events);
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
            return Ok(());
        };
        // A stream that had spent its budget resumes now, not when the next
        // packet happens to arrive: the engine already holds what it can read.
        let result = conn.ack_stream(stream_id, bytes, &mut self.pending_events);
        self.service(id, Instant::now());
        result
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
        vec![self.local_multiaddr()]
    }

    fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
        self.connections
            .values()
            .filter(|conn| conn.is_server())
            .map(|conn| conn.endpoint().transport().clone())
            .collect()
    }

    fn send_datagram(&mut self, target: &Multiaddr, payload: &[u8]) -> Result<(), TransportError> {
        // The socket a hole punch has to leave from is this one: the binding it
        // opens is only useful for QUIC packets arriving back on it.
        self.send_raw_udp(target, payload)
    }

    fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        // The engine runs on a fine-grained `Instant` sampled once per poll;
        // the host's millisecond sample anchors `next_deadline` and is never
        // handed to the engine as time.
        let instant = Instant::now();
        self.clock = Some((now, instant));
        self.host_time.set(now.unix_seconds);
        // Events accumulate in `self.pending_events` for the whole poll and
        // are only taken at the very end, so an error path leaves the batch
        // queued for the next call instead of dropping it.
        self.socket.flush();
        // The sweep runs whatever ended the batch: connections defer their
        // output to it, so a batch cut short by an error must not leave them
        // unsent.
        let received = self.recv_batch(instant);
        self.sweep(instant);
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
        if !self.pending_events.is_empty() || self.recv_saturated {
            return Some(Deadline::IMMEDIATE);
        }

        // Datagrams stuck on socket writability can't be woken by a readable
        // peek; return a near deadline so the driver retries the flush soon.
        // Checked before the retained sample: `dial` queues datagrams before
        // the first `poll`, and a host that idled on `None` there would never
        // come back to flush them. `IMMEDIATE` is due on any timeline.
        if self.socket.has_pending() {
            return Some(
                self.clock
                    .map_or(Deadline::IMMEDIATE, |(now, _)| now.deadline_after(1)),
            );
        }

        // No sample yet means no timeline to answer on.
        let (now, instant) = self.clock?;
        self.connections
            .values()
            .filter_map(QuicConnection::timeout)
            .min()
            .map(|timeout| deadline_for_timeout(now, timeout.saturating_duration_since(instant)))
    }
}

impl QuicTransport {
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
            TransportEvent::StreamOpened { id: event_id, .. }
            | TransportEvent::Error { id: event_id, .. }
            | TransportEvent::Closed { id: event_id } => *event_id != id,
            _ => true,
        });
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
        // leaves now. Drain the retry queue first so a full one has room to
        // retain them; closing an already-closed connection is a no-op.
        self.socket.flush();
        let ids: Vec<ConnectionId> = self.connections.keys().copied().collect();
        for id in ids {
            match self.close(id) {
                Ok(()) | Err(_) => {}
            }
        }
        self.socket.flush();
        self.socket.clear();
    }
}

impl BlockingTransport for QuicTransport {
    fn wait_for_input(&mut self, timeout: Duration) -> WaitOutcome {
        let Some(readiness) = self.readiness.as_mut() else {
            return WaitOutcome::Unsupported;
        };
        // Buffered events are work the host has yet to see; parking on socket
        // readiness would sleep on them until an unrelated packet arrived.
        let (events, socket) = (&self.pending_events, &self.socket.udp);
        wait_for_sockets(
            readiness,
            || !events.is_empty() || socket::has_queued_input(socket),
            timeout,
        )
    }

    fn wait_handle(&self) -> WaitHandle {
        self.readiness
            .as_ref()
            .map_or_else(WaitHandle::noop, ReadinessWait::wait_handle)
    }

    #[cfg(unix)]
    fn readiness_fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.readiness.as_ref().and_then(ReadinessWait::fd)
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
        data: Bytes,
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

    fn ack_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        bytes: usize,
    ) -> Result<(), TransportError> {
        match self {
            Self::Single(transport) => transport.ack_stream(id, stream_id, bytes),
            Self::Dual(transport) => transport.ack_stream(id, stream_id, bytes),
        }
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        match self {
            Self::Single(transport) => transport.close(id),
            Self::Dual(transport) => transport.close(id),
        }
    }

    fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        match self {
            Self::Single(transport) => transport.poll(now),
            Self::Dual(transport) => transport.poll(now),
        }
    }

    fn next_deadline(&self) -> Option<Deadline> {
        match self {
            Self::Single(transport) => transport.next_deadline(),
            Self::Dual(transport) => transport.next_deadline(),
        }
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        match self {
            Self::Single(transport) => transport.local_addresses(),
            Self::Dual(transport) => transport.local_addresses(),
        }
    }

    fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
        match self {
            Self::Single(transport) => transport.active_inbound_connection_sources(),
            Self::Dual(transport) => transport.active_inbound_connection_sources(),
        }
    }

    fn send_datagram(&mut self, target: &Multiaddr, payload: &[u8]) -> Result<(), TransportError> {
        self.send_raw_udp(target, payload)
    }
}

impl BlockingTransport for QuicEndpoint {
    fn wait_for_input(&mut self, timeout: Duration) -> WaitOutcome {
        match self {
            Self::Single(transport) => transport.wait_for_input(timeout),
            Self::Dual(transport) => transport.wait_for_input(timeout),
        }
    }

    fn wait_handle(&self) -> WaitHandle {
        match self {
            Self::Single(transport) => BlockingTransport::wait_handle(&**transport),
            Self::Dual(transport) => BlockingTransport::wait_handle(&**transport),
        }
    }

    #[cfg(unix)]
    fn readiness_fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        match self {
            Self::Single(transport) => transport.readiness_fd(),
            Self::Dual(transport) => transport.readiness_fd(),
        }
    }
}

impl Transport for DualQuicTransport {
    fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        let family = family_for_socket_addr(dial_socket_addr(addr.transport(), "dial target")?);
        self.transport_mut(family).dial(addr)
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        let family = Self::family_for_addr(addr);
        self.transport_mut(family).listen(addr)
    }

    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        let family = Self::family_for_id(id)?;
        self.transport_mut(family).open_stream(id)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
    ) -> Result<(), TransportError> {
        let family = Self::family_for_id(id)?;
        self.transport_mut(family).send_stream(id, stream_id, data)
    }

    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        let family = Self::family_for_id(id)?;
        self.transport_mut(family).close_stream_write(id, stream_id)
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        let family = Self::family_for_id(id)?;
        self.transport_mut(family).reset_stream(id, stream_id)
    }

    fn ack_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        bytes: usize,
    ) -> Result<(), TransportError> {
        // An id neither family owns is an unknown connection: a no-op.
        match Self::family_for_id(id) {
            Ok(family) => self.transport_mut(family).ack_stream(id, stream_id, bytes),
            Err(_) => Ok(()),
        }
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        let family = Self::family_for_id(id)?;
        self.transport_mut(family).close(id)
    }

    fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        let ipv4_events = self.ipv4.poll(now)?;
        let ipv6_events = match self.ipv6.poll(now) {
            Ok(events) => events,
            Err(e) => {
                // Requeue the already-taken IPv4 batch (ahead of anything
                // newer) so the IPv6 error doesn't drop it.
                let mut requeued = ipv4_events;
                requeued.append(&mut self.ipv4.pending_events);
                self.ipv4.pending_events = requeued;
                return Err(e);
            }
        };

        let mut events = ipv4_events;
        events.extend(ipv6_events);
        Ok(events)
    }

    fn next_deadline(&self) -> Option<Deadline> {
        Deadline::earliest_opt(self.ipv4.next_deadline(), self.ipv6.next_deadline())
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        let mut addrs = self.ipv4.local_addresses();
        addrs.extend(self.ipv6.local_addresses());
        addrs
    }

    fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
        let mut addrs = self.ipv4.active_inbound_connection_sources();
        addrs.extend(self.ipv6.active_inbound_connection_sources());
        addrs
    }

    fn send_datagram(&mut self, target: &Multiaddr, payload: &[u8]) -> Result<(), TransportError> {
        self.send_raw_udp(target, payload)
    }
}

impl BlockingTransport for DualQuicTransport {
    fn wait_handle(&self) -> WaitHandle {
        self.readiness.wait_handle()
    }

    fn wait_for_input(&mut self, timeout: Duration) -> WaitOutcome {
        // One poll watches both sockets, so the wait blocks on either family
        // at once. Events either half buffered outside a poll count as input
        // too: this does not go through the halves' own waits.
        let (ipv4, ipv6) = (&self.ipv4, &self.ipv6);
        wait_for_sockets(
            &mut self.readiness,
            || {
                [ipv4, ipv6].into_iter().any(|half| {
                    !half.pending_events.is_empty() || socket::has_queued_input(&half.socket.udp)
                })
            },
            timeout,
        )
    }

    #[cfg(unix)]
    fn readiness_fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.readiness.fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minip2p_identity::Ed25519Keypair;

    #[test]
    fn bound_socket_address_is_exposed_as_transport_multiaddr() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind socket");
        let bound = socket.local_addr().expect("bound address");
        let transport = QuicTransport::from_socket(QuicNodeConfig::generate(), socket)
            .expect("construct transport");
        let expected = Multiaddr::from_protocols(vec![
            Protocol::Ip4([127, 0, 0, 1]),
            Protocol::Udp(bound.port()),
            Protocol::QuicV1,
        ]);

        assert_ne!(bound.port(), 0, "the OS must resolve the ephemeral port");
        assert_eq!(transport.local_multiaddr(), expected);
        assert_eq!(Transport::local_addresses(&transport), vec![expected]);
    }

    fn loopback_peer_addr(host: Protocol) -> PeerAddr {
        let keypair = Ed25519Keypair::generate();
        let transport = Multiaddr::from_protocols(vec![host, Protocol::Udp(9), Protocol::QuicV1]);
        PeerAddr::new(transport, keypair.peer_id()).expect("peer addr")
    }

    #[test]
    fn best_effort_datagram_queue_drops_overflow_without_error() {
        let limits = QuicLimits {
            max_pending_datagrams: 2,
            ..QuicLimits::default()
        };
        let mut transport = QuicTransport::new(
            QuicNodeConfig::generate().with_limits(limits),
            "127.0.0.1:0",
        )
        .expect("bind");
        let destination = transport.local_addr();

        for payload in [&[1u8][..], &[2u8][..], &[3u8][..]] {
            transport.socket.retain(payload, destination);
        }

        assert_eq!(
            transport.socket.pending_len(),
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
            let Err(error) = QuicTransport::new(
                QuicNodeConfig::generate().with_limits(limits),
                "127.0.0.1:0",
            ) else {
                panic!("zero limit must be rejected");
            };
            assert!(matches!(error, TransportError::InvalidConfig { .. }));
        }
    }

    #[test]
    fn poll_drains_a_bounded_number_of_datagrams_per_call() {
        let mut transport =
            QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").expect("bind");
        let destination = transport.local_addr();

        let sender = UdpSocket::bind("127.0.0.1:0").expect("sender");
        for _ in 0..MAX_DATAGRAMS_PER_POLL + 8 {
            sender.send_to(&[0u8; 8], destination).expect("send");
        }

        // Wait for the kernel to queue the first datagram, then give the
        // rest a moment to land before polling.
        let start = std::time::Instant::now();
        while !socket::has_queued_input(&transport.socket.udp) {
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "datagrams never arrived"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(50));

        transport.poll(Now::from_millis(0)).expect("poll");
        assert!(
            socket::has_queued_input(&transport.socket.udp),
            "one poll must leave datagrams beyond the per-poll bound in the kernel buffer"
        );
        assert_eq!(
            transport.next_deadline(),
            Some(Deadline::IMMEDIATE),
            "a saturated batch has the driver poll again at once"
        );

        // Follow-up polls drain the remainder.
        let start = std::time::Instant::now();
        while socket::has_queued_input(&transport.socket.udp) {
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "overflow never drained"
            );
            transport.poll(Now::from_millis(0)).expect("poll");
        }
    }

    #[test]
    fn poisoned_queued_datagram_is_dropped_without_failing_the_poll() {
        let mut transport =
            QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").expect("bind");
        let addr = transport.local_multiaddr();
        transport
            .pending_events
            .push(TransportEvent::Listening { addr: addr.clone() });

        // An IPv6 destination on an IPv4 socket makes the datagram send fail
        // with a hard error. A dead route affects only that packet's
        // destination, so the poll must drop it and carry on rather than
        // abort the whole endpoint.
        let bad_destination: SocketAddr = "[::1]:9".parse().expect("socket addr");
        transport.socket.retain(&[0u8; 4], bad_destination);
        let good_destination = transport.local_addr();
        transport.socket.retain(&[0u8; 4], good_destination);

        let events = transport.poll(Now::from_millis(0)).expect("poll");
        assert!(
            events
                .iter()
                .any(|event| matches!(event, TransportEvent::Listening { addr: a } if *a == addr)),
            "events queued before the poisoned datagram must still be delivered"
        );
        assert!(
            !transport.socket.has_pending(),
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
        let mut transport =
            QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").expect("bind");
        assert_eq!(transport.next_deadline(), None, "idle and never polled");

        // `dial` can queue a datagram before any poll has taken a sample. A
        // host that idled on `None` here would never flush it.
        let destination = transport.local_addr();
        transport.socket.retain(&[0u8; 4], destination);

        let deadline = transport.next_deadline().expect("queued work must be due");
        assert!(
            deadline.is_expired_at(Now::from_millis(0)),
            "with no retained sample the deadline must be due on any timeline"
        );
    }

    #[test]
    fn next_deadline_is_near_while_outbound_work_is_queued() {
        let mut transport =
            QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").expect("bind");
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
        transport.socket.retain(&[0u8; 4], destination);
        assert_eq!(
            transport.next_deadline(),
            Some(now.deadline_after(1)),
            "queued datagrams must keep the driver polling"
        );
    }

    #[test]
    fn wait_for_input_reports_readiness_without_consuming_input() {
        let mut transport =
            QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").expect("bind");

        assert_eq!(
            transport.wait_for_input(Duration::ZERO),
            WaitOutcome::TimedOut
        );
        assert_eq!(
            transport.wait_for_input(Duration::from_millis(10)),
            WaitOutcome::TimedOut,
            "an idle socket must time out"
        );

        let sender = UdpSocket::bind("127.0.0.1:0").expect("sender");
        sender
            .send_to(&[1, 2, 3], transport.local_addr())
            .expect("send probe");
        assert_eq!(
            transport.wait_for_input(Duration::from_secs(2)),
            WaitOutcome::Ready
        );
        // A zero budget is an accurate non-blocking probe: queued input
        // still reports Ready.
        assert_eq!(transport.wait_for_input(Duration::ZERO), WaitOutcome::Ready);

        // Readiness polling must not consume the datagram.
        let mut buf = [0u8; 16];
        let (len, _) = transport
            .socket
            .udp
            .recv_from(&mut buf)
            .expect("datagram must still be queued");
        assert_eq!(
            buf.get(..len)
                .expect("UDP receive lengths fit the supplied test buffer"),
            &[1, 2, 3]
        );
    }

    #[test]
    fn wait_handle_interrupts_a_blocking_wait() {
        let mut endpoint =
            QuicEndpoint::bind(QuicNodeConfig::generate(), "127.0.0.1:0").expect("bind");
        let handle = endpoint.wait_handle();
        let waiter = std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let outcome = endpoint.wait_for_input(Duration::from_secs(5));
            (outcome, started.elapsed())
        });

        std::thread::sleep(Duration::from_millis(25));
        handle.interrupt();

        let (outcome, elapsed) = waiter.join().expect("waiter");
        assert_eq!(outcome, WaitOutcome::Interrupted);
        assert!(
            elapsed < Duration::from_millis(500),
            "interrupt took {elapsed:?}"
        );
    }

    #[test]
    fn dual_stack_wait_consumes_one_interrupt_once() {
        let mut endpoint =
            QuicEndpoint::dual_stack(QuicNodeConfig::generate()).expect("dual-stack bind");
        let handle = endpoint.wait_handle();
        let waiter = std::thread::spawn(move || {
            let interrupted = endpoint.wait_for_input(Duration::from_secs(1));
            let next = endpoint.wait_for_input(Duration::from_millis(10));
            (interrupted, next)
        });

        std::thread::sleep(Duration::from_millis(25));
        handle.interrupt();

        let (interrupted, next) = waiter.join().expect("waiter");
        assert_eq!(
            interrupted,
            WaitOutcome::Interrupted,
            "the active dual-stack wait must observe the interrupt"
        );
        assert_eq!(
            next,
            WaitOutcome::TimedOut,
            "one logical interrupt must not leak from the sibling family poll"
        );
    }

    #[test]
    fn explicit_dual_stack_wildcards_can_share_one_port() {
        let reservation = UdpSocket::bind("0.0.0.0:0").expect("reserve port");
        let port = reservation.local_addr().expect("reserved addr").port();
        drop(reservation);
        let ipv4 = format!("/ip4/0.0.0.0/udp/{port}/quic-v1")
            .parse::<Multiaddr>()
            .expect("ipv4 multiaddr");
        let ipv6 = format!("/ip6/::/udp/{port}/quic-v1")
            .parse::<Multiaddr>()
            .expect("ipv6 multiaddr");

        let endpoint = QuicEndpoint::bind_dual_multiaddr(QuicNodeConfig::generate(), &ipv4, &ipv6)
            .expect("same-port wildcard pair");

        assert_eq!(endpoint.local_addresses().len(), 2);
    }

    /// Sends one datagram to `family`'s loopback `port` and returns once the
    /// kernel has queued it on `socket`.
    fn deliver(socket: &UdpSocket, family: AddressFamily) {
        let (from, port) = (
            match family {
                AddressFamily::Ipv4 => "127.0.0.1:0",
                AddressFamily::Ipv6 => "[::1]:0",
            },
            socket.local_addr().expect("local addr").port(),
        );
        let sender = UdpSocket::bind(from).expect("sender");
        sender
            .send_to(&[1u8; 4], loopback(family, port))
            .expect("send datagram");
        let start = std::time::Instant::now();
        while !socket::has_queued_input(socket) {
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "datagram never arrived on the {} socket",
                family.name()
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn dual_stack_zero_timeout_wait_reports_queued_input_on_either_family() {
        for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            let mut transport = DualQuicTransport::new(QuicNodeConfig::generate()).expect("bind");
            deliver(&transport.transport(family).socket.udp, family);

            assert_eq!(
                transport.wait_for_input(Duration::ZERO),
                WaitOutcome::Ready,
                "{} input",
                family.name()
            );
        }
    }

    /// The drain-before-block invariant of `BlockingTransport::readiness_fd`:
    /// once `poll` has taken the input, a zero-timeout wait answers
    /// `TimedOut` and leaves the fd unreadable, so an enclosing `poll(2)` can
    /// block on it. Linux epoll re-checks a stale entry when its fd is polled,
    /// so this mainly guards kqueue, which does not.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "illumos",
        target_os = "solaris"
    ))]
    #[test]
    fn a_zero_timeout_wait_that_times_out_leaves_the_readiness_fd_unreadable() {
        /// Whether `fd` reads as ready right now, without consuming anything.
        fn fd_is_readable(fd: std::os::fd::BorrowedFd<'_>) -> bool {
            use rustix::event::{PollFd, PollFlags, Timespec, poll};
            let mut fds = [PollFd::from_borrowed_fd(fd, PollFlags::IN)];
            poll(&mut fds, Some(&Timespec::default())).expect("poll readiness fd") > 0
        }

        fn check(transport: &mut dyn BlockingTransport, family: AddressFamily) {
            assert_eq!(transport.wait_for_input(Duration::ZERO), WaitOutcome::Ready);
            transport.poll(Now::from_millis(0)).expect("poll");
            assert_eq!(
                transport.wait_for_input(Duration::ZERO),
                WaitOutcome::TimedOut,
                "{} input was consumed",
                family.name()
            );
            let fd = transport.readiness_fd().expect("quic exposes its selector");
            assert!(
                !fd_is_readable(fd),
                "{} readiness was left on the fd",
                family.name()
            );
        }

        let mut single =
            QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").expect("bind");
        deliver(&single.socket.udp, AddressFamily::Ipv4);
        check(&mut single, AddressFamily::Ipv4);

        for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            let mut dual = DualQuicTransport::new(QuicNodeConfig::generate()).expect("bind");
            deliver(&dual.transport(family).socket.udp, family);
            check(&mut dual, family);
        }
    }

    /// Sends one datagram to `target` after `delay` from another thread, and
    /// returns when it was sent.
    fn send_later(
        from: &'static str,
        target: SocketAddr,
        delay: Duration,
    ) -> std::thread::JoinHandle<std::time::Instant> {
        std::thread::spawn(move || {
            let sender = UdpSocket::bind(from).expect("sender");
            std::thread::sleep(delay);
            let sent = std::time::Instant::now();
            sender.send_to(&[7u8; 4], target).expect("send datagram");
            sent
        })
    }

    fn loopback(family: AddressFamily, port: u16) -> SocketAddr {
        match family {
            AddressFamily::Ipv4 => SocketAddr::from(([127, 0, 0, 1], port)),
            AddressFamily::Ipv6 => SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
        }
    }

    #[test]
    fn dual_stack_wait_wakes_promptly_for_a_datagram_on_either_family() {
        // Each arrival lands mid-slice in the *other* family's turn of a wait
        // taking 10 ms turns (IPv4: 0-10 ms, IPv6: 10-20 ms, ...), where it
        // would wait about 7 ms. The best of three is held to the bound, so
        // one descheduled thread on a busy runner cannot fail it.
        for (family, delays_ms) in [
            (AddressFamily::Ipv4, [13, 33, 53]),
            (AddressFamily::Ipv6, [3, 23, 43]),
        ] {
            let mut latencies = Vec::new();
            for delay_ms in delays_ms {
                let mut transport =
                    DualQuicTransport::new(QuicNodeConfig::generate()).expect("bind");
                let port = transport.transport(family).local_addr().port();
                let from = match family {
                    AddressFamily::Ipv4 => "127.0.0.1:0",
                    AddressFamily::Ipv6 => "[::1]:0",
                };
                let sender = send_later(
                    from,
                    loopback(family, port),
                    Duration::from_millis(delay_ms),
                );

                let outcome = transport.wait_for_input(Duration::from_secs(5));
                let woke = std::time::Instant::now();
                let sent = sender.join().expect("sender thread");

                assert_eq!(outcome, WaitOutcome::Ready, "{} input", family.name());
                latencies.push(woke.saturating_duration_since(sent));
            }
            let best = latencies.iter().min().expect("three trials");
            assert!(
                *best < Duration::from_millis(5),
                "{} input woke the wait after {latencies:?}",
                family.name()
            );
        }
    }

    #[test]
    fn dns_hosts_are_refused_with_a_resolve_first_error() {
        // A lookup here would block the driver thread for the resolver's
        // timeout, so a name is an address error that says what to do.
        let named = loopback_peer_addr(Protocol::Dns4("localhost".to_string()));
        let assert_resolve_first = |result: Result<(), TransportError>| {
            assert!(
                matches!(&result, Err(TransportError::InvalidAddress { reason, .. })
                    if reason.contains("resolve it to /ip4 or /ip6 first")),
                "got {result:?}"
            );
        };

        let mut single =
            QuicEndpoint::bind(QuicNodeConfig::generate(), DEFAULT_IPV4_BIND).expect("bind ipv4");
        assert_resolve_first(Transport::dial(&mut single, &named).map(drop));
        assert_resolve_first(single.dial_ip4(&named).map(drop));
        assert_resolve_first(single.send_raw_udp(named.transport(), b"x"));

        let mut dual = QuicEndpoint::dual_stack(QuicNodeConfig::generate()).expect("bind");
        assert_resolve_first(Transport::dial(&mut dual, &named).map(drop));
        assert_resolve_first(dual.dial_ip4(&named).map(drop));
        assert_resolve_first(dual.send_raw_udp(named.transport(), b"x"));
    }

    #[test]
    fn dual_stack_halves_allocate_disjoint_ids_from_the_same_sequence() {
        // Both halves start their sequence at 1. Before namespacing, keeping
        // them apart needed an odd/even rewrite on every id and event.
        let mut ipv4 =
            QuicTransport::new(QuicNodeConfig::generate(), DEFAULT_IPV4_BIND).expect("bind ipv4");
        let mut ipv6 =
            QuicTransport::new(QuicNodeConfig::generate(), DEFAULT_IPV6_BIND).expect("bind ipv6");

        let from_ipv4 = ipv4.allocate_connection_id().expect("ipv4 id");
        let from_ipv6 = ipv6.allocate_connection_id().expect("ipv6 id");

        assert_eq!(from_ipv4.sequence(), from_ipv6.sequence());
        assert_ne!(from_ipv4, from_ipv6);
        assert_eq!(from_ipv4.namespace(), ConnectionNamespace::QUIC_IPV4);
        assert_eq!(from_ipv6.namespace(), ConnectionNamespace::QUIC_IPV6);
    }

    #[test]
    fn dual_stack_rejects_ids_from_another_transport() {
        let mut endpoint = DualQuicTransport::new(QuicNodeConfig::generate()).expect("bind");
        let foreign =
            ConnectionId::namespaced(ConnectionNamespace::TCP_IPV4, 1).expect("id in range");

        assert_eq!(
            endpoint.open_stream(foreign),
            Err(TransportError::ConnectionNotFound { id: foreign })
        );
        assert_eq!(
            endpoint.close(foreign),
            Err(TransportError::ConnectionNotFound { id: foreign })
        );
    }

    #[test]
    fn dual_stack_explicit_family_dials_only_that_family() {
        let mut endpoint = QuicEndpoint::dual_stack(QuicNodeConfig::generate()).expect("bind");
        let id = endpoint
            .dial_ip4(&loopback_peer_addr(Protocol::Ip4([127, 0, 0, 1])))
            .expect("dial ipv4");
        assert_eq!(id.namespace(), ConnectionNamespace::QUIC_IPV4);

        let mut ipv6 = [0; 16];
        ipv6[15] = 1;
        let id = endpoint
            .dial_ip6(&loopback_peer_addr(Protocol::Ip6(ipv6)))
            .expect("dial ipv6");
        assert_eq!(id.namespace(), ConnectionNamespace::QUIC_IPV6);

        assert!(matches!(
            endpoint.dial_ip6(&loopback_peer_addr(Protocol::Ip4([127, 0, 0, 1]))),
            Err(TransportError::InvalidAddress { .. })
        ));
    }

    #[test]
    fn single_endpoint_explicit_family_rejects_mismatched_socket() {
        let mut ipv6 = [0; 16];
        ipv6[15] = 1;
        let mut endpoint =
            QuicEndpoint::bind(QuicNodeConfig::generate(), DEFAULT_IPV4_BIND).expect("bind ipv4");
        let err = endpoint
            .dial_ip6(&loopback_peer_addr(Protocol::Ip6(ipv6)))
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
