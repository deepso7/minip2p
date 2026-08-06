use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::ops::RangeInclusive;

use minip2p_core::{Multiaddr, Protocol};
use minip2p_platform::{Deadline, Now};
use smoltcp::iface::{
    Interface, PollIngressSingleResult, PollResult, SocketHandle as SmoltcpHandle, SocketSet,
};
use smoltcp::phy::Device;
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint};

use crate::provider::{SocketHandle, TcpError, TcpEvent, TcpProvider, host_and_port};

/// Largest shared read buffer, however big a socket's receive ring is.
///
/// One buffer serves every socket, so it is sized to drain a typical ring in a
/// single call without scaling with a host that configures a very large one.
const MAX_READ_CHUNK: usize = 16 * 1024;

/// Packets one poll takes off the link before the rest wait their turn.
///
/// A host with no operating system has nothing to preempt a poll, so a link
/// that keeps delivering must not be able to hold one open -- which is what
/// [`Interface::poll`] does, and says so. Whatever is left over makes the next
/// poll immediate rather than waiting on a timer.
const MAX_INGRESS_PER_POLL: usize = 32;

/// Limits for a [`SmoltcpTcpProvider`].
///
/// Every socket costs `rx_buffer + tx_buffer` bytes for as long as it exists,
/// including the ones sitting in a listener's backlog, so these are the numbers
/// that decide the provider's memory footprint: at most
/// `max_sockets * (rx_buffer + tx_buffer)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmoltcpConfig {
    /// Receive ring per socket.
    ///
    /// This is the peer's send window, so it bounds throughput on a link with
    /// any latency to speak of. It is not a correctness limit: the transport
    /// takes whatever arrives.
    pub rx_buffer: usize,
    /// Transmit ring per socket.
    ///
    /// Writes larger than the free space here are accepted in part, which the
    /// transport already expects of any socket.
    pub tx_buffer: usize,
    /// Sockets held in `Listen` per listener, ready to catch an incoming SYN.
    ///
    /// smoltcp has no listen queue: a socket either is waiting for a SYN or is
    /// not, and a SYN arriving with none waiting is refused. This is how deep
    /// that pool is, so it is the number of connections that may arrive at once
    /// without one being turned away.
    pub backlog: usize,
    /// Ceiling on sockets in existence at one time.
    ///
    /// Counts backlog sockets and ones closing down as well as live
    /// connections. Reaching it fails [`connect`](TcpProvider::connect) and
    /// stops listeners refilling their backlog, rather than allocating past
    /// what the host budgeted.
    pub max_sockets: usize,
    /// How long a handshake may hang before it is abandoned, or `None` to keep
    /// retransmitting indefinitely.
    ///
    /// Applies in both directions, because smoltcp gives up on neither: it
    /// retransmits for as long as the socket lives. Without this a dial to an
    /// address nothing answers at never finishes and never fails, and an
    /// inbound `SYN` that is never acknowledged holds a socket for good --
    /// which is the whole budget away from a peer that opens connections and
    /// walks off.
    ///
    /// Measured from the first [`poll`](TcpProvider::poll) that sees the
    /// stream, since that is the first time this provider is told what time it
    /// is.
    pub connect_timeout_ms: Option<u64>,
    /// Local ports dials are drawn from.
    ///
    /// Allocated round-robin, and returned only once the socket using it is
    /// gone -- which is after `TIME-WAIT`, not when the connection is reported
    /// closed, so a port is never reused while the old connection still owns
    /// the four-tuple.
    pub ephemeral_ports: RangeInclusive<u16>,
}

impl Default for SmoltcpConfig {
    fn default() -> Self {
        Self {
            // Four maximum-size segments each way: enough that a link with some
            // latency stays busy, small enough that a device with a handful of
            // connections fits in tens of kilobytes.
            rx_buffer: 8 * 1024,
            tx_buffer: 8 * 1024,
            backlog: 2,
            max_sockets: 16,
            connect_timeout_ms: Some(10_000),
            ephemeral_ports: 49152..=65535,
        }
    }
}

/// Which side opened the stream, and so which event announces it.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Role {
    Inbound,
    Outbound,
}

/// Where a stream is between being asked for and carrying bytes.
///
/// One state rather than a flag plus a deadline, so a countdown cannot outlive
/// the handshake it was bounding: an established connection is `Open`, and
/// `Open` carries no deadline to report.
///
/// A handshake nothing answers is not self-limiting -- smoltcp retransmits for
/// as long as the socket exists -- so it needs a countdown of its own. Without
/// one a dial to a silent address never finishes and never fails, and an
/// inbound `SYN` never acknowledged holds a socket for good, which is a
/// device's whole budget away from a peer that opens connections and walks off.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    /// Coming up, not yet timed.
    ///
    /// The countdown starts at the first poll to see the stream rather than at
    /// the call that created it, because this provider has no clock: the only
    /// time it holds between polls is the last poll's sample, and after an idle
    /// spell that is arbitrarily long ago. Dating a dial from it would start it
    /// already expired.
    Opening,
    /// Coming up, given up on at this monotonic millisecond.
    OpeningUntil(u64),
    /// Coming up, waited on indefinitely, because the host asked for no timeout.
    OpeningForever,
    /// Announced, so events may be reported against it.
    Open,
}

struct Entry {
    inner: SmoltcpHandle,
    role: Role,
    /// Held only by a dial, and returned to the pool once the socket is
    /// reclaimed. A listener's port is shared by every connection it accepts,
    /// so those carry none.
    ephemeral_port: Option<u16>,
    /// The remote's end-of-stream has already been reported.
    read_closed: bool,
    /// A send was refused in part, so a [`TcpEvent::Writable`] is owed once
    /// there is room again.
    send_blocked: bool,
    phase: Phase,
}

/// A socket whose stream is over, waiting on smoltcp to finish with it.
struct Reclaim {
    socket: SmoltcpHandle,
    /// Released only when the socket is finally gone, so a port is never handed
    /// to a new dial while `TIME-WAIT` still holds the old connection on it.
    port: Option<u16>,
}

struct Listener {
    /// The concrete address reported to the caller.
    bound: Multiaddr,
    endpoint: IpListenEndpoint,
    /// Sockets parked in `Listen`, waiting for a SYN.
    armed: Vec<SmoltcpHandle>,
}

/// A [`TcpProvider`] over [smoltcp], for hosts with no operating system.
///
/// The whole transport above this -- the upgrade, multiplexing, the
/// [`Transport`](minip2p_transport::Transport) contract -- is the same code the
/// hosted `StdTcpProvider` runs under. This is the other end of that seam.
///
/// # Ownership
///
/// The host builds the [`Interface`] and hands it over, because addressing is
/// its business: which medium the link speaks, what addresses it holds, whether
/// they came from DHCP. This provider owns only sockets, and reaches the
/// interface through [`interface_mut`](Self::interface_mut) if the host needs
/// to reconfigure it later.
///
/// ```no_run
/// # use minip2p_tcp::{SmoltcpConfig, SmoltcpTcpProvider};
/// # use smoltcp::iface::{Config, Interface};
/// # use smoltcp::phy::Device;
/// # use smoltcp::time::Instant;
/// # use smoltcp::wire::{HardwareAddress, IpCidr, Ipv4Address};
/// # fn build<D: Device>(mut device: D) -> SmoltcpTcpProvider<D> {
/// let mut iface = Interface::new(
///     Config::new(HardwareAddress::Ip),
///     &mut device,
///     Instant::from_millis(0),
/// );
/// iface.update_ip_addrs(|addrs| {
///     let _ = addrs.push(IpCidr::new(Ipv4Address::new(192, 168, 1, 2).into(), 24));
/// });
/// SmoltcpTcpProvider::new(device, iface, SmoltcpConfig::default())
/// # }
/// ```
///
/// # Addresses
///
/// `/ip4` and `/ip6` only. `/dns*` is refused rather than guessed at: name
/// resolution is I/O this provider does not do, and a host that needs it
/// resolves the name itself and dials the result.
///
/// A wildcard listen host binds every address the interface holds, of either
/// family -- smoltcp has one listen endpoint, not one per family, so a
/// `/ip4/0.0.0.0` listener answers on the interface's IPv6 addresses too.
/// [`listen`](TcpProvider::listen) reports one of them and
/// [`local_addresses`](TcpProvider::local_addresses) reports them all.
///
/// Two addresses may name the same port, because smoltcp matches a segment on
/// the local address as well as the port; a wildcard is what collides with
/// everything on its port, since it answers for every address there.
///
/// # Driving it
///
/// smoltcp is timer-driven -- retransmits, delayed acknowledgements, closing
/// timers -- so [`next_deadline`](TcpProvider::next_deadline) is load-bearing
/// here in a way it is not for a readiness-driven provider. A host that ignores
/// it will still work as long as it polls often enough, but a host that honours
/// it can sleep between packets, which is the point on a device that runs on a
/// battery.
///
/// [smoltcp]: https://docs.rs/smoltcp
pub struct SmoltcpTcpProvider<D: Device> {
    device: D,
    iface: Interface,
    sockets: SocketSet<'static>,
    config: SmoltcpConfig,
    listeners: Vec<Listener>,
    entries: BTreeMap<SocketHandle, Entry>,
    /// Produced while servicing sockets, drained by the `poll` that produced
    /// them.
    ready: VecDeque<TcpEvent>,
    next_id: u64,
    /// Where the next ephemeral port search starts, so dials cycle the range
    /// rather than reusing the port just released.
    next_port: u16,
    /// Ports drawn from the pool and not yet given back: a live dial's, and a
    /// listener's when it asked for any port. A listener that named its own
    /// port is not in here -- what makes that one taken is the listener
    /// itself, which [`listen_conflict`](Self::listen_conflict) is what
    /// consults.
    used_ports: BTreeSet<u16>,
    /// Sockets finished with, kept until smoltcp has dispatched their last
    /// packet and reached `Closed`.
    reclaiming: Vec<Reclaim>,
    /// The `now` from the last poll, so operations between polls can be
    /// timestamped without this provider reading a clock.
    now_ms: u64,
    /// Bytes were queued since the last poll and have not been put on the wire.
    egress_pending: bool,
    /// The last poll spent its ingress budget, so the link still holds packets
    /// nothing else will announce.
    ingress_pending: bool,
    /// smoltcp's own answer to when it next needs driving, captured during
    /// `poll` because computing it needs the interface mutably.
    poll_at: Option<u64>,
    read_buffer: Vec<u8>,
}

fn instant(millis: u64) -> Instant {
    // smoltcp keeps time as microseconds in an `i64`, so the largest
    // millisecond value it can hold is a thousandth of `i64::MAX`. Saturating
    // at `i64::MAX` itself would overflow the multiplication inside.
    let ceiling = i64::MAX / 1000;
    Instant::from_millis(i64::try_from(millis).unwrap_or(ceiling).min(ceiling))
}

/// Turns an endpoint into the `/ipX/tcp/port` multiaddr for it.
fn endpoint_to_multiaddr(endpoint: IpEndpoint) -> Multiaddr {
    let host = match endpoint.addr {
        IpAddress::Ipv4(v4) => Protocol::Ip4(v4.octets()),
        IpAddress::Ipv6(v6) => Protocol::Ip6(v6.octets()),
    };
    Multiaddr::from_protocols(vec![host, Protocol::Tcp(endpoint.port)])
}

fn address_to_multiaddr(address: IpAddress, port: u16) -> Multiaddr {
    endpoint_to_multiaddr(IpEndpoint::new(address, port))
}

/// Splits a `/tcp` multiaddr into an IP address and a port, rejecting names.
fn ip_and_port(addr: &Multiaddr, context: &'static str) -> Result<(IpAddress, u16), TcpError> {
    let (host, port) = host_and_port(addr, context)?;
    let address = match host {
        Protocol::Ip4(octets) => IpAddress::Ipv4(Ipv4Addr::from(octets)),
        Protocol::Ip6(octets) => IpAddress::Ipv6(Ipv6Addr::from(octets)),
        _ => {
            return Err(TcpError::Address {
                context,
                reason: format!(
                    "{addr} names a host; this provider does no name resolution, \
                     so give it an /ip4 or /ip6 address"
                ),
            });
        }
    };
    Ok((address, port))
}

fn is_unspecified(address: IpAddress) -> bool {
    match address {
        IpAddress::Ipv4(v4) => v4.is_unspecified(),
        IpAddress::Ipv6(v6) => v6.is_unspecified(),
    }
}

impl<D: Device> SmoltcpTcpProvider<D> {
    /// Creates a provider over an interface the host has already configured.
    pub fn new(device: D, iface: Interface, config: SmoltcpConfig) -> Self {
        let read_buffer = vec![0u8; config.rx_buffer.clamp(512, MAX_READ_CHUNK)];
        let next_port = *config.ephemeral_ports.start();
        Self {
            device,
            iface,
            sockets: SocketSet::new(Vec::new()),
            config,
            listeners: Vec::new(),
            entries: BTreeMap::new(),
            ready: VecDeque::new(),
            next_id: 1,
            next_port,
            used_ports: BTreeSet::new(),
            reclaiming: Vec::new(),
            now_ms: 0,
            egress_pending: false,
            ingress_pending: false,
            poll_at: None,
            read_buffer,
        }
    }

    /// The interface, for a host that reconfigures addressing while running.
    pub fn interface_mut(&mut self) -> &mut Interface {
        &mut self.iface
    }

    /// The link, for a host that has to service it out of band.
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    fn allocate_handle(&mut self) -> SocketHandle {
        let handle = SocketHandle::new(self.next_id);
        self.next_id += 1;
        handle
    }

    /// Sockets this provider has in existence, whatever they are doing.
    fn socket_count(&self) -> usize {
        self.entries.len()
            + self.reclaiming.len()
            + self
                .listeners
                .iter()
                .map(|listener| listener.armed.len())
                .sum::<usize>()
    }

    fn new_socket(&mut self) -> Result<SmoltcpHandle, TcpError> {
        if self.socket_count() >= self.config.max_sockets {
            return Err(TcpError::Exhausted {
                resource: "tcp sockets",
            });
        }
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; self.config.rx_buffer]),
            tcp::SocketBuffer::new(vec![0u8; self.config.tx_buffer]),
        );
        Ok(self.sockets.add(socket))
    }

    fn allocate_port(&mut self) -> Result<u16, TcpError> {
        let exhausted = TcpError::Exhausted {
            resource: "ephemeral ports",
        };
        let (start, end) = (
            *self.config.ephemeral_ports.start(),
            *self.config.ephemeral_ports.end(),
        );
        if start > end {
            return Err(exhausted);
        }
        if self.next_port < start || self.next_port > end {
            self.next_port = start;
        }
        for _ in 0..=(end - start) {
            let port = self.next_port;
            self.next_port = if port == end { start } else { port + 1 };
            // A listener's port is passed over even though a dial could safely
            // share it -- smoltcp tells the two apart by the four-tuple -- so
            // that a port has one owner and a reservation means one thing.
            if !self.listen_conflict(None, port) && self.used_ports.insert(port) {
                return Ok(port);
            }
        }
        Err(exhausted)
    }

    /// Returns a port to the pool, if there was one to return.
    fn release(&mut self, port: Option<u16>) {
        if let Some(port) = port {
            self.used_ports.remove(&port);
        }
    }

    /// Whether a listen endpoint overlaps one this provider already holds.
    ///
    /// Two listeners on one port collide only when a segment could belong to
    /// either: the same address, or a wildcard on either side. Distinct
    /// addresses are distinct endpoints to smoltcp, which matches the local
    /// address as well as the port, so refusing them would turn a listener per
    /// address into a listener per port -- and a host binding one address per
    /// family on a fixed port would get its second bind refused.
    fn listen_conflict(&self, address: Option<IpAddress>, port: u16) -> bool {
        self.listeners.iter().any(|listener| {
            listener.endpoint.port == port
                && match (listener.endpoint.addr, address) {
                    (Some(bound), Some(wanted)) => bound == wanted,
                    _ => true,
                }
        })
    }

    /// Drops an entry, releasing its port and queueing its socket for reclaim.
    ///
    /// The socket itself outlives this, until [`reclaim`](Self::reclaim) finds
    /// it has nothing left to say -- and so does its port, because a connection
    /// in `TIME-WAIT` still owns the four-tuple it was using.
    fn retire(&mut self, handle: SocketHandle) {
        let Some(entry) = self.entries.remove(&handle) else {
            return;
        };
        self.reclaiming.push(Reclaim {
            socket: entry.inner,
            port: entry.ephemeral_port,
        });
    }

    /// Removes sockets that have finished closing down.
    ///
    /// A socket is not thrown away the moment its entry goes: smoltcp may still
    /// owe the peer a `FIN`, an `RST`, or a final acknowledgement, and it holds
    /// `TIME-WAIT` open to absorb a retransmitted `FIN`. Anything a socket has
    /// to say is dispatched by the egress at the head of the next poll, which
    /// [`egress_pending`](Self::next_deadline) makes sure happens; this only
    /// collects what has said it.
    fn reclaim(&mut self) {
        let (sockets, used_ports) = (&mut self.sockets, &mut self.used_ports);
        self.reclaiming.retain(|pending| {
            if sockets.get::<tcp::Socket>(pending.socket).state() != tcp::State::Closed {
                return true;
            }
            sockets.remove(pending.socket);
            if let Some(port) = pending.port {
                used_ports.remove(&port);
            }
            false
        });
    }

    /// Promotes listener sockets that caught a connection and refills the pool.
    fn harvest_listeners(&mut self) {
        for index in 0..self.listeners.len() {
            let armed = core::mem::take(&mut self.listeners[index].armed);
            let mut kept = Vec::with_capacity(armed.len());
            for inner in armed {
                match self.sockets.get::<tcp::Socket>(inner).state() {
                    tcp::State::Listen => kept.push(inner),
                    // Taken. It becomes a stream of its own, announced once the
                    // handshake finishes -- or, if it dies first, retired
                    // without a word, since nothing was ever handed over for
                    // it. Either way the backlog refills below.
                    _ => {
                        let handle = self.allocate_handle();
                        self.entries.insert(
                            handle,
                            Entry {
                                inner,
                                role: Role::Inbound,
                                ephemeral_port: None,
                                read_closed: false,
                                send_blocked: false,
                                phase: Phase::Opening,
                            },
                        );
                    }
                }
            }
            self.listeners[index].armed = kept;
        }
    }

    /// Tops a listener's backlog back up to what the configuration asks for.
    ///
    /// Stops quietly at the socket ceiling: refusing to allocate past the
    /// host's budget is the point of the ceiling, and the backlog refills on a
    /// later poll once something frees up.
    fn arm_listener(&mut self, index: usize) {
        let endpoint = self.listeners[index].endpoint;
        while self.listeners[index].armed.len() < self.config.backlog {
            let Ok(inner) = self.new_socket() else {
                return;
            };
            if self
                .sockets
                .get_mut::<tcp::Socket>(inner)
                .listen(endpoint)
                .is_err()
            {
                self.sockets.remove(inner);
                return;
            }
            self.listeners[index].armed.push(inner);
        }
    }

    /// Runs the interface for one poll: maintenance, ingress, then egress.
    ///
    /// Deliberately not [`Interface::poll`], which processes every packet the
    /// link has queued and so runs for as long as they keep arriving -- an
    /// unbounded amount of work, as smoltcp's own warning on it says. Nothing
    /// preempts that on a device with no operating system, so the ingress is
    /// budgeted the way the hosted provider budgets reads and accepts, and
    /// what did not fit is reported as due now.
    fn drive(&mut self, timestamp: Instant) {
        self.iface.poll_maintenance(timestamp);

        let mut budget = MAX_INGRESS_PER_POLL;
        self.ingress_pending = loop {
            if budget == 0 {
                break true;
            }
            budget -= 1;
            if self
                .iface
                .poll_ingress_single(timestamp, &mut self.device, &mut self.sockets)
                == PollIngressSingleResult::None
            {
                break false;
            }
        };

        // After the ingress, so what just arrived is acknowledged in the same
        // poll. Bounded by the transmit rings rather than by the link, which is
        // why this one drains rather than counting.
        while self
            .iface
            .poll_egress(timestamp, &mut self.device, &mut self.sockets)
            == PollResult::SocketStateChanged
        {}
    }

    /// Turns one socket's state into events.
    fn service(&mut self, handle: SocketHandle) {
        let Some(entry) = self.entries.get(&handle) else {
            return;
        };
        let inner = entry.inner;
        if entry.phase != Phase::Open && !self.announce(handle) {
            return;
        }

        // Reads first, and to exhaustion: the receive ring is what bounds this,
        // and bytes left in it would have to wait for whatever wakes the host
        // next.
        loop {
            let socket = self.sockets.get_mut::<tcp::Socket>(inner);
            if !socket.can_recv() {
                break;
            }
            let Ok(taken) = socket.recv_slice(&mut self.read_buffer) else {
                break;
            };
            if taken == 0 {
                break;
            }
            self.ready.push_back(TcpEvent::Received {
                socket: handle,
                data: self.read_buffer[..taken].to_vec(),
            });
        }

        let socket = self.sockets.get::<tcp::Socket>(inner);
        // Reads are drained above, so this is genuinely the end of the stream
        // rather than a full ring.
        let ended = !socket.may_recv();
        let writable = socket.can_send();
        let finished = !socket.is_open();

        let Some(entry) = self.entries.get_mut(&handle) else {
            return;
        };
        if ended && !entry.read_closed {
            entry.read_closed = true;
            self.ready
                .push_back(TcpEvent::RemoteWriteClosed { socket: handle });
        }
        if writable && entry.send_blocked {
            entry.send_blocked = false;
            self.ready.push_back(TcpEvent::Writable { socket: handle });
        }
        if finished {
            // smoltcp does not tell a reset apart from an orderly shutdown on
            // the socket, so there is no reason to report that would not be a
            // guess. What the peer did or did not manage to send is visible to
            // the session above, which is where a truncated stream is a fault.
            self.ready.push_back(TcpEvent::Closed {
                socket: handle,
                reason: None,
            });
            self.retire(handle);
        }
    }

    /// Starts a stream's countdown if it has not started already,
    /// and reports where it stands.
    ///
    /// This is the only place a handshake is given a deadline, and it runs from
    /// inside a poll, so the deadline is measured from a time sample the host
    /// just took. Both roles get one: a dial nothing answers and an inbound
    /// `SYN` never acknowledged are the same stalled socket from opposite ends,
    /// and smoltcp abandons neither on its own.
    fn start_countdown(&mut self, handle: SocketHandle) -> Phase {
        let timeout = self.config.connect_timeout_ms;
        let now = self.now_ms;
        let Some(entry) = self.entries.get_mut(&handle) else {
            return Phase::OpeningForever;
        };
        if entry.phase == Phase::Opening {
            entry.phase = match timeout {
                Some(timeout) => Phase::OpeningUntil(now.saturating_add(timeout)),
                None => Phase::OpeningForever,
            };
        }
        entry.phase
    }

    /// Announces a stream once its handshake finishes, or gives up on it.
    ///
    /// Returns whether the stream is now announced and worth servicing.
    fn announce(&mut self, handle: SocketHandle) -> bool {
        let phase = self.start_countdown(handle);
        let Some(entry) = self.entries.get(&handle) else {
            return false;
        };
        let (inner, role) = (entry.inner, entry.role);
        let socket = self.sockets.get::<tcp::Socket>(inner);

        if !socket.may_send() {
            // A reset in `SYN-RECEIVED` puts a socket back into `Listen` rather
            // than closing it, so a stream can end by its socket becoming
            // somebody else's again. Either way this one is over, and keeping
            // an entry that names a socket no longer carrying it would hold a
            // slot against a stream that does not exist.
            let gave_up = if !socket.is_open() || socket.is_listening() {
                Some("the connection attempt failed")
            } else if matches!(phase, Phase::OpeningUntil(deadline) if self.now_ms >= deadline) {
                Some("the connection attempt timed out")
            } else {
                None
            };
            let Some(reason) = gave_up else {
                return false;
            };
            // Forces a socket still waiting on a `SYN` to `Closed` so it can be
            // reclaimed. It sends no reset worth having: nothing answered, which
            // is the whole reason this stream is being given up on.
            self.sockets.get_mut::<tcp::Socket>(inner).abort();
            if role == Role::Outbound {
                // The handle is already the caller's, so it has to be retired
                // in the open. An inbound attempt was never handed over, so it
                // leaves without a word.
                self.ready.push_back(TcpEvent::Closed {
                    socket: handle,
                    reason: Some(reason.to_string()),
                });
            }
            self.retire(handle);
            return false;
        }

        // A stream with no remote endpoint is one that has not finished coming
        // up, whatever the transmit half says; announcing it would name an
        // address nobody is at.
        let Some(remote) = socket.remote_endpoint().map(endpoint_to_multiaddr) else {
            return false;
        };
        let Some(entry) = self.entries.get_mut(&handle) else {
            return false;
        };
        entry.phase = Phase::Open;
        self.ready.push_back(match role {
            Role::Inbound => TcpEvent::Accepted {
                socket: handle,
                remote,
            },
            Role::Outbound => TcpEvent::Connected {
                socket: handle,
                remote,
            },
        });
        true
    }
}

impl<D: Device> TcpProvider for SmoltcpTcpProvider<D> {
    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TcpError> {
        let (address, requested) = ip_and_port(addr, "tcp listen")?;
        let wildcard = is_unspecified(address);
        if !wildcard && !self.iface.has_ip_addr(address) {
            return Err(TcpError::Address {
                context: "tcp listen",
                reason: format!("{addr} is not an address of this interface"),
            });
        }

        let endpoint = IpListenEndpoint {
            addr: (!wildcard).then_some(address),
            port: 0,
        };
        let port = if requested == 0 {
            self.allocate_port()?
        } else {
            if self.listen_conflict(endpoint.addr, requested) {
                return Err(TcpError::Address {
                    context: "tcp listen",
                    reason: format!("port {requested} is already in use"),
                });
            }
            requested
        };
        // Only a port this call drew from the pool is handed back on failure;
        // a port the caller named was never taken out of it.
        let drawn = (requested == 0).then_some(port);

        // A wildcard has to resolve to something concrete, and on an interface
        // with no address at all there is nothing to resolve it to.
        let bound = if wildcard {
            let first = self.iface.ip_addrs().first().ok_or(TcpError::Address {
                context: "tcp listen",
                reason: "the interface holds no address to listen on".into(),
            });
            match first {
                Ok(cidr) => address_to_multiaddr(cidr.address(), port),
                Err(error) => {
                    self.release(drawn);
                    return Err(error);
                }
            }
        } else {
            address_to_multiaddr(address, port)
        };

        let index = self.listeners.len();
        self.listeners.push(Listener {
            bound: bound.clone(),
            endpoint: IpListenEndpoint { port, ..endpoint },
            armed: Vec::new(),
        });
        self.arm_listener(index);
        if self.listeners[index].armed.is_empty() {
            self.listeners.pop();
            self.release(drawn);
            return Err(TcpError::Exhausted {
                resource: "tcp sockets",
            });
        }
        Ok(bound)
    }

    fn connect(&mut self, addr: &Multiaddr) -> Result<SocketHandle, TcpError> {
        let (address, port) = ip_and_port(addr, "tcp dial")?;
        if port == 0 {
            return Err(TcpError::Address {
                context: "tcp dial",
                reason: format!("{addr} has no port to dial"),
            });
        }
        let local = self.allocate_port()?;
        let inner = self.new_socket().inspect_err(|_| {
            self.used_ports.remove(&local);
        })?;

        let remote = IpEndpoint::new(address, port);
        let context = self.iface.context();
        if let Err(error) = self
            .sockets
            .get_mut::<tcp::Socket>(inner)
            .connect(context, remote, local)
        {
            self.sockets.remove(inner);
            self.used_ports.remove(&local);
            return Err(TcpError::Io {
                operation: "starting a connect",
                reason: error.to_string(),
            });
        }

        let handle = self.allocate_handle();
        self.entries.insert(
            handle,
            Entry {
                inner,
                role: Role::Outbound,
                ephemeral_port: Some(local),
                read_closed: false,
                send_blocked: false,
                phase: Phase::Opening,
            },
        );
        // The SYN is queued, not sent.
        self.egress_pending = true;
        Ok(handle)
    }

    fn send(&mut self, socket: SocketHandle, data: &[u8]) -> Result<usize, TcpError> {
        let entry = self
            .entries
            .get(&socket)
            .ok_or(TcpError::UnknownSocket { socket })?;
        let inner = entry.inner;
        // `InvalidState` means the transmit half is shut -- the connection is
        // closing, or gone. That is a socket taking nothing rather than a
        // failed write, and it is already on its way to a `Closed`.
        let accepted = self
            .sockets
            .get_mut::<tcp::Socket>(inner)
            .send_slice(data)
            .unwrap_or(0);

        let Some(entry) = self.entries.get_mut(&socket) else {
            return Ok(accepted);
        };
        if accepted < data.len() {
            entry.send_blocked = true;
        }
        if accepted > 0 {
            self.egress_pending = true;
        }
        Ok(accepted)
    }

    fn close_write(&mut self, socket: SocketHandle) -> Result<(), TcpError> {
        let entry = self
            .entries
            .get(&socket)
            .ok_or(TcpError::UnknownSocket { socket })?;
        // smoltcp sends the `FIN` behind whatever is still queued, so this
        // needs no flushing of its own -- only a poll to put it on the wire.
        self.sockets.get_mut::<tcp::Socket>(entry.inner).close();
        self.egress_pending = true;
        Ok(())
    }

    fn abort(&mut self, socket: SocketHandle) {
        let Some(entry) = self.entries.get(&socket) else {
            return;
        };
        self.sockets.get_mut::<tcp::Socket>(entry.inner).abort();
        // The caller is owed nothing further, and there is nothing to take
        // back: `poll` hands over everything it produces before it returns, so
        // between polls there is never an event queued to discard.
        self.retire(socket);
        // The reset still has to reach the peer.
        self.egress_pending = true;
    }

    fn poll(&mut self, now: Now) -> Result<Vec<TcpEvent>, TcpError> {
        self.now_ms = now.monotonic_ms;
        let timestamp = instant(now.monotonic_ms);
        self.drive(timestamp);
        self.egress_pending = false;

        self.harvest_listeners();
        for handle in self.entries.keys().copied().collect::<Vec<_>>() {
            self.service(handle);
        }

        self.reclaim();
        // After the reclaim, not before: a connection that ended during this
        // poll frees a socket, and a listener refilled ahead of that would miss
        // it and finish the poll with an empty backlog. A `SYN` arriving before
        // the next poll is then lost, and the peer waits out a retransmit to
        // get in -- so this is a poll leaving the provider ready rather than
        // one poll behind.
        for index in 0..self.listeners.len() {
            self.arm_listener(index);
        }

        self.poll_at = self
            .iface
            .poll_at(timestamp, &self.sockets)
            .map(|at| u64::try_from(at.total_millis()).unwrap_or(0));
        Ok(self.ready.drain(..).collect())
    }

    fn next_deadline(&self) -> Option<Deadline> {
        if self.egress_pending || self.ingress_pending {
            // Something is queued -- ours to send, or the link's for us to take
            // in -- and will not move until the next poll.
            return Some(Deadline::IMMEDIATE);
        }
        let connects = self
            .entries
            .values()
            .filter_map(|entry| match entry.phase {
                Phase::OpeningUntil(deadline) => Some(deadline),
                // A stream still waiting for its first poll was created since
                // the last one, which `egress_pending` has already made urgent.
                Phase::Opening | Phase::OpeningForever | Phase::Open => None,
            })
            .min()
            .map(Deadline::from_millis);
        Deadline::earliest_opt(self.poll_at.map(Deadline::from_millis), connects)
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        self.listeners
            .iter()
            .flat_map(|listener| match listener.endpoint.addr {
                Some(_) => vec![listener.bound.clone()],
                // A wildcard listener answers on every address the interface
                // holds, so reporting only the one `listen` picked would hide
                // most of the ways it can be reached.
                None => self
                    .iface
                    .ip_addrs()
                    .iter()
                    .map(|cidr| address_to_multiaddr(cidr.address(), listener.endpoint.port))
                    .collect(),
            })
            .collect()
    }
}
