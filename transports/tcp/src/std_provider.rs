use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr};

use minip2p_core::{Multiaddr, Protocol};
use minip2p_platform::{Deadline, Now};
use minip2p_transport::{PollSource, TokenSpace};
use mio::event::Event;
use mio::{Interest, Registry, Token, Waker};
use socket2::{Domain, Protocol as SocketProtocol, Socket as Socket2, Type};

use crate::provider::{SocketHandle, TcpError, TcpEvent, TcpProvider, host_and_port};

/// Read size per syscall. Large enough that a busy stream is not dominated by
/// syscall overhead, small enough not to hold a big buffer per provider.
const READ_CHUNK: usize = 16 * 1024;

/// Reads one socket may take from a single poll before the rest wait their
/// turn -- 128 KiB at [`READ_CHUNK`] apiece. Without a bound, one fast peer
/// starves every other socket and the host's timers along with it.
const MAX_READS_PER_POLL: usize = 8;

/// Connections accepted in a single poll, for the same reason.
const MAX_ACCEPTS_PER_POLL: usize = 32;

fn io_error(operation: &'static str, error: &dyn core::fmt::Display) -> TcpError {
    TcpError::Io {
        operation,
        reason: error.to_string(),
    }
}

/// Converts a socket address to the `/ipX/tcp/port` multiaddr for it.
fn socket_addr_to_multiaddr(addr: SocketAddr) -> Multiaddr {
    match addr {
        SocketAddr::V4(v4) => Multiaddr::from_protocols(vec![
            Protocol::Ip4(v4.ip().octets()),
            Protocol::Tcp(v4.port()),
        ]),
        SocketAddr::V6(v6) => Multiaddr::from_protocols(vec![
            Protocol::Ip6(v6.ip().octets()),
            Protocol::Tcp(v6.port()),
        ]),
    }
}

/// Resolves a bind address, rejecting names.
///
/// A listener has to bind one concrete interface; a name that resolves to
/// several would make the choice silently, so it is refused instead.
fn listen_addr(addr: &Multiaddr) -> Result<SocketAddr, TcpError> {
    let (host, port) = host_and_port(addr, "tcp listen")?;
    match host {
        Protocol::Ip4(octets) => Ok(SocketAddr::new(IpAddr::from(octets), port)),
        Protocol::Ip6(octets) => Ok(SocketAddr::new(IpAddr::from(octets), port)),
        _ => Err(TcpError::Address {
            context: "tcp listen",
            reason: "listen needs an /ip4 or /ip6 host; names are dial-only".to_string(),
        }),
    }
}

fn bind_listener(requested: SocketAddr) -> std::io::Result<mio::net::TcpListener> {
    let socket = Socket2::new(
        Domain::for_address(requested),
        Type::STREAM,
        Some(SocketProtocol::TCP),
    )?;
    if requested.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&requested.into())?;
    let backlog = if cfg!(target_os = "horizon") {
        20
    } else if cfg!(target_os = "haiku") {
        32
    } else {
        128
    };
    socket.listen(backlog)?;
    Ok(mio::net::TcpListener::from_std(socket.into()))
}

/// Keeps small protocol frames from waiting behind an unacknowledged write.
fn disable_nagle(stream: &mio::net::TcpStream) -> Result<(), TcpError> {
    stream
        .set_nodelay(true)
        .map_err(|error| io_error("disabling Nagle's algorithm", &error))
}

/// The socket address a dial targets, rejecting names.
///
/// A name lookup blocks, and `connect` runs on the driver thread, so this
/// provider never resolves: the std `Endpoint` resolves `/dns*` candidates off
/// its driver, and a direct caller resolves the name itself first.
fn dial_addr(addr: &Multiaddr) -> Result<SocketAddr, TcpError> {
    let (host, port) = host_and_port(addr, "tcp dial")?;
    match host {
        Protocol::Ip4(octets) => Ok(SocketAddr::new(IpAddr::from(octets), port)),
        Protocol::Ip6(octets) => Ok(SocketAddr::new(IpAddr::from(octets), port)),
        Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) => Err(TcpError::Address {
            context: "tcp dial",
            reason: format!(
                "{addr} names a host; resolve it to /ip4 or /ip6 first \
                 (this provider does not resolve names)"
            ),
        }),
        _ => Err(TcpError::Address {
            context: "tcp dial",
            reason: format!("{addr} has no host component"),
        }),
    }
}

struct Listener {
    listener: mio::net::TcpListener,
    /// Its registration token, once attached.
    token: Option<Token>,
    bound: Multiaddr,
}

/// What a registration token currently stands for.
#[derive(Clone, Copy)]
enum Slot {
    Listener,
    Socket(SocketHandle),
}

/// The host's shared poll, once attached, and the tokens handed out in it.
///
/// Tokens are reused once their socket is deregistered, and are deliberately
/// not [`SocketHandle`]s: a handle is never reused, so a stale event for a
/// recycled token can at most mark the replacement possibly ready, never
/// touch the retired socket's lifecycle.
struct Registration {
    registry: Registry,
    tokens: TokenSpace,
    /// Token index to what holds it now.
    slots: Vec<Option<Slot>>,
    /// Indexes free for reuse.
    free: Vec<usize>,
}

impl Registration {
    /// Registers `source` for `slot` under a fresh or recycled token.
    fn register(
        &mut self,
        source: &mut impl mio::event::Source,
        slot: Slot,
        interest: Interest,
    ) -> Result<Token, TcpError> {
        let index = self.free.pop().unwrap_or(self.slots.len());
        let Some(token) = self.tokens.token(index) else {
            return Err(TcpError::Exhausted {
                resource: "readiness tokens",
            });
        };
        if let Err(error) = self.registry.register(source, token, interest) {
            self.release_index(index);
            return Err(io_error("registering a socket", &error));
        }
        if index == self.slots.len() {
            self.slots.push(Some(slot));
        } else if let Some(entry) = self.slots.get_mut(index) {
            *entry = Some(slot);
        }
        Ok(token)
    }

    /// Deregisters `source` and frees its token for reuse.
    fn deregister(&mut self, source: &mut impl mio::event::Source, token: Token) {
        // The source is about to drop, which releases the registration too.
        drop(self.registry.deregister(source));
        if let Some(index) = self.tokens.index_of(token) {
            self.release_index(index);
        }
    }

    fn release_index(&mut self, index: usize) {
        if let Some(entry) = self.slots.get_mut(index) {
            *entry = None;
        }
        if index < self.slots.len() {
            self.free.push(index);
        }
    }

    fn slot(&self, token: Token) -> Option<Slot> {
        let index = self.tokens.index_of(token)?;
        self.slots.get(index).copied().flatten()
    }
}

enum Phase {
    /// `connect` has been issued; writability decides whether it succeeded.
    Connecting,
    /// The stream is up and carrying bytes.
    Open,
}

struct Socket {
    stream: mio::net::TcpStream,
    /// Its registration token, once attached.
    token: Option<Token>,
    remote: Multiaddr,
    phase: Phase,
    /// Set by a readiness event, cleared by a write the socket did not take
    /// whole.
    writable: bool,
    /// Whether `WRITABLE` is currently registered.
    ///
    /// Registered only while something is waiting on it: a connect that has yet
    /// to complete, or a write the socket refused. That is what an
    /// edge-triggered readiness API expects, and it keeps
    /// [`TcpEvent::Writable`] meaningful rather than a stream of edges nobody
    /// asked for.
    ///
    /// The wake it buys a blocking driver -- resuming a stalled write the
    /// moment the socket drains, instead of sleeping to the stall deadline --
    /// is not covered by a test: on loopback a socket that stays full long
    /// enough to observe is not reliably arrangeable, and above the session a
    /// draining peer sends Yamux acknowledgements that would wake the driver
    /// anyway.
    watching_writable: bool,
    /// The remote's FIN has already been reported.
    read_closed: bool,
    /// The local write side has been shut down.
    write_closed: bool,
}

/// A [`TcpProvider`] over operating-system sockets, driven by `mio`.
///
/// Non-blocking throughout: [`poll`](TcpProvider::poll),
/// [`send`](TcpProvider::send), [`close_write`](TcpProvider::close_write), and
/// [`abort`](TcpProvider::abort) service whatever is ready and return. It owns
/// no poll of its own: as a [`PollSource`] it registers its sockets with the
/// host's shared one and records what [`dispatch`](PollSource::dispatch)
/// reports. Readiness is edge-triggered, so every ready socket is read until
/// it reports `WouldBlock`, and work a per-poll budget left behind keeps
/// [`next_deadline`](TcpProvider::next_deadline) due now -- anything less
/// would leave bytes sitting in a kernel buffer with no further notification
/// coming.
///
/// Before it is attached, every poll treats every socket as possibly ready,
/// so a host that never attaches it (a `SwarmCore` polling on its own
/// cadence) still makes progress.
///
/// [`connect`](TcpProvider::connect) never blocks either: the connect
/// completes on a later [`poll`](TcpProvider::poll) as
/// [`TcpEvent::Connected`].
///
/// # Names
///
/// Dialing and listening take `/ip4` or `/ip6` hosts only. A `/dns*` address
/// is refused with [`TcpError::Address`], because a name lookup blocks and
/// would stall every connection on the driver thread. The std `minip2p`
/// `Endpoint` resolves names off its driver; a direct caller resolves the name
/// itself and dials the result.
///
/// A wildcard listen host binds every interface, including ones that appear
/// later. IPv6 listeners are IPv6-only, so explicit IPv4 and IPv6 wildcards can
/// share a port. The bound address is reported as the wildcard rather than
/// expanded, because which of a machine's addresses are worth handing to a
/// peer is the host's decision, not a socket's. mDNS makes that substitution
/// from its own interface list, and address selection drops what is left.
pub struct StdTcpProvider {
    /// The host's shared poll, once attached.
    registration: Option<Registration>,
    listeners: BTreeMap<usize, Listener>,
    sockets: BTreeMap<SocketHandle, Socket>,
    /// Sockets readiness marked readable, until reading reaches
    /// `WouldBlock`. Kept apart from `sockets` so a poll visits only these
    /// rather than every socket.
    readable: BTreeSet<SocketHandle>,
    /// Sockets still in [`Phase::Connecting`], which every poll re-checks.
    connecting: BTreeSet<SocketHandle>,
    /// Produced by servicing sockets, drained by the next `poll`.
    ready: VecDeque<TcpEvent>,
    /// The next socket handle. Monotonic: a handle is never reused.
    next_handle: u64,
    /// The next listener key.
    next_listener: usize,
    read_buffer: Vec<u8>,
    /// A per-poll cap was reached, so sockets still have work the caller has
    /// not seen. Readiness alone will not report it again, so the provider
    /// reports itself due until a poll takes it.
    deferred_work: bool,
    /// Which listener leads the next round of accepts.
    ///
    /// Rotating the start is what keeps a flooded listener from starving the
    /// ones after it; see [`accept_all`](Self::accept_all).
    accept_cursor: usize,
}

impl StdTcpProvider {
    /// Creates a provider. Its sockets register with a host's shared poll
    /// once it is attached as a [`PollSource`].
    pub fn new() -> Result<Self, TcpError> {
        Ok(Self {
            registration: None,
            listeners: BTreeMap::new(),
            sockets: BTreeMap::new(),
            readable: BTreeSet::new(),
            connecting: BTreeSet::new(),
            ready: VecDeque::new(),
            next_handle: 1,
            next_listener: 0,
            read_buffer: vec![0; READ_CHUNK],
            deferred_work: false,
            accept_cursor: 0,
        })
    }

    fn allocate_handle(&mut self) -> SocketHandle {
        let handle = SocketHandle::new(self.next_handle);
        self.next_handle += 1;
        handle
    }

    /// Registers `source` if attached; `None` until then.
    fn register(
        &mut self,
        source: &mut impl mio::event::Source,
        slot: Slot,
        interest: Interest,
    ) -> Result<Option<Token>, TcpError> {
        match self.registration.as_mut() {
            Some(registration) => registration.register(source, slot, interest).map(Some),
            None => Ok(None),
        }
    }

    /// Turns `WRITABLE` interest on or off for one socket.
    ///
    /// A failure here leaves the socket registered as it was; the next write
    /// still discovers whether the socket takes bytes, so this degrades
    /// latency rather than correctness.
    fn watch_writable(&mut self, handle: SocketHandle, wanted: bool) {
        let Some(socket) = self.sockets.get_mut(&handle) else {
            return;
        };
        if socket.watching_writable == wanted {
            return;
        }
        let interest = if wanted {
            Interest::READABLE | Interest::WRITABLE
        } else {
            Interest::READABLE
        };
        // Unattached, the flag alone is kept for when it is registered.
        let (Some(registration), Some(token)) = (self.registration.as_ref(), socket.token) else {
            socket.watching_writable = wanted;
            return;
        };
        if registration
            .registry
            .reregister(&mut socket.stream, token, interest)
            .is_ok()
        {
            socket.watching_writable = wanted;
        }
    }

    /// Accepts what each listener has queued, up to this poll's budget.
    ///
    /// Listeners are visited round-robin from a cursor that advances every
    /// poll. Walking them in `BTreeMap` order instead would let a sustained
    /// flood on the lowest-token listener spend the whole budget every time
    /// and starve every later bind indefinitely; rotating the start costs one
    /// index and guarantees each listener leads a poll in turn.
    fn accept_all(&mut self) {
        let tokens: Vec<usize> = self.listeners.keys().copied().collect();
        if tokens.is_empty() {
            return;
        }
        let start = self.accept_cursor % tokens.len();
        // Whoever led this poll goes last in the next one.
        self.accept_cursor = start.wrapping_add(1);

        let mut budget = MAX_ACCEPTS_PER_POLL;
        for &token in tokens.iter().cycle().skip(start).take(tokens.len()) {
            loop {
                if budget == 0 {
                    // A flood must not hold the poll open; the backlog keeps
                    // until the next one, which a wait is told not to sleep
                    // through. Checked before `accept`, because a connection
                    // taken off the kernel's queue and then dropped is that
                    // peer's connection killed rather than deferred.
                    self.deferred_work = true;
                    return;
                }
                let Some(listener) = self.listeners.get(&token) else {
                    break;
                };
                match listener.listener.accept() {
                    Ok((stream, peer)) => {
                        budget -= 1;
                        if let Err(error) = self.adopt(stream, socket_addr_to_multiaddr(peer)) {
                            // Nothing names this stream yet, so there is no
                            // handle to report the failure against; dropping it
                            // is the whole of the cleanup.
                            let _ = error;
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == ErrorKind::Interrupted => {
                        // Charged even though nothing was accepted, so a storm
                        // of signals cannot hold the poll open either.
                        budget -= 1;
                        continue;
                    }
                    // One bad accept must not take the listener down; the next
                    // poll tries again.
                    Err(_) => break,
                }
            }
        }
    }

    /// Registers an accepted stream and announces it.
    fn adopt(
        &mut self,
        mut stream: mio::net::TcpStream,
        remote: Multiaddr,
    ) -> Result<(), TcpError> {
        disable_nagle(&stream)?;
        let handle = self.allocate_handle();
        let token = self.register(&mut stream, Slot::Socket(handle), Interest::READABLE)?;
        // Data may have arrived with the connection, before any edge this
        // registration could report.
        self.readable.insert(handle);
        self.sockets.insert(
            handle,
            Socket {
                stream,
                token,
                remote: remote.clone(),
                phase: Phase::Open,
                // Optimistic: the first write that is refused is what turns the
                // interest on, and until then there is nothing to wait for.
                writable: true,
                watching_writable: false,
                read_closed: false,
                write_closed: false,
            },
        );
        self.ready.push_back(TcpEvent::Accepted {
            socket: handle,
            remote,
        });
        Ok(())
    }

    /// Finishes a pending connect, or reports why it failed.
    fn settle_connect(&mut self, handle: SocketHandle) {
        let Some(socket) = self.sockets.get_mut(&handle) else {
            return;
        };
        if !matches!(socket.phase, Phase::Connecting) {
            return;
        }

        // A refused or unreachable connect surfaces here rather than from
        // `connect` itself, which only starts the attempt.
        match socket.stream.take_error() {
            Ok(Some(error)) => {
                self.close(handle, Some(error.to_string()));
                return;
            }
            Err(error) => {
                self.close(handle, Some(error.to_string()));
                return;
            }
            Ok(None) => {}
        }
        // Not connected yet. Writability can be reported before the handshake
        // finishes, and `peer_addr` is what tells the two apart. Every poll
        // retries rather than waiting for another edge: under edge-triggered
        // readiness the edge that arrived early may be the only one, and a dial
        // that parked on it would never complete.
        let Ok(peer) = socket.stream.peer_addr() else {
            return;
        };

        socket.phase = Phase::Open;
        // A finished connect is a writable socket, whether or not an event
        // said so (an unattached provider gets none).
        socket.writable = true;
        self.connecting.remove(&handle);
        socket.remote = socket_addr_to_multiaddr(peer);
        let remote = socket.remote.clone();
        // Connect completion was the only reason to watch writability.
        self.watch_writable(handle, false);
        self.ready.push_back(TcpEvent::Connected {
            socket: handle,
            remote,
        });
    }

    /// Reads until the socket has nothing more to give, or the budget runs out.
    fn read_all(&mut self, handle: SocketHandle) {
        let mut budget = MAX_READS_PER_POLL;
        loop {
            let Some(socket) = self.sockets.get_mut(&handle) else {
                return;
            };
            if !self.readable.contains(&handle) || !matches!(socket.phase, Phase::Open) {
                // A connecting socket keeps its mark for once it is open.
                return;
            }
            if socket.read_closed {
                // Nothing more will be read, whatever readiness says.
                self.readable.remove(&handle);
                return;
            }
            if budget == 0 {
                // Leave `readable` set so the next poll picks up where this one
                // stopped. Readiness will not announce it again -- nothing
                // changed at the socket -- so a wait is told not to park.
                self.deferred_work = true;
                return;
            }
            budget -= 1;
            match socket.stream.read(&mut self.read_buffer) {
                Ok(0) => {
                    socket.read_closed = true;
                    self.readable.remove(&handle);
                    self.ready
                        .push_back(TcpEvent::RemoteWriteClosed { socket: handle });
                    self.retire_if_finished(handle);
                    return;
                }
                Ok(read) => {
                    let Some(data) = self.read_buffer.get(..read).map(ToOwned::to_owned) else {
                        self.readable.remove(&handle);
                        return;
                    };
                    self.ready.push_back(TcpEvent::Received {
                        socket: handle,
                        data,
                    });
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    self.readable.remove(&handle);
                    return;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => {
                    let reason = error.to_string();
                    self.close(handle, Some(reason));
                    return;
                }
            }
        }
    }

    /// Retires a socket once neither direction can carry anything more.
    ///
    /// Without this a gracefully closed connection -- the local write side shut
    /// down, the remote's FIN read -- would sit in the map with its descriptor
    /// held, because the caller has been told the stream ended and will not ask
    /// again.
    fn retire_if_finished(&mut self, handle: SocketHandle) {
        let finished = self
            .sockets
            .get(&handle)
            .is_some_and(|socket| socket.read_closed && socket.write_closed);
        if finished {
            self.close(handle, None);
        }
    }

    /// Retires a socket and reports it.
    ///
    /// Events already queued for it stay: those are bytes the socket really
    /// delivered, and they are ordered before the `Closed` that follows. A
    /// stream that fails after handing over data still handed over that data.
    fn close(&mut self, handle: SocketHandle, reason: Option<String>) {
        let Some(mut socket) = self.sockets.remove(&handle) else {
            return;
        };
        self.readable.remove(&handle);
        self.connecting.remove(&handle);
        if let (Some(registration), Some(token)) = (self.registration.as_mut(), socket.token) {
            registration.deregister(&mut socket.stream, token);
        }
        self.ready.push_back(TcpEvent::Closed {
            socket: handle,
            reason,
        });
    }

    fn discard_queued(&mut self, handle: SocketHandle) {
        self.ready.retain(|event| event_socket(event) != handle);
    }
}

fn event_socket(event: &TcpEvent) -> SocketHandle {
    match event {
        TcpEvent::Accepted { socket, .. }
        | TcpEvent::Connected { socket, .. }
        | TcpEvent::Received { socket, .. }
        | TcpEvent::RemoteWriteClosed { socket }
        | TcpEvent::Writable { socket }
        | TcpEvent::Closed { socket, .. } => *socket,
    }
}

impl TcpProvider for StdTcpProvider {
    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TcpError> {
        let requested = listen_addr(addr)?;
        let mut listener =
            bind_listener(requested).map_err(|error| io_error("binding a listener", &error))?;
        let bound = listener
            .local_addr()
            .map_err(|error| io_error("reading the bound address", &error))?;
        let key = self.next_listener;
        let token = self.register(&mut listener, Slot::Listener, Interest::READABLE)?;
        self.next_listener += 1;

        let bound = socket_addr_to_multiaddr(bound);
        self.listeners.insert(
            key,
            Listener {
                listener,
                token,
                bound: bound.clone(),
            },
        );
        Ok(bound)
    }

    fn connect(&mut self, addr: &Multiaddr) -> Result<SocketHandle, TcpError> {
        let target = dial_addr(addr)?;
        let mut stream = mio::net::TcpStream::connect(target)
            .map_err(|error| io_error("starting a connect", &error))?;
        disable_nagle(&stream)?;
        let handle = self.allocate_handle();
        let token = self.register(
            &mut stream,
            Slot::Socket(handle),
            Interest::READABLE | Interest::WRITABLE,
        )?;

        self.connecting.insert(handle);
        self.sockets.insert(
            handle,
            Socket {
                stream,
                token,
                remote: socket_addr_to_multiaddr(target),
                phase: Phase::Connecting,
                writable: false,
                // Writability is how a connect reports that it finished, so
                // this one starts watching and stops once it has.
                watching_writable: true,
                read_closed: false,
                write_closed: false,
            },
        );
        Ok(handle)
    }

    fn send(&mut self, socket: SocketHandle, data: &[u8]) -> Result<usize, TcpError> {
        let result = {
            let entry = self
                .sockets
                .get_mut(&socket)
                .ok_or(TcpError::UnknownSocket { socket })?;
            if matches!(entry.phase, Phase::Connecting) {
                // A connect can complete in the kernel before its readiness
                // event is polled. Keep the provider's public Connected gate:
                // no bytes may leave until settle_connect changes the phase
                // and queues that event.
                return Ok(0);
            }
            loop {
                match entry.stream.write(data) {
                    Ok(written) => {
                        // A partial write means the send buffer is full; only a
                        // readiness event says otherwise.
                        if written < data.len() {
                            entry.writable = false;
                        }
                        break Ok(written);
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        entry.writable = false;
                        break Ok(0);
                    }
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    Err(error) => break Err(io_error("writing to a stream", &error)),
                }
            }
        };
        // Now there is something to wait for, so ask to hear about it.
        if self
            .sockets
            .get(&socket)
            .is_some_and(|entry| !entry.writable)
        {
            self.watch_writable(socket, true);
        }
        result
    }

    fn close_write(&mut self, socket: SocketHandle) -> Result<(), TcpError> {
        let entry = self
            .sockets
            .get_mut(&socket)
            .ok_or(TcpError::UnknownSocket { socket })?;
        entry.write_closed = true;
        let result = entry
            .stream
            .shutdown(Shutdown::Write)
            .map_err(|error| io_error("half-closing a stream", &error));
        // The remote may already have finished, in which case this was the last
        // thing keeping the socket alive.
        self.retire_if_finished(socket);
        result
    }

    fn abort(&mut self, socket: SocketHandle) {
        self.readable.remove(&socket);
        self.connecting.remove(&socket);
        if let Some(mut entry) = self.sockets.remove(&socket) {
            if let (Some(registration), Some(token)) = (self.registration.as_mut(), entry.token) {
                registration.deregister(&mut entry.stream, token);
            }
            // Dropping the stream closes it. The kernel still flushes whatever
            // it already accepted, so this is a close rather than a reset --
            // the peer sees the stream end either way, which is what the
            // contract promises.
        }
        // The caller asked for this, so it is owed no further events.
        self.discard_queued(socket);
    }

    fn poll(&mut self, _now: Now) -> Result<Vec<TcpEvent>, TcpError> {
        self.deferred_work = false;
        if self.registration.is_none() {
            // Nothing reports readiness yet, so every open socket may have
            // something; reading one that does not costs a `WouldBlock`.
            self.readable.extend(self.sockets.keys().copied());
        }
        self.accept_all();

        // Only sockets with something to do. Connects settle first, so a
        // stream's `Connected` still precedes the bytes read behind it.
        for handle in self.connecting.iter().copied().collect::<Vec<_>>() {
            self.settle_connect(handle);
        }
        for handle in self.readable.iter().copied().collect::<Vec<_>>() {
            self.read_all(handle);
        }
        Ok(self.ready.drain(..).collect())
    }

    /// Due now while anything learned from readiness is still unserviced:
    /// events not yet handed over, a socket marked readable, or work a
    /// budget deferred. No edge will announce those again.
    fn next_deadline(&self) -> Option<Deadline> {
        (!self.ready.is_empty() || self.deferred_work || !self.readable.is_empty())
            .then_some(Deadline::IMMEDIATE)
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        self.listeners
            .values()
            .map(|listener| listener.bound.clone())
            .collect()
    }
}

impl PollSource for StdTcpProvider {
    /// Registers every listener and socket opened so far; later ones register
    /// as they open. Registering reports a socket's current readiness, so
    /// bytes that arrived before attach still raise an event.
    fn attach(
        &mut self,
        registry: Registry,
        tokens: TokenSpace,
        _waker: Arc<Waker>,
    ) -> std::io::Result<()> {
        let mut registration = Registration {
            registry,
            tokens,
            slots: Vec::new(),
            free: Vec::new(),
        };
        let to_io = |error: TcpError| std::io::Error::other(error.to_string());
        for listener in self.listeners.values_mut() {
            listener.token = Some(
                registration
                    .register(&mut listener.listener, Slot::Listener, Interest::READABLE)
                    .map_err(to_io)?,
            );
        }
        for (&handle, socket) in &mut self.sockets {
            let interest = if socket.watching_writable {
                Interest::READABLE | Interest::WRITABLE
            } else {
                Interest::READABLE
            };
            socket.token = Some(
                registration
                    .register(&mut socket.stream, Slot::Socket(handle), interest)
                    .map_err(to_io)?,
            );
        }
        self.registration = Some(registration);
        Ok(())
    }

    fn dispatch(&mut self, event: &Event) {
        let Some(slot) = self
            .registration
            .as_ref()
            .and_then(|registration| registration.slot(event.token()))
        else {
            // A token freed since: a stale event, and nothing to do.
            return;
        };
        // Listeners need no flag: `accept` runs to `WouldBlock` on every poll
        // regardless.
        let Slot::Socket(handle) = slot else {
            return;
        };
        let Some(socket) = self.sockets.get_mut(&handle) else {
            return;
        };
        if event.is_readable() || event.is_read_closed() || event.is_error() {
            self.readable.insert(handle);
        }
        if event.is_writable() {
            socket.writable = true;
            if matches!(socket.phase, Phase::Open) && socket.watching_writable {
                // The socket has room again, so stop watching for it.
                self.watch_writable(handle, false);
                self.ready.push_back(TcpEvent::Writable { socket: handle });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;
    use minip2p_transport::SharedPoll;
    use std::thread;
    use std::time::Instant;

    fn loopback_listener() -> (StdTcpProvider, Multiaddr) {
        let mut server = StdTcpProvider::new().expect("server");
        let bound = server
            .listen(&"/ip4/127.0.0.1/tcp/0".parse().expect("address"))
            .expect("listen");
        (server, bound)
    }

    fn token_of(provider: &StdTcpProvider, handle: SocketHandle) -> Option<Token> {
        provider.sockets.get(&handle).and_then(|socket| socket.token)
    }

    #[test]
    fn a_recycled_token_never_carries_the_old_handles_lifecycle() {
        let (_server, bound) = loopback_listener();
        let mut client = StdTcpProvider::new().expect("client");
        let mut poll = SharedPoll::new().expect("poll");
        poll.attach(&mut client).expect("attach");

        let old = client.connect(&bound).expect("first connect");
        let old_token = token_of(&client, old).expect("registered");
        client.abort(old);
        let new = client.connect(&bound).expect("second connect");
        assert_ne!(old, new, "handles are never reused");
        assert_eq!(
            token_of(&client, new),
            Some(old_token),
            "the freed token is reused"
        );

        // Retiring the old handle again must not touch the socket that now
        // holds its token.
        client.abort(old);
        assert!(client.sockets.contains_key(&new));
        let registration = client.registration.as_ref().expect("attached");
        assert!(matches!(
            registration.slot(old_token),
            Some(Slot::Socket(holder)) if holder == new
        ));

        // A stale event for the old socket only marks the new one possibly
        // ready, which a poll answers with nothing at all.
        client.readable.insert(new);
        let events = client.poll(Now::from_millis(0)).expect("poll");
        assert!(
            events
                .iter()
                .all(|event| !matches!(event, TcpEvent::Closed { .. } | TcpEvent::Received { .. })),
            "a spurious wake is harmless: {events:?}"
        );
    }

    #[test]
    fn an_attached_provider_is_woken_by_input_and_reads_it_all() {
        let (mut server, bound) = loopback_listener();
        let mut poll = SharedPoll::new().expect("poll");
        poll.attach(&mut server).expect("attach");
        let mut peer = std::net::TcpStream::connect(
            bound.to_string().replace("/ip4/", "").replace("/tcp/", ":"),
        )
        .expect("peer connects");

        // The accept is announced by readiness, then the bytes behind it.
        let started = Instant::now();
        let mut accepted = None;
        while accepted.is_none() {
            assert!(started.elapsed() < Duration::from_secs(5), "never accepted");
            poll.harvest(&mut server, Duration::from_secs(5))
                .expect("harvest");
            accepted = server
                .poll(Now::from_millis(0))
                .expect("poll")
                .into_iter()
                .find_map(|event| match event {
                    TcpEvent::Accepted { socket, .. } => Some(socket),
                    _ => None,
                });
        }
        std::io::Write::write_all(&mut peer, b"edge").expect("write");
        let mut received = Vec::new();
        while received.len() < 4 {
            assert!(started.elapsed() < Duration::from_secs(5), "never read");
            poll.harvest(&mut server, Duration::from_secs(5))
                .expect("harvest");
            assert!(
                TcpProvider::next_deadline(&server).is_some(),
                "dispatched readiness is due until polled"
            );
            for event in server.poll(Now::from_millis(0)).expect("poll") {
                if let TcpEvent::Received { data, .. } = event {
                    received.extend(data);
                }
            }
        }
        assert_eq!(received, b"edge");
        assert_eq!(
            TcpProvider::next_deadline(&server),
            None,
            "read to WouldBlock, nothing left owed"
        );
    }

    #[test]
    fn accepted_and_dialed_streams_disable_nagle() {
        let mut server = StdTcpProvider::new().expect("server");
        let mut client = StdTcpProvider::new().expect("client");
        let bound = server
            .listen(&"/ip4/127.0.0.1/tcp/0".parse().expect("address"))
            .expect("listen");

        let dialed = client.connect(&bound).expect("connect");
        assert!(
            client.sockets[&dialed]
                .stream
                .nodelay()
                .expect("dialed stream option")
        );

        let started = Instant::now();
        let accepted = loop {
            if let Some(socket) = server
                .poll(Now::from_millis(0))
                .expect("poll server")
                .into_iter()
                .find_map(|event| match event {
                    TcpEvent::Accepted { socket, .. } => Some(socket),
                    _ => None,
                })
            {
                break socket;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "server did not accept the connection"
            );
            thread::sleep(Duration::from_millis(1));
        };
        assert!(
            server.sockets[&accepted]
                .stream
                .nodelay()
                .expect("accepted stream option")
        );
    }
}
