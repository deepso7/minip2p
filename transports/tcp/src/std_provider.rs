use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, ToSocketAddrs};

use minip2p_core::{Multiaddr, Protocol};
use minip2p_platform::Now;
use minip2p_transport::{WaitHandle, WaitOutcome};
use mio::{Events, Interest, Poll, Token, Waker};

use crate::blocking::BlockingTcpProvider;
use crate::provider::{SocketHandle, TcpError, TcpEvent, TcpProvider, host_and_port};

/// Reserved for the interrupt waker, so no registration may use it.
const WAKER_TOKEN: Token = Token(0);

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

/// Resolves a dial address, performing a blocking name lookup for `/dns*`.
///
/// Resolution is I/O, which is why it lives here rather than in the portable
/// transport. It blocks, matching the QUIC adapter; a host that cannot afford
/// that should resolve names itself and dial the resulting `/ip4` or `/ip6`
/// address.
fn dial_addr(addr: &Multiaddr) -> Result<SocketAddr, TcpError> {
    let (host, port) = host_and_port(addr, "tcp dial")?;
    // `(name, port)` rather than a reassembled `"name:port"`: the string form
    // has to be parsed back apart, and a name carrying a colon would be split
    // in the wrong place.
    let resolve = |name: &str, want: fn(&SocketAddr) -> bool| -> Result<SocketAddr, TcpError> {
        (name, port)
            .to_socket_addrs()
            .map_err(|error| TcpError::Address {
                context: "tcp dial",
                reason: format!("resolving {name} failed: {error}"),
            })?
            .find(want)
            .ok_or_else(|| TcpError::Address {
                context: "tcp dial",
                reason: format!("{name} resolved to no usable address"),
            })
    };
    match host {
        Protocol::Ip4(octets) => Ok(SocketAddr::new(IpAddr::from(octets), port)),
        Protocol::Ip6(octets) => Ok(SocketAddr::new(IpAddr::from(octets), port)),
        Protocol::Dns(name) => resolve(&name, |_| true),
        Protocol::Dns4(name) => resolve(&name, |addr| addr.is_ipv4()),
        Protocol::Dns6(name) => resolve(&name, |addr| addr.is_ipv6()),
        _ => Err(TcpError::Address {
            context: "tcp dial",
            reason: format!("{addr} has no host component"),
        }),
    }
}

struct Listener {
    listener: mio::net::TcpListener,
    bound: Multiaddr,
}

enum Phase {
    /// `connect` has been issued; writability decides whether it succeeded.
    Connecting,
    /// The stream is up and carrying bytes.
    Open,
}

struct Socket {
    stream: mio::net::TcpStream,
    token: Token,
    remote: Multiaddr,
    phase: Phase,
    /// Set by a readiness event, cleared by reading to `WouldBlock`.
    readable: bool,
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
/// Non-blocking on the drive path: [`poll`](TcpProvider::poll),
/// [`send`](TcpProvider::send), [`close_write`](TcpProvider::close_write), and
/// [`abort`](TcpProvider::abort) service whatever is ready and return, so
/// [`BlockingTcpProvider::wait_for_input`] is the only call a driven loop makes
/// that ever blocks. Readiness is edge-triggered, so every socket is read and
/// written until it reports `WouldBlock` -- anything less would leave bytes
/// sitting in a kernel buffer with no further notification coming.
///
/// The exception is [`connect`](TcpProvider::connect) to a `/dns*` address,
/// which blocks for the name lookup before the connect starts; see
/// [Names](#names). Dialing an `/ip4` or `/ip6` address never blocks, and the
/// connect itself is asynchronous either way -- it completes on a later
/// [`poll`](TcpProvider::poll) as [`TcpEvent::Connected`].
///
/// # Names
///
/// `/dns`, `/dns4`, and `/dns6` dial addresses are resolved here, with a
/// blocking lookup. Listening requires a concrete `/ip4` or `/ip6` host.
pub struct StdTcpProvider {
    poll: Poll,
    events: Events,
    waker: Arc<Waker>,
    listeners: BTreeMap<usize, Listener>,
    sockets: BTreeMap<SocketHandle, Socket>,
    /// Produced by servicing sockets, drained by the next `poll`.
    ready: VecDeque<TcpEvent>,
    /// Shared between listener tokens and socket handles, so one registration
    /// can never be mistaken for another.
    next_id: u64,
    read_buffer: Vec<u8>,
    /// A wake that arrived while nobody was waiting.
    ///
    /// `poll` absorbs readiness too, so an interrupt can land there instead of
    /// in a wait. Remembering it is what stops a handle losing the wakeup to
    /// that race, which is what [`WaitHandle`] promises.
    pending_interrupt: bool,
    /// A per-poll cap was reached, so sockets still have work the caller has
    /// not seen. Readiness alone will not report it again, so a wait must not
    /// park on it.
    deferred_work: bool,
    /// Which listener leads the next round of accepts.
    ///
    /// Rotating the start is what keeps a flooded listener from starving the
    /// ones after it; see [`accept_all`](Self::accept_all).
    accept_cursor: usize,
}

impl StdTcpProvider {
    /// Creates a provider with its own readiness registry.
    pub fn new() -> Result<Self, TcpError> {
        let poll = Poll::new().map_err(|error| io_error("creating a poll registry", &error))?;
        let waker = Arc::new(
            Waker::new(poll.registry(), WAKER_TOKEN)
                .map_err(|error| io_error("creating a waker", &error))?,
        );
        Ok(Self {
            poll,
            events: Events::with_capacity(64),
            waker,
            listeners: BTreeMap::new(),
            sockets: BTreeMap::new(),
            ready: VecDeque::new(),
            next_id: 1,
            read_buffer: vec![0; READ_CHUNK],
            pending_interrupt: false,
            deferred_work: false,
            accept_cursor: 0,
        })
    }

    fn allocate_token(&mut self) -> Result<Token, TcpError> {
        let id = self.next_id;
        let token = usize::try_from(id)
            .map(Token)
            .map_err(|_| TcpError::Exhausted {
                resource: "readiness tokens",
            })?;
        self.next_id += 1;
        Ok(token)
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
        if self
            .poll
            .registry()
            .reregister(&mut socket.stream, socket.token, interest)
            .is_ok()
        {
            socket.watching_writable = wanted;
        }
    }

    /// Folds a `mio` poll into the per-socket readiness flags.
    ///
    /// Returns whether anything other than the waker fired. A wake is recorded
    /// in `pending_interrupt` instead of returned, because it has to survive
    /// being absorbed by a `poll` that nobody was waiting on.
    fn absorb_readiness(&mut self, timeout: Duration) -> Result<bool, TcpError> {
        self.events.clear();
        match self.poll.poll(&mut self.events, Some(timeout)) {
            Ok(()) => {}
            // A signal cut the wait short; the caller polls regardless.
            Err(error) if error.kind() == ErrorKind::Interrupted => return Ok(true),
            Err(error) => return Err(io_error("waiting for readiness", &error)),
        }

        // Collect first: the flags live behind `&mut self`, which `events`
        // borrows for the duration of the iteration.
        let observed: Vec<(Token, bool, bool)> = self
            .events
            .iter()
            .map(|event| (event.token(), event.is_readable(), event.is_writable()))
            .collect();

        let mut ready = false;
        let mut drained = Vec::new();
        for (token, readable, writable) in observed {
            if token == WAKER_TOKEN {
                self.pending_interrupt = true;
                continue;
            }
            ready = true;
            let Some((handle, socket)) = self
                .sockets
                .iter_mut()
                .find(|(_, socket)| socket.token == token)
            else {
                // Listeners need no flag: `accept` runs to `WouldBlock` on
                // every poll regardless.
                continue;
            };
            socket.readable |= readable;
            if writable {
                socket.writable = true;
                if matches!(socket.phase, Phase::Open) {
                    drained.push(*handle);
                }
            }
        }

        for handle in drained {
            // The socket has room again, so stop watching for it -- otherwise
            // the next wait returns instantly on the same standing readiness.
            self.watch_writable(handle, false);
            self.ready.push_back(TcpEvent::Writable { socket: handle });
        }
        Ok(ready)
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
        for offset in 0..tokens.len() {
            let token = tokens[(start + offset) % tokens.len()];
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
        let token = self.allocate_token()?;
        self.poll
            .registry()
            .register(&mut stream, token, Interest::READABLE)
            .map_err(|error| io_error("registering an accepted stream", &error))?;
        let handle = SocketHandle::new(token.0 as u64);
        self.sockets.insert(
            handle,
            Socket {
                stream,
                token,
                remote: remote.clone(),
                phase: Phase::Open,
                readable: true,
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
            if !socket.readable || socket.read_closed || !matches!(socket.phase, Phase::Open) {
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
                    socket.readable = false;
                    self.ready
                        .push_back(TcpEvent::RemoteWriteClosed { socket: handle });
                    self.retire_if_finished(handle);
                    return;
                }
                Ok(read) => {
                    let data = self.read_buffer[..read].to_vec();
                    self.ready.push_back(TcpEvent::Received {
                        socket: handle,
                        data,
                    });
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    socket.readable = false;
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
        let _ = self.poll.registry().deregister(&mut socket.stream);
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
        let mut listener = mio::net::TcpListener::bind(requested)
            .map_err(|error| io_error("binding a listener", &error))?;
        let bound = listener
            .local_addr()
            .map_err(|error| io_error("reading the bound address", &error))?;
        let token = self.allocate_token()?;
        self.poll
            .registry()
            .register(&mut listener, token, Interest::READABLE)
            .map_err(|error| io_error("registering a listener", &error))?;

        let bound = socket_addr_to_multiaddr(bound);
        self.listeners.insert(
            token.0,
            Listener {
                listener,
                bound: bound.clone(),
            },
        );
        Ok(bound)
    }

    fn connect(&mut self, addr: &Multiaddr) -> Result<SocketHandle, TcpError> {
        let target = dial_addr(addr)?;
        let mut stream = mio::net::TcpStream::connect(target)
            .map_err(|error| io_error("starting a connect", &error))?;
        let token = self.allocate_token()?;
        self.poll
            .registry()
            .register(&mut stream, token, Interest::READABLE | Interest::WRITABLE)
            .map_err(|error| io_error("registering a stream", &error))?;

        let handle = SocketHandle::new(token.0 as u64);
        self.sockets.insert(
            handle,
            Socket {
                stream,
                token,
                remote: socket_addr_to_multiaddr(target),
                phase: Phase::Connecting,
                readable: false,
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
        if let Some(mut entry) = self.sockets.remove(&socket) {
            let _ = self.poll.registry().deregister(&mut entry.stream);
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
        self.absorb_readiness(Duration::ZERO)?;
        self.accept_all();

        for handle in self.sockets.keys().copied().collect::<Vec<_>>() {
            self.settle_connect(handle);
            self.read_all(handle);
        }
        Ok(self.ready.drain(..).collect())
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        self.listeners
            .values()
            .map(|listener| listener.bound.clone())
            .collect()
    }
}

impl BlockingTcpProvider for StdTcpProvider {
    fn wait_for_input(&mut self, timeout: Duration) -> WaitOutcome {
        if core::mem::take(&mut self.pending_interrupt) {
            // A wake that landed while nobody was waiting, possibly absorbed by
            // a `poll`. Honouring it here is what keeps a handle from losing
            // the race against the waiter.
            return WaitOutcome::Interrupted;
        }
        if self.deferred_work || self.sockets.values().any(|socket| socket.readable) {
            // Sockets still hold bytes this provider has not handed over.
            // Readiness will not mention them again, so parking would strand
            // them.
            return WaitOutcome::Ready;
        }

        // Readiness is folded into the sockets rather than discarded, so the
        // `poll` that follows still sees what this wait learned.
        let ready = match self.absorb_readiness(timeout) {
            // A failed wait is not a reason to sleep; let the caller poll.
            Err(_) => return WaitOutcome::Ready,
            Ok(ready) => ready,
        };
        if core::mem::take(&mut self.pending_interrupt) {
            WaitOutcome::Interrupted
        } else if ready {
            WaitOutcome::Ready
        } else {
            WaitOutcome::TimedOut
        }
    }

    fn wait_handle(&self) -> WaitHandle {
        let waker = Arc::clone(&self.waker);
        WaitHandle::new(move || {
            let _ = waker.wake();
        })
    }
}
