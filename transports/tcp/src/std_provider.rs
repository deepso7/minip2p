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
use crate::provider::{SocketHandle, TcpError, TcpEvent, TcpProvider};

/// Reserved for the interrupt waker, so no registration may use it.
const WAKER_TOKEN: Token = Token(0);

/// Read size per syscall. Large enough that a busy stream is not dominated by
/// syscall overhead, small enough not to hold a big buffer per provider.
const READ_CHUNK: usize = 16 * 1024;

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

/// Splits a `/tcp` multiaddr into its host and port components.
fn host_and_port(addr: &Multiaddr, context: &'static str) -> Result<(Protocol, u16), TcpError> {
    let protocols = addr.protocols();
    let host = protocols
        .first()
        .filter(|protocol| protocol.is_host())
        .ok_or_else(|| TcpError::Address {
            context,
            reason: format!("{addr} has no host component"),
        })?;
    let Some(Protocol::Tcp(port)) = protocols.get(1) else {
        return Err(TcpError::Address {
            context,
            reason: format!("{addr} has no /tcp port"),
        });
    };
    Ok((host.clone(), *port))
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
    let resolve = |name: &str, want: fn(&SocketAddr) -> bool| -> Result<SocketAddr, TcpError> {
        let query = format!("{name}:{port}");
        query
            .to_socket_addrs()
            .map_err(|error| TcpError::Address {
                context: "tcp dial",
                reason: format!("resolving {query} failed: {error}"),
            })?
            .find(want)
            .ok_or_else(|| TcpError::Address {
                context: "tcp dial",
                reason: format!("{query} resolved to no usable address"),
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
}

/// A [`TcpProvider`] over operating-system sockets, driven by `mio`.
///
/// Non-blocking throughout: [`poll`](TcpProvider::poll) services whatever is
/// ready and returns, and [`BlockingTcpProvider::wait_for_input`] is the only
/// call that ever blocks. Readiness is edge-triggered, so every socket is read
/// and written until it reports `WouldBlock` -- anything less would leave bytes
/// sitting in a kernel buffer with no further notification coming.
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
    /// Returns whether the waker fired and whether anything else did, which is
    /// all [`BlockingTcpProvider::wait_for_input`] needs to classify the wait.
    fn absorb_readiness(&mut self, timeout: Duration) -> Result<(bool, bool), TcpError> {
        self.events.clear();
        match self.poll.poll(&mut self.events, Some(timeout)) {
            Ok(()) => {}
            // A signal cut the wait short; the caller polls regardless.
            Err(error) if error.kind() == ErrorKind::Interrupted => return Ok((false, true)),
            Err(error) => return Err(io_error("waiting for readiness", &error)),
        }

        // Collect first: the flags live behind `&mut self`, which `events`
        // borrows for the duration of the iteration.
        let observed: Vec<(Token, bool, bool)> = self
            .events
            .iter()
            .map(|event| (event.token(), event.is_readable(), event.is_writable()))
            .collect();

        let mut woken = false;
        let mut ready = false;
        let mut drained = Vec::new();
        for (token, readable, writable) in observed {
            if token == WAKER_TOKEN {
                woken = true;
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
        Ok((woken, ready))
    }

    /// Accepts everything each listener has queued.
    fn accept_all(&mut self) {
        let tokens: Vec<usize> = self.listeners.keys().copied().collect();
        for token in tokens {
            while let Some(accepted) = self
                .listeners
                .get(&token)
                .map(|listener| listener.listener.accept())
            {
                match accepted {
                    Ok((stream, peer)) => {
                        if let Err(error) = self.adopt(stream, socket_addr_to_multiaddr(peer)) {
                            // Nothing names this stream yet, so there is no
                            // handle to report the failure against; dropping it
                            // is the whole of the cleanup.
                            let _ = error;
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
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
        if !matches!(socket.phase, Phase::Connecting) || !socket.writable {
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
        // Not connected yet: on some platforms writability is reported before
        // the handshake finishes, and `peer_addr` is what tells them apart.
        let Ok(peer) = socket.stream.peer_addr() else {
            socket.writable = false;
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

    /// Reads until the socket has nothing more to give.
    fn read_all(&mut self, handle: SocketHandle) {
        loop {
            let Some(socket) = self.sockets.get_mut(&handle) else {
                return;
            };
            if !socket.readable || socket.read_closed || !matches!(socket.phase, Phase::Open) {
                return;
            }
            match socket.stream.read(&mut self.read_buffer) {
                Ok(0) => {
                    socket.read_closed = true;
                    socket.readable = false;
                    self.ready
                        .push_back(TcpEvent::RemoteWriteClosed { socket: handle });
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

    /// Retires a socket and reports it, discarding anything else queued for it.
    fn close(&mut self, handle: SocketHandle, reason: Option<String>) {
        let Some(mut socket) = self.sockets.remove(&handle) else {
            return;
        };
        let _ = self.poll.registry().deregister(&mut socket.stream);
        self.discard_queued(handle);
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
        entry
            .stream
            .shutdown(Shutdown::Write)
            .map_err(|error| io_error("half-closing a stream", &error))
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
        // Readiness is folded into the sockets rather than discarded, so the
        // `poll` that follows still sees what this wait learned.
        match self.absorb_readiness(timeout) {
            // A failed wait is not a reason to sleep; let the caller poll.
            Err(_) => WaitOutcome::Ready,
            Ok((true, _)) => WaitOutcome::Interrupted,
            Ok((false, true)) => WaitOutcome::Ready,
            Ok((false, false)) => WaitOutcome::TimedOut,
        }
    }

    fn wait_handle(&self) -> WaitHandle {
        let waker = Arc::clone(&self.waker);
        WaitHandle::new(move || {
            let _ = waker.wake();
        })
    }
}
