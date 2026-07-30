use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::Multiaddr;
use minip2p_platform::{Deadline, Now};
use thiserror::Error;

use core::fmt;

/// One byte stream owned by a [`TcpProvider`].
///
/// Providers mint these; the transport only ever hands them back. A handle
/// names a stream for as long as the provider reports it, and is never reused
/// for a different stream afterwards.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SocketHandle(u64);

impl SocketHandle {
    /// Creates a handle from a raw value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SocketHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "socket#{}", self.0)
    }
}

/// Why a provider operation failed.
///
/// Deliberately narrower than
/// [`TransportError`](minip2p_transport::TransportError): a provider knows
/// about sockets and addresses, not about connection or stream identifiers.
/// [`TcpTransport`](crate::TcpTransport) is what turns these into the
/// transport contract's errors.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TcpError {
    /// The address cannot be used for this operation.
    #[error("invalid address for {context}: {reason}")]
    Address {
        /// What was being attempted, for the message.
        context: &'static str,
        /// Why the address was rejected.
        reason: String,
    },
    /// The underlying I/O failed.
    #[error("{operation} failed: {reason}")]
    Io {
        /// Which operation failed, for the message.
        operation: &'static str,
        /// What the platform reported.
        reason: String,
    },
    /// The handle does not name a stream this provider currently owns.
    #[error("{socket} is not open")]
    UnknownSocket {
        /// The handle that was passed in.
        socket: SocketHandle,
    },
    /// A provider-side limit is already reached.
    #[error("resource exhausted: {resource}")]
    Exhausted {
        /// Which limit, for the message.
        resource: &'static str,
    },
}

/// Something a provider observed on one of its streams.
///
/// See [`TcpProvider::poll`] for the ordering guarantees these carry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpEvent {
    /// A listener accepted an inbound stream.
    Accepted {
        /// The new stream.
        socket: SocketHandle,
        /// Where it came from, as a `/tcp` transport address.
        remote: Multiaddr,
    },
    /// An outbound stream from [`TcpProvider::connect`] finished connecting.
    Connected {
        /// The stream that is now writable.
        socket: SocketHandle,
        /// The address actually reached, which for a `/dns*` dial is the
        /// resolved one rather than the requested one.
        remote: Multiaddr,
    },
    /// Bytes arrived, in stream order.
    Received {
        /// Which stream.
        socket: SocketHandle,
        /// Payload; never empty.
        data: Vec<u8>,
    },
    /// The remote closed its write side; no more [`TcpEvent::Received`] will
    /// follow for this stream.
    RemoteWriteClosed {
        /// Which stream.
        socket: SocketHandle,
    },
    /// A stream that previously accepted only part of a
    /// [`TcpProvider::send`] may now accept more.
    Writable {
        /// Which stream.
        socket: SocketHandle,
    },
    /// The stream is gone, in either direction, and the handle is spent.
    Closed {
        /// Which stream.
        socket: SocketHandle,
        /// What happened, when it was a failure rather than an orderly end.
        reason: Option<String>,
    },
}

/// Supplies ordered, reliable byte streams to [`TcpTransport`](crate::TcpTransport).
///
/// This is the transport's only I/O seam. Everything above it -- the upgrade,
/// substream multiplexing, connection and stream identifiers, the whole
/// [`Transport`](minip2p_transport::Transport) contract -- is portable and
/// caller-driven. A provider owns sockets, listeners, and any name resolution;
/// it owns no clock and no executor, and never blocks.
///
/// # Addresses
///
/// Providers speak `/tcp` multiaddrs, not platform socket types, which is what
/// keeps the transport `no_std`. Interpreting a `/dns*` host is a provider's
/// job because resolution is I/O: a hosted provider may resolve it, and an
/// embedded one may reject it. Providers report the concrete address they
/// actually bound or reached, so the transport can describe endpoints without
/// knowing how they were derived.
///
/// # Contract
///
/// - Exactly one [`TcpEvent::Accepted`] or [`TcpEvent::Connected`] is emitted
///   per stream, before any other event for it. A handle returned by
///   [`connect`](Self::connect) is not writable until its `Connected` arrives.
/// - [`TcpEvent::Received`] carries bytes in stream order and is never empty.
/// - [`TcpEvent::RemoteWriteClosed`] is emitted at most once, and no `Received`
///   follows it.
/// - [`TcpEvent::Closed`] is terminal: no further events for that handle, and
///   the handle is never reused.
/// - [`TcpEvent::Writable`] is a hint, not a requirement. The transport retries
///   buffered writes on every poll regardless, so a provider whose readiness
///   reporting is coarse still drains; emitting it lets a host wake sooner.
/// - After [`abort`](Self::abort), the provider emits nothing further for that
///   handle -- the caller asked for the teardown and needs no confirmation.
/// - Events for one stream are in causal order within a single `poll`.
/// - `poll` never blocks; it returns an empty vec when idle.
pub trait TcpProvider {
    /// Binds a listener and returns the address it actually bound.
    ///
    /// A request with port 0, or a wildcard host, resolves to the concrete
    /// address in the return value. Inbound streams then arrive as
    /// [`TcpEvent::Accepted`].
    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TcpError>;

    /// Starts connecting to `addr` and returns the handle immediately.
    ///
    /// The stream is not usable until its [`TcpEvent::Connected`] is polled.
    /// A connect that ultimately fails reports [`TcpEvent::Closed`] with a
    /// reason rather than erroring here.
    fn connect(&mut self, addr: &Multiaddr) -> Result<SocketHandle, TcpError>;

    /// Writes as much of `data` as the stream will take right now, returning
    /// how many leading bytes were accepted.
    ///
    /// A short write is normal, not an error: the caller keeps the remainder
    /// and retries on its next poll. Accepting nothing is a valid short write.
    /// `data` is never empty.
    ///
    /// A socket that keeps accepting nothing eventually fails the connection,
    /// so a provider that can tell a busy peer from a dead one should report
    /// the dead one as [`TcpEvent::Closed`] rather than refuse writes forever.
    fn send(&mut self, socket: SocketHandle, data: &[u8]) -> Result<usize, TcpError>;

    /// Half-closes the local write side once buffered bytes are flushed.
    ///
    /// The remote observes end-of-stream. Reads continue until the remote
    /// closes too.
    fn close_write(&mut self, socket: SocketHandle) -> Result<(), TcpError>;

    /// Discards the stream immediately, dropping anything unflushed.
    ///
    /// Infallible and idempotent: aborting an unknown or already-gone handle
    /// is a no-op, because the caller's intent is satisfied either way.
    fn abort(&mut self, socket: SocketHandle);

    /// Drives the provider and returns what it observed.
    ///
    /// `now` is the host's time sample for this drive iteration; a provider
    /// that schedules work retains it to answer
    /// [`next_deadline`](Self::next_deadline) rather than reading a clock.
    fn poll(&mut self, now: Now) -> Result<Vec<TcpEvent>, TcpError>;

    /// When the provider next needs polling for a timer of its own.
    ///
    /// On the timeline of the [`Now`] samples given to [`poll`](Self::poll).
    /// Defaults to `None`, which suits a provider driven purely by socket
    /// readiness.
    fn next_deadline(&self) -> Option<Deadline> {
        None
    }

    /// The addresses this provider is currently listening on.
    fn local_addresses(&self) -> Vec<Multiaddr> {
        Vec::new()
    }
}
