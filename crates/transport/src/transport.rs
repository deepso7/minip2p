use alloc::vec::Vec;
use core::time::Duration;

use minip2p_core::{Multiaddr, PeerAddr};

use crate::{ConnectionId, StreamId, TransportError, TransportEvent};

/// Result of [`Transport::wait_for_input`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// Input may be ready; the caller should poll now.
    Ready,
    /// The timeout elapsed without input arriving.
    TimedOut,
    /// The transport cannot wait for readiness; the caller should fall back
    /// to sleeping between polls.
    Unsupported,
}

/// The core transport abstraction.
///
/// Concrete adapters (QUIC, WebSocket, etc.) implement this trait. The host
/// drives the transport by calling [`poll`](Transport::poll) and reacting to
/// [`TransportEvent`](crate::TransportEvent)s.
///
/// # Contract
///
/// All adapters must uphold the following guarantees:
///
/// ## Connection lifecycle
///
/// - `dial()` returns the allocated connection id before any events for that
///   connection are emitted.
/// - A dialed connection emits `Connected` exactly once after the handshake
///   completes. No stream events may precede `Connected`.
/// - An incoming connection emits `IncomingConnection` before `Connected`.
/// - After `close()` is called, the connection eventually emits `Closed`.
///   No further events are emitted for that connection id after `Closed`.
/// - `ConnectionNotFound` is returned for any operation on an unknown or
///   already-closed connection id.
///
/// ## Stream lifecycle
///
/// - `open_stream()` returns a `StreamId` and emits `StreamOpened`.
/// - Remote-initiated streams emit `IncomingStream` before any `StreamData`.
/// - `StreamData` may be emitted zero or more times for a stream.
/// - `StreamRemoteWriteClosed` is emitted at most once per stream when the
///   remote half-closes its write side.
/// - `StreamClosed` is emitted at most once when both sides are closed.
///   No further events are emitted for that stream after `StreamClosed`.
/// - `reset_stream()` immediately closes both directions and emits
///   `StreamClosed` (if not already emitted).
///
/// ## Event ordering
///
/// - Events for a single connection are returned in causal order within a
///   single `poll()` call.
/// - Events across different connections have no ordering guarantee.
/// - `poll()` never blocks. It returns an empty vec when idle.
pub trait Transport {
    /// Initiate an outbound connection and return its allocated connection id.
    ///
    /// The transport owns connection-id allocation for both inbound and
    /// outbound connections, so adapters can avoid collisions between accepted
    /// connections and later dials. The connection is not usable until
    /// `Connected` is emitted from `poll()`.
    fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError>;

    /// Start listening for inbound connections on the given address.
    ///
    /// Returns the actual resolved listen address and emits `Listening` on
    /// success with the same address. Incoming connections produce
    /// `IncomingConnection` followed by `Connected`.
    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError>;

    /// Open a new bidirectional stream on an existing connection.
    ///
    /// Returns `InvalidState` if the connection is not yet `Connected`.
    /// Emits `StreamOpened` on success.
    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError>;

    /// Write data to a stream.
    ///
    /// Returns `StreamSendFailed` if the write side is already closed.
    /// Empty data is a no-op.
    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), TransportError>;

    /// Half-close the write side of a stream (send FIN).
    ///
    /// The remote will observe `StreamRemoteWriteClosed`. The stream remains
    /// readable until the remote also closes or the stream is reset.
    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError>;

    /// Abruptly reset a stream in both directions.
    ///
    /// Emits `StreamClosed` if not already emitted. Pending writes are dropped.
    fn reset_stream(&mut self, id: ConnectionId, stream_id: StreamId)
    -> Result<(), TransportError>;

    /// Gracefully close a connection.
    ///
    /// All streams are implicitly closed. The connection eventually emits
    /// `Closed` from `poll()`.
    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError>;

    /// Drive the transport forward and return any pending events.
    ///
    /// Must be called regularly. Never blocks -- returns an empty vec when
    /// there is no work to do.
    fn poll(&mut self) -> Result<Vec<TransportEvent>, TransportError>;

    /// Returns the duration until the transport next needs to be polled for a
    /// protocol timer, if it has one.
    ///
    /// Runtime drivers can combine this with socket readiness instead of using
    /// a fixed polling cadence. Returning zero means the timer is already due.
    ///
    /// Adapters with queued outbound work that is waiting on socket
    /// writability should return a short duration here so drivers keep
    /// polling until the queue drains.
    fn next_timeout(&self) -> Option<Duration> {
        None
    }

    /// Block the calling thread until new transport input may be available or
    /// `timeout` elapses, whichever comes first.
    ///
    /// Adapters that own a socket should override this with a real readiness
    /// wait (e.g. a blocking peek with a read timeout) so idle drivers can
    /// sleep for the full timer budget instead of polling on a fixed cadence.
    /// Implementations must not consume input and must tolerate spurious
    /// wakeups; callers always follow up with [`poll`](Transport::poll).
    ///
    /// The default returns [`WaitOutcome::Unsupported`], telling the driver to
    /// fall back to short sleeps between polls.
    fn wait_for_input(&mut self, timeout: Duration) -> WaitOutcome {
        let _ = timeout;
        WaitOutcome::Unsupported
    }

    /// Returns the transport multiaddrs this node is currently listening
    /// on.
    ///
    /// The swarm driver snapshots this on each `poll()` tick and uses it
    /// to auto-populate Identify's `listen_addrs` so remote peers learn
    /// where they can reach us. Returning an empty vec is valid for
    /// transports that don't bind (outbound-only) or haven't bound yet.
    ///
    /// Default implementation returns empty; adapters that know their
    /// bound addresses should override.
    fn local_addresses(&self) -> Vec<Multiaddr> {
        Vec::new()
    }

    /// Returns the remote transport address for every active inbound/accepted
    /// connection (pre-`Closed`), intentionally excluding outbound dials.
    ///
    /// Each multiaddr is the source address of the accepted connection as
    /// the transport observes it, without any `/p2p/<peer-id>` suffix --
    /// peer identity lives on `ConnectionEndpoint`, not in this address.
    /// Hole-punch responders use this to distinguish a real inbound packet
    /// from their own simultaneous direct dial attempt.
    ///
    /// Default implementation returns empty; adapters should override.
    fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
        Vec::new()
    }
}
