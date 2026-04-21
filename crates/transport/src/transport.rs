use alloc::vec::Vec;

use minip2p_core::{Multiaddr, PeerAddr};

use crate::{ConnectionId, StreamId, TransportError, TransportEvent};

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
/// - `dial()` returns `Ok` before any events for that connection are emitted.
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
    /// Initiate an outbound connection.
    ///
    /// The caller provides the `id`; the transport must reject duplicates with
    /// `ConnectionExists`. The connection is not usable until `Connected` is
    /// emitted from `poll()`.
    fn dial(&mut self, id: ConnectionId, addr: &PeerAddr) -> Result<(), TransportError>;

    /// Start listening for inbound connections on the given address.
    ///
    /// Emits `Listening` on success. Incoming connections produce
    /// `IncomingConnection` followed by `Connected`.
    fn listen(&mut self, addr: &Multiaddr) -> Result<(), TransportError>;

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
}
