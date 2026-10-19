//! The WebTransport I/O seam: what [`WebTransportClient`](crate::WebTransportClient)
//! needs from the platform's WebTransport API.
//!
//! In a browser the implementation is TypeScript around the `WebTransport`
//! object; natively it can be any HTTP/3 stack. The seam is caller-driven like
//! the rest of minip2p: every call returns at once, and outcomes the platform
//! learns later (a session coming up, a stream's bytes, a write resolving) are
//! queued and handed back by [`WebTransportIo::poll_event`].

use alloc::string::String;
use core::fmt;

use minip2p_core::{Bytes, Multihash};
use thiserror::Error;

/// One WebTransport session (one `new WebTransport(url)` in a browser).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionHandle(pub u64);

/// One bidirectional stream of a session. Handles are unique across every
/// session of one [`WebTransportIo`] and never reused.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StreamHandle(pub u64);

impl fmt::Display for StreamHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stream {}", self.0)
    }
}

/// A call the platform refused outright, such as a URL it cannot parse or
/// a session that is already closed.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("WebTransport I/O failed: {0}")]
pub struct IoError(pub String);

/// Something the platform learned since the last poll.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IoEvent {
    /// The session's CONNECT succeeded (`ready` resolved).
    SessionReady { session: SessionHandle },
    /// The session ended, or never came up (`ready` or `closed` settled).
    /// Every stream of it is gone with it, without events of their own.
    SessionClosed {
        session: SessionHandle,
        /// The WebTransport close code, 0 when the platform gave none.
        code: u32,
        /// Why, for diagnostics.
        reason: String,
    },
    /// A stream from [`WebTransportIo::open_stream`] is open and writable.
    StreamOpened { stream: StreamHandle },
    /// The server opened a bidirectional stream.
    IncomingStream {
        session: SessionHandle,
        stream: StreamHandle,
    },
    /// Bytes read from a stream, never more than were granted with
    /// [`WebTransportIo::grant_read`].
    Data { stream: StreamHandle, bytes: Bytes },
    /// The peer finished its side of the stream.
    Fin { stream: StreamHandle },
    /// The peer reset its side of the stream. `code` is the WebTransport
    /// application error code (a browser's `streamErrorCode`), already
    /// mapped back from HTTP/3; 0 when the platform gave none.
    Reset { stream: StreamHandle, code: u8 },
    /// The peer asked us to stop sending on the stream, with a WebTransport
    /// code as for [`IoEvent::Reset`]. The client reports it unchanged in
    /// `StreamWriteStopped`, as the QUIC server does.
    StopSending { stream: StreamHandle, code: u8 },
    /// One accepted [`WebTransportIo::write`] resolved, releasing exactly
    /// its `bytes`.
    WriteCompleted { stream: StreamHandle, bytes: usize },
}

/// The platform's WebTransport API, as a caller-driven provider.
///
/// Nothing blocks and nothing is async: the implementation turns promise
/// resolutions into queued [`IoEvent`]s and wakes its host, which then polls
/// the client.
pub trait WebTransportIo {
    /// Starts a session to `url`, trusting exactly the server certificates
    /// whose SHA-256 hashes are `certhashes` (`serverCertificateHashes`).
    /// [`IoEvent::SessionReady`] or [`IoEvent::SessionClosed`] follows.
    fn connect(&mut self, url: &str, certhashes: &[Multihash]) -> Result<SessionHandle, IoError>;

    /// Opens a bidirectional stream; [`IoEvent::StreamOpened`] follows once
    /// it can be written.
    fn open_stream(&mut self, session: SessionHandle) -> Result<StreamHandle, IoError>;

    /// Copies a prefix of `data` into the stream's in-flight writes and
    /// returns its length; a short write is backpressure. Each accepted
    /// write later reports [`IoEvent::WriteCompleted`] with its own length,
    /// so a write that accepts nothing always has an earlier one still to
    /// complete.
    fn write(&mut self, stream: StreamHandle, data: &[u8]) -> Result<usize, IoError>;

    /// Finishes the write side after every accepted write.
    fn close_write(&mut self, stream: StreamHandle);

    /// Resets the stream in both directions (`abort()` and `cancel()`).
    /// `code` is a WebTransport application error code; the platform maps
    /// it into HTTP/3's range on the wire. minip2p only ever sends 0.
    fn reset(&mut self, stream: StreamHandle, code: u8);

    /// Asks the peer to stop sending (`cancel()` only).
    fn stop(&mut self, stream: StreamHandle, code: u8);

    /// Lets the stream deliver up to `bytes` more in [`IoEvent::Data`].
    fn grant_read(&mut self, stream: StreamHandle, bytes: usize);

    /// Closes the session with a WebTransport close code and reason: a
    /// `CLOSE_WEBTRANSPORT_SESSION` capsule and FIN on the CONNECT stream,
    /// as `WebTransport.close()` does, leaving the server to close QUIC.
    fn close(&mut self, session: SessionHandle, code: u32, reason: &str);

    /// The next queued event, if any.
    fn poll_event(&mut self) -> Option<IoEvent>;
}
