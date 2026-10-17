use alloc::string::String;

use thiserror::Error;

use minip2p_core::platform::{EntropyError, IoErrorKind};
use minip2p_core::{Bytes, Multiaddr, PeerAddrError};

use crate::{ConnectionId, StreamId};

/// Errors returned by [`Transport`](crate::Transport) operations.
///
/// From [`send_stream`](crate::Transport::send_stream), only
/// [`Full`](Self::Full) says exactly what was accepted. Any other error may
/// follow a partial queue: a prefix of the payload can already be on its way.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum TransportError {
    #[error("invalid address for {context}: {reason}")]
    InvalidAddress {
        context: &'static str,
        reason: String,
    },
    /// The transport has no bound local address to listen on.
    #[error("the transport has no bound local address to listen on")]
    NotListening,
    /// A bound address could not be made into this node's dialable
    /// `PeerAddr`.
    #[error("cannot build a local peer address from {addr}: {error}")]
    LocalPeerAddr {
        /// The bound transport address.
        addr: Multiaddr,
        /// Why it is not a valid peer address.
        error: PeerAddrError,
    },
    /// The transport needed randomness (a handshake key, say) and the
    /// platform had none.
    #[error("entropy unavailable: {0}")]
    Entropy(#[from] EntropyError),
    /// The platform I/O under the transport failed.
    #[error("{operation} failed ({kind}): {detail}")]
    Io {
        /// What the transport was doing.
        operation: &'static str,
        /// What kind of failure the platform reported.
        kind: IoErrorKind,
        /// The platform's own description, for diagnostics.
        detail: String,
    },
    #[error("resource exhausted: {resource}")]
    ResourceExhausted { resource: &'static str },
    /// The transport does not offer this operation at all, as opposed to
    /// having tried it and failed. Callers choosing between transports read
    /// this as "not here", not as an error to report to a user.
    #[error("this transport does not support {operation}")]
    Unsupported { operation: &'static str },
    #[error("connection {id} not found")]
    ConnectionNotFound { id: ConnectionId },
    /// The operation failed in a way that ended the connection: the
    /// transport closed it, and its
    /// [`Closed`](crate::TransportEvent::Closed) event carries this failure
    /// as its reason. From then on the connection is not found.
    #[error("connection {id} closed: {reason}")]
    ConnectionClosed { id: ConnectionId, reason: String },
    #[error("connection {id} is {state}, expected {expected}")]
    InvalidState {
        id: ConnectionId,
        state: crate::ConnectionState,
        expected: crate::ConnectionState,
    },
    /// Binding a listener failed in the platform.
    #[error("listen on {addr} failed ({kind}): {detail}")]
    ListenFailed {
        /// The address the listener was asked for.
        addr: Multiaddr,
        /// What kind of failure the platform reported.
        kind: IoErrorKind,
        /// The platform's own description, for diagnostics.
        detail: String,
    },
    #[error("dial failed for {id}: {reason}")]
    DialFailed { id: ConnectionId, reason: String },
    #[error("stream {stream_id} not found on connection {id}")]
    StreamNotFound {
        id: ConnectionId,
        stream_id: StreamId,
    },
    #[error("stream {stream_id} already exists on connection {id}")]
    StreamExists {
        id: ConnectionId,
        stream_id: StreamId,
    },
    /// The stream could not queue every byte of a write. Retryable, never a
    /// fault: `unsent` is the exact suffix that was not accepted (the whole
    /// payload when nothing fit), and a
    /// [`TransportEvent::StreamWritable`](crate::TransportEvent::StreamWritable)
    /// for the stream follows once it can queue again.
    #[error("stream {stream_id} on connection {id} is full; {} bytes unsent", unsent.len())]
    Full {
        id: ConnectionId,
        stream_id: StreamId,
        unsent: Bytes,
    },
    /// An acknowledgement named more bytes than the stream has delivered
    /// and not yet had acknowledged. Nothing was acknowledged.
    #[error(
        "cannot acknowledge {acked} bytes on stream {stream_id} of connection {id}: only {unacked} are unacknowledged"
    )]
    AckExceedsDelivered {
        id: ConnectionId,
        stream_id: StreamId,
        /// Bytes the call tried to acknowledge.
        acked: usize,
        /// Bytes the stream had delivered and not yet had acknowledged.
        unacked: usize,
    },
    #[error("stream send failed for {id}/{stream_id}: {reason}")]
    StreamSendFailed {
        id: ConnectionId,
        stream_id: StreamId,
        reason: String,
    },
    #[error("stream close write failed for {id}/{stream_id}: {reason}")]
    StreamCloseWriteFailed {
        id: ConnectionId,
        stream_id: StreamId,
        reason: String,
    },
    #[error("stream reset failed for {id}/{stream_id}: {reason}")]
    StreamResetFailed {
        id: ConnectionId,
        stream_id: StreamId,
        reason: String,
    },
    #[error("close failed for {id}: {reason}")]
    CloseFailed { id: ConnectionId, reason: String },
    /// Driving the transport failed inside the transport itself: a session
    /// or negotiation fault, not the platform underneath.
    #[error("poll error: {reason}")]
    PollError { reason: String },
}

impl TransportError {
    /// An [`Io`](Self::Io) error from a `std::io::Error`.
    #[cfg(feature = "std")]
    pub fn io(operation: &'static str, error: &std::io::Error) -> Self {
        use alloc::string::ToString;

        Self::Io {
            operation,
            kind: error.kind().into(),
            detail: error.to_string(),
        }
    }

    /// The unsent tail of a [`TransportError::Full`] write, or `None` for any
    /// other error.
    pub fn into_unsent(self) -> Option<Bytes> {
        match self {
            Self::Full { unsent, .. } => Some(unsent),
            _ => None,
        }
    }
}
