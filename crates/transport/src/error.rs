use alloc::string::String;

use thiserror::Error;

use crate::{ConnectionId, StreamId};

/// Errors returned by [`Transport`](crate::Transport) operations.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("invalid address for {context}: {reason}")]
    InvalidAddress {
        context: &'static str,
        reason: String,
    },
    #[error("invalid transport configuration: {reason}")]
    InvalidConfig { reason: String },
    #[error("resource exhausted: {resource}")]
    ResourceExhausted { resource: &'static str },
    #[error("connection {id} not found")]
    ConnectionNotFound { id: ConnectionId },
    #[error("connection {id} already exists")]
    ConnectionExists { id: ConnectionId },
    #[error("connection {id} is {state}, expected {expected}")]
    InvalidState {
        id: ConnectionId,
        state: crate::ConnectionState,
        expected: crate::ConnectionState,
    },
    #[error("not listening on any address")]
    NotListening,
    #[error("listen failed: {reason}")]
    ListenFailed { reason: String },
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
    #[error("failed to open stream on {id}: {reason}")]
    OpenStreamFailed { id: ConnectionId, reason: String },
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
    #[error("poll error: {reason}")]
    PollError { reason: String },
}
