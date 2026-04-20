use alloc::string::String;

use thiserror::Error;

use crate::ConnectionId;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
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
    #[error("send failed for {id}: {reason}")]
    SendFailed { id: ConnectionId, reason: String },
    #[error("close failed for {id}: {reason}")]
    CloseFailed { id: ConnectionId, reason: String },
    #[error("poll error: {reason}")]
    PollError { reason: String },
}
