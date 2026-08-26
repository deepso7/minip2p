//! Errors exposed to binding shells.

/// An error returned by a synchronous FFI operation.
#[derive(Debug, thiserror::Error)]
pub enum FfiError {
    /// The endpoint's background driver was already started.
    #[error("endpoint driver already started")]
    AlreadyStarted,
    /// The endpoint has stopped and cannot be restarted.
    #[error("endpoint is stopped")]
    Stopped,
    /// Endpoint configuration was internally inconsistent.
    #[error("invalid endpoint configuration: {detail}")]
    InvalidConfig {
        /// Human-readable validation detail.
        detail: String,
    },
    /// Secret key material was not exactly 32 bytes.
    #[error("invalid secret key: {detail}")]
    InvalidKey {
        /// Human-readable validation detail.
        detail: String,
    },
    /// A peer ID could not be parsed.
    #[error("invalid peer id: {detail}")]
    InvalidPeerId {
        /// Human-readable parse detail.
        detail: String,
    },
    /// A multiaddress or peer address could not be parsed.
    #[error("invalid address: {detail}")]
    InvalidAddress {
        /// Human-readable parse detail.
        detail: String,
    },
    /// A pubsub topic failed validation.
    #[error("invalid topic: {detail}")]
    InvalidTopic {
        /// Human-readable validation detail.
        detail: String,
    },
    /// The operation is valid but reserved by another endpoint subsystem.
    #[error("operation not permitted: {detail}")]
    NotPermitted {
        /// Human-readable refusal detail.
        detail: String,
    },
    /// A bounded outbound queue is full.
    #[error("outbound backpressure")]
    Backpressure,
    /// A pubsub message exceeds the protocol limit.
    #[error("message too large")]
    MessageTooLarge,
    /// A synchronous transport operation failed.
    #[error("transport error: {detail}")]
    Transport {
        /// Human-readable transport detail.
        detail: String,
    },
    /// The operation is unavailable in the endpoint's current lifecycle state.
    #[error("invalid endpoint state: {detail}")]
    InvalidState {
        /// Human-readable state detail.
        detail: String,
    },
    /// An internal invariant or unexpected construction path failed.
    #[error("internal error: {detail}")]
    Internal {
        /// Human-readable failure detail.
        detail: String,
    },
}
