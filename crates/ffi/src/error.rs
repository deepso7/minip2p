//! Errors exposed across the foreign-function boundary.

/// An error returned by a synchronous FFI operation.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
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
