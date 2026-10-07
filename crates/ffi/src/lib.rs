//! UniFFI bindings for embedding minip2p in mobile applications.

#![warn(missing_docs)]

mod endpoint;

pub use endpoint::P2pEndpoint;
// Records, enums and errors are UniFFI types of `minip2p-ffi-core` itself,
// derived behind its `uniffi` feature.
pub use minip2p_ffi_core::{
    ConnectTarget, ConnectionInfo, DiscoveryOptions, DiscoverySource, DriverFailureKind,
    EndpointConfig, EndpointErrorKind, FfiError, IdentifyInfo, KnownPeerInfo, MdnsOptions,
    NatErrorKind, OpenStreamResult, P2pEvent, PathKind, Reachability, RelayReservationInfo,
};

/// Doorbell implemented by the embedding runtime.
#[uniffi::export(with_foreign)]
pub trait P2pEventDoorbell: Send + Sync {
    /// Reports that synchronous event draining can make progress.
    fn on_events_ready(&self);
}

/// Generates raw Ed25519 secret key material.
#[uniffi::export]
pub fn generate_secret_key() -> Vec<u8> {
    minip2p_ffi_core::generate_secret_key()
}

/// Derives a base58 peer ID from raw Ed25519 secret key material.
#[uniffi::export]
pub fn peer_id_from_secret_key(secret_key: Vec<u8>) -> Result<String, FfiError> {
    minip2p_ffi_core::peer_id_from_secret_key(secret_key)
}

/// Builds a circuit multiaddress for `peer_id` through `relay_addr`.
#[uniffi::export]
pub fn circuit_address(relay_addr: String, peer_id: String) -> Result<String, FfiError> {
    minip2p_ffi_core::circuit_address(relay_addr, peer_id)
}

uniffi::setup_scaffolding!();
