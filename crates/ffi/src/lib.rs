//! UniFFI bindings for embedding minip2p in mobile applications.

#![warn(missing_docs)]

mod config;
mod endpoint;
mod error;
mod events;

pub use config::{
    DiscoveryOptions, EndpointConfig, KnownPeerInfo, MdnsOptions, PubsubRouter,
    RelayReservationInfo, TransportOptions,
};
pub use endpoint::P2pEndpoint;
pub use error::FfiError;
pub use events::{
    DiscoverySource, DriverFailureKind, EndpointErrorKind, IdentifyInfo, NatErrorKind,
    OpenStreamResult, P2pEvent, PathKind, Reachability,
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
