//! Binding-agnostic endpoint lifecycle and event delivery for foreign runtimes.

#![warn(missing_docs)]

mod config;
mod driver;
mod endpoint;
mod error;
mod events;

pub use config::{
    DiscoveryOptions, EndpointConfig, KnownPeerInfo, MdnsOptions, PubsubRouter,
    RelayReservationInfo, TransportOptions,
};
pub use driver::DriverStats;
pub use endpoint::P2pEndpoint;
pub use error::FfiError;
pub use events::{
    DiscoverySource, DriverFailureKind, EndpointErrorKind, EventDoorbell, IdentifyInfo,
    NatErrorKind, OpenStreamResult, P2pEvent, PathKind, Reachability,
};

use std::str::FromStr;

use minip2p::{Ed25519Keypair, Multiaddr, PeerAddr, PeerId, Protocol};

const SECRET_KEY_LENGTH: usize = 32;

/// Generates raw Ed25519 secret key material.
pub fn generate_secret_key() -> Vec<u8> {
    Ed25519Keypair::generate().secret_key_bytes().to_vec()
}

/// Derives a base58 peer ID from raw Ed25519 secret key material.
pub fn peer_id_from_secret_key(secret_key: Vec<u8>) -> Result<String, FfiError> {
    Ok(keypair_from_bytes(secret_key)?.peer_id().to_base58())
}

/// Builds a circuit multiaddress for `peer_id` through `relay_addr`.
pub fn circuit_address(relay_addr: String, peer_id: String) -> Result<String, FfiError> {
    let relay = parse_direct_peer_addr(&relay_addr)?;
    let target = PeerId::from_str(&peer_id).map_err(|error| FfiError::InvalidPeerId {
        detail: error.to_string(),
    })?;
    let mut protocols = relay.transport().protocols().to_vec();
    protocols.push(Protocol::P2p(relay.peer_id().clone()));
    protocols.push(Protocol::P2pCircuit);
    protocols.push(Protocol::P2p(target));
    Ok(Multiaddr::from_protocols(protocols).to_string())
}

fn parse_direct_peer_addr(address: &str) -> Result<PeerAddr, FfiError> {
    let relay = PeerAddr::from_str(address).map_err(|error| FfiError::InvalidAddress {
        detail: error.to_string(),
    })?;
    if relay.transport().transport_kind().is_none() || relay.transport().is_wildcard_host() {
        return Err(FfiError::InvalidAddress {
            detail: "relay address must be a direct /quic-v1 or /tcp peer address".into(),
        });
    }
    Ok(relay)
}

fn keypair_from_bytes(secret_key: Vec<u8>) -> Result<Ed25519Keypair, FfiError> {
    let secret_key: [u8; SECRET_KEY_LENGTH] =
        secret_key
            .try_into()
            .map_err(|value: Vec<u8>| FfiError::InvalidKey {
                detail: format!(
                    "expected {SECRET_KEY_LENGTH} bytes, received {}",
                    value.len()
                ),
            })?;
    Ok(Ed25519Keypair::from_secret_key_bytes(secret_key))
}
