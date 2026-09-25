//! Binding-agnostic endpoint lifecycle and event delivery for foreign runtimes.
//!
//! Connection attempts follow one contract: [`P2pEndpoint::connect`]
//! admits an attempt under a single Connect ID and the event stream carries
//! exactly one terminal for it — [`P2pEvent::PathEstablished`],
//! [`P2pEvent::ConnectFailed`], or [`P2pEvent::ConnectCancelled`] after
//! [`P2pEndpoint::cancel_connect`]. If the bounded carry drops a terminal,
//! `P2pEvent::EventsDropped::terminal_connect_ids` names its Connect ID, so
//! exactly the affected foreign wait settles with a delivery-loss error and recovers through
//! the State getters (`connected_peers`, `connection_info`, `path`,
//! `known_peers`, `listen_addrs`). The detached driver owns the Endpoint
//! wait outcomes — event, deadline, interrupted — and releases ownership on
//! interruption so commands never deadlock.

#![warn(missing_docs)]

mod config;
mod connect;
mod driver;
mod endpoint;
mod error;
mod events;

pub use config::{
    DiscoveryOptions, EndpointConfig, KnownPeerInfo, MdnsOptions, RelayReservationInfo,
};
pub use connect::ConnectTarget;
pub use driver::DriverStats;
pub use endpoint::P2pEndpoint;
pub use error::FfiError;
pub use events::{
    ConnectionInfo, DiscoverySource, DriverFailureKind, EndpointErrorKind, EventDoorbell,
    IdentifyInfo, NatErrorKind, OpenStreamResult, P2pEvent, PathKind, Reachability,
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
    let peer_addr = PeerAddr::from_str(address).map_err(|error| FfiError::InvalidAddress {
        detail: error.to_string(),
    })?;
    if peer_addr.transport().transport_kind().is_none() || peer_addr.transport().is_wildcard_host()
    {
        return Err(FfiError::InvalidAddress {
            detail: "address must be a complete direct /quic-v1 or /tcp peer address".into(),
        });
    }
    Ok(peer_addr)
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
