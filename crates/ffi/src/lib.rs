//! UniFFI bindings for embedding minip2p in mobile applications.

#![warn(missing_docs)]

mod config;
mod driver;
mod endpoint;
mod error;
mod events;

use std::str::FromStr;

pub use config::{
    DiscoveryOptions, EndpointConfig, KnownPeerInfo, MdnsOptions, PubsubRouter,
    RelayReservationInfo,
};
pub use driver::DriverStats;
pub use endpoint::P2pEndpoint;
pub use error::FfiError;
pub use events::{
    DiscoverySource, DriverFailureKind, EndpointErrorKind, IdentifyInfo, NatErrorKind, P2pEvent,
    P2pEventListener, PathKind, Reachability,
};
use minip2p::{Ed25519Keypair, Multiaddr, PeerAddr, PeerId, Protocol};

const SECRET_KEY_LENGTH: usize = 32;

const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<minip2p::Endpoint>();
};

/// Generates raw Ed25519 secret key material.
#[uniffi::export]
pub fn generate_secret_key() -> Vec<u8> {
    Ed25519Keypair::generate().secret_key_bytes().to_vec()
}

/// Derives a base58 peer ID from raw Ed25519 secret key material.
#[uniffi::export]
pub fn peer_id_from_secret_key(secret_key: Vec<u8>) -> Result<String, FfiError> {
    Ok(keypair_from_bytes(secret_key)?.peer_id().to_base58())
}

/// Builds a circuit multiaddress for `peer_id` through `relay_addr`.
#[uniffi::export]
pub fn circuit_address(relay_addr: String, peer_id: String) -> Result<String, FfiError> {
    let relay = parse_direct_quic_peer_addr(&relay_addr)?;
    let target = PeerId::from_str(&peer_id).map_err(|error| FfiError::InvalidPeerId {
        detail: error.to_string(),
    })?;

    let mut protocols = relay.transport().protocols().to_vec();
    protocols.push(Protocol::P2p(relay.peer_id().clone()));
    protocols.push(Protocol::P2pCircuit);
    protocols.push(Protocol::P2p(target));
    Ok(Multiaddr::from_protocols(protocols).to_string())
}

fn parse_direct_quic_peer_addr(address: &str) -> Result<PeerAddr, FfiError> {
    let relay = PeerAddr::from_str(address).map_err(|error| FfiError::InvalidAddress {
        detail: error.to_string(),
    })?;
    if !relay.transport().is_quic_transport() || relay.transport().is_wildcard_host() {
        return Err(FfiError::InvalidAddress {
            detail: "relay address must be a direct QUIC-v1 peer address".into(),
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

uniffi::setup_scaffolding!();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_round_trips_to_a_stable_peer_id() {
        let secret = vec![7; SECRET_KEY_LENGTH];
        let first = peer_id_from_secret_key(secret.clone()).expect("peer id");
        let second = peer_id_from_secret_key(secret).expect("peer id");
        let expected = Ed25519Keypair::from_secret_key_bytes([7; SECRET_KEY_LENGTH])
            .peer_id()
            .to_base58();

        assert_eq!(first, second);
        assert_eq!(first, expected);
    }

    #[test]
    fn generated_secret_key_has_the_expected_length_and_derives_a_peer_id() {
        let secret = generate_secret_key();

        assert_eq!(secret.len(), SECRET_KEY_LENGTH);
        let peer_id = peer_id_from_secret_key(secret).expect("generated key must round-trip");
        assert!(PeerId::from_str(&peer_id).is_ok());
    }

    #[test]
    fn secret_key_length_is_validated() {
        assert!(matches!(
            peer_id_from_secret_key(vec![1; SECRET_KEY_LENGTH - 1]),
            Err(FfiError::InvalidKey { .. })
        ));
    }

    #[test]
    fn circuit_address_matches_the_libp2p_shape() {
        let relay = Ed25519Keypair::from_secret_key_bytes([1; SECRET_KEY_LENGTH]).peer_id();
        let target = Ed25519Keypair::from_secret_key_bytes([2; SECRET_KEY_LENGTH]).peer_id();
        let relay_addr = format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{relay}");

        let address =
            circuit_address(relay_addr.clone(), target.to_base58()).expect("circuit address");

        assert_eq!(address, format!("{relay_addr}/p2p-circuit/p2p/{target}"));
    }

    #[test]
    fn circuit_address_accepts_a_cid_v1_target() {
        let relay = Ed25519Keypair::from_secret_key_bytes([1; SECRET_KEY_LENGTH]).peer_id();
        let target = Ed25519Keypair::from_secret_key_bytes([2; SECRET_KEY_LENGTH]).peer_id();
        let relay_addr = format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{relay}");

        let address = circuit_address(relay_addr, target.to_cid_base32()).expect("circuit address");

        assert!(address.ends_with(&format!("/p2p/{target}")));
    }

    #[test]
    fn circuit_address_rejects_invalid_inputs() {
        let relay = Ed25519Keypair::from_secret_key_bytes([1; SECRET_KEY_LENGTH]).peer_id();
        let target = Ed25519Keypair::from_secret_key_bytes([2; SECRET_KEY_LENGTH]).peer_id();

        assert!(matches!(
            circuit_address("not-an-address".into(), target.to_base58()),
            Err(FfiError::InvalidAddress { .. })
        ));
        assert!(matches!(
            circuit_address(
                format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{relay}"),
                "not-a-peer-id".into()
            ),
            Err(FfiError::InvalidPeerId { .. })
        ));
    }

    #[test]
    fn circuit_address_rejects_non_quic_and_existing_circuit_relays() {
        let relay = Ed25519Keypair::from_secret_key_bytes([1; SECRET_KEY_LENGTH]).peer_id();
        let target = Ed25519Keypair::from_secret_key_bytes([2; SECRET_KEY_LENGTH]).peer_id();

        for invalid in [
            format!("/ip4/127.0.0.1/udp/4001/p2p/{relay}"),
            format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p-circuit/p2p/{relay}"),
        ] {
            let error = circuit_address(invalid, target.to_base58())
                .expect_err("invalid relay shape must be rejected");
            assert!(matches!(
                error,
                FfiError::InvalidAddress { ref detail }
                    if detail == "relay address must be a direct QUIC-v1 peer address"
            ));
        }
    }
}
