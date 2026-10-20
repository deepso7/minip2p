//! Binding-agnostic endpoint lifecycle and event delivery for foreign runtimes.
//!
//! The crate has two layers. The thread-free host core is always built: the
//! bounded [`EventCarry`], the [`P2pEvent`] model and its conversion from
//! [`minip2p::EndpointEvent`] ([`convert_endpoint_event`]), the config, error
//! and [`ConnectTarget`] types, the stream-write helpers, and the key
//! helpers. It needs no threads, clock or sockets, so a single-threaded host
//! (the wasm shell) drives a `PortableEndpoint` with it. The default
//! `driver` feature adds the std host: [`P2pEndpoint`], its detached driver
//! and doorbell threads, and Name resolution.
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

mod carry;
mod config;
mod connect;
#[cfg(feature = "driver")]
mod driver;
#[cfg(feature = "driver")]
mod endpoint;
mod error;
mod events;
#[cfg(feature = "serde")]
mod js_shape;
#[cfg(feature = "driver")]
mod limits;
mod writes;

pub use carry::{DriverStats, EventCarry, PUMP_DRAIN_LIMIT};
pub use config::{
    DiscoveryOptions, EndpointConfig, KnownPeerInfo, LimitsOptions, MdnsOptions, QuicLimitsOptions,
    RelayReservationInfo, TcpLimitsOptions, TimeoutLimit, WindowLimit, YamuxOptions,
};
pub use connect::{ConnectTarget, parse_connect_target};
#[cfg(feature = "driver")]
pub use endpoint::{DEFAULT_STOP_TIMEOUT_MS, P2pEndpoint};
pub use error::{
    ConfigCapability, FfiError, driver_failure_kind, map_driver_error, map_gossipsub_error,
    map_topic_error,
};
#[cfg(any(feature = "driver", feature = "relay"))]
pub use events::convert_reachability;
pub use events::{
    CloseOutcome, ConnectionCloseReason, ConnectionInfo, DiscoverySource, DriverFailureKind,
    EndpointErrorKind, EventDoorbell, IdentifyInfo, MdnsFailureKind, NatErrorKind,
    OpenStreamResult, P2pEvent, PathKind, Reachability, UnfinishedConnection,
    convert_endpoint_event, convert_identify, convert_path,
};
pub use writes::{map_write_error, stream_writer, write_accepted_event};

use std::str::FromStr;

use minip2p::{Ed25519Keypair, Multiaddr, PeerAddr, PeerId, Protocol};

// The `uniffi` feature makes this crate its own UniFFI namespace, so the
// UniFFI shell exports these records, enums and errors without mirroring them.
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

const SECRET_KEY_LENGTH: usize = 32;

/// Generates raw Ed25519 secret key material from the operating system's
/// entropy. Hosts without it generate the 32 bytes from their own source.
#[cfg(feature = "driver")]
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
    let target = parse_peer_id(&peer_id)?;
    let mut protocols = relay.transport().protocols().to_vec();
    protocols.push(Protocol::P2p(relay.peer_id().clone()));
    protocols.push(Protocol::P2pCircuit);
    protocols.push(Protocol::P2p(target));
    Ok(Multiaddr::from_protocols(protocols).to_string())
}

/// Parses a base58 peer ID supplied by a binding.
pub fn parse_peer_id(peer_id: &str) -> Result<PeerId, FfiError> {
    PeerId::from_str(peer_id).map_err(|error| FfiError::InvalidPeerId {
        detail: error.to_string(),
    })
}

/// Parses a relay or AutoNAT server address supplied by a binding: a
/// complete direct peer address with a concrete host.
pub fn parse_direct_peer_addr(address: &str) -> Result<PeerAddr, FfiError> {
    let peer_addr = PeerAddr::from_str(address).map_err(|error| FfiError::InvalidAddress {
        detail: error.to_string(),
    })?;
    if peer_addr.transport().transport_kind().is_none() || peer_addr.transport().is_wildcard_host()
    {
        return Err(FfiError::InvalidAddress {
            detail:
                "address must be a complete direct /quic-v1, /webtransport or /tcp peer address"
                    .into(),
        });
    }
    Ok(peer_addr)
}

/// Builds the Ed25519 identity from raw secret key material supplied by a
/// binding, which must be exactly 32 bytes.
pub fn keypair_from_bytes(secret_key: Vec<u8>) -> Result<Ed25519Keypair, FfiError> {
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
