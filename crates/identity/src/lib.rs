//! Peer identity primitives for minip2p.
//!
//! Provides Ed25519 key generation, public key protobuf encoding, peer id
//! derivation and parsing, and signature verification. `no_std` + `alloc`
//! compatible.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "ed25519")]
mod ed25519;
mod key;
mod peer_id;
#[cfg(feature = "ed25519")]
mod signed;

#[cfg(feature = "ed25519")]
pub use ed25519::{
    ED25519_PUBLIC_KEY_LENGTH, ED25519_SECRET_KEY_LENGTH, ED25519_SIGNATURE_LENGTH, Ed25519Keypair,
};
#[cfg(feature = "ed25519")]
pub use key::VerifyError;
pub use key::{KeyType, PublicKey, PublicKeyError};
pub use peer_id::{
    PEER_ID_MULTIHASH_SIZE, PeerId, PeerIdError, PeerMultihash, VarintError, read_uvarint,
    uvarint_len, write_uvarint,
};
#[cfg(feature = "ed25519")]
pub use signed::SignedBytes;
