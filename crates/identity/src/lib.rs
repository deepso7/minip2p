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

/// Helpers shared by this crate's unit tests.
#[cfg(test)]
pub(crate) mod test_util {
    use alloc::vec::Vec;

    /// Decodes an even-length hex string into bytes; panics on invalid input.
    pub(crate) fn decode_hex(input: &str) -> Vec<u8> {
        assert_eq!(input.len() % 2, 0);
        let mut out = Vec::with_capacity(input.len() / 2);
        let bytes = input.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16).expect("invalid hex") as u8;
            let lo = (bytes[i + 1] as char).to_digit(16).expect("invalid hex") as u8;
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }
}
