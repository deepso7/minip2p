#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod key;
mod peer_id;

pub use key::{KeyType, PublicKey, PublicKeyError};
pub use peer_id::{PEER_ID_MULTIHASH_SIZE, PeerId, PeerIdError, PeerMultihash, VarintError};
