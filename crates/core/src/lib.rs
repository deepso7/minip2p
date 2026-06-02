//! Transport-agnostic address primitives for minip2p.
//!
//! Provides [`Multiaddr`] parsing/formatting, [`PeerAddr`] for validated
//! transport + peer id addresses, and the [`Protocol`] enum. `no_std` + `alloc`
//! compatible.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod candidates;
mod direct_paths;
mod error;
mod external_addresses;
mod multiaddr;
mod peer_addr;
mod protocol;

pub use candidates::{
    DirectCandidate, DirectCandidateRejectReason, DirectCandidateRejection,
    DirectCandidateSelection, DirectCandidateSource, select_direct_candidates,
};
pub use direct_paths::{
    DEFAULT_DIRECT_PATH_RETRY_MS, DirectPath, DirectPathBook, DirectPathSource, DirectPathStatus,
    DirectPathUpdate, MAX_DIRECT_PATHS,
};
pub use error::{MultiaddrError, PeerAddrError};
pub use external_addresses::{
    ExternalAddress, ExternalAddressBook, ExternalAddressSource, ExternalAddressUpdate,
    MAX_EXTERNAL_ADDRS,
};
pub use minip2p_identity::PeerId;
pub use minip2p_identity::{VarintError, read_uvarint, uvarint_len, write_uvarint};
pub use multiaddr::Multiaddr;
pub use peer_addr::PeerAddr;
pub use protocol::Protocol;
