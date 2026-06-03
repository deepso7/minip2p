//! Transport-agnostic address primitives for minip2p.
//!
//! Provides [`Multiaddr`] parsing/formatting, [`PeerAddr`] for validated
//! transport + peer id addresses, and the [`Protocol`] enum. `no_std` + `alloc`
//! compatible.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod candidates;
mod error;
mod multiaddr;
mod peer_addr;
mod protocol;
mod sans_io;

pub use candidates::{
    DirectCandidate, DirectCandidateRejectReason, DirectCandidateRejection,
    DirectCandidateSelection, DirectCandidateSource, select_direct_candidates,
};
pub use error::{MultiaddrError, PeerAddrError};
pub use minip2p_identity::PeerId;
pub use minip2p_identity::{VarintError, read_uvarint, uvarint_len, write_uvarint};
pub use multiaddr::Multiaddr;
pub use peer_addr::PeerAddr;
pub use protocol::Protocol;
pub use sans_io::SansIo;
