//! Transport-agnostic address primitives for minip2p.
//!
//! Provides [`Multiaddr`] parsing/formatting, [`PeerAddr`] for validated
//! transport + peer id addresses, the [`Protocol`] enum, and the
//! varint-length-prefixed frame codec shared by the protocol crates.
//! `no_std` + `alloc` compatible.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod candidates;
mod error;
mod frame;
mod multiaddr;
mod peer_addr;
mod protocol;
mod sans_io;

pub use candidates::select_direct_addrs;
pub use error::{MultiaddrError, PeerAddrError};
pub use frame::{FrameDecode, decode_frame, encode_frame};
pub use minip2p_identity::PeerId;
pub use minip2p_identity::{VarintError, read_uvarint, uvarint_len, write_uvarint};
pub use multiaddr::Multiaddr;
pub use peer_addr::PeerAddr;
pub use protocol::Protocol;
pub use sans_io::SansIoProtocol;
