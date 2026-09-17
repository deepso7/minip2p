//! Transport-agnostic address primitives for minip2p.
//!
//! Provides [`Multiaddr`] parsing/formatting, [`PeerAddr`] for validated
//! transport + peer id addresses, the [`Protocol`] enum, the
//! varint-length-prefixed frame codec, and the shared protobuf field codec
//! used by protocol crates. `no_std` + `alloc` compatible.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod candidates;
mod error;
mod frame;
mod multiaddr;
mod peer_addr;
mod protobuf;
mod protocol;
mod sans_io;

pub use candidates::select_direct_addrs;
pub use error::{MultiaddrError, PeerAddrError};
pub use frame::{FrameDecode, decode_frame, encode_frame};
pub use minip2p_identity::PeerId;
pub use minip2p_identity::{VarintError, read_uvarint, uvarint_len, write_uvarint};
pub use multiaddr::{Multiaddr, TransportKind};
pub use peer_addr::PeerAddr;
pub use protobuf::{
    WIRE_I32, WIRE_I64, WIRE_LEN, WIRE_VARINT, WireError, encode_bytes_field, encode_nested_field,
    encode_varint_field, read_len_delimited, read_string, read_tag, read_varint_value, skip_field,
    tag_byte, write_tag,
};
pub use protocol::Protocol;
pub use sans_io::SansIoProtocol;
