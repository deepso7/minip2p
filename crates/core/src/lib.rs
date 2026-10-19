//! Transport-agnostic address primitives for minip2p.
//!
//! Provides [`Multiaddr`] parsing/formatting (including WebTransport
//! `/certhash` components), [`PeerAddr`] for validated
//! transport + peer id addresses, [`ConnectId`] for Connection-attempt
//! correlation, a connection's [`Path`], the [`Protocol`] enum, the
//! varint-length-prefixed frame codec, the shared protobuf field codec used
//! by protocol crates, and the shared stream payload type [`Bytes`]. The
//! [`platform`] module holds the clock, deadline, and entropy contracts every
//! caller-driven component uses.
//! `no_std` + `alloc` compatible.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod candidates;
mod certhash;
mod connect_id;
mod error;
mod exchange;
mod frame;
mod multiaddr;
mod path;
mod payload;
mod peer_addr;
pub mod platform;
mod protobuf;
mod protocol;

/// Shared, cheaply cloneable stream payload (ADR 0011).
///
/// Every stream read and write carries one, so fan-out and forwarding clone a
/// handle instead of the bytes. Wire decoders keep borrowing `&[u8]`.
pub use bytes::Bytes;
pub use candidates::select_direct_addrs;
pub use connect_id::ConnectId;
pub use error::{CerthashError, MultiaddrError, PeerAddrError};
pub use exchange::{FrameExchange, FrameFault};
pub use frame::{FrameDecode, decode_frame, encode_frame};
pub use minip2p_identity::{Multihash, PeerId};
pub use minip2p_identity::{VarintError, read_uvarint, uvarint_len, write_uvarint};
pub use multiaddr::{Multiaddr, TransportKind};
pub use path::Path;
pub use payload::retain_slice;
pub use peer_addr::PeerAddr;
pub use protobuf::{
    WIRE_I32, WIRE_I64, WIRE_LEN, WIRE_VARINT, WireError, encode_bytes_field, encode_varint_field,
    read_len_delimited, read_string, read_tag, read_varint_value, skip_field, tag_byte, write_tag,
};
pub use protocol::Protocol;
