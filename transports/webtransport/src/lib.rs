//! Sans-I/O HTTP/3 and QPACK codec for libp2p WebTransport.
//!
//! This crate holds the wire codec that the QUIC WebTransport listener and
//! the native test client share, and the client side of libp2p WebTransport. It owns no streams and no sockets: callers
//! feed the bytes of one QUIC stream into a decoder and get back frames,
//! stream headers or capsules, or "need more" (`None`).
//!
//! - [`h3`]: QUIC varints, HTTP/3 frames and SETTINGS, stream headers
//!   (including the WebTransport `0x41` / `0x54` prefixes), capsules, and the
//!   WebTransport ↔ HTTP/3 error-code mapping.
//! - [`qpack`]: a static-table-only QPACK decoder (with Huffman) bounded by
//!   decoded-size caps, and a minimal encoder.
//!
//! - [`WebTransportIo`]: the seam to a platform's WebTransport API (in a
//!   browser, TypeScript around the `WebTransport` object), and
//!   [`WebTransportClient`], the libp2p WebTransport dialer over it.
//!
//! Every decoder is bounded by explicit caps, so a peer cannot make it
//! allocate more than a few KiB before authentication. `no_std` + `alloc`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod client;
mod error;
pub mod h3;
mod io;
mod limits;
pub mod qpack;

pub use client::{LIBP2P_WEBTRANSPORT_PATH, WebTransportClient, webtransport_url};
pub use error::{Error, VarIntTooLarge};
pub use io::{IoError, IoEvent, SessionHandle, StreamHandle, WebTransportIo};
pub use limits::WebTransportLimits;
