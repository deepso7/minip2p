//! Sans-I/O secure, multiplexed session over an ordered byte stream.
//!
//! Drives the libp2p upgrade stack that every stream-oriented transport needs:
//!
//! ```text
//! ordered byte stream
//!   -> multistream-select  (/noise)
//!   -> Noise XX            (authenticates the remote peer)
//!   -> multistream-select  (/yamux/1.0.0, encrypted)
//!   -> Yamux               (libp2p substreams)
//! ```
//!
//! The session owns no socket, no clock, and no executor. Callers feed it
//! bytes read from the underlying stream with [`SecureMuxSession::handle_input`]
//! and drain [`SessionOutput`] values with
//! [`SecureMuxSession::poll_output`], writing every
//! [`SessionOutput::Write`] back to that stream. After the upgrade,
//! [`SecureMuxSession::poll`] / [`SecureMuxSession::next_deadline`] drive
//! Yamux keepalive from the host's time sample. `no_std + alloc`.
//!
//! Relay circuits and TCP connections differ only in what the byte stream is,
//! so both drive this same component rather than duplicating the state
//! machine.
//!
//! # Policy stays with the caller
//!
//! The session reports [`SessionOutput::Established`] once Yamux is up and the
//! remote identity is verified. It does not decide whether the connection
//! should be kept: a host that races a direct dial against a relayed one, or
//! that de-duplicates connections per peer, applies that policy when it drains
//! `Established` and tears the session down if it loses.
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

extern crate alloc;

mod session;

pub use session::{
    KEEPALIVE_INTERVAL_MS, SecureMuxSession, SessionConfig, SessionError, SessionOutput,
    SessionRole, YamuxConfig, YamuxError,
};
