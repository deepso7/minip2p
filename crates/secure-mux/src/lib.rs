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
//! drain [`SessionOutput`] events with [`SecureMuxSession::poll_output`],
//! and pull bytes for that stream with [`SecureMuxSession::poll_write`] while
//! it has room -- frames are encrypted only when pulled, so a full downstream
//! is backpressure rather than growing buffers. After the upgrade,
//! [`SecureMuxSession::poll`] / [`SecureMuxSession::next_deadline`] drive
//! Yamux keepalive from the host's time sample; a peer that stops answering
//! fails the session with [`YamuxError::KeepaliveTimeout`]. `no_std + alloc`.
//!
//! The Noise XX and Yamux state machines it drives are public as the
//! [`noise`] and [`yamux`] modules.
//!
//! # Memory budgets
//!
//! An owner with a memory budget (ADR 0021) passes its ledger to
//! [`SecureMuxSession::handle_input_within`] and
//! [`SecureMuxSession::open_stream_within`], which reserve each substream's
//! receive window before any state exists for it, and releases one window
//! for each stream [`SecureMuxSession::take_settled_streams`] reports. The
//! session's own retained storage is
//! [`SecureMuxSession::fixed_reservation_bytes`].
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

pub mod noise;
mod session;
pub mod yamux;

pub use session::{
    KEEPALIVE_ACK_TIMEOUT_MS, KEEPALIVE_HANDOFF_TIMEOUT_MS, KEEPALIVE_INTERVAL_MS, MAX_INPUT_BATCH,
    NOISE_WIRE_FRAME, SecureMuxSession, SessionConfig, SessionError, SessionOutput, SessionRole,
    YamuxConfig, YamuxError,
};
