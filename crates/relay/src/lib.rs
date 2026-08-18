//! Sans-I/O state machines for the Circuit Relay v2 wire protocols.
//!
//! Client roles are [`HopReservation`], [`HopConnect`], and [`StopResponder`].
//! Relay-side roles are [`HopResponder`] and [`StopInitiator`]. Each machine
//! owns one HOP or STOP stream; reservation policy, clocks, admission, and
//! forwarding remain the caller's responsibility.
//!
//! Well-framed semantic violations receive a deterministic relay status and a
//! local write close. Invalid framing and oversized declarations request a
//! reset. Accepted CONNECT handshakes retain any application payload pipelined
//! behind the final control frame.
//!
//! Every control frame uses an 8 KiB payload limit. This is a deliberate
//! minip2p extension over rust-libp2p's 4 KiB relay codec limit.
//!
//! `no_std` + `alloc` compatible.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod client;
mod message;
mod server;

use alloc::string::String;
use alloc::vec::Vec;

pub use client::{
    ConnectOutcome, HopConnect, HopConnectInput, HopConnectOutput, HopReservation,
    HopReservationInput, HopReservationOutput, ReservationOutcome, StopConnectRequest,
    StopResponder, StopResponderInput, StopResponderOutput,
};
pub(crate) use message::describe_status;
pub use message::{
    FrameDecode, HopMessage, HopMessageType, Limit, Peer, RelayMessageError, Reservation, Status,
    StopMessage, StopMessageType, decode_frame, encode_frame,
};
pub use server::{
    HopRequest, HopResponder, HopResponderInput, HopResponderOutput, StopInitiator,
    StopInitiatorInput, StopInitiatorOutcome, StopInitiatorOutput,
};

/// Protocol ID for the HOP subprotocol (client ↔ relay).
pub const HOP_PROTOCOL_ID: &str = "/libp2p/circuit/relay/0.2.0/hop";
/// Protocol ID for the STOP subprotocol (relay ↔ destination).
pub const STOP_PROTOCOL_ID: &str = "/libp2p/circuit/relay/0.2.0/stop";

/// Maximum protobuf payload size for every relay control frame: 8 KiB.
///
/// A frame with exactly this payload size is accepted. Larger declarations
/// are protocol violations and cause relay-side machines to request a reset.
pub const MAX_MESSAGE_SIZE: usize = 8192;

/// Errors returned for invalid local machine use or client-side wire failures.
///
/// Relay-side wire failures are normally represented by status, close, or
/// reset outputs so callers can execute their deterministic terminal action.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RelayError {
    /// A message exceeded the maximum allowed size.
    #[error("relay message exceeds maximum size ({len} > {MAX_MESSAGE_SIZE})")]
    MessageTooLarge { len: usize },
    /// The remote declared a frame length exceeding the maximum allowed size.
    #[error("relay frame length exceeds maximum size ({len} > {MAX_MESSAGE_SIZE})")]
    FrameTooLarge { len: u64 },
    /// An incoming message failed to decode.
    #[error("malformed relay message: {0}")]
    Malformed(#[from] RelayMessageError),
    /// An input or wire message was invalid for the current state.
    #[error("unexpected message: {0}")]
    UnexpectedMessage(String),
}

/// Longest length prefix a legal frame can carry.
pub(crate) const MAX_FRAME_PREFIX_LEN: usize = 2;

pub(crate) fn enforce_max_size(buf: &[u8]) -> Result<(), RelayError> {
    if buf.len() > MAX_MESSAGE_SIZE + MAX_FRAME_PREFIX_LEN {
        return Err(RelayError::MessageTooLarge { len: buf.len() });
    }
    Ok(())
}

pub(crate) fn checked_outbound_frame(payload: &[u8]) -> Result<Vec<u8>, RelayError> {
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(RelayError::MessageTooLarge { len: payload.len() });
    }
    Ok(encode_frame(payload))
}

/// Encodes a bounded HOP `STATUS` control frame.
///
/// Returns [`RelayError::MessageTooLarge`] when reservation metadata pushes
/// the protobuf payload over [`MAX_MESSAGE_SIZE`].
pub fn encode_hop_status(
    status: Status,
    reservation: Option<Reservation>,
    limit: Option<Limit>,
) -> Result<Vec<u8>, RelayError> {
    checked_outbound_frame(
        &HopMessage {
            kind: HopMessageType::Status,
            peer: None,
            reservation,
            limit,
            status: Some(status),
        }
        .encode(),
    )
}

/// Encodes a bounded STOP `STATUS` control frame.
///
/// The fixed-size status frame always fits; the `Result` keeps the helper's
/// contract aligned with [`encode_hop_status`].
pub fn encode_stop_status(status: Status) -> Result<Vec<u8>, RelayError> {
    checked_outbound_frame(
        &StopMessage {
            kind: StopMessageType::Status,
            peer: None,
            limit: None,
            status: Some(status),
        }
        .encode(),
    )
}
