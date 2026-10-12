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

use minip2p_core::{FrameExchange, FrameFault};

pub use client::{
    ConnectOutcome, HopConnect, HopConnectOutput, HopReservation, HopReservationOutput,
    ReservationOutcome, StopConnectRequest, StopResponder, StopResponderOutput,
};
pub(crate) use message::describe_status;
pub use message::{
    FrameDecode, HopMessage, HopMessageType, Limit, Peer, RelayMessageError, Reservation, Status,
    StopMessage, StopMessageType, decode_frame, encode_frame,
};
pub use server::{
    HopRequest, HopResponder, HopResponderOutput, StopInitiator, StopInitiatorOutcome,
    StopInitiatorOutput,
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

/// Maximum application payload retained with a HOP or STOP CONNECT while its
/// service decision is pending: 64 KiB.
///
/// This is a pre-authorization memory bound, not a circuit data limit. Once a
/// CONNECT is accepted, bridge data is streamed without this restriction.
pub const MAX_PENDING_BRIDGE_SIZE: usize = 64 * 1024;

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
    /// Stream input arrived while a relay-side service decision was pending.
    ///
    /// The driver must pause reads after receiving a relay request and resume
    /// them only after providing the accept or reject decision.
    #[error("relay stream input must pause while a service decision is pending")]
    DecisionPending,
    /// CONNECT payload coalesced before authorization exceeded the memory cap.
    #[error(
        "pending relay bridge payload exceeds maximum size ({len} > {MAX_PENDING_BRIDGE_SIZE})"
    )]
    PendingBridgeTooLarge { len: usize },
}

impl From<FrameFault> for RelayError {
    fn from(fault: FrameFault) -> Self {
        match fault {
            FrameFault::TooLarge { len, .. } => Self::FrameTooLarge { len },
            FrameFault::Overflow { len, .. } => Self::MessageTooLarge { len },
            FrameFault::Wire(e) => Self::Malformed(e.into()),
        }
    }
}

/// The frame exchange every relay machine reads its handshake through.
///
/// Bytes behind the handshake frame are not the exchange's to bound: once
/// the circuit is established they are bridged traffic, which streams
/// without the control-frame limit, and the server roles cap what they hold
/// before a decision with [`MAX_PENDING_BRIDGE_SIZE`] themselves. Every
/// machine decodes as soon as it buffers, so the receive buffer never holds
/// more than one incomplete frame plus the read that completes it.
pub(crate) fn handshake_frames() -> FrameExchange {
    FrameExchange::with_trailing(MAX_MESSAGE_SIZE, usize::MAX)
}

/// Queues an outbound control frame, refusing a payload over
/// [`MAX_MESSAGE_SIZE`] as [`RelayError::MessageTooLarge`].
pub(crate) fn queue_control(frames: &mut FrameExchange, payload: &[u8]) -> Result<(), RelayError> {
    frames.queue(payload).map_err(|fault| match fault {
        FrameFault::TooLarge { .. } => RelayError::MessageTooLarge { len: payload.len() },
        other => other.into(),
    })
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
