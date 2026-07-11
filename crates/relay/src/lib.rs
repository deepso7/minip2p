//! Sans-IO state machines for Circuit Relay v2.
//!
//! Implements three client-side flows:
//! - [`HopReservation`] -- reserve a slot on a relay (client -> relay).
//! - [`HopConnect`] -- ask a relay to connect us to another peer (client -> relay).
//! - [`StopResponder`] -- accept an incoming circuit from a relay (relay -> us).
//!
//! Each state machine is driven through [`SansIoProtocol`]: callers feed
//! role-specific input enums, drain output enums, and execute outbound bytes
//! against the underlying transport stream. No I/O is performed inside.
//!
//! `no_std` + `alloc` compatible.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod message;

use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::SansIoProtocol;

pub use message::{
    FrameDecode, HopMessage, HopMessageType, Limit, Peer, RelayMessageError, Reservation, Status,
    StopMessage, StopMessageType, decode_frame, describe_status, encode_frame,
};

/// Protocol id for the HOP subprotocol (client <-> relay).
pub const HOP_PROTOCOL_ID: &str = "/libp2p/circuit/relay/0.2.0/hop";
/// Protocol id for the STOP subprotocol (relay <-> destination).
pub const STOP_PROTOCOL_ID: &str = "/libp2p/circuit/relay/0.2.0/stop";

/// Maximum size for a single incoming relay message (8 KiB).
///
/// Messages larger than this are rejected as a protocol violation.
pub const MAX_MESSAGE_SIZE: usize = 8192;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by relay state machines.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RelayError {
    /// A message exceeded the maximum allowed size. This covers both
    /// incoming data and locally constructed outbound messages: a frame
    /// this crate's own decoder would reject is never queued for sending.
    #[error("relay message exceeds maximum size ({len} > {MAX_MESSAGE_SIZE})")]
    MessageTooLarge { len: usize },
    /// The remote declared a frame length exceeding the maximum allowed size.
    #[error("relay frame length exceeds maximum size ({len} > {MAX_MESSAGE_SIZE})")]
    FrameTooLarge { len: u64 },
    /// An incoming message failed to decode.
    #[error("malformed relay message: {0}")]
    Malformed(#[from] RelayMessageError),
    /// The remote peer sent a message of an unexpected kind for the current state.
    #[error("unexpected message: {0}")]
    UnexpectedMessage(String),
}

// ---------------------------------------------------------------------------
// HopReservation: RESERVE flow (client -> relay)
// ---------------------------------------------------------------------------

/// Outcome of a RESERVE exchange with a relay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReservationOutcome {
    /// The relay accepted the reservation.
    Accepted {
        /// Reservation details (expire, addrs, voucher) if provided.
        reservation: Option<Reservation>,
        /// Connection limits (duration, data) if provided.
        limit: Option<Limit>,
    },
    /// The relay rejected the reservation.
    Refused {
        /// The status code returned by the relay.
        status: Status,
        /// Human-readable reason for logging.
        reason: String,
    },
}

/// Input accepted by [`HopReservation`] through [`SansIoProtocol`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HopReservationInput {
    /// Drain queued RESERVE bytes into an output.
    Flush,
    /// Bytes received from the relay stream.
    Data(Vec<u8>),
    /// Remote write side closed.
    RemoteWriteClosed,
}

/// Output produced by [`HopReservation`] through [`SansIoProtocol`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HopReservationOutput {
    /// Bytes to write to the relay stream.
    Outbound(Vec<u8>),
    /// Reservation result decoded from the relay response.
    Outcome(ReservationOutcome),
}

/// Client-side state machine for the HOP RESERVE flow.
///
/// Usage:
/// 1. Construct with [`HopReservation::new`].
/// 2. Drain [`HopReservationOutput::Outbound`] from
///    [`SansIoProtocol::poll_output`] and send the bytes on the relay stream.
/// 3. Feed incoming stream bytes with [`HopReservationInput::Data`].
/// 4. Drain [`HopReservationOutput::Outcome`] to observe accepted/refused
///    completion.
pub struct HopReservation {
    outbound: Vec<u8>,
    recv_buf: Vec<u8>,
    state: FlowState,
    outcome: Option<ReservationOutcome>,
    emitted_outcome: bool,
}

/// Common flow states for client-initiated request/response exchanges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlowState {
    /// Request pending; nothing sent yet.
    Pending,
    /// Request sent; waiting for a STATUS response frame.
    AwaitingResponse,
    /// Flow completed (success or failure). No further work.
    Done,
}

impl HopReservation {
    /// Creates a new reservation state machine and queues the RESERVE message.
    pub fn new() -> Self {
        // The RESERVE request has no variable-length fields, so its encoded
        // frame is structurally far below MAX_MESSAGE_SIZE; no outbound size
        // check is needed here.
        let request = HopMessage {
            kind: HopMessageType::Reserve,
            peer: None,
            reservation: None,
            limit: None,
            status: None,
        };
        let body = request.encode();
        let outbound = encode_frame(&body);

        Self {
            outbound,
            recv_buf: Vec::new(),
            state: FlowState::Pending,
            outcome: None,
            emitted_outcome: false,
        }
    }

    /// Drains and returns any pending outbound bytes.
    ///
    /// Call this after construction and whenever you need to flush data to
    /// the relay stream.
    fn take_outbound(&mut self) -> Vec<u8> {
        if self.state == FlowState::Pending {
            self.state = FlowState::AwaitingResponse;
        }
        core::mem::take(&mut self.outbound)
    }

    /// Feeds incoming stream bytes from the relay.
    fn on_data(&mut self, data: &[u8]) -> Result<(), RelayError> {
        if self.state == FlowState::Done {
            return Ok(());
        }

        self.recv_buf.extend_from_slice(data);
        self.try_decode_response()
    }

    /// Notifies the state machine that the remote closed its write side.
    ///
    /// If a complete response has not yet been decoded, this is not itself
    /// an error -- callers can still receive partial buffered data.
    fn on_remote_write_closed(&mut self) -> Result<(), RelayError> {
        self.try_decode_response()
    }

    /// Returns the outcome of the flow, if available.
    #[cfg(test)]
    fn outcome(&self) -> Option<&ReservationOutcome> {
        self.outcome.as_ref()
    }

    /// Returns `true` if the flow has completed.
    pub fn is_done(&self) -> bool {
        self.state == FlowState::Done
    }

    /// Attempts to decode the response frame from the receive buffer.
    fn try_decode_response(&mut self) -> Result<(), RelayError> {
        if self.state == FlowState::Done {
            return Ok(());
        }

        enforce_max_size(&self.recv_buf).inspect_err(|_| {
            self.state = FlowState::Done;
        })?;

        let (msg, consumed) = match decode_frame(&self.recv_buf) {
            FrameDecode::Complete { payload, consumed } => {
                let msg = HopMessage::decode(payload).map_err(|e| {
                    self.state = FlowState::Done;
                    RelayError::Malformed(e)
                })?;
                (msg, consumed)
            }
            FrameDecode::Incomplete => return Ok(()),
            FrameDecode::TooLarge { len } => {
                self.state = FlowState::Done;
                return Err(RelayError::FrameTooLarge { len });
            }
            FrameDecode::Error(e) => {
                self.state = FlowState::Done;
                return Err(RelayError::Malformed(RelayMessageError::Varint(e)));
            }
        };
        self.recv_buf.drain(..consumed);

        if msg.kind != HopMessageType::Status {
            self.state = FlowState::Done;
            return Err(RelayError::UnexpectedMessage(unexpected_hop_reason(
                msg.kind, "STATUS",
            )));
        }

        let status = msg.status.unwrap_or(Status::Unused);
        self.state = FlowState::Done;

        self.outcome = Some(if status == Status::Ok {
            ReservationOutcome::Accepted {
                reservation: msg.reservation,
                limit: msg.limit,
            }
        } else {
            ReservationOutcome::Refused {
                status,
                reason: describe_status(status),
            }
        });
        self.emitted_outcome = false;

        Ok(())
    }
}

impl SansIoProtocol for HopReservation {
    type Input = HopReservationInput;
    type Output = HopReservationOutput;
    type Error = RelayError;

    fn handle_input(&mut self, input: Self::Input) -> Result<(), Self::Error> {
        match input {
            HopReservationInput::Flush => {}
            HopReservationInput::Data(data) => self.on_data(&data)?,
            HopReservationInput::RemoteWriteClosed => self.on_remote_write_closed()?,
        }
        Ok(())
    }

    fn poll_output(&mut self) -> Option<Self::Output> {
        let outbound = self.take_outbound();
        if !outbound.is_empty() {
            return Some(HopReservationOutput::Outbound(outbound));
        }
        if !self.emitted_outcome
            && let Some(outcome) = self.outcome.clone()
        {
            self.emitted_outcome = true;
            return Some(HopReservationOutput::Outcome(outcome));
        }
        None
    }

    fn is_idle(&self) -> bool {
        self.outbound.is_empty() && (self.emitted_outcome || self.outcome.is_none())
    }
}

impl Default for HopReservation {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// HopConnect: CONNECT flow (client -> relay)
// ---------------------------------------------------------------------------

/// Outcome of a CONNECT exchange with a relay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectOutcome {
    /// The relay accepted the connection and bridged the stream.
    ///
    /// Any further bytes received on this stream are the relayed data from
    /// the target peer.
    Bridged {
        /// Connection limits (duration, data) if provided by the relay.
        limit: Option<Limit>,
    },
    /// The relay refused to establish the circuit.
    Refused { status: Status, reason: String },
}

/// Input accepted by [`HopConnect`] through [`SansIoProtocol`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HopConnectInput {
    /// Drain queued CONNECT bytes into an output.
    Flush,
    /// Bytes received from the relay stream.
    Data(Vec<u8>),
    /// Remote write side closed.
    RemoteWriteClosed,
}

/// Output produced by [`HopConnect`] through [`SansIoProtocol`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HopConnectOutput {
    /// Bytes to write to the relay stream.
    Outbound(Vec<u8>),
    /// CONNECT result decoded from the relay response.
    Outcome(ConnectOutcome),
    /// Bytes received after the relay circuit was bridged.
    BridgeData(Vec<u8>),
}

/// Client-side state machine for the HOP CONNECT flow.
///
/// Usage:
/// 1. Construct with [`HopConnect::new`], passing the target peer's id.
/// 2. Drain [`HopConnectOutput::Outbound`] from
///    [`SansIoProtocol::poll_output`] and send the bytes.
/// 3. Feed incoming stream bytes with [`HopConnectInput::Data`].
/// 4. When [`HopConnectOutput::Outcome`] returns `ConnectOutcome::Bridged`,
///    the stream becomes the relay circuit; drain
///    [`HopConnectOutput::BridgeData`] for any pipelined peer-to-peer bytes.
pub struct HopConnect {
    outbound: Vec<u8>,
    recv_buf: Vec<u8>,
    state: FlowState,
    outcome: Option<ConnectOutcome>,
    emitted_outcome: bool,
    bridge_bytes: Vec<u8>,
    /// Deferred construction error (oversized CONNECT), surfaced by the
    /// first [`SansIoProtocol::handle_input`] call.
    pending_error: Option<RelayError>,
}

impl HopConnect {
    /// Creates a new CONNECT state machine targeting the given peer id.
    ///
    /// `target_peer_id` should be the multihash-encoded PeerId bytes.
    ///
    /// If the encoded CONNECT would exceed [`MAX_MESSAGE_SIZE`] -- a frame
    /// any hardened relay (including this crate's own decoder) would
    /// reject -- no bytes are queued and the first
    /// [`SansIoProtocol::handle_input`] call fails with
    /// [`RelayError::MessageTooLarge`].
    pub fn new(target_peer_id: Vec<u8>) -> Self {
        let request = HopMessage {
            kind: HopMessageType::Connect,
            peer: Some(Peer {
                id: target_peer_id,
                addrs: Vec::new(),
            }),
            reservation: None,
            limit: None,
            status: None,
        };
        let (outbound, state, pending_error) = match checked_outbound_frame(&request.encode()) {
            Ok(frame) => (frame, FlowState::Pending, None),
            Err(err) => (Vec::new(), FlowState::Done, Some(err)),
        };

        Self {
            outbound,
            recv_buf: Vec::new(),
            state,
            outcome: None,
            emitted_outcome: false,
            bridge_bytes: Vec::new(),
            pending_error,
        }
    }

    /// Drains and returns any pending outbound bytes.
    fn take_outbound(&mut self) -> Vec<u8> {
        if self.state == FlowState::Pending {
            self.state = FlowState::AwaitingResponse;
        }
        core::mem::take(&mut self.outbound)
    }

    /// Feeds incoming stream bytes from the relay.
    ///
    /// After the CONNECT is accepted, any further bytes passed here are
    /// buffered as bridged relay traffic; drain them with
    /// [`HopConnect::take_bridge_bytes`].
    fn on_data(&mut self, data: &[u8]) -> Result<(), RelayError> {
        if self.state == FlowState::Done {
            // Already bridged or errored — any further bytes belong to the
            // bridged channel (or are garbage after an error).
            if matches!(self.outcome, Some(ConnectOutcome::Bridged { .. })) {
                self.bridge_bytes.extend_from_slice(data);
            }
            return Ok(());
        }

        self.recv_buf.extend_from_slice(data);
        self.try_decode_response()
    }

    /// Notifies the state machine that the remote closed its write side.
    fn on_remote_write_closed(&mut self) -> Result<(), RelayError> {
        self.try_decode_response()
    }

    /// Returns the outcome of the flow, if available.
    #[cfg(test)]
    fn outcome(&self) -> Option<&ConnectOutcome> {
        self.outcome.as_ref()
    }

    /// Returns `true` if the flow has completed.
    pub fn is_done(&self) -> bool {
        self.state == FlowState::Done
    }

    /// Drains any bridged relay traffic received since the last call.
    ///
    /// Only yields bytes after the flow transitions to `Bridged`.
    fn take_bridge_bytes(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.bridge_bytes)
    }

    /// Attempts to decode the response from the receive buffer.
    fn try_decode_response(&mut self) -> Result<(), RelayError> {
        if self.state == FlowState::Done {
            return Ok(());
        }

        enforce_max_size(&self.recv_buf).inspect_err(|_| {
            self.state = FlowState::Done;
        })?;

        let (msg, consumed) = match decode_frame(&self.recv_buf) {
            FrameDecode::Complete { payload, consumed } => {
                let msg = HopMessage::decode(payload).map_err(|e| {
                    self.state = FlowState::Done;
                    RelayError::Malformed(e)
                })?;
                (msg, consumed)
            }
            FrameDecode::Incomplete => return Ok(()),
            FrameDecode::TooLarge { len } => {
                self.state = FlowState::Done;
                return Err(RelayError::FrameTooLarge { len });
            }
            FrameDecode::Error(e) => {
                self.state = FlowState::Done;
                return Err(RelayError::Malformed(RelayMessageError::Varint(e)));
            }
        };
        self.recv_buf.drain(..consumed);

        if msg.kind != HopMessageType::Status {
            self.state = FlowState::Done;
            return Err(RelayError::UnexpectedMessage(unexpected_hop_reason(
                msg.kind, "STATUS",
            )));
        }

        let status = msg.status.unwrap_or(Status::Unused);
        self.state = FlowState::Done;

        self.outcome = Some(if status == Status::Ok {
            // Any bytes buffered after the STATUS frame belong to the bridged
            // stream. This catches the case where the relay pipelines the
            // first bytes of the bridged connection into the same packet.
            if !self.recv_buf.is_empty() {
                self.bridge_bytes.append(&mut self.recv_buf);
            }
            ConnectOutcome::Bridged { limit: msg.limit }
        } else {
            ConnectOutcome::Refused {
                status,
                reason: describe_status(status),
            }
        });
        self.emitted_outcome = false;

        Ok(())
    }
}

impl SansIoProtocol for HopConnect {
    type Input = HopConnectInput;
    type Output = HopConnectOutput;
    type Error = RelayError;

    fn handle_input(&mut self, input: Self::Input) -> Result<(), Self::Error> {
        if let Some(err) = self.pending_error.take() {
            return Err(err);
        }
        match input {
            HopConnectInput::Flush => {}
            HopConnectInput::Data(data) => self.on_data(&data)?,
            HopConnectInput::RemoteWriteClosed => self.on_remote_write_closed()?,
        }
        Ok(())
    }

    fn poll_output(&mut self) -> Option<Self::Output> {
        let outbound = self.take_outbound();
        if !outbound.is_empty() {
            return Some(HopConnectOutput::Outbound(outbound));
        }
        if !self.emitted_outcome
            && let Some(outcome) = self.outcome.clone()
        {
            self.emitted_outcome = true;
            return Some(HopConnectOutput::Outcome(outcome));
        }
        let bridge_bytes = self.take_bridge_bytes();
        if !bridge_bytes.is_empty() {
            return Some(HopConnectOutput::BridgeData(bridge_bytes));
        }
        None
    }

    fn is_idle(&self) -> bool {
        self.pending_error.is_none()
            && self.outbound.is_empty()
            && self.bridge_bytes.is_empty()
            && (self.emitted_outcome || self.outcome.is_none())
    }
}

// ---------------------------------------------------------------------------
// StopResponder: incoming STOP CONNECT flow (relay -> us)
// ---------------------------------------------------------------------------

/// A STOP CONNECT request from a relay, waiting for acceptance or rejection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopConnectRequest {
    /// The peer the relay is bridging to us.
    pub source_peer_id: Vec<u8>,
    /// Connection limits, if any.
    pub limit: Option<Limit>,
}

/// Input accepted by [`StopResponder`] through [`SansIoProtocol`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StopResponderInput {
    /// Drain queued STATUS bytes into an output.
    Flush,
    /// Bytes received from the relay stream.
    Data(Vec<u8>),
    /// Remote write side closed.
    RemoteWriteClosed,
    /// Accept the pending CONNECT request.
    Accept,
    /// Reject the pending CONNECT request with a status.
    Reject(Status),
}

/// Output produced by [`StopResponder`] through [`SansIoProtocol`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StopResponderOutput {
    /// Decoded CONNECT request.
    Request(StopConnectRequest),
    /// Bytes to write to the relay stream.
    Outbound(Vec<u8>),
    /// Bytes received after the relay circuit was bridged.
    BridgeData(Vec<u8>),
}

/// Server-side state machine for the STOP protocol (we are the destination).
///
/// Flow:
/// 1. Relay opens a STOP stream to us and sends a CONNECT message.
/// 2. Feed bytes with [`StopResponderInput::Data`] and drain
///    [`StopResponderOutput::Request`].
/// 3. Decide to accept or reject with [`StopResponderInput::Accept`] or
///    [`StopResponderInput::Reject`].
/// 4. Send resulting [`StopResponderOutput::Outbound`] bytes to the relay.
/// 5. If accepted, the stream becomes the bridged circuit; drain
///    [`StopResponderOutput::BridgeData`] for any pipelined bytes.
pub struct StopResponder {
    outbound: Vec<u8>,
    recv_buf: Vec<u8>,
    state: StopState,
    request: Option<StopConnectRequest>,
    emitted_request: bool,
    bridge_bytes: Vec<u8>,
}

/// State progression for a STOP responder flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StopState {
    /// Waiting to receive CONNECT from the relay.
    AwaitingConnect,
    /// CONNECT received; waiting for the host to accept or reject.
    AwaitingDecision,
    /// Host responded; flow complete.
    Done,
    /// Bridged: subsequent bytes belong to the bridged circuit.
    Bridged,
}

impl StopResponder {
    /// Creates a new STOP responder waiting for a CONNECT frame.
    pub fn new() -> Self {
        Self {
            outbound: Vec::new(),
            recv_buf: Vec::new(),
            state: StopState::AwaitingConnect,
            request: None,
            emitted_request: false,
            bridge_bytes: Vec::new(),
        }
    }

    /// Drains and returns any pending outbound bytes.
    fn take_outbound(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outbound)
    }

    /// Feeds incoming stream bytes from the relay.
    fn on_data(&mut self, data: &[u8]) -> Result<(), RelayError> {
        if self.state == StopState::Bridged {
            self.bridge_bytes.extend_from_slice(data);
            return Ok(());
        }

        if self.state == StopState::Done {
            return Ok(());
        }

        self.recv_buf.extend_from_slice(data);
        self.try_decode_connect()
    }

    /// Notifies the state machine that the remote closed its write side.
    fn on_remote_write_closed(&mut self) -> Result<(), RelayError> {
        self.try_decode_connect()
    }

    /// Returns the decoded CONNECT request, if received.
    #[cfg(test)]
    fn request(&self) -> Option<&StopConnectRequest> {
        self.request.as_ref()
    }

    /// Returns `true` once a decision has been made and sent.
    pub fn is_done(&self) -> bool {
        matches!(self.state, StopState::Done | StopState::Bridged)
    }

    /// Accepts the CONNECT request, queuing a `STATUS: OK` response.
    ///
    /// After this, the stream becomes the bridged circuit; any further bytes
    /// received from the relay are queued into [`StopResponder::take_bridge_bytes`].
    fn accept(&mut self) -> Result<(), RelayError> {
        self.send_status(Status::Ok, StopState::Bridged)?;
        // Any bytes the relay pipelined after its CONNECT belong to the bridge.
        if !self.recv_buf.is_empty() {
            self.bridge_bytes.append(&mut self.recv_buf);
        }
        Ok(())
    }

    /// Rejects the CONNECT request with the given status code.
    fn reject(&mut self, status: Status) -> Result<(), RelayError> {
        self.send_status(status, StopState::Done)
    }

    /// Drains any bridged relay traffic received since the last call.
    fn take_bridge_bytes(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.bridge_bytes)
    }

    /// Emits a StopMessage with `type = STATUS` and the given status code.
    fn send_status(&mut self, status: Status, next_state: StopState) -> Result<(), RelayError> {
        if self.state != StopState::AwaitingDecision {
            return Err(RelayError::UnexpectedMessage(alloc::format!(
                "cannot respond from state {:?}",
                self.state
            )));
        }

        // The STATUS response carries only fixed varint fields, so its
        // encoded frame is structurally far below MAX_MESSAGE_SIZE; no
        // outbound size check is needed here.
        let response = StopMessage {
            kind: StopMessageType::Status,
            peer: None,
            limit: None,
            status: Some(status),
        };
        let body = response.encode();
        self.outbound.extend(encode_frame(&body));
        self.state = next_state;
        Ok(())
    }

    /// Decodes the CONNECT request from the receive buffer.
    fn try_decode_connect(&mut self) -> Result<(), RelayError> {
        if self.state != StopState::AwaitingConnect {
            return Ok(());
        }

        enforce_max_size(&self.recv_buf).inspect_err(|_| {
            self.state = StopState::Done;
        })?;

        let (msg, consumed) = match decode_frame(&self.recv_buf) {
            FrameDecode::Complete { payload, consumed } => {
                let msg = StopMessage::decode(payload).map_err(|e| {
                    self.state = StopState::Done;
                    RelayError::Malformed(e)
                })?;
                (msg, consumed)
            }
            FrameDecode::Incomplete => return Ok(()),
            FrameDecode::TooLarge { len } => {
                self.state = StopState::Done;
                return Err(RelayError::FrameTooLarge { len });
            }
            FrameDecode::Error(e) => {
                self.state = StopState::Done;
                return Err(RelayError::Malformed(RelayMessageError::Varint(e)));
            }
        };
        self.recv_buf.drain(..consumed);

        if msg.kind != StopMessageType::Connect {
            self.state = StopState::Done;
            return Err(RelayError::UnexpectedMessage(unexpected_stop_reason(
                msg.kind, "CONNECT",
            )));
        }

        let peer = msg.peer.ok_or_else(|| {
            self.state = StopState::Done;
            RelayError::UnexpectedMessage(alloc::string::String::from(
                "STOP CONNECT missing peer field",
            ))
        })?;

        self.request = Some(StopConnectRequest {
            source_peer_id: peer.id,
            limit: msg.limit,
        });
        self.emitted_request = false;
        self.state = StopState::AwaitingDecision;

        Ok(())
    }
}

impl SansIoProtocol for StopResponder {
    type Input = StopResponderInput;
    type Output = StopResponderOutput;
    type Error = RelayError;

    fn handle_input(&mut self, input: Self::Input) -> Result<(), Self::Error> {
        match input {
            StopResponderInput::Flush => {}
            StopResponderInput::Data(data) => self.on_data(&data)?,
            StopResponderInput::RemoteWriteClosed => self.on_remote_write_closed()?,
            StopResponderInput::Accept => self.accept()?,
            StopResponderInput::Reject(status) => self.reject(status)?,
        }
        Ok(())
    }

    fn poll_output(&mut self) -> Option<Self::Output> {
        if !self.emitted_request
            && let Some(request) = self.request.clone()
        {
            self.emitted_request = true;
            return Some(StopResponderOutput::Request(request));
        }
        let outbound = self.take_outbound();
        if !outbound.is_empty() {
            return Some(StopResponderOutput::Outbound(outbound));
        }
        let bridge_bytes = self.take_bridge_bytes();
        if !bridge_bytes.is_empty() {
            return Some(StopResponderOutput::BridgeData(bridge_bytes));
        }
        None
    }

    fn is_idle(&self) -> bool {
        self.outbound.is_empty()
            && self.bridge_bytes.is_empty()
            && (self.emitted_request || self.request.is_none())
    }
}

impl Default for StopResponder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Rejects an oversized receive buffer to protect against memory exhaustion.
fn enforce_max_size(buf: &[u8]) -> Result<(), RelayError> {
    if buf.len() > MAX_MESSAGE_SIZE {
        return Err(RelayError::MessageTooLarge { len: buf.len() });
    }
    Ok(())
}

/// Encodes an outbound message payload as a length-prefixed frame,
/// rejecting payloads that exceed [`MAX_MESSAGE_SIZE`].
///
/// This mirrors the inbound limit enforced by [`decode_frame`]: the state
/// machines must never put a frame on the wire that a spec-compliant
/// receiver (including this crate's own decoder) would reject as oversized.
fn checked_outbound_frame(payload: &[u8]) -> Result<Vec<u8>, RelayError> {
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(RelayError::MessageTooLarge { len: payload.len() });
    }
    Ok(encode_frame(payload))
}

fn unexpected_hop_reason(actual: HopMessageType, expected: &str) -> String {
    use alloc::format;
    format!(
        "expected HOP message of type {expected} but got {:?}",
        actual
    )
}

fn unexpected_stop_reason(actual: StopMessageType, expected: &str) -> String {
    use alloc::format;
    format!(
        "expected STOP message of type {expected} but got {:?}",
        actual
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: encode a HopMessage as a length-prefixed frame.
    fn frame_hop(msg: HopMessage) -> Vec<u8> {
        encode_frame(&msg.encode())
    }

    /// Helper: encode a StopMessage as a length-prefixed frame.
    fn frame_stop(msg: StopMessage) -> Vec<u8> {
        encode_frame(&msg.encode())
    }

    // --- HopReservation -----------------------------------------------------

    #[test]
    fn reservation_sends_reserve_and_accepts_ok_response() {
        let mut flow = HopReservation::new();

        // Take and decode outbound.
        let outbound = flow.take_outbound();
        let FrameDecode::Complete { payload, .. } = decode_frame(&outbound) else {
            panic!("expected complete frame");
        };
        let req = HopMessage::decode(payload).unwrap();
        assert_eq!(req.kind, HopMessageType::Reserve);

        // Simulate relay response: STATUS:OK with reservation.
        let response = frame_hop(HopMessage {
            kind: HopMessageType::Status,
            peer: None,
            reservation: Some(Reservation {
                expire: Some(2_000_000_000),
                addrs: vec![vec![0x04, 1, 2, 3, 4]],
                voucher: None,
            }),
            limit: Some(Limit {
                duration: Some(900),
                data: Some(10_000_000),
            }),
            status: Some(Status::Ok),
        });
        flow.on_data(&response).unwrap();

        assert!(flow.is_done());
        match flow.outcome() {
            Some(ReservationOutcome::Accepted { reservation, limit }) => {
                assert_eq!(
                    reservation.as_ref().and_then(|r| r.expire),
                    Some(2_000_000_000)
                );
                assert_eq!(limit.as_ref().and_then(|l| l.duration), Some(900));
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn reservation_handles_refusal() {
        let mut flow = HopReservation::new();
        let _ = flow.take_outbound();

        let response = frame_hop(HopMessage {
            kind: HopMessageType::Status,
            peer: None,
            reservation: None,
            limit: None,
            status: Some(Status::ReservationRefused),
        });
        flow.on_data(&response).unwrap();

        match flow.outcome() {
            Some(ReservationOutcome::Refused { status, .. }) => {
                assert_eq!(*status, Status::ReservationRefused);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn reservation_handles_fragmented_response() {
        let mut flow = HopReservation::new();
        let _ = flow.take_outbound();

        let response = frame_hop(HopMessage {
            kind: HopMessageType::Status,
            peer: None,
            reservation: None,
            limit: None,
            status: Some(Status::Ok),
        });

        // Feed byte-by-byte.
        for byte in &response {
            flow.on_data(&[*byte]).unwrap();
        }

        assert!(flow.is_done());
        assert!(matches!(
            flow.outcome(),
            Some(ReservationOutcome::Accepted { .. })
        ));
    }

    #[test]
    fn reservation_rejects_wrong_response_type() {
        let mut flow = HopReservation::new();
        let _ = flow.take_outbound();

        let response = frame_hop(HopMessage {
            kind: HopMessageType::Connect,
            peer: None,
            reservation: None,
            limit: None,
            status: None,
        });
        let err = flow.on_data(&response).unwrap_err();
        assert!(matches!(err, RelayError::UnexpectedMessage(_)));
    }

    #[test]
    fn reservation_rejects_oversized_message() {
        let mut flow = HopReservation::new();
        let _ = flow.take_outbound();

        let large = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let err = flow.on_data(&large).unwrap_err();
        assert!(matches!(err, RelayError::MessageTooLarge { .. }));
    }

    #[test]
    fn reservation_rejects_oversized_declared_frame_length() {
        // A tiny header declaring an impossible payload length must fail
        // immediately instead of stalling while waiting for more bytes.
        let mut flow = HopReservation::new();
        let _ = flow.take_outbound();

        let mut header = Vec::new();
        minip2p_core::write_uvarint((MAX_MESSAGE_SIZE + 1) as u64, &mut header);
        let err = flow.on_data(&header).unwrap_err();
        assert!(matches!(err, RelayError::FrameTooLarge { .. }));
        assert!(flow.is_done());
    }

    // --- HopConnect ---------------------------------------------------------

    #[test]
    fn connect_sends_connect_and_bridges_on_ok() {
        let target = b"target-peer-id".to_vec();
        let mut flow = HopConnect::new(target.clone());

        // Outbound must be a CONNECT message with the target peer id.
        let outbound = flow.take_outbound();
        let FrameDecode::Complete { payload, .. } = decode_frame(&outbound) else {
            panic!();
        };
        let req = HopMessage::decode(payload).unwrap();
        assert_eq!(req.kind, HopMessageType::Connect);
        assert_eq!(req.peer.as_ref().map(|p| &p.id), Some(&target));

        // Relay accepts.
        let response = frame_hop(HopMessage {
            kind: HopMessageType::Status,
            peer: None,
            reservation: None,
            limit: None,
            status: Some(Status::Ok),
        });
        flow.on_data(&response).unwrap();

        assert!(matches!(
            flow.outcome(),
            Some(ConnectOutcome::Bridged { .. })
        ));
    }

    #[test]
    fn connect_pipelined_bridge_bytes_are_captured() {
        let mut flow = HopConnect::new(b"peer".to_vec());
        let _ = flow.take_outbound();

        let mut packet = frame_hop(HopMessage {
            kind: HopMessageType::Status,
            peer: None,
            reservation: None,
            limit: None,
            status: Some(Status::Ok),
        });
        packet.extend_from_slice(b"bridged-payload");
        flow.on_data(&packet).unwrap();

        assert!(matches!(
            flow.outcome(),
            Some(ConnectOutcome::Bridged { .. })
        ));
        assert_eq!(flow.take_bridge_bytes(), b"bridged-payload");
    }

    #[test]
    fn connect_post_bridge_data_goes_to_bridge_buffer() {
        let mut flow = HopConnect::new(b"peer".to_vec());
        let _ = flow.take_outbound();

        let response = frame_hop(HopMessage {
            kind: HopMessageType::Status,
            peer: None,
            reservation: None,
            limit: None,
            status: Some(Status::Ok),
        });
        flow.on_data(&response).unwrap();
        assert!(flow.take_bridge_bytes().is_empty());

        flow.on_data(b"more-data-from-peer").unwrap();
        assert_eq!(flow.take_bridge_bytes(), b"more-data-from-peer");
    }

    #[test]
    fn connect_handles_refusal() {
        let mut flow = HopConnect::new(b"peer".to_vec());
        let _ = flow.take_outbound();

        let response = frame_hop(HopMessage {
            kind: HopMessageType::Status,
            peer: None,
            reservation: None,
            limit: None,
            status: Some(Status::NoReservation),
        });
        flow.on_data(&response).unwrap();

        assert!(matches!(
            flow.outcome(),
            Some(ConnectOutcome::Refused {
                status: Status::NoReservation,
                ..
            })
        ));
    }

    #[test]
    fn connect_rejects_oversized_target_peer_id() {
        let mut flow = HopConnect::new(vec![0u8; MAX_MESSAGE_SIZE + 1]);

        // The oversized frame must never be emitted...
        assert!(!flow.is_idle());
        assert!(flow.poll_output().is_none());
        // ...and the error surfaces on the first input.
        let err = flow.handle_input(HopConnectInput::Flush).unwrap_err();
        assert!(matches!(err, RelayError::MessageTooLarge { .. }));
        assert!(flow.is_done());
        assert!(flow.is_idle());
    }

    #[test]
    fn connect_at_exact_max_size_still_encodes() {
        // Peer id sized so the encoded CONNECT payload is exactly
        // MAX_MESSAGE_SIZE: 2 bytes type field + 1 tag + 2-byte length
        // varint for the nested Peer + (1 tag + 2-byte length varint +
        // 8184 id bytes).
        let id = vec![0u8; 8184];
        let request = HopMessage {
            kind: HopMessageType::Connect,
            peer: Some(Peer {
                id: id.clone(),
                addrs: Vec::new(),
            }),
            reservation: None,
            limit: None,
            status: None,
        };
        assert_eq!(request.encode().len(), MAX_MESSAGE_SIZE);

        let mut flow = HopConnect::new(id);
        flow.handle_input(HopConnectInput::Flush).unwrap();
        let Some(HopConnectOutput::Outbound(bytes)) = flow.poll_output() else {
            panic!("exactly-max CONNECT must be emitted");
        };
        assert!(matches!(decode_frame(&bytes), FrameDecode::Complete { .. }));

        // One more byte and the frame must be refused.
        let mut flow = HopConnect::new(vec![0u8; 8185]);
        let err = flow.handle_input(HopConnectInput::Flush).unwrap_err();
        assert!(matches!(err, RelayError::MessageTooLarge { len } if len == MAX_MESSAGE_SIZE + 1));
    }

    // --- StopResponder ------------------------------------------------------

    #[test]
    fn stop_receives_connect_accepts_and_bridges() {
        let mut flow = StopResponder::new();

        // Incoming CONNECT from relay.
        let connect = frame_stop(StopMessage {
            kind: StopMessageType::Connect,
            peer: Some(Peer {
                id: b"source-peer".to_vec(),
                addrs: vec![],
            }),
            limit: Some(Limit {
                duration: Some(300),
                data: None,
            }),
            status: None,
        });
        flow.on_data(&connect).unwrap();

        // We should now have a pending request.
        let request = flow.request().expect("request should be populated");
        assert_eq!(request.source_peer_id, b"source-peer");
        assert_eq!(request.limit.as_ref().and_then(|l| l.duration), Some(300));

        // Accept and verify outbound is STATUS:OK.
        flow.accept().unwrap();
        let outbound = flow.take_outbound();
        let FrameDecode::Complete { payload, .. } = decode_frame(&outbound) else {
            panic!();
        };
        let response = StopMessage::decode(payload).unwrap();
        assert_eq!(response.kind, StopMessageType::Status);
        assert_eq!(response.status, Some(Status::Ok));

        // Subsequent data is bridged.
        flow.on_data(b"relayed-peer-traffic").unwrap();
        assert_eq!(flow.take_bridge_bytes(), b"relayed-peer-traffic");
    }

    #[test]
    fn stop_pipelined_bridge_bytes_captured_on_accept() {
        let mut flow = StopResponder::new();

        let mut packet = frame_stop(StopMessage {
            kind: StopMessageType::Connect,
            peer: Some(Peer {
                id: b"src".to_vec(),
                addrs: vec![],
            }),
            limit: None,
            status: None,
        });
        packet.extend_from_slice(b"pipelined-bytes");
        flow.on_data(&packet).unwrap();
        flow.accept().unwrap();

        assert_eq!(flow.take_bridge_bytes(), b"pipelined-bytes");
    }

    #[test]
    fn stop_reject_emits_non_ok_status() {
        let mut flow = StopResponder::new();

        let connect = frame_stop(StopMessage {
            kind: StopMessageType::Connect,
            peer: Some(Peer {
                id: b"src".to_vec(),
                addrs: vec![],
            }),
            limit: None,
            status: None,
        });
        flow.on_data(&connect).unwrap();
        flow.reject(Status::ConnectionFailed).unwrap();

        let outbound = flow.take_outbound();
        let FrameDecode::Complete { payload, .. } = decode_frame(&outbound) else {
            panic!();
        };
        let response = StopMessage::decode(payload).unwrap();
        assert_eq!(response.status, Some(Status::ConnectionFailed));
        assert!(flow.is_done());
    }

    #[test]
    fn stop_accept_without_connect_fails() {
        let mut flow = StopResponder::new();
        let err = flow.accept().unwrap_err();
        assert!(matches!(err, RelayError::UnexpectedMessage(_)));
    }

    #[test]
    fn stop_connect_without_peer_fails() {
        let mut flow = StopResponder::new();
        let connect = frame_stop(StopMessage {
            kind: StopMessageType::Connect,
            peer: None,
            limit: None,
            status: None,
        });
        let err = flow.on_data(&connect).unwrap_err();
        assert!(matches!(err, RelayError::UnexpectedMessage(_)));
    }

    #[test]
    fn stop_rejects_unexpected_message_type() {
        let mut flow = StopResponder::new();
        let msg = frame_stop(StopMessage {
            kind: StopMessageType::Status,
            peer: None,
            limit: None,
            status: Some(Status::Ok),
        });
        let err = flow.on_data(&msg).unwrap_err();
        assert!(matches!(err, RelayError::UnexpectedMessage(_)));
    }

    #[test]
    fn stop_handles_fragmented_connect() {
        let mut flow = StopResponder::new();

        let connect = frame_stop(StopMessage {
            kind: StopMessageType::Connect,
            peer: Some(Peer {
                id: b"src".to_vec(),
                addrs: vec![],
            }),
            limit: None,
            status: None,
        });

        for byte in &connect {
            flow.on_data(&[*byte]).unwrap();
        }

        assert!(flow.request().is_some());
    }

    #[test]
    fn relay_flows_implement_sans_io_protocol() {
        let mut reservation = HopReservation::new();
        reservation
            .handle_input(HopReservationInput::Flush)
            .unwrap();
        assert!(matches!(
            reservation.poll_output(),
            Some(HopReservationOutput::Outbound(_))
        ));

        let response = frame_hop(HopMessage {
            kind: HopMessageType::Status,
            peer: None,
            reservation: None,
            limit: None,
            status: Some(Status::Ok),
        });
        reservation
            .handle_input(HopReservationInput::Data(response))
            .unwrap();
        assert!(matches!(
            reservation.poll_output(),
            Some(HopReservationOutput::Outcome(
                ReservationOutcome::Accepted { .. }
            ))
        ));

        let mut stop = StopResponder::new();
        let mut connect = frame_stop(StopMessage {
            kind: StopMessageType::Connect,
            peer: Some(Peer {
                id: b"src".to_vec(),
                addrs: vec![],
            }),
            limit: None,
            status: None,
        });
        connect.extend_from_slice(b"bridge");
        stop.handle_input(StopResponderInput::Data(connect))
            .unwrap();
        assert!(matches!(
            stop.poll_output(),
            Some(StopResponderOutput::Request(_))
        ));

        stop.handle_input(StopResponderInput::Accept).unwrap();
        assert!(matches!(
            stop.poll_output(),
            Some(StopResponderOutput::Outbound(_))
        ));
        assert_eq!(
            stop.poll_output(),
            Some(StopResponderOutput::BridgeData(b"bridge".to_vec()))
        );
    }
}
