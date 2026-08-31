use alloc::collections::VecDeque;
use alloc::vec::Vec;

use minip2p_core::{PeerId, SansIoProtocol};

use crate::{
    FrameDecode, HopMessage, HopMessageType, Limit, MAX_PENDING_BRIDGE_SIZE, Peer, RelayError,
    Reservation, Status, StopMessage, StopMessageType, decode_frame, encode_frame,
    encode_hop_status, encode_stop_status,
};

/// A syntactically valid request received on an inbound HOP stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HopRequest {
    /// Request to create or renew a reservation.
    Reserve,
    /// Request to connect to a reserved destination.
    Connect {
        /// Destination named by the request.
        destination_peer_id: PeerId,
    },
}

/// Inputs accepted by [`HopResponder`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HopResponderInput {
    /// Bytes received on the inbound HOP stream.
    Data(Vec<u8>),
    /// The remote closed its write side.
    ///
    /// A complete request and queued response remain drainable; only an
    /// incomplete request terminates without a decision.
    RemoteWriteClosed,
    /// The remote reset the stream, discarding pending decisions and outputs.
    RemoteReset,
    /// Accept a pending RESERVE request.
    AcceptReservation {
        /// Reservation metadata returned to the requester.
        reservation: Reservation,
        /// Circuit limit advertised with the reservation.
        limit: Option<Limit>,
    },
    /// Accept a pending CONNECT with the advertised circuit limit.
    AcceptConnect {
        /// Limit applied to the circuit, or none when unrestricted.
        limit: Option<Limit>,
    },
    /// Reject the pending request with an exact wire status.
    ///
    /// `OK` and `UNUSED` are not valid denials and request a stream reset.
    Reject(Status),
}

/// Outputs produced by [`HopResponder`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HopResponderOutput {
    /// A request requiring a service decision.
    Request(HopRequest),
    /// Bytes to write to the HOP stream.
    Outbound(Vec<u8>),
    /// Close the local write side after all preceding output is sent.
    CloseWrite,
    /// Reset the stream because no valid status response can be sent.
    Reset,
    /// Application bytes received after a CONNECT request.
    BridgeData(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingRequest {
    Reserve,
    Connect,
}

/// Relay-side wire machine for one inbound HOP stream.
///
/// Feed stream bytes until [`HopResponderOutput::Request`] is emitted, then
/// provide exactly one accept/reject decision. RESERVE and rejected requests
/// emit a status followed by [`HopResponderOutput::CloseWrite`]. An accepted
/// CONNECT emits its status before any [`HopResponderOutput::BridgeData`].
/// After a request output, pause stream reads until supplying its decision;
/// additional data returns [`RelayError::DecisionPending`] without being
/// retained. Payload coalesced with the request frame remains available after
/// CONNECT acceptance up to [`MAX_PENDING_BRIDGE_SIZE`]; a larger pending
/// payload resets the stream. This bound does not apply after acceptance.
/// Invalid framing terminates with [`HopResponderOutput::Reset`]. Inputs after
/// a terminal error are ignored. A remote write close preserves a complete
/// request and all causally preceding outputs, while a reset discards them.
pub struct HopResponder {
    recv_buf: Vec<u8>,
    outputs: VecDeque<HopResponderOutput>,
    pending_request: Option<PendingRequest>,
    pending_bridge: Vec<u8>,
    bridged: bool,
    remote_write_closed: bool,
    done: bool,
}

impl HopResponder {
    /// Creates a responder waiting for a single HOP request.
    pub fn new() -> Self {
        Self {
            recv_buf: Vec::new(),
            outputs: VecDeque::new(),
            pending_request: None,
            pending_bridge: Vec::new(),
            bridged: false,
            remote_write_closed: false,
            done: false,
        }
    }

    fn on_data(&mut self, mut data: Vec<u8>) -> Result<(), RelayError> {
        if self.remote_write_closed {
            return Ok(());
        }
        if self.bridged {
            if !data.is_empty() {
                self.outputs.push_back(HopResponderOutput::BridgeData(data));
            }
            return Ok(());
        }
        if self.done {
            return Ok(());
        }
        if self.pending_request.is_some() {
            return Err(RelayError::DecisionPending);
        }
        if self.recv_buf.is_empty() {
            self.recv_buf = data;
        } else {
            self.recv_buf.append(&mut data);
        }
        let (payload, consumed) = match decode_frame(&self.recv_buf) {
            FrameDecode::Complete { payload, consumed } => (payload, consumed),
            FrameDecode::Incomplete => return Ok(()),
            FrameDecode::TooLarge { .. } | FrameDecode::Error(_) => {
                self.queue_reset();
                return Ok(());
            }
        };
        if self.recv_buf.len() - consumed > MAX_PENDING_BRIDGE_SIZE {
            self.queue_reset();
            return Ok(());
        }
        let message = match HopMessage::decode(payload) {
            Ok(message) => message,
            Err(_) => {
                self.queue_status_and_close(Status::MalformedMessage);
                return Ok(());
            }
        };
        let (request, pending_request) = match message.kind {
            HopMessageType::Reserve => (HopRequest::Reserve, PendingRequest::Reserve),
            HopMessageType::Connect => {
                let Some(peer) = message.peer else {
                    self.queue_status_and_close(Status::MalformedMessage);
                    return Ok(());
                };
                let Ok(destination_peer_id) = PeerId::from_bytes(&peer.id) else {
                    self.queue_status_and_close(Status::MalformedMessage);
                    return Ok(());
                };
                (
                    HopRequest::Connect {
                        destination_peer_id,
                    },
                    PendingRequest::Connect,
                )
            }
            HopMessageType::Status => {
                self.queue_status_and_close(Status::UnexpectedMessage);
                return Ok(());
            }
        };
        if pending_request == PendingRequest::Connect {
            self.pending_bridge = self.recv_buf.split_off(consumed);
        }
        self.recv_buf = Vec::new();
        self.pending_request = Some(pending_request);
        self.outputs.push_back(HopResponderOutput::Request(request));
        Ok(())
    }

    fn accept_reservation(
        &mut self,
        mut reservation: Reservation,
        limit: Option<Limit>,
    ) -> Result<(), RelayError> {
        if self.pending_request != Some(PendingRequest::Reserve) {
            return Err(RelayError::UnexpectedMessage(
                "cannot accept HOP RESERVE without a pending RESERVE request".into(),
            ));
        }
        // Reservation vouchers are intentionally outside minip2p's relay
        // server contract. Keep the wire field absent even if a low-level
        // host reused a client-decoded Reservation value here.
        reservation.voucher = None;
        self.queue_terminal_hop_response(encode_hop_status(Status::Ok, Some(reservation), limit));
        Ok(())
    }

    fn accept_connect(&mut self, limit: Option<Limit>) -> Result<(), RelayError> {
        if self.pending_request != Some(PendingRequest::Connect) {
            return Err(RelayError::UnexpectedMessage(
                "cannot accept HOP CONNECT without a pending CONNECT request".into(),
            ));
        }
        let Ok(frame) = encode_hop_status(Status::Ok, None, limit) else {
            self.queue_reset();
            return Ok(());
        };
        self.outputs.push_back(HopResponderOutput::Outbound(frame));
        if !self.pending_bridge.is_empty() {
            self.outputs
                .push_back(HopResponderOutput::BridgeData(core::mem::take(
                    &mut self.pending_bridge,
                )));
        }
        self.pending_request = None;
        self.bridged = !self.remote_write_closed;
        self.done = true;
        Ok(())
    }

    fn reject(&mut self, status: Status) -> Result<(), RelayError> {
        if self.pending_request.is_none() {
            return Err(RelayError::UnexpectedMessage(
                "cannot reject without a pending HOP request".into(),
            ));
        }
        if matches!(status, Status::Ok | Status::Unused) {
            self.queue_reset();
            return Ok(());
        }
        self.queue_status_and_close(status);
        Ok(())
    }

    fn queue_status_and_close(&mut self, status: Status) {
        self.queue_terminal_hop_response(encode_hop_status(status, None, None));
    }

    fn queue_terminal_hop_response(&mut self, response: Result<Vec<u8>, RelayError>) {
        match response {
            Ok(frame) => {
                self.outputs.push_back(HopResponderOutput::Outbound(frame));
                self.outputs.push_back(HopResponderOutput::CloseWrite);
            }
            Err(_) => self.outputs.push_back(HopResponderOutput::Reset),
        }
        self.pending_request = None;
        self.pending_bridge = Vec::new();
        self.recv_buf = Vec::new();
        self.done = true;
    }

    fn queue_reset(&mut self) {
        self.recv_buf = Vec::new();
        self.pending_request = None;
        self.pending_bridge = Vec::new();
        self.outputs.push_back(HopResponderOutput::Reset);
        self.done = true;
    }

    fn remote_write_closed(&mut self) {
        self.remote_write_closed = true;
        self.recv_buf = Vec::new();
        if self.pending_request.is_none() && !self.done {
            self.pending_bridge = Vec::new();
            self.done = true;
        }
        self.bridged = false;
    }

    fn remote_reset(&mut self) {
        self.recv_buf = Vec::new();
        self.pending_request = None;
        self.pending_bridge = Vec::new();
        self.outputs.clear();
        self.bridged = false;
        self.remote_write_closed = true;
        self.done = true;
    }

    /// Returns true once the handshake has reached a terminal state.
    ///
    /// An accepted CONNECT may continue to produce bridge data after this
    /// becomes true.
    pub fn is_done(&self) -> bool {
        self.done
    }
}

impl SansIoProtocol for HopResponder {
    type Input = HopResponderInput;
    type Output = HopResponderOutput;
    type Error = RelayError;

    fn handle_input(&mut self, input: Self::Input) -> Result<(), Self::Error> {
        match input {
            HopResponderInput::Data(data) => self.on_data(data),
            HopResponderInput::RemoteWriteClosed => {
                self.remote_write_closed();
                Ok(())
            }
            HopResponderInput::RemoteReset => {
                self.remote_reset();
                Ok(())
            }
            HopResponderInput::AcceptReservation { reservation, limit } => {
                self.accept_reservation(reservation, limit)
            }
            HopResponderInput::AcceptConnect { limit } => self.accept_connect(limit),
            HopResponderInput::Reject(status) => self.reject(status),
        }
    }

    fn poll_output(&mut self) -> Option<Self::Output> {
        self.outputs.pop_front()
    }

    fn is_idle(&self) -> bool {
        self.outputs.is_empty()
    }
}

impl Default for HopResponder {
    fn default() -> Self {
        Self::new()
    }
}

/// Terminal result of an outbound STOP exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopInitiatorOutcome {
    /// The destination accepted the circuit.
    Accepted,
    /// The destination returned a non-OK wire status.
    Refused {
        /// Exact status received from the destination.
        status: Status,
    },
    /// The response violated the STOP wire contract.
    ProtocolError {
        /// HOP status corresponding to the violation.
        status: Status,
    },
    /// The destination closed before returning a complete response.
    RemoteWriteClosed,
    /// The destination reset before returning a complete response.
    RemoteReset,
}

impl StopInitiatorOutcome {
    /// Maps this STOP result to the status returned on the source HOP stream.
    ///
    /// Only resource-limit and permission refusals pass through. Other
    /// well-formed refusal codes are unexpected in a STOP response.
    pub const fn hop_status(self) -> Status {
        match self {
            StopInitiatorOutcome::Accepted => Status::Ok,
            StopInitiatorOutcome::Refused {
                status: Status::ResourceLimitExceeded,
            } => Status::ResourceLimitExceeded,
            StopInitiatorOutcome::Refused {
                status: Status::PermissionDenied,
            } => Status::PermissionDenied,
            StopInitiatorOutcome::Refused { .. } => Status::UnexpectedMessage,
            StopInitiatorOutcome::ProtocolError { status } => status,
            StopInitiatorOutcome::RemoteWriteClosed | StopInitiatorOutcome::RemoteReset => {
                Status::ConnectionFailed
            }
        }
    }
}

/// Inputs accepted by [`StopInitiator`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StopInitiatorInput {
    /// Bytes received on the outbound STOP stream.
    Data(Vec<u8>),
    /// The remote closed its write side.
    ///
    /// Outputs from a complete response remain drainable.
    RemoteWriteClosed,
    /// The remote reset the stream.
    ///
    /// Semantic outputs from a response decoded before the reset remain
    /// drainable; unsent transport actions are discarded.
    RemoteReset,
}

/// Outputs produced by [`StopInitiator`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StopInitiatorOutput {
    /// Bytes to write to the STOP stream.
    Outbound(Vec<u8>),
    /// Terminal handshake result.
    Outcome(StopInitiatorOutcome),
    /// Application bytes received after the final handshake frame.
    BridgeData(Vec<u8>),
    /// Close the local write side after a semantic protocol-error response.
    CloseWrite,
    /// Reset the stream after invalid framing or an oversized declaration.
    Reset,
}

/// Relay-side wire machine for one outbound STOP stream.
///
/// Construction queues STOP CONNECT. A valid STATUS produces one exact
/// [`StopInitiatorOutcome`]; accepted responses expose payload coalesced after
/// the frame as [`StopInitiatorOutput::BridgeData`]. Well-framed semantic
/// errors emit a corrective status and close-write before the outcome. Invalid
/// framing emits reset before the outcome. Remote close/reset before a complete
/// response maps to `CONNECTION_FAILED` through
/// [`StopInitiatorOutcome::hop_status`]. Once a response is complete, a later
/// close/reset does not erase its queued outcome or bridge data.
pub struct StopInitiator {
    recv_buf: Vec<u8>,
    outputs: VecDeque<StopInitiatorOutput>,
    bridged: bool,
    done: bool,
}

impl StopInitiator {
    /// Creates an initiator and queues a STOP CONNECT for `source_peer_id`.
    pub fn new(source_peer_id: PeerId, limit: Option<Limit>) -> Self {
        let request = StopMessage {
            kind: StopMessageType::Connect,
            peer: Some(Peer {
                id: source_peer_id.to_bytes(),
                addrs: Vec::new(),
            }),
            limit,
            status: None,
        };
        let mut outputs = VecDeque::new();
        outputs.push_back(StopInitiatorOutput::Outbound(encode_frame(
            &request.encode(),
        )));
        Self {
            recv_buf: Vec::new(),
            outputs,
            bridged: false,
            done: false,
        }
    }

    fn on_data(&mut self, data: &[u8]) -> Result<(), RelayError> {
        if self.bridged {
            if !data.is_empty() {
                self.outputs
                    .push_back(StopInitiatorOutput::BridgeData(data.to_vec()));
            }
            return Ok(());
        }
        if self.done {
            return Ok(());
        }
        self.recv_buf.extend_from_slice(data);
        let (message, consumed) = match decode_frame(&self.recv_buf) {
            FrameDecode::Complete { payload, consumed } => {
                let decoded = StopMessage::decode(payload);
                (decoded, consumed)
            }
            FrameDecode::Incomplete => return Ok(()),
            FrameDecode::TooLarge { .. } | FrameDecode::Error(_) => {
                self.queue_reset(Status::MalformedMessage);
                return Ok(());
            }
        };
        let message = match message {
            Ok(message) => message,
            Err(_) => {
                self.queue_protocol_error(Status::MalformedMessage);
                return Ok(());
            }
        };
        if message.kind != StopMessageType::Status {
            self.queue_protocol_error(Status::UnexpectedMessage);
            return Ok(());
        }
        let Some(status) = message.status else {
            self.queue_protocol_error(Status::MalformedMessage);
            return Ok(());
        };
        let outcome = if status == Status::Ok {
            self.bridged = true;
            StopInitiatorOutcome::Accepted
        } else {
            StopInitiatorOutcome::Refused { status }
        };
        self.outputs
            .push_back(StopInitiatorOutput::Outcome(outcome));
        if self.bridged && consumed < self.recv_buf.len() {
            self.outputs.push_back(StopInitiatorOutput::BridgeData(
                self.recv_buf
                    .get(consumed..)
                    .expect("a complete frame consumes no more than the receive buffer")
                    .to_vec(),
            ));
        }
        self.recv_buf.clear();
        self.done = true;
        Ok(())
    }

    fn queue_protocol_error(&mut self, status: Status) {
        match encode_stop_status(status) {
            Ok(frame) => {
                self.outputs.push_back(StopInitiatorOutput::Outbound(frame));
                self.outputs.push_back(StopInitiatorOutput::CloseWrite);
            }
            Err(_) => self.outputs.push_back(StopInitiatorOutput::Reset),
        }
        self.outputs.push_back(StopInitiatorOutput::Outcome(
            StopInitiatorOutcome::ProtocolError { status },
        ));
        self.recv_buf.clear();
        self.done = true;
    }

    fn queue_reset(&mut self, status: Status) {
        self.outputs.push_back(StopInitiatorOutput::Reset);
        self.outputs.push_back(StopInitiatorOutput::Outcome(
            StopInitiatorOutcome::ProtocolError { status },
        ));
        self.recv_buf.clear();
        self.done = true;
    }

    fn remote_write_closed(&mut self) {
        if !self.done {
            self.outputs.clear();
            self.outputs.push_back(StopInitiatorOutput::Outcome(
                StopInitiatorOutcome::RemoteWriteClosed,
            ));
        }
        self.finish_remote_terminal();
    }

    fn remote_reset(&mut self) {
        if self.done {
            self.outputs.retain(|output| {
                matches!(
                    output,
                    StopInitiatorOutput::Outcome(_) | StopInitiatorOutput::BridgeData(_)
                )
            });
        } else {
            self.outputs.clear();
            self.outputs.push_back(StopInitiatorOutput::Outcome(
                StopInitiatorOutcome::RemoteReset,
            ));
        }
        self.finish_remote_terminal();
    }

    fn finish_remote_terminal(&mut self) {
        self.recv_buf = Vec::new();
        self.bridged = false;
        self.done = true;
    }

    /// Returns true once the STOP handshake has terminated.
    ///
    /// An accepted STOP stream may continue to produce bridge data afterward.
    pub fn is_done(&self) -> bool {
        self.done
    }
}

impl SansIoProtocol for StopInitiator {
    type Input = StopInitiatorInput;
    type Output = StopInitiatorOutput;
    type Error = RelayError;

    fn handle_input(&mut self, input: Self::Input) -> Result<(), Self::Error> {
        match input {
            StopInitiatorInput::Data(data) => self.on_data(&data),
            StopInitiatorInput::RemoteWriteClosed => {
                self.remote_write_closed();
                Ok(())
            }
            StopInitiatorInput::RemoteReset => {
                self.remote_reset();
                Ok(())
            }
        }
    }

    fn poll_output(&mut self) -> Option<Self::Output> {
        self.outputs.pop_front()
    }

    fn is_idle(&self) -> bool {
        self.outputs.is_empty()
    }
}
