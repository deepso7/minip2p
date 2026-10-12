use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::FrameExchange;

use crate::RelayError;
use crate::{
    HopMessage, HopMessageType, Limit, MAX_PENDING_BRIDGE_SIZE, Peer, Reservation, Status,
    StopMessage, StopMessageType, describe_status, handshake_frames, queue_control,
};

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

/// Output produced by [`HopReservation::poll_output`].
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
///    [`HopReservation::poll_output`] and send the bytes on the relay stream.
/// 3. Feed incoming stream bytes with [`HopReservation::on_data`].
/// 4. Drain [`HopReservationOutput::Outcome`] to observe accepted/refused
///    completion.
///
/// Bytes the relay sends behind its STATUS frame are ignored: a reservation
/// stream carries nothing after the response.
pub struct HopReservation {
    frames: FrameExchange,
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
        let request = HopMessage {
            kind: HopMessageType::Reserve,
            peer: None,
            reservation: None,
            limit: None,
            status: None,
        };
        let mut frames = handshake_frames();
        frames
            .queue(&request.encode())
            .expect("RESERVE has no variable-length fields and always fits one frame");

        Self {
            frames,
            state: FlowState::Pending,
            outcome: None,
            emitted_outcome: false,
        }
    }

    /// Feeds incoming stream bytes from the relay.
    ///
    /// Any error ends the flow; later input is ignored.
    pub fn on_data(&mut self, data: &[u8]) -> Result<(), RelayError> {
        if self.state == FlowState::Done {
            return Ok(());
        }
        let result = self
            .frames
            .push(data)
            .map_err(RelayError::from)
            .and_then(|()| self.try_decode_response());
        self.finish_on_error(result)
    }

    /// Notifies the state machine that the remote closed its write side.
    ///
    /// If a complete response has not yet been decoded, this is not itself
    /// an error -- callers can still receive partial buffered data.
    pub fn on_remote_write_closed(&mut self) -> Result<(), RelayError> {
        if self.state == FlowState::Done {
            return Ok(());
        }
        let result = self.try_decode_response();
        self.finish_on_error(result)
    }

    /// Returns the next pending output, if any.
    ///
    /// Drain until `None` after construction and after every input, before
    /// waiting on the stream again.
    pub fn poll_output(&mut self) -> Option<HopReservationOutput> {
        if self.frames.has_outbound() {
            if self.state == FlowState::Pending {
                self.state = FlowState::AwaitingResponse;
            }
            return Some(HopReservationOutput::Outbound(self.frames.take_outbound()));
        }
        if !self.emitted_outcome
            && let Some(outcome) = self.outcome.clone()
        {
            self.emitted_outcome = true;
            return Some(HopReservationOutput::Outcome(outcome));
        }
        None
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

    fn finish_on_error(&mut self, result: Result<(), RelayError>) -> Result<(), RelayError> {
        if result.is_err() {
            self.state = FlowState::Done;
        }
        result
    }

    /// Attempts to decode the response frame from the receive buffer.
    fn try_decode_response(&mut self) -> Result<(), RelayError> {
        let Some(msg) = next_hop_status(&mut self.frames)? else {
            return Ok(());
        };
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

/// Output produced by [`HopConnect::poll_output`].
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
/// 2. Drain [`HopConnectOutput::Outbound`] from [`HopConnect::poll_output`]
///    and send the bytes.
/// 3. Feed incoming stream bytes with [`HopConnect::on_data`].
/// 4. When [`HopConnectOutput::Outcome`] returns `ConnectOutcome::Bridged`,
///    the stream becomes the relay circuit; drain
///    [`HopConnectOutput::BridgeData`] for any pipelined peer-to-peer bytes.
///
/// Bytes behind an accepting STATUS frame, in the same read or later, are
/// bridged traffic and are not bound by the control-frame limit.
pub struct HopConnect {
    frames: FrameExchange,
    state: FlowState,
    outcome: Option<ConnectOutcome>,
    emitted_outcome: bool,
    bridge_bytes: Vec<u8>,
}

impl HopConnect {
    /// Creates a new CONNECT state machine targeting the given peer id.
    ///
    /// `target_peer_id` should be the multihash-encoded PeerId bytes.
    ///
    /// Fails with [`RelayError::MessageTooLarge`] if the encoded CONNECT
    /// would exceed [`MAX_MESSAGE_SIZE`](crate::MAX_MESSAGE_SIZE) -- a frame
    /// any hardened relay (including this crate's own decoder) would reject.
    pub fn new(target_peer_id: Vec<u8>) -> Result<Self, RelayError> {
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
        let mut frames = handshake_frames();
        queue_control(&mut frames, &request.encode())?;

        Ok(Self {
            frames,
            state: FlowState::Pending,
            outcome: None,
            emitted_outcome: false,
            bridge_bytes: Vec::new(),
        })
    }

    /// Feeds incoming stream bytes from the relay.
    ///
    /// After the CONNECT is accepted, any further bytes passed here are
    /// emitted as [`HopConnectOutput::BridgeData`]. Any error ends the flow;
    /// later input is ignored.
    pub fn on_data(&mut self, data: &[u8]) -> Result<(), RelayError> {
        if self.state == FlowState::Done {
            // Already bridged or errored — any further bytes belong to the
            // bridged channel (or are garbage after an error).
            if matches!(self.outcome, Some(ConnectOutcome::Bridged { .. })) {
                self.bridge_bytes.extend_from_slice(data);
            }
            return Ok(());
        }
        let result = self
            .frames
            .push(data)
            .map_err(RelayError::from)
            .and_then(|()| self.try_decode_response());
        self.finish_on_error(result)
    }

    /// Notifies the state machine that the remote closed its write side.
    pub fn on_remote_write_closed(&mut self) -> Result<(), RelayError> {
        if self.state == FlowState::Done {
            return Ok(());
        }
        let result = self.try_decode_response();
        self.finish_on_error(result)
    }

    /// Returns the next pending output, if any.
    ///
    /// Drain until `None` after construction and after every input, before
    /// waiting on the stream again.
    pub fn poll_output(&mut self) -> Option<HopConnectOutput> {
        if self.frames.has_outbound() {
            if self.state == FlowState::Pending {
                self.state = FlowState::AwaitingResponse;
            }
            return Some(HopConnectOutput::Outbound(self.frames.take_outbound()));
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

    fn finish_on_error(&mut self, result: Result<(), RelayError>) -> Result<(), RelayError> {
        if result.is_err() {
            self.state = FlowState::Done;
        }
        result
    }

    /// Attempts to decode the response from the receive buffer.
    fn try_decode_response(&mut self) -> Result<(), RelayError> {
        let Some(msg) = next_hop_status(&mut self.frames)? else {
            return Ok(());
        };
        let status = msg.status.unwrap_or(Status::Unused);
        self.state = FlowState::Done;
        self.outcome = Some(if status == Status::Ok {
            // Any bytes buffered after the STATUS frame belong to the bridged
            // stream. This catches the case where the relay pipelines the
            // first bytes of the bridged connection into the same packet.
            self.bridge_bytes.append(&mut self.frames.take_buffered());
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

/// Output produced by [`StopResponder::poll_output`].
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
/// 2. Feed bytes with [`StopResponder::on_data`] and drain
///    [`StopResponderOutput::Request`].
/// 3. Decide to accept or reject with [`StopResponder::accept`] or
///    [`StopResponder::reject`].
/// 4. Send resulting [`StopResponderOutput::Outbound`] bytes to the relay.
/// 5. If accepted, the stream becomes the bridged circuit; drain
///    [`StopResponderOutput::BridgeData`] for any pipelined bytes.
///
/// Pause stream reads after the request output until supplying the decision.
/// Additional data returns [`RelayError::DecisionPending`] without retention.
/// Payload coalesced with CONNECT is capped by [`MAX_PENDING_BRIDGE_SIZE`]; a
/// larger pending payload returns [`RelayError::PendingBridgeTooLarge`].
pub struct StopResponder {
    frames: FrameExchange,
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
            frames: handshake_frames(),
            state: StopState::AwaitingConnect,
            request: None,
            emitted_request: false,
            bridge_bytes: Vec::new(),
        }
    }

    /// Feeds incoming stream bytes from the relay.
    ///
    /// Returns [`RelayError::DecisionPending`] while a request awaits its
    /// decision. Any other error ends the flow; later input is ignored.
    pub fn on_data(&mut self, data: &[u8]) -> Result<(), RelayError> {
        match self.state {
            StopState::Bridged => {
                self.bridge_bytes.extend_from_slice(data);
                return Ok(());
            }
            StopState::Done => return Ok(()),
            StopState::AwaitingDecision => return Err(RelayError::DecisionPending),
            StopState::AwaitingConnect => {}
        }
        let result = self
            .frames
            .push(data)
            .map_err(RelayError::from)
            .and_then(|()| self.try_decode_connect());
        self.finish_on_error(result)
    }

    /// Notifies the state machine that the remote closed its write side.
    pub fn on_remote_write_closed(&mut self) -> Result<(), RelayError> {
        if self.state != StopState::AwaitingConnect {
            return Ok(());
        }
        let result = self.try_decode_connect();
        self.finish_on_error(result)
    }

    /// Accepts the CONNECT request, queuing a `STATUS: OK` response.
    ///
    /// After this, the stream becomes the bridged circuit; payload the relay
    /// pipelined behind its CONNECT, and any further bytes received, are
    /// emitted as [`StopResponderOutput::BridgeData`].
    pub fn accept(&mut self) -> Result<(), RelayError> {
        self.send_status(Status::Ok, StopState::Bridged)?;
        self.bridge_bytes.append(&mut self.frames.take_buffered());
        Ok(())
    }

    /// Rejects the CONNECT request with the given status code.
    pub fn reject(&mut self, status: Status) -> Result<(), RelayError> {
        self.send_status(status, StopState::Done)
    }

    /// Returns the next pending output, if any.
    ///
    /// Drain until `None` after every input, before waiting on the stream
    /// or the decision again.
    pub fn poll_output(&mut self) -> Option<StopResponderOutput> {
        if !self.emitted_request
            && let Some(request) = self.request.clone()
        {
            self.emitted_request = true;
            return Some(StopResponderOutput::Request(request));
        }
        if self.frames.has_outbound() {
            return Some(StopResponderOutput::Outbound(self.frames.take_outbound()));
        }
        let bridge_bytes = self.take_bridge_bytes();
        if !bridge_bytes.is_empty() {
            return Some(StopResponderOutput::BridgeData(bridge_bytes));
        }
        None
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

    /// Drains any bridged relay traffic received since the last call.
    fn take_bridge_bytes(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.bridge_bytes)
    }

    fn finish_on_error(&mut self, result: Result<(), RelayError>) -> Result<(), RelayError> {
        if result.is_err() {
            self.state = StopState::Done;
        }
        result
    }

    /// Queues a StopMessage with `type = STATUS` and the given status code.
    fn send_status(&mut self, status: Status, next_state: StopState) -> Result<(), RelayError> {
        if self.state != StopState::AwaitingDecision {
            return Err(RelayError::UnexpectedMessage(alloc::format!(
                "cannot respond from state {:?}",
                self.state
            )));
        }
        let response = StopMessage {
            kind: StopMessageType::Status,
            peer: None,
            limit: None,
            status: Some(status),
        };
        queue_control(&mut self.frames, &response.encode())?;
        self.state = next_state;
        Ok(())
    }

    /// Decodes the CONNECT request from the receive buffer.
    fn try_decode_connect(&mut self) -> Result<(), RelayError> {
        let Some(msg) = self
            .frames
            .next_frame(|payload| StopMessage::decode(payload).map_err(RelayError::Malformed))?
        else {
            return Ok(());
        };
        let pending_len = self.frames.buffered().len();
        if pending_len > MAX_PENDING_BRIDGE_SIZE {
            self.frames.take_buffered();
            return Err(RelayError::PendingBridgeTooLarge { len: pending_len });
        }
        if msg.kind != StopMessageType::Connect {
            return Err(RelayError::UnexpectedMessage(unexpected_stop_reason(
                msg.kind, "CONNECT",
            )));
        }
        let peer = msg.peer.ok_or_else(|| {
            RelayError::UnexpectedMessage(String::from("STOP CONNECT missing peer field"))
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

impl Default for StopResponder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Decodes the relay's HOP response, if a whole frame is buffered, and
/// checks that it is a STATUS.
fn next_hop_status(frames: &mut FrameExchange) -> Result<Option<HopMessage>, RelayError> {
    let Some(msg) =
        frames.next_frame(|payload| HopMessage::decode(payload).map_err(RelayError::Malformed))?
    else {
        return Ok(None);
    };
    if msg.kind != HopMessageType::Status {
        return Err(RelayError::UnexpectedMessage(unexpected_hop_reason(
            msg.kind, "STATUS",
        )));
    }
    Ok(Some(msg))
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
    use crate::{FrameDecode, MAX_MESSAGE_SIZE, RelayMessageError, decode_frame, encode_frame};

    /// Helper: encode a HopMessage as a length-prefixed frame.
    fn frame_hop(msg: HopMessage) -> Vec<u8> {
        encode_frame(&msg.encode())
    }

    /// Helper: encode a StopMessage as a length-prefixed frame.
    fn frame_stop(msg: StopMessage) -> Vec<u8> {
        encode_frame(&msg.encode())
    }

    fn hop_status(status: Status) -> HopMessage {
        HopMessage {
            kind: HopMessageType::Status,
            peer: None,
            reservation: None,
            limit: None,
            status: Some(status),
        }
    }

    /// A `STATUS: OK` whose payload is exactly [`MAX_MESSAGE_SIZE`] bytes,
    /// padded with a reservation voucher.
    fn max_size_ok_status() -> Vec<u8> {
        let msg = (MAX_MESSAGE_SIZE - 16..MAX_MESSAGE_SIZE)
            .map(|voucher_len| HopMessage {
                reservation: Some(Reservation {
                    expire: None,
                    addrs: Vec::new(),
                    voucher: Some(vec![0x5a; voucher_len]),
                }),
                ..hop_status(Status::Ok)
            })
            .find(|msg| msg.encode().len() == MAX_MESSAGE_SIZE)
            .expect("some voucher length pads STATUS to exactly the maximum");
        frame_hop(msg)
    }

    fn stop_connect(id: &[u8]) -> StopMessage {
        StopMessage {
            kind: StopMessageType::Connect,
            peer: Some(Peer {
                id: id.to_vec(),
                addrs: vec![],
            }),
            limit: None,
            status: None,
        }
    }

    /// A header declaring one byte more than the maximum, with no payload.
    fn over_declared_header() -> Vec<u8> {
        let mut header = Vec::new();
        minip2p_core::write_uvarint((MAX_MESSAGE_SIZE + 1) as u64, &mut header);
        header
    }

    /// Takes the RESERVE queued at construction.
    fn reservation_request(flow: &mut HopReservation) -> Vec<u8> {
        let Some(HopReservationOutput::Outbound(bytes)) = flow.poll_output() else {
            panic!("RESERVE is queued at construction");
        };
        bytes
    }

    /// Takes the CONNECT queued at construction.
    fn connect_request(flow: &mut HopConnect) -> Vec<u8> {
        let Some(HopConnectOutput::Outbound(bytes)) = flow.poll_output() else {
            panic!("CONNECT is queued at construction");
        };
        bytes
    }

    fn decode_hop(bytes: &[u8]) -> HopMessage {
        let FrameDecode::Complete { payload, .. } = decode_frame(bytes) else {
            panic!("expected complete frame");
        };
        HopMessage::decode(payload).unwrap()
    }

    // --- HopReservation -----------------------------------------------------

    #[test]
    fn reservation_sends_reserve_and_accepts_ok_response() {
        let mut flow = HopReservation::new();

        let req = decode_hop(&reservation_request(&mut flow));
        assert_eq!(req.kind, HopMessageType::Reserve);

        // Simulate relay response: STATUS:OK with reservation.
        let response = frame_hop(HopMessage {
            reservation: Some(Reservation {
                expire: Some(2_000_000_000),
                addrs: vec![vec![0x04, 1, 2, 3, 4]],
                voucher: None,
            }),
            limit: Some(Limit {
                duration: Some(900),
                data: Some(10_000_000),
            }),
            ..hop_status(Status::Ok)
        });
        flow.on_data(&response).unwrap();

        assert!(flow.is_done());
        match flow.poll_output() {
            Some(HopReservationOutput::Outcome(ReservationOutcome::Accepted {
                reservation,
                limit,
            })) => {
                assert_eq!(
                    reservation.as_ref().and_then(|r| r.expire),
                    Some(2_000_000_000)
                );
                assert_eq!(limit.as_ref().and_then(|l| l.duration), Some(900));
            }
            other => panic!("unexpected output: {other:?}"),
        }
        assert!(flow.poll_output().is_none());
    }

    #[test]
    fn reservation_handles_refusal() {
        let mut flow = HopReservation::new();
        reservation_request(&mut flow);

        flow.on_data(&frame_hop(hop_status(Status::ReservationRefused)))
            .unwrap();

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
        reservation_request(&mut flow);

        for byte in &frame_hop(hop_status(Status::Ok)) {
            flow.on_data(&[*byte]).unwrap();
        }

        assert!(flow.is_done());
        assert!(matches!(
            flow.outcome(),
            Some(ReservationOutcome::Accepted { .. })
        ));
    }

    #[test]
    fn reservation_accepts_a_status_at_exactly_the_maximum_size() {
        let mut flow = HopReservation::new();
        reservation_request(&mut flow);

        flow.on_data(&max_size_ok_status()).unwrap();
        assert!(matches!(
            flow.outcome(),
            Some(ReservationOutcome::Accepted { .. })
        ));
    }

    #[test]
    fn reservation_ignores_bytes_behind_the_status() {
        let mut flow = HopReservation::new();
        reservation_request(&mut flow);

        let mut packet = frame_hop(hop_status(Status::Ok));
        packet.extend_from_slice(&vec![0xab; MAX_MESSAGE_SIZE + 1]);
        flow.on_data(&packet).unwrap();
        flow.on_data(b"later").unwrap();

        assert!(matches!(
            flow.poll_output(),
            Some(HopReservationOutput::Outcome(
                ReservationOutcome::Accepted { .. }
            ))
        ));
        assert!(flow.poll_output().is_none());
    }

    #[test]
    fn reservation_rejects_wrong_response_type() {
        let mut flow = HopReservation::new();
        reservation_request(&mut flow);

        let response = frame_hop(HopMessage {
            kind: HopMessageType::Connect,
            status: None,
            ..hop_status(Status::Ok)
        });
        let err = flow.on_data(&response).unwrap_err();
        assert!(matches!(err, RelayError::UnexpectedMessage(_)));
        assert!(flow.is_done());
    }

    #[test]
    fn reservation_rejects_oversized_declared_frame_length() {
        // A tiny header declaring an impossible payload length must fail
        // immediately instead of stalling while waiting for more bytes.
        let mut flow = HopReservation::new();
        reservation_request(&mut flow);

        let err = flow.on_data(&over_declared_header()).unwrap_err();
        assert_eq!(
            err,
            RelayError::FrameTooLarge {
                len: MAX_MESSAGE_SIZE as u64 + 1
            }
        );
        assert!(flow.is_done());
    }

    #[test]
    fn reservation_reports_a_malformed_status_frame() {
        let mut flow = HopReservation::new();
        reservation_request(&mut flow);

        // A well-framed payload with no `type` field.
        let err = flow.on_data(&encode_frame(&[])).unwrap_err();
        assert_eq!(err, RelayError::Malformed(RelayMessageError::MissingType));
        assert!(flow.is_done());
    }

    // --- HopConnect ---------------------------------------------------------

    #[test]
    fn connect_sends_connect_and_bridges_on_ok() {
        let target = b"target-peer-id".to_vec();
        let mut flow = HopConnect::new(target.clone()).unwrap();

        let req = decode_hop(&connect_request(&mut flow));
        assert_eq!(req.kind, HopMessageType::Connect);
        assert_eq!(req.peer.as_ref().map(|p| &p.id), Some(&target));

        flow.on_data(&frame_hop(hop_status(Status::Ok))).unwrap();

        assert_eq!(
            flow.poll_output(),
            Some(HopConnectOutput::Outcome(ConnectOutcome::Bridged {
                limit: None
            }))
        );
        assert!(flow.poll_output().is_none());
    }

    #[test]
    fn connect_pipelined_bridge_bytes_follow_the_outcome() {
        let mut flow = HopConnect::new(b"peer".to_vec()).unwrap();
        connect_request(&mut flow);

        let mut packet = frame_hop(hop_status(Status::Ok));
        packet.extend_from_slice(b"bridged-payload");
        flow.on_data(&packet).unwrap();

        assert!(matches!(
            flow.poll_output(),
            Some(HopConnectOutput::Outcome(ConnectOutcome::Bridged { .. }))
        ));
        assert_eq!(
            flow.poll_output(),
            Some(HopConnectOutput::BridgeData(b"bridged-payload".to_vec()))
        );
    }

    #[test]
    fn connect_coalesced_bridge_bytes_beyond_frame_cap_are_captured() {
        // A coalesced read can carry the STATUS frame plus more bridged
        // bytes than one maximal frame; the receive path must not tear
        // the flow down over the buffer total.
        let mut flow = HopConnect::new(b"peer".to_vec()).unwrap();
        connect_request(&mut flow);

        let mut packet = max_size_ok_status();
        let bridged = vec![0xabu8; MAX_MESSAGE_SIZE + 1];
        packet.extend_from_slice(&bridged);
        flow.on_data(&packet).unwrap();

        assert!(matches!(
            flow.outcome(),
            Some(ConnectOutcome::Bridged { .. })
        ));
        assert_eq!(flow.take_bridge_bytes(), bridged);
    }

    #[test]
    fn connect_post_bridge_data_goes_to_bridge_buffer() {
        let mut flow = HopConnect::new(b"peer".to_vec()).unwrap();
        connect_request(&mut flow);

        flow.on_data(&frame_hop(hop_status(Status::Ok))).unwrap();
        assert!(flow.take_bridge_bytes().is_empty());

        flow.on_data(b"more-data-from-peer").unwrap();
        assert_eq!(flow.take_bridge_bytes(), b"more-data-from-peer");
    }

    #[test]
    fn connect_handles_fragmented_response() {
        let mut flow = HopConnect::new(b"peer".to_vec()).unwrap();
        connect_request(&mut flow);

        for byte in &frame_hop(hop_status(Status::Ok)) {
            flow.on_data(&[*byte]).unwrap();
        }
        assert!(matches!(
            flow.outcome(),
            Some(ConnectOutcome::Bridged { .. })
        ));
    }

    #[test]
    fn connect_handles_refusal_and_drops_later_bytes() {
        let mut flow = HopConnect::new(b"peer".to_vec()).unwrap();
        connect_request(&mut flow);

        let mut packet = frame_hop(hop_status(Status::NoReservation));
        packet.extend_from_slice(b"not-a-circuit");
        flow.on_data(&packet).unwrap();

        assert!(matches!(
            flow.poll_output(),
            Some(HopConnectOutput::Outcome(ConnectOutcome::Refused {
                status: Status::NoReservation,
                ..
            }))
        ));
        assert!(flow.poll_output().is_none());
    }

    #[test]
    fn connect_rejects_oversized_declared_frame_length() {
        let mut flow = HopConnect::new(b"peer".to_vec()).unwrap();
        connect_request(&mut flow);

        let err = flow.on_data(&over_declared_header()).unwrap_err();
        assert_eq!(
            err,
            RelayError::FrameTooLarge {
                len: MAX_MESSAGE_SIZE as u64 + 1
            }
        );
        assert!(flow.is_done());
        // A failed flow never turns later bytes into bridge data.
        flow.on_data(b"after-failure").unwrap();
        assert!(flow.poll_output().is_none());
    }

    #[test]
    fn connect_constructor_refuses_an_oversized_target_peer_id() {
        // The oversized frame is never built: the caller learns at
        // construction, with no input needed to surface the error.
        assert!(matches!(
            HopConnect::new(vec![0u8; MAX_MESSAGE_SIZE + 1]),
            Err(RelayError::MessageTooLarge { len }) if len > MAX_MESSAGE_SIZE
        ));
    }

    #[test]
    fn connect_at_exact_max_size_still_encodes() {
        // Peer id sized so the encoded CONNECT payload is exactly
        // MAX_MESSAGE_SIZE: 2 bytes type field + 1 tag + 2-byte length
        // varint for the nested Peer + (1 tag + 2-byte length varint +
        // 8184 id bytes).
        let id = vec![0u8; 8184];
        let mut flow = HopConnect::new(id.clone()).unwrap();
        let bytes = connect_request(&mut flow);
        let FrameDecode::Complete { payload, .. } = decode_frame(&bytes) else {
            panic!("exactly-max CONNECT must be emitted");
        };
        assert_eq!(payload.len(), MAX_MESSAGE_SIZE);

        // One more byte and the frame must be refused.
        assert!(matches!(
            HopConnect::new(vec![0u8; 8185]).err(),
            Some(RelayError::MessageTooLarge { len }) if len == MAX_MESSAGE_SIZE + 1
        ));
    }

    // --- StopResponder ------------------------------------------------------

    #[test]
    fn stop_receives_connect_accepts_and_bridges() {
        let mut flow = StopResponder::new();

        // Incoming CONNECT from relay.
        let connect = frame_stop(StopMessage {
            limit: Some(Limit {
                duration: Some(300),
                data: None,
            }),
            ..stop_connect(b"source-peer")
        });
        flow.on_data(&connect).unwrap();

        let Some(StopResponderOutput::Request(request)) = flow.poll_output() else {
            panic!("request should be emitted");
        };
        assert_eq!(request.source_peer_id, b"source-peer");
        assert_eq!(request.limit.as_ref().and_then(|l| l.duration), Some(300));

        // Accept and verify outbound is STATUS:OK.
        flow.accept().unwrap();
        let Some(StopResponderOutput::Outbound(outbound)) = flow.poll_output() else {
            panic!("STATUS should be queued");
        };
        let FrameDecode::Complete { payload, .. } = decode_frame(&outbound) else {
            panic!();
        };
        let response = StopMessage::decode(payload).unwrap();
        assert_eq!(response.kind, StopMessageType::Status);
        assert_eq!(response.status, Some(Status::Ok));

        // Subsequent data is bridged.
        flow.on_data(b"relayed-peer-traffic").unwrap();
        assert_eq!(
            flow.poll_output(),
            Some(StopResponderOutput::BridgeData(
                b"relayed-peer-traffic".to_vec()
            ))
        );
    }

    #[test]
    fn stop_pipelined_bridge_bytes_follow_the_status_on_accept() {
        let mut flow = StopResponder::new();

        let mut packet = frame_stop(stop_connect(b"src"));
        packet.extend_from_slice(b"pipelined-bytes");
        flow.on_data(&packet).unwrap();
        assert!(matches!(
            flow.poll_output(),
            Some(StopResponderOutput::Request(_))
        ));
        flow.accept().unwrap();

        assert!(matches!(
            flow.poll_output(),
            Some(StopResponderOutput::Outbound(_))
        ));
        assert_eq!(
            flow.poll_output(),
            Some(StopResponderOutput::BridgeData(b"pipelined-bytes".to_vec()))
        );
    }

    #[test]
    fn stop_accepts_an_exactly_max_connect_with_pipelined_bytes() {
        // A STOP CONNECT whose payload is exactly MAX_MESSAGE_SIZE, with
        // bridge bytes coalesced behind it in one read.
        let connect = stop_connect(&[0u8; 8184]);
        assert_eq!(connect.encode().len(), MAX_MESSAGE_SIZE);
        let mut coalesced = frame_stop(connect);
        coalesced.extend_from_slice(b"early-bridge-bytes");

        let mut flow = StopResponder::new();
        flow.on_data(&coalesced)
            .expect("exactly-max STOP CONNECT + pipelined bytes must be accepted");
        assert!(matches!(
            flow.poll_output(),
            Some(StopResponderOutput::Request(_))
        ));
    }

    #[test]
    fn stop_rejects_oversized_declared_frame_length() {
        let mut flow = StopResponder::new();
        let err = flow.on_data(&over_declared_header()).unwrap_err();
        assert_eq!(
            err,
            RelayError::FrameTooLarge {
                len: MAX_MESSAGE_SIZE as u64 + 1
            }
        );
        assert!(flow.is_done());
    }

    #[test]
    fn stop_reject_emits_non_ok_status() {
        let mut flow = StopResponder::new();
        flow.on_data(&frame_stop(stop_connect(b"src"))).unwrap();
        flow.reject(Status::ConnectionFailed).unwrap();

        assert!(matches!(
            flow.poll_output(),
            Some(StopResponderOutput::Request(_))
        ));
        let Some(StopResponderOutput::Outbound(outbound)) = flow.poll_output() else {
            panic!("STATUS should be queued");
        };
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
            peer: None,
            ..stop_connect(b"")
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
        for byte in &frame_stop(stop_connect(b"src")) {
            flow.on_data(&[*byte]).unwrap();
        }
        assert!(flow.request().is_some());
    }
}
