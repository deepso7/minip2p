//! Sans-IO state machines for Circuit Relay v2.
//!
//! Implements three client-side flows:
//! - [`HopReservation`] -- reserve a slot on a relay (client -> relay).
//! - [`HopConnect`] -- ask a relay to connect us to another peer (client -> relay).
//! - [`StopResponder`] -- accept an incoming circuit from a relay (relay -> us).
//!
//! Each state machine is driven by feeding stream bytes in via [`on_data`]
//! methods and reading out a byte slice to send to the peer via
//! [`take_outbound`]. No I/O is performed inside; the caller is responsible
//! for writing to and reading from the underlying transport stream.
//!
//! `no_std` + `alloc` compatible.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod message;

use alloc::string::String;
use alloc::vec::Vec;

pub use message::{
    decode_frame, describe_status, encode_frame, FrameDecode, HopMessage, HopMessageType, Limit,
    Peer, RelayMessageError, Reservation, Status, StopMessage, StopMessageType,
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
    /// The incoming message exceeded the maximum allowed size.
    #[error("relay message exceeds maximum size ({len} > {MAX_MESSAGE_SIZE})")]
    MessageTooLarge { len: usize },
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

/// Client-side state machine for the HOP RESERVE flow.
///
/// Usage:
/// 1. Construct with [`HopReservation::new`].
/// 2. Call [`HopReservation::take_outbound`] and send the returned bytes on
///    the relay stream.
/// 3. Feed incoming stream bytes via [`HopReservation::on_data`].
/// 4. Poll [`HopReservation::outcome`] after each step; `Some(_)` means the
///    flow has completed (accepted or refused).
pub struct HopReservation {
    outbound: Vec<u8>,
    recv_buf: Vec<u8>,
    state: FlowState,
    outcome: Option<ReservationOutcome>,
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
        let body = request.encode();
        let outbound = encode_frame(&body);

        Self {
            outbound,
            recv_buf: Vec::new(),
            state: FlowState::Pending,
            outcome: None,
        }
    }

    /// Drains and returns any pending outbound bytes.
    ///
    /// Call this after construction and whenever you need to flush data to
    /// the relay stream.
    pub fn take_outbound(&mut self) -> Vec<u8> {
        if self.state == FlowState::Pending {
            self.state = FlowState::AwaitingResponse;
        }
        core::mem::take(&mut self.outbound)
    }

    /// Feeds incoming stream bytes from the relay.
    pub fn on_data(&mut self, data: &[u8]) -> Result<(), RelayError> {
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
    pub fn on_remote_write_closed(&mut self) -> Result<(), RelayError> {
        self.try_decode_response()
    }

    /// Returns the outcome of the flow, if available.
    pub fn outcome(&self) -> Option<&ReservationOutcome> {
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

        enforce_max_size(&self.recv_buf).map_err(|e| {
            self.state = FlowState::Done;
            e
        })?;

        let (payload, consumed) = match decode_frame(&self.recv_buf) {
            FrameDecode::Complete { payload, consumed } => (payload.to_vec(), consumed),
            FrameDecode::Incomplete => return Ok(()),
            FrameDecode::Error(e) => {
                self.state = FlowState::Done;
                return Err(RelayError::Malformed(RelayMessageError::Varint(e)));
            }
        };
        self.recv_buf.drain(..consumed);

        let msg = HopMessage::decode(&payload).map_err(|e| {
            self.state = FlowState::Done;
            RelayError::Malformed(e)
        })?;

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
    Refused {
        status: Status,
        reason: String,
    },
}

/// Client-side state machine for the HOP CONNECT flow.
///
/// Usage:
/// 1. Construct with [`HopConnect::new`], passing the target peer's id.
/// 2. Call [`HopConnect::take_outbound`] and send the returned bytes.
/// 3. Feed incoming stream bytes via [`HopConnect::on_data`].
/// 4. When [`HopConnect::outcome`] returns `ConnectOutcome::Bridged`, the
///    stream becomes the relay circuit: caller may drain leftover bytes via
///    [`HopConnect::take_bridge_bytes`] and treat subsequent stream data as
///    relayed peer-to-peer traffic.
pub struct HopConnect {
    outbound: Vec<u8>,
    recv_buf: Vec<u8>,
    state: FlowState,
    outcome: Option<ConnectOutcome>,
    bridge_bytes: Vec<u8>,
}

impl HopConnect {
    /// Creates a new CONNECT state machine targeting the given peer id.
    ///
    /// `target_peer_id` should be the multihash-encoded PeerId bytes.
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
        let body = request.encode();
        let outbound = encode_frame(&body);

        Self {
            outbound,
            recv_buf: Vec::new(),
            state: FlowState::Pending,
            outcome: None,
            bridge_bytes: Vec::new(),
        }
    }

    /// Drains and returns any pending outbound bytes.
    pub fn take_outbound(&mut self) -> Vec<u8> {
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
    pub fn on_data(&mut self, data: &[u8]) -> Result<(), RelayError> {
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
    pub fn on_remote_write_closed(&mut self) -> Result<(), RelayError> {
        self.try_decode_response()
    }

    /// Returns the outcome of the flow, if available.
    pub fn outcome(&self) -> Option<&ConnectOutcome> {
        self.outcome.as_ref()
    }

    /// Returns `true` if the flow has completed.
    pub fn is_done(&self) -> bool {
        self.state == FlowState::Done
    }

    /// Drains any bridged relay traffic received since the last call.
    ///
    /// Only yields bytes after the flow transitions to `Bridged`.
    pub fn take_bridge_bytes(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.bridge_bytes)
    }

    /// Attempts to decode the response from the receive buffer.
    fn try_decode_response(&mut self) -> Result<(), RelayError> {
        if self.state == FlowState::Done {
            return Ok(());
        }

        enforce_max_size(&self.recv_buf).map_err(|e| {
            self.state = FlowState::Done;
            e
        })?;

        let (payload, consumed) = match decode_frame(&self.recv_buf) {
            FrameDecode::Complete { payload, consumed } => (payload.to_vec(), consumed),
            FrameDecode::Incomplete => return Ok(()),
            FrameDecode::Error(e) => {
                self.state = FlowState::Done;
                return Err(RelayError::Malformed(RelayMessageError::Varint(e)));
            }
        };
        self.recv_buf.drain(..consumed);

        let msg = HopMessage::decode(&payload).map_err(|e| {
            self.state = FlowState::Done;
            RelayError::Malformed(e)
        })?;

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

/// Server-side state machine for the STOP protocol (we are the destination).
///
/// Flow:
/// 1. Relay opens a STOP stream to us and sends a CONNECT message.
/// 2. We decode it via [`StopResponder::on_data`] -> observe
///    [`StopResponder::request`] populated.
/// 3. We decide to accept or reject and call [`StopResponder::accept`] or
///    [`StopResponder::reject`].
/// 4. We send the resulting outbound bytes via [`StopResponder::take_outbound`].
/// 5. If accepted, the stream becomes the bridged circuit; drain leftover
///    bytes via [`StopResponder::take_bridge_bytes`].
pub struct StopResponder {
    outbound: Vec<u8>,
    recv_buf: Vec<u8>,
    state: StopState,
    request: Option<StopConnectRequest>,
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
            bridge_bytes: Vec::new(),
        }
    }

    /// Drains and returns any pending outbound bytes.
    pub fn take_outbound(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outbound)
    }

    /// Feeds incoming stream bytes from the relay.
    pub fn on_data(&mut self, data: &[u8]) -> Result<(), RelayError> {
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
    pub fn on_remote_write_closed(&mut self) -> Result<(), RelayError> {
        self.try_decode_connect()
    }

    /// Returns the decoded CONNECT request, if received.
    pub fn request(&self) -> Option<&StopConnectRequest> {
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
    pub fn accept(&mut self) -> Result<(), RelayError> {
        self.send_status(Status::Ok, StopState::Bridged)?;
        // Any bytes the relay pipelined after its CONNECT belong to the bridge.
        if !self.recv_buf.is_empty() {
            self.bridge_bytes.append(&mut self.recv_buf);
        }
        Ok(())
    }

    /// Rejects the CONNECT request with the given status code.
    pub fn reject(&mut self, status: Status) -> Result<(), RelayError> {
        self.send_status(status, StopState::Done)
    }

    /// Drains any bridged relay traffic received since the last call.
    pub fn take_bridge_bytes(&mut self) -> Vec<u8> {
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

        enforce_max_size(&self.recv_buf).map_err(|e| {
            self.state = StopState::Done;
            e
        })?;

        let (payload, consumed) = match decode_frame(&self.recv_buf) {
            FrameDecode::Complete { payload, consumed } => (payload.to_vec(), consumed),
            FrameDecode::Incomplete => return Ok(()),
            FrameDecode::Error(e) => {
                self.state = StopState::Done;
                return Err(RelayError::Malformed(RelayMessageError::Varint(e)));
            }
        };
        self.recv_buf.drain(..consumed);

        let msg = StopMessage::decode(&payload).map_err(|e| {
            self.state = StopState::Done;
            RelayError::Malformed(e)
        })?;

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

/// Rejects an oversized receive buffer to protect against memory exhaustion.
fn enforce_max_size(buf: &[u8]) -> Result<(), RelayError> {
    if buf.len() > MAX_MESSAGE_SIZE {
        return Err(RelayError::MessageTooLarge { len: buf.len() });
    }
    Ok(())
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
                assert_eq!(reservation.as_ref().and_then(|r| r.expire), Some(2_000_000_000));
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
            Some(ConnectOutcome::Refused { status: Status::NoReservation, .. })
        ));
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
}
