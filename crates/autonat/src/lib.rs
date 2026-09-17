//! Sans-IO state machines for libp2p AutoNAT v1.
//!
//! AutoNAT probes whether a peer's advertised addresses are reachable through
//! real libp2p dials. This crate only handles protocol bytes and state; callers
//! own streams, dial-back attempts, timers, and policy decisions.
//!
//! Field framing uses the shared protobuf vocabulary in [`minip2p_core`];
//! AutoNAT keeps its message types, semantic checks (including rejecting field
//! number 0), and contextual [`AutoNatError`] values.
//!
//! `no_std` + `alloc` compatible.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use minip2p_core::{
    Multiaddr, PeerId, SansIoProtocol, WIRE_LEN, WIRE_VARINT, WireError, encode_bytes_field,
    encode_nested_field, encode_varint_field, read_len_delimited, read_tag, read_varint_value,
    skip_field,
};
#[cfg(test)]
use minip2p_core::{VarintError, write_uvarint};

/// Protocol id for AutoNAT v1.
pub const AUTONAT_PROTOCOL_ID: &str = "/libp2p/autonat/1.0.0";

/// Maximum size for one AutoNAT frame.
pub const MAX_MESSAGE_SIZE: usize = 8192;

#[cfg(test)]
const TAG_TYPE: u8 = (1 << 3) | WIRE_VARINT;

/// Top-level AutoNAT message type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MessageType {
    /// Request that the service dial the supplied peer addresses.
    Dial = 0,
    /// Service result for a dial request.
    DialResponse = 1,
}

impl MessageType {
    fn from_u64(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::Dial),
            1 => Some(Self::DialResponse),
            _ => None,
        }
    }
}

/// AutoNAT response status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseStatus {
    /// Dial-back succeeded.
    Ok = 0,
    /// Dial-back failed.
    DialError = 100,
    /// Service refused to dial, usually due to policy/rate limiting.
    DialRefused = 101,
    /// Request was malformed.
    BadRequest = 200,
    /// Service failed internally.
    InternalError = 300,
}

impl ResponseStatus {
    fn from_u64(value: u64) -> Self {
        match value {
            0 => Self::Ok,
            100 => Self::DialError,
            101 => Self::DialRefused,
            200 => Self::BadRequest,
            300 => Self::InternalError,
            _ => Self::InternalError,
        }
    }
}

/// Reachability result emitted by the client state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reachability {
    /// AutoNAT service successfully dialed at least one advertised address.
    Public {
        /// Addresses the service reports as dialable.
        addrs: Vec<Multiaddr>,
        /// Raw address bytes from the response, retained for diagnostics.
        raw_addrs: Vec<Vec<u8>>,
    },
    /// Dial-back failed or was refused, so the peer is likely private.
    Private {
        /// Response status.
        status: ResponseStatus,
        /// Human-readable service-provided reason, if any.
        reason: String,
    },
    /// The service could not provide a useful result.
    Unknown {
        /// Response status.
        status: ResponseStatus,
        /// Human-readable service-provided reason, if any.
        reason: String,
    },
}

/// Dial-back request emitted by the server state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutoNatRequest {
    /// Peer the service should dial back.
    pub peer_id: PeerId,
    /// Parsed candidate addresses.
    pub addrs: Vec<Multiaddr>,
    /// Raw candidate address bytes from the request.
    pub raw_addrs: Vec<Vec<u8>>,
}

/// Input accepted by [`AutoNatClient`] through [`SansIoProtocol`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AutoNatClientInput {
    /// Drain any queued request bytes into an output.
    Flush,
    /// Bytes received from the AutoNAT service stream.
    Data(Vec<u8>),
    /// Remote write side closed. The local side remains usable; this lets the
    /// client finish decoding any buffered response bytes.
    RemoteWriteClosed,
}

/// Output produced by [`AutoNatClient`] through [`SansIoProtocol`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AutoNatClientOutput {
    /// Bytes to write to the AutoNAT service stream.
    Outbound(Vec<u8>),
    /// Reachability result decoded from the service response.
    Outcome(Reachability),
}

/// Input accepted by [`AutoNatServer`] through [`SansIoProtocol`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AutoNatServerInput {
    /// Bytes received from the requester stream.
    Data(Vec<u8>),
    /// Queue a successful DIAL_RESPONSE with dialable addresses.
    RespondPublic { addrs: Vec<Multiaddr> },
    /// Queue an unsuccessful DIAL_RESPONSE.
    RespondError {
        /// Response status.
        status: ResponseStatus,
        /// Human-readable reason.
        reason: String,
    },
    /// Drain any queued response bytes into an output.
    Flush,
}

/// Output produced by [`AutoNatServer`] through [`SansIoProtocol`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AutoNatServerOutput {
    /// Dial-back request decoded from the requester.
    Request(AutoNatRequest),
    /// Bytes to write to the requester stream.
    Outbound(Vec<u8>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PeerInfo {
    id: Vec<u8>,
    addrs: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Dial {
    peer: Option<PeerInfo>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DialResponse {
    status: ResponseStatus,
    status_text: Option<String>,
    addrs: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Message {
    kind: MessageType,
    dial: Option<Dial>,
    dial_response: Option<DialResponse>,
}

/// AutoNAT state-machine and message errors.
///
/// Shared framing failures are wrapped as [`Self::Wire`] so callers retain
/// AutoNAT context while reusing the core protobuf vocabulary.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AutoNatError {
    /// Incoming message exceeded the configured maximum size.
    #[error("AutoNAT message exceeds maximum size ({len} > {MAX_MESSAGE_SIZE})")]
    MessageTooLarge { len: usize },
    /// Frame prefix declared a message larger than the configured maximum size.
    #[error("AutoNAT frame length exceeds maximum size ({len} > {MAX_MESSAGE_SIZE})")]
    FrameTooLarge { len: u64 },
    /// A shared protobuf framing failure.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// Required message type field was missing.
    #[error("required `type` field missing")]
    MissingType,
    /// Unknown message type value.
    #[error("invalid message type value: {value}")]
    InvalidMessageType { value: u64 },
    /// Required nested field was missing.
    #[error("required field missing: {0}")]
    MissingField(&'static str),
    /// The remote sent a message that is invalid for this state.
    #[error("unexpected message: {0}")]
    UnexpectedMessage(String),
    /// PeerId bytes could not be decoded.
    #[error("invalid peer id in AutoNAT message: {0}")]
    InvalidPeerId(String),
}

/// Client-side AutoNAT probe.
pub struct AutoNatClient {
    outbound: Vec<u8>,
    recv_buf: Vec<u8>,
    state: FlowState,
    outcome: Option<Reachability>,
    emitted_outcome: bool,
}

/// Server-side AutoNAT request handler.
pub struct AutoNatServer {
    outbound: Vec<u8>,
    recv_buf: Vec<u8>,
    request: Option<AutoNatRequest>,
    emitted_request: bool,
    state: ServerState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlowState {
    Pending,
    AwaitingResponse,
    Done,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServerState {
    AwaitingRequest,
    RequestReady,
    Done,
}

impl AutoNatClient {
    /// Creates a client probe and queues a DIAL request.
    pub fn new(peer_id: &PeerId, addrs: &[Multiaddr]) -> Self {
        let peer = PeerInfo {
            id: peer_id.to_bytes(),
            addrs: addrs.iter().map(Multiaddr::to_bytes).collect(),
        };
        let msg = Message {
            kind: MessageType::Dial,
            dial: Some(Dial { peer: Some(peer) }),
            dial_response: None,
        };
        Self {
            outbound: encode_frame(&msg.encode()),
            recv_buf: Vec::new(),
            state: FlowState::Pending,
            outcome: None,
            emitted_outcome: false,
        }
    }

    /// Drains pending outbound bytes.
    fn take_outbound(&mut self) -> Vec<u8> {
        if self.state == FlowState::Pending {
            self.state = FlowState::AwaitingResponse;
        }
        core::mem::take(&mut self.outbound)
    }

    /// Feeds incoming bytes from the AutoNAT service stream.
    fn on_data(&mut self, data: &[u8]) -> Result<(), AutoNatError> {
        if self.state == FlowState::Done {
            return Ok(());
        }
        self.recv_buf.extend_from_slice(data);
        self.try_decode_response()
    }

    /// Notifies the client that the remote write half has closed.
    fn on_remote_write_closed(&mut self) -> Result<(), AutoNatError> {
        self.try_decode_response()
    }

    /// Returns the reachability outcome, if available.
    #[cfg(test)]
    fn outcome(&self) -> Option<&Reachability> {
        self.outcome.as_ref()
    }

    fn try_decode_response(&mut self) -> Result<(), AutoNatError> {
        enforce_max_size(&self.recv_buf)?;
        let (decoded, consumed) = match decode_frame(&self.recv_buf) {
            FrameDecode::Complete { payload, consumed } => (Message::decode(payload), consumed),
            FrameDecode::Incomplete => return Ok(()),
            FrameDecode::TooLarge { len } => return Err(AutoNatError::FrameTooLarge { len }),
            FrameDecode::Error(e) => return Err(WireError::from(e).into()),
        };
        self.recv_buf.drain(..consumed);
        let msg = decoded?;

        if msg.kind != MessageType::DialResponse {
            self.state = FlowState::Done;
            return Err(AutoNatError::UnexpectedMessage(
                "expected DIAL_RESPONSE".into(),
            ));
        }
        let response = msg
            .dial_response
            .ok_or(AutoNatError::MissingField("dial_response"))?;
        let reason = response.status_text.unwrap_or_default();
        let raw_addrs = response.addrs;

        self.outcome = Some(match response.status {
            ResponseStatus::Ok => Reachability::Public {
                addrs: decode_addrs(&raw_addrs),
                raw_addrs,
            },
            ResponseStatus::DialError | ResponseStatus::DialRefused => Reachability::Private {
                status: response.status,
                reason,
            },
            ResponseStatus::BadRequest | ResponseStatus::InternalError => Reachability::Unknown {
                status: response.status,
                reason,
            },
        });
        self.state = FlowState::Done;
        Ok(())
    }
}

impl AutoNatServer {
    /// Creates a server state machine awaiting one DIAL request.
    pub fn new() -> Self {
        Self {
            outbound: Vec::new(),
            recv_buf: Vec::new(),
            request: None,
            emitted_request: false,
            state: ServerState::AwaitingRequest,
        }
    }

    /// Feeds incoming bytes from a requester.
    fn on_data(&mut self, data: &[u8]) -> Result<(), AutoNatError> {
        if self.state != ServerState::AwaitingRequest {
            return Ok(());
        }
        self.recv_buf.extend_from_slice(data);
        self.try_decode_request()
    }

    /// Returns the parsed dial-back request, if ready.
    #[cfg(test)]
    fn request(&self) -> Option<&AutoNatRequest> {
        self.request.as_ref()
    }

    /// Queues a successful DIAL_RESPONSE with dialable addresses.
    fn respond_public(&mut self, addrs: &[Multiaddr]) {
        self.respond(ResponseStatus::Ok, None, addrs);
    }

    /// Queues an unsuccessful DIAL_RESPONSE.
    fn respond_error(&mut self, status: ResponseStatus, reason: impl Into<String>) {
        self.respond(status, Some(reason.into()), &[]);
    }

    /// Drains pending outbound bytes.
    fn take_outbound(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outbound)
    }

    fn respond(
        &mut self,
        status: ResponseStatus,
        status_text: Option<String>,
        addrs: &[Multiaddr],
    ) {
        let msg = Message {
            kind: MessageType::DialResponse,
            dial: None,
            dial_response: Some(DialResponse {
                status,
                status_text,
                addrs: addrs.iter().map(Multiaddr::to_bytes).collect(),
            }),
        };
        self.outbound = encode_frame(&msg.encode());
        self.state = ServerState::Done;
    }

    fn try_decode_request(&mut self) -> Result<(), AutoNatError> {
        enforce_max_size(&self.recv_buf)?;
        let (decoded, consumed) = match decode_frame(&self.recv_buf) {
            FrameDecode::Complete { payload, consumed } => (Message::decode(payload), consumed),
            FrameDecode::Incomplete => return Ok(()),
            FrameDecode::TooLarge { len } => return Err(AutoNatError::FrameTooLarge { len }),
            FrameDecode::Error(e) => return Err(WireError::from(e).into()),
        };
        self.recv_buf.drain(..consumed);
        let msg = decoded?;

        if msg.kind != MessageType::Dial {
            self.state = ServerState::Done;
            return Err(AutoNatError::UnexpectedMessage("expected DIAL".into()));
        }
        let dial = msg.dial.ok_or(AutoNatError::MissingField("dial"))?;
        let peer = dial.peer.ok_or(AutoNatError::MissingField("dial.peer"))?;
        let peer_id =
            PeerId::from_bytes(&peer.id).map_err(|e| AutoNatError::InvalidPeerId(e.to_string()))?;
        let addrs = decode_addrs(&peer.addrs);
        self.request = Some(AutoNatRequest {
            peer_id,
            addrs,
            raw_addrs: peer.addrs,
        });
        self.emitted_request = false;
        self.state = ServerState::RequestReady;
        Ok(())
    }
}

impl SansIoProtocol for AutoNatClient {
    type Input = AutoNatClientInput;
    type Output = AutoNatClientOutput;
    type Error = AutoNatError;

    fn handle_input(&mut self, input: Self::Input) -> Result<(), Self::Error> {
        match input {
            AutoNatClientInput::Flush => {}
            AutoNatClientInput::Data(data) => self.on_data(&data)?,
            AutoNatClientInput::RemoteWriteClosed => self.on_remote_write_closed()?,
        }
        Ok(())
    }

    fn poll_output(&mut self) -> Option<Self::Output> {
        let outbound = self.take_outbound();
        if !outbound.is_empty() {
            return Some(AutoNatClientOutput::Outbound(outbound));
        }
        if !self.emitted_outcome
            && let Some(outcome) = self.outcome.clone()
        {
            self.emitted_outcome = true;
            return Some(AutoNatClientOutput::Outcome(outcome));
        }
        None
    }

    fn is_idle(&self) -> bool {
        self.outbound.is_empty() && (self.emitted_outcome || self.outcome.is_none())
    }
}

impl SansIoProtocol for AutoNatServer {
    type Input = AutoNatServerInput;
    type Output = AutoNatServerOutput;
    type Error = AutoNatError;

    fn handle_input(&mut self, input: Self::Input) -> Result<(), Self::Error> {
        match input {
            AutoNatServerInput::Data(data) => self.on_data(&data)?,
            AutoNatServerInput::RespondPublic { addrs } => self.respond_public(&addrs),
            AutoNatServerInput::RespondError { status, reason } => {
                self.respond_error(status, reason)
            }
            AutoNatServerInput::Flush => {}
        }
        Ok(())
    }

    fn poll_output(&mut self) -> Option<Self::Output> {
        if !self.emitted_request
            && let Some(request) = self.request.clone()
        {
            self.emitted_request = true;
            return Some(AutoNatServerOutput::Request(request));
        }
        let outbound = self.take_outbound();
        if !outbound.is_empty() {
            return Some(AutoNatServerOutput::Outbound(outbound));
        }
        None
    }

    fn is_idle(&self) -> bool {
        self.outbound.is_empty() && (self.emitted_request || self.request.is_none())
    }
}

impl Default for AutoNatServer {
    fn default() -> Self {
        Self::new()
    }
}

pub use minip2p_core::{FrameDecode, encode_frame};

/// Decodes a varint-length-prefixed frame from `input`.
///
/// A declared payload length greater than [`MAX_MESSAGE_SIZE`] is rejected
/// with [`FrameDecode::TooLarge`].
pub fn decode_frame(input: &[u8]) -> FrameDecode<'_> {
    minip2p_core::decode_frame(input, MAX_MESSAGE_SIZE)
}

impl Message {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_varint_field(&mut out, 1, self.kind as u64);
        if let Some(dial) = &self.dial {
            encode_nested_field(&mut out, 2, &dial.encode());
        }
        if let Some(response) = &self.dial_response {
            encode_nested_field(&mut out, 3, &response.encode());
        }
        out
    }

    fn decode(input: &[u8]) -> Result<Self, AutoNatError> {
        let mut idx = 0;
        let mut kind = None;
        let mut dial = None;
        let mut dial_response = None;
        while let Some((field, wire)) = read_autonat_tag(input, &mut idx)? {
            match (field, wire) {
                (1, WIRE_VARINT) => {
                    let value = read_varint_value(input, &mut idx)?;
                    kind = Some(
                        MessageType::from_u64(value)
                            .ok_or(AutoNatError::InvalidMessageType { value })?,
                    );
                }
                (2, WIRE_LEN) => dial = Some(Dial::decode(read_len_delimited(input, &mut idx)?)?),
                (3, WIRE_LEN) => {
                    dial_response =
                        Some(DialResponse::decode(read_len_delimited(input, &mut idx)?)?)
                }
                _ => skip_field(input, &mut idx, wire)?,
            }
        }
        Ok(Self {
            kind: kind.ok_or(AutoNatError::MissingType)?,
            dial,
            dial_response,
        })
    }
}

impl Dial {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(peer) = &self.peer {
            encode_nested_field(&mut out, 1, &peer.encode());
        }
        out
    }

    fn decode(input: &[u8]) -> Result<Self, AutoNatError> {
        let mut idx = 0;
        let mut peer = None;
        while let Some((field, wire)) = read_autonat_tag(input, &mut idx)? {
            match (field, wire) {
                (1, WIRE_LEN) => {
                    peer = Some(PeerInfo::decode(read_len_delimited(input, &mut idx)?)?)
                }
                _ => skip_field(input, &mut idx, wire)?,
            }
        }
        Ok(Self { peer })
    }
}

impl PeerInfo {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_bytes_field(&mut out, 1, &self.id);
        for addr in &self.addrs {
            encode_bytes_field(&mut out, 2, addr);
        }
        out
    }

    fn decode(input: &[u8]) -> Result<Self, AutoNatError> {
        let mut idx = 0;
        let mut id = Vec::new();
        let mut addrs = Vec::new();
        while let Some((field, wire)) = read_autonat_tag(input, &mut idx)? {
            match (field, wire) {
                (1, WIRE_LEN) => id = read_len_delimited(input, &mut idx)?.to_vec(),
                (2, WIRE_LEN) => addrs.push(read_len_delimited(input, &mut idx)?.to_vec()),
                _ => skip_field(input, &mut idx, wire)?,
            }
        }
        Ok(Self { id, addrs })
    }
}

impl DialResponse {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_varint_field(&mut out, 1, self.status as u64);
        if let Some(text) = &self.status_text {
            encode_bytes_field(&mut out, 2, text.as_bytes());
        }
        for addr in &self.addrs {
            encode_bytes_field(&mut out, 3, addr);
        }
        out
    }

    fn decode(input: &[u8]) -> Result<Self, AutoNatError> {
        let mut idx = 0;
        let mut status = ResponseStatus::InternalError;
        let mut status_text = None;
        let mut addrs = Vec::new();
        while let Some((field, wire)) = read_autonat_tag(input, &mut idx)? {
            match (field, wire) {
                (1, WIRE_VARINT) => {
                    status = ResponseStatus::from_u64(read_varint_value(input, &mut idx)?)
                }
                (2, WIRE_LEN) => {
                    let text = read_len_delimited(input, &mut idx)?;
                    status_text = Some(String::from_utf8_lossy(text).into_owned());
                }
                (3, WIRE_LEN) => addrs.push(read_len_delimited(input, &mut idx)?.to_vec()),
                _ => skip_field(input, &mut idx, wire)?,
            }
        }
        Ok(Self {
            status,
            status_text,
            addrs,
        })
    }
}

fn decode_addrs(raw: &[Vec<u8>]) -> Vec<Multiaddr> {
    raw.iter()
        .filter_map(|bytes| Multiaddr::from_bytes(bytes).ok())
        .collect()
}

fn enforce_max_size(buf: &[u8]) -> Result<(), AutoNatError> {
    if buf.len() > MAX_MESSAGE_SIZE {
        return Err(AutoNatError::MessageTooLarge { len: buf.len() });
    }
    Ok(())
}

/// AutoNAT rejects protobuf field number 0; shared `read_tag` leaves that policy to callers.
fn read_autonat_tag(input: &[u8], idx: &mut usize) -> Result<Option<(u64, u8)>, AutoNatError> {
    let offset = *idx;
    match read_tag(input, idx)? {
        Some((0, wire_type)) => Err(WireError::UnsupportedWireType { wire_type, offset }.into()),
        other => Ok(other),
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use core::str::FromStr;

    use super::*;

    const PEER_ID: &str = "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N";

    #[test]
    fn client_server_public_round_trip() {
        let peer_id = PeerId::from_str(PEER_ID).unwrap();
        let addr = Multiaddr::from_str("/ip4/203.0.113.7/udp/4001/quic-v1").unwrap();
        let mut client = AutoNatClient::new(&peer_id, core::slice::from_ref(&addr));
        let mut server = AutoNatServer::new();

        server.on_data(&client.take_outbound()).unwrap();
        let request = server.request().expect("request should decode");
        assert_eq!(request.peer_id, peer_id);
        assert_eq!(request.addrs, vec![addr.clone()]);

        server.respond_public(&request.addrs.clone());
        client.on_data(&server.take_outbound()).unwrap();

        assert!(
            matches!(client.outcome(), Some(Reachability::Public { addrs, .. }) if addrs == &vec![addr])
        );
    }

    #[test]
    fn client_maps_dial_error_to_private() {
        let peer_id = PeerId::from_str(PEER_ID).unwrap();
        let mut client = AutoNatClient::new(&peer_id, &[]);
        let mut server = AutoNatServer::new();

        server.on_data(&client.take_outbound()).unwrap();
        server.respond_error(ResponseStatus::DialError, "all dialbacks failed");
        client.on_data(&server.take_outbound()).unwrap();

        assert!(
            matches!(client.outcome(), Some(Reachability::Private { status: ResponseStatus::DialError, reason }) if reason == "all dialbacks failed")
        );
    }

    #[test]
    fn client_consumes_bad_frame_before_decode_error() {
        let peer_id = PeerId::from_str(PEER_ID).unwrap();
        let mut client = AutoNatClient::new(&peer_id, &[]);
        let _ = client.take_outbound();

        let bad_frame = encode_frame(&[TAG_TYPE, 99]);
        assert!(matches!(
            client.on_data(&bad_frame),
            Err(AutoNatError::InvalidMessageType { value: 99 })
        ));

        let mut server = AutoNatServer::new();
        server.respond_error(ResponseStatus::DialError, "after bad frame");
        client.on_data(&server.take_outbound()).unwrap();

        assert!(
            matches!(client.outcome(), Some(Reachability::Private { status: ResponseStatus::DialError, reason }) if reason == "after bad frame")
        );
    }

    #[test]
    fn server_consumes_bad_frame_before_decode_error() {
        let mut server = AutoNatServer::new();

        let bad_frame = encode_frame(&[TAG_TYPE, 99]);
        assert!(matches!(
            server.on_data(&bad_frame),
            Err(AutoNatError::InvalidMessageType { value: 99 })
        ));

        let peer_id = PeerId::from_str(PEER_ID).unwrap();
        let addr = Multiaddr::from_str("/ip4/203.0.113.7/udp/4001/quic-v1").unwrap();
        let mut client = AutoNatClient::new(&peer_id, core::slice::from_ref(&addr));
        server.on_data(&client.take_outbound()).unwrap();

        let request = server
            .request()
            .expect("request should decode after bad frame");
        assert_eq!(request.peer_id, peer_id);
        assert_eq!(request.addrs, vec![addr]);
    }

    #[test]
    fn rejects_declared_frame_length_above_max() {
        let mut frame = Vec::new();
        write_uvarint((MAX_MESSAGE_SIZE + 1) as u64, &mut frame);

        assert_eq!(
            decode_frame(&frame),
            FrameDecode::TooLarge {
                len: (MAX_MESSAGE_SIZE + 1) as u64
            }
        );
    }

    #[test]
    fn dial_encode_matches_known_bytes() {
        // type=DIAL, nested Dial { Peer { id = [0xaa], no addrs } }
        let msg = Message {
            kind: MessageType::Dial,
            dial: Some(Dial {
                peer: Some(PeerInfo {
                    id: vec![0xaa],
                    addrs: Vec::new(),
                }),
            }),
            dial_response: None,
        };
        assert_eq!(
            msg.encode(),
            vec![
                0x08, 0x00, // type = DIAL
                0x12, 0x05, // dial LEN 5
                0x0a, 0x03, // peer LEN 3
                0x0a, 0x01, 0xaa, // peer.id
            ]
        );
    }

    #[test]
    fn dial_response_encode_matches_known_bytes() {
        let msg = Message {
            kind: MessageType::DialResponse,
            dial: None,
            dial_response: Some(DialResponse {
                status: ResponseStatus::Ok,
                status_text: Some(String::from("ok")),
                addrs: vec![vec![0x04, 127, 0, 0, 1]],
            }),
        };
        assert_eq!(
            msg.encode(),
            vec![
                0x08, 0x01, // type = DIAL_RESPONSE
                0x1a, 0x0d, // dialResponse LEN 13
                0x08, 0x00, // status = OK
                0x12, 0x02, b'o', b'k', // statusText
                0x1a, 0x05, 0x04, 127, 0, 0, 1, // addr
            ]
        );
    }

    #[test]
    fn decode_rejects_field_number_zero() {
        let err = Message::decode(&[0x02, 0x00]).unwrap_err();
        assert!(matches!(
            err,
            AutoNatError::Wire(WireError::UnsupportedWireType {
                wire_type: WIRE_LEN,
                offset: 0
            })
        ));
    }

    #[test]
    fn wire_failures_keep_autonat_display() {
        let err = Message::decode(&[0x12, 0x05, b'a', b'b']).unwrap_err();
        assert!(matches!(
            err,
            AutoNatError::Wire(WireError::FieldOverflow {
                offset: 2,
                length: 5,
                remaining: 2
            })
        ));
        let display = alloc::format!("{err}");
        assert!(
            display.contains("claims length"),
            "wire detail should remain visible: {display}"
        );
    }

    #[test]
    fn client_and_server_implement_sans_io_protocol() {
        let peer_id = PeerId::from_str(PEER_ID).unwrap();
        let addr = Multiaddr::from_str("/ip4/203.0.113.7/udp/4001/quic-v1").unwrap();
        let mut client = AutoNatClient::new(&peer_id, core::slice::from_ref(&addr));
        let mut server = AutoNatServer::new();

        client.handle_input(AutoNatClientInput::Flush).unwrap();
        let Some(AutoNatClientOutput::Outbound(request_bytes)) = client.poll_output() else {
            panic!("client should emit request bytes");
        };

        server
            .handle_input(AutoNatServerInput::Data(request_bytes))
            .unwrap();
        let Some(AutoNatServerOutput::Request(request)) = server.poll_output() else {
            panic!("server should emit request");
        };
        assert_eq!(request.peer_id, peer_id);

        server
            .handle_input(AutoNatServerInput::RespondPublic {
                addrs: request.addrs,
            })
            .unwrap();
        let Some(AutoNatServerOutput::Outbound(response_bytes)) = server.poll_output() else {
            panic!("server should emit response bytes");
        };

        client
            .handle_input(AutoNatClientInput::Data(response_bytes))
            .unwrap();
        assert!(matches!(
            client.poll_output(),
            Some(AutoNatClientOutput::Outcome(Reachability::Public { addrs, .. }))
                if addrs == vec![addr]
        ));
        assert!(client.is_idle());
    }
}

/// Golden equivalence tests for the varint-length-prefixed frame codec.
///
/// The fixed vectors pin the exact wire behavior of the codec this crate
/// originally implemented locally; after consolidation into `minip2p-core`
/// they exercise the shared codec through this crate's wrappers and must
/// keep passing byte for byte.
#[cfg(test)]
mod frame_golden {
    use super::*;

    #[test]
    fn golden_empty_payload() {
        assert_eq!(encode_frame(&[]), [0x00]);
        assert!(matches!(
            decode_frame(&[0x00]),
            FrameDecode::Complete { payload, consumed: 1 } if payload.is_empty()
        ));
    }

    #[test]
    fn golden_single_byte_payload() {
        assert_eq!(encode_frame(b"\xab"), [0x01, 0xab]);
        assert!(matches!(
            decode_frame(&[0x01, 0xab]),
            FrameDecode::Complete { payload, consumed: 2 } if payload == b"\xab"
        ));
    }

    #[test]
    fn golden_payload_at_max_len() {
        let payload = vec![0x5au8; MAX_MESSAGE_SIZE];
        let framed = encode_frame(&payload);
        // 8192 as a minimal uvarint.
        assert_eq!(framed[..2], [0x80, 0x40]);
        assert_eq!(framed.len(), MAX_MESSAGE_SIZE + 2);
        assert!(matches!(
            decode_frame(&framed),
            FrameDecode::Complete { payload: p, consumed }
                if p == payload.as_slice() && consumed == MAX_MESSAGE_SIZE + 2
        ));
    }

    #[test]
    fn golden_declared_len_above_max_too_large() {
        // 8193 as a minimal uvarint; rejected from the header alone.
        assert!(matches!(
            decode_frame(&[0x81, 0x40]),
            FrameDecode::TooLarge { len } if len as u128 == 8193
        ));
    }

    #[test]
    fn golden_declared_len_u64_max_too_large() {
        // u64::MAX as a 10-byte uvarint, followed by a garbage byte.
        let input = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x22,
        ];
        assert!(matches!(
            decode_frame(&input),
            FrameDecode::TooLarge { len } if len as u128 == u128::from(u64::MAX)
        ));
    }

    #[test]
    fn golden_truncated_header_incomplete() {
        assert!(matches!(decode_frame(&[]), FrameDecode::Incomplete));
        // Continuation bit set with no following byte.
        assert!(matches!(decode_frame(&[0x80]), FrameDecode::Incomplete));
    }

    #[test]
    fn golden_truncated_payload_incomplete() {
        // Declares 5 bytes, only 2 buffered.
        assert!(matches!(
            decode_frame(&[0x05, 0xaa, 0xbb]),
            FrameDecode::Incomplete
        ));
        let framed = encode_frame(b"hello");
        assert!(matches!(
            decode_frame(&framed[..framed.len() - 1]),
            FrameDecode::Incomplete
        ));
    }

    #[test]
    fn golden_oversized_varint_header_error() {
        // Ten continuation bytes overflow u64 before the varint terminates.
        assert!(matches!(
            decode_frame(&[0xff; 10]),
            FrameDecode::Error(VarintError::Overflow)
        ));
    }

    #[test]
    fn golden_non_minimal_length_rejected() {
        // Length 1 encoded in two bytes ([0x81, 0x00]) is non-canonical.
        assert!(matches!(
            decode_frame(&[0x81, 0x00, 0xaa]),
            FrameDecode::Error(VarintError::NonCanonical)
        ));
    }

    #[test]
    fn golden_multi_frame_consumed() {
        let mut buf = encode_frame(b"first");
        buf.extend_from_slice(&encode_frame(b"second"));
        let consumed = match decode_frame(&buf) {
            FrameDecode::Complete { payload, consumed } => {
                assert_eq!(payload, b"first");
                assert_eq!(consumed, 6);
                consumed
            }
            _ => panic!("expected first frame"),
        };
        assert!(matches!(
            decode_frame(&buf[consumed..]),
            FrameDecode::Complete { payload, consumed: 7 } if payload == b"second"
        ));
    }
}
