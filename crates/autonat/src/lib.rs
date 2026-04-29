//! Sans-IO state machines for libp2p AutoNAT v1.
//!
//! AutoNAT probes whether a peer's advertised addresses are reachable through
//! real libp2p dials. This crate only handles protocol bytes and state; callers
//! own streams, dial-back attempts, timers, and policy decisions.
//!
//! `no_std` + `alloc` compatible.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use minip2p_core::{Multiaddr, PeerId, VarintError, read_uvarint, write_uvarint};

/// Protocol id for AutoNAT v1.
pub const AUTONAT_PROTOCOL_ID: &str = "/libp2p/autonat/1.0.0";

/// Maximum size for one AutoNAT frame.
pub const MAX_MESSAGE_SIZE: usize = 8192;

const WIRE_VARINT: u8 = 0;
const WIRE_LEN: u8 = 2;
const TAG_TYPE: u8 = (1 << 3) | WIRE_VARINT;
const TAG_DIAL: u8 = (2 << 3) | WIRE_LEN;
const TAG_DIAL_RESPONSE: u8 = (3 << 3) | WIRE_LEN;
const TAG_PEER: u8 = (1 << 3) | WIRE_LEN;
const TAG_PEER_ID: u8 = (1 << 3) | WIRE_LEN;
const TAG_PEER_ADDRS: u8 = (2 << 3) | WIRE_LEN;
const TAG_STATUS: u8 = (1 << 3) | WIRE_VARINT;
const TAG_STATUS_TEXT: u8 = (2 << 3) | WIRE_LEN;
const TAG_RESPONSE_ADDRS: u8 = (3 << 3) | WIRE_LEN;

/// Top-level AutoNAT message type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageType {
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
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AutoNatError {
    /// Incoming message exceeded the configured maximum size.
    #[error("AutoNAT message exceeds maximum size ({len} > {MAX_MESSAGE_SIZE})")]
    MessageTooLarge { len: usize },
    /// A varint could not be decoded.
    #[error("varint error: {0}")]
    Varint(#[from] VarintError),
    /// A length-delimited field extends beyond the message boundary.
    #[error("field at offset {offset} claims length {length} but only {remaining} bytes remain")]
    FieldOverflow {
        /// Byte offset where the field body should start.
        offset: usize,
        /// Declared field length.
        length: usize,
        /// Remaining bytes in the message.
        remaining: usize,
    },
    /// Unsupported protobuf wire type.
    #[error("unsupported wire type {wire_type} at offset {offset}")]
    UnsupportedWireType { wire_type: u8, offset: usize },
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
}

/// Server-side AutoNAT request handler.
pub struct AutoNatServer {
    outbound: Vec<u8>,
    recv_buf: Vec<u8>,
    request: Option<AutoNatRequest>,
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
        }
    }

    /// Drains pending outbound bytes.
    pub fn take_outbound(&mut self) -> Vec<u8> {
        if self.state == FlowState::Pending {
            self.state = FlowState::AwaitingResponse;
        }
        core::mem::take(&mut self.outbound)
    }

    /// Feeds incoming bytes from the AutoNAT service stream.
    pub fn on_data(&mut self, data: &[u8]) -> Result<(), AutoNatError> {
        if self.state == FlowState::Done {
            return Ok(());
        }
        self.recv_buf.extend_from_slice(data);
        self.try_decode_response()
    }

    /// Returns the reachability outcome, if available.
    pub fn outcome(&self) -> Option<&Reachability> {
        self.outcome.as_ref()
    }

    fn try_decode_response(&mut self) -> Result<(), AutoNatError> {
        enforce_max_size(&self.recv_buf)?;
        let (payload, consumed) = match decode_frame(&self.recv_buf) {
            FrameDecode::Complete { payload, consumed } => (payload.to_vec(), consumed),
            FrameDecode::Incomplete => return Ok(()),
            FrameDecode::Error(e) => return Err(AutoNatError::Varint(e)),
        };
        self.recv_buf.drain(..consumed);

        let msg = Message::decode(&payload)?;
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
            state: ServerState::AwaitingRequest,
        }
    }

    /// Feeds incoming bytes from a requester.
    pub fn on_data(&mut self, data: &[u8]) -> Result<(), AutoNatError> {
        if self.state != ServerState::AwaitingRequest {
            return Ok(());
        }
        self.recv_buf.extend_from_slice(data);
        self.try_decode_request()
    }

    /// Returns the parsed dial-back request, if ready.
    pub fn request(&self) -> Option<&AutoNatRequest> {
        self.request.as_ref()
    }

    /// Queues a successful DIAL_RESPONSE with dialable addresses.
    pub fn respond_public(&mut self, addrs: &[Multiaddr]) {
        self.respond(ResponseStatus::Ok, None, addrs);
    }

    /// Queues an unsuccessful DIAL_RESPONSE.
    pub fn respond_error(&mut self, status: ResponseStatus, reason: impl Into<String>) {
        self.respond(status, Some(reason.into()), &[]);
    }

    /// Drains pending outbound bytes.
    pub fn take_outbound(&mut self) -> Vec<u8> {
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
        let (payload, consumed) = match decode_frame(&self.recv_buf) {
            FrameDecode::Complete { payload, consumed } => (payload.to_vec(), consumed),
            FrameDecode::Incomplete => return Ok(()),
            FrameDecode::Error(e) => return Err(AutoNatError::Varint(e)),
        };
        self.recv_buf.drain(..consumed);

        let msg = Message::decode(&payload)?;
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
        self.state = ServerState::RequestReady;
        Ok(())
    }
}

impl Default for AutoNatServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Frame decode result for varint-length-prefixed AutoNAT messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameDecode<'a> {
    /// A complete frame is available.
    Complete { payload: &'a [u8], consumed: usize },
    /// More bytes are needed.
    Incomplete,
    /// The frame length varint was malformed.
    Error(VarintError),
}

/// Encodes a protobuf message body with a varint length prefix.
pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_uvarint(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}

/// Decodes a varint-length-prefixed frame from `input`.
pub fn decode_frame(input: &[u8]) -> FrameDecode<'_> {
    let (len, used) = match read_uvarint(input) {
        Ok(v) => v,
        Err(VarintError::BufferTooShort) => return FrameDecode::Incomplete,
        Err(e) => return FrameDecode::Error(e),
    };
    let len = len as usize;
    let end = used.saturating_add(len);
    if input.len() < end {
        return FrameDecode::Incomplete;
    }
    FrameDecode::Complete {
        payload: &input[used..end],
        consumed: end,
    }
}

impl Message {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_varint_field(&mut out, TAG_TYPE, self.kind as u64);
        if let Some(dial) = &self.dial {
            encode_bytes_field(&mut out, TAG_DIAL, &dial.encode());
        }
        if let Some(response) = &self.dial_response {
            encode_bytes_field(&mut out, TAG_DIAL_RESPONSE, &response.encode());
        }
        out
    }

    fn decode(input: &[u8]) -> Result<Self, AutoNatError> {
        let mut idx = 0;
        let mut kind = None;
        let mut dial = None;
        let mut dial_response = None;
        while let Some((field, wire)) = read_tag(input, &mut idx)? {
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
                (_, WIRE_LEN) => {
                    let _ = read_len_delimited(input, &mut idx)?;
                }
                (_, WIRE_VARINT) => {
                    let _ = read_varint_value(input, &mut idx)?;
                }
                (_, other) => {
                    return Err(AutoNatError::UnsupportedWireType {
                        wire_type: other,
                        offset: idx,
                    });
                }
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
            encode_bytes_field(&mut out, TAG_PEER, &peer.encode());
        }
        out
    }

    fn decode(input: &[u8]) -> Result<Self, AutoNatError> {
        let mut idx = 0;
        let mut peer = None;
        while let Some((field, wire)) = read_tag(input, &mut idx)? {
            match (field, wire) {
                (1, WIRE_LEN) => {
                    peer = Some(PeerInfo::decode(read_len_delimited(input, &mut idx)?)?)
                }
                (_, WIRE_LEN) => {
                    let _ = read_len_delimited(input, &mut idx)?;
                }
                (_, WIRE_VARINT) => {
                    let _ = read_varint_value(input, &mut idx)?;
                }
                (_, other) => {
                    return Err(AutoNatError::UnsupportedWireType {
                        wire_type: other,
                        offset: idx,
                    });
                }
            }
        }
        Ok(Self { peer })
    }
}

impl PeerInfo {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_bytes_field(&mut out, TAG_PEER_ID, &self.id);
        for addr in &self.addrs {
            encode_bytes_field(&mut out, TAG_PEER_ADDRS, addr);
        }
        out
    }

    fn decode(input: &[u8]) -> Result<Self, AutoNatError> {
        let mut idx = 0;
        let mut id = Vec::new();
        let mut addrs = Vec::new();
        while let Some((field, wire)) = read_tag(input, &mut idx)? {
            match (field, wire) {
                (1, WIRE_LEN) => id = read_len_delimited(input, &mut idx)?.to_vec(),
                (2, WIRE_LEN) => addrs.push(read_len_delimited(input, &mut idx)?.to_vec()),
                (_, WIRE_LEN) => {
                    let _ = read_len_delimited(input, &mut idx)?;
                }
                (_, WIRE_VARINT) => {
                    let _ = read_varint_value(input, &mut idx)?;
                }
                (_, other) => {
                    return Err(AutoNatError::UnsupportedWireType {
                        wire_type: other,
                        offset: idx,
                    });
                }
            }
        }
        Ok(Self { id, addrs })
    }
}

impl DialResponse {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_varint_field(&mut out, TAG_STATUS, self.status as u64);
        if let Some(text) = &self.status_text {
            encode_bytes_field(&mut out, TAG_STATUS_TEXT, text.as_bytes());
        }
        for addr in &self.addrs {
            encode_bytes_field(&mut out, TAG_RESPONSE_ADDRS, addr);
        }
        out
    }

    fn decode(input: &[u8]) -> Result<Self, AutoNatError> {
        let mut idx = 0;
        let mut status = ResponseStatus::InternalError;
        let mut status_text = None;
        let mut addrs = Vec::new();
        while let Some((field, wire)) = read_tag(input, &mut idx)? {
            match (field, wire) {
                (1, WIRE_VARINT) => {
                    status = ResponseStatus::from_u64(read_varint_value(input, &mut idx)?)
                }
                (2, WIRE_LEN) => {
                    let text = read_len_delimited(input, &mut idx)?;
                    status_text = Some(String::from_utf8_lossy(text).into_owned());
                }
                (3, WIRE_LEN) => addrs.push(read_len_delimited(input, &mut idx)?.to_vec()),
                (_, WIRE_LEN) => {
                    let _ = read_len_delimited(input, &mut idx)?;
                }
                (_, WIRE_VARINT) => {
                    let _ = read_varint_value(input, &mut idx)?;
                }
                (_, other) => {
                    return Err(AutoNatError::UnsupportedWireType {
                        wire_type: other,
                        offset: idx,
                    });
                }
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

fn encode_varint_field(out: &mut Vec<u8>, tag: u8, value: u64) {
    out.push(tag);
    write_uvarint(value, out);
}

fn encode_bytes_field(out: &mut Vec<u8>, tag: u8, data: &[u8]) {
    out.push(tag);
    write_uvarint(data.len() as u64, out);
    out.extend_from_slice(data);
}

fn read_tag(input: &[u8], idx: &mut usize) -> Result<Option<(u64, u8)>, AutoNatError> {
    if *idx >= input.len() {
        return Ok(None);
    }
    let offset = *idx;
    let (tag_value, used) = read_uvarint(&input[*idx..])?;
    *idx += used;
    let wire_type = (tag_value & 0x07) as u8;
    let field_number = tag_value >> 3;
    if field_number == 0 {
        return Err(AutoNatError::UnsupportedWireType { wire_type, offset });
    }
    Ok(Some((field_number, wire_type)))
}

fn read_len_delimited<'a>(input: &'a [u8], idx: &mut usize) -> Result<&'a [u8], AutoNatError> {
    let (length, used) = read_uvarint(&input[*idx..])?;
    *idx += used;
    let length = length as usize;
    let remaining = input.len().saturating_sub(*idx);
    if length > remaining {
        return Err(AutoNatError::FieldOverflow {
            offset: *idx,
            length,
            remaining,
        });
    }
    let value = &input[*idx..*idx + length];
    *idx += length;
    Ok(value)
}

fn read_varint_value(input: &[u8], idx: &mut usize) -> Result<u64, AutoNatError> {
    let (value, used) = read_uvarint(&input[*idx..])?;
    *idx += used;
    Ok(value)
}

#[cfg(test)]
mod tests {
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
}
