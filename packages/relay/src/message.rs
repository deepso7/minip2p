//! Protobuf encoding and decoding for Circuit Relay v2 messages.
//!
//! Implements the wire format from
//! <https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md>:
//!
//! ```text
//! message HopMessage {
//!   Type type = 1;              // RESERVE=0 | CONNECT=1 | STATUS=2
//!   Peer peer = 2;
//!   Reservation reservation = 3;
//!   Limit limit = 4;
//!   Status status = 5;
//! }
//! message StopMessage {
//!   Type type = 1;              // CONNECT=0 | STATUS=1
//!   Peer peer = 2;
//!   Limit limit = 3;
//!   Status status = 4;
//! }
//! message Peer { bytes id = 1; repeated bytes addrs = 2; }
//! message Reservation { uint64 expire = 1; repeated bytes addrs = 2; bytes voucher = 3; }
//! message Limit { uint32 duration = 1; uint64 data = 2; }
//! ```

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::{read_uvarint, uvarint_len, write_uvarint, VarintError};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// HopMessage type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HopMessageType {
    Reserve = 0,
    Connect = 1,
    Status = 2,
}

impl HopMessageType {
    /// Convert from the raw varint value.
    pub fn from_u64(value: u64) -> Option<Self> {
        match value {
            0 => Some(HopMessageType::Reserve),
            1 => Some(HopMessageType::Connect),
            2 => Some(HopMessageType::Status),
            _ => None,
        }
    }
}

/// StopMessage type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopMessageType {
    Connect = 0,
    Status = 1,
}

impl StopMessageType {
    /// Convert from the raw varint value.
    pub fn from_u64(value: u64) -> Option<Self> {
        match value {
            0 => Some(StopMessageType::Connect),
            1 => Some(StopMessageType::Status),
            _ => None,
        }
    }
}

/// Status codes shared by HopMessage and StopMessage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Unused = 0,
    Ok = 100,
    ReservationRefused = 200,
    ResourceLimitExceeded = 201,
    PermissionDenied = 202,
    ConnectionFailed = 203,
    NoReservation = 204,
    MalformedMessage = 400,
    UnexpectedMessage = 401,
}

impl Status {
    /// Convert from the raw varint value.
    ///
    /// Unknown codes map to `Unused` (treated as "no status set").
    pub fn from_u64(value: u64) -> Self {
        match value {
            100 => Status::Ok,
            200 => Status::ReservationRefused,
            201 => Status::ResourceLimitExceeded,
            202 => Status::PermissionDenied,
            203 => Status::ConnectionFailed,
            204 => Status::NoReservation,
            400 => Status::MalformedMessage,
            401 => Status::UnexpectedMessage,
            _ => Status::Unused,
        }
    }
}

// ---------------------------------------------------------------------------
// Nested messages
// ---------------------------------------------------------------------------

/// `Peer` message: identifies a remote peer by id and addresses.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Peer {
    /// PeerId bytes (multihash).
    pub id: Vec<u8>,
    /// Addresses the peer can be reached on (multiaddr binary).
    pub addrs: Vec<Vec<u8>>,
}

/// `Reservation` message: returned by the relay after a successful RESERVE.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Reservation {
    /// Reservation expiration (UTC UNIX seconds).
    pub expire: Option<u64>,
    /// Relay addresses reachable via this reservation.
    pub addrs: Vec<Vec<u8>>,
    /// Reservation voucher (signed envelope).
    pub voucher: Option<Vec<u8>>,
}

/// `Limit` message: constraints on a relayed connection.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Limit {
    /// Max duration of a relayed connection in seconds (0 = unlimited).
    pub duration: Option<u32>,
    /// Max bytes per direction (0 = unlimited).
    pub data: Option<u64>,
}

// ---------------------------------------------------------------------------
// Top-level messages
// ---------------------------------------------------------------------------

/// `HopMessage`: client <-> relay protocol messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HopMessage {
    pub kind: HopMessageType,
    pub peer: Option<Peer>,
    pub reservation: Option<Reservation>,
    pub limit: Option<Limit>,
    pub status: Option<Status>,
}

/// `StopMessage`: relay <-> destination protocol messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopMessage {
    pub kind: StopMessageType,
    pub peer: Option<Peer>,
    pub limit: Option<Limit>,
    pub status: Option<Status>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur while decoding relay messages.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum RelayMessageError {
    /// A varint could not be decoded.
    #[error("varint error: {0}")]
    Varint(#[from] VarintError),
    /// A length-delimited field extends beyond the message boundary.
    #[error("field at offset {offset} claims length {length} but only {remaining} bytes remain")]
    FieldOverflow {
        offset: usize,
        length: usize,
        remaining: usize,
    },
    /// An unknown wire type was encountered and cannot be safely skipped.
    #[error("unsupported wire type {wire_type} at offset {offset}")]
    UnsupportedWireType { wire_type: u8, offset: usize },
    /// The top-level `type` field was missing.
    #[error("required `type` field missing")]
    MissingType,
    /// The top-level `type` field had an unrecognized value.
    #[error("invalid message type value: {value}")]
    InvalidMessageType { value: u64 },
}

// ---------------------------------------------------------------------------
// Protobuf helpers
// ---------------------------------------------------------------------------

/// Computes the tag byte for (field_number, wire_type).
///
/// Only handles field numbers < 16 (single-byte tags), which covers everything
/// in the relay v2 spec.
const fn tag_byte(field: u8, wire_type: u8) -> u8 {
    (field << 3) | wire_type
}

const WIRE_VARINT: u8 = 0;
const WIRE_I64: u8 = 1;
const WIRE_LEN: u8 = 2;
const WIRE_I32: u8 = 5;

/// Writes a `(tag, varint_value)` field.
fn encode_varint_field(out: &mut Vec<u8>, tag: u8, value: u64) {
    out.push(tag);
    write_uvarint(value, out);
}

/// Writes a `(tag, length, bytes)` field.
fn encode_bytes_field(out: &mut Vec<u8>, tag: u8, data: &[u8]) {
    out.push(tag);
    write_uvarint(data.len() as u64, out);
    out.extend_from_slice(data);
}

/// Writes a `(tag, length, nested_message)` field.
fn encode_nested_field(out: &mut Vec<u8>, tag: u8, nested: &[u8]) {
    encode_bytes_field(out, tag, nested);
}

/// Reads the next (tag, wire_type) pair from the buffer.
///
/// Returns `Ok(None)` when the buffer is exhausted.
fn read_tag(input: &[u8], idx: &mut usize) -> Result<Option<(u64, u8)>, RelayMessageError> {
    if *idx >= input.len() {
        return Ok(None);
    }
    let (tag_value, used) = read_uvarint(&input[*idx..])?;
    *idx += used;
    let wire_type = (tag_value & 0x07) as u8;
    let field_number = tag_value >> 3;
    Ok(Some((field_number, wire_type)))
}

/// Reads a length-delimited value, advancing `idx` past the length and bytes.
fn read_len_delimited<'a>(
    input: &'a [u8],
    idx: &mut usize,
) -> Result<&'a [u8], RelayMessageError> {
    let (length, used) = read_uvarint(&input[*idx..])?;
    *idx += used;
    let length = length as usize;
    let remaining = input.len().saturating_sub(*idx);
    if length > remaining {
        return Err(RelayMessageError::FieldOverflow {
            offset: *idx,
            length,
            remaining,
        });
    }
    let value = &input[*idx..*idx + length];
    *idx += length;
    Ok(value)
}

/// Reads a varint field value.
fn read_varint_value(input: &[u8], idx: &mut usize) -> Result<u64, RelayMessageError> {
    let (value, used) = read_uvarint(&input[*idx..])?;
    *idx += used;
    Ok(value)
}

/// Skips over an unknown field based on its wire type.
fn skip_unknown_field(
    input: &[u8],
    idx: &mut usize,
    wire_type: u8,
) -> Result<(), RelayMessageError> {
    match wire_type {
        WIRE_VARINT => {
            let (_, used) = read_uvarint(&input[*idx..])?;
            *idx += used;
            Ok(())
        }
        WIRE_LEN => {
            let (length, used) = read_uvarint(&input[*idx..])?;
            *idx += used;
            let length = length as usize;
            let remaining = input.len().saturating_sub(*idx);
            if length > remaining {
                return Err(RelayMessageError::FieldOverflow {
                    offset: *idx,
                    length,
                    remaining,
                });
            }
            *idx += length;
            Ok(())
        }
        WIRE_I32 => {
            if *idx + 4 > input.len() {
                return Err(RelayMessageError::FieldOverflow {
                    offset: *idx,
                    length: 4,
                    remaining: input.len().saturating_sub(*idx),
                });
            }
            *idx += 4;
            Ok(())
        }
        WIRE_I64 => {
            if *idx + 8 > input.len() {
                return Err(RelayMessageError::FieldOverflow {
                    offset: *idx,
                    length: 8,
                    remaining: input.len().saturating_sub(*idx),
                });
            }
            *idx += 8;
            Ok(())
        }
        _ => Err(RelayMessageError::UnsupportedWireType {
            wire_type,
            offset: *idx,
        }),
    }
}

// ---------------------------------------------------------------------------
// Length-prefixed framing
// ---------------------------------------------------------------------------

/// Result of attempting to decode a single length-prefixed frame.
pub enum FrameDecode<'a> {
    /// A complete frame was decoded.
    Complete {
        /// The payload bytes (without the length prefix).
        payload: &'a [u8],
        /// Total number of bytes consumed from the input (length prefix + payload).
        consumed: usize,
    },
    /// Not enough bytes are buffered yet to decode a complete frame.
    Incomplete,
    /// The frame header is malformed.
    Error(VarintError),
}

/// Attempts to decode one varint-length-prefixed frame from `input`.
///
/// Returns `Incomplete` if the buffer is missing bytes.
pub fn decode_frame(input: &[u8]) -> FrameDecode<'_> {
    if input.is_empty() {
        return FrameDecode::Incomplete;
    }

    let (length, used) = match read_uvarint(input) {
        Ok(v) => v,
        Err(VarintError::BufferTooShort) => return FrameDecode::Incomplete,
        Err(e) => return FrameDecode::Error(e),
    };

    let length = length as usize;
    let total = used + length;
    if input.len() < total {
        return FrameDecode::Incomplete;
    }

    FrameDecode::Complete {
        payload: &input[used..total],
        consumed: total,
    }
}

/// Encodes `payload` with a varint length prefix.
pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(uvarint_len(payload.len() as u64) + payload.len());
    write_uvarint(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}

// ---------------------------------------------------------------------------
// Peer encode/decode
// ---------------------------------------------------------------------------

impl Peer {
    /// Encodes the Peer message body (without length prefix).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.id.is_empty() {
            encode_bytes_field(&mut out, tag_byte(1, WIRE_LEN), &self.id);
        }
        for addr in &self.addrs {
            encode_bytes_field(&mut out, tag_byte(2, WIRE_LEN), addr);
        }
        out
    }

    /// Decodes a Peer message body.
    pub fn decode(input: &[u8]) -> Result<Self, RelayMessageError> {
        let mut msg = Peer::default();
        let mut idx = 0;
        while let Some((field, wire_type)) = read_tag(input, &mut idx)? {
            match (field, wire_type) {
                (1, WIRE_LEN) => {
                    msg.id = read_len_delimited(input, &mut idx)?.to_vec();
                }
                (2, WIRE_LEN) => {
                    msg.addrs
                        .push(read_len_delimited(input, &mut idx)?.to_vec());
                }
                _ => skip_unknown_field(input, &mut idx, wire_type)?,
            }
        }
        Ok(msg)
    }
}

// ---------------------------------------------------------------------------
// Reservation encode/decode
// ---------------------------------------------------------------------------

impl Reservation {
    /// Encodes the Reservation message body (without length prefix).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(expire) = self.expire {
            encode_varint_field(&mut out, tag_byte(1, WIRE_VARINT), expire);
        }
        for addr in &self.addrs {
            encode_bytes_field(&mut out, tag_byte(2, WIRE_LEN), addr);
        }
        if let Some(ref voucher) = self.voucher {
            encode_bytes_field(&mut out, tag_byte(3, WIRE_LEN), voucher);
        }
        out
    }

    /// Decodes a Reservation message body.
    pub fn decode(input: &[u8]) -> Result<Self, RelayMessageError> {
        let mut msg = Reservation::default();
        let mut idx = 0;
        while let Some((field, wire_type)) = read_tag(input, &mut idx)? {
            match (field, wire_type) {
                (1, WIRE_VARINT) => {
                    msg.expire = Some(read_varint_value(input, &mut idx)?);
                }
                (2, WIRE_LEN) => {
                    msg.addrs
                        .push(read_len_delimited(input, &mut idx)?.to_vec());
                }
                (3, WIRE_LEN) => {
                    msg.voucher = Some(read_len_delimited(input, &mut idx)?.to_vec());
                }
                _ => skip_unknown_field(input, &mut idx, wire_type)?,
            }
        }
        Ok(msg)
    }
}

// ---------------------------------------------------------------------------
// Limit encode/decode
// ---------------------------------------------------------------------------

impl Limit {
    /// Encodes the Limit message body (without length prefix).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(duration) = self.duration {
            encode_varint_field(&mut out, tag_byte(1, WIRE_VARINT), duration as u64);
        }
        if let Some(data) = self.data {
            encode_varint_field(&mut out, tag_byte(2, WIRE_VARINT), data);
        }
        out
    }

    /// Decodes a Limit message body.
    pub fn decode(input: &[u8]) -> Result<Self, RelayMessageError> {
        let mut msg = Limit::default();
        let mut idx = 0;
        while let Some((field, wire_type)) = read_tag(input, &mut idx)? {
            match (field, wire_type) {
                (1, WIRE_VARINT) => {
                    msg.duration = Some(read_varint_value(input, &mut idx)? as u32);
                }
                (2, WIRE_VARINT) => {
                    msg.data = Some(read_varint_value(input, &mut idx)?);
                }
                _ => skip_unknown_field(input, &mut idx, wire_type)?,
            }
        }
        Ok(msg)
    }
}

// ---------------------------------------------------------------------------
// HopMessage encode/decode
// ---------------------------------------------------------------------------

impl HopMessage {
    /// Encodes the HopMessage body (without length prefix).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_varint_field(&mut out, tag_byte(1, WIRE_VARINT), self.kind as u64);

        if let Some(ref peer) = self.peer {
            let nested = peer.encode();
            encode_nested_field(&mut out, tag_byte(2, WIRE_LEN), &nested);
        }
        if let Some(ref reservation) = self.reservation {
            let nested = reservation.encode();
            encode_nested_field(&mut out, tag_byte(3, WIRE_LEN), &nested);
        }
        if let Some(ref limit) = self.limit {
            let nested = limit.encode();
            encode_nested_field(&mut out, tag_byte(4, WIRE_LEN), &nested);
        }
        if let Some(status) = self.status {
            encode_varint_field(&mut out, tag_byte(5, WIRE_VARINT), status as u64);
        }
        out
    }

    /// Decodes a HopMessage body.
    pub fn decode(input: &[u8]) -> Result<Self, RelayMessageError> {
        let mut kind: Option<HopMessageType> = None;
        let mut peer: Option<Peer> = None;
        let mut reservation: Option<Reservation> = None;
        let mut limit: Option<Limit> = None;
        let mut status: Option<Status> = None;

        let mut idx = 0;
        while let Some((field, wire_type)) = read_tag(input, &mut idx)? {
            match (field, wire_type) {
                (1, WIRE_VARINT) => {
                    let value = read_varint_value(input, &mut idx)?;
                    kind = Some(HopMessageType::from_u64(value).ok_or(
                        RelayMessageError::InvalidMessageType { value },
                    )?);
                }
                (2, WIRE_LEN) => {
                    let body = read_len_delimited(input, &mut idx)?;
                    peer = Some(Peer::decode(body)?);
                }
                (3, WIRE_LEN) => {
                    let body = read_len_delimited(input, &mut idx)?;
                    reservation = Some(Reservation::decode(body)?);
                }
                (4, WIRE_LEN) => {
                    let body = read_len_delimited(input, &mut idx)?;
                    limit = Some(Limit::decode(body)?);
                }
                (5, WIRE_VARINT) => {
                    let value = read_varint_value(input, &mut idx)?;
                    status = Some(Status::from_u64(value));
                }
                _ => skip_unknown_field(input, &mut idx, wire_type)?,
            }
        }

        Ok(HopMessage {
            kind: kind.ok_or(RelayMessageError::MissingType)?,
            peer,
            reservation,
            limit,
            status,
        })
    }
}

// ---------------------------------------------------------------------------
// StopMessage encode/decode
// ---------------------------------------------------------------------------

impl StopMessage {
    /// Encodes the StopMessage body (without length prefix).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_varint_field(&mut out, tag_byte(1, WIRE_VARINT), self.kind as u64);

        if let Some(ref peer) = self.peer {
            let nested = peer.encode();
            encode_nested_field(&mut out, tag_byte(2, WIRE_LEN), &nested);
        }
        if let Some(ref limit) = self.limit {
            let nested = limit.encode();
            encode_nested_field(&mut out, tag_byte(3, WIRE_LEN), &nested);
        }
        if let Some(status) = self.status {
            encode_varint_field(&mut out, tag_byte(4, WIRE_VARINT), status as u64);
        }
        out
    }

    /// Decodes a StopMessage body.
    pub fn decode(input: &[u8]) -> Result<Self, RelayMessageError> {
        let mut kind: Option<StopMessageType> = None;
        let mut peer: Option<Peer> = None;
        let mut limit: Option<Limit> = None;
        let mut status: Option<Status> = None;

        let mut idx = 0;
        while let Some((field, wire_type)) = read_tag(input, &mut idx)? {
            match (field, wire_type) {
                (1, WIRE_VARINT) => {
                    let value = read_varint_value(input, &mut idx)?;
                    kind = Some(StopMessageType::from_u64(value).ok_or(
                        RelayMessageError::InvalidMessageType { value },
                    )?);
                }
                (2, WIRE_LEN) => {
                    let body = read_len_delimited(input, &mut idx)?;
                    peer = Some(Peer::decode(body)?);
                }
                (3, WIRE_LEN) => {
                    let body = read_len_delimited(input, &mut idx)?;
                    limit = Some(Limit::decode(body)?);
                }
                (4, WIRE_VARINT) => {
                    let value = read_varint_value(input, &mut idx)?;
                    status = Some(Status::from_u64(value));
                }
                _ => skip_unknown_field(input, &mut idx, wire_type)?,
            }
        }

        Ok(StopMessage {
            kind: kind.ok_or(RelayMessageError::MissingType)?,
            peer,
            limit,
            status,
        })
    }
}

// ---------------------------------------------------------------------------
// Status name helper
// ---------------------------------------------------------------------------

impl Status {
    /// Returns a human-readable name for this status.
    pub fn as_name(&self) -> &'static str {
        match self {
            Status::Unused => "UNUSED",
            Status::Ok => "OK",
            Status::ReservationRefused => "RESERVATION_REFUSED",
            Status::ResourceLimitExceeded => "RESOURCE_LIMIT_EXCEEDED",
            Status::PermissionDenied => "PERMISSION_DENIED",
            Status::ConnectionFailed => "CONNECTION_FAILED",
            Status::NoReservation => "NO_RESERVATION",
            Status::MalformedMessage => "MALFORMED_MESSAGE",
            Status::UnexpectedMessage => "UNEXPECTED_MESSAGE",
        }
    }
}

/// Builds a human-readable description of a non-OK status response.
pub fn describe_status(status: Status) -> String {
    use alloc::string::ToString;
    match status {
        Status::Ok => "OK".to_string(),
        other => {
            use alloc::format;
            format!("{} ({})", other.as_name(), other as u16)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_message_reserve_round_trip() {
        let msg = HopMessage {
            kind: HopMessageType::Reserve,
            peer: None,
            reservation: None,
            limit: None,
            status: None,
        };
        let encoded = msg.encode();
        let decoded = HopMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn hop_message_status_ok_with_reservation_round_trip() {
        let msg = HopMessage {
            kind: HopMessageType::Status,
            peer: None,
            reservation: Some(Reservation {
                expire: Some(1_700_000_000),
                addrs: vec![vec![0x04, 127, 0, 0, 1], vec![0x04, 10, 0, 0, 1]],
                voucher: Some(b"voucher-bytes".to_vec()),
            }),
            limit: Some(Limit {
                duration: Some(600),
                data: Some(1_048_576),
            }),
            status: Some(Status::Ok),
        };
        let encoded = msg.encode();
        let decoded = HopMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn hop_message_connect_with_peer_round_trip() {
        let msg = HopMessage {
            kind: HopMessageType::Connect,
            peer: Some(Peer {
                id: b"some-peer-id-multihash".to_vec(),
                addrs: vec![],
            }),
            reservation: None,
            limit: None,
            status: None,
        };
        let encoded = msg.encode();
        let decoded = HopMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn stop_message_connect_round_trip() {
        let msg = StopMessage {
            kind: StopMessageType::Connect,
            peer: Some(Peer {
                id: b"source-peer-id".to_vec(),
                addrs: vec![],
            }),
            limit: Some(Limit {
                duration: Some(120),
                data: None,
            }),
            status: None,
        };
        let encoded = msg.encode();
        let decoded = StopMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn stop_message_status_ok_round_trip() {
        let msg = StopMessage {
            kind: StopMessageType::Status,
            peer: None,
            limit: None,
            status: Some(Status::Ok),
        };
        let encoded = msg.encode();
        let decoded = StopMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn hop_message_missing_type_fails() {
        // Encode only a peer field with no type.
        let mut buf = Vec::new();
        encode_nested_field(&mut buf, tag_byte(2, WIRE_LEN), &Peer::default().encode());

        let err = HopMessage::decode(&buf).unwrap_err();
        assert!(matches!(err, RelayMessageError::MissingType));
    }

    #[test]
    fn hop_message_invalid_type_fails() {
        // Encode type=99 (invalid).
        let mut buf = Vec::new();
        encode_varint_field(&mut buf, tag_byte(1, WIRE_VARINT), 99);

        let err = HopMessage::decode(&buf).unwrap_err();
        assert!(matches!(
            err,
            RelayMessageError::InvalidMessageType { value: 99 }
        ));
    }

    #[test]
    fn decoder_skips_unknown_fields() {
        // RESERVE message with unknown field 99 before and after the type.
        let mut buf = Vec::new();

        // Unknown field 99, LEN: "extra"
        encode_bytes_field(&mut buf, tag_byte(9, WIRE_LEN), b"extra");
        // type=RESERVE
        encode_varint_field(&mut buf, tag_byte(1, WIRE_VARINT), 0);
        // Unknown field 10, VARINT: 42
        encode_varint_field(&mut buf, tag_byte(10, WIRE_VARINT), 42);

        let decoded = HopMessage::decode(&buf).unwrap();
        assert_eq!(decoded.kind, HopMessageType::Reserve);
    }

    #[test]
    fn frame_round_trip() {
        let payload = b"hello world";
        let framed = encode_frame(payload);

        match decode_frame(&framed) {
            FrameDecode::Complete { payload: p, consumed } => {
                assert_eq!(p, payload);
                assert_eq!(consumed, framed.len());
            }
            _ => panic!("expected complete frame"),
        }
    }

    #[test]
    fn frame_incomplete_when_length_missing() {
        assert!(matches!(decode_frame(&[]), FrameDecode::Incomplete));
    }

    #[test]
    fn frame_incomplete_when_payload_truncated() {
        let mut framed = encode_frame(b"hello world");
        framed.truncate(framed.len() - 3);
        assert!(matches!(decode_frame(&framed), FrameDecode::Incomplete));
    }

    #[test]
    fn unknown_status_maps_to_unused() {
        assert_eq!(Status::from_u64(9999), Status::Unused);
    }

    #[test]
    fn reservation_decode_empty_yields_defaults() {
        let msg = Reservation::decode(&[]).unwrap();
        assert_eq!(msg, Reservation::default());
    }

    #[test]
    fn limit_encode_omits_none_fields() {
        let msg = Limit {
            duration: None,
            data: Some(100),
        };
        let encoded = msg.encode();
        // Should only contain the `data` field (tag 2, varint value 100).
        // Tag byte = (2 << 3) | 0 = 0x10
        assert_eq!(encoded, vec![0x10, 100]);
    }
}
