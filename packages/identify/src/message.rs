//! Protobuf encoding and decoding for the Identify message.
//!
//! Implements the following protobuf schema (proto2):
//!
//! ```text
//! message Identify {
//!   optional bytes  publicKey       = 1;
//!   repeated bytes  listenAddrs     = 2;
//!   repeated string protocols       = 3;
//!   optional bytes  observedAddr    = 4;
//!   optional string protocolVersion = 5;
//!   optional string agentVersion    = 6;
//! }
//! ```
//!
//! All fields use wire type LEN (2). The encoder writes fields in field-number
//! order. The decoder accepts fields in any order, rejects unsupported wire
//! types, and silently skips unknown fields that use a known wire type.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::{read_uvarint, write_uvarint, VarintError};
use thiserror::Error;

// Protobuf wire types from the spec.
const WIRE_VARINT: u8 = 0;
const WIRE_I64: u8 = 1;
const WIRE_LEN: u8 = 2;
const WIRE_I32: u8 = 5;

// Protobuf field numbers for the Identify message.
const FIELD_PUBLIC_KEY: u64 = 1;
const FIELD_LISTEN_ADDRS: u64 = 2;
const FIELD_PROTOCOLS: u64 = 3;
const FIELD_OBSERVED_ADDR: u64 = 4;
const FIELD_PROTOCOL_VERSION: u64 = 5;
const FIELD_AGENT_VERSION: u64 = 6;

// Single-byte tag bytes used by the encoder (valid for field numbers < 16).
// These are only used when producing output; the decoder does not match on
// truncated u8 tags (see the full-width match in `decode` below).
const TAG_PUBLIC_KEY: u8 = ((FIELD_PUBLIC_KEY as u8) << 3) | WIRE_LEN;
const TAG_LISTEN_ADDRS: u8 = ((FIELD_LISTEN_ADDRS as u8) << 3) | WIRE_LEN;
const TAG_PROTOCOLS: u8 = ((FIELD_PROTOCOLS as u8) << 3) | WIRE_LEN;
const TAG_OBSERVED_ADDR: u8 = ((FIELD_OBSERVED_ADDR as u8) << 3) | WIRE_LEN;
const TAG_PROTOCOL_VERSION: u8 = ((FIELD_PROTOCOL_VERSION as u8) << 3) | WIRE_LEN;
const TAG_AGENT_VERSION: u8 = ((FIELD_AGENT_VERSION as u8) << 3) | WIRE_LEN;

/// The decoded identify message exchanged between peers.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IdentifyMessage {
    /// The peer's public key (protobuf-encoded `PublicKey` message).
    pub public_key: Option<Vec<u8>>,
    /// Addresses the peer is listening on (multiaddr binary encoding).
    pub listen_addrs: Vec<Vec<u8>>,
    /// Protocol IDs the peer supports.
    pub protocols: Vec<String>,
    /// The address the peer observes us connecting from (multiaddr binary).
    pub observed_addr: Option<Vec<u8>>,
    /// Protocol version string (e.g. `"ipfs/0.1.0"`).
    pub protocol_version: Option<String>,
    /// Agent version string (e.g. `"go-libp2p/0.36.0"`).
    pub agent_version: Option<String>,
}

/// Errors that can occur during identify message decoding.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum IdentifyMessageError {
    /// A varint could not be decoded.
    #[error("varint error: {0}")]
    Varint(#[from] VarintError),
    /// A length-delimited field extends beyond the message boundary, or a
    /// length value exceeds `usize` on the current target.
    #[error("field at offset {offset} has length {length} but only {remaining} bytes remain")]
    FieldOverflow {
        offset: usize,
        length: u64,
        remaining: usize,
    },
    /// A string field contains invalid UTF-8.
    #[error("invalid UTF-8 in field {field_number}")]
    InvalidUtf8 { field_number: u64 },
    /// The wire type of a field is not one of the four supported types
    /// (`VARINT`, `I64`, `LEN`, `I32`).
    ///
    /// Unlike ignorable unknown *fields*, an unknown *wire type* means the
    /// decoder cannot safely determine the field length, so parsing stops
    /// with an error rather than silently returning a partial message.
    #[error("unsupported wire type {wire_type} at offset {offset}")]
    UnsupportedWireType { wire_type: u8, offset: usize },
}

impl IdentifyMessage {
    /// Encodes the message to protobuf binary format.
    ///
    /// Fields are written in field-number order.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();

        if let Some(ref key) = self.public_key {
            encode_bytes_field(&mut out, TAG_PUBLIC_KEY, key);
        }

        for addr in &self.listen_addrs {
            encode_bytes_field(&mut out, TAG_LISTEN_ADDRS, addr);
        }

        for proto in &self.protocols {
            encode_bytes_field(&mut out, TAG_PROTOCOLS, proto.as_bytes());
        }

        if let Some(ref addr) = self.observed_addr {
            encode_bytes_field(&mut out, TAG_OBSERVED_ADDR, addr);
        }

        if let Some(ref ver) = self.protocol_version {
            encode_bytes_field(&mut out, TAG_PROTOCOL_VERSION, ver.as_bytes());
        }

        if let Some(ref ver) = self.agent_version {
            encode_bytes_field(&mut out, TAG_AGENT_VERSION, ver.as_bytes());
        }

        out
    }

    /// Decodes a message from protobuf binary format.
    ///
    /// - Accepts fields in any order.
    /// - Silently skips unknown *fields* that use a supported wire type.
    /// - Returns `UnsupportedWireType` for wire types outside the supported
    ///   set (0, 1, 2, 5) so malformed messages are rejected rather than
    ///   silently truncated.
    pub fn decode(input: &[u8]) -> Result<Self, IdentifyMessageError> {
        let mut msg = IdentifyMessage::default();
        let mut idx = 0;

        while idx < input.len() {
            // Read the field tag as a full u64 -- field numbers >= 16 encode
            // as multi-byte varints. Truncating to u8 here would let a remote
            // peer alias known fields via high-numbered field tags (e.g.
            // field 33 + LEN wire type = 266, cast to u8 = 0x0A = public_key).
            let (tag_value, tag_used) = read_uvarint(&input[idx..])?;
            idx += tag_used;

            let wire_type = (tag_value & 0x07) as u8;
            let field_number = tag_value >> 3;

            match wire_type {
                WIRE_LEN => {
                    let value = read_len_delimited(input, &mut idx)?;

                    match field_number {
                        FIELD_PUBLIC_KEY => {
                            msg.public_key = Some(value.to_vec());
                        }
                        FIELD_LISTEN_ADDRS => {
                            msg.listen_addrs.push(value.to_vec());
                        }
                        FIELD_PROTOCOLS => {
                            let s = core::str::from_utf8(value).map_err(|_| {
                                IdentifyMessageError::InvalidUtf8 { field_number }
                            })?;
                            msg.protocols.push(String::from(s));
                        }
                        FIELD_OBSERVED_ADDR => {
                            msg.observed_addr = Some(value.to_vec());
                        }
                        FIELD_PROTOCOL_VERSION => {
                            let s = core::str::from_utf8(value).map_err(|_| {
                                IdentifyMessageError::InvalidUtf8 { field_number }
                            })?;
                            msg.protocol_version = Some(String::from(s));
                        }
                        FIELD_AGENT_VERSION => {
                            let s = core::str::from_utf8(value).map_err(|_| {
                                IdentifyMessageError::InvalidUtf8 { field_number }
                            })?;
                            msg.agent_version = Some(String::from(s));
                        }
                        _ => {
                            // Unknown LEN field -- already consumed bytes above.
                        }
                    }
                }
                WIRE_VARINT => {
                    // Skip unknown varint values.
                    let (_, used) = read_uvarint(&input[idx..])?;
                    idx += used;
                }
                WIRE_I32 => {
                    if idx + 4 > input.len() {
                        return Err(IdentifyMessageError::FieldOverflow {
                            offset: idx,
                            length: 4,
                            remaining: input.len().saturating_sub(idx),
                        });
                    }
                    idx += 4;
                }
                WIRE_I64 => {
                    if idx + 8 > input.len() {
                        return Err(IdentifyMessageError::FieldOverflow {
                            offset: idx,
                            length: 8,
                            remaining: input.len().saturating_sub(idx),
                        });
                    }
                    idx += 8;
                }
                other => {
                    // Wire types 3 and 4 (deprecated start/end group) and 6,
                    // 7 (undefined) cannot be safely skipped because we have
                    // no way to determine their field length.
                    return Err(IdentifyMessageError::UnsupportedWireType {
                        wire_type: other,
                        offset: idx,
                    });
                }
            }
        }

        Ok(msg)
    }
}

/// Writes a length-delimited protobuf field: tag + varint length + bytes.
fn encode_bytes_field(out: &mut Vec<u8>, tag: u8, data: &[u8]) {
    out.push(tag);
    write_uvarint(data.len() as u64, out);
    out.extend_from_slice(data);
}

/// Reads a length-delimited value at `*idx`, advancing `*idx` past the length
/// prefix and payload bytes. Performs a checked conversion from `u64` to
/// `usize` to guard against truncation on 32-bit targets.
fn read_len_delimited<'a>(
    input: &'a [u8],
    idx: &mut usize,
) -> Result<&'a [u8], IdentifyMessageError> {
    let (length_u64, len_used) = read_uvarint(&input[*idx..])?;
    *idx += len_used;

    let remaining = input.len().saturating_sub(*idx);
    let length = usize::try_from(length_u64).map_err(|_| IdentifyMessageError::FieldOverflow {
        offset: *idx,
        length: length_u64,
        remaining,
    })?;

    if length > remaining {
        return Err(IdentifyMessageError::FieldOverflow {
            offset: *idx,
            length: length_u64,
            remaining,
        });
    }

    let value = &input[*idx..*idx + length];
    *idx += length;
    Ok(value)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_empty_message() {
        let msg = IdentifyMessage::default();
        let encoded = msg.encode();
        assert!(encoded.is_empty());
        let decoded = IdentifyMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn round_trip_full_message() {
        let msg = IdentifyMessage {
            public_key: Some(vec![0x08, 0x01, 0x12, 0x20, 0xAA]),
            listen_addrs: vec![vec![0x04, 127, 0, 0, 1], vec![0x04, 10, 0, 0, 1]],
            protocols: vec![
                String::from("/ipfs/ping/1.0.0"),
                String::from("/ipfs/id/1.0.0"),
            ],
            observed_addr: Some(vec![0x04, 192, 168, 1, 100]),
            protocol_version: Some(String::from("ipfs/0.1.0")),
            agent_version: Some(String::from("minip2p/0.1.0")),
        };

        let encoded = msg.encode();
        let decoded = IdentifyMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn round_trip_optional_fields_absent() {
        let msg = IdentifyMessage {
            public_key: None,
            listen_addrs: vec![],
            protocols: vec![String::from("/ipfs/ping/1.0.0")],
            observed_addr: None,
            protocol_version: None,
            agent_version: Some(String::from("test/0.1.0")),
        };

        let encoded = msg.encode();
        let decoded = IdentifyMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_ignores_unknown_fields() {
        // Build a message with a known field, then an unknown field (tag 0x3A = field 7, LEN),
        // then another known field.
        let mut data = Vec::new();

        data.push(TAG_AGENT_VERSION);
        data.push(4);
        data.extend_from_slice(b"test");

        data.push((7 << 3) | WIRE_LEN);
        data.push(7);
        data.extend_from_slice(b"unknown");

        data.push(TAG_PROTOCOL_VERSION);
        data.push(2);
        data.extend_from_slice(b"v1");

        let decoded = IdentifyMessage::decode(&data).unwrap();
        assert_eq!(decoded.agent_version.as_deref(), Some("test"));
        assert_eq!(decoded.protocol_version.as_deref(), Some("v1"));
    }

    #[test]
    fn decode_rejects_truncated_field() {
        let mut data = Vec::new();
        data.push(TAG_PUBLIC_KEY);
        data.push(10);
        data.extend_from_slice(&[0u8; 5]);

        let err = IdentifyMessage::decode(&data).unwrap_err();
        assert!(matches!(err, IdentifyMessageError::FieldOverflow { .. }));
    }

    #[test]
    fn decode_rejects_invalid_utf8_in_string_field() {
        let mut data = Vec::new();
        data.push(TAG_AGENT_VERSION);
        data.push(3);
        data.extend_from_slice(&[0xFF, 0xFE, 0xFD]);

        let err = IdentifyMessage::decode(&data).unwrap_err();
        assert!(matches!(err, IdentifyMessageError::InvalidUtf8 { .. }));
    }

    #[test]
    fn decode_skips_varint_unknown_fields() {
        let mut data = Vec::new();

        // Unknown field 10, VARINT: value 42
        data.push((10 << 3) | WIRE_VARINT);
        data.push(42);

        data.push(TAG_AGENT_VERSION);
        data.push(2);
        data.extend_from_slice(b"ok");

        let decoded = IdentifyMessage::decode(&data).unwrap();
        assert_eq!(decoded.agent_version.as_deref(), Some("ok"));
    }

    #[test]
    fn encode_field_order_matches_spec() {
        let msg = IdentifyMessage {
            public_key: Some(vec![0x01]),
            listen_addrs: vec![vec![0x02]],
            protocols: vec![String::from("p")],
            observed_addr: Some(vec![0x03]),
            protocol_version: Some(String::from("v")),
            agent_version: Some(String::from("a")),
        };

        let encoded = msg.encode();

        let tags: Vec<u8> = extract_field_tags(&encoded);
        assert_eq!(
            tags,
            vec![
                TAG_PUBLIC_KEY,
                TAG_LISTEN_ADDRS,
                TAG_PROTOCOLS,
                TAG_OBSERVED_ADDR,
                TAG_PROTOCOL_VERSION,
                TAG_AGENT_VERSION,
            ]
        );
    }

    /// Regression test for a tag-truncation bug where a high-numbered field
    /// (>= 16) would alias a known single-byte tag after `as u8` truncation.
    ///
    /// Field 33 with wire type LEN encodes as the varint `266 = 0x8A 0x02`.
    /// Casting `266 as u8` yields `0x0A`, which was the byte for
    /// `TAG_PUBLIC_KEY`. A well-behaved decoder must recognize this as an
    /// unknown field-number-33 record, not as public_key.
    #[test]
    fn decode_does_not_alias_high_field_numbers_to_known_fields() {
        let mut data = Vec::new();

        // Field 33, wire type LEN, payload "aliased"
        write_uvarint((33 << 3) | (WIRE_LEN as u64), &mut data);
        write_uvarint(7, &mut data);
        data.extend_from_slice(b"aliased");

        // Known field: agentVersion = "real"
        data.push(TAG_AGENT_VERSION);
        data.push(4);
        data.extend_from_slice(b"real");

        let decoded = IdentifyMessage::decode(&data).unwrap();
        assert!(
            decoded.public_key.is_none(),
            "field 33 must not alias public_key (tag 0x0A)"
        );
        assert_eq!(decoded.agent_version.as_deref(), Some("real"));
    }

    #[test]
    fn decode_rejects_unsupported_wire_type() {
        // Field 1 with wire type 3 (deprecated "start group").
        let mut data = Vec::new();
        data.push((1 << 3) | 3);

        let err = IdentifyMessage::decode(&data).unwrap_err();
        assert!(matches!(
            err,
            IdentifyMessageError::UnsupportedWireType { wire_type: 3, .. }
        ));
    }

    #[test]
    fn decode_rejects_unsupported_wire_type_mid_message() {
        // Field 1 wire type 3 appears AFTER a known field; without the fix
        // this would silently return a partial message with only the first
        // field populated.
        let mut data = Vec::new();
        data.push(TAG_AGENT_VERSION);
        data.push(2);
        data.extend_from_slice(b"hi");
        data.push((2 << 3) | 4); // field 2, "end group" (deprecated)

        let err = IdentifyMessage::decode(&data).unwrap_err();
        assert!(matches!(
            err,
            IdentifyMessageError::UnsupportedWireType { wire_type: 4, .. }
        ));
    }

    /// Helper: extracts the tag bytes from a protobuf-encoded message.
    fn extract_field_tags(data: &[u8]) -> Vec<u8> {
        let mut tags = Vec::new();
        let mut idx = 0;
        while idx < data.len() {
            let tag = data[idx];
            tags.push(tag);
            idx += 1;

            let wire_type = tag & 0x07;
            match wire_type {
                WIRE_LEN => {
                    let (len, used) = read_uvarint(&data[idx..]).unwrap();
                    idx += used + len as usize;
                }
                WIRE_VARINT => {
                    let (_, used) = read_uvarint(&data[idx..]).unwrap();
                    idx += used;
                }
                _ => break,
            }
        }
        tags
    }
}
