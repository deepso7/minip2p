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
//! Field framing uses the shared protobuf vocabulary in [`minip2p_core`].
//! All fields use wire type LEN (2). The encoder writes fields in field-number
//! order. The decoder accepts fields in any order, rejects unsupported wire
//! types, and silently skips unknown fields that use a known wire type.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::{
    WIRE_LEN, WireError, encode_bytes_field, read_len_delimited, read_tag, skip_field,
};
use thiserror::Error;

// Protobuf field numbers for the Identify message.
const FIELD_PUBLIC_KEY: u64 = 1;
const FIELD_LISTEN_ADDRS: u64 = 2;
const FIELD_PROTOCOLS: u64 = 3;
const FIELD_OBSERVED_ADDR: u64 = 4;
const FIELD_PROTOCOL_VERSION: u64 = 5;
const FIELD_AGENT_VERSION: u64 = 6;

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
///
/// Shared framing failures are wrapped as [`Self::Wire`] so callers retain
/// identify context while reusing the core protobuf vocabulary.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum IdentifyMessageError {
    /// A shared protobuf framing failure.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// A string field contains invalid UTF-8.
    #[error("invalid UTF-8 in field {field_number}")]
    InvalidUtf8 { field_number: u64 },
    /// The varint length prefix declared more payload than the buffer holds.
    #[error("identify length prefix is truncated")]
    TruncatedPrefix,
}

impl IdentifyMessage {
    /// Encodes the message to protobuf binary format.
    ///
    /// Fields are written in field-number order.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();

        if let Some(ref key) = self.public_key {
            encode_bytes_field(&mut out, FIELD_PUBLIC_KEY, key);
        }

        for addr in &self.listen_addrs {
            encode_bytes_field(&mut out, FIELD_LISTEN_ADDRS, addr);
        }

        for proto in &self.protocols {
            encode_bytes_field(&mut out, FIELD_PROTOCOLS, proto.as_bytes());
        }

        if let Some(ref addr) = self.observed_addr {
            encode_bytes_field(&mut out, FIELD_OBSERVED_ADDR, addr);
        }

        if let Some(ref ver) = self.protocol_version {
            encode_bytes_field(&mut out, FIELD_PROTOCOL_VERSION, ver.as_bytes());
        }

        if let Some(ref ver) = self.agent_version {
            encode_bytes_field(&mut out, FIELD_AGENT_VERSION, ver.as_bytes());
        }

        out
    }

    /// Decodes a message from protobuf binary format.
    ///
    /// - Accepts fields in any order.
    /// - Silently skips unknown *fields* that use a supported wire type.
    /// - Returns [`IdentifyMessageError::Wire`] with
    ///   [`WireError::UnsupportedWireType`] for wire types outside the
    ///   supported set (0, 1, 2, 5) so malformed messages are rejected
    ///   rather than silently truncated.
    pub fn decode(input: &[u8]) -> Result<Self, IdentifyMessageError> {
        let mut msg = IdentifyMessage::default();
        let mut idx = 0;

        // Tags are full varints so field numbers >= 16 cannot alias known
        // single-byte tags (e.g. field 33 + LEN = 266, which is 0x8A 0x02,
        // not public_key's 0x0A).
        while let Some((field_number, wire_type)) = read_tag(input, &mut idx)? {
            match (field_number, wire_type) {
                (FIELD_PUBLIC_KEY, WIRE_LEN) => {
                    msg.public_key = Some(read_len_delimited(input, &mut idx)?.to_vec());
                }
                (FIELD_LISTEN_ADDRS, WIRE_LEN) => {
                    msg.listen_addrs
                        .push(read_len_delimited(input, &mut idx)?.to_vec());
                }
                (FIELD_PROTOCOLS, WIRE_LEN) => {
                    msg.protocols
                        .push(read_identify_string(input, &mut idx, field_number)?);
                }
                (FIELD_OBSERVED_ADDR, WIRE_LEN) => {
                    msg.observed_addr = Some(read_len_delimited(input, &mut idx)?.to_vec());
                }
                (FIELD_PROTOCOL_VERSION, WIRE_LEN) => {
                    msg.protocol_version =
                        Some(read_identify_string(input, &mut idx, field_number)?);
                }
                (FIELD_AGENT_VERSION, WIRE_LEN) => {
                    msg.agent_version = Some(read_identify_string(input, &mut idx, field_number)?);
                }
                _ => skip_field(input, &mut idx, wire_type)?,
            }
        }

        Ok(msg)
    }
}

/// Reads a length-delimited UTF-8 string, preserving the Identify field number
/// in the public error (shared [`minip2p_core::read_string`] reports offset).
fn read_identify_string(
    input: &[u8],
    idx: &mut usize,
    field_number: u64,
) -> Result<String, IdentifyMessageError> {
    let value = read_len_delimited(input, idx)?;
    #[expect(
        clippy::map_err_ignore,
        reason = "The public error identifies the malformed protobuf field without exposing UTF-8 internals."
    )]
    core::str::from_utf8(value)
        .map(String::from)
        .map_err(|_| IdentifyMessageError::InvalidUtf8 { field_number })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::vec;

    use minip2p_core::{WIRE_LEN, WIRE_VARINT, read_uvarint, write_uvarint};

    use super::*;

    // Single-byte tags for field numbers < 16 (known-good fixture literals).
    const TAG_PUBLIC_KEY: u8 = ((FIELD_PUBLIC_KEY as u8) << 3) | WIRE_LEN;
    const TAG_LISTEN_ADDRS: u8 = ((FIELD_LISTEN_ADDRS as u8) << 3) | WIRE_LEN;
    const TAG_PROTOCOLS: u8 = ((FIELD_PROTOCOLS as u8) << 3) | WIRE_LEN;
    const TAG_OBSERVED_ADDR: u8 = ((FIELD_OBSERVED_ADDR as u8) << 3) | WIRE_LEN;
    const TAG_PROTOCOL_VERSION: u8 = ((FIELD_PROTOCOL_VERSION as u8) << 3) | WIRE_LEN;
    const TAG_AGENT_VERSION: u8 = ((FIELD_AGENT_VERSION as u8) << 3) | WIRE_LEN;

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
        assert!(matches!(
            err,
            IdentifyMessageError::Wire(WireError::FieldOverflow { .. })
        ));
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
        // Unknown field 10, VARINT: value 42
        let mut data = vec![(10 << 3) | WIRE_VARINT, 42, TAG_AGENT_VERSION, 2];
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
        assert_eq!(
            encoded,
            vec![
                TAG_PUBLIC_KEY,
                1,
                0x01,
                TAG_LISTEN_ADDRS,
                1,
                0x02,
                TAG_PROTOCOLS,
                1,
                b'p',
                TAG_OBSERVED_ADDR,
                1,
                0x03,
                TAG_PROTOCOL_VERSION,
                1,
                b'v',
                TAG_AGENT_VERSION,
                1,
                b'a',
            ]
        );

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
        let data = vec![(1 << 3) | 3];

        let err = IdentifyMessage::decode(&data).unwrap_err();
        assert!(matches!(
            err,
            IdentifyMessageError::Wire(WireError::UnsupportedWireType { wire_type: 3, .. })
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
            IdentifyMessageError::Wire(WireError::UnsupportedWireType { wire_type: 4, .. })
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
