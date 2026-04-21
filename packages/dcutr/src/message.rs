//! Protobuf encoding for the DCUtR `HolePunch` message.
//!
//! The proto2 schema from
//! <https://github.com/libp2p/specs/blob/master/relay/DCUtR.md>:
//!
//! ```text
//! message HolePunch {
//!   enum Type {
//!     CONNECT = 100;
//!     SYNC = 300;
//!   }
//!   required Type type = 1;      // wire type VARINT (0)
//!   repeated bytes ObsAddrs = 2; // wire type LEN (2)
//! }
//! ```

extern crate alloc;

use alloc::vec::Vec;

use minip2p_core::{read_uvarint, uvarint_len, write_uvarint, VarintError};
use thiserror::Error;

// Tag bytes: (field_number << 3) | wire_type
const TAG_TYPE: u8 = (1 << 3) | 0; // 0x08, varint
const TAG_OBS_ADDRS: u8 = (2 << 3) | 2; // 0x12, length-delimited

/// Type discriminator for the HolePunch message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HolePunchType {
    Connect = 100,
    Sync = 300,
}

impl HolePunchType {
    /// Convert from the raw varint value.
    pub fn from_u64(value: u64) -> Option<Self> {
        match value {
            100 => Some(HolePunchType::Connect),
            300 => Some(HolePunchType::Sync),
            _ => None,
        }
    }
}

/// The DCUtR `HolePunch` message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HolePunch {
    /// Message kind (CONNECT or SYNC).
    pub kind: HolePunchType,
    /// Observed (and possibly predicted) peer addresses in multiaddr binary form.
    pub obs_addrs: Vec<Vec<u8>>,
}

/// Errors that can occur while decoding a HolePunch message.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum DcutrMessageError {
    #[error("varint error: {0}")]
    Varint(#[from] VarintError),
    #[error("field at offset {offset} claims length {length} but only {remaining} bytes remain")]
    FieldOverflow {
        offset: usize,
        length: usize,
        remaining: usize,
    },
    #[error("unsupported wire type {wire_type} at offset {offset}")]
    UnsupportedWireType { wire_type: u8, offset: usize },
    #[error("required `type` field missing")]
    MissingType,
    #[error("invalid HolePunch type value: {value}")]
    InvalidType { value: u64 },
}

impl HolePunch {
    /// Encodes the message body (without length prefix).
    pub fn encode(&self) -> Vec<u8> {
        // Capacity upper bound: tag + varint type + per-addr (tag + varint len + bytes).
        let addrs_bytes: usize = self
            .obs_addrs
            .iter()
            .map(|a| 1 + uvarint_len(a.len() as u64) + a.len())
            .sum();
        let mut out = Vec::with_capacity(1 + uvarint_len(self.kind as u64) + addrs_bytes);

        out.push(TAG_TYPE);
        write_uvarint(self.kind as u64, &mut out);

        for addr in &self.obs_addrs {
            out.push(TAG_OBS_ADDRS);
            write_uvarint(addr.len() as u64, &mut out);
            out.extend_from_slice(addr);
        }

        out
    }

    /// Decodes a HolePunch message body (without length prefix).
    pub fn decode(input: &[u8]) -> Result<Self, DcutrMessageError> {
        let mut kind: Option<HolePunchType> = None;
        let mut obs_addrs = Vec::new();
        let mut idx = 0;

        while idx < input.len() {
            let (tag_value, used) = read_uvarint(&input[idx..])?;
            idx += used;
            let tag = tag_value as u8;
            let wire_type = tag & 0x07;

            match (tag, wire_type) {
                (TAG_TYPE, 0) => {
                    let (value, used) = read_uvarint(&input[idx..])?;
                    idx += used;
                    kind = Some(
                        HolePunchType::from_u64(value)
                            .ok_or(DcutrMessageError::InvalidType { value })?,
                    );
                }
                (TAG_OBS_ADDRS, 2) => {
                    let (length, len_used) = read_uvarint(&input[idx..])?;
                    idx += len_used;
                    let length = length as usize;
                    let remaining = input.len().saturating_sub(idx);
                    if length > remaining {
                        return Err(DcutrMessageError::FieldOverflow {
                            offset: idx,
                            length,
                            remaining,
                        });
                    }
                    obs_addrs.push(input[idx..idx + length].to_vec());
                    idx += length;
                }
                // Skip unknown fields based on wire type.
                (_, 0) => {
                    let (_, used) = read_uvarint(&input[idx..])?;
                    idx += used;
                }
                (_, 2) => {
                    let (length, len_used) = read_uvarint(&input[idx..])?;
                    idx += len_used;
                    let length = length as usize;
                    let remaining = input.len().saturating_sub(idx);
                    if length > remaining {
                        return Err(DcutrMessageError::FieldOverflow {
                            offset: idx,
                            length,
                            remaining,
                        });
                    }
                    idx += length;
                }
                (_, 1) => {
                    if idx + 8 > input.len() {
                        return Err(DcutrMessageError::FieldOverflow {
                            offset: idx,
                            length: 8,
                            remaining: input.len().saturating_sub(idx),
                        });
                    }
                    idx += 8;
                }
                (_, 5) => {
                    if idx + 4 > input.len() {
                        return Err(DcutrMessageError::FieldOverflow {
                            offset: idx,
                            length: 4,
                            remaining: input.len().saturating_sub(idx),
                        });
                    }
                    idx += 4;
                }
                (_, other) => {
                    return Err(DcutrMessageError::UnsupportedWireType {
                        wire_type: other,
                        offset: idx,
                    });
                }
            }
        }

        Ok(HolePunch {
            kind: kind.ok_or(DcutrMessageError::MissingType)?,
            obs_addrs,
        })
    }
}

// ---------------------------------------------------------------------------
// Length-prefixed framing
// ---------------------------------------------------------------------------

/// Result of attempting to decode a single length-prefixed frame.
pub enum FrameDecode<'a> {
    Complete { payload: &'a [u8], consumed: usize },
    Incomplete,
    Error(VarintError),
}

/// Attempts to decode one varint-length-prefixed frame from `input`.
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_round_trip() {
        let msg = HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: vec![
                vec![0x04, 127, 0, 0, 1],
                vec![0x04, 10, 0, 0, 1],
                vec![0x04, 192, 168, 1, 1],
            ],
        };
        let encoded = msg.encode();
        let decoded = HolePunch::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn sync_round_trip() {
        let msg = HolePunch {
            kind: HolePunchType::Sync,
            obs_addrs: Vec::new(),
        };
        let encoded = msg.encode();
        let decoded = HolePunch::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_rejects_missing_type() {
        // Just a single ObsAddrs with no type field.
        let mut buf = Vec::new();
        buf.push(TAG_OBS_ADDRS);
        buf.push(3);
        buf.extend_from_slice(b"abc");

        let err = HolePunch::decode(&buf).unwrap_err();
        assert!(matches!(err, DcutrMessageError::MissingType));
    }

    #[test]
    fn decode_rejects_invalid_type() {
        let mut buf = Vec::new();
        buf.push(TAG_TYPE);
        write_uvarint(999, &mut buf);

        let err = HolePunch::decode(&buf).unwrap_err();
        assert!(matches!(err, DcutrMessageError::InvalidType { value: 999 }));
    }

    #[test]
    fn frame_round_trip() {
        let payload = b"abcdef";
        let framed = encode_frame(payload);
        match decode_frame(&framed) {
            FrameDecode::Complete { payload: p, consumed } => {
                assert_eq!(p, payload);
                assert_eq!(consumed, framed.len());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn frame_incomplete_on_short_input() {
        let framed = encode_frame(b"abcdef");
        let truncated = &framed[..framed.len() - 2];
        assert!(matches!(decode_frame(truncated), FrameDecode::Incomplete));
    }

    #[test]
    fn decoder_skips_unknown_fields() {
        // Unknown field 5 VARINT before the real type field.
        let mut buf = Vec::new();
        buf.push((5 << 3) | 0); // unknown field, varint
        write_uvarint(42, &mut buf);
        buf.push(TAG_TYPE);
        write_uvarint(100, &mut buf); // CONNECT

        let decoded = HolePunch::decode(&buf).unwrap();
        assert_eq!(decoded.kind, HolePunchType::Connect);
    }
}
