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

use minip2p_core::{VarintError, read_uvarint, uvarint_len, write_uvarint};
use thiserror::Error;

// Wire types from the protobuf spec.
const WIRE_VARINT: u8 = 0;
const WIRE_LEN: u8 = 2;

// Field numbers for the HolePunch message.
const FIELD_TYPE: u64 = 1;
const FIELD_OBS_ADDRS: u64 = 2;

// Single-byte tag bytes used by the encoder (valid for field numbers < 16).
// The decoder does NOT match on truncated u8 tags -- it uses the full u64
// field_number + wire_type split below -- so these are encoder-only.
const TAG_TYPE: u8 = ((FIELD_TYPE as u8) << 3) | WIRE_VARINT; // 0x08
const TAG_OBS_ADDRS: u8 = ((FIELD_OBS_ADDRS as u8) << 3) | WIRE_LEN; // 0x12

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
            // Read the field tag as a full u64. Field numbers >= 16 encode as
            // multi-byte varints; truncating to u8 would let a remote peer
            // alias known tags (e.g. field 33 + LEN => 266, `266 as u8 = 0x0A`).
            let (tag_value, used) = read_uvarint(&input[idx..])?;
            idx += used;

            let wire_type = (tag_value & 0x07) as u8;
            let field_number = tag_value >> 3;

            match (field_number, wire_type) {
                (FIELD_TYPE, WIRE_VARINT) => {
                    let (value, used) = read_uvarint(&input[idx..])?;
                    idx += used;
                    kind = Some(
                        HolePunchType::from_u64(value)
                            .ok_or(DcutrMessageError::InvalidType { value })?,
                    );
                }
                (FIELD_OBS_ADDRS, WIRE_LEN) => {
                    let value = read_len_delimited(input, &mut idx)?;
                    obs_addrs.push(value.to_vec());
                }
                // Skip unknown fields based on their wire type.
                (_, WIRE_VARINT) => {
                    let (_, used) = read_uvarint(&input[idx..])?;
                    idx += used;
                }
                (_, WIRE_LEN) => {
                    let _ = read_len_delimited(input, &mut idx)?;
                }
                (_, 1 /* I64 */) => {
                    if idx + 8 > input.len() {
                        return Err(DcutrMessageError::FieldOverflow {
                            offset: idx,
                            length: 8,
                            remaining: input.len().saturating_sub(idx),
                        });
                    }
                    idx += 8;
                }
                (_, 5 /* I32 */) => {
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

/// Reads a length-delimited value, performing a checked `u64 -> usize`
/// conversion to guard against truncation on 32-bit targets.
fn read_len_delimited<'a>(input: &'a [u8], idx: &mut usize) -> Result<&'a [u8], DcutrMessageError> {
    let (length_u64, len_used) = read_uvarint(&input[*idx..])?;
    *idx += len_used;

    let remaining = input.len().saturating_sub(*idx);
    let length = usize::try_from(length_u64).map_err(|_| DcutrMessageError::FieldOverflow {
        offset: *idx,
        length: usize::MAX,
        remaining,
    })?;

    if length > remaining {
        return Err(DcutrMessageError::FieldOverflow {
            offset: *idx,
            length,
            remaining,
        });
    }

    let value = &input[*idx..*idx + length];
    *idx += length;
    Ok(value)
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
            FrameDecode::Complete {
                payload: p,
                consumed,
            } => {
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

    /// Regression test: a multi-byte tag for a high-numbered unknown field
    /// must not alias a single-byte tag for a known field after truncation.
    ///
    /// Field 33 + wire type LEN encodes as varint `266 = 0x8A 0x02`. Casting
    /// `266 as u8` yields `0x12` -- the tag byte for `TAG_OBS_ADDRS`. A
    /// well-behaved decoder must treat it as an unknown field-33 record.
    #[test]
    fn decode_does_not_alias_high_field_numbers_to_known_fields() {
        let mut buf = Vec::new();

        // Unknown field 33, wire type LEN, payload "aliased"
        write_uvarint((33 << 3) | (WIRE_LEN as u64), &mut buf);
        write_uvarint(7, &mut buf);
        buf.extend_from_slice(b"aliased");

        // Then the real type field.
        buf.push(TAG_TYPE);
        write_uvarint(100, &mut buf); // CONNECT

        let decoded = HolePunch::decode(&buf).unwrap();
        assert_eq!(decoded.kind, HolePunchType::Connect);
        assert!(
            decoded.obs_addrs.is_empty(),
            "field 33 must not alias obs_addrs (tag 0x12)"
        );
    }
}
