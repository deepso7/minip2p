//! Shared protobuf field codec for minip2p protocol crates.
//!
//! Owns the common wire vocabulary — tag bytes, varint and length-delimited
//! field encode/decode, unknown-field skipping, and [`WireError`] — so framing
//! limits and malformed-input behavior cannot drift between protocols.
//!
//! Protocol crates keep their own message structs, semantic validation, and
//! contextual public errors; they wrap [`WireError`] rather than exposing it
//! bare. Field-number policy (for example rejecting field 0) stays with the
//! caller. This module is `no_std` + `alloc` and introduces no I/O, clock, or
//! async dependency.
//!
//! Stream-level length-prefix framing remains in [`crate::frame`].

use alloc::string::String;
use alloc::vec::Vec;

use minip2p_identity::{VarintError, read_uvarint, write_uvarint};
use thiserror::Error;

/// Protobuf wire type: varint.
pub const WIRE_VARINT: u8 = 0;
/// Protobuf wire type: 64-bit fixed.
pub const WIRE_I64: u8 = 1;
/// Protobuf wire type: length-delimited.
pub const WIRE_LEN: u8 = 2;
/// Protobuf wire type: 32-bit fixed.
pub const WIRE_I32: u8 = 5;

/// Errors from shared protobuf framing helpers.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum WireError {
    /// A varint could not be decoded.
    #[error("varint error: {0}")]
    Varint(#[from] VarintError),
    /// A length-delimited or fixed-width field extends beyond the message.
    #[error("field at offset {offset} claims length {length} but only {remaining} bytes remain")]
    FieldOverflow {
        offset: usize,
        length: usize,
        remaining: usize,
    },
    /// An unknown wire type was encountered and cannot be safely skipped.
    #[error("unsupported wire type {wire_type} at offset {offset}")]
    UnsupportedWireType { wire_type: u8, offset: usize },
    /// A length-delimited string field is not valid UTF-8.
    #[error("invalid UTF-8 in length-delimited field at offset {offset}")]
    InvalidUtf8 { offset: usize },
}

/// Computes the single-byte tag for `(field_number, wire_type)`.
///
/// Only handles field numbers `< 16` (single-byte tags), which covers the
/// protocols that currently share this helper.
pub const fn tag_byte(field: u8, wire_type: u8) -> u8 {
    (field << 3) | wire_type
}

/// Writes a `(tag, varint_value)` field.
pub fn encode_varint_field(out: &mut Vec<u8>, tag: u8, value: u64) {
    out.push(tag);
    write_uvarint(value, out);
}

/// Writes a `(tag, length, bytes)` field.
pub fn encode_bytes_field(out: &mut Vec<u8>, tag: u8, data: &[u8]) {
    out.push(tag);
    write_uvarint(data.len() as u64, out);
    out.extend_from_slice(data);
}

/// Writes a `(tag, length, nested_message)` field.
pub fn encode_nested_field(out: &mut Vec<u8>, tag: u8, nested: &[u8]) {
    encode_bytes_field(out, tag, nested);
}

/// Reads the next `(field_number, wire_type)` pair from the buffer.
///
/// Returns `Ok(None)` when the buffer is exhausted. Does not reject field
/// number 0; callers that need that policy apply it themselves.
pub fn read_tag(input: &[u8], idx: &mut usize) -> Result<Option<(u64, u8)>, WireError> {
    if *idx >= input.len() {
        return Ok(None);
    }
    let (tag_value, used) = read_uvarint(input.get(*idx..).ok_or(VarintError::BufferTooShort)?)?;
    advance(input, idx, used)?;
    let wire_type = (tag_value & 0x07) as u8;
    let field_number = tag_value >> 3;
    Ok(Some((field_number, wire_type)))
}

/// Reads a length-delimited value, advancing `idx` past the length and bytes.
pub fn read_len_delimited<'a>(input: &'a [u8], idx: &mut usize) -> Result<&'a [u8], WireError> {
    let (length, used) = read_uvarint(input.get(*idx..).ok_or(VarintError::BufferTooShort)?)?;
    advance(input, idx, used)?;
    #[expect(
        clippy::map_err_ignore,
        reason = "wire lengths wider than usize are reported as varint overflow"
    )]
    let length = usize::try_from(length).map_err(|_| VarintError::Overflow)?;
    let remaining = input.len().saturating_sub(*idx);
    if length > remaining {
        return Err(WireError::FieldOverflow {
            offset: *idx,
            length,
            remaining,
        });
    }
    let end = idx
        .checked_add(length)
        .ok_or(WireError::FieldOverflow {
            offset: *idx,
            length,
            remaining,
        })?;
    let value = input.get(*idx..end).ok_or(WireError::FieldOverflow {
        offset: *idx,
        length,
        remaining,
    })?;
    *idx = end;
    Ok(value)
}

/// Reads a length-delimited UTF-8 string field.
pub fn read_string(input: &[u8], idx: &mut usize) -> Result<String, WireError> {
    let offset = *idx;
    let bytes = read_len_delimited(input, idx)?;
    #[expect(
        clippy::map_err_ignore,
        reason = "the public error preserves the payload offset, not UTF-8 parser internals"
    )]
    let value = core::str::from_utf8(bytes).map_err(|_| WireError::InvalidUtf8 { offset })?;
    Ok(String::from(value))
}

/// Reads a varint field value.
pub fn read_varint_value(input: &[u8], idx: &mut usize) -> Result<u64, WireError> {
    let (value, used) = read_uvarint(input.get(*idx..).ok_or(VarintError::BufferTooShort)?)?;
    advance(input, idx, used)?;
    Ok(value)
}

/// Skips over an unknown field based on its wire type.
pub fn skip_field(input: &[u8], idx: &mut usize, wire_type: u8) -> Result<(), WireError> {
    match wire_type {
        WIRE_VARINT => {
            let (_, used) = read_uvarint(input.get(*idx..).ok_or(VarintError::BufferTooShort)?)?;
            advance(input, idx, used)
        }
        WIRE_LEN => {
            let (length, used) =
                read_uvarint(input.get(*idx..).ok_or(VarintError::BufferTooShort)?)?;
            advance(input, idx, used)?;
            #[expect(
                clippy::map_err_ignore,
                reason = "wire lengths wider than usize are reported as varint overflow"
            )]
            let length = usize::try_from(length).map_err(|_| VarintError::Overflow)?;
            let remaining = input.len().saturating_sub(*idx);
            if length > remaining {
                return Err(WireError::FieldOverflow {
                    offset: *idx,
                    length,
                    remaining,
                });
            }
            advance(input, idx, length)
        }
        WIRE_I32 => advance(input, idx, 4),
        WIRE_I64 => advance(input, idx, 8),
        _ => Err(WireError::UnsupportedWireType {
            wire_type,
            offset: *idx,
        }),
    }
}

fn advance(input: &[u8], idx: &mut usize, length: usize) -> Result<(), WireError> {
    let remaining = input.len().saturating_sub(*idx);
    let end = idx
        .checked_add(length)
        .filter(|end| *end <= input.len())
        .ok_or(WireError::FieldOverflow {
            offset: *idx,
            length,
            remaining,
        })?;
    *idx = end;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn tag_byte_packs_field_and_wire_type() {
        assert_eq!(tag_byte(1, WIRE_VARINT), 0x08);
        assert_eq!(tag_byte(2, WIRE_LEN), 0x12);
        assert_eq!(tag_byte(5, WIRE_VARINT), 0x28);
    }

    #[test]
    fn encode_varint_field_matches_known_bytes() {
        let mut out = Vec::new();
        encode_varint_field(&mut out, tag_byte(1, WIRE_VARINT), 0);
        assert_eq!(out, vec![0x08, 0x00]);
    }

    #[test]
    fn encode_bytes_field_matches_known_bytes() {
        let mut out = Vec::new();
        encode_bytes_field(&mut out, tag_byte(1, WIRE_LEN), b"ab");
        assert_eq!(out, vec![0x0a, 0x02, b'a', b'b']);
    }

    #[test]
    fn encode_nested_field_is_length_delimited_bytes() {
        let mut out = Vec::new();
        encode_nested_field(&mut out, tag_byte(2, WIRE_LEN), &[0x08, 0x01]);
        assert_eq!(out, vec![0x12, 0x02, 0x08, 0x01]);
    }

    #[test]
    fn read_tag_returns_none_at_end() {
        let mut idx = 0;
        assert_eq!(read_tag(&[], &mut idx).unwrap(), None);
    }

    #[test]
    fn read_tag_splits_field_and_wire_type() {
        let input = [0x08, 0x01];
        let mut idx = 0;
        assert_eq!(read_tag(&input, &mut idx).unwrap(), Some((1, WIRE_VARINT)));
        assert_eq!(idx, 1);
    }

    #[test]
    fn read_tag_allows_field_number_zero() {
        // Shared helpers do not enforce field-number policy; callers may.
        let input = [0x02, 0x00]; // field 0, LEN, empty
        let mut idx = 0;
        assert_eq!(read_tag(&input, &mut idx).unwrap(), Some((0, WIRE_LEN)));
    }

    #[test]
    fn read_varint_value_round_trips() {
        let mut buf = Vec::new();
        encode_varint_field(&mut buf, tag_byte(1, WIRE_VARINT), 150);
        let mut idx = 0;
        let (field, wire) = read_tag(&buf, &mut idx).unwrap().unwrap();
        assert_eq!((field, wire), (1, WIRE_VARINT));
        assert_eq!(read_varint_value(&buf, &mut idx).unwrap(), 150);
        assert_eq!(idx, buf.len());
    }

    #[test]
    fn read_len_delimited_round_trips() {
        let mut buf = Vec::new();
        encode_bytes_field(&mut buf, tag_byte(1, WIRE_LEN), b"hello");
        let mut idx = 0;
        let (_, _) = read_tag(&buf, &mut idx).unwrap().unwrap();
        assert_eq!(read_len_delimited(&buf, &mut idx).unwrap(), b"hello");
    }

    #[test]
    fn read_len_delimited_reports_field_overflow() {
        let input = [0x05, b'a', b'b']; // length 5, only 2 bytes remain
        let mut idx = 0;
        let err = read_len_delimited(&input, &mut idx).unwrap_err();
        assert_eq!(
            err,
            WireError::FieldOverflow {
                offset: 1,
                length: 5,
                remaining: 2,
            }
        );
    }

    #[test]
    fn read_string_accepts_utf8_and_rejects_invalid() {
        let mut good = Vec::new();
        encode_bytes_field(&mut good, tag_byte(1, WIRE_LEN), b"ok");
        let mut idx = 0;
        let (_, _) = read_tag(&good, &mut idx).unwrap().unwrap();
        assert_eq!(read_string(&good, &mut idx).unwrap(), "ok");

        let mut bad = Vec::new();
        encode_bytes_field(&mut bad, tag_byte(1, WIRE_LEN), &[0xff, 0xfe]);
        let mut idx = 0;
        let (_, _) = read_tag(&bad, &mut idx).unwrap().unwrap();
        assert!(matches!(
            read_string(&bad, &mut idx),
            Err(WireError::InvalidUtf8 { offset: 1 })
        ));
    }

    #[test]
    fn skip_field_skips_known_wire_types() {
        let mut buf = Vec::new();
        encode_bytes_field(&mut buf, tag_byte(9, WIRE_LEN), b"extra");
        encode_varint_field(&mut buf, tag_byte(1, WIRE_VARINT), 0);
        encode_varint_field(&mut buf, tag_byte(10, WIRE_VARINT), 42);

        let mut idx = 0;
        let (field, wire) = read_tag(&buf, &mut idx).unwrap().unwrap();
        assert_eq!(field, 9);
        skip_field(&buf, &mut idx, wire).unwrap();

        let (field, wire) = read_tag(&buf, &mut idx).unwrap().unwrap();
        assert_eq!((field, wire), (1, WIRE_VARINT));
        assert_eq!(read_varint_value(&buf, &mut idx).unwrap(), 0);

        let (field, wire) = read_tag(&buf, &mut idx).unwrap().unwrap();
        assert_eq!(field, 10);
        skip_field(&buf, &mut idx, wire).unwrap();
        assert_eq!(idx, buf.len());
    }

    #[test]
    fn skip_field_rejects_unsupported_wire_type() {
        let input = [];
        let mut idx = 0;
        let err = skip_field(&input, &mut idx, 7).unwrap_err();
        assert_eq!(
            err,
            WireError::UnsupportedWireType {
                wire_type: 7,
                offset: 0,
            }
        );
    }

    #[test]
    fn skip_fixed32_and_fixed64() {
        let mut buf = Vec::new();
        buf.push(tag_byte(1, WIRE_I32));
        buf.extend_from_slice(&[1, 2, 3, 4]);
        buf.push(tag_byte(2, WIRE_I64));
        buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let mut idx = 0;
        let (_, wire) = read_tag(&buf, &mut idx).unwrap().unwrap();
        skip_field(&buf, &mut idx, wire).unwrap();
        let (_, wire) = read_tag(&buf, &mut idx).unwrap().unwrap();
        skip_field(&buf, &mut idx, wire).unwrap();
        assert_eq!(idx, buf.len());
    }

    #[test]
    fn truncated_varint_reports_varint_error() {
        let input = [0x80]; // incomplete varint
        let mut idx = 0;
        assert!(matches!(
            read_varint_value(&input, &mut idx),
            Err(WireError::Varint(VarintError::BufferTooShort))
        ));
    }
}
