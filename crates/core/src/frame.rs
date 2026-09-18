//! Varint-length-prefixed frame codec shared by the minip2p protocol crates.
//!
//! Frames are `<uvarint payload length><payload>`. The decoder enforces a
//! caller-supplied maximum payload length and canonical (minimal) varint
//! headers; protocol crates wrap [`decode_frame`] with their own bound.
//!
//! Generic golden and malformed-header cases for this codec live in this
//! module's unit tests. Protocol crates keep only a wrapper check that their
//! `MAX_*` bound is wired correctly.

use alloc::vec::Vec;

use minip2p_identity::{VarintError, read_uvarint, uvarint_len, write_uvarint};

/// Result of attempting to decode a single length-prefixed frame.
#[derive(Clone, Debug, Eq, PartialEq)]
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
    /// The declared payload length exceeds the decoder's maximum.
    TooLarge {
        /// The declared payload length from the frame header.
        len: u64,
    },
    /// The frame header is malformed.
    Error(VarintError),
}

/// Attempts to decode one varint-length-prefixed frame from `input`.
///
/// Returns `Incomplete` if the buffer is missing bytes. A declared payload
/// length greater than `max_len` is rejected with [`FrameDecode::TooLarge`],
/// so callers never buffer towards a frame that can never legally complete.
pub fn decode_frame(input: &[u8], max_len: usize) -> FrameDecode<'_> {
    if input.is_empty() {
        return FrameDecode::Incomplete;
    }

    let (length, used) = match read_uvarint(input) {
        Ok(v) => v,
        Err(VarintError::BufferTooShort) => return FrameDecode::Incomplete,
        Err(e) => return FrameDecode::Error(e),
    };

    // Check the declared length as u64 BEFORE any usize conversion so the
    // rejection is identical on 32-bit and 64-bit targets.
    if length > max_len as u64 {
        return FrameDecode::TooLarge { len: length };
    }
    // Cannot truncate: `length <= max_len` holds here.
    let length = length as usize;
    let Some(total) = used.checked_add(length) else {
        return FrameDecode::Incomplete;
    };
    let Some(payload) = input.get(used..total) else {
        return FrameDecode::Incomplete;
    };

    FrameDecode::Complete {
        payload,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical goldens for the shared stream length-prefix codec.
    ///
    /// Protocol crates wrap [`decode_frame`] with their own `max_len`; the
    /// wire behavior below must stay byte-identical for every wrapper.
    #[test]
    fn golden_empty_payload() {
        assert_eq!(encode_frame(&[]), [0x00]);
        assert!(matches!(
            decode_frame(&[0x00], 4096),
            FrameDecode::Complete { payload, consumed: 1 } if payload.is_empty()
        ));
    }

    #[test]
    fn golden_single_byte_payload() {
        assert_eq!(encode_frame(b"\xab"), [0x01, 0xab]);
        assert!(matches!(
            decode_frame(&[0x01, 0xab], 4096),
            FrameDecode::Complete { payload, consumed: 2 } if payload == b"\xab"
        ));
    }

    #[test]
    fn golden_payload_at_max_len() {
        for max_len in [4096usize, 8192, 65536] {
            let payload = vec![0x5au8; max_len];
            let framed = encode_frame(&payload);
            assert_eq!(framed.len(), max_len + uvarint_len(max_len as u64));
            assert!(matches!(
                decode_frame(&framed, max_len),
                FrameDecode::Complete { payload: p, consumed }
                    if p == payload.as_slice() && consumed == framed.len()
            ));
        }
    }

    #[test]
    fn golden_declared_len_above_max_too_large() {
        // 8193 as a minimal uvarint; rejected from the header alone.
        assert!(matches!(
            decode_frame(&[0x81, 0x40], 8192),
            FrameDecode::TooLarge { len } if u128::from(len) == 8193
        ));
        assert!(matches!(
            decode_frame(&[0x81, 0x20], 4096),
            FrameDecode::TooLarge { len } if u128::from(len) == 4097
        ));
    }

    #[test]
    fn golden_declared_len_u64_max_too_large() {
        let input = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x22,
        ];
        assert!(matches!(
            decode_frame(&input, 8192),
            FrameDecode::TooLarge { len } if u128::from(len) == u128::from(u64::MAX)
        ));
    }

    #[test]
    fn golden_truncated_header_incomplete() {
        assert!(matches!(decode_frame(&[], 8192), FrameDecode::Incomplete));
        assert!(matches!(
            decode_frame(&[0x80], 8192),
            FrameDecode::Incomplete
        ));
    }

    #[test]
    fn golden_truncated_payload_incomplete() {
        assert!(matches!(
            decode_frame(&[0x05, 0xaa, 0xbb], 8192),
            FrameDecode::Incomplete
        ));
        let framed = encode_frame(b"hello");
        assert!(matches!(
            decode_frame(&framed[..framed.len() - 1], 8192),
            FrameDecode::Incomplete
        ));
    }

    #[test]
    fn golden_oversized_varint_header_error() {
        assert!(matches!(
            decode_frame(&[0xff; 10], 8192),
            FrameDecode::Error(VarintError::Overflow)
        ));
    }

    #[test]
    fn golden_non_minimal_length_rejected() {
        assert!(matches!(
            decode_frame(&[0x81, 0x00, 0xaa], 8192),
            FrameDecode::Error(VarintError::NonCanonical)
        ));
    }

    #[test]
    fn golden_multi_frame_consumed() {
        let mut buf = encode_frame(b"first");
        buf.extend_from_slice(&encode_frame(b"second"));
        let consumed = match decode_frame(&buf, 8192) {
            FrameDecode::Complete { payload, consumed } => {
                assert_eq!(payload, b"first");
                assert_eq!(consumed, 6);
                consumed
            }
            _ => panic!("expected first frame"),
        };
        assert!(matches!(
            decode_frame(&buf[consumed..], 8192),
            FrameDecode::Complete { payload, consumed: 7 } if payload == b"second"
        ));
    }
}
