//! Varint-length-prefixed frame codec shared by the minip2p protocol crates.
//!
//! Frames are `<uvarint payload length><payload>`. The decoder enforces a
//! caller-supplied maximum payload length and canonical (minimal) varint
//! headers; protocol crates wrap [`decode_frame`] with their own bound.

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
