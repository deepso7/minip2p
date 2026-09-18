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
//!
//! Field framing uses the shared protobuf vocabulary in [`minip2p_core`];
//! this module keeps DCUtR message types, semantic checks, and contextual
//! [`DcutrMessageError`] values.

extern crate alloc;

use alloc::vec::Vec;

use minip2p_core::{
    WIRE_LEN, WIRE_VARINT, WireError, encode_bytes_field, encode_varint_field, read_len_delimited,
    read_tag, read_varint_value, skip_field, uvarint_len,
};
use thiserror::Error;

use crate::MAX_MESSAGE_SIZE;

// Field numbers for the HolePunch message.
const FIELD_TYPE: u64 = 1;
const FIELD_OBS_ADDRS: u64 = 2;

#[cfg(test)]
const TAG_TYPE: u8 = ((FIELD_TYPE as u8) << 3) | WIRE_VARINT; // 0x08
#[cfg(test)]
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
///
/// Shared framing failures are wrapped as [`Self::Wire`] so callers retain
/// DCUtR context while reusing the core protobuf vocabulary.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum DcutrMessageError {
    /// A shared protobuf framing failure.
    #[error(transparent)]
    Wire(#[from] WireError),
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

        encode_varint_field(&mut out, FIELD_TYPE, self.kind as u64);
        for addr in &self.obs_addrs {
            encode_bytes_field(&mut out, FIELD_OBS_ADDRS, addr);
        }

        out
    }

    /// Decodes a HolePunch message body (without length prefix).
    pub fn decode(input: &[u8]) -> Result<Self, DcutrMessageError> {
        let mut kind: Option<HolePunchType> = None;
        let mut obs_addrs = Vec::new();
        let mut idx = 0;

        while let Some((field_number, wire_type)) = read_tag(input, &mut idx)? {
            match (field_number, wire_type) {
                (FIELD_TYPE, WIRE_VARINT) => {
                    let value = read_varint_value(input, &mut idx)?;
                    kind = Some(
                        HolePunchType::from_u64(value)
                            .ok_or(DcutrMessageError::InvalidType { value })?,
                    );
                }
                (FIELD_OBS_ADDRS, WIRE_LEN) => {
                    obs_addrs.push(read_len_delimited(input, &mut idx)?.to_vec());
                }
                _ => skip_field(input, &mut idx, wire_type)?,
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

pub use minip2p_core::{FrameDecode, encode_frame};

/// Attempts to decode one varint-length-prefixed frame from `input`.
///
/// A declared payload length greater than [`MAX_MESSAGE_SIZE`] is rejected
/// with [`FrameDecode::TooLarge`], so callers never buffer towards a frame
/// that can never legally complete.
pub fn decode_frame(input: &[u8]) -> FrameDecode<'_> {
    minip2p_core::decode_frame(input, MAX_MESSAGE_SIZE)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use minip2p_core::write_uvarint;

    #[test]
    fn connect_encode_matches_known_bytes() {
        let msg = HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: vec![vec![0x04, 127, 0, 0, 1]],
        };
        assert_eq!(
            msg.encode(),
            vec![0x08, 0x64, 0x12, 0x05, 0x04, 127, 0, 0, 1]
        );
    }

    #[test]
    fn sync_encode_matches_known_bytes() {
        let msg = HolePunch {
            kind: HolePunchType::Sync,
            obs_addrs: Vec::new(),
        };
        assert_eq!(msg.encode(), vec![0x08, 0xac, 0x02]);
    }

    #[test]
    fn wire_failures_preserve_dcutr_context_in_display() {
        let input = [0x12, 0x05, b'a', b'b']; // obs_addrs LEN, length 5, only 2 bytes
        let err = HolePunch::decode(&input).unwrap_err();
        assert!(matches!(
            err,
            DcutrMessageError::Wire(WireError::FieldOverflow {
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
        let wrapped = crate::DcutrError::Malformed(err);
        let outer = alloc::format!("{wrapped}");
        assert!(
            outer.starts_with("malformed DCUtR message:"),
            "DCUtR context must wrap the shared failure: {outer}"
        );
    }

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

    /// Wrapper binds [`MAX_MESSAGE_SIZE`]; generic framing goldens live in
    /// `minip2p_core::frame`.
    #[test]
    fn frame_size_limit_is_exact() {
        let payload = vec![0xabu8; MAX_MESSAGE_SIZE];
        let framed = encode_frame(&payload);
        assert!(matches!(
            decode_frame(&framed),
            FrameDecode::Complete { payload: p, .. } if p == payload.as_slice()
        ));

        let mut over = Vec::new();
        write_uvarint((MAX_MESSAGE_SIZE + 1) as u64, &mut over);
        assert!(matches!(
            decode_frame(&over),
            FrameDecode::TooLarge { len } if len == (MAX_MESSAGE_SIZE + 1) as u64
        ));
    }
}
