//! QUIC variable-length integers (RFC 9000 §16).

use alloc::vec::Vec;

use crate::VarIntTooLarge;

/// The largest value a varint can carry, 2^62 − 1.
pub const MAX: u64 = (1 << 62) - 1;

/// Decodes one varint from the front of `buf`, returning the value and the
/// number of bytes it used, or `None` if `buf` holds only part of it.
pub fn decode(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    let bytes = buf.get(..len)?;
    let value = bytes
        .iter()
        .skip(1)
        .fold(u64::from(first & 0x3f), |acc, &b| (acc << 8) | u64::from(b));
    Some((value, len))
}

/// Appends `value` to `out` in its shortest encoding.
pub fn encode(value: u64, out: &mut Vec<u8>) -> Result<(), VarIntTooLarge> {
    let len = encoded_len(value)?;
    let tag = match len {
        1 => 0x00,
        2 => 0x40,
        4 => 0x80,
        _ => 0xc0,
    };
    let bytes = value.to_be_bytes();
    let start = bytes.len() - len;
    for (i, b) in bytes.iter().skip(start).enumerate() {
        out.push(if i == 0 { b | tag } else { *b });
    }
    Ok(())
}

/// The number of bytes [`encode`] writes for `value`.
pub fn encoded_len(value: u64) -> Result<usize, VarIntTooLarge> {
    match value {
        0..=0x3f => Ok(1),
        0x40..=0x3fff => Ok(2),
        0x4000..=0x3fff_ffff => Ok(4),
        0x4000_0000..=MAX => Ok(8),
        _ => Err(VarIntTooLarge),
    }
}

/// Accumulates one varint across input chunks, for the stateful decoders.
#[derive(Clone, Debug, Default)]
pub(crate) struct VarIntReader {
    buf: [u8; 8],
    len: usize,
}

impl VarIntReader {
    /// Consumes bytes from `input` until a whole varint is read.
    pub(crate) fn read(&mut self, input: &mut &[u8]) -> Option<u64> {
        while let Some((&byte, rest)) = input.split_first() {
            if let Some(slot) = self.buf.get_mut(self.len) {
                *slot = byte;
            }
            self.len += 1;
            *input = rest;
            let need = 1usize << (self.buf[0] >> 6);
            if self.len == need {
                self.len = 0;
                return decode(&self.buf).map(|(value, _)| value);
            }
        }
        None
    }

    /// Whether no varint is partially read.
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 9000 Appendix A.1 sample encodings.
    const SAMPLES: [(&[u8], u64); 4] = [
        (
            &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
            151_288_809_941_952_652,
        ),
        (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
        (&[0x7b, 0xbd], 15_293),
        (&[0x25], 37),
    ];

    #[test]
    fn decodes_and_encodes_rfc_9000_samples() {
        for (bytes, value) in SAMPLES {
            assert_eq!(decode(bytes), Some((value, bytes.len())));
            let mut out = Vec::new();
            encode(value, &mut out).unwrap();
            assert_eq!(out, bytes);
        }
        // A two-byte encoding of 37 is also valid on the wire.
        assert_eq!(decode(&[0x40, 0x25]), Some((37, 2)));
    }

    #[test]
    fn partial_input_needs_more() {
        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&[0x9d, 0x7f, 0x3e]), None);
    }

    #[test]
    fn values_past_2_62_are_rejected() {
        assert_eq!(encode(MAX + 1, &mut Vec::new()), Err(VarIntTooLarge));
        assert_eq!(encoded_len(MAX), Ok(8));
    }

    #[test]
    fn reader_reassembles_a_varint_split_across_chunks() {
        let mut reader = VarIntReader::default();
        let mut first: &[u8] = &[0xc2, 0x19, 0x7c];
        assert_eq!(reader.read(&mut first), None);
        assert!(!reader.is_empty());
        let mut rest: &[u8] = &[0x5e, 0xff, 0x14, 0xe8, 0x8c, 0x25];
        assert_eq!(reader.read(&mut rest), Some(151_288_809_941_952_652));
        assert_eq!(rest, &[0x25]);
        assert!(reader.is_empty());
    }
}
