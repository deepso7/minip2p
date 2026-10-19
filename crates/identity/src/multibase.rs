//! Multibase text codecs: base58btc, RFC 4648 base32 and base16.
//!
//! These are the codecs peer ids use, exposed for other multibase-encoded
//! values such as WebTransport `/certhash` multihashes. The functions work
//! on the payload *without* the multibase prefix character (`z`, `b`/`B`,
//! `f`/`F`); choosing a codec by prefix is the caller's job.

use alloc::{string::String, vec::Vec};

use thiserror::Error;

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE32_ALPHABET_LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Errors from decoding multibase text.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MultibaseError {
    #[error("multibase input is empty")]
    EmptyInput,
    #[error("invalid base58btc character '{character}' at index {index}")]
    InvalidBase58Character { character: char, index: usize },
    #[error("invalid base32 character '{character}' at index {index}")]
    InvalidBase32Character { character: char, index: usize },
    #[error("invalid base16 character '{character}' at index {index}")]
    InvalidBase16Character { character: char, index: usize },
    #[error("base16 input has an odd number of digits")]
    OddBase16Length,
}

/// Base58 digits packed per limb: `58^5` is the largest power of 58 below
/// `2^30`, so one limb times `2^32` plus a carry still fits in a `u64`.
const BASE58_LIMB_DIGITS: usize = 5;
/// `58^5`, the base of each limb in [`encode_base58btc`].
const BASE58_LIMB: u64 = 58u64.pow(BASE58_LIMB_DIGITS as u32);

/// Encodes bytes as base58btc (Bitcoin alphabet).
/// Preserves leading zero bytes as '1' characters, then converts the rest
/// from base-256 to base-58. The conversion runs on wide words (4 input
/// bytes into limbs of five base-58 digits) rather than single digits,
/// which keeps encoding a peer id cheap on the per-event FFI path.
pub fn encode_base58btc(input: &[u8]) -> String {
    let leading_zeros = input.iter().take_while(|byte| **byte == 0).count();
    let rest = input
        .get(leading_zeros..)
        .expect("leading zero count comes from the same input");

    // Little-endian limbs in base 58^5. The first group takes the odd
    // bytes (possibly none) so every later group is exactly 4 bytes wide.
    let mut limbs: Vec<u32> = Vec::with_capacity(rest.len() * 138 / 500 + 1);
    let (head, tail) = rest.split_at(rest.len() % 4);
    for group in
        core::iter::once(head).chain(tail.as_chunks::<4>().0.iter().map(|group| group.as_slice()))
    {
        let shift = 8 * group.len() as u32;
        let mut carry = group
            .iter()
            .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
        for limb in &mut limbs {
            let value = (u64::from(*limb) << shift) + carry;
            *limb = (value % BASE58_LIMB) as u32;
            carry = value / BASE58_LIMB;
        }
        while carry > 0 {
            limbs.push((carry % BASE58_LIMB) as u32);
            carry /= BASE58_LIMB;
        }
    }

    let mut out = String::with_capacity(leading_zeros + limbs.len() * BASE58_LIMB_DIGITS);
    out.extend(core::iter::repeat_n('1', leading_zeros));
    // Every limb but the most significant prints all five digits.
    for (index, limb) in limbs.iter().rev().enumerate() {
        let mut digits = [0u8; BASE58_LIMB_DIGITS];
        let mut value = *limb;
        for digit in digits.iter_mut().rev() {
            *digit = (value % 58) as u8;
            value /= 58;
        }
        let skip = if index == 0 {
            digits.iter().take_while(|digit| **digit == 0).count()
        } else {
            0
        };
        for digit in digits.iter().skip(skip) {
            out.push(char::from(
                *BASE58_ALPHABET
                    .get(usize::from(*digit))
                    .expect("base-58 digit is produced by modulo 58"),
            ));
        }
    }

    out
}

/// Decodes base58btc text into bytes.
/// Reverses the encoding: leading '1' chars become zero bytes, then converts
/// the rest from base-58 to base-256 five digits at a time into 32-bit limbs.
pub fn decode_base58btc(input: &str) -> Result<Vec<u8>, MultibaseError> {
    if input.is_empty() {
        return Err(MultibaseError::EmptyInput);
    }

    let leading_zeros = input.chars().take_while(|c| *c == '1').count();
    let mut digits = Vec::with_capacity(input.len());
    for (index, ch) in input.chars().enumerate().skip(leading_zeros) {
        digits.push(
            base58_value(ch).ok_or(MultibaseError::InvalidBase58Character {
                character: ch,
                index,
            })?,
        );
    }

    // Little-endian limbs in base 2^32. The first group takes the odd
    // digits (possibly none) so every later group is exactly five wide.
    let mut limbs: Vec<u32> = Vec::with_capacity(digits.len() * 733 / 3200 + 1);
    let (head, tail) = digits.split_at(digits.len() % BASE58_LIMB_DIGITS);
    for group in core::iter::once(head).chain(
        tail.as_chunks::<BASE58_LIMB_DIGITS>()
            .0
            .iter()
            .map(|group| group.as_slice()),
    ) {
        let scale = 58u64.pow(group.len() as u32);
        let mut carry = group
            .iter()
            .fold(0u64, |acc, digit| acc * 58 + u64::from(*digit));
        for limb in &mut limbs {
            let value = u64::from(*limb) * scale + carry;
            *limb = value as u32;
            carry = value >> 32;
        }
        while carry > 0 {
            limbs.push(carry as u32);
            carry >>= 32;
        }
    }

    let mut out = Vec::with_capacity(leading_zeros + limbs.len() * 4);
    out.resize(leading_zeros, 0u8);
    for (index, limb) in limbs.iter().rev().enumerate() {
        let bytes = limb.to_be_bytes();
        // The most significant limb drops its zero padding.
        let skip = if index == 0 {
            bytes.iter().take_while(|byte| **byte == 0).count()
        } else {
            0
        };
        out.extend_from_slice(bytes.get(skip..).expect("skip is at most 4"));
    }

    Ok(out)
}

/// Maps a base58btc character to its 0..57 numeric value, or `None` if invalid.
/// The ranges follow [`BASE58_ALPHABET`], which skips `0`, `I`, `O`, and `l`.
fn base58_value(c: char) -> Option<u8> {
    let byte = u8::try_from(c).ok()?;
    match byte {
        b'1'..=b'9' => Some(byte - b'1'),
        b'A'..=b'H' => Some(byte - b'A' + 9),
        b'J'..=b'N' => Some(byte - b'J' + 17),
        b'P'..=b'Z' => Some(byte - b'P' + 22),
        b'a'..=b'k' => Some(byte - b'a' + 33),
        b'm'..=b'z' => Some(byte - b'm' + 44),
        _ => None,
    }
}

/// RFC 4648 base32 encoding, lowercase alphabet, no padding.
/// Streams input through a bit buffer, emitting 5-bit groups as characters.
/// Any remaining bits (<5) are left-shifted and emitted as a final character.
pub fn encode_base32_lower(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity((input.len() * 8).div_ceil(5));
    let mut buffer = 0u16;
    let mut bits = 0u8;

    for byte in input.iter().copied() {
        buffer = (buffer << 8) | byte as u16;
        bits += 8;

        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(
                *BASE32_ALPHABET_LOWER
                    .get(idx)
                    .expect("base-32 index is masked to five bits") as char,
            );
        }
    }

    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(
            *BASE32_ALPHABET_LOWER
                .get(idx)
                .expect("base-32 index is masked to five bits") as char,
        );
    }

    out
}

/// Decodes RFC 4648 base32 (case-insensitive), no padding.
/// Accumulates 5-bit values into a bit buffer, emitting full bytes as they form.
pub fn decode_base32(input: &str) -> Result<Vec<u8>, MultibaseError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity((input.len() * 5) / 8);
    let mut buffer = 0u32;
    let mut bits = 0u8;

    for (index, ch) in input.chars().enumerate() {
        let value = base32_value(ch).ok_or(MultibaseError::InvalidBase32Character {
            character: ch,
            index,
        })? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;

        while bits >= 8 {
            bits -= 8;
            let byte = ((buffer >> bits) & 0xff) as u8;
            out.push(byte);
        }
    }

    Ok(out)
}

/// Maps a base32 character (case-insensitive) to its 0..31 numeric value, or `None` if invalid.
fn base32_value(c: char) -> Option<u8> {
    let lower = c.to_ascii_lowercase();
    match lower {
        'a'..='z' => Some(lower as u8 - b'a'),
        '2'..='7' => Some(26 + (lower as u8 - b'2')),
        _ => None,
    }
}

/// Decodes base16 (hex, case-insensitive) text into bytes.
pub fn decode_base16(input: &str) -> Result<Vec<u8>, MultibaseError> {
    let digits = input
        .chars()
        .enumerate()
        .map(|(index, character)| {
            character
                .to_digit(16)
                .map(|digit| digit as u8)
                .ok_or(MultibaseError::InvalidBase16Character { character, index })
        })
        .collect::<Result<Vec<u8>, _>>()?;
    let (pairs, odd) = digits.as_chunks::<2>();
    if !odd.is_empty() {
        return Err(MultibaseError::OddBase16Length);
    }
    Ok(pairs.iter().map(|[hi, lo]| (hi << 4) | lo).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The go-libp2p certhash fixture in each text codec (payloads only),
    /// with the bytes taken from an independent decoder.
    const SHA256_MULTIHASH_HEX: &str =
        "1220c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2";

    #[test]
    fn decodes_the_same_multihash_from_every_codec() {
        let expected = crate::test_util::decode_hex(SHA256_MULTIHASH_HEX);
        assert_eq!(
            decode_base58btc("QmbWTwYGcmdyK9CYfNBcfs9nhZs17a6FQ4Y8oea278xx41"),
            Ok(expected.clone())
        );
        let base32 = "ciqmhk4p6e3sb2fnsbd52okgnm6is5hfslbpuob5ji4wa4kmv3ymj4q";
        assert_eq!(decode_base32(base32), Ok(expected.clone()));
        assert_eq!(
            decode_base32(&base32.to_ascii_uppercase()),
            Ok(expected.clone())
        );
        assert_eq!(encode_base32_lower(&expected), base32);
        assert_eq!(decode_base16(SHA256_MULTIHASH_HEX), Ok(expected.clone()));
        assert_eq!(
            decode_base16(&SHA256_MULTIHASH_HEX.to_ascii_uppercase()),
            Ok(expected)
        );
    }

    #[test]
    fn base16_rejects_odd_length_and_non_hex() {
        assert_eq!(decode_base16("abc"), Err(MultibaseError::OddBase16Length));
        assert_eq!(
            decode_base16("0g"),
            Err(MultibaseError::InvalidBase16Character {
                character: 'g',
                index: 1
            })
        );
    }

    /// The original digit-at-a-time base58 codec, kept as the reference the
    /// limb-based codec must match byte for byte.
    fn reference_encode_base58(input: &[u8]) -> String {
        if input.is_empty() {
            return String::new();
        }

        let leading_zeros = input.iter().take_while(|byte| **byte == 0).count();
        let mut digits = Vec::with_capacity((input.len() * 138 / 100) + 1);

        for byte in input
            .get(leading_zeros..)
            .expect("leading zero count comes from the same input")
            .iter()
            .copied()
        {
            let mut carry = byte as u32;
            for digit in &mut digits {
                let value = (*digit as u32) * 256 + carry;
                *digit = (value % 58) as u8;
                carry = value / 58;
            }
            while carry > 0 {
                digits.push((carry % 58) as u8);
                carry /= 58;
            }

            if digits.is_empty() {
                digits.push(0);
            }
        }

        let mut out = String::with_capacity(input.len() * 2);
        for _ in 0..leading_zeros {
            out.push('1');
        }

        if digits.is_empty() {
            return out;
        }

        for digit in digits.iter().rev().copied() {
            out.push(
                *BASE58_ALPHABET
                    .get(digit as usize)
                    .expect("base-58 digit is produced by modulo 58") as char,
            );
        }

        out
    }

    /// Decodes base58btc text into bytes.
    /// Reverses the encoding: leading '1' chars become zero bytes, then performs
    /// big-number base conversion from base-58 back to base-256.
    fn reference_decode_base58(input: &str) -> Result<Vec<u8>, MultibaseError> {
        if input.is_empty() {
            return Err(MultibaseError::EmptyInput);
        }

        let leading_zeros = input.chars().take_while(|c| *c == '1').count();
        let mut bytes = Vec::with_capacity(input.len());

        for (index, ch) in input.chars().enumerate().skip(leading_zeros) {
            let value =
                reference_base58_value(ch).ok_or(MultibaseError::InvalidBase58Character {
                    character: ch,
                    index,
                })? as u32;
            let mut carry = value;

            if bytes.is_empty() {
                bytes.push(0);
            }

            for byte in &mut bytes {
                let acc = (*byte as u32) * 58 + carry;
                *byte = (acc & 0xff) as u8;
                carry = acc >> 8;
            }

            while carry > 0 {
                bytes.push((carry & 0xff) as u8);
                carry >>= 8;
            }
        }

        let mut out = Vec::with_capacity(leading_zeros + bytes.len());
        out.resize(leading_zeros, 0u8);

        for byte in bytes.iter().rev().copied() {
            out.push(byte);
        }

        Ok(out)
    }

    /// Maps a base58btc character to its 0..57 numeric value, or `None` if invalid.
    fn reference_base58_value(c: char) -> Option<u8> {
        BASE58_ALPHABET
            .iter()
            .position(|v| *v == c as u8)
            .map(|idx| idx as u8)
    }

    #[test]
    fn base58_codec_matches_reference() {
        // xorshift64: deterministic inputs without a dev-dependency.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut inputs: Vec<Vec<u8>> = vec![
            vec![],
            vec![0],
            vec![0, 0, 0],
            vec![0, 0, 1],
            vec![0xff; 64],
        ];
        for len in 0..80 {
            for _ in 0..16 {
                let zeros = (next() % 4) as usize;
                let mut bytes = vec![0u8; zeros.min(len)];
                bytes.extend((bytes.len()..len).map(|_| next() as u8));
                inputs.push(bytes);
            }
        }

        for bytes in inputs {
            let text = encode_base58btc(&bytes);
            assert_eq!(text, reference_encode_base58(&bytes), "encode {bytes:?}");
            if !text.is_empty() {
                assert_eq!(
                    decode_base58btc(&text),
                    reference_decode_base58(&text),
                    "decode {text}"
                );
                assert_eq!(decode_base58btc(&text), Ok(bytes));
            }
        }
        for c in (0..=255u8).map(char::from) {
            assert_eq!(base58_value(c), reference_base58_value(c), "value {c:?}");
        }
        // The reference truncated `char as u8`, so U+0131 aliased to '1'.
        assert_eq!(
            decode_base58btc("12D3\u{131}"),
            Err(MultibaseError::InvalidBase58Character {
                character: '\u{131}',
                index: 4,
            })
        );
        for text in [
            "1",
            "111",
            "z",
            "zzzzzzzzzzzzzzzzzz",
            "11z",
            "2",
            "Qm0bad",
            "12D3é",
        ] {
            assert_eq!(
                decode_base58btc(text),
                reference_decode_base58(text),
                "decode {text}"
            );
        }
    }
}
