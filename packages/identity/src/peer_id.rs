use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt, str::FromStr};

use multihash::Multihash;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::PublicKey;

pub const IDENTITY_MULTIHASH_CODE: u64 = 0x00;
pub const SHA256_MULTIHASH_CODE: u64 = 0x12;
pub const LIBP2P_KEY_MULTICODEC: u64 = 0x72;

const MAX_INLINE_KEY_LENGTH: usize = 42;

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE32_ALPHABET_LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
pub const PEER_ID_MULTIHASH_SIZE: usize = 64;

pub type PeerMultihash = Multihash<PEER_ID_MULTIHASH_SIZE>;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// A libp2p peer id represented as raw multihash bytes.
pub struct PeerId {
    multihash: PeerMultihash,
}

impl PeerId {
    /// Builds a peer id from a decoded `PublicKey`.
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        Self::from_public_key_protobuf(&public_key.encode_protobuf())
    }

    /// Builds a peer id from deterministic protobuf-encoded public key bytes.
    ///
    /// Uses `identity` multihash when payload length is <= 42 bytes,
    /// otherwise uses `sha2-256` multihash.
    pub fn from_public_key_protobuf(encoded_public_key: &[u8]) -> Self {
        let multihash = if encoded_public_key.len() <= MAX_INLINE_KEY_LENGTH {
            build_multihash(IDENTITY_MULTIHASH_CODE, encoded_public_key)
        } else {
            let digest = Sha256::digest(encoded_public_key);
            build_multihash(SHA256_MULTIHASH_CODE, digest.as_slice())
        };

        Self { multihash }
    }

    /// Parses and validates multihash-encoded peer id bytes.
    pub fn from_bytes(multihash: &[u8]) -> Result<Self, PeerIdError> {
        let parsed = PeerMultihash::from_bytes(multihash)
            .map_err(|err| PeerIdError::InvalidMultihash(err.to_string()))?;

        Self::from_multihash(parsed)
    }

    /// Validates and stores an existing multihash value.
    pub fn from_multihash(multihash: PeerMultihash) -> Result<Self, PeerIdError> {
        validate_multihash(&multihash)?;
        Ok(Self { multihash })
    }

    /// Returns the underlying typed multihash value.
    pub fn multihash(&self) -> &PeerMultihash {
        &self.multihash
    }

    /// Consumes the peer id and returns the typed multihash value.
    pub fn into_multihash(self) -> PeerMultihash {
        self.multihash
    }

    /// Encodes this peer id into multihash bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.multihash.to_bytes()
    }

    /// Returns the raw digest bytes without allocation.
    ///
    /// For the full encoded multihash (code + size + digest), use `to_bytes()`.
    pub fn digest_bytes(&self) -> &[u8] {
        self.multihash.digest()
    }

    /// Encodes this peer id as legacy base58btc multihash text.
    pub fn to_base58(&self) -> String {
        let multihash = self.to_bytes();
        encode_base58(&multihash)
    }

    /// Encodes this peer id as CIDv1 (`libp2p-key`) in base32 multibase.
    pub fn to_cid_base32(&self) -> String {
        let multihash = self.to_bytes();
        let mut cid = Vec::with_capacity(4 + multihash.len());
        write_uvarint(1, &mut cid);
        write_uvarint(LIBP2P_KEY_MULTICODEC, &mut cid);
        cid.extend_from_slice(&multihash);

        let mut out = String::with_capacity(1 + ((cid.len() * 8) + 4) / 5);
        out.push('b');
        out.push_str(&encode_base32_nopad_lower(&cid));
        out
    }

    /// Parses legacy base58btc peer id text.
    pub fn from_base58(input: &str) -> Result<Self, PeerIdError> {
        let multihash = decode_base58(input)?;
        Self::from_bytes(&multihash)
    }

    /// Parses CID peer id text and extracts the multihash.
    pub fn from_cid(input: &str) -> Result<Self, PeerIdError> {
        if input.is_empty() {
            return Err(PeerIdError::EmptyInput);
        }

        let mut chars = input.chars();
        let prefix = chars.next().ok_or(PeerIdError::EmptyInput)?;
        let payload = chars.as_str();

        let cid_bytes = match prefix {
            'b' | 'B' => decode_base32_nopad(payload)?,
            'z' => decode_base58(payload)?,
            _ => return Err(PeerIdError::UnsupportedMultibase(prefix)),
        };

        let (version, version_len) =
            read_uvarint(&cid_bytes).map_err(PeerIdError::InvalidCidVersionVarint)?;
        if version != 1 {
            return Err(PeerIdError::UnsupportedCidVersion(version));
        }

        let (codec, codec_len) = read_uvarint(&cid_bytes[version_len..])
            .map_err(PeerIdError::InvalidCidMulticodecVarint)?;
        if codec != LIBP2P_KEY_MULTICODEC {
            return Err(PeerIdError::UnsupportedMulticodec(codec));
        }

        let multihash = cid_bytes[version_len + codec_len..].to_vec();
        Self::from_bytes(&multihash)
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base58())
    }
}

impl FromStr for PeerId {
    type Err = PeerIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with('1') || s.starts_with("Qm") {
            return Self::from_base58(s);
        }

        Self::from_cid(s)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PeerIdError {
    #[error("peer id input is empty")]
    EmptyInput,
    #[error("unsupported multibase prefix '{0}' (supported: b/B for base32, z for base58btc)")]
    UnsupportedMultibase(char),
    #[error("unsupported cid version {0}; expected v1")]
    UnsupportedCidVersion(u64),
    #[error("unsupported multicodec 0x{0:x}; expected libp2p-key (0x72)")]
    UnsupportedMulticodec(u64),
    #[error("invalid sha2-256 digest length: expected 32, got {actual}")]
    InvalidSha256DigestLength { actual: usize },
    #[error("invalid base58btc character '{character}' at index {index}")]
    InvalidBase58Character { character: char, index: usize },
    #[error("invalid base32 character '{character}' at index {index}")]
    InvalidBase32Character { character: char, index: usize },
    #[error("invalid cid version varint: {0}")]
    InvalidCidVersionVarint(VarintError),
    #[error("invalid cid multicodec varint: {0}")]
    InvalidCidMulticodecVarint(VarintError),
    #[error("invalid multihash: {0}")]
    InvalidMultihash(String),
    #[error("invalid varint: {0}")]
    Varint(VarintError),
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VarintError {
    #[error("buffer ended before varint terminated")]
    BufferTooShort,
    #[error("varint overflows u64")]
    Overflow,
    #[error("varint is not minimally encoded")]
    NonCanonical,
}

pub fn uvarint_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

/// Writes minimally-encoded unsigned varint bytes.
pub fn write_uvarint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Reads an unsigned varint and enforces canonical (minimal) encoding.
pub fn read_uvarint(input: &[u8]) -> Result<(u64, usize), VarintError> {
    let mut value = 0u64;
    let mut shift = 0u32;

    for (idx, byte) in input.iter().copied().enumerate() {
        if idx >= 10 {
            return Err(VarintError::Overflow);
        }

        if idx == 9 && (byte & 0x80 != 0 || byte > 1) {
            return Err(VarintError::Overflow);
        }

        let low = (byte & 0x7f) as u64;
        value |= low << shift;

        if (byte & 0x80) == 0 {
            let used = idx + 1;
            if used != uvarint_len(value) {
                return Err(VarintError::NonCanonical);
            }
            return Ok((value, used));
        }

        shift += 7;
    }

    Err(VarintError::BufferTooShort)
}

fn validate_multihash(multihash: &PeerMultihash) -> Result<(), PeerIdError> {
    let digest_len = multihash.digest().len();
    if multihash.code() == SHA256_MULTIHASH_CODE && digest_len != 32 {
        return Err(PeerIdError::InvalidSha256DigestLength { actual: digest_len });
    }

    Ok(())
}

/// Constructs a typed multihash for peer id storage.
fn build_multihash(code: u64, digest: &[u8]) -> PeerMultihash {
    PeerMultihash::wrap(code, digest)
        .expect("peer id digests are bounded (identity<=42, sha2-256=32)")
}

/// Encodes bytes as base58btc.
fn encode_base58(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }

    let leading_zeros = input.iter().take_while(|byte| **byte == 0).count();
    let mut digits = Vec::with_capacity((input.len() * 138 / 100) + 1);

    for byte in input[leading_zeros..].iter().copied() {
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
        out.push(BASE58_ALPHABET[digit as usize] as char);
    }

    out
}

/// Decodes base58btc text into bytes.
fn decode_base58(input: &str) -> Result<Vec<u8>, PeerIdError> {
    if input.is_empty() {
        return Err(PeerIdError::EmptyInput);
    }

    let leading_zeros = input.chars().take_while(|c| *c == '1').count();
    let mut bytes = Vec::with_capacity(input.len());

    for (index, ch) in input.chars().enumerate().skip(leading_zeros) {
        let value = base58_value(ch).ok_or(PeerIdError::InvalidBase58Character {
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

fn base58_value(c: char) -> Option<u8> {
    BASE58_ALPHABET
        .iter()
        .position(|v| *v == c as u8)
        .map(|idx| idx as u8)
}

/// RFC4648 base32 (lowercase), no padding.
fn encode_base32_nopad_lower(input: &[u8]) -> String {
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
            out.push(BASE32_ALPHABET_LOWER[idx] as char);
        }
    }

    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET_LOWER[idx] as char);
    }

    out
}

/// Decodes RFC4648 base32 (case-insensitive), no padding.
fn decode_base32_nopad(input: &str) -> Result<Vec<u8>, PeerIdError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity((input.len() * 5) / 8);
    let mut buffer = 0u32;
    let mut bits = 0u8;

    for (index, ch) in input.chars().enumerate() {
        let value = base32_value(ch).ok_or(PeerIdError::InvalidBase32Character {
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

fn base32_value(c: char) -> Option<u8> {
    let lower = c.to_ascii_lowercase();
    match lower {
        'a'..='z' => Some(lower as u8 - b'a'),
        '2'..='7' => Some(26 + (lower as u8 - b'2')),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyType, PublicKey};

    fn decode_hex(input: &str) -> Vec<u8> {
        assert_eq!(input.len() % 2, 0);
        let mut out = Vec::with_capacity(input.len() / 2);
        let bytes = input.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16).expect("invalid hex") as u8;
            let lo = (bytes[i + 1] as char).to_digit(16).expect("invalid hex") as u8;
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    #[test]
    fn computes_ed25519_peer_id_from_spec_vector() {
        let public_key = PublicKey::new(
            KeyType::Ed25519,
            decode_hex("1ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e"),
        );

        let peer_id = PeerId::from_public_key(&public_key);

        let mh = peer_id.to_bytes();
        assert_eq!(mh[0], 0x00);
        assert_eq!(mh[1], 0x24);

        let encoded = peer_id.to_base58();
        let parsed = PeerId::from_base58(&encoded).expect("must parse generated base58");
        assert_eq!(parsed, peer_id);
    }

    #[test]
    fn computes_rsa_peer_id_from_spec_vector() {
        let encoded_public_key = decode_hex(
            "080012a60430820222300d06092a864886f70d01010105000382020f003082020a0282020100e1beab071d08200bde24eef00d049449b07770ff9910257b2d7d5dda242ce8f0e2f12e1af4b32d9efd2c090f66b0f29986dbb645dae9880089704a94e5066d594162ae6ee8892e6ec70701db0a6c445c04778eb3de1293aa1a23c3825b85c6620a2bc3f82f9b0c309bc0ab3aeb1873282bebd3da03c33e76c21e9beb172fd44c9e43be32e2c99827033cf8d0f0c606f4579326c930eb4e854395ad941256542c793902185153c474bed109d6ff5141ebf9cd256cf58893a37f83729f97e7cb435ec679d2e33901d27bb35aa0d7e20561da08885ef0abbf8e2fb48d6a5487047a9ecb1ad41fa7ed84f6e3e8ecd5d98b3982d2a901b4454991766da295ab78822add5612a2df83bcee814cf50973e80d7ef38111b1bd87da2ae92438a2c8cbcc70b31ee319939a3b9c761dbc13b5c086d6b64bf7ae7dacc14622375d92a8ff9af7eb962162bbddebf90acb32adb5e4e4029f1c96019949ecfbfeffd7ac1e3fbcc6b6168c34be3d5a2e5999fcbb39bba7adbca78eab09b9bc39f7fa4b93411f4cc175e70c0a083e96bfaefb04a9580b4753c1738a6a760ae1afd851a1a4bdad231cf56e9284d832483df215a46c1c21bdf0c6cfe951c18f1ee4078c79c13d63edb6e14feaeffabc90ad317e4875fe648101b0864097e998f0ca3025ef9638cd2b0caecd3770ab54a1d9c6ca959b0f5dcbc90caeefc4135baca6fd475224269bbe1b0203010001",
        );

        let peer_id = PeerId::from_public_key_protobuf(&encoded_public_key);
        let mh = peer_id.to_bytes();
        assert_eq!(mh[0], 0x12);
        assert_eq!(mh[1], 0x20);

        let encoded_legacy = peer_id.to_base58();
        let encoded_cid = peer_id.to_cid_base32();

        let parsed_legacy = PeerId::from_base58(&encoded_legacy).expect("legacy parse must work");
        let parsed_cid = PeerId::from_cid(&encoded_cid).expect("cid parse must work");
        assert_eq!(parsed_legacy, peer_id);
        assert_eq!(parsed_cid, peer_id);
    }

    #[test]
    fn parses_both_legacy_and_cid_forms() {
        let legacy = "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N";
        let cid = "bafzbeie5745rpv2m6tjyuugywy4d5ewrqgqqhfnf445he3omzpjbx5xqxe";

        let peer_from_legacy: PeerId = legacy.parse().expect("legacy parse must work");
        let peer_from_cid: PeerId = cid.parse().expect("cid parse must work");

        assert_eq!(peer_from_legacy, peer_from_cid);
        assert_eq!(peer_from_legacy.to_base58(), legacy);
        assert_eq!(peer_from_legacy.to_cid_base32(), cid);
    }

    #[test]
    fn includes_multihash_error_details() {
        let err = PeerId::from_bytes(&[0xff]).expect_err("invalid multihash bytes should fail");

        match err {
            PeerIdError::InvalidMultihash(message) => assert!(!message.is_empty()),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn reports_base58_error_with_index() {
        let err = PeerId::from_base58("Qm0bad").expect_err("invalid base58 should fail");

        assert_eq!(
            err,
            PeerIdError::InvalidBase58Character {
                character: '0',
                index: 2,
            }
        );
    }

    #[test]
    fn reports_cid_varint_context() {
        let err = PeerId::from_cid("b").expect_err("empty cid payload should fail");

        assert_eq!(
            err,
            PeerIdError::InvalidCidVersionVarint(VarintError::BufferTooShort)
        );
    }
}
