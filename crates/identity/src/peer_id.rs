use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt, str::FromStr};

use multihash::Multihash;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::PublicKey;
use crate::multibase::{
    MultibaseError, decode_base32, decode_base58btc, encode_base32_lower, encode_base58btc,
};

/// Multihash code for identity (inline) hashing.
const IDENTITY_MULTIHASH_CODE: u64 = 0x00;
/// Multihash code for SHA-256 hashing.
const SHA256_MULTIHASH_CODE: u64 = 0x12;
/// CIDv1 multicodec value for `libp2p-key`.
const LIBP2P_KEY_MULTICODEC: u64 = 0x72;

/// Public keys with protobuf encoding at or below this size are inlined
/// using identity multihash; larger keys are SHA-256 hashed.
const MAX_INLINE_KEY_LENGTH: usize = 42;

/// Maximum multihash digest size used for peer ids.
pub const PEER_ID_MULTIHASH_SIZE: usize = 64;

/// Multihash type used for peer id storage.
pub type PeerMultihash = Multihash<PEER_ID_MULTIHASH_SIZE>;

/// A libp2p peer id, stored as a multihash.
///
/// Peer ids are derived from public keys. Small keys (Ed25519) are inlined
/// using identity multihash; larger keys (RSA) are SHA-256 hashed.
///
/// Supports parsing and formatting in both legacy base58btc and CIDv1
/// (base32 multibase) forms.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
        encode_base58btc(&multihash)
    }

    /// Encodes this peer id as CIDv1 (`libp2p-key`) in base32 multibase.
    pub fn to_cid_base32(&self) -> String {
        let multihash = self.to_bytes();
        let mut cid = Vec::with_capacity(4 + multihash.len());
        write_uvarint(1, &mut cid);
        write_uvarint(LIBP2P_KEY_MULTICODEC, &mut cid);
        cid.extend_from_slice(&multihash);

        let mut out = String::with_capacity(1 + (cid.len() * 8).div_ceil(5));
        out.push('b');
        out.push_str(&encode_base32_lower(&cid));
        out
    }

    /// Parses legacy base58btc peer id text.
    pub fn from_base58(input: &str) -> Result<Self, PeerIdError> {
        let multihash = decode_base58btc(input)?;
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
            'b' | 'B' => decode_base32(payload)?,
            'z' => decode_base58btc(payload)?,
            _ => return Err(PeerIdError::UnsupportedMultibase(prefix)),
        };

        let (version, version_len) =
            read_uvarint(&cid_bytes).map_err(PeerIdError::InvalidCidVersionVarint)?;
        if version != 1 {
            return Err(PeerIdError::UnsupportedCidVersion(version));
        }

        let codec_input =
            cid_bytes
                .get(version_len..)
                .ok_or(PeerIdError::InvalidCidMulticodecVarint(
                    VarintError::BufferTooShort,
                ))?;
        let (codec, codec_len) =
            read_uvarint(codec_input).map_err(PeerIdError::InvalidCidMulticodecVarint)?;
        if codec != LIBP2P_KEY_MULTICODEC {
            return Err(PeerIdError::UnsupportedMulticodec(codec));
        }

        let multihash_offset =
            version_len
                .checked_add(codec_len)
                .ok_or(PeerIdError::InvalidCidMulticodecVarint(
                    VarintError::Overflow,
                ))?;
        let multihash = cid_bytes
            .get(multihash_offset..)
            .ok_or(PeerIdError::InvalidCidMulticodecVarint(
                VarintError::BufferTooShort,
            ))?
            .to_vec();
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

/// Errors that can occur when parsing or validating a peer id.
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
    #[error("invalid identity digest length: expected at most 42, got {actual}")]
    InvalidIdentityDigestLength { actual: usize },
    #[error(
        "unsupported peer id multihash code 0x{0:x}; expected identity (0x0) or sha2-256 (0x12)"
    )]
    UnsupportedMultihashCode(u64),
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
}

/// Keeps peer id text errors in the peer id vocabulary: peer ids only use the
/// base58btc and base32 codecs, so the base16 cases cannot arise from them.
impl From<MultibaseError> for PeerIdError {
    fn from(error: MultibaseError) -> Self {
        match error {
            MultibaseError::EmptyInput => Self::EmptyInput,
            MultibaseError::InvalidBase58Character { character, index } => {
                Self::InvalidBase58Character { character, index }
            }
            MultibaseError::InvalidBase32Character { character, index } => {
                Self::InvalidBase32Character { character, index }
            }
            other @ (MultibaseError::InvalidBase16Character { .. }
            | MultibaseError::OddBase16Length) => Self::InvalidMultihash(other.to_string()),
        }
    }
}

/// Errors from unsigned varint decoding.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VarintError {
    #[error("buffer ended before varint terminated")]
    BufferTooShort,
    #[error("varint overflows u64")]
    Overflow,
    #[error("varint is not minimally encoded")]
    NonCanonical,
}

/// Returns the number of bytes needed to encode `value` as an unsigned varint.
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
    let (value, remaining) = read_uvarint_with_remainder(input)?;
    Ok((value, input.len() - remaining.len()))
}

/// Reads a canonical unsigned varint and returns the input following it.
pub fn read_uvarint_with_remainder(input: &[u8]) -> Result<(u64, &[u8]), VarintError> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let mut bytes = input.iter();

    for idx in 0..input.len() {
        let Some(&byte) = bytes.next() else {
            return Err(VarintError::BufferTooShort);
        };
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
            return Ok((value, bytes.as_slice()));
        }

        shift += 7;
    }

    Err(VarintError::BufferTooShort)
}

/// Validates that a multihash is a legal peer id encoding.
/// Currently only checks that SHA-256 digests are exactly 32 bytes;
/// identity-hashed multihashes are accepted with any digest length.
/// Accepts only the peer id shapes libp2p defines: an inlined key (identity,
/// at most 42 bytes) or its sha2-256 digest. Those are also exactly the
/// shapes whose base58 text (`1…` / `Qm…`) parses back as a peer id.
fn validate_multihash(multihash: &PeerMultihash) -> Result<(), PeerIdError> {
    let digest_len = multihash.digest().len();
    match multihash.code() {
        IDENTITY_MULTIHASH_CODE if digest_len > MAX_INLINE_KEY_LENGTH => {
            Err(PeerIdError::InvalidIdentityDigestLength { actual: digest_len })
        }
        SHA256_MULTIHASH_CODE if digest_len != 32 => {
            Err(PeerIdError::InvalidSha256DigestLength { actual: digest_len })
        }
        IDENTITY_MULTIHASH_CODE | SHA256_MULTIHASH_CODE => Ok(()),
        code => Err(PeerIdError::UnsupportedMultihashCode(code)),
    }
}

/// Constructs a typed `Multihash<64>` by wrapping the given hash code and digest.
/// Panics if the digest exceeds the 64-byte capacity (should never happen for peer ids).
fn build_multihash(code: u64, digest: &[u8]) -> PeerMultihash {
    PeerMultihash::wrap(code, digest)
        .expect("peer id digests are bounded (identity<=42, sha2-256=32)")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::decode_hex;
    use crate::{KeyType, PublicKey};

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
    fn rejects_multihashes_that_are_not_peer_ids() {
        // Fuzz find: code 0x02 decoded, printed as "9q", and failed to parse.
        assert_eq!(
            PeerId::from_bytes(&[0x02, 0x00]),
            Err(PeerIdError::UnsupportedMultihashCode(0x02))
        );

        let mut oversized = vec![0x00, 43];
        oversized.extend([7; 43]);
        assert_eq!(
            PeerId::from_bytes(&oversized),
            Err(PeerIdError::InvalidIdentityDigestLength { actual: 43 })
        );

        // Every accepted shape prints text that parses back.
        let inline = PeerId::from_bytes(&[0x00, 0x00]).expect("empty identity");
        assert_eq!(inline.to_string().parse::<PeerId>(), Ok(inline));
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

    #[test]
    fn reads_uvarint_with_remainder() {
        let input = [0xac, 0x02, 0xaa, 0xbb];
        let (value, remaining) = read_uvarint_with_remainder(&input).expect("valid varint");

        assert_eq!(value, 300);
        assert_eq!(remaining, [0xaa, 0xbb]);
    }
}
