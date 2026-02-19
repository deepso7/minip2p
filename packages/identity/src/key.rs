use alloc::vec::Vec;
use thiserror::Error;

use crate::peer_id::{read_uvarint, uvarint_len, write_uvarint};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
/// Key type values used by libp2p key protobuf wrappers.
pub enum KeyType {
    Rsa = 0,
    Ed25519 = 1,
    Secp256k1 = 2,
    Ecdsa = 3,
}

impl TryFrom<u64> for KeyType {
    type Error = PublicKeyError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Rsa),
            1 => Ok(Self::Ed25519),
            2 => Ok(Self::Secp256k1),
            3 => Ok(Self::Ecdsa),
            _ => Err(PublicKeyError::UnknownKeyType(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// libp2p `PublicKey` protobuf wrapper.
///
/// `data` is key-type-specific encoded key bytes.
pub struct PublicKey {
    key_type: KeyType,
    data: Vec<u8>,
}

impl PublicKey {
    /// Creates a new public key wrapper.
    pub fn new(key_type: KeyType, data: Vec<u8>) -> Self {
        Self { key_type, data }
    }

    /// Returns the protobuf key type value.
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Returns the raw key bytes stored in the protobuf `Data` field.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Consumes the key and returns key bytes.
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    /// Encodes this key as deterministic protobuf bytes.
    ///
    /// Encoding order is fixed: field `Type` (tag 1), then `Data` (tag 2).
    pub fn encode_protobuf(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(1 + 1 + 1 + uvarint_len(self.data.len() as u64) + self.data.len());
        out.push(0x08);
        write_uvarint(self.key_type as u64, &mut out);
        out.push(0x12);
        write_uvarint(self.data.len() as u64, &mut out);
        out.extend_from_slice(&self.data);
        out
    }

    /// Decodes a deterministic libp2p `PublicKey` protobuf byte sequence.
    pub fn decode_protobuf(input: &[u8]) -> Result<Self, PublicKeyError> {
        if input.is_empty() {
            return Err(PublicKeyError::EmptyInput);
        }

        let mut idx = 0usize;
        if input.get(idx).copied() != Some(0x08) {
            return Err(PublicKeyError::InvalidFieldTag {
                expected: 0x08,
                found: input.get(idx).copied(),
            });
        }

        idx += 1;
        let (key_type_raw, used) = read_uvarint(&input[idx..]).map_err(PublicKeyError::Varint)?;
        idx += used;
        let key_type = KeyType::try_from(key_type_raw)?;

        if input.get(idx).copied() != Some(0x12) {
            return Err(PublicKeyError::InvalidFieldTag {
                expected: 0x12,
                found: input.get(idx).copied(),
            });
        }

        idx += 1;
        let (data_len, used) = read_uvarint(&input[idx..]).map_err(PublicKeyError::Varint)?;
        idx += used;

        let data_len: usize = data_len
            .try_into()
            .map_err(|_| PublicKeyError::LengthOverflow)?;

        if idx + data_len != input.len() {
            return Err(PublicKeyError::InvalidLength {
                expected_total: idx + data_len,
                actual_total: input.len(),
            });
        }

        Ok(Self {
            key_type,
            data: input[idx..].to_vec(),
        })
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PublicKeyError {
    #[error("public key protobuf input is empty")]
    EmptyInput,
    #[error("invalid protobuf field tag: expected 0x{expected:02x}, found {found:?}")]
    InvalidFieldTag { expected: u8, found: Option<u8> },
    #[error("invalid protobuf varint: {0}")]
    Varint(crate::peer_id::VarintError),
    #[error("unknown key type value: {0}")]
    UnknownKeyType(u64),
    #[error("protobuf length does not fit in usize")]
    LengthOverflow,
    #[error("invalid protobuf length: expected total {expected_total} bytes, got {actual_total}")]
    InvalidLength {
        expected_total: usize,
        actual_total: usize,
    },
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

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
    fn encodes_and_decodes_public_key_protobuf() {
        let key = PublicKey::new(KeyType::Ed25519, vec![1, 2, 3, 4]);
        let encoded = key.encode_protobuf();
        assert_eq!(encoded, vec![0x08, 0x01, 0x12, 0x04, 1, 2, 3, 4]);

        let decoded = PublicKey::decode_protobuf(&encoded).expect("decode should succeed");
        assert_eq!(decoded, key);
    }

    #[test]
    fn decodes_spec_ed25519_public_key() {
        let encoded =
            decode_hex("080112201ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e");

        let key = PublicKey::decode_protobuf(&encoded).expect("must decode");
        assert_eq!(key.key_type(), KeyType::Ed25519);
        assert_eq!(key.encode_protobuf(), encoded);
    }
}
