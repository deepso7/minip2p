use alloc::vec::Vec;

use minip2p_core::{WIRE_LEN, encode_bytes_field, read_len_delimited, read_tag, skip_field};
use minip2p_identity::PublicKey;

use crate::NoiseError;

const FIELD_IDENTITY_KEY: u64 = 1;
const FIELD_IDENTITY_SIG: u64 = 2;
const FIELD_EXTENSIONS: u64 = 4;

/// Decoded libp2p Noise handshake payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoiseHandshakePayload {
    /// Protobuf-encoded libp2p identity public key.
    pub identity_key: Vec<u8>,
    /// Signature binding the identity key to the Noise static key.
    pub identity_sig: Vec<u8>,
    /// Opaque encoded extensions message, when one was supplied.
    pub extensions: Option<Vec<u8>>,
}

impl NoiseHandshakePayload {
    pub(crate) fn new(identity_key: PublicKey, identity_sig: [u8; 64]) -> Self {
        Self {
            identity_key: identity_key.encode_protobuf(),
            identity_sig: identity_sig.to_vec(),
            extensions: None,
        }
    }

    /// Encodes the payload using protobuf wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_bytes_field(&mut out, FIELD_IDENTITY_KEY, &self.identity_key);
        encode_bytes_field(&mut out, FIELD_IDENTITY_SIG, &self.identity_sig);
        if let Some(extensions) = &self.extensions {
            encode_bytes_field(&mut out, FIELD_EXTENSIONS, extensions);
        }
        out
    }

    /// Decodes a libp2p Noise handshake payload.
    pub fn decode(input: &[u8]) -> Result<Self, NoiseError> {
        let mut cursor = 0usize;
        let mut identity_key = None;
        let mut identity_sig = None;
        let mut extensions = None;

        while let Some((field, wire_type)) = read_tag(input, &mut cursor)? {
            if field == 0 {
                return Err(NoiseError::InvalidPayload("invalid field number zero"));
            }

            match (field, wire_type) {
                (FIELD_IDENTITY_KEY, WIRE_LEN) => {
                    set_unique_field(
                        &mut identity_key,
                        read_len_delimited(input, &mut cursor)?.to_vec(),
                        "duplicate identity key",
                    )?;
                }
                (FIELD_IDENTITY_SIG, WIRE_LEN) => {
                    set_unique_field(
                        &mut identity_sig,
                        read_len_delimited(input, &mut cursor)?.to_vec(),
                        "duplicate identity signature",
                    )?;
                }
                (FIELD_EXTENSIONS, WIRE_LEN) => {
                    set_unique_field(
                        &mut extensions,
                        read_len_delimited(input, &mut cursor)?.to_vec(),
                        "duplicate extensions",
                    )?;
                }
                (FIELD_IDENTITY_KEY | FIELD_IDENTITY_SIG | FIELD_EXTENSIONS, _) => {
                    return Err(NoiseError::InvalidPayload(
                        "known field has non-length-delimited wire type",
                    ));
                }
                _ => skip_field(input, &mut cursor, wire_type)?,
            }
        }

        Ok(Self {
            identity_key: identity_key.ok_or(NoiseError::InvalidPayload("missing identity key"))?,
            identity_sig: identity_sig
                .ok_or(NoiseError::InvalidPayload("missing identity signature"))?,
            extensions,
        })
    }
}

fn set_unique_field<T>(
    slot: &mut Option<T>,
    value: T,
    duplicate_reason: &'static str,
) -> Result<(), NoiseError> {
    if slot.replace(value).is_some() {
        Err(NoiseError::InvalidPayload(duplicate_reason))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minip2p_identity::{Ed25519Keypair, KeyType};

    #[test]
    fn encode_matches_known_payload_bytes() {
        let payload = NoiseHandshakePayload {
            identity_key: b"key".to_vec(),
            identity_sig: vec![7; 4],
            extensions: Some(b"ext".to_vec()),
        };
        assert_eq!(
            payload.encode(),
            [
                0x0a, 3, b'k', b'e', b'y', 0x12, 4, 7, 7, 7, 7, 0x22, 3, b'e', b'x', b't',
            ]
        );
    }

    #[test]
    fn round_trips_payload() {
        let key = Ed25519Keypair::from_secret_key_bytes([3; 32]).public_key();
        let payload = NoiseHandshakePayload::new(key.clone(), [7; 64]);
        let decoded = NoiseHandshakePayload::decode(&payload.encode()).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(
            PublicKey::decode_protobuf(&decoded.identity_key)
                .unwrap()
                .key_type(),
            KeyType::Ed25519
        );
    }

    #[test]
    fn rejects_truncated_payload() {
        let _ = NoiseHandshakePayload::decode(&[0x0a, 0x20, 1]).unwrap_err();
    }

    #[test]
    fn rejects_field_number_zero() {
        let key = Ed25519Keypair::from_secret_key_bytes([3; 32]).public_key();
        let encoded = NoiseHandshakePayload::new(key, [7; 64]).encode();

        for invalid_field in [[0x00, 0x00], [0x02, 0x00]] {
            let mut payload = invalid_field.to_vec();
            payload.extend_from_slice(&encoded);
            assert_eq!(
                NoiseHandshakePayload::decode(&payload),
                Err(NoiseError::InvalidPayload("invalid field number zero"))
            );
        }
    }
}
