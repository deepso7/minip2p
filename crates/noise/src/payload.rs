use alloc::vec::Vec;

use minip2p_identity::{PublicKey, read_uvarint, write_uvarint};

use crate::NoiseError;

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
        write_bytes_field(1, &self.identity_key, &mut out);
        write_bytes_field(2, &self.identity_sig, &mut out);
        if let Some(extensions) = &self.extensions {
            write_bytes_field(4, extensions, &mut out);
        }
        out
    }

    /// Decodes a libp2p Noise handshake payload.
    pub fn decode(input: &[u8]) -> Result<Self, NoiseError> {
        let mut cursor = 0usize;
        let mut identity_key = None;
        let mut identity_sig = None;
        let mut extensions = None;

        while cursor < input.len() {
            let (tag, used) = read_uvarint(&input[cursor..])
                .map_err(|_| NoiseError::InvalidPayload("invalid field tag"))?;
            cursor += used;
            let field = tag >> 3;
            let wire = tag & 7;

            if matches!(field, 1 | 2 | 4) {
                if wire != 2 {
                    return Err(NoiseError::InvalidPayload(
                        "known field has non-length-delimited wire type",
                    ));
                }
                let value = read_bytes(input, &mut cursor)?.to_vec();
                let (slot, duplicate_reason) = match field {
                    1 => (&mut identity_key, "duplicate identity key"),
                    2 => (&mut identity_sig, "duplicate identity signature"),
                    4 => (&mut extensions, "duplicate extensions"),
                    _ => unreachable!("known fields were matched above"),
                };
                if slot.replace(value).is_some() {
                    return Err(NoiseError::InvalidPayload(duplicate_reason));
                }
            } else {
                skip_unknown(input, &mut cursor, wire)?;
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

fn write_bytes_field(field: u64, value: &[u8], out: &mut Vec<u8>) {
    write_uvarint((field << 3) | 2, out);
    write_uvarint(value.len() as u64, out);
    out.extend_from_slice(value);
}

fn read_bytes<'a>(input: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], NoiseError> {
    let (len, used) = read_uvarint(&input[*cursor..])
        .map_err(|_| NoiseError::InvalidPayload("invalid field length"))?;
    *cursor += used;
    let len =
        usize::try_from(len).map_err(|_| NoiseError::InvalidPayload("field length overflow"))?;
    let end = cursor
        .checked_add(len)
        .ok_or(NoiseError::InvalidPayload("field length overflow"))?;
    let value = input
        .get(*cursor..end)
        .ok_or(NoiseError::InvalidPayload("truncated field"))?;
    *cursor = end;
    Ok(value)
}

fn skip_unknown(input: &[u8], cursor: &mut usize, wire: u64) -> Result<(), NoiseError> {
    let count = match wire {
        0 => {
            let (_, used) = read_uvarint(&input[*cursor..])
                .map_err(|_| NoiseError::InvalidPayload("invalid unknown varint"))?;
            used
        }
        1 => 8,
        2 => {
            let _ = read_bytes(input, cursor)?;
            return Ok(());
        }
        5 => 4,
        _ => return Err(NoiseError::InvalidPayload("unsupported protobuf wire type")),
    };
    *cursor = cursor
        .checked_add(count)
        .filter(|end| *end <= input.len())
        .ok_or(NoiseError::InvalidPayload("truncated unknown field"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use minip2p_identity::{Ed25519Keypair, KeyType};

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
        assert!(NoiseHandshakePayload::decode(&[0x0a, 0x20, 1]).is_err());
    }
}
