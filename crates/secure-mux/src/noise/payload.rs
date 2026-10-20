use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::{
    WIRE_LEN, encode_bytes_field, read_len_delimited, read_string, read_tag, skip_field,
};
use minip2p_identity::{Multihash, PublicKey};

use crate::noise::NoiseError;

const FIELD_IDENTITY_KEY: u64 = 1;
const FIELD_IDENTITY_SIG: u64 = 2;
const FIELD_EXTENSIONS: u64 = 4;
const FIELD_WEBTRANSPORT_CERTHASHES: u64 = 1;
const FIELD_STREAM_MUXERS: u64 = 2;

/// libp2p `NoiseExtensions`, carried in the handshake payload.
///
/// A WebTransport listener sends its current certificate hashes here so a
/// dialer can bind the Noise identity to the TLS certificate it accepted.
/// Noise only carries the values; checking them is the caller's job.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NoiseExtensions {
    /// Multihashes of the WebTransport certificates the sender accepts.
    pub webtransport_certhashes: Vec<Multihash>,
    /// Stream muxer protocol ids for early muxer negotiation.
    pub stream_muxers: Vec<String>,
}

impl NoiseExtensions {
    /// Encodes the extensions using protobuf wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for hash in &self.webtransport_certhashes {
            encode_bytes_field(&mut out, FIELD_WEBTRANSPORT_CERTHASHES, &hash.to_bytes());
        }
        for muxer in &self.stream_muxers {
            encode_bytes_field(&mut out, FIELD_STREAM_MUXERS, muxer.as_bytes());
        }
        out
    }

    /// Decodes a protobuf `NoiseExtensions` message, skipping unknown fields.
    pub fn decode(input: &[u8]) -> Result<Self, NoiseError> {
        let mut cursor = 0usize;
        let mut extensions = Self::default();
        while let Some((field, wire_type)) = read_tag(input, &mut cursor)? {
            match (field, wire_type) {
                (FIELD_WEBTRANSPORT_CERTHASHES, WIRE_LEN) => {
                    let bytes = read_len_delimited(input, &mut cursor)?;
                    #[expect(
                        clippy::map_err_ignore,
                        reason = "NoiseError exposes a stable reason, not multihash internals."
                    )]
                    let hash = Multihash::from_bytes(bytes)
                        .map_err(|_| NoiseError::InvalidPayload("invalid webtransport certhash"))?;
                    extensions.webtransport_certhashes.push(hash);
                }
                (FIELD_STREAM_MUXERS, WIRE_LEN) => {
                    extensions
                        .stream_muxers
                        .push(read_string(input, &mut cursor)?);
                }
                (FIELD_WEBTRANSPORT_CERTHASHES | FIELD_STREAM_MUXERS, _) => {
                    return Err(NoiseError::InvalidPayload(
                        "known field has non-length-delimited wire type",
                    ));
                }
                _ => skip_field(input, &mut cursor, wire_type)?,
            }
        }
        Ok(extensions)
    }
}

/// Decoded libp2p Noise handshake payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoiseHandshakePayload {
    /// Protobuf-encoded libp2p identity public key.
    pub identity_key: Vec<u8>,
    /// Signature binding the identity key to the Noise static key.
    pub identity_sig: Vec<u8>,
    /// Extensions message, when one was supplied.
    pub extensions: Option<NoiseExtensions>,
}

impl NoiseHandshakePayload {
    pub(crate) fn new(
        identity_key: PublicKey,
        identity_sig: [u8; 64],
        extensions: Option<NoiseExtensions>,
    ) -> Self {
        Self {
            identity_key: identity_key.encode_protobuf(),
            identity_sig: identity_sig.to_vec(),
            extensions,
        }
    }

    /// Encodes the payload using protobuf wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_bytes_field(&mut out, FIELD_IDENTITY_KEY, &self.identity_key);
        encode_bytes_field(&mut out, FIELD_IDENTITY_SIG, &self.identity_sig);
        if let Some(extensions) = &self.extensions {
            encode_bytes_field(&mut out, FIELD_EXTENSIONS, &extensions.encode());
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
                        NoiseExtensions::decode(read_len_delimited(input, &mut cursor)?)?,
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
    use minip2p_core::WireError;
    use minip2p_identity::{Ed25519Keypair, KeyType};

    #[test]
    fn encode_matches_known_payload_bytes() {
        let payload = NoiseHandshakePayload {
            identity_key: b"key".to_vec(),
            identity_sig: vec![7; 4],
            extensions: Some(NoiseExtensions {
                webtransport_certhashes: Vec::new(),
                stream_muxers: vec!["m".into()],
            }),
        };
        assert_eq!(
            payload.encode(),
            [
                0x0a, 3, b'k', b'e', b'y', 0x12, 4, 7, 7, 7, 7, 0x22, 3, 0x12, 1, b'm',
            ]
        );
    }

    #[test]
    fn extensions_encode_matches_libp2p_proto_bytes() {
        // message NoiseExtensions { repeated bytes webtransport_certhashes = 1;
        //                           repeated string stream_muxers = 2; }
        let extensions = NoiseExtensions {
            webtransport_certhashes: vec![Multihash::wrap(0x12, &[0xab; 32]).unwrap()],
            stream_muxers: vec!["/yamux/1.0.0".into()],
        };
        let mut expected = vec![0x0a, 34, 0x12, 32];
        expected.extend_from_slice(&[0xab; 32]);
        expected.extend_from_slice(&[0x12, 12]);
        expected.extend_from_slice(b"/yamux/1.0.0");
        assert_eq!(extensions.encode(), expected);
        assert_eq!(NoiseExtensions::decode(&expected), Ok(extensions));
    }

    #[test]
    fn extensions_decode_skips_unknown_fields_and_rejects_bad_multihashes() {
        // Field 3 (varint) is unknown and skipped.
        assert_eq!(
            NoiseExtensions::decode(&[0x18, 0x01]),
            Ok(NoiseExtensions::default())
        );
        assert_eq!(
            NoiseExtensions::decode(&[0x0a, 2, 0x12, 5]),
            Err(NoiseError::InvalidPayload("invalid webtransport certhash"))
        );
    }

    #[test]
    fn payload_carries_typed_extensions() {
        let extensions = NoiseExtensions {
            webtransport_certhashes: vec![Multihash::wrap(0x12, &[1; 32]).unwrap()],
            stream_muxers: Vec::new(),
        };
        let payload = NoiseHandshakePayload {
            identity_key: b"key".to_vec(),
            identity_sig: vec![7; 4],
            extensions: Some(extensions),
        };
        assert_eq!(
            NoiseHandshakePayload::decode(&payload.encode()),
            Ok(payload)
        );
    }

    #[test]
    fn round_trips_payload() {
        let key = Ed25519Keypair::from_secret_key_bytes([3; 32]).public_key();
        let payload = NoiseHandshakePayload::new(key.clone(), [7; 64], None);
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
    fn rejects_invalid_field_numbers() {
        let key = Ed25519Keypair::from_secret_key_bytes([3; 32]).public_key();
        let encoded = NoiseHandshakePayload::new(key, [7; 64], None).encode();

        // Field 0 (varint and LEN), then field 2^29, each ahead of a valid payload.
        let cases: [(&[u8], u64); 3] = [
            (&[0x00, 0x00], 0),
            (&[0x02, 0x00], 0),
            (&[0x80, 0x80, 0x80, 0x80, 0x10, 0x00], 1 << 29),
        ];
        for (invalid_field, field) in cases {
            let mut payload = invalid_field.to_vec();
            payload.extend_from_slice(&encoded);
            assert_eq!(
                NoiseHandshakePayload::decode(&payload),
                Err(NoiseError::Wire(WireError::InvalidFieldNumber {
                    field,
                    offset: 0
                }))
            );
        }
    }
}
