//! Wire codec for the libp2p pubsub RPC as spoken on `/floodsub/1.0.0`:
//! protobuf encode/decode, varint-length-prefixed stream framing, and
//! StrictSign message signing/verification.
//!
//! Verification matches upstream (go-libp2p / rust-libp2p) exactly: the
//! decoded message is canonically re-encoded with `signature` and `key`
//! omitted, and the signature is checked over `"libp2p-pubsub:" ++ that
//! encoding`. The received bytes (`RawMessage::raw`) are kept only so
//! forwarding can embed them verbatim.

use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::{PeerId, VarintError, read_uvarint, uvarint_len, write_uvarint};
use minip2p_identity::{Ed25519Keypair, PublicKey};

/// Protocol id negotiated for floodsub RPC streams.
pub const FLOODSUB_PROTOCOL_ID: &str = "/floodsub/1.0.0";

/// Maximum encoded RPC size accepted or produced (libp2p pubsub default).
pub const MAX_RPC_SIZE: usize = 65536;

/// Maximum topic length in bytes, enforced on subscribe and publish alike.
pub const MAX_TOPIC_LEN: usize = 1024;

/// Domain-separation prefix for StrictSign signatures.
const SIGN_PREFIX: &[u8] = b"libp2p-pubsub:";

/// Ed25519 signatures are exactly 64 bytes.
const SIGNATURE_LEN: usize = 64;

/// One pubsub RPC: subscription changes and/or published messages.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Rpc {
    /// Field 1: subscription additions/removals.
    pub subscriptions: Vec<SubOpts>,
    /// Field 2: published (or forwarded) messages.
    pub publish: Vec<RawMessage>,
}

/// One subscription change inside an RPC.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SubOpts {
    /// Field 1: `true` = subscribe, `false` = unsubscribe.
    pub subscribe: Option<bool>,
    /// Field 2: the topic the change applies to.
    pub topic_id: Option<String>,
}

/// A publish entry.
///
/// `raw` preserves the exact received (or locally constructed) encoding of
/// the `Message` submessage; forwarding embeds `raw` verbatim so a relayed
/// message reaches downstream verifiers byte-identical. The decoded fields
/// are for local routing and verification only — verification re-encodes
/// them canonically (see [`RawMessage::sign_bytes`]) rather than trusting
/// `raw`, matching upstream libp2p behavior.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RawMessage {
    /// The exact wire encoding of this message submessage.
    pub raw: Vec<u8>,
    /// Field 1: the publisher's `PeerId` bytes.
    pub from: Option<Vec<u8>>,
    /// Field 2: application payload.
    pub data: Option<Vec<u8>>,
    /// Field 3: publisher-assigned sequence number (8 big-endian bytes).
    pub seqno: Option<Vec<u8>>,
    /// Field 4: topics this message belongs to. minip2p always emits
    /// exactly one; multiple entries are decoded for legacy compatibility.
    pub topic_ids: Vec<String>,
    /// Field 5: StrictSign signature.
    pub signature: Option<Vec<u8>>,
    /// Field 6: the publisher's public key (protobuf-encoded). Omitted by
    /// minip2p — recoverable from an inline-Ed25519 `from`.
    pub key: Option<Vec<u8>>,
}

/// Decode errors for RPC/message protobuf payloads.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PubsubWireError {
    /// A varint was malformed.
    #[error("varint error: {0}")]
    Varint(#[from] VarintError),
    /// A length-delimited field overran the buffer.
    #[error("field at offset {offset} declares {length} bytes but only {remaining} remain")]
    FieldOverflow {
        /// Offset of the field's payload.
        offset: usize,
        /// Declared payload length.
        length: usize,
        /// Bytes remaining in the buffer.
        remaining: usize,
    },
    /// A field used a wire type this codec does not accept.
    #[error("unsupported wire type {wire_type} at offset {offset}")]
    UnsupportedWireType {
        /// The offending wire type.
        wire_type: u8,
        /// Offset of the field's tag.
        offset: usize,
    },
    /// A string field held invalid UTF-8.
    #[error("invalid utf-8 in string field at offset {offset}")]
    InvalidUtf8 {
        /// Offset of the field's payload.
        offset: usize,
    },
}

/// Why an inbound message failed StrictSign verification.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MessageVerifyError {
    /// The `from` field is missing.
    #[error("message has no from field")]
    MissingFrom,
    /// The `from` field does not parse as a peer id.
    #[error("message from field is not a valid peer id")]
    InvalidFrom,
    /// The `seqno` field is missing or not exactly 8 bytes.
    #[error("message seqno must be exactly 8 bytes")]
    InvalidSeqno,
    /// The message carries no signature and unsigned messages are refused.
    #[error("message is unsigned")]
    MissingSignature,
    /// A `key` field without a `signature` is always invalid.
    #[error("message carries a key but no signature")]
    KeyWithoutSignature,
    /// The signature is not the expected length.
    #[error("signature must be exactly 64 bytes")]
    InvalidSignatureLength,
    /// The embedded `key` field does not decode as a public key.
    #[error("message key field does not decode as a public key")]
    InvalidKey,
    /// The signing key does not correspond to the `from` peer id — either
    /// the embedded `key` mismatches, or `from` does not inline its key.
    #[error("signing key does not match the from peer id")]
    KeyPeerIdMismatch,
    /// The signature check failed.
    #[error("invalid signature")]
    SignatureInvalid,
}

impl SubOpts {
    /// Encodes the SubOpts message body (without length prefix).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(subscribe) = self.subscribe {
            encode_varint_field(
                &mut out,
                tag_byte(1, WIRE_VARINT),
                if subscribe { 1 } else { 0 },
            );
        }
        if let Some(topic) = &self.topic_id {
            encode_bytes_field(&mut out, tag_byte(2, WIRE_LEN), topic.as_bytes());
        }
        out
    }

    /// Decodes a SubOpts message body.
    pub fn decode(input: &[u8]) -> Result<Self, PubsubWireError> {
        let mut opts = Self::default();
        let mut idx = 0;
        while let Some((field, wire_type)) = read_tag(input, &mut idx)? {
            match (field, wire_type) {
                (1, WIRE_VARINT) => {
                    opts.subscribe = Some(read_varint_value(input, &mut idx)? != 0);
                }
                (2, WIRE_LEN) => {
                    let offset = idx;
                    let bytes = read_len_delimited(input, &mut idx)?;
                    let topic = core::str::from_utf8(bytes)
                        .map_err(|_| PubsubWireError::InvalidUtf8 { offset })?;
                    opts.topic_id = Some(String::from(topic));
                }
                (_, wire_type) => skip_unknown_field(input, &mut idx, wire_type)?,
            }
        }
        Ok(opts)
    }
}

impl RawMessage {
    /// Builds a StrictSign-signed message for `topic` from our identity.
    ///
    /// `seqno` must be strictly increasing per publisher; it becomes the 8
    /// big-endian `seqno` bytes and half of the message's dedup id.
    pub fn build_signed(keypair: &Ed25519Keypair, topic: &str, data: Vec<u8>, seqno: u64) -> Self {
        let mut message = Self {
            raw: Vec::new(),
            from: Some(keypair.peer_id().to_bytes()),
            data: Some(data),
            seqno: Some(seqno.to_be_bytes().to_vec()),
            topic_ids: alloc::vec![String::from(topic)],
            signature: None,
            key: None,
        };
        let signature = keypair.sign(&message.sign_bytes());
        message.signature = Some(signature.to_vec());
        message.raw = message.encode_fields(true);
        message
    }

    /// The bytes StrictSign signs: `"libp2p-pubsub:"` ++ the canonical
    /// encoding of the decoded `from`/`data`/`seqno`/`topic_ids` fields with
    /// `signature`/`key` omitted. Upstream verifies by decoding, clearing
    /// those two fields, and re-encoding — this is that re-encoding, shared
    /// by our build and verify paths.
    pub fn sign_bytes(&self) -> Vec<u8> {
        let body = self.encode_fields(false);
        let mut out = Vec::with_capacity(SIGN_PREFIX.len() + body.len());
        out.extend_from_slice(SIGN_PREFIX);
        out.extend_from_slice(&body);
        out
    }

    /// The wire encoding of this message: the preserved `raw` bytes when
    /// present (decoded or built messages), otherwise a fresh canonical
    /// encoding of the fields.
    pub fn to_wire(&self) -> Vec<u8> {
        if self.raw.is_empty() {
            self.encode_fields(true)
        } else {
            self.raw.clone()
        }
    }

    /// Encodes fields 1–4 in field order, plus `signature`/`key` when
    /// `include_signature` is set.
    fn encode_fields(&self, include_signature: bool) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(from) = &self.from {
            encode_bytes_field(&mut out, tag_byte(1, WIRE_LEN), from);
        }
        if let Some(data) = &self.data {
            encode_bytes_field(&mut out, tag_byte(2, WIRE_LEN), data);
        }
        if let Some(seqno) = &self.seqno {
            encode_bytes_field(&mut out, tag_byte(3, WIRE_LEN), seqno);
        }
        for topic in &self.topic_ids {
            encode_bytes_field(&mut out, tag_byte(4, WIRE_LEN), topic.as_bytes());
        }
        if include_signature {
            if let Some(signature) = &self.signature {
                encode_bytes_field(&mut out, tag_byte(5, WIRE_LEN), signature);
            }
            if let Some(key) = &self.key {
                encode_bytes_field(&mut out, tag_byte(6, WIRE_LEN), key);
            }
        }
        out
    }

    /// Decodes a Message submessage body, preserving `input` as `raw`.
    pub fn decode(input: &[u8]) -> Result<Self, PubsubWireError> {
        let mut message = Self {
            raw: input.to_vec(),
            ..Self::default()
        };
        let mut idx = 0;
        while let Some((field, wire_type)) = read_tag(input, &mut idx)? {
            match (field, wire_type) {
                (1, WIRE_LEN) => message.from = Some(read_len_delimited(input, &mut idx)?.to_vec()),
                (2, WIRE_LEN) => message.data = Some(read_len_delimited(input, &mut idx)?.to_vec()),
                (3, WIRE_LEN) => {
                    message.seqno = Some(read_len_delimited(input, &mut idx)?.to_vec());
                }
                (4, WIRE_LEN) => {
                    let offset = idx;
                    let bytes = read_len_delimited(input, &mut idx)?;
                    let topic = core::str::from_utf8(bytes)
                        .map_err(|_| PubsubWireError::InvalidUtf8 { offset })?;
                    message.topic_ids.push(String::from(topic));
                }
                (5, WIRE_LEN) => {
                    message.signature = Some(read_len_delimited(input, &mut idx)?.to_vec());
                }
                (6, WIRE_LEN) => message.key = Some(read_len_delimited(input, &mut idx)?.to_vec()),
                (_, wire_type) => skip_unknown_field(input, &mut idx, wire_type)?,
            }
        }
        Ok(message)
    }

    /// Verifies this message per StrictSign and returns its publisher and
    /// dedup seqno.
    ///
    /// Rules (see the crate README for the interop rationale):
    /// - `from` must parse as a peer id; `seqno` must be exactly 8 bytes —
    ///   required even for unsigned messages, they form the dedup id.
    /// - A present signature is always verified, `allow_unsigned` or not.
    /// - `key` without `signature` is invalid.
    /// - The signing key must round-trip to `from`
    ///   (`PeerId::from_public_key(key) == from`) whether it came from the
    ///   `key` field or was recovered from an inline-Ed25519 `from`.
    pub fn verify(&self, allow_unsigned: bool) -> Result<(PeerId, u64), MessageVerifyError> {
        let from_bytes = self
            .from
            .as_deref()
            .ok_or(MessageVerifyError::MissingFrom)?;
        let from = PeerId::from_bytes(from_bytes).map_err(|_| MessageVerifyError::InvalidFrom)?;
        let seqno_bytes = self
            .seqno
            .as_deref()
            .ok_or(MessageVerifyError::InvalidSeqno)?;
        let seqno_array: [u8; 8] = seqno_bytes
            .try_into()
            .map_err(|_| MessageVerifyError::InvalidSeqno)?;
        let seqno = u64::from_be_bytes(seqno_array);

        let Some(signature) = self.signature.as_deref() else {
            if self.key.is_some() {
                return Err(MessageVerifyError::KeyWithoutSignature);
            }
            if allow_unsigned {
                return Ok((from, seqno));
            }
            return Err(MessageVerifyError::MissingSignature);
        };
        let signature: &[u8; SIGNATURE_LEN] = signature
            .try_into()
            .map_err(|_| MessageVerifyError::InvalidSignatureLength)?;

        // The signing key must correspond to `from`, whichever way it was
        // conveyed: an embedded `key` that hashes to a different peer id is
        // a forgery vector, and a recovered key trivially satisfies the
        // check only when `from` really inlines it.
        let public_key = match self.key.as_deref() {
            Some(key) => {
                PublicKey::decode_protobuf(key).map_err(|_| MessageVerifyError::InvalidKey)?
            }
            None => PublicKey::decode_protobuf(from.digest_bytes())
                .map_err(|_| MessageVerifyError::KeyPeerIdMismatch)?,
        };
        if PeerId::from_public_key(&public_key) != from {
            return Err(MessageVerifyError::KeyPeerIdMismatch);
        }

        public_key
            .verify(&self.sign_bytes(), signature)
            .map_err(|_| MessageVerifyError::SignatureInvalid)?;
        Ok((from, seqno))
    }
}

impl Rpc {
    /// Encodes the RPC body (without length prefix).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for sub in &self.subscriptions {
            encode_nested_field(&mut out, tag_byte(1, WIRE_LEN), &sub.encode());
        }
        for message in &self.publish {
            encode_nested_field(&mut out, tag_byte(2, WIRE_LEN), &message.to_wire());
        }
        out
    }

    /// Decodes an RPC body.
    pub fn decode(input: &[u8]) -> Result<Self, PubsubWireError> {
        let mut rpc = Self::default();
        let mut idx = 0;
        while let Some((field, wire_type)) = read_tag(input, &mut idx)? {
            match (field, wire_type) {
                (1, WIRE_LEN) => {
                    let nested = read_len_delimited(input, &mut idx)?;
                    rpc.subscriptions.push(SubOpts::decode(nested)?);
                }
                (2, WIRE_LEN) => {
                    let nested = read_len_delimited(input, &mut idx)?;
                    rpc.publish.push(RawMessage::decode(nested)?);
                }
                (_, wire_type) => skip_unknown_field(input, &mut idx, wire_type)?,
            }
        }
        Ok(rpc)
    }
}

// ---------------------------------------------------------------------------
// Protobuf helpers
// ---------------------------------------------------------------------------

/// Computes the tag byte for (field_number, wire_type). Only handles field
/// numbers < 16 (single-byte tags), which covers the whole pubsub RPC.
const fn tag_byte(field: u8, wire_type: u8) -> u8 {
    (field << 3) | wire_type
}

const WIRE_VARINT: u8 = 0;
const WIRE_I64: u8 = 1;
const WIRE_LEN: u8 = 2;
const WIRE_I32: u8 = 5;

/// Writes a `(tag, varint_value)` field.
fn encode_varint_field(out: &mut Vec<u8>, tag: u8, value: u64) {
    out.push(tag);
    write_uvarint(value, out);
}

/// Writes a `(tag, length, bytes)` field.
fn encode_bytes_field(out: &mut Vec<u8>, tag: u8, data: &[u8]) {
    out.push(tag);
    write_uvarint(data.len() as u64, out);
    out.extend_from_slice(data);
}

/// Writes a `(tag, length, nested_message)` field.
fn encode_nested_field(out: &mut Vec<u8>, tag: u8, nested: &[u8]) {
    encode_bytes_field(out, tag, nested);
}

/// Reads the next (field_number, wire_type) pair. The tag is kept as a full
/// u64 before splitting so high field numbers can never alias low ones.
///
/// Returns `Ok(None)` when the buffer is exhausted.
fn read_tag(input: &[u8], idx: &mut usize) -> Result<Option<(u64, u8)>, PubsubWireError> {
    if *idx >= input.len() {
        return Ok(None);
    }
    let (tag_value, used) = read_uvarint(&input[*idx..])?;
    *idx += used;
    let wire_type = (tag_value & 0x07) as u8;
    let field_number = tag_value >> 3;
    Ok(Some((field_number, wire_type)))
}

/// Reads a length-delimited value, advancing `idx` past length and bytes.
fn read_len_delimited<'a>(input: &'a [u8], idx: &mut usize) -> Result<&'a [u8], PubsubWireError> {
    let (length, used) = read_uvarint(&input[*idx..])?;
    *idx += used;
    let length = usize::try_from(length).map_err(|_| VarintError::Overflow)?;
    let remaining = input.len().saturating_sub(*idx);
    if length > remaining {
        return Err(PubsubWireError::FieldOverflow {
            offset: *idx,
            length,
            remaining,
        });
    }
    let value = &input[*idx..*idx + length];
    *idx += length;
    Ok(value)
}

/// Reads a varint field value.
fn read_varint_value(input: &[u8], idx: &mut usize) -> Result<u64, PubsubWireError> {
    let (value, used) = read_uvarint(&input[*idx..])?;
    *idx += used;
    Ok(value)
}

/// Skips over an unknown field based on its wire type.
fn skip_unknown_field(input: &[u8], idx: &mut usize, wire_type: u8) -> Result<(), PubsubWireError> {
    match wire_type {
        WIRE_VARINT => {
            let (_, used) = read_uvarint(&input[*idx..])?;
            *idx += used;
            Ok(())
        }
        WIRE_LEN => {
            read_len_delimited(input, idx)?;
            Ok(())
        }
        WIRE_I32 => {
            if *idx + 4 > input.len() {
                return Err(PubsubWireError::FieldOverflow {
                    offset: *idx,
                    length: 4,
                    remaining: input.len().saturating_sub(*idx),
                });
            }
            *idx += 4;
            Ok(())
        }
        WIRE_I64 => {
            if *idx + 8 > input.len() {
                return Err(PubsubWireError::FieldOverflow {
                    offset: *idx,
                    length: 8,
                    remaining: input.len().saturating_sub(*idx),
                });
            }
            *idx += 8;
            Ok(())
        }
        _ => Err(PubsubWireError::UnsupportedWireType {
            wire_type,
            offset: *idx,
        }),
    }
}

// ---------------------------------------------------------------------------
// Length-prefixed framing
// ---------------------------------------------------------------------------

/// Result of attempting to decode a single length-prefixed RPC frame.
pub enum FrameDecode<'a> {
    /// A complete frame was decoded.
    Complete {
        /// The payload bytes (without the length prefix).
        payload: &'a [u8],
        /// Total bytes consumed from the input (prefix + payload).
        consumed: usize,
    },
    /// Not enough bytes are buffered yet to decode a complete frame.
    Incomplete,
    /// The declared payload length exceeds [`MAX_RPC_SIZE`].
    TooLarge {
        /// The declared payload length from the frame header.
        len: u64,
    },
    /// The frame header is malformed.
    Error(VarintError),
}

/// Attempts to decode one varint-length-prefixed frame from `input`.
///
/// Returns `Incomplete` while bytes are missing. A declared length greater
/// than [`MAX_RPC_SIZE`] is rejected with [`FrameDecode::TooLarge`] before
/// any buffering, so callers never buffer toward a frame that can never
/// legally complete.
pub fn decode_frame(input: &[u8]) -> FrameDecode<'_> {
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
    if length > MAX_RPC_SIZE as u64 {
        return FrameDecode::TooLarge { len: length };
    }
    // Cannot truncate: `length <= MAX_RPC_SIZE` holds here.
    let length = length as usize;
    if length > input.len().saturating_sub(used) {
        return FrameDecode::Incomplete;
    }
    let total = used + length;

    FrameDecode::Complete {
        payload: &input[used..total],
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn keypair() -> Ed25519Keypair {
        Ed25519Keypair::from_secret_key_bytes([7u8; 32])
    }

    fn other_keypair() -> Ed25519Keypair {
        Ed25519Keypair::from_secret_key_bytes([9u8; 32])
    }

    // -- protobuf round-trips ------------------------------------------------

    #[test]
    fn empty_rpc_round_trips_as_empty_bytes() {
        let rpc = Rpc::default();
        let encoded = rpc.encode();
        assert!(encoded.is_empty());
        assert_eq!(Rpc::decode(&encoded).unwrap(), rpc);
    }

    #[test]
    fn subscriptions_round_trip() {
        let rpc = Rpc {
            subscriptions: vec![
                SubOpts {
                    subscribe: Some(true),
                    topic_id: Some(String::from("news")),
                },
                SubOpts {
                    subscribe: Some(false),
                    topic_id: Some(String::from("olds")),
                },
            ],
            publish: Vec::new(),
        };
        assert_eq!(Rpc::decode(&rpc.encode()).unwrap(), rpc);
    }

    #[test]
    fn signed_message_round_trips_with_raw_preserved() {
        let message = RawMessage::build_signed(&keypair(), "chat", b"hello".to_vec(), 42);
        let rpc = Rpc {
            subscriptions: Vec::new(),
            publish: vec![message.clone()],
        };
        let decoded = Rpc::decode(&rpc.encode()).unwrap();
        assert_eq!(decoded.publish.len(), 1);
        assert_eq!(decoded.publish[0], message);
        assert_eq!(decoded.publish[0].raw, message.raw);
    }

    #[test]
    fn multi_topic_message_decodes_all_topics() {
        let message = RawMessage {
            topic_ids: vec![String::from("a"), String::from("b")],
            ..RawMessage::default()
        };
        let decoded = RawMessage::decode(&message.encode_fields(true)).unwrap();
        assert_eq!(decoded.topic_ids, vec!["a", "b"]);
    }

    #[test]
    fn golden_vector_matches_hand_encoding() {
        // RPC { subscriptions: [SubOpts { subscribe: true, topic_id: "t" }],
        //       publish: [Message { from: [0xAB], data: [1, 2],
        //                           seqno: 1u64 BE, topic_ids: ["t"] }] }
        let expected: &[u8] = &[
            0x0a, 0x05, // subscriptions: 5-byte SubOpts
            0x08, 0x01, // subscribe = true
            0x12, 0x01, b't', // topic_id = "t"
            0x12, 0x14, // publish: 20-byte Message
            0x0a, 0x01, 0xab, // from = [0xAB]
            0x12, 0x02, 0x01, 0x02, // data = [1, 2]
            0x1a, 0x08, 0, 0, 0, 0, 0, 0, 0, 1, // seqno = 1u64 BE
            0x22, 0x01, b't', // topic_ids = ["t"]
        ];
        let rpc = Rpc {
            subscriptions: vec![SubOpts {
                subscribe: Some(true),
                topic_id: Some(String::from("t")),
            }],
            publish: vec![RawMessage {
                from: Some(vec![0xAB]),
                data: Some(vec![1, 2]),
                seqno: Some(1u64.to_be_bytes().to_vec()),
                topic_ids: vec![String::from("t")],
                ..RawMessage::default()
            }],
        };
        assert_eq!(rpc.encode(), expected);
        let decoded = Rpc::decode(expected).unwrap();
        assert_eq!(decoded.subscriptions, rpc.subscriptions);
        assert_eq!(decoded.publish[0].from, rpc.publish[0].from);
        assert_eq!(decoded.publish[0].seqno, rpc.publish[0].seqno);
    }

    #[test]
    fn unknown_fields_are_skipped() {
        let mut encoded = SubOpts {
            subscribe: Some(true),
            topic_id: Some(String::from("t")),
        }
        .encode();
        // Append field 15, wire type LEN, 3 bytes.
        encoded.extend_from_slice(&[tag_byte(15, WIRE_LEN), 3, 0xde, 0xad, 0xbe]);
        let decoded = SubOpts::decode(&encoded).unwrap();
        assert_eq!(decoded.subscribe, Some(true));
        assert_eq!(decoded.topic_id.as_deref(), Some("t"));
    }

    #[test]
    fn high_field_numbers_do_not_alias_low_ones() {
        // Field 33 with wire type LEN encodes as a 2-byte tag whose low byte
        // could be mistaken for field 1 if tags were truncated to u8.
        let mut encoded = Vec::new();
        write_uvarint((33u64 << 3) | u64::from(WIRE_LEN), &mut encoded);
        write_uvarint(1, &mut encoded);
        encoded.push(0xFF);
        let decoded = RawMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.from, None, "field 33 must not alias field 1");
    }

    #[test]
    fn truncated_field_errors() {
        // from-field claims 5 bytes, provides 1.
        let encoded = [tag_byte(1, WIRE_LEN), 5, 0xab];
        assert!(matches!(
            RawMessage::decode(&encoded),
            Err(PubsubWireError::FieldOverflow { .. })
        ));
    }

    #[test]
    fn invalid_utf8_topic_errors() {
        let encoded = [tag_byte(4, WIRE_LEN), 2, 0xff, 0xfe];
        assert!(matches!(
            RawMessage::decode(&encoded),
            Err(PubsubWireError::InvalidUtf8 { .. })
        ));
    }

    #[test]
    fn unsupported_wire_type_errors() {
        // Wire type 3 (group start) is not supported.
        let encoded = [(9 << 3) | 3];
        assert!(matches!(
            RawMessage::decode(&encoded),
            Err(PubsubWireError::UnsupportedWireType { wire_type: 3, .. })
        ));
    }

    // -- framing -------------------------------------------------------------

    #[test]
    fn frame_round_trips() {
        let framed = encode_frame(b"hello");
        match decode_frame(&framed) {
            FrameDecode::Complete { payload, consumed } => {
                assert_eq!(payload, b"hello");
                assert_eq!(consumed, framed.len());
            }
            _ => panic!("expected complete frame"),
        }
    }

    #[test]
    fn incomplete_prefix_and_payload_wait_for_more() {
        assert!(matches!(decode_frame(&[]), FrameDecode::Incomplete));
        // Multi-byte varint cut short.
        assert!(matches!(decode_frame(&[0x80]), FrameDecode::Incomplete));
        // Declared 5 bytes, only 2 present.
        assert!(matches!(
            decode_frame(&[5, 0xaa, 0xbb]),
            FrameDecode::Incomplete
        ));
    }

    #[test]
    fn frame_size_limit_is_exact() {
        let mut at_limit = Vec::new();
        write_uvarint(MAX_RPC_SIZE as u64, &mut at_limit);
        at_limit.extend_from_slice(&vec![0u8; MAX_RPC_SIZE]);
        assert!(matches!(
            decode_frame(&at_limit),
            FrameDecode::Complete { .. }
        ));

        let mut over = Vec::new();
        write_uvarint(MAX_RPC_SIZE as u64 + 1, &mut over);
        assert!(matches!(decode_frame(&over), FrameDecode::TooLarge { .. }));
    }

    // -- signing -------------------------------------------------------------

    #[test]
    fn signed_message_verifies_and_yields_identity() {
        let kp = keypair();
        let message = RawMessage::build_signed(&kp, "chat", b"hello".to_vec(), 42);
        assert!(message.key.is_none(), "key must be omitted on the wire");
        let (from, seqno) = message.verify(false).expect("verify");
        assert_eq!(from, kp.peer_id());
        assert_eq!(seqno, 42);
    }

    #[test]
    fn tampering_breaks_the_signature() {
        let kp = keypair();
        let good = RawMessage::build_signed(&kp, "chat", b"hello".to_vec(), 42);

        let mut bad_data = good.clone();
        bad_data.data = Some(b"hellp".to_vec());
        assert_eq!(
            bad_data.verify(false),
            Err(MessageVerifyError::SignatureInvalid)
        );

        let mut bad_topic = good.clone();
        bad_topic.topic_ids = vec![String::from("chas")];
        assert_eq!(
            bad_topic.verify(false),
            Err(MessageVerifyError::SignatureInvalid)
        );

        let mut bad_seqno = good.clone();
        bad_seqno.seqno = Some(43u64.to_be_bytes().to_vec());
        assert_eq!(
            bad_seqno.verify(false),
            Err(MessageVerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn explicit_key_field_is_honored_but_must_match_from() {
        let kp = keypair();
        let mut message = RawMessage::build_signed(&kp, "chat", b"hi".to_vec(), 7);
        message.key = Some(kp.public_key().encode_protobuf());
        assert!(message.verify(false).is_ok(), "matching key field verifies");

        // A forged key that verifies the signature but hashes to a different
        // peer id must be rejected: otherwise anyone could impersonate `from`.
        let attacker = other_keypair();
        let mut forged = RawMessage {
            raw: Vec::new(),
            from: Some(kp.peer_id().to_bytes()),
            data: Some(b"evil".to_vec()),
            seqno: Some(1u64.to_be_bytes().to_vec()),
            topic_ids: vec![String::from("chat")],
            signature: None,
            key: Some(attacker.public_key().encode_protobuf()),
        };
        forged.signature = Some(attacker.sign(&forged.sign_bytes()).to_vec());
        assert_eq!(
            forged.verify(false),
            Err(MessageVerifyError::KeyPeerIdMismatch)
        );
    }

    #[test]
    fn verification_recovers_the_key_from_an_inline_from() {
        let message = RawMessage::build_signed(&keypair(), "chat", b"hi".to_vec(), 7);
        assert!(message.key.is_none());
        assert!(message.verify(false).is_ok());
    }

    #[test]
    fn unsigned_messages_need_allow_unsigned_and_a_valid_id() {
        let kp = keypair();
        let unsigned = RawMessage {
            from: Some(kp.peer_id().to_bytes()),
            seqno: Some(9u64.to_be_bytes().to_vec()),
            data: Some(b"hi".to_vec()),
            topic_ids: vec![String::from("chat")],
            ..RawMessage::default()
        };
        assert_eq!(
            unsigned.verify(false),
            Err(MessageVerifyError::MissingSignature)
        );
        let (from, seqno) = unsigned.verify(true).expect("allow_unsigned accepts");
        assert_eq!(from, kp.peer_id());
        assert_eq!(seqno, 9);

        // Even unsigned, the dedup id fields stay mandatory.
        let mut no_from = unsigned.clone();
        no_from.from = None;
        assert_eq!(no_from.verify(true), Err(MessageVerifyError::MissingFrom));
        let mut short_seqno = unsigned.clone();
        short_seqno.seqno = Some(vec![1, 2, 3]);
        assert_eq!(
            short_seqno.verify(true),
            Err(MessageVerifyError::InvalidSeqno)
        );
    }

    #[test]
    fn key_without_signature_is_invalid_even_when_unsigned_is_allowed() {
        let kp = keypair();
        let message = RawMessage {
            from: Some(kp.peer_id().to_bytes()),
            seqno: Some(9u64.to_be_bytes().to_vec()),
            key: Some(kp.public_key().encode_protobuf()),
            ..RawMessage::default()
        };
        assert_eq!(
            message.verify(true),
            Err(MessageVerifyError::KeyWithoutSignature)
        );
    }

    #[test]
    fn verification_recanonicalizes_instead_of_trusting_raw() {
        // A sender may serialize with unknown fields; upstream verifies the
        // canonical re-encoding of the KNOWN fields, so the message must
        // verify iff the canonical encoding is what was signed — while `raw`
        // still carries the original bytes verbatim for forwarding.
        let kp = keypair();
        let signed = RawMessage::build_signed(&kp, "chat", b"hi".to_vec(), 7);
        let mut wire = signed.encode_fields(true);
        // Unknown field 12 appended by the hypothetical sender AFTER signing
        // the canonical fields (matches upstream behavior).
        wire.extend_from_slice(&[tag_byte(12, WIRE_LEN), 2, 0xca, 0xfe]);

        let decoded = RawMessage::decode(&wire).unwrap();
        assert_eq!(decoded.raw, wire, "raw keeps the original bytes");
        assert!(
            decoded.verify(false).is_ok(),
            "unknown fields are not part of the canonical sign bytes"
        );
        assert_eq!(decoded.to_wire(), wire, "forwarding embeds raw verbatim");
    }
}
