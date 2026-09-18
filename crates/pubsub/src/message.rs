//! Wire codec for the libp2p pubsub RPC as spoken by floodsub and meshsub:
//! protobuf encode/decode, varint-length-prefixed stream framing, and
//! StrictSign message signing/verification.
//!
//! Field framing uses the shared protobuf vocabulary in [`minip2p_core`];
//! this module keeps pubsub message types, StrictSign canonicalization, and
//! contextual [`PubsubWireError`] values (including field-number policy).
//!
//! Verification matches upstream (go-libp2p / rust-libp2p) exactly: the
//! decoded message is canonically re-encoded with `signature` and `key`
//! omitted, and the signature is checked over `"libp2p-pubsub:" ++ that
//! encoding`. The received bytes (`RawMessage::raw`) are kept only so
//! forwarding can embed them verbatim.

use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::{
    PeerId, WIRE_LEN, WIRE_VARINT, WireError, encode_bytes_field, encode_nested_field,
    encode_varint_field, read_len_delimited, read_string, read_varint_value, skip_field,
};
use minip2p_identity::{Ed25519Keypair, PublicKey};

/// Protocol id negotiated for floodsub RPC streams.
pub const FLOODSUB_PROTOCOL_ID: &str = "/floodsub/1.0.0";

/// Protocol id for gossipsub v1.0 RPC streams.
pub const MESHSUB_PROTOCOL_ID_V10: &str = "/meshsub/1.0.0";

/// Protocol id for gossipsub v1.1 RPC streams.
pub const MESHSUB_PROTOCOL_ID_V11: &str = "/meshsub/1.1.0";

/// Maximum encoded RPC size accepted or produced (libp2p pubsub default).
pub const MAX_RPC_SIZE: usize = 65536;

/// Maximum topic length in bytes, enforced on subscribe and publish alike.
pub const MAX_TOPIC_LEN: usize = 1024;

/// Maximum accepted `seqno` length in bytes. Implementations disagree on
/// the format (go: 8 big-endian bytes, rust-libp2p floodsub: 20 random
/// bytes), so the seqno is treated as opaque; the cap bounds what the
/// seen-cache stores per message id.
pub(crate) const MAX_SEQNO_LEN: usize = 64;

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
    /// Field 3: gossipsub mesh and gossip control messages.
    pub control: Option<ControlMessage>,
}

/// Gossipsub control messages carried by field 3 of an [`Rpc`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ControlMessage {
    /// Field 1: advertisements of cached message ids.
    pub ihave: Vec<ControlIHave>,
    /// Field 2: requests for advertised message ids.
    pub iwant: Vec<ControlIWant>,
    /// Field 3: requests to join topic meshes.
    pub graft: Vec<ControlGraft>,
    /// Field 4: requests to leave topic meshes.
    pub prune: Vec<ControlPrune>,
}

/// An IHAVE advertisement for recent messages on a topic.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ControlIHave {
    /// Field 1: topic whose cached ids are advertised.
    pub topic_id: Option<String>,
    /// Field 2: opaque message ids. Despite the protobuf `string` type,
    /// upstream implementations permit arbitrary bytes here.
    pub message_ids: Vec<Vec<u8>>,
}

/// An IWANT request for advertised messages.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ControlIWant {
    /// Field 1: opaque message ids requested from the peer.
    pub message_ids: Vec<Vec<u8>>,
}

/// A GRAFT request to join a topic mesh.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ControlGraft {
    /// Field 1: topic whose mesh should include the sender.
    pub topic_id: Option<String>,
}

/// A PRUNE request to leave a topic mesh.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ControlPrune {
    /// Field 1: topic whose mesh should exclude the sender.
    pub topic_id: Option<String>,
    /// Field 2: peer-exchange entries. minip2p preserves these on decode
    /// even when the router elects not to use PX.
    pub peers: Vec<PeerInfo>,
    /// Field 3: v1.1 prune backoff in seconds.
    pub backoff: Option<u64>,
}

/// Peer-exchange information embedded in a [`ControlPrune`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PeerInfo {
    /// Field 1: binary libp2p peer id.
    pub peer_id: Option<Vec<u8>>,
    /// Field 2: signed peer record envelope.
    pub signed_peer_record: Option<Vec<u8>>,
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
/// them canonically (via the internal `RawMessage::sign_bytes`) rather than
/// trusting `raw`, matching upstream libp2p behavior.
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
///
/// Shared framing failures are wrapped as [`Self::Wire`] so callers retain
/// pubsub context while reusing the core protobuf vocabulary.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PubsubWireError {
    /// A shared protobuf framing failure.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// A tag used field number zero, which protobuf reserves as illegal.
    /// Upstream decoders reject it; silently skipping would let hostile
    /// encoders smuggle bytes that canonical re-encoding drops.
    #[error("illegal field number 0 at offset {offset}")]
    InvalidFieldNumber {
        /// Offset of the field's tag.
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
    /// The `seqno` field is missing, empty, or longer than
    /// `MAX_SEQNO_LEN` bytes (currently 64).
    #[error("message seqno must be 1..=64 bytes")]
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
            encode_varint_field(&mut out, 1, if subscribe { 1 } else { 0 });
        }
        if let Some(topic) = &self.topic_id {
            encode_bytes_field(&mut out, 2, topic.as_bytes());
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
                    opts.topic_id = Some(read_string(input, &mut idx)?);
                }
                (_, wire_type) => skip_field(input, &mut idx, wire_type)?,
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
    ///
    /// Every decoded topic participates, in order. Current go treats field
    /// 4 as singular (its re-encode keeps only the last duplicate), but no
    /// implementation *emits* duplicate field-4 entries in signed messages,
    /// so the rules only diverge on hand-crafted input — where including
    /// everything fails toward rejection, the safe direction.
    pub(crate) fn sign_bytes(&self) -> Vec<u8> {
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
            encode_bytes_field(&mut out, 1, from);
        }
        if let Some(data) = &self.data {
            encode_bytes_field(&mut out, 2, data);
        }
        if let Some(seqno) = &self.seqno {
            encode_bytes_field(&mut out, 3, seqno);
        }
        for topic in &self.topic_ids {
            encode_bytes_field(&mut out, 4, topic.as_bytes());
        }
        if include_signature {
            if let Some(signature) = &self.signature {
                encode_bytes_field(&mut out, 5, signature);
            }
            if let Some(key) = &self.key {
                encode_bytes_field(&mut out, 6, key);
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
                    message.topic_ids.push(read_string(input, &mut idx)?);
                }
                (5, WIRE_LEN) => {
                    message.signature = Some(read_len_delimited(input, &mut idx)?.to_vec());
                }
                (6, WIRE_LEN) => message.key = Some(read_len_delimited(input, &mut idx)?.to_vec()),
                (_, wire_type) => skip_field(input, &mut idx, wire_type)?,
            }
        }
        Ok(message)
    }

    /// Parses only the fields needed for the default dedup id. Routers use
    /// this cheap path to discard known replays before signature verification;
    /// unseen messages still pass through [`Self::verify`] before acceptance.
    pub(crate) fn source_and_seqno(&self) -> Result<(PeerId, Vec<u8>), MessageVerifyError> {
        let from_bytes = self
            .from
            .as_deref()
            .ok_or(MessageVerifyError::MissingFrom)?;
        #[expect(
            clippy::map_err_ignore,
            reason = "the verification API intentionally exposes one invalid-publisher category"
        )]
        let from = PeerId::from_bytes(from_bytes).map_err(|_| MessageVerifyError::InvalidFrom)?;
        let seqno = self
            .seqno
            .as_deref()
            .filter(|seqno| !seqno.is_empty() && seqno.len() <= MAX_SEQNO_LEN)
            .ok_or(MessageVerifyError::InvalidSeqno)?
            .to_vec();
        Ok((from, seqno))
    }

    /// Verifies this message per StrictSign and returns its publisher,
    /// dedup seqno bytes, and whether it carried a verified signature.
    ///
    /// Rules (see the crate README for the interop rationale):
    /// - `from` must parse as a peer id; `seqno` must be 1..=64 bytes —
    ///   required even for unsigned messages, they form the dedup id.
    ///   Length varies by implementation (go emits 8 big-endian bytes,
    ///   rust-libp2p floodsub 20 random bytes), so the seqno is opaque
    ///   bytes; the cap only bounds the seen-cache's per-id memory.
    /// - A present signature is always verified, `allow_unsigned` or not.
    /// - `key` without `signature` is invalid.
    /// - The signing key must round-trip to `from`
    ///   (`PeerId::from_public_key(key) == from`) whether it came from the
    ///   `key` field or was recovered from an inline-Ed25519 `from`.
    pub fn verify(
        &self,
        allow_unsigned: bool,
    ) -> Result<(PeerId, Vec<u8>, bool), MessageVerifyError> {
        let (from, seqno) = self.source_and_seqno()?;

        let Some(signature) = self.signature.as_deref() else {
            if self.key.is_some() {
                return Err(MessageVerifyError::KeyWithoutSignature);
            }
            if allow_unsigned {
                return Ok((from, seqno, false));
            }
            return Err(MessageVerifyError::MissingSignature);
        };
        #[expect(
            clippy::map_err_ignore,
            reason = "the error records the only useful detail: that the signature length is invalid"
        )]
        let signature: &[u8; SIGNATURE_LEN] = signature
            .try_into()
            .map_err(|_| MessageVerifyError::InvalidSignatureLength)?;

        // The signing key must correspond to `from`, whichever way it was
        // conveyed: an embedded `key` that hashes to a different peer id is
        // a forgery vector, and a recovered key trivially satisfies the
        // check only when `from` really inlines it.
        let public_key = match self.key.as_deref() {
            Some(key) =>
            {
                #[expect(
                    clippy::map_err_ignore,
                    reason = "wire decode details intentionally collapse into the public invalid-key category"
                )]
                PublicKey::decode_protobuf(key).map_err(|_| MessageVerifyError::InvalidKey)?
            }
            None =>
            {
                #[expect(
                    clippy::map_err_ignore,
                    reason = "a non-inline peer id has no recoverable signing key and maps to a key-peer mismatch"
                )]
                PublicKey::decode_protobuf(from.digest_bytes())
                    .map_err(|_| MessageVerifyError::KeyPeerIdMismatch)?
            }
        };
        if PeerId::from_public_key(&public_key) != from {
            return Err(MessageVerifyError::KeyPeerIdMismatch);
        }

        #[expect(
            clippy::map_err_ignore,
            reason = "signature verifier details must not distinguish malformed keys from invalid signatures to callers"
        )]
        public_key
            .verify(&self.sign_bytes(), signature)
            .map_err(|_| MessageVerifyError::SignatureInvalid)?;
        Ok((from, seqno, true))
    }
}

impl ControlMessage {
    /// Encodes the ControlMessage body (without its enclosing RPC field).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for ihave in &self.ihave {
            encode_nested_field(&mut out, 1, &ihave.encode());
        }
        for iwant in &self.iwant {
            encode_nested_field(&mut out, 2, &iwant.encode());
        }
        for graft in &self.graft {
            encode_nested_field(&mut out, 3, &graft.encode());
        }
        for prune in &self.prune {
            encode_nested_field(&mut out, 4, &prune.encode());
        }
        out
    }

    /// Decodes a ControlMessage body.
    pub fn decode(input: &[u8]) -> Result<Self, PubsubWireError> {
        let mut control = Self::default();
        control.merge_from(input)?;
        Ok(control)
    }

    /// Applies protobuf message-merge semantics to another encoded
    /// ControlMessage occurrence: repeated fields append in wire order.
    fn merge_from(&mut self, input: &[u8]) -> Result<(), PubsubWireError> {
        let mut idx = 0;
        while let Some((field, wire_type)) = read_tag(input, &mut idx)? {
            match (field, wire_type) {
                (1, WIRE_LEN) => {
                    self.ihave
                        .push(ControlIHave::decode(read_len_delimited(input, &mut idx)?)?);
                }
                (2, WIRE_LEN) => {
                    self.iwant
                        .push(ControlIWant::decode(read_len_delimited(input, &mut idx)?)?);
                }
                (3, WIRE_LEN) => {
                    self.graft
                        .push(ControlGraft::decode(read_len_delimited(input, &mut idx)?)?);
                }
                (4, WIRE_LEN) => {
                    self.prune
                        .push(ControlPrune::decode(read_len_delimited(input, &mut idx)?)?);
                }
                (_, wire_type) => skip_field(input, &mut idx, wire_type)?,
            }
        }
        Ok(())
    }
}

impl ControlIHave {
    /// Encodes the ControlIHave message body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(topic_id) = &self.topic_id {
            encode_bytes_field(&mut out, 1, topic_id.as_bytes());
        }
        for message_id in &self.message_ids {
            encode_bytes_field(&mut out, 2, message_id);
        }
        out
    }

    /// Decodes a ControlIHave message body.
    pub fn decode(input: &[u8]) -> Result<Self, PubsubWireError> {
        let mut message = Self::default();
        let mut idx = 0;
        while let Some((field, wire_type)) = read_tag(input, &mut idx)? {
            match (field, wire_type) {
                (1, WIRE_LEN) => {
                    message.topic_id = Some(read_string(input, &mut idx)?);
                }
                (2, WIRE_LEN) => {
                    message
                        .message_ids
                        .push(read_len_delimited(input, &mut idx)?.to_vec());
                }
                (_, wire_type) => skip_field(input, &mut idx, wire_type)?,
            }
        }
        Ok(message)
    }
}

impl ControlIWant {
    /// Encodes the ControlIWant message body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for message_id in &self.message_ids {
            encode_bytes_field(&mut out, 1, message_id);
        }
        out
    }

    /// Decodes a ControlIWant message body.
    pub fn decode(input: &[u8]) -> Result<Self, PubsubWireError> {
        let mut message = Self::default();
        let mut idx = 0;
        while let Some((field, wire_type)) = read_tag(input, &mut idx)? {
            match (field, wire_type) {
                (1, WIRE_LEN) => message
                    .message_ids
                    .push(read_len_delimited(input, &mut idx)?.to_vec()),
                (_, wire_type) => skip_field(input, &mut idx, wire_type)?,
            }
        }
        Ok(message)
    }
}

impl ControlGraft {
    /// Encodes the ControlGraft message body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(topic_id) = &self.topic_id {
            encode_bytes_field(&mut out, 1, topic_id.as_bytes());
        }
        out
    }

    /// Decodes a ControlGraft message body.
    pub fn decode(input: &[u8]) -> Result<Self, PubsubWireError> {
        let mut message = Self::default();
        let mut idx = 0;
        while let Some((field, wire_type)) = read_tag(input, &mut idx)? {
            match (field, wire_type) {
                (1, WIRE_LEN) => message.topic_id = Some(read_string(input, &mut idx)?),
                (_, wire_type) => skip_field(input, &mut idx, wire_type)?,
            }
        }
        Ok(message)
    }
}

impl ControlPrune {
    /// Encodes the ControlPrune message body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(topic_id) = &self.topic_id {
            encode_bytes_field(&mut out, 1, topic_id.as_bytes());
        }
        for peer in &self.peers {
            encode_nested_field(&mut out, 2, &peer.encode());
        }
        if let Some(backoff) = self.backoff {
            encode_varint_field(&mut out, 3, backoff);
        }
        out
    }

    /// Decodes a ControlPrune message body.
    pub fn decode(input: &[u8]) -> Result<Self, PubsubWireError> {
        let mut message = Self::default();
        let mut idx = 0;
        while let Some((field, wire_type)) = read_tag(input, &mut idx)? {
            match (field, wire_type) {
                (1, WIRE_LEN) => message.topic_id = Some(read_string(input, &mut idx)?),
                (2, WIRE_LEN) => message
                    .peers
                    .push(PeerInfo::decode(read_len_delimited(input, &mut idx)?)?),
                (3, WIRE_VARINT) => message.backoff = Some(read_varint_value(input, &mut idx)?),
                (_, wire_type) => skip_field(input, &mut idx, wire_type)?,
            }
        }
        Ok(message)
    }
}

impl PeerInfo {
    /// Encodes the PeerInfo message body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(peer_id) = &self.peer_id {
            encode_bytes_field(&mut out, 1, peer_id);
        }
        if let Some(record) = &self.signed_peer_record {
            encode_bytes_field(&mut out, 2, record);
        }
        out
    }

    /// Decodes a PeerInfo message body.
    pub fn decode(input: &[u8]) -> Result<Self, PubsubWireError> {
        let mut peer = Self::default();
        let mut idx = 0;
        while let Some((field, wire_type)) = read_tag(input, &mut idx)? {
            match (field, wire_type) {
                (1, WIRE_LEN) => {
                    peer.peer_id = Some(read_len_delimited(input, &mut idx)?.to_vec());
                }
                (2, WIRE_LEN) => {
                    peer.signed_peer_record = Some(read_len_delimited(input, &mut idx)?.to_vec());
                }
                (_, wire_type) => skip_field(input, &mut idx, wire_type)?,
            }
        }
        Ok(peer)
    }
}

impl Rpc {
    /// Encodes the RPC body (without length prefix).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for sub in &self.subscriptions {
            encode_nested_field(&mut out, 1, &sub.encode());
        }
        for message in &self.publish {
            encode_nested_field(&mut out, 2, &message.to_wire());
        }
        if let Some(control) = &self.control {
            encode_nested_field(&mut out, 3, &control.encode());
        }
        out
    }

    /// Decodes an RPC body.
    pub fn decode(input: &[u8]) -> Result<Self, PubsubWireError> {
        Self::decode_inner(input, true)
    }

    /// Decodes the floodsub fields of an RPC while treating meshsub control
    /// as an opaque length-delimited extension. Floodsub never consumes
    /// field 3, so parsing its nested lists would only allocate attacker-
    /// controlled state that the router immediately discards.
    pub(crate) fn decode_floodsub(input: &[u8]) -> Result<Self, PubsubWireError> {
        Self::decode_inner(input, false)
    }

    fn decode_inner(input: &[u8], decode_control: bool) -> Result<Self, PubsubWireError> {
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
                (3, WIRE_LEN) => {
                    let nested = read_len_delimited(input, &mut idx)?;
                    if decode_control {
                        rpc.control
                            .get_or_insert_with(ControlMessage::default)
                            .merge_from(nested)?;
                    }
                }
                (_, wire_type) => skip_field(input, &mut idx, wire_type)?,
            }
        }
        Ok(rpc)
    }
}

// ---------------------------------------------------------------------------
// Field-number policy
// ---------------------------------------------------------------------------

/// Reads the next `(field_number, wire_type)` pair and rejects field 0.
///
/// Shared [`minip2p_core::read_tag`] does not enforce field-number policy.
/// Pubsub matches upstream by refusing field 0 rather than skipping it.
fn read_tag(input: &[u8], idx: &mut usize) -> Result<Option<(u64, u8)>, PubsubWireError> {
    let offset = *idx;
    match minip2p_core::read_tag(input, idx)? {
        Some((0, _)) => Err(PubsubWireError::InvalidFieldNumber { offset }),
        other => Ok(other),
    }
}

// ---------------------------------------------------------------------------
// Length-prefixed framing
// ---------------------------------------------------------------------------

pub use minip2p_core::FrameDecode;

/// Attempts to decode one varint-length-prefixed frame from `input`.
///
/// Returns `Incomplete` while bytes are missing. A declared length greater
/// than [`MAX_RPC_SIZE`] is rejected with [`FrameDecode::TooLarge`] before
/// any buffering, so callers never buffer toward a frame that can never
/// legally complete.
pub fn decode_frame(input: &[u8]) -> FrameDecode<'_> {
    minip2p_core::decode_frame(input, MAX_RPC_SIZE)
}

/// Encodes `payload` with a varint length prefix.
///
/// Callers keep payloads within [`MAX_RPC_SIZE`] — receivers reject larger
/// frames unread. The agent's outbound paths are all bounded (publish and
/// snapshot sizes are validated; forwards re-wrap an accepted inbound
/// frame), so an oversized frame here is a caller bug.
pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    debug_assert!(
        payload.len() <= MAX_RPC_SIZE,
        "frame payload exceeds MAX_RPC_SIZE"
    );
    minip2p_core::encode_frame(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use minip2p_core::{tag_byte, write_uvarint};

    fn keypair() -> Ed25519Keypair {
        Ed25519Keypair::from_secret_key_bytes([7u8; 32])
    }

    fn other_keypair() -> Ed25519Keypair {
        Ed25519Keypair::from_secret_key_bytes([9u8; 32])
    }

    fn tag(field: u8, wire: u8) -> u8 {
        tag_byte(field, wire).expect("test field numbers fit in one byte")
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
            control: None,
        };
        assert_eq!(Rpc::decode(&rpc.encode()).unwrap(), rpc);
    }

    #[test]
    fn signed_message_round_trips_with_raw_preserved() {
        let message = RawMessage::build_signed(&keypair(), "chat", b"hello".to_vec(), 42);
        let rpc = Rpc {
            subscriptions: Vec::new(),
            publish: vec![message.clone()],
            control: None,
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
    fn control_golden_vector_matches_hand_encoding() {
        let expected: &[u8] = &[
            0x1a, 0x27, // RPC.control: 39-byte ControlMessage
            0x0a, 0x0a, // ihave: 10-byte ControlIHave
            0x0a, 0x01, b't', // topic_id = "t"
            0x12, 0x02, 0xaa, 0xbb, // message_ids[0]
            0x12, 0x01, 0xff, // message_ids[1] (arbitrary non-UTF-8 bytes)
            0x12, 0x04, // iwant: 4-byte ControlIWant
            0x0a, 0x02, 0x01, 0x02, // message_ids[0]
            0x1a, 0x03, // graft: 3-byte ControlGraft
            0x0a, 0x01, b't', // topic_id = "t"
            0x22, 0x0e, // prune: 14-byte ControlPrune
            0x0a, 0x01, b't', // topic_id = "t"
            0x12, 0x07, // peers: 7-byte PeerInfo
            0x0a, 0x02, 0x01, 0x02, // peer_id
            0x12, 0x01, 0x03, // signed_peer_record
            0x18, 0x3c, // backoff = 60
        ];
        let control = ControlMessage {
            ihave: vec![ControlIHave {
                topic_id: Some(String::from("t")),
                message_ids: vec![vec![0xaa, 0xbb], vec![0xff]],
            }],
            iwant: vec![ControlIWant {
                message_ids: vec![vec![1, 2]],
            }],
            graft: vec![ControlGraft {
                topic_id: Some(String::from("t")),
            }],
            prune: vec![ControlPrune {
                topic_id: Some(String::from("t")),
                peers: vec![PeerInfo {
                    peer_id: Some(vec![1, 2]),
                    signed_peer_record: Some(vec![3]),
                }],
                backoff: Some(60),
            }],
        };
        let rpc = Rpc {
            subscriptions: Vec::new(),
            publish: Vec::new(),
            control: Some(control.clone()),
        };
        assert_eq!(rpc.encode(), expected);
        assert_eq!(Rpc::decode(expected).unwrap().control, Some(control));
    }

    #[test]
    fn repeated_rpc_control_fields_merge() {
        let first = ControlMessage {
            graft: vec![ControlGraft {
                topic_id: Some(String::from("a")),
            }],
            ..ControlMessage::default()
        };
        let second = ControlMessage {
            prune: vec![ControlPrune {
                topic_id: Some(String::from("b")),
                backoff: Some(30),
                ..ControlPrune::default()
            }],
            ..ControlMessage::default()
        };
        let mut encoded = Vec::new();
        encode_nested_field(&mut encoded, 3, &first.encode());
        encode_nested_field(&mut encoded, 3, &second.encode());

        let merged = Rpc::decode(&encoded).unwrap().control.unwrap();
        assert_eq!(merged.graft, first.graft);
        assert_eq!(merged.prune, second.prune);
        let reencoded = Rpc {
            control: Some(merged),
            ..Rpc::default()
        }
        .encode();
        assert_eq!(reencoded.first(), Some(&tag(3, WIRE_LEN)));
        assert_eq!(
            Rpc::decode(&reencoded)
                .unwrap()
                .control
                .unwrap()
                .graft
                .len(),
            1
        );
    }

    #[test]
    fn malformed_and_unknown_control_fields_follow_codec_rules() {
        // Control messages share field-0 policy and still skip unknown tags.
        let field_zero = [0x00, 0x01];
        assert!(matches!(
            ControlMessage::decode(&field_zero),
            Err(PubsubWireError::InvalidFieldNumber { offset: 0 })
        ));

        let mut with_unknown = ControlGraft {
            topic_id: Some(String::from("t")),
        }
        .encode();
        with_unknown.extend_from_slice(&[tag(15, WIRE_LEN), 1, 0xff]);
        assert_eq!(
            ControlGraft::decode(&with_unknown)
                .unwrap()
                .topic_id
                .as_deref(),
            Some("t")
        );
    }

    #[test]
    fn floodsub_decode_skips_control_without_parsing_it() {
        // The nested field-zero tag is malformed protobuf. The shared
        // meshsub-aware decoder rejects it, while floodsub treats the whole
        // control body as an opaque extension and still decodes later fields.
        let mut encoded = Vec::new();
        encode_nested_field(&mut encoded, 3, &[0x00, 0x01]);
        encode_nested_field(
            &mut encoded,
            1,
            &SubOpts {
                subscribe: Some(true),
                topic_id: Some(String::from("t")),
            }
            .encode(),
        );

        assert!(matches!(
            Rpc::decode(&encoded),
            Err(PubsubWireError::InvalidFieldNumber { .. })
        ));
        let floodsub = Rpc::decode_floodsub(&encoded).unwrap();
        assert_eq!(floodsub.control, None);
        assert_eq!(floodsub.subscriptions.len(), 1);
        assert_eq!(floodsub.subscriptions[0].topic_id.as_deref(), Some("t"));
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
            control: None,
        };
        assert_eq!(rpc.encode(), expected);
        let decoded = Rpc::decode(expected).unwrap();
        assert_eq!(decoded.subscriptions, rpc.subscriptions);
        assert_eq!(decoded.publish[0].from, rpc.publish[0].from);
        assert_eq!(decoded.publish[0].seqno, rpc.publish[0].seqno);
    }

    #[test]
    fn invalid_utf8_topic_errors() {
        let encoded = [tag(4, WIRE_LEN), 2, 0xff, 0xfe];
        assert!(matches!(
            RawMessage::decode(&encoded),
            Err(PubsubWireError::Wire(WireError::InvalidUtf8 { .. }))
        ));
    }

    #[test]
    fn field_number_zero_is_rejected() {
        // Tag 0x00 = field 0, wire type varint: protobuf-illegal; upstream
        // decoders error rather than skip.
        let encoded = [0x00, 0x01];
        assert!(matches!(
            RawMessage::decode(&encoded),
            Err(PubsubWireError::InvalidFieldNumber { offset: 0 })
        ));
        assert!(matches!(
            SubOpts::decode(&encoded),
            Err(PubsubWireError::InvalidFieldNumber { offset: 0 })
        ));
        assert!(matches!(
            Rpc::decode(&encoded),
            Err(PubsubWireError::InvalidFieldNumber { offset: 0 })
        ));
    }

    // -- framing -------------------------------------------------------------

    /// Wrapper binds [`MAX_RPC_SIZE`]; generic framing goldens live in
    /// `minip2p_core::frame`.
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
        let (from, seqno, signed) = message.verify(false).expect("verify");
        assert_eq!(from, kp.peer_id());
        assert_eq!(seqno, 42u64.to_be_bytes().to_vec());
        assert!(signed);
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
        message.verify(false).expect("matching key field verifies");

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
        message.verify(false).expect("inline key verifies");
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
        let (from, seqno, signed) = unsigned.verify(true).expect("allow_unsigned accepts");
        assert_eq!(from, kp.peer_id());
        assert_eq!(seqno, 9u64.to_be_bytes().to_vec());
        assert!(!signed);

        // Seqno length is implementation-defined: rust-libp2p floodsub
        // emits 20 random bytes. Anything 1..=64 is accepted.
        let mut rust_seqno = unsigned.clone();
        rust_seqno.seqno = Some(vec![7; 20]);
        rust_seqno.verify(true).expect("20-byte seqno verifies");

        // Even unsigned, the dedup id fields stay mandatory and bounded.
        let mut no_from = unsigned.clone();
        no_from.from = None;
        assert_eq!(no_from.verify(true), Err(MessageVerifyError::MissingFrom));
        let mut empty_seqno = unsigned.clone();
        empty_seqno.seqno = Some(Vec::new());
        assert_eq!(
            empty_seqno.verify(true),
            Err(MessageVerifyError::InvalidSeqno)
        );
        let mut huge_seqno = unsigned.clone();
        huge_seqno.seqno = Some(vec![0; MAX_SEQNO_LEN + 1]);
        assert_eq!(
            huge_seqno.verify(true),
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
        wire.extend_from_slice(&[tag(12, WIRE_LEN), 2, 0xca, 0xfe]);

        let decoded = RawMessage::decode(&wire).unwrap();
        assert_eq!(decoded.raw, wire, "raw keeps the original bytes");
        assert!(
            decoded.verify(false).is_ok(),
            "unknown fields are not part of the canonical sign bytes"
        );
        assert_eq!(decoded.to_wire(), wire, "forwarding embeds raw verbatim");
    }
}
