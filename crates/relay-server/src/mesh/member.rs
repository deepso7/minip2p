//! The member protocol ([`MEMBER_PROTOCOL_ID`]): how two mesh nodes show
//! each other that the relay's public identity vouches for their backbone
//! keys (ADR 0028).
//!
//! Every node holds the public identity's secret key, so at startup it signs
//! [`member_proof_message`] for its own backbone peer id. On each new
//! backbone connection both sides open a member stream, send that 64-byte
//! signature and half-close. The receiver checks it against the public key
//! and the connection's remote peer id (authenticated by the transport's
//! handshake), answers [`MEMBER_ACCEPT`] and half-closes. Each message is
//! judged only at its sender's half-close, so a short or long one is a
//! rejection; [`MemberReader`] buffers it in a fixed buffer.

use alloc::vec::Vec;

use minip2p_core::PeerId;
use minip2p_identity::{Ed25519Keypair, PublicKey};

/// The member protocol, opened by both sides of every backbone connection.
pub const MEMBER_PROTOCOL_ID: &str = "/minip2p/relay-mesh/member/1.0.0";

/// A member proof's length: one Ed25519 signature.
pub const MEMBER_PROOF_LEN: usize = 64;

/// The receiver's whole answer to a valid proof.
pub const MEMBER_ACCEPT: u8 = 0x01;

/// How long a new backbone connection may stay unverified before it is
/// closed, in milliseconds.
pub const MEMBER_PROOF_TIMEOUT_MS: u64 = 5_000;

const PROOF_DOMAIN: &[u8] = b"minip2p relay mesh member v1";

/// What the public identity signs for `backbone`: a domain string, then the
/// backbone peer id's bytes. Shared by signing and verification.
pub fn member_proof_message(backbone: &PeerId) -> Vec<u8> {
    let mut message = PROOF_DOMAIN.to_vec();
    message.extend_from_slice(&backbone.to_bytes());
    message
}

/// Signs the member proof for `backbone` with the public identity.
pub fn sign_member_proof(public: &Ed25519Keypair, backbone: &PeerId) -> [u8; MEMBER_PROOF_LEN] {
    public.sign(&member_proof_message(backbone))
}

/// Whether `proof` is `public_key`'s signature for `backbone`.
pub fn verify_member_proof(
    public_key: &PublicKey,
    backbone: &PeerId,
    proof: &[u8; MEMBER_PROOF_LEN],
) -> bool {
    public_key
        .verify(&member_proof_message(backbone), proof)
        .is_ok()
}

/// Why a member message was malformed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MemberMessageError {
    /// More bytes arrived than the message holds.
    #[error("more bytes than the message holds")]
    TooLong,
    /// The sender half-closed before the whole message arrived.
    #[error("ended before the whole message arrived")]
    TooShort,
}

/// Buffers one fixed-size member message (a proof, or an accept) until its
/// sender half-closes. The buffer never grows past the proof's length,
/// however much an unverified peer sends: bytes past the message only mark
/// it too long, judged at the half-close like a short one.
#[derive(Clone, Debug)]
pub struct MemberReader {
    buf: [u8; MEMBER_PROOF_LEN],
    len: usize,
    expected: usize,
    too_long: bool,
}

impl MemberReader {
    /// A reader for a peer's [`MEMBER_PROOF_LEN`]-byte proof.
    pub const fn proof() -> Self {
        Self::exactly(MEMBER_PROOF_LEN)
    }

    /// A reader for the one-byte answer to this node's proof.
    pub const fn accept() -> Self {
        Self::exactly(1)
    }

    const fn exactly(expected: usize) -> Self {
        Self {
            buf: [0; MEMBER_PROOF_LEN],
            len: 0,
            expected,
            too_long: false,
        }
    }

    /// Takes one read. Bytes past the message are dropped and make
    /// [`finish`](Self::finish) fail.
    pub fn push(&mut self, data: &[u8]) {
        let end = self.len.saturating_add(data.len());
        match self.buf.get_mut(self.len..end) {
            Some(slot) if end <= self.expected => {
                slot.copy_from_slice(data);
                self.len = end;
            }
            _ => self.too_long = true,
        }
    }

    /// The whole message, at the sender's half-close.
    pub fn finish(&self) -> Result<&[u8], MemberMessageError> {
        if self.too_long {
            return Err(MemberMessageError::TooLong);
        }
        if self.len < self.expected {
            return Err(MemberMessageError::TooShort);
        }
        self.buf.get(..self.len).ok_or(MemberMessageError::TooShort)
    }

    /// The whole proof, at the sender's half-close.
    pub fn finish_proof(&self) -> Result<[u8; MEMBER_PROOF_LEN], MemberMessageError> {
        self.finish()?
            .try_into()
            .map_err(|_wrong_length| MemberMessageError::TooShort)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair(seed: u8) -> Ed25519Keypair {
        Ed25519Keypair::from_secret_key_bytes([seed; 32])
    }

    #[test]
    fn a_proof_verifies_only_for_its_backbone_and_public_key() {
        let (public, other) = (keypair(1), keypair(2));
        let (backbone, stranger) = (keypair(3).peer_id(), keypair(4).peer_id());
        let proof = sign_member_proof(&public, &backbone);
        assert!(verify_member_proof(&public.public_key(), &backbone, &proof));
        assert!(!verify_member_proof(
            &public.public_key(),
            &stranger,
            &proof
        ));
        assert!(!verify_member_proof(&other.public_key(), &backbone, &proof));
    }

    #[test]
    fn a_reader_takes_split_reads_and_rejects_short_or_long_messages() {
        let mut reader = MemberReader::proof();
        reader.push(&[7; 10]);
        assert_eq!(reader.finish(), Err(MemberMessageError::TooShort));
        reader.push(&[7; 54]);
        assert_eq!(reader.finish_proof(), Ok([7; MEMBER_PROOF_LEN]));
        reader.push(&[7]);
        assert_eq!(reader.finish(), Err(MemberMessageError::TooLong));

        let mut accept = MemberReader::accept();
        assert_eq!(accept.finish(), Err(MemberMessageError::TooShort));
        accept.push(&[MEMBER_ACCEPT]);
        assert_eq!(accept.finish(), Ok(&[MEMBER_ACCEPT][..]));
        accept.push(&[0]);
        assert_eq!(accept.finish(), Err(MemberMessageError::TooLong));
    }
}
