//! Sans-I/O implementation of the libp2p Noise security protocol.
//!
//! The crate implements `Noise_XX_25519_ChaChaPoly_SHA256` with libp2p's
//! identity-key payload and two-byte big-endian message framing. It performs
//! end-to-end identity verification and exposes encrypted transport bytes as a
//! caller-driven [`SansIoProtocol`] state machine.
//!
//! Randomness deliberately lives outside this crate: callers must provide
//! fresh X25519 static and ephemeral secret bytes for each [`NoiseSession`].

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

extern crate alloc;

mod cipher;
mod frames;
mod handshake;
mod hkdf;
mod payload;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;

use cipher::CipherState;
use handshake::{HandshakeResult, HandshakeState};
use minip2p_core::SansIoProtocol;
use minip2p_identity::{Ed25519Keypair, PeerId, PublicKey};
use thiserror::Error;

pub use frames::{FrameDecoder, MAX_FRAME_LEN, encode_frame};
pub use payload::NoiseHandshakePayload;

/// Multistream-select protocol identifier for libp2p Noise.
pub const NOISE_PROTOCOL_ID: &str = "/noise";

/// Largest plaintext carried by one encrypted transport frame.
pub const MAX_TRANSPORT_PLAINTEXT: usize = MAX_FRAME_LEN - 16;

/// Role of this side in the Noise XX handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoiseRole {
    /// Opens the secure channel and sends handshake messages one and three.
    Initiator,
    /// Accepts the secure channel and sends handshake message two.
    Responder,
}

/// Immutable inputs used to create one Noise session.
#[derive(Clone)]
pub struct NoiseConfig {
    /// Handshake role for this side.
    pub role: NoiseRole,
    /// Long-term libp2p Ed25519 identity used to authenticate the Noise static key.
    pub identity: Ed25519Keypair,
    /// Fresh X25519 static secret for this session.
    pub static_secret: [u8; 32],
    /// Fresh X25519 ephemeral secret for this session.
    pub ephemeral_secret: [u8; 32],
    /// Required remote identity, when the caller already knows its peer ID.
    pub expected_peer: Option<PeerId>,
}

impl fmt::Debug for NoiseConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NoiseConfig")
            .field("role", &self.role)
            .field("identity", &self.identity)
            .field("static_secret", &"<redacted>")
            .field("ephemeral_secret", &"<redacted>")
            .field("expected_peer", &self.expected_peer)
            .finish()
    }
}

/// Input accepted by [`NoiseSession`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NoiseInput {
    /// Starts the handshake. The initiator emits message one; the responder waits.
    Start,
    /// Bytes received from the underlying ordered stream.
    Data(Vec<u8>),
    /// Plaintext to encrypt after the handshake completes.
    Encrypt(Vec<u8>),
}

/// Output produced by [`NoiseSession`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NoiseOutput {
    /// Framed bytes that the caller must write to the underlying stream.
    Outbound(Vec<u8>),
    /// The secure handshake completed and authenticated the remote identity.
    HandshakeComplete {
        /// Cryptographically verified remote peer ID.
        peer: PeerId,
        /// Identity key from the verified libp2p Noise payload.
        identity_key: PublicKey,
    },
    /// One decrypted transport message.
    Decrypted(Vec<u8>),
}

/// Errors returned by the Noise frame, handshake, and transport state machine.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NoiseError {
    /// A framed message cannot fit in the two-byte libp2p length prefix.
    #[error("Noise frame is too large: {len} bytes")]
    FrameTooLarge {
        /// Attempted payload length.
        len: usize,
    },
    /// The state machine has already been started.
    #[error("Noise session has already been started")]
    AlreadyStarted,
    /// An input cannot be handled in the session's current phase.
    #[error("invalid Noise input: {0}")]
    InvalidInput(&'static str),
    /// The session reached an internally inconsistent state.
    #[error("invalid Noise state: {0}")]
    InvalidState(&'static str),
    /// A handshake message arrived in the wrong order.
    #[error("unexpected Noise handshake message")]
    UnexpectedHandshakeMessage,
    /// A handshake message had an invalid shape.
    #[error("invalid Noise handshake message: {0}")]
    InvalidHandshakeMessage(&'static str),
    /// The libp2p handshake payload was malformed.
    #[error("invalid libp2p Noise payload: {0}")]
    InvalidPayload(&'static str),
    /// The payload's encoded libp2p identity key was invalid.
    #[error("invalid identity key in Noise payload")]
    InvalidIdentityKey,
    /// The signature binding the identity key to the Noise static key failed.
    #[error("invalid identity signature in Noise payload")]
    InvalidIdentitySignature,
    /// The verified identity did not equal the peer expected by the caller.
    #[error("Noise peer identity does not match the expected peer")]
    IdentityMismatch,
    /// X25519 produced the all-zero shared secret for a low-order remote point.
    #[error("non-contributory X25519 shared secret")]
    NonContributory,
    /// ChaCha20-Poly1305 encryption failed.
    #[error("Noise encryption failed")]
    Encryption,
    /// ChaCha20-Poly1305 authentication or decryption failed.
    #[error("Noise decryption failed")]
    Decryption,
    /// A Noise cipher nonce reached its terminal value.
    #[error("Noise cipher nonce exhausted")]
    NonceExhausted,
    /// The session previously failed and cannot process more input.
    #[error("Noise session has failed")]
    Failed,
}

impl NoiseError {
    fn is_terminal(&self) -> bool {
        !matches!(self, Self::AlreadyStarted | Self::InvalidInput(_))
    }
}

/// Caller-driven libp2p Noise XX handshake and transport cipher.
///
/// Protocol and cryptographic errors permanently fail the session and discard
/// queued output. Caller-misuse errors ([`NoiseError::AlreadyStarted`] and
/// [`NoiseError::InvalidInput`]) leave both the session and its output intact.
pub struct NoiseSession {
    handshake: Option<HandshakeState>,
    send_cipher: Option<CipherState>,
    receive_cipher: Option<CipherState>,
    decoder: FrameDecoder,
    pending: VecDeque<NoiseOutput>,
    started: bool,
    failed: bool,
}

impl NoiseSession {
    /// Creates a session from caller-supplied identity and fresh X25519 secrets.
    pub fn new(config: NoiseConfig) -> Self {
        Self {
            handshake: Some(HandshakeState::new(
                config.role,
                config.identity,
                config.static_secret,
                config.ephemeral_secret,
                config.expected_peer,
            )),
            send_cipher: None,
            receive_cipher: None,
            decoder: FrameDecoder::new(),
            pending: VecDeque::new(),
            started: false,
            failed: false,
        }
    }

    /// Returns whether the authenticated handshake has completed.
    pub fn is_handshake_complete(&self) -> bool {
        self.send_cipher.is_some() && self.receive_cipher.is_some()
    }

    fn start(&mut self) -> Result<(), NoiseError> {
        if self.started {
            return Err(NoiseError::AlreadyStarted);
        }
        self.started = true;
        let outbound = self
            .handshake
            .as_mut()
            .ok_or(NoiseError::InvalidState("handshake is unavailable"))?
            .start()?;
        if let Some(message) = outbound {
            self.pending
                .push_back(NoiseOutput::Outbound(encode_frame(&message)?));
        }
        Ok(())
    }

    fn receive(&mut self, bytes: &[u8]) -> Result<(), NoiseError> {
        if !self.started {
            return Err(NoiseError::InvalidInput("session has not been started"));
        }
        self.decoder.push(bytes);
        while let Some(message) = self.decoder.next_frame() {
            if self.is_handshake_complete() {
                let plaintext = self
                    .receive_cipher
                    .as_mut()
                    .ok_or(NoiseError::InvalidState("receive cipher is unavailable"))?
                    .decrypt_with_ad(b"", &message)?;
                self.pending.push_back(NoiseOutput::Decrypted(plaintext));
                continue;
            }

            let (outbound, complete) = self
                .handshake
                .as_mut()
                .ok_or(NoiseError::InvalidState("handshake is unavailable"))?
                .read_message(&message)?;
            if let Some(outbound) = outbound {
                self.pending
                    .push_back(NoiseOutput::Outbound(encode_frame(&outbound)?));
            }
            if let Some(result) = complete {
                self.complete_handshake(result);
            }
        }
        Ok(())
    }

    fn complete_handshake(&mut self, result: HandshakeResult) {
        self.send_cipher = Some(result.send);
        self.receive_cipher = Some(result.receive);
        self.handshake = None;
        self.pending.push_back(NoiseOutput::HandshakeComplete {
            peer: result.peer,
            identity_key: result.identity_key,
        });
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<(), NoiseError> {
        let cipher = self
            .send_cipher
            .as_mut()
            .ok_or(NoiseError::InvalidInput("handshake is not complete"))?;
        if plaintext.is_empty() {
            let ciphertext = cipher.encrypt_with_ad(b"", plaintext)?;
            self.pending
                .push_back(NoiseOutput::Outbound(encode_frame(&ciphertext)?));
            return Ok(());
        }
        for segment in plaintext.chunks(MAX_TRANSPORT_PLAINTEXT) {
            let ciphertext = cipher.encrypt_with_ad(b"", segment)?;
            self.pending
                .push_back(NoiseOutput::Outbound(encode_frame(&ciphertext)?));
        }
        Ok(())
    }
}

impl SansIoProtocol for NoiseSession {
    type Input = NoiseInput;
    type Output = NoiseOutput;
    type Error = NoiseError;

    fn handle_input(&mut self, input: Self::Input) -> Result<(), Self::Error> {
        if self.failed {
            return Err(NoiseError::Failed);
        }
        let result = match input {
            NoiseInput::Start => self.start(),
            NoiseInput::Data(bytes) => self.receive(&bytes),
            NoiseInput::Encrypt(plaintext) => self.encrypt(&plaintext),
        };
        if result.as_ref().is_err_and(NoiseError::is_terminal) {
            self.failed = true;
            self.pending.clear();
        }
        result
    }

    fn poll_output(&mut self) -> Option<Self::Output> {
        self.pending.pop_front()
    }

    fn is_idle(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Pair {
        initiator: NoiseSession,
        responder: NoiseSession,
        initiator_peer: PeerId,
        responder_peer: PeerId,
    }

    impl Pair {
        fn new() -> Self {
            let initiator_identity = Ed25519Keypair::from_secret_key_bytes([1; 32]);
            let responder_identity = Ed25519Keypair::from_secret_key_bytes([2; 32]);
            let initiator_peer = initiator_identity.peer_id();
            let responder_peer = responder_identity.peer_id();
            Self {
                initiator: NoiseSession::new(NoiseConfig {
                    role: NoiseRole::Initiator,
                    identity: initiator_identity,
                    static_secret: [3; 32],
                    ephemeral_secret: [4; 32],
                    expected_peer: Some(responder_peer.clone()),
                }),
                responder: NoiseSession::new(NoiseConfig {
                    role: NoiseRole::Responder,
                    identity: responder_identity,
                    static_secret: [5; 32],
                    ephemeral_secret: [6; 32],
                    expected_peer: Some(initiator_peer.clone()),
                }),
                initiator_peer,
                responder_peer,
            }
        }

        fn handshake(&mut self) {
            self.initiator.handle_input(NoiseInput::Start).unwrap();
            self.responder.handle_input(NoiseInput::Start).unwrap();

            let message1 = outbound(&mut self.initiator);
            self.responder
                .handle_input(NoiseInput::Data(message1))
                .unwrap();
            let message2 = outbound(&mut self.responder);
            self.initiator
                .handle_input(NoiseInput::Data(message2))
                .unwrap();
            let message3 = outbound(&mut self.initiator);
            assert_eq!(handshake_peer(&mut self.initiator), self.responder_peer);
            self.responder
                .handle_input(NoiseInput::Data(message3))
                .unwrap();
            assert_eq!(handshake_peer(&mut self.responder), self.initiator_peer);
        }
    }

    fn outbound(session: &mut NoiseSession) -> Vec<u8> {
        match session.poll_output().expect("outbound data") {
            NoiseOutput::Outbound(data) => data,
            other => panic!("expected outbound data, got {other:?}"),
        }
    }

    fn handshake_peer(session: &mut NoiseSession) -> PeerId {
        match session.poll_output().expect("handshake completion") {
            NoiseOutput::HandshakeComplete { peer, .. } => peer,
            other => panic!("expected handshake completion, got {other:?}"),
        }
    }

    #[test]
    fn xx_round_trip_both_directions() {
        let mut pair = Pair::new();
        pair.handshake();

        pair.initiator
            .handle_input(NoiseInput::Encrypt(b"hello responder".to_vec()))
            .unwrap();
        pair.responder
            .handle_input(NoiseInput::Data(outbound(&mut pair.initiator)))
            .unwrap();
        assert_eq!(
            pair.responder.poll_output(),
            Some(NoiseOutput::Decrypted(b"hello responder".to_vec()))
        );

        pair.responder
            .handle_input(NoiseInput::Encrypt(b"hello initiator".to_vec()))
            .unwrap();
        pair.initiator
            .handle_input(NoiseInput::Data(outbound(&mut pair.responder)))
            .unwrap();
        assert_eq!(
            pair.initiator.poll_output(),
            Some(NoiseOutput::Decrypted(b"hello initiator".to_vec()))
        );
    }

    #[test]
    fn caller_misuse_preserves_pending_output_and_session_usability() {
        let mut pair = Pair::new();

        assert_eq!(
            pair.initiator
                .handle_input(NoiseInput::Encrypt(b"too early".to_vec())),
            Err(NoiseError::InvalidInput("handshake is not complete"))
        );
        assert_eq!(
            pair.responder.handle_input(NoiseInput::Data(Vec::new())),
            Err(NoiseError::InvalidInput("session has not been started"))
        );

        pair.initiator.handle_input(NoiseInput::Start).unwrap();
        assert_eq!(
            pair.initiator.handle_input(NoiseInput::Start),
            Err(NoiseError::AlreadyStarted)
        );
        let message1 = outbound(&mut pair.initiator);

        pair.responder.handle_input(NoiseInput::Start).unwrap();
        pair.responder
            .handle_input(NoiseInput::Data(message1))
            .unwrap();
        let message2 = outbound(&mut pair.responder);
        pair.initiator
            .handle_input(NoiseInput::Data(message2))
            .unwrap();
        let message3 = outbound(&mut pair.initiator);
        assert_eq!(handshake_peer(&mut pair.initiator), pair.responder_peer);
        pair.responder
            .handle_input(NoiseInput::Data(message3))
            .unwrap();
        assert_eq!(handshake_peer(&mut pair.responder), pair.initiator_peer);
    }

    #[test]
    fn accepts_one_byte_drip_fragmentation() {
        let mut pair = Pair::new();
        pair.initiator.handle_input(NoiseInput::Start).unwrap();
        pair.responder.handle_input(NoiseInput::Start).unwrap();
        let message1 = outbound(&mut pair.initiator);
        for byte in message1 {
            pair.responder
                .handle_input(NoiseInput::Data(alloc::vec![byte]))
                .unwrap();
        }
        let message2 = outbound(&mut pair.responder);
        for byte in message2 {
            pair.initiator
                .handle_input(NoiseInput::Data(alloc::vec![byte]))
                .unwrap();
        }
        let message3 = outbound(&mut pair.initiator);
        let _ = handshake_peer(&mut pair.initiator);
        for byte in message3 {
            pair.responder
                .handle_input(NoiseInput::Data(alloc::vec![byte]))
                .unwrap();
        }
        let _ = handshake_peer(&mut pair.responder);
    }

    #[test]
    fn rejects_expected_identity_mismatch() {
        let mut pair = Pair::new();
        pair.initiator.handshake = Some(HandshakeState::new(
            NoiseRole::Initiator,
            Ed25519Keypair::from_secret_key_bytes([1; 32]),
            [3; 32],
            [4; 32],
            Some(Ed25519Keypair::from_secret_key_bytes([99; 32]).peer_id()),
        ));
        pair.initiator.handle_input(NoiseInput::Start).unwrap();
        pair.responder.handle_input(NoiseInput::Start).unwrap();
        let message1 = outbound(&mut pair.initiator);
        pair.responder
            .handle_input(NoiseInput::Data(message1))
            .unwrap();
        let message2 = outbound(&mut pair.responder);
        assert_eq!(
            pair.initiator.handle_input(NoiseInput::Data(message2)),
            Err(NoiseError::IdentityMismatch)
        );
        assert!(pair.initiator.poll_output().is_none());
    }

    #[test]
    fn rejects_non_contributory_remote_key() {
        let mut responder = Pair::new().responder;
        responder.handle_input(NoiseInput::Start).unwrap();
        let zero_message = encode_frame(&[0; 32]).unwrap();
        assert_eq!(
            responder.handle_input(NoiseInput::Data(zero_message)),
            Err(NoiseError::NonContributory)
        );
        assert!(responder.poll_output().is_none());
        assert_eq!(
            responder.handle_input(NoiseInput::Start),
            Err(NoiseError::Failed)
        );
    }

    #[test]
    fn segments_transport_plaintext_at_wire_limit() {
        let mut pair = Pair::new();
        pair.handshake();
        let plaintext = alloc::vec![9; MAX_TRANSPORT_PLAINTEXT + 1];
        pair.initiator
            .handle_input(NoiseInput::Encrypt(plaintext.clone()))
            .unwrap();
        let first = outbound(&mut pair.initiator);
        let second = outbound(&mut pair.initiator);
        assert_eq!(
            u16::from_be_bytes([first[0], first[1]]) as usize,
            MAX_FRAME_LEN
        );
        pair.responder
            .handle_input(NoiseInput::Data(first))
            .unwrap();
        pair.responder
            .handle_input(NoiseInput::Data(second))
            .unwrap();
        assert_eq!(
            pair.responder.poll_output(),
            Some(NoiseOutput::Decrypted(
                plaintext[..MAX_TRANSPORT_PLAINTEXT].to_vec()
            ))
        );
        assert_eq!(
            pair.responder.poll_output(),
            Some(NoiseOutput::Decrypted(
                plaintext[MAX_TRANSPORT_PLAINTEXT..].to_vec()
            ))
        );
    }

    #[test]
    fn maximum_transport_plaintext_uses_one_frame() {
        let mut pair = Pair::new();
        pair.handshake();
        let plaintext = alloc::vec![8; MAX_TRANSPORT_PLAINTEXT];
        pair.initiator
            .handle_input(NoiseInput::Encrypt(plaintext.clone()))
            .unwrap();
        let frame = outbound(&mut pair.initiator);
        assert_eq!(
            u16::from_be_bytes([frame[0], frame[1]]) as usize,
            MAX_FRAME_LEN
        );
        assert!(pair.initiator.poll_output().is_none());
        pair.responder
            .handle_input(NoiseInput::Data(frame))
            .unwrap();
        assert_eq!(
            pair.responder.poll_output(),
            Some(NoiseOutput::Decrypted(plaintext))
        );
    }

    #[test]
    fn config_debug_redacts_x25519_secrets() {
        let config = NoiseConfig {
            role: NoiseRole::Initiator,
            identity: Ed25519Keypair::from_secret_key_bytes([1; 32]),
            static_secret: [0xaa; 32],
            ephemeral_secret: [0xbb; 32],
            expected_peer: None,
        };
        let debug = alloc::format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("170, 170"));
        assert!(!debug.contains("187, 187"));
    }
}
