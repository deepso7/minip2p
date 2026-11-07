//! Sans-I/O implementation of the libp2p Noise security protocol.
//!
//! This module implements `Noise_XX_25519_ChaChaPoly_SHA256` with libp2p's
//! identity-key payload and two-byte big-endian message framing. It performs
//! end-to-end identity verification and exposes encrypted transport bytes as a
//! caller-driven state machine: feed it through [`NoiseSession::start`],
//! [`NoiseSession::on_data`] and [`NoiseSession::encrypt`], then drain
//! [`NoiseSession::poll_output`] until it returns `None`.
//!
//! Randomness deliberately lives outside this module: callers must provide
//! fresh X25519 static and ephemeral secret bytes for each [`NoiseSession`].

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
use minip2p_identity::{Ed25519Keypair, PeerId, PublicKey};
use thiserror::Error;

pub(crate) use cipher::TAG_LEN;
pub use frames::{FrameDecoder, MAX_FRAME_LEN, encode_frame};
pub use payload::{NoiseExtensions, NoiseHandshakePayload};

/// Multistream-select protocol identifier for libp2p Noise.
pub const NOISE_PROTOCOL_ID: &str = "/noise";

/// Length of the big-endian length prefix before every Noise frame.
pub(crate) const FRAME_PREFIX_LEN: usize = 2;

/// Largest plaintext carried by one encrypted transport frame.
pub const MAX_TRANSPORT_PLAINTEXT: usize = MAX_FRAME_LEN - cipher::TAG_LEN;

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
    /// Extensions sent in this side's handshake payload. `None` sends none,
    /// keeping the payload byte-identical to a plain libp2p Noise handshake.
    pub local_extensions: Option<NoiseExtensions>,
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
            .field("local_extensions", &self.local_extensions)
            .finish()
    }
}

/// Output produced by [`NoiseSession::poll_output`].
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
        /// Extensions the remote sent in its verified payload, if any.
        remote_extensions: Option<NoiseExtensions>,
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
    /// Shared protobuf framing failed while decoding the handshake payload.
    #[error("invalid libp2p Noise payload: {0}")]
    Wire(#[from] minip2p_core::WireError),
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
    state: State,
    decoder: FrameDecoder,
    pending: VecDeque<NoiseOutput>,
}

/// Where a [`NoiseSession`] is in its life.
enum State {
    /// Created; `start` has not run.
    Idle(HandshakeState),
    /// Exchanging the XX handshake messages.
    Handshaking(HandshakeState),
    /// Handshake complete: frames are encrypted and decrypted.
    Transport {
        send: CipherState,
        receive: CipherState,
        handshake_hash: [u8; 32],
    },
    /// A terminal error ended the session.
    Failed,
}

impl NoiseSession {
    /// Creates a session from caller-supplied identity and fresh X25519 secrets.
    pub fn new(config: NoiseConfig) -> Self {
        Self {
            state: State::Idle(HandshakeState::new(
                config.role,
                config.identity,
                config.static_secret,
                config.ephemeral_secret,
                config.expected_peer,
                config.local_extensions,
            )),
            decoder: FrameDecoder::new(),
            pending: VecDeque::new(),
        }
    }

    /// Returns whether the authenticated handshake has completed and the
    /// session is still live: `false` once it has failed.
    pub fn is_handshake_complete(&self) -> bool {
        matches!(self.state, State::Transport { .. })
    }

    /// Returns the final Noise handshake hash once the handshake completes.
    ///
    /// Both ends compute the same value, so it names this session on either
    /// side (channel binding, in Noise terms). `None` once the session has
    /// failed.
    pub fn handshake_hash(&self) -> Option<[u8; 32]> {
        match self.state {
            State::Transport { handshake_hash, .. } => Some(handshake_hash),
            _ => None,
        }
    }

    /// Starts the handshake. The initiator queues message one; the responder
    /// waits for it.
    pub fn start(&mut self) -> Result<(), NoiseError> {
        let result = self.check_live().and_then(|()| self.begin_handshake());
        self.settle(result)
    }

    /// Feeds bytes received from the underlying ordered stream: handshake
    /// messages before completion, encrypted transport frames after.
    pub fn on_data(&mut self, bytes: Vec<u8>) -> Result<(), NoiseError> {
        let result = self.check_live().and_then(|()| self.receive(bytes));
        self.settle(result)
    }

    /// Frames and encrypts `plaintext` once the handshake has completed,
    /// queuing the frames as [`NoiseOutput::Outbound`].
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(), NoiseError> {
        let result = self
            .check_live()
            .and_then(|()| self.encrypt_frames(plaintext));
        self.settle(result)
    }

    /// [`encrypt`](Self::encrypt) for a plaintext that sits at
    /// `frame[FRAME_PREFIX_LEN..]`, with the head reserved for the length
    /// prefix. A plaintext that fits one transport frame is sealed in that
    /// buffer, which is queued as the frame: give it [`TAG_LEN`] bytes
    /// of spare capacity and nothing is allocated or copied. A larger one is
    /// split and copied as `encrypt` does.
    pub(crate) fn encrypt_in_place(&mut self, frame: Vec<u8>) -> Result<(), NoiseError> {
        let result = self.check_live().and_then(|()| {
            let plaintext_len = frame.len().saturating_sub(FRAME_PREFIX_LEN);
            if plaintext_len > MAX_TRANSPORT_PLAINTEXT {
                return self.encrypt_frames(frame.get(FRAME_PREFIX_LEN..).unwrap_or_default());
            }
            self.seal_frame(frame)
        });
        self.settle(result)
    }

    /// Returns the next pending output, if any.
    ///
    /// Drain until `None` after every input, before waiting on the stream or
    /// the application again.
    pub fn poll_output(&mut self) -> Option<NoiseOutput> {
        self.pending.pop_front()
    }

    /// Refuses input once a terminal error has failed the session.
    fn check_live(&self) -> Result<(), NoiseError> {
        if matches!(self.state, State::Failed) {
            return Err(NoiseError::Failed);
        }
        Ok(())
    }

    /// Fails the session, dropping queued output, on a terminal error.
    fn settle(&mut self, result: Result<(), NoiseError>) -> Result<(), NoiseError> {
        if result.as_ref().is_err_and(NoiseError::is_terminal) {
            self.state = State::Failed;
            self.pending.clear();
        }
        result
    }

    fn begin_handshake(&mut self) -> Result<(), NoiseError> {
        match core::mem::replace(&mut self.state, State::Failed) {
            State::Idle(mut handshake) => {
                // A start error is terminal, so the session stays `Failed`.
                let outbound = handshake.start()?;
                self.state = State::Handshaking(handshake);
                if let Some(message) = outbound {
                    self.pending
                        .push_back(NoiseOutput::Outbound(encode_frame(&message)?));
                }
                Ok(())
            }
            other => {
                self.state = other;
                Err(NoiseError::AlreadyStarted)
            }
        }
    }

    fn receive(&mut self, bytes: Vec<u8>) -> Result<(), NoiseError> {
        if matches!(self.state, State::Idle(_)) {
            return Err(NoiseError::InvalidInput("session has not been started"));
        }
        self.decoder.push(bytes);
        while let Some(mut message) = self.decoder.next_frame() {
            match &mut self.state {
                State::Transport { receive, .. } => {
                    receive.decrypt_with_ad(b"", &mut message)?;
                    self.pending.push_back(NoiseOutput::Decrypted(message));
                }
                State::Handshaking(handshake) => {
                    let (outbound, complete) = handshake.read_message(&message)?;
                    if let Some(outbound) = outbound {
                        self.pending
                            .push_back(NoiseOutput::Outbound(encode_frame(&outbound)?));
                    }
                    if let Some(result) = complete {
                        self.complete_handshake(result);
                    }
                }
                // Both are refused before any frame is decoded.
                State::Idle(_) | State::Failed => return Err(NoiseError::Failed),
            }
        }
        Ok(())
    }

    fn complete_handshake(&mut self, result: HandshakeResult) {
        self.state = State::Transport {
            send: result.send,
            receive: result.receive,
            handshake_hash: result.handshake_hash,
        };
        self.pending.push_back(NoiseOutput::HandshakeComplete {
            peer: result.peer,
            identity_key: result.identity_key,
            remote_extensions: result.remote_extensions,
        });
    }

    /// Frames and encrypts `plaintext` in `MAX_TRANSPORT_PLAINTEXT` segments.
    /// Each segment is copied once into its outbound frame and encrypted there.
    fn encrypt_frames(&mut self, plaintext: &[u8]) -> Result<(), NoiseError> {
        // An empty write still emits one tag-only frame.
        let empty = plaintext.is_empty().then_some(&[][..]);
        for segment in plaintext.chunks(MAX_TRANSPORT_PLAINTEXT).chain(empty) {
            let mut frame = Vec::with_capacity(FRAME_PREFIX_LEN + segment.len() + cipher::TAG_LEN);
            frame.extend_from_slice(&[0; FRAME_PREFIX_LEN]);
            frame.extend_from_slice(segment);
            self.seal_frame(frame)?;
        }
        Ok(())
    }

    /// Writes the length prefix over `frame[..FRAME_PREFIX_LEN]`, encrypts the
    /// plaintext after it in place, appends the tag and queues the frame.
    fn seal_frame(&mut self, mut frame: Vec<u8>) -> Result<(), NoiseError> {
        let State::Transport { send: cipher, .. } = &mut self.state else {
            return Err(NoiseError::InvalidInput("handshake is not complete"));
        };
        let len = frame.len().saturating_sub(FRAME_PREFIX_LEN) + cipher::TAG_LEN;
        #[expect(
            clippy::map_err_ignore,
            reason = "The conversion error has no detail beyond the length stored in NoiseError."
        )]
        let prefix = u16::try_from(len).map_err(|_| NoiseError::FrameTooLarge { len })?;
        let Some(head) = frame.get_mut(..FRAME_PREFIX_LEN) else {
            return Err(NoiseError::InvalidInput(
                "frame has no room for its length prefix",
            ));
        };
        head.copy_from_slice(&prefix.to_be_bytes());
        cipher.encrypt_with_ad(b"", &mut frame, FRAME_PREFIX_LEN)?;
        self.pending.push_back(NoiseOutput::Outbound(frame));
        Ok(())
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
                    local_extensions: None,
                }),
                responder: NoiseSession::new(NoiseConfig {
                    role: NoiseRole::Responder,
                    identity: responder_identity,
                    static_secret: [5; 32],
                    ephemeral_secret: [6; 32],
                    expected_peer: Some(initiator_peer.clone()),
                    local_extensions: None,
                }),
                initiator_peer,
                responder_peer,
            }
        }

        fn handshake(&mut self) {
            self.initiator.start().unwrap();
            self.responder.start().unwrap();

            let message1 = outbound(&mut self.initiator);
            self.responder.on_data(message1).unwrap();
            let message2 = outbound(&mut self.responder);
            self.initiator.on_data(message2).unwrap();
            let message3 = outbound(&mut self.initiator);
            assert_eq!(handshake_peer(&mut self.initiator), self.responder_peer);
            self.responder.on_data(message3).unwrap();
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
        handshake_complete(session).0
    }

    fn handshake_complete(session: &mut NoiseSession) -> (PeerId, Option<NoiseExtensions>) {
        match session.poll_output().expect("handshake completion") {
            NoiseOutput::HandshakeComplete {
                peer,
                remote_extensions,
                ..
            } => (peer, remote_extensions),
            other => panic!("expected handshake completion, got {other:?}"),
        }
    }

    /// Runs XX to completion and returns what each side learned:
    /// `(initiator's view of the responder, responder's view of the initiator)`.
    fn exchange_extensions(
        initiator: Option<NoiseExtensions>,
        responder: Option<NoiseExtensions>,
    ) -> (Option<NoiseExtensions>, Option<NoiseExtensions>) {
        let mut pair = Pair::new();
        pair.initiator = NoiseSession::new(NoiseConfig {
            role: NoiseRole::Initiator,
            identity: Ed25519Keypair::from_secret_key_bytes([1; 32]),
            static_secret: [3; 32],
            ephemeral_secret: [4; 32],
            expected_peer: Some(pair.responder_peer.clone()),
            local_extensions: initiator,
        });
        pair.responder = NoiseSession::new(NoiseConfig {
            role: NoiseRole::Responder,
            identity: Ed25519Keypair::from_secret_key_bytes([2; 32]),
            static_secret: [5; 32],
            ephemeral_secret: [6; 32],
            expected_peer: Some(pair.initiator_peer.clone()),
            local_extensions: responder,
        });
        pair.initiator.start().unwrap();
        pair.responder.start().unwrap();
        let message1 = outbound(&mut pair.initiator);
        pair.responder.on_data(message1).unwrap();
        let message2 = outbound(&mut pair.responder);
        pair.initiator.on_data(message2).unwrap();
        let message3 = outbound(&mut pair.initiator);
        let (_, at_initiator) = handshake_complete(&mut pair.initiator);
        pair.responder.on_data(message3).unwrap();
        let (_, at_responder) = handshake_complete(&mut pair.responder);
        (at_initiator, at_responder)
    }

    fn certhash(byte: u8) -> minip2p_identity::Multihash {
        minip2p_identity::Multihash::wrap(0x12, &[byte; 32]).unwrap()
    }

    #[test]
    fn responder_certhashes_reach_the_initiator() {
        let extensions = NoiseExtensions {
            webtransport_certhashes: alloc::vec![certhash(1), certhash(2)],
            stream_muxers: Vec::new(),
        };
        let (at_initiator, at_responder) = exchange_extensions(None, Some(extensions.clone()));
        assert_eq!(at_initiator, Some(extensions));
        assert_eq!(at_responder, None);
    }

    #[test]
    fn initiator_extensions_reach_the_responder() {
        let extensions = NoiseExtensions {
            webtransport_certhashes: Vec::new(),
            stream_muxers: alloc::vec!["/yamux/1.0.0".into()],
        };
        let (at_initiator, at_responder) = exchange_extensions(Some(extensions.clone()), None);
        assert_eq!(at_initiator, None);
        assert_eq!(at_responder, Some(extensions));
    }

    #[test]
    fn both_ends_share_the_handshake_hash() {
        let mut pair = Pair::new();
        assert_eq!(pair.initiator.handshake_hash(), None);
        pair.handshake();

        let hash = pair.initiator.handshake_hash().expect("handshake complete");
        assert_eq!(pair.responder.handshake_hash(), Some(hash));
    }

    #[test]
    fn xx_round_trip_both_directions() {
        let mut pair = Pair::new();
        pair.handshake();

        pair.initiator.encrypt(b"hello responder").unwrap();
        pair.responder
            .on_data(outbound(&mut pair.initiator))
            .unwrap();
        assert_eq!(
            pair.responder.poll_output(),
            Some(NoiseOutput::Decrypted(b"hello responder".to_vec()))
        );

        pair.responder.encrypt(b"hello initiator").unwrap();
        pair.initiator
            .on_data(outbound(&mut pair.responder))
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
            pair.initiator.encrypt(b"too early"),
            Err(NoiseError::InvalidInput("handshake is not complete"))
        );
        assert_eq!(
            pair.responder.on_data(Vec::new()),
            Err(NoiseError::InvalidInput("session has not been started"))
        );

        pair.initiator.start().unwrap();
        assert_eq!(pair.initiator.start(), Err(NoiseError::AlreadyStarted));
        let message1 = outbound(&mut pair.initiator);

        pair.responder.start().unwrap();
        pair.responder.on_data(message1).unwrap();
        let message2 = outbound(&mut pair.responder);
        pair.initiator.on_data(message2).unwrap();
        let message3 = outbound(&mut pair.initiator);
        assert_eq!(handshake_peer(&mut pair.initiator), pair.responder_peer);
        pair.responder.on_data(message3).unwrap();
        assert_eq!(handshake_peer(&mut pair.responder), pair.initiator_peer);
    }

    #[test]
    fn accepts_one_byte_drip_fragmentation() {
        let mut pair = Pair::new();
        pair.initiator.start().unwrap();
        pair.responder.start().unwrap();
        let message1 = outbound(&mut pair.initiator);
        for byte in message1 {
            pair.responder.on_data(alloc::vec![byte]).unwrap();
        }
        let message2 = outbound(&mut pair.responder);
        for byte in message2 {
            pair.initiator.on_data(alloc::vec![byte]).unwrap();
        }
        let message3 = outbound(&mut pair.initiator);
        let _ = handshake_peer(&mut pair.initiator);
        for byte in message3 {
            pair.responder.on_data(alloc::vec![byte]).unwrap();
        }
        let _ = handshake_peer(&mut pair.responder);
    }

    #[test]
    fn rejects_expected_identity_mismatch() {
        let mut pair = Pair::new();
        pair.initiator = NoiseSession::new(NoiseConfig {
            role: NoiseRole::Initiator,
            identity: Ed25519Keypair::from_secret_key_bytes([1; 32]),
            static_secret: [3; 32],
            ephemeral_secret: [4; 32],
            expected_peer: Some(Ed25519Keypair::from_secret_key_bytes([99; 32]).peer_id()),
            local_extensions: None,
        });
        pair.initiator.start().unwrap();
        pair.responder.start().unwrap();
        let message1 = outbound(&mut pair.initiator);
        pair.responder.on_data(message1).unwrap();
        let message2 = outbound(&mut pair.responder);
        assert_eq!(
            pair.initiator.on_data(message2),
            Err(NoiseError::IdentityMismatch)
        );
        assert!(pair.initiator.poll_output().is_none());
    }

    #[test]
    fn rejects_non_contributory_remote_key() {
        let mut responder = Pair::new().responder;
        responder.start().unwrap();
        let zero_message = encode_frame(&[0; 32]).unwrap();
        assert_eq!(
            responder.on_data(zero_message),
            Err(NoiseError::NonContributory)
        );
        assert!(responder.poll_output().is_none());
        assert_eq!(responder.start(), Err(NoiseError::Failed));
    }

    #[test]
    fn segments_transport_plaintext_at_wire_limit() {
        let mut pair = Pair::new();
        pair.handshake();
        let plaintext = alloc::vec![9; MAX_TRANSPORT_PLAINTEXT + 1];
        pair.initiator.encrypt(&plaintext).unwrap();
        let first = outbound(&mut pair.initiator);
        let second = outbound(&mut pair.initiator);
        assert_eq!(
            u16::from_be_bytes([first[0], first[1]]) as usize,
            MAX_FRAME_LEN
        );
        pair.responder.on_data(first).unwrap();
        pair.responder.on_data(second).unwrap();
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
        pair.initiator.encrypt(&plaintext).unwrap();
        let frame = outbound(&mut pair.initiator);
        assert_eq!(
            u16::from_be_bytes([frame[0], frame[1]]) as usize,
            MAX_FRAME_LEN
        );
        assert!(pair.initiator.poll_output().is_none());
        pair.responder.on_data(frame).unwrap();
        assert_eq!(
            pair.responder.poll_output(),
            Some(NoiseOutput::Decrypted(plaintext))
        );
    }

    #[test]
    fn in_place_encryption_matches_encrypt_and_keeps_the_buffer() {
        let mut copied = Pair::new();
        let mut in_place = Pair::new();
        copied.handshake();
        in_place.handshake();
        for len in [0, 1, MAX_TRANSPORT_PLAINTEXT, MAX_TRANSPORT_PLAINTEXT + 1] {
            let plaintext = alloc::vec![7; len];
            copied.initiator.encrypt(&plaintext).unwrap();
            let mut frame = Vec::with_capacity(FRAME_PREFIX_LEN + len + TAG_LEN);
            frame.extend_from_slice(&[0; FRAME_PREFIX_LEN]);
            frame.extend_from_slice(&plaintext);
            let buffer = frame.as_ptr();
            in_place.initiator.encrypt_in_place(frame).unwrap();
            let mut first = true;
            while let Some(expected) = copied.initiator.poll_output() {
                let NoiseOutput::Outbound(sealed) = in_place.initiator.poll_output().unwrap()
                else {
                    panic!("expected outbound data");
                };
                // A plaintext that fits one frame is sealed in the given buffer.
                if first && len <= MAX_TRANSPORT_PLAINTEXT {
                    assert_eq!(sealed.as_ptr(), buffer);
                }
                first = false;
                assert_eq!(NoiseOutput::Outbound(sealed), expected);
            }
            assert!(in_place.initiator.poll_output().is_none());
        }
    }

    #[test]
    fn empty_write_emits_one_tag_only_frame() {
        let mut pair = Pair::new();
        pair.handshake();
        pair.initiator.encrypt(&[]).unwrap();
        let frame = outbound(&mut pair.initiator);
        assert_eq!(frame.len(), 2 + cipher::TAG_LEN);
        assert!(pair.initiator.poll_output().is_none());
        pair.responder.on_data(frame).unwrap();
        assert_eq!(
            pair.responder.poll_output(),
            Some(NoiseOutput::Decrypted(Vec::new()))
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
            local_extensions: None,
        };
        let debug = alloc::format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("170, 170"));
        assert!(!debug.contains("187, 187"));
    }
}
