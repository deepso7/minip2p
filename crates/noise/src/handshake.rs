use alloc::vec::Vec;

use minip2p_identity::{Ed25519Keypair, PeerId, PublicKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::cipher::CipherState;
use crate::hkdf;
use crate::payload::NoiseHandshakePayload;
use crate::{NoiseError, NoiseRole};

const PROTOCOL_NAME: &[u8] = b"Noise_XX_25519_ChaChaPoly_SHA256";
const SIGNATURE_PREFIX: &[u8] = b"noise-libp2p-static-key:";

pub(crate) struct HandshakeResult {
    pub(crate) send: CipherState,
    pub(crate) receive: CipherState,
    pub(crate) peer: PeerId,
    pub(crate) identity_key: PublicKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    InitiatorWriteMessage1,
    InitiatorReadMessage2,
    InitiatorWriteMessage3,
    ResponderReadMessage1,
    ResponderWriteMessage2,
    ResponderReadMessage3,
    Complete,
}

pub(crate) struct HandshakeState {
    role: NoiseRole,
    step: Step,
    identity: Ed25519Keypair,
    local_static: [u8; 32],
    local_ephemeral: [u8; 32],
    remote_ephemeral: Option<[u8; 32]>,
    expected_peer: Option<PeerId>,
    symmetric: SymmetricState,
}

impl HandshakeState {
    pub(crate) fn new(
        role: NoiseRole,
        identity: Ed25519Keypair,
        local_static: [u8; 32],
        local_ephemeral: [u8; 32],
        expected_peer: Option<PeerId>,
    ) -> Self {
        let step = match role {
            NoiseRole::Initiator => Step::InitiatorWriteMessage1,
            NoiseRole::Responder => Step::ResponderReadMessage1,
        };
        Self {
            role,
            step,
            identity,
            local_static,
            local_ephemeral,
            remote_ephemeral: None,
            expected_peer,
            symmetric: SymmetricState::new(),
        }
    }

    pub(crate) fn start(&mut self) -> Result<Option<Vec<u8>>, NoiseError> {
        match self.step {
            Step::InitiatorWriteMessage1 => {
                let public = public_key(self.local_ephemeral);
                self.symmetric.mix_hash(&public);
                // XX message 1 has an empty payload. Noise still runs
                // EncryptAndHash over it, which advances the handshake hash.
                let _ = self.symmetric.encrypt_and_hash(b"")?;
                self.step = Step::InitiatorReadMessage2;
                Ok(Some(public.to_vec()))
            }
            Step::ResponderReadMessage1 => Ok(None),
            _ => Err(NoiseError::AlreadyStarted),
        }
    }

    pub(crate) fn read_message(
        &mut self,
        message: &[u8],
    ) -> Result<(Option<Vec<u8>>, Option<HandshakeResult>), NoiseError> {
        match self.step {
            Step::ResponderReadMessage1 => {
                let remote = exact_array::<32>(message, "invalid Noise message 1 length")?;
                self.remote_ephemeral = Some(remote);
                self.symmetric.mix_hash(&remote);
                let plaintext = self.symmetric.decrypt_and_hash(&message[32..])?;
                debug_assert!(plaintext.is_empty());
                self.step = Step::ResponderWriteMessage2;
                let response = self.write_message2()?;
                Ok((Some(response), None))
            }
            Step::InitiatorReadMessage2 => {
                let (peer, identity_key) = self.read_message2(message)?;
                self.step = Step::InitiatorWriteMessage3;
                let response = self.write_message3()?;
                let result = self.finish_with_peer(peer, identity_key);
                Ok((Some(response), Some(result)))
            }
            Step::ResponderReadMessage3 => {
                let (peer, identity_key) = self.read_message3(message)?;
                let result = self.finish_with_peer(peer, identity_key);
                Ok((None, Some(result)))
            }
            _ => Err(NoiseError::UnexpectedHandshakeMessage),
        }
    }

    fn write_message2(&mut self) -> Result<Vec<u8>, NoiseError> {
        debug_assert_eq!(self.role, NoiseRole::Responder);
        debug_assert_eq!(self.step, Step::ResponderWriteMessage2);
        let remote_e = required(self.remote_ephemeral)?;
        let local_e_public = public_key(self.local_ephemeral);
        let mut out = local_e_public.to_vec();
        self.symmetric.mix_hash(&local_e_public);
        self.symmetric
            .mix_key(&dh(self.local_ephemeral, remote_e)?)?;

        let local_s_public = public_key(self.local_static);
        out.extend_from_slice(&self.symmetric.encrypt_and_hash(&local_s_public)?);
        self.symmetric.mix_key(&dh(self.local_static, remote_e)?)?;
        let payload = self.local_payload(local_s_public);
        out.extend_from_slice(&self.symmetric.encrypt_and_hash(&payload)?);
        self.step = Step::ResponderReadMessage3;
        Ok(out)
    }

    fn read_message2(&mut self, message: &[u8]) -> Result<(PeerId, PublicKey), NoiseError> {
        if message.len() < 32 + 48 + 16 {
            return Err(NoiseError::InvalidHandshakeMessage(
                "Noise message 2 is too short",
            ));
        }
        let remote_e: [u8; 32] = message[..32].try_into().expect("length checked");
        self.remote_ephemeral = Some(remote_e);
        self.symmetric.mix_hash(&remote_e);
        self.symmetric
            .mix_key(&dh(self.local_ephemeral, remote_e)?)?;

        let remote_s_bytes = self.symmetric.decrypt_and_hash(&message[32..80])?;
        let remote_s = exact_array::<32>(&remote_s_bytes, "invalid remote static key")?;
        self.symmetric
            .mix_key(&dh(self.local_ephemeral, remote_s)?)?;
        let payload = self.symmetric.decrypt_and_hash(&message[80..])?;
        self.verify_payload(&payload, remote_s)
    }

    fn write_message3(&mut self) -> Result<Vec<u8>, NoiseError> {
        debug_assert_eq!(self.role, NoiseRole::Initiator);
        debug_assert_eq!(self.step, Step::InitiatorWriteMessage3);
        let remote_e = required(self.remote_ephemeral)?;
        let local_s_public = public_key(self.local_static);
        let mut out = self.symmetric.encrypt_and_hash(&local_s_public)?;
        self.symmetric.mix_key(&dh(self.local_static, remote_e)?)?;
        let payload = self.local_payload(local_s_public);
        out.extend_from_slice(&self.symmetric.encrypt_and_hash(&payload)?);
        self.step = Step::Complete;
        Ok(out)
    }

    fn read_message3(&mut self, message: &[u8]) -> Result<(PeerId, PublicKey), NoiseError> {
        if message.len() < 48 + 16 {
            return Err(NoiseError::InvalidHandshakeMessage(
                "Noise message 3 is too short",
            ));
        }
        let remote_s_bytes = self.symmetric.decrypt_and_hash(&message[..48])?;
        let remote_s = exact_array::<32>(&remote_s_bytes, "invalid remote static key")?;
        self.symmetric
            .mix_key(&dh(self.local_ephemeral, remote_s)?)?;
        let payload = self.symmetric.decrypt_and_hash(&message[48..])?;
        let verified = self.verify_payload(&payload, remote_s)?;
        self.step = Step::Complete;
        Ok(verified)
    }

    fn local_payload(&self, static_public: [u8; 32]) -> Vec<u8> {
        let mut signed = Vec::with_capacity(SIGNATURE_PREFIX.len() + static_public.len());
        signed.extend_from_slice(SIGNATURE_PREFIX);
        signed.extend_from_slice(&static_public);
        NoiseHandshakePayload::new(self.identity.public_key(), self.identity.sign(&signed)).encode()
    }

    fn verify_payload(
        &self,
        payload: &[u8],
        remote_static: [u8; 32],
    ) -> Result<(PeerId, PublicKey), NoiseError> {
        let payload = NoiseHandshakePayload::decode(payload)?;
        let identity_key = PublicKey::decode_protobuf(&payload.identity_key)
            .map_err(|_| NoiseError::InvalidIdentityKey)?;
        let signature: [u8; 64] = payload
            .identity_sig
            .try_into()
            .map_err(|_| NoiseError::InvalidIdentitySignature)?;
        let mut signed = Vec::with_capacity(SIGNATURE_PREFIX.len() + remote_static.len());
        signed.extend_from_slice(SIGNATURE_PREFIX);
        signed.extend_from_slice(&remote_static);
        identity_key
            .verify(&signed, &signature)
            .map_err(|_| NoiseError::InvalidIdentitySignature)?;
        let peer = PeerId::from_public_key(&identity_key);
        if self
            .expected_peer
            .as_ref()
            .is_some_and(|expected| expected != &peer)
        {
            return Err(NoiseError::IdentityMismatch);
        }
        Ok((peer, identity_key))
    }

    fn finish_with_peer(&mut self, peer: PeerId, identity_key: PublicKey) -> HandshakeResult {
        let (first, second) = self.symmetric.split();
        let (send, receive) = match self.role {
            NoiseRole::Initiator => (first, second),
            NoiseRole::Responder => (second, first),
        };
        HandshakeResult {
            send,
            receive,
            peer,
            identity_key,
        }
    }
}

struct SymmetricState {
    chaining_key: [u8; 32],
    hash: [u8; 32],
    cipher: CipherState,
}

impl SymmetricState {
    fn new() -> Self {
        Self::with_prologue(b"")
    }

    fn with_prologue(prologue: &[u8]) -> Self {
        let mut initial = [0u8; 32];
        if PROTOCOL_NAME.len() <= initial.len() {
            initial[..PROTOCOL_NAME.len()].copy_from_slice(PROTOCOL_NAME);
        } else {
            initial = Sha256::digest(PROTOCOL_NAME).into();
        }
        let mut state = Self {
            chaining_key: initial,
            hash: initial,
            cipher: CipherState::new(),
        };
        // Noise always mixes the prologue, including an empty prologue. Hashing
        // `h || []` is not a no-op and is required for libp2p interoperability.
        state.mix_hash(prologue);
        state
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut hash = Sha256::new();
        hash.update(self.hash);
        hash.update(data);
        self.hash = hash.finalize().into();
    }

    fn mix_key(&mut self, input: &[u8]) -> Result<(), NoiseError> {
        let (chaining_key, temp_key) = hkdf::derive2(&self.chaining_key, input);
        self.chaining_key = chaining_key;
        self.cipher.initialize_key(temp_key);
        Ok(())
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let ciphertext = self.cipher.encrypt_with_ad(&self.hash, plaintext)?;
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let plaintext = self.cipher.decrypt_with_ad(&self.hash, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    fn split(&self) -> (CipherState, CipherState) {
        let (first, second) = hkdf::derive2(&self.chaining_key, b"");
        let mut first_cipher = CipherState::new();
        first_cipher.initialize_key(first);
        let mut second_cipher = CipherState::new();
        second_cipher.initialize_key(second);
        (first_cipher, second_cipher)
    }
}

fn public_key(secret: [u8; 32]) -> [u8; 32] {
    X25519PublicKey::from(&StaticSecret::from(secret)).to_bytes()
}

fn dh(secret: [u8; 32], public: [u8; 32]) -> Result<[u8; 32], NoiseError> {
    let shared = StaticSecret::from(secret).diffie_hellman(&X25519PublicKey::from(public));
    let bytes = shared.to_bytes();
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(NoiseError::NonContributory);
    }
    Ok(bytes)
}

fn exact_array<const N: usize>(input: &[u8], reason: &'static str) -> Result<[u8; N], NoiseError> {
    input
        .try_into()
        .map_err(|_| NoiseError::InvalidHandshakeMessage(reason))
}

fn required<T>(value: Option<T>) -> Result<T, NoiseError> {
    value.ok_or(NoiseError::InvalidState("missing handshake key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTOR: &str = include_str!("../tests/fixtures/noise-c-basic-xx.txt");

    #[test]
    fn rejects_bad_identity_signature() {
        let remote_identity = Ed25519Keypair::from_secret_key_bytes([8; 32]);
        let remote_static = public_key([9; 32]);
        let mut signed = Vec::from(SIGNATURE_PREFIX);
        signed.extend_from_slice(&remote_static);
        let mut signature = remote_identity.sign(&signed);
        signature[0] ^= 1;
        let payload = NoiseHandshakePayload::new(remote_identity.public_key(), signature).encode();
        let state = HandshakeState::new(
            NoiseRole::Initiator,
            Ed25519Keypair::from_secret_key_bytes([1; 32]),
            [2; 32],
            [3; 32],
            None,
        );
        assert_eq!(
            state.verify_payload(&payload, remote_static),
            Err(NoiseError::InvalidIdentitySignature)
        );
    }

    #[test]
    fn matches_noise_c_xx_known_answer_vector() {
        let prologue = hex(value("prologue"));
        let initiator_static = array(value("init_static"));
        let initiator_ephemeral = array(value("init_ephemeral"));
        let responder_static = array(value("resp_static"));
        let responder_ephemeral = array(value("resp_ephemeral"));
        let payloads = (1..=6)
            .map(|number| hex(value(&alloc::format!("payload{number}"))))
            .collect::<Vec<_>>();
        let expected = (1..=6)
            .map(|number| hex(value(&alloc::format!("ciphertext{number}"))))
            .collect::<Vec<_>>();

        let mut initiator = SymmetricState::with_prologue(&prologue);
        let mut responder = SymmetricState::with_prologue(&prologue);

        let initiator_e = public_key(initiator_ephemeral);
        let mut message1 = initiator_e.to_vec();
        initiator.mix_hash(&initiator_e);
        message1.extend_from_slice(&initiator.encrypt_and_hash(&payloads[0]).unwrap());
        assert_eq!(message1, expected[0]);

        responder.mix_hash(&message1[..32]);
        assert_eq!(
            responder.decrypt_and_hash(&message1[32..]).unwrap(),
            payloads[0]
        );

        let responder_e = public_key(responder_ephemeral);
        let mut message2 = responder_e.to_vec();
        responder.mix_hash(&responder_e);
        responder
            .mix_key(&dh(responder_ephemeral, initiator_e).unwrap())
            .unwrap();
        let responder_s = public_key(responder_static);
        message2.extend_from_slice(&responder.encrypt_and_hash(&responder_s).unwrap());
        responder
            .mix_key(&dh(responder_static, initiator_e).unwrap())
            .unwrap();
        message2.extend_from_slice(&responder.encrypt_and_hash(&payloads[1]).unwrap());
        assert_eq!(message2, expected[1]);

        initiator.mix_hash(&message2[..32]);
        initiator
            .mix_key(&dh(initiator_ephemeral, responder_e).unwrap())
            .unwrap();
        assert_eq!(
            initiator.decrypt_and_hash(&message2[32..80]).unwrap(),
            responder_s
        );
        initiator
            .mix_key(&dh(initiator_ephemeral, responder_s).unwrap())
            .unwrap();
        assert_eq!(
            initiator.decrypt_and_hash(&message2[80..]).unwrap(),
            payloads[1]
        );

        let initiator_s = public_key(initiator_static);
        let mut message3 = initiator.encrypt_and_hash(&initiator_s).unwrap();
        initiator
            .mix_key(&dh(initiator_static, responder_e).unwrap())
            .unwrap();
        message3.extend_from_slice(&initiator.encrypt_and_hash(&payloads[2]).unwrap());
        assert_eq!(message3, expected[2]);

        assert_eq!(
            responder.decrypt_and_hash(&message3[..48]).unwrap(),
            initiator_s
        );
        responder
            .mix_key(&dh(responder_ephemeral, initiator_s).unwrap())
            .unwrap();
        assert_eq!(
            responder.decrypt_and_hash(&message3[48..]).unwrap(),
            payloads[2]
        );

        let (mut initiator_send, mut initiator_receive) = initiator.split();
        let (responder_receive, mut responder_send) = responder.split();

        let message4 = responder_send.encrypt_with_ad(b"", &payloads[3]).unwrap();
        assert_eq!(message4, expected[3]);
        assert_eq!(
            initiator_receive.decrypt_with_ad(b"", &message4).unwrap(),
            payloads[3]
        );

        let message5 = initiator_send.encrypt_with_ad(b"", &payloads[4]).unwrap();
        assert_eq!(message5, expected[4]);
        let mut responder_receive = responder_receive;
        assert_eq!(
            responder_receive.decrypt_with_ad(b"", &message5).unwrap(),
            payloads[4]
        );

        let message6 = responder_send.encrypt_with_ad(b"", &payloads[5]).unwrap();
        assert_eq!(message6, expected[5]);
        assert_eq!(
            initiator_receive.decrypt_with_ad(b"", &message6).unwrap(),
            payloads[5]
        );
    }

    fn value(name: &str) -> &str {
        VECTOR
            .lines()
            .filter_map(|line| line.split_once('='))
            .find_map(|(field, value)| (field == name).then_some(value))
            .unwrap_or_else(|| panic!("missing fixture field {name}"))
    }

    fn array(input: &str) -> [u8; 32] {
        hex(input).try_into().expect("32-byte fixture value")
    }

    fn hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = core::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }
}
