use alloc::vec::Vec;

use crate::{ED25519_SIGNATURE_LENGTH, Ed25519Keypair, PublicKey, VerifyError};

/// Signed byte payload using an embedded public key and Ed25519 signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedBytes {
    public_key: PublicKey,
    payload: Vec<u8>,
    signature: [u8; ED25519_SIGNATURE_LENGTH],
}

impl SignedBytes {
    /// Signs payload bytes with an Ed25519 keypair.
    pub fn sign_ed25519(keypair: &Ed25519Keypair, payload: impl Into<Vec<u8>>) -> Self {
        let payload = payload.into();
        let signature = keypair.sign(&payload);
        Self {
            public_key: keypair.public_key(),
            payload,
            signature,
        }
    }

    /// Builds a signed payload from explicit parts.
    pub fn from_parts(
        public_key: PublicKey,
        payload: Vec<u8>,
        signature: [u8; ED25519_SIGNATURE_LENGTH],
    ) -> Self {
        Self {
            public_key,
            payload,
            signature,
        }
    }

    /// Returns the embedded public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns the signed payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the raw Ed25519 signature bytes.
    pub fn signature(&self) -> &[u8; ED25519_SIGNATURE_LENGTH] {
        &self.signature
    }

    /// Consumes this value and returns all parts.
    pub fn into_parts(self) -> (PublicKey, Vec<u8>, [u8; ED25519_SIGNATURE_LENGTH]) {
        (self.public_key, self.payload, self.signature)
    }

    /// Verifies this payload signature against the embedded public key.
    pub fn verify(&self) -> Result<(), VerifyError> {
        self.public_key.verify(&self.payload, &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::{KeyType, VerifyError};

    #[test]
    fn signs_and_verifies_payload() {
        let keypair = Ed25519Keypair::from_secret_key_bytes([21u8; 32]);
        let payload = b"hello-minip2p";

        let signed = SignedBytes::sign_ed25519(&keypair, payload.as_slice());
        signed.verify().expect("signature must verify");
    }

    #[test]
    fn rejects_tampered_payload() {
        let keypair = Ed25519Keypair::from_secret_key_bytes([23u8; 32]);
        let signed = SignedBytes::sign_ed25519(&keypair, b"payload");

        let mut tampered_payload = signed.payload().to_vec();
        tampered_payload[0] ^= 0x01;

        let tampered = SignedBytes::from_parts(
            signed.public_key().clone(),
            tampered_payload,
            *signed.signature(),
        );
        let err = tampered
            .verify()
            .expect_err("tampered payload must not verify");

        assert_eq!(err, VerifyError::InvalidSignature);
    }

    #[test]
    fn rejects_unsupported_key_type() {
        let signed = SignedBytes::from_parts(
            PublicKey::new(KeyType::Rsa, vec![1, 2, 3]),
            b"payload".to_vec(),
            [0u8; ED25519_SIGNATURE_LENGTH],
        );

        let err = signed
            .verify()
            .expect_err("non-ed25519 key types are unsupported");
        assert_eq!(err, VerifyError::UnsupportedKeyType(KeyType::Rsa));
    }
}
