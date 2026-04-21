use core::fmt;

use ed25519_dalek::{Signer, SigningKey};
use rand_core::CryptoRngCore;

#[cfg(feature = "std")]
use rand_core::OsRng;

use crate::{KeyType, PeerId, PublicKey};

pub const ED25519_SECRET_KEY_LENGTH: usize = 32;
pub const ED25519_PUBLIC_KEY_LENGTH: usize = 32;
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

/// Ed25519 keypair with helpers to derive `PublicKey` and `PeerId`.
#[derive(Clone, Eq, PartialEq)]
pub struct Ed25519Keypair {
    secret_key: [u8; ED25519_SECRET_KEY_LENGTH],
    public_key: [u8; ED25519_PUBLIC_KEY_LENGTH],
}

/// Custom `Debug` impl that redacts the secret key to prevent accidental leakage in logs.
impl fmt::Debug for Ed25519Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Keypair")
            .field("secret_key", &"<redacted>")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl Ed25519Keypair {
    /// Creates an Ed25519 keypair from raw 32-byte secret key material.
    pub fn from_secret_key_bytes(secret_key: [u8; ED25519_SECRET_KEY_LENGTH]) -> Self {
        let signing_key = SigningKey::from_bytes(&secret_key);
        let public_key = signing_key.verifying_key().to_bytes();

        Self {
            secret_key,
            public_key,
        }
    }

    /// Generates a new Ed25519 keypair using the provided CSPRNG.
    pub fn generate_with_rng<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let signing_key = SigningKey::generate(rng);
        let secret_key = signing_key.to_bytes();
        let public_key = signing_key.verifying_key().to_bytes();

        Self {
            secret_key,
            public_key,
        }
    }

    /// Generates a new Ed25519 keypair using OS randomness.
    #[cfg(feature = "std")]
    pub fn generate() -> Self {
        let mut rng = OsRng;
        Self::generate_with_rng(&mut rng)
    }

    /// Returns the 32-byte secret key material.
    pub fn secret_key_bytes(&self) -> [u8; ED25519_SECRET_KEY_LENGTH] {
        self.secret_key
    }

    /// Returns the 32-byte public key material.
    pub fn public_key_bytes(&self) -> [u8; ED25519_PUBLIC_KEY_LENGTH] {
        self.public_key
    }

    /// Returns this keypair's public key as a libp2p `PublicKey` wrapper.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::new(KeyType::Ed25519, self.public_key.to_vec())
    }

    /// Computes this keypair's peer id.
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_public_key(&self.public_key())
    }

    /// Signs a message with this keypair's secret key.
    pub fn sign(&self, message: &[u8]) -> [u8; ED25519_SIGNATURE_LENGTH] {
        let signing_key = SigningKey::from_bytes(&self.secret_key);
        signing_key.sign(message).to_bytes()
    }
}

/// Convenience conversion: extracts the libp2p `PublicKey` from an Ed25519 keypair.
impl From<&Ed25519Keypair> for PublicKey {
    fn from(keypair: &Ed25519Keypair) -> Self {
        keypair.public_key()
    }
}

/// Convenience conversion: derives a `PeerId` directly from an Ed25519 keypair.
impl From<&Ed25519Keypair> for PeerId {
    fn from(keypair: &Ed25519Keypair) -> Self {
        keypair.peer_id()
    }
}

#[cfg(test)]
mod tests {
    use rand_core::{CryptoRng, Error, RngCore};

    use super::*;

    struct TestRng(u64);

    impl TestRng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }
    }

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                let len = chunk.len();
                chunk.copy_from_slice(&bytes[..len]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for TestRng {}

    #[test]
    fn derives_public_key_and_peer_id_from_secret() {
        let secret_key = [7u8; ED25519_SECRET_KEY_LENGTH];
        let keypair = Ed25519Keypair::from_secret_key_bytes(secret_key);

        assert_eq!(keypair.secret_key_bytes(), secret_key);
        assert_eq!(keypair.public_key().key_type(), KeyType::Ed25519);
        assert_eq!(
            keypair.public_key().data(),
            keypair.public_key_bytes().as_slice()
        );
        assert_eq!(
            keypair.peer_id(),
            PeerId::from_public_key(&keypair.public_key())
        );
    }

    #[test]
    fn generate_with_rng_is_deterministic_for_same_rng_state() {
        let mut rng_a = TestRng::new(12345);
        let mut rng_b = TestRng::new(12345);

        let keypair_a = Ed25519Keypair::generate_with_rng(&mut rng_a);
        let keypair_b = Ed25519Keypair::generate_with_rng(&mut rng_b);

        assert_eq!(keypair_a.secret_key_bytes(), keypair_b.secret_key_bytes());
        assert_eq!(keypair_a.public_key_bytes(), keypair_b.public_key_bytes());
        assert_eq!(keypair_a.peer_id(), keypair_b.peer_id());
    }

    #[test]
    fn reconstructing_from_secret_preserves_identity() {
        let mut rng = TestRng::new(9876);
        let generated = Ed25519Keypair::generate_with_rng(&mut rng);
        let restored = Ed25519Keypair::from_secret_key_bytes(generated.secret_key_bytes());

        assert_eq!(restored.public_key_bytes(), generated.public_key_bytes());
        assert_eq!(restored.peer_id(), generated.peer_id());
    }

    #[test]
    fn signs_and_verifies_message() {
        let keypair = Ed25519Keypair::from_secret_key_bytes([3u8; ED25519_SECRET_KEY_LENGTH]);
        let message = b"minip2p";
        let signature = keypair.sign(message);

        assert_eq!(signature.len(), ED25519_SIGNATURE_LENGTH);
        keypair
            .public_key()
            .verify(message, &signature)
            .expect("signature must verify");
    }

    #[test]
    fn signature_fails_for_tampered_message() {
        let keypair = Ed25519Keypair::from_secret_key_bytes([5u8; ED25519_SECRET_KEY_LENGTH]);
        let signature = keypair.sign(b"original");

        let err = keypair
            .public_key()
            .verify(b"tampered", &signature)
            .expect_err("tampered message must fail");
        assert!(matches!(err, crate::VerifyError::InvalidSignature));
    }

    #[cfg(feature = "std")]
    #[test]
    fn generates_with_os_rng() {
        let keypair = Ed25519Keypair::generate();

        assert_eq!(keypair.public_key().key_type(), KeyType::Ed25519);
        assert_eq!(keypair.public_key().data().len(), ED25519_PUBLIC_KEY_LENGTH);
    }
}
