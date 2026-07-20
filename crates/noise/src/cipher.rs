use alloc::vec::Vec;

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};

use crate::NoiseError;

#[derive(Clone)]
pub(crate) struct CipherState {
    key: Option<[u8; 32]>,
    nonce: u64,
}

impl CipherState {
    pub(crate) const fn new() -> Self {
        Self {
            key: None,
            nonce: 0,
        }
    }

    pub(crate) fn initialize_key(&mut self, key: [u8; 32]) {
        self.key = Some(key);
        self.nonce = 0;
    }

    pub(crate) fn encrypt_with_ad(
        &mut self,
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        let Some(key) = self.key else {
            return Ok(plaintext.to_vec());
        };
        let nonce = self.next_nonce()?;
        let ciphertext = ChaCha20Poly1305::new((&key).into())
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: ad,
                },
            )
            .map_err(|_| NoiseError::Encryption)?;
        self.nonce += 1;
        Ok(ciphertext)
    }

    pub(crate) fn decrypt_with_ad(
        &mut self,
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        let Some(key) = self.key else {
            return Ok(ciphertext.to_vec());
        };
        let nonce = self.next_nonce()?;
        let plaintext = ChaCha20Poly1305::new((&key).into())
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: ciphertext,
                    aad: ad,
                },
            )
            .map_err(|_| NoiseError::Decryption)?;
        // Noise increments n only after a successful DECRYPT operation.
        self.nonce += 1;
        Ok(plaintext)
    }

    fn next_nonce(&self) -> Result<[u8; 12], NoiseError> {
        if self.nonce == u64::MAX {
            return Err(NoiseError::NonceExhausted);
        }
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.nonce.to_le_bytes());
        Ok(nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_nonce_exhaustion() {
        let mut cipher = CipherState::new();
        cipher.initialize_key([4; 32]);
        cipher.nonce = u64::MAX;
        assert_eq!(
            cipher.encrypt_with_ad(b"", b"x"),
            Err(NoiseError::NonceExhausted)
        );
    }

    #[test]
    fn decrypt_failure_does_not_advance_nonce() {
        let mut sender = CipherState::new();
        sender.initialize_key([4; 32]);
        let ciphertext = sender.encrypt_with_ad(b"context", b"plaintext").unwrap();

        let mut receiver = CipherState::new();
        receiver.initialize_key([4; 32]);
        let mut corrupted = ciphertext.clone();
        corrupted[0] ^= 1;
        assert_eq!(
            receiver.decrypt_with_ad(b"context", &corrupted),
            Err(NoiseError::Decryption)
        );
        assert_eq!(receiver.nonce, 0);
        assert_eq!(
            receiver.decrypt_with_ad(b"context", &ciphertext).unwrap(),
            b"plaintext"
        );
        assert_eq!(receiver.nonce, 1);
    }
}
