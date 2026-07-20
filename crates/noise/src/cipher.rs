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
        let nonce = self.take_nonce()?;
        ChaCha20Poly1305::new((&key).into())
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: ad,
                },
            )
            .map_err(|_| NoiseError::Encryption)
    }

    pub(crate) fn decrypt_with_ad(
        &mut self,
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        let Some(key) = self.key else {
            return Ok(ciphertext.to_vec());
        };
        let nonce = self.take_nonce()?;
        ChaCha20Poly1305::new((&key).into())
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: ciphertext,
                    aad: ad,
                },
            )
            .map_err(|_| NoiseError::Decryption)
    }

    fn take_nonce(&mut self) -> Result<[u8; 12], NoiseError> {
        if self.nonce == u64::MAX {
            return Err(NoiseError::NonceExhausted);
        }
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.nonce.to_le_bytes());
        self.nonce += 1;
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
}
