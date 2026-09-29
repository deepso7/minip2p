use alloc::vec::Vec;

use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit};

use crate::NoiseError;

/// Length of the ChaCha20-Poly1305 authentication tag on every keyed ciphertext.
pub(crate) const TAG_LEN: usize = 16;

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

    /// Encrypts `buffer[start..]` in place and appends the [`TAG_LEN`]-byte tag.
    ///
    /// Bytes before `start` (a frame header or earlier handshake fields) are
    /// left alone. Before a key is set this is a no-op, as Noise specifies.
    pub(crate) fn encrypt_with_ad(
        &mut self,
        ad: &[u8],
        buffer: &mut Vec<u8>,
        start: usize,
    ) -> Result<(), NoiseError> {
        let Some(key) = self.key else {
            return Ok(());
        };
        let nonce = self.next_nonce()?;
        let plaintext = buffer.get_mut(start..).ok_or(NoiseError::InvalidState(
            "encryption start is out of bounds",
        ))?;
        #[expect(
            clippy::map_err_ignore,
            reason = "NoiseError intentionally hides backend encryption failures."
        )]
        let tag = ChaCha20Poly1305::new((&key).into())
            .encrypt_inout_detached((&nonce).into(), ad, plaintext.into())
            .map_err(|_| NoiseError::Encryption)?;
        buffer.extend_from_slice(&tag);
        // No ciphertext was emitted on error, so the nonce is safe to reuse on retry.
        self.nonce += 1;
        Ok(())
    }

    /// Verifies and decrypts `buffer` in place, truncating the tag.
    ///
    /// On failure `buffer` is unchanged and the nonce does not advance. Before
    /// a key is set this is a no-op, as Noise specifies.
    pub(crate) fn decrypt_with_ad(
        &mut self,
        ad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), NoiseError> {
        let Some(key) = self.key else {
            return Ok(());
        };
        let nonce = self.next_nonce()?;
        #[expect(
            clippy::map_err_ignore,
            reason = "NoiseError intentionally hides backend decryption failures."
        )]
        ChaCha20Poly1305::new((&key).into())
            .decrypt_in_place((&nonce).into(), ad, buffer)
            .map_err(|_| NoiseError::Decryption)?;
        // Noise increments n only after a successful DECRYPT operation.
        self.nonce += 1;
        Ok(())
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
            cipher.encrypt_with_ad(b"", &mut b"x".to_vec(), 0),
            Err(NoiseError::NonceExhausted)
        );
    }

    #[test]
    fn encrypts_after_start_in_place_and_round_trips() {
        let mut sender = CipherState::new();
        sender.initialize_key([4; 32]);
        let mut buffer = b"hdplaintext".to_vec();
        sender.encrypt_with_ad(b"context", &mut buffer, 2).unwrap();
        assert_eq!(buffer.len(), 2 + 9 + 16, "only the tag is appended");
        assert_eq!(&buffer[..2], b"hd", "bytes before start stay plaintext");
        assert_ne!(&buffer[2..11], b"plaintext");

        let mut receiver = CipherState::new();
        receiver.initialize_key([4; 32]);
        let mut ciphertext = buffer[2..].to_vec();
        receiver
            .decrypt_with_ad(b"context", &mut ciphertext)
            .unwrap();
        assert_eq!(ciphertext, b"plaintext");
    }

    #[test]
    fn decrypt_failure_does_not_advance_nonce() {
        let mut sender = CipherState::new();
        sender.initialize_key([4; 32]);
        let mut ciphertext = b"plaintext".to_vec();
        sender
            .encrypt_with_ad(b"context", &mut ciphertext, 0)
            .unwrap();

        let mut receiver = CipherState::new();
        receiver.initialize_key([4; 32]);
        let mut corrupted = ciphertext.clone();
        corrupted[0] ^= 1;
        let rejected = corrupted.clone();
        assert_eq!(
            receiver.decrypt_with_ad(b"context", &mut corrupted),
            Err(NoiseError::Decryption)
        );
        assert_eq!(corrupted, rejected, "a rejected frame is left untouched");
        assert_eq!(receiver.nonce, 0);
        receiver
            .decrypt_with_ad(b"context", &mut ciphertext)
            .unwrap();
        assert_eq!(ciphertext, b"plaintext");
        assert_eq!(receiver.nonce, 1);
    }
}
