use alloc::vec::Vec;

use crate::NoiseError;

/// Largest payload representable by libp2p Noise's two-byte frame length.
pub const MAX_FRAME_LEN: usize = u16::MAX as usize;

/// Incremental decoder for two-byte big-endian length-prefixed Noise frames.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
}

impl FrameDecoder {
    /// Creates an empty decoder.
    pub const fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Appends bytes received from the underlying stream.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Returns the next complete frame payload, if one is buffered.
    pub fn next_frame(&mut self) -> Option<Vec<u8>> {
        if self.buffer.len() < 2 {
            return None;
        }
        let len = u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize;
        if self.buffer.len() < len + 2 {
            return None;
        }
        let payload = self.buffer[2..len + 2].to_vec();
        self.buffer.drain(..len + 2);
        Some(payload)
    }

    /// Returns the number of bytes currently buffered, including a partial header.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

/// Encodes one Noise handshake or transport message.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
    let len = u16::try_from(payload.len())
        .map_err(|_| NoiseError::FrameTooLarge { len: payload.len() })?;
    let mut out = Vec::with_capacity(payload.len() + 2);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_fragmented_and_coalesced_frames() {
        let mut decoder = FrameDecoder::new();
        let mut bytes = encode_frame(b"one").unwrap();
        bytes.extend_from_slice(&encode_frame(b"two").unwrap());
        for byte in &bytes[..4] {
            decoder.push(core::slice::from_ref(byte));
            assert!(decoder.next_frame().is_none());
        }
        decoder.push(&bytes[4..]);
        assert_eq!(decoder.next_frame().unwrap(), b"one");
        assert_eq!(decoder.next_frame().unwrap(), b"two");
        assert!(decoder.next_frame().is_none());
    }

    #[test]
    fn rejects_unrepresentable_payload() {
        let payload = alloc::vec![0; MAX_FRAME_LEN + 1];
        assert!(matches!(
            encode_frame(&payload),
            Err(NoiseError::FrameTooLarge { .. })
        ));
    }
}
