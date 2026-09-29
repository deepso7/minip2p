use alloc::vec::Vec;

use crate::NoiseError;

/// Largest payload representable by libp2p Noise's two-byte frame length.
pub const MAX_FRAME_LEN: usize = u16::MAX as usize;

/// Incremental decoder for two-byte big-endian length-prefixed Noise frames.
#[derive(Debug)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
    offset: usize,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameDecoder {
    /// Creates an empty decoder.
    pub const fn new() -> Self {
        Self {
            buffer: Vec::new(),
            offset: 0,
        }
    }

    /// Appends bytes received from the underlying stream.
    ///
    /// When nothing is buffered, `bytes` is adopted as the buffer instead of
    /// being copied into it.
    pub fn push(&mut self, bytes: Vec<u8>) {
        if self.buffer.is_empty() {
            self.buffer = bytes;
            self.offset = 0;
        } else {
            self.buffer.extend_from_slice(&bytes);
        }
    }

    /// Returns the next complete frame payload, if one is buffered.
    ///
    /// A buffer holding exactly one frame is handed back whole, minus its
    /// length prefix, so a caller-owned frame is never copied.
    pub fn next_frame(&mut self) -> Option<Vec<u8>> {
        let remaining = self.buffer.get(self.offset..)?;
        let length: [u8; 2] = remaining.get(..2)?.try_into().ok()?;
        let start = self.offset.checked_add(2)?;
        let end = start.checked_add(u16::from_be_bytes(length).into())?;
        if end > self.buffer.len() {
            return None;
        }
        if self.offset == 0 && end == self.buffer.len() {
            let mut frame = core::mem::take(&mut self.buffer);
            frame.drain(..2);
            return Some(frame);
        }
        let payload = self.buffer.get(start..end)?.to_vec();
        self.offset = end;
        self.compact_if_needed();
        Some(payload)
    }

    /// Returns the number of bytes currently buffered, including a partial header.
    #[cfg(test)]
    pub fn buffered_len(&self) -> usize {
        self.buffer.len() - self.offset
    }

    fn compact_if_needed(&mut self) {
        if self.offset == self.buffer.len() {
            self.buffer.clear();
            self.offset = 0;
        } else if self.offset >= self.buffer.len() / 2 {
            let remaining = self.buffer.len() - self.offset;
            self.buffer.copy_within(self.offset.., 0);
            self.buffer.truncate(remaining);
            self.offset = 0;
        }
    }
}

/// Encodes one Noise handshake or transport message.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
    #[expect(
        clippy::map_err_ignore,
        reason = "The conversion error has no detail beyond the payload length stored in NoiseError."
    )]
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
            decoder.push(alloc::vec![*byte]);
            assert!(decoder.next_frame().is_none());
        }
        decoder.push(bytes[4..].to_vec());
        assert_eq!(decoder.next_frame().unwrap(), b"one");
        assert_eq!(decoder.next_frame().unwrap(), b"two");
        assert!(decoder.next_frame().is_none());
    }

    #[test]
    fn decodes_many_coalesced_frames_while_compacting_periodically() {
        const FRAME_COUNT: u16 = 1_024;

        let mut bytes = Vec::new();
        for value in 0..FRAME_COUNT {
            bytes.extend_from_slice(&encode_frame(&value.to_be_bytes()).unwrap());
        }

        let mut decoder = FrameDecoder::new();
        decoder.push(bytes);
        let mut compactions = 0;
        let mut previous_storage_len = decoder.buffer.len();

        for expected in 0..FRAME_COUNT {
            assert_eq!(
                decoder.buffered_len(),
                usize::from(FRAME_COUNT - expected) * 4
            );
            assert_eq!(decoder.next_frame().unwrap(), expected.to_be_bytes());

            if decoder.buffer.len() < previous_storage_len {
                compactions += 1;
            }
            previous_storage_len = decoder.buffer.len();
        }

        assert!(compactions > 1);
        assert_eq!(decoder.buffered_len(), 0);
        assert!(decoder.buffer.is_empty());
        assert_eq!(decoder.offset, 0);
    }

    #[test]
    fn adopts_a_lone_caller_owned_frame_without_copying() {
        let bytes = encode_frame(b"payload").unwrap();
        let allocation = bytes.as_ptr();
        let mut decoder = FrameDecoder::new();
        decoder.push(bytes);
        let frame = decoder.next_frame().unwrap();
        assert_eq!(frame, b"payload");
        assert_eq!(frame.as_ptr(), allocation, "the pushed buffer is reused");
        assert_eq!(decoder.buffered_len(), 0);
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
