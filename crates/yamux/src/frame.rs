use alloc::vec::Vec;

use crate::YamuxError;

/// Size of every Yamux frame header.
pub const HEADER_LEN: usize = 12;

/// Opens a new stream.
pub const FLAG_SYN: u16 = 1;
/// Acknowledges a remotely opened stream.
pub const FLAG_ACK: u16 = 2;
/// Half-closes a stream's write side.
pub const FLAG_FIN: u16 = 4;
/// Immediately resets a stream.
pub const FLAG_RST: u16 = 8;

const STREAM_FLAGS: u16 = FLAG_SYN | FLAG_ACK | FLAG_FIN | FLAG_RST;
const PING_FLAGS: u16 = FLAG_SYN | FLAG_ACK;

/// Yamux wire-frame type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameType {
    /// Stream data; the header value is payload length.
    Data = 0,
    /// Flow-control credit; the header value is added send credit.
    WindowUpdate = 1,
    /// Session ping; the header value is an opaque nonce.
    Ping = 2,
    /// Session termination; the header value is a reason code.
    GoAway = 3,
}

impl FrameType {
    fn decode(value: u8) -> Result<Self, YamuxError> {
        match value {
            0 => Ok(Self::Data),
            1 => Ok(Self::WindowUpdate),
            2 => Ok(Self::Ping),
            3 => Ok(Self::GoAway),
            other => Err(YamuxError::UnknownFrameType(other)),
        }
    }
}

/// Fully decoded Yamux frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    frame_type: FrameType,
    flags: u16,
    stream_id: u32,
    value: u32,
    payload: Vec<u8>,
}

impl Frame {
    /// Constructs a data frame.
    pub fn data(stream_id: u32, flags: u16, payload: Vec<u8>) -> Result<Self, YamuxError> {
        let value = u32::try_from(payload.len()).map_err(|_| YamuxError::FrameLengthOverflow)?;
        let frame = Self {
            frame_type: FrameType::Data,
            flags,
            stream_id,
            value,
            payload,
        };
        frame.validate()?;
        Ok(frame)
    }

    /// Constructs a window-update frame.
    pub fn window_update(stream_id: u32, flags: u16, credit: u32) -> Result<Self, YamuxError> {
        let frame = Self {
            frame_type: FrameType::WindowUpdate,
            flags,
            stream_id,
            value: credit,
            payload: Vec::new(),
        };
        frame.validate()?;
        Ok(frame)
    }

    /// Constructs a ping request or response frame.
    pub fn ping(flags: u16, nonce: u32) -> Result<Self, YamuxError> {
        let frame = Self {
            frame_type: FrameType::Ping,
            flags,
            stream_id: 0,
            value: nonce,
            payload: Vec::new(),
        };
        frame.validate()?;
        Ok(frame)
    }

    /// Constructs a GoAway frame.
    pub fn go_away(code: u32) -> Self {
        Self {
            frame_type: FrameType::GoAway,
            flags: 0,
            stream_id: 0,
            value: code,
            payload: Vec::new(),
        }
    }

    /// Returns this frame's type.
    pub fn frame_type(&self) -> FrameType {
        self.frame_type
    }

    /// Returns the raw flag bits.
    pub fn flags(&self) -> u16 {
        self.flags
    }

    /// Returns the stream identifier (`0` for session frames).
    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    /// Returns the type-dependent header value.
    pub fn value(&self) -> u32 {
        self.value
    }

    /// Returns the data-frame payload, empty for all other frame types.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Encodes this frame to its 12-byte header plus optional data payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(HEADER_LEN + self.payload.len());
        output.push(0);
        output.push(self.frame_type as u8);
        output.extend_from_slice(&self.flags.to_be_bytes());
        output.extend_from_slice(&self.stream_id.to_be_bytes());
        output.extend_from_slice(&self.value.to_be_bytes());
        output.extend_from_slice(&self.payload);
        output
    }

    fn validate(&self) -> Result<(), YamuxError> {
        let allowed = match self.frame_type {
            FrameType::Data | FrameType::WindowUpdate => STREAM_FLAGS,
            FrameType::Ping => PING_FLAGS,
            FrameType::GoAway => 0,
        };
        if self.flags & !allowed != 0
            || (self.frame_type == FrameType::Ping && !matches!(self.flags, FLAG_SYN | FLAG_ACK))
        {
            return Err(YamuxError::InvalidFlags {
                frame_type: self.frame_type,
                flags: self.flags,
            });
        }
        let valid_stream = match self.frame_type {
            FrameType::Data | FrameType::WindowUpdate => self.stream_id != 0,
            FrameType::Ping | FrameType::GoAway => self.stream_id == 0,
        };
        if !valid_stream {
            return Err(YamuxError::InvalidStreamId {
                frame_type: self.frame_type,
                stream: self.stream_id,
            });
        }
        Ok(())
    }
}

/// Incremental decoder for Yamux's fixed header and data-frame payload.
#[derive(Debug)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
    offset: usize,
    max_frame_len: u32,
}

impl FrameDecoder {
    /// Creates a decoder that rejects data payloads above `max_frame_len`.
    pub const fn new(max_frame_len: u32) -> Self {
        Self {
            buffer: Vec::new(),
            offset: 0,
            max_frame_len,
        }
    }

    /// Appends ordered connection bytes.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Returns the next complete frame, if available.
    ///
    /// Oversized data frames are rejected as soon as their 12-byte header is
    /// present; the decoder never reserves their declared payload length.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, YamuxError> {
        let available = self.buffer.len() - self.offset;
        if available < HEADER_LEN {
            return Ok(None);
        }
        let header = &self.buffer[self.offset..self.offset + HEADER_LEN];
        if header[0] != 0 {
            return Err(YamuxError::UnsupportedVersion(header[0]));
        }
        let frame_type = FrameType::decode(header[1])?;
        let flags = u16::from_be_bytes([header[2], header[3]]);
        let stream_id = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let value = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
        if frame_type == FrameType::Data && value > self.max_frame_len {
            return Err(YamuxError::FrameTooLarge {
                length: value,
                max: self.max_frame_len,
            });
        }
        let payload_len = if frame_type == FrameType::Data {
            usize::try_from(value).map_err(|_| YamuxError::FrameLengthOverflow)?
        } else {
            0
        };
        let frame_len = HEADER_LEN
            .checked_add(payload_len)
            .ok_or(YamuxError::FrameLengthOverflow)?;
        if available < frame_len {
            return Ok(None);
        }
        let payload_start = self.offset + HEADER_LEN;
        let frame = Frame {
            frame_type,
            flags,
            stream_id,
            value,
            payload: self.buffer[payload_start..payload_start + payload_len].to_vec(),
        };
        frame.validate()?;
        self.offset += frame_len;
        self.compact_if_needed();
        Ok(Some(frame))
    }

    /// Returns unread buffered bytes, including a partial header or payload.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len() - self.offset
    }

    pub(crate) fn clear(&mut self) {
        self.buffer.clear();
        self.offset = 0;
    }

    fn compact_if_needed(&mut self) {
        if self.offset == self.buffer.len() {
            self.clear();
        } else if self.offset >= self.buffer.len() / 2 {
            let remaining = self.buffer.len() - self.offset;
            self.buffer.copy_within(self.offset.., 0);
            self.buffer.truncate(remaining);
            self.offset = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_spec_header_layout() {
        let frame = Frame::data(3, FLAG_SYN | FLAG_FIN, b"abc".to_vec()).unwrap();
        assert_eq!(
            frame.encode(),
            [&[0, 0, 0, 5, 0, 0, 0, 3, 0, 0, 0, 3], b"abc".as_slice()].concat()
        );
    }

    #[test]
    fn decodes_fragmented_and_coalesced_frames() {
        let first = Frame::data(1, FLAG_SYN, b"one".to_vec()).unwrap().encode();
        let second = Frame::window_update(1, FLAG_ACK, 7).unwrap().encode();
        let mut bytes = first.clone();
        bytes.extend_from_slice(&second);
        let mut decoder = FrameDecoder::new(1024);
        for byte in &bytes[..HEADER_LEN - 1] {
            decoder.push(core::slice::from_ref(byte));
            assert_eq!(decoder.next_frame().unwrap(), None);
        }
        decoder.push(&bytes[HEADER_LEN - 1..]);
        assert_eq!(decoder.next_frame().unwrap().unwrap().encode(), first);
        assert_eq!(decoder.next_frame().unwrap().unwrap().encode(), second);
        assert_eq!(decoder.next_frame().unwrap(), None);
        assert_eq!(decoder.buffered_len(), 0);
    }

    #[test]
    fn rejects_oversized_data_from_header_alone() {
        let header = [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 4, 1];
        let mut decoder = FrameDecoder::new(1024);
        decoder.push(&header);
        assert_eq!(
            decoder.next_frame(),
            Err(YamuxError::FrameTooLarge {
                length: 1025,
                max: 1024
            })
        );
        assert_eq!(decoder.buffered_len(), HEADER_LEN);
        assert!(decoder.buffer.capacity() < 1025);
    }
}
