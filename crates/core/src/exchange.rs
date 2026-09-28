//! One side of a length-prefixed request/response exchange.
//!
//! Every protocol that speaks `<uvarint length><payload>` frames over a stream
//! repeats the same three things: a buffer of bytes to send, a buffer of bytes
//! received so far, and a loop that pulls whole frames out of the second one.
//! [`FrameExchange`] owns those three; each protocol keeps its own messages,
//! states, errors and policy for what may follow a frame.
//!
//! The receive buffer is bounded. A frame whose declared length is over the
//! maximum is rejected from its header alone by [`decode_frame`], and bytes
//! that could never become a legal frame are refused before they are copied in,
//! so a peer cannot grow the buffer by sending a prefix it never completes.

use alloc::vec::Vec;

use minip2p_identity::uvarint_len;
use thiserror::Error;

use crate::frame::{FrameDecode, decode_frame, encode_frame};
use crate::protobuf::WireError;

/// A framing failure, before any protocol meaning is read from the bytes.
///
/// Protocols map this onto their own error type; the variants carry the limit
/// they crossed so that mapping needs no extra context.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum FrameFault {
    /// The frame header declared a payload larger than the maximum.
    #[error("frame length {len} exceeds the maximum of {max}")]
    TooLarge {
        /// The declared payload length.
        len: u64,
        /// The maximum this exchange accepts.
        max: usize,
    },
    /// More bytes are buffered than any legal frame could need.
    #[error("{len} buffered bytes exceed the receive limit of {limit}")]
    Overflow {
        /// What the buffer would have held.
        len: usize,
        /// The receive limit.
        limit: usize,
    },
    /// The frame header is malformed.
    #[error(transparent)]
    Wire(#[from] WireError),
}

/// Buffers one side of a framed exchange: bytes to send, bytes received, and
/// the decode loop between them.
#[derive(Clone, Debug)]
pub struct FrameExchange {
    outbound: Vec<u8>,
    recv: Vec<u8>,
    max_len: usize,
    recv_limit: usize,
}

impl FrameExchange {
    /// An exchange bounded at one maximal frame.
    ///
    /// Use this where a peer that sends more before we have parsed what it
    /// already sent is out of spec.
    pub fn new(max_len: usize) -> Self {
        Self::with_trailing(max_len, 0)
    }

    /// An exchange that also tolerates `trailing` bytes behind the frame being
    /// parsed.
    ///
    /// For a protocol that pipelines (DCUtR's SYNC can arrive with CONNECT) or
    /// hands the remainder on (the relay passes bytes after HOP to the bridged
    /// stream), those bytes are legal and must not be refused with the frame
    /// they arrived with.
    pub fn with_trailing(max_len: usize, trailing: usize) -> Self {
        Self {
            outbound: Vec::new(),
            recv: Vec::new(),
            max_len,
            recv_limit: max_len
                .saturating_add(uvarint_len(max_len as u64))
                .saturating_add(trailing),
        }
    }

    /// The largest payload this exchange sends or accepts.
    pub const fn max_len(&self) -> usize {
        self.max_len
    }

    /// Frames `payload` and queues it for sending.
    ///
    /// Rejects a payload over [`max_len`](Self::max_len) rather than putting a
    /// frame on the wire that a compliant peer must refuse.
    pub fn queue(&mut self, payload: &[u8]) -> Result<(), FrameFault> {
        if payload.len() > self.max_len {
            return Err(FrameFault::TooLarge {
                len: payload.len() as u64,
                max: self.max_len,
            });
        }
        self.outbound.extend_from_slice(&encode_frame(payload));
        Ok(())
    }

    /// Takes the queued bytes, leaving the send buffer empty.
    pub fn take_outbound(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outbound)
    }

    /// Returns true while bytes are waiting to be sent.
    pub fn has_outbound(&self) -> bool {
        !self.outbound.is_empty()
    }

    /// Buffers received bytes.
    ///
    /// Refuses them — before copying — when they could not be part of a legal
    /// frame, so an unbounded chunk is never held.
    pub fn push(&mut self, data: &[u8]) -> Result<(), FrameFault> {
        let len = self.recv.len().saturating_add(data.len());
        if len > self.recv_limit {
            return Err(FrameFault::Overflow {
                len,
                limit: self.recv_limit,
            });
        }
        self.recv.extend_from_slice(data);
        Ok(())
    }

    /// Decodes the next complete frame, if one is buffered.
    ///
    /// `decode` sees the payload alone, without its length prefix, and returns
    /// the protocol's own message type. The frame is consumed whether or not
    /// `decode` succeeds, so a rejected message never leaves half a frame
    /// behind for the next call to trip over.
    pub fn next_frame<T, E>(
        &mut self,
        decode: impl FnOnce(&[u8]) -> Result<T, E>,
    ) -> Result<Option<T>, E>
    where
        E: From<FrameFault>,
    {
        let (decoded, consumed) = match decode_frame(&self.recv, self.max_len) {
            FrameDecode::Complete { payload, consumed } => (decode(payload), consumed),
            FrameDecode::Incomplete => return Ok(None),
            FrameDecode::TooLarge { len } => {
                return Err(FrameFault::TooLarge {
                    len,
                    max: self.max_len,
                }
                .into());
            }
            FrameDecode::Error(e) => return Err(FrameFault::Wire(WireError::from(e)).into()),
        };
        self.recv.drain(..consumed);
        decoded.map(Some)
    }

    /// The bytes received but not yet consumed by [`next_frame`](Self::next_frame).
    pub fn buffered(&self) -> &[u8] {
        &self.recv
    }

    /// Takes the unconsumed bytes, leaving the receive buffer empty.
    ///
    /// This is how a protocol hands on what follows its last frame: the relay
    /// gives it to the bridged stream, DCUtR keeps what arrived behind CONNECT.
    pub fn take_buffered(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.recv)
    }

    /// Drops the unconsumed bytes and releases the buffer.
    pub fn clear_buffered(&mut self) {
        self.recv = Vec::new();
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    const MAX: usize = 8192;
    /// `MAX` is below 2^14, so its length prefix is two bytes.
    const PREFIX: usize = 2;

    /// The payload decoder used by the tests: every frame is its own bytes.
    fn identity(payload: &[u8]) -> Result<Vec<u8>, FrameFault> {
        Ok(payload.to_vec())
    }

    #[test]
    fn frame_at_max_len_is_accepted() {
        let mut ex = FrameExchange::new(MAX);
        let framed = encode_frame(&vec![0x5a; MAX]);
        assert_eq!(framed.len(), MAX + PREFIX);

        ex.push(&framed).expect("a maximal frame fits");
        assert_eq!(ex.next_frame(identity).unwrap().unwrap().len(), MAX);
        assert!(ex.buffered().is_empty());
    }

    #[test]
    fn declared_len_above_max_is_rejected_from_the_header() {
        let mut ex = FrameExchange::new(MAX);
        // 8193 as a minimal uvarint, with no payload behind it.
        ex.push(&[0x81, 0x40]).expect("two bytes fit");
        assert_eq!(
            ex.next_frame(identity).unwrap_err(),
            FrameFault::TooLarge {
                len: MAX as u64 + 1,
                max: MAX
            }
        );
    }

    #[test]
    fn a_chunk_over_the_limit_is_refused_before_it_is_buffered() {
        let mut ex = FrameExchange::new(MAX);
        let oversized = vec![0u8; MAX + PREFIX + 1];

        assert_eq!(
            ex.push(&oversized).unwrap_err(),
            FrameFault::Overflow {
                len: MAX + PREFIX + 1,
                limit: MAX + PREFIX
            }
        );
        assert!(ex.buffered().is_empty(), "the chunk was not copied in");
    }

    #[test]
    fn a_stalled_frame_cannot_grow_past_the_limit() {
        let mut ex = FrameExchange::new(MAX);
        // A header promising a maximal payload, then bytes that never complete it.
        ex.push(&encode_frame(&vec![0u8; MAX])[..MAX]).unwrap();
        assert!(ex.next_frame(identity).unwrap().is_none());

        assert!(matches!(
            ex.push(&vec![0u8; MAX]),
            Err(FrameFault::Overflow { .. })
        ));
    }

    #[test]
    fn trailing_bytes_ride_along_when_the_protocol_allows_them() {
        let mut ex = FrameExchange::with_trailing(MAX, MAX);
        let mut chunk = encode_frame(&vec![0x5a; MAX]);
        chunk.extend_from_slice(b"pipelined");

        ex.push(&chunk)
            .expect("a maximal frame plus trailing bytes");
        assert_eq!(ex.next_frame(identity).unwrap().unwrap().len(), MAX);
        assert_eq!(ex.buffered(), b"pipelined");
        assert_eq!(ex.take_buffered(), b"pipelined");
        assert!(ex.buffered().is_empty());
    }

    #[test]
    fn a_frame_split_across_reads_decodes_once_it_completes() {
        let mut ex = FrameExchange::new(MAX);
        let framed = encode_frame(b"hello");

        for byte in &framed[..framed.len() - 1] {
            ex.push(&[*byte]).unwrap();
            assert!(ex.next_frame(identity).unwrap().is_none());
        }
        ex.push(&framed[framed.len() - 1..]).unwrap();
        assert_eq!(ex.next_frame(identity).unwrap().unwrap(), b"hello");
    }

    #[test]
    fn frames_are_consumed_one_at_a_time() {
        let mut ex = FrameExchange::new(MAX);
        let mut chunk = encode_frame(b"first");
        chunk.extend_from_slice(&encode_frame(b"second"));

        ex.push(&chunk).unwrap();
        assert_eq!(ex.next_frame(identity).unwrap().unwrap(), b"first");
        assert_eq!(ex.next_frame(identity).unwrap().unwrap(), b"second");
        assert!(ex.next_frame(identity).unwrap().is_none());
    }

    #[test]
    fn a_malformed_header_is_a_wire_fault() {
        let mut ex = FrameExchange::new(MAX);
        // Non-minimal length prefix.
        ex.push(&[0x81, 0x00, 0xaa]).unwrap();
        assert!(matches!(
            ex.next_frame(identity).unwrap_err(),
            FrameFault::Wire(_)
        ));
    }

    #[test]
    fn a_rejected_message_still_consumes_its_frame() {
        let mut ex = FrameExchange::new(MAX);
        let mut chunk = encode_frame(b"bad");
        chunk.extend_from_slice(&encode_frame(b"good"));
        ex.push(&chunk).unwrap();

        let rejected: Result<Option<()>, FrameFault> =
            ex.next_frame(|_| Err(FrameFault::Overflow { len: 0, limit: 0 }));
        assert!(matches!(rejected, Err(FrameFault::Overflow { .. })));
        assert_eq!(ex.next_frame(identity).unwrap().unwrap(), b"good");
    }

    #[test]
    fn queue_frames_the_payload_and_refuses_an_oversized_one() {
        let mut ex = FrameExchange::new(MAX);
        ex.queue(b"request").unwrap();
        assert!(ex.has_outbound());
        assert_eq!(ex.take_outbound(), encode_frame(b"request"));
        assert!(!ex.has_outbound());

        assert_eq!(
            ex.queue(&vec![0u8; MAX + 1]).unwrap_err(),
            FrameFault::TooLarge {
                len: MAX as u64 + 1,
                max: MAX
            }
        );
        assert!(!ex.has_outbound(), "a refused payload queues nothing");
    }

    #[test]
    fn queued_frames_keep_their_order() {
        let mut ex = FrameExchange::new(MAX);
        ex.queue(b"one").unwrap();
        ex.queue(b"two").unwrap();

        let mut expected = encode_frame(b"one");
        expected.extend_from_slice(&encode_frame(b"two"));
        assert_eq!(ex.take_outbound(), expected);
    }
}
