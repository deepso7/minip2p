//! Uni stream headers and the WebTransport stream prefixes.

use alloc::vec::Vec;

use super::varint::{self, VarIntReader};
use super::{frame_type, stream_type};
use crate::VarIntTooLarge;

/// What a uni stream carries, from its first varint (and, for WebTransport,
/// the session id after it).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UniStreamType {
    /// The HTTP/3 control stream.
    Control,
    /// A server push stream; the push id follows.
    Push,
    /// The QPACK encoder stream.
    QpackEncoder,
    /// The QPACK decoder stream.
    QpackDecoder,
    /// A WebTransport uni stream of the given session.
    WebTransport {
        /// The session (CONNECT stream) id.
        session_id: u64,
    },
    /// Any other type; RFC 9114 §6.2 says to abort reading it with
    /// `H3_STREAM_CREATION_ERROR`, not to fail the connection.
    Unknown(u64),
}

/// Incremental decoder for the header of one inbound uni stream. Bytes after
/// the header are left in the input for the stream's own decoder.
#[derive(Clone, Debug, Default)]
pub struct UniStreamHeaderDecoder {
    reader: VarIntReader,
    webtransport: bool,
}

impl UniStreamHeaderDecoder {
    /// A decoder at the start of a uni stream.
    pub fn new() -> Self {
        Self::default()
    }

    /// Consumes header bytes from the front of `input`, returning the stream
    /// type once it is complete, or `None` while more bytes are needed.
    pub fn decode(&mut self, input: &mut &[u8]) -> Option<UniStreamType> {
        if self.webtransport {
            let session_id = self.reader.read(input)?;
            return Some(UniStreamType::WebTransport { session_id });
        }
        let ty = match self.reader.read(input)? {
            stream_type::CONTROL => UniStreamType::Control,
            stream_type::PUSH => UniStreamType::Push,
            stream_type::QPACK_ENCODER => UniStreamType::QpackEncoder,
            stream_type::QPACK_DECODER => UniStreamType::QpackDecoder,
            stream_type::WEBTRANSPORT => {
                self.webtransport = true;
                return self.decode(input);
            }
            other => UniStreamType::Unknown(other),
        };
        Some(ty)
    }
}

/// Appends the header that opens a uni stream of type `ty` to `out`.
pub fn encode_uni_stream_type(ty: UniStreamType, out: &mut Vec<u8>) -> Result<(), VarIntTooLarge> {
    match ty {
        UniStreamType::Control => varint::encode(stream_type::CONTROL, out),
        UniStreamType::Push => varint::encode(stream_type::PUSH, out),
        UniStreamType::QpackEncoder => varint::encode(stream_type::QPACK_ENCODER, out),
        UniStreamType::QpackDecoder => varint::encode(stream_type::QPACK_DECODER, out),
        UniStreamType::WebTransport { session_id } => {
            varint::encode(stream_type::WEBTRANSPORT, out)?;
            varint::encode(session_id, out)
        }
        UniStreamType::Unknown(other) => varint::encode(other, out),
    }
}

/// Appends the `0x41` + session id prefix that opens a WebTransport bidi
/// stream to `out`. The peer's [`FrameDecoder`](super::FrameDecoder) reads it
/// as [`Frame::WebTransportStream`](super::Frame::WebTransportStream).
pub fn encode_webtransport_bidi_header(
    session_id: u64,
    out: &mut Vec<u8>,
) -> Result<(), VarIntTooLarge> {
    varint::encode(frame_type::WEBTRANSPORT_STREAM, out)?;
    varint::encode(session_id, out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h3::{Frame, FrameDecoder};

    #[test]
    fn decodes_each_uni_stream_type() {
        let cases: [(&[u8], UniStreamType); 6] = [
            (&[0x00], UniStreamType::Control),
            (&[0x01], UniStreamType::Push),
            (&[0x02], UniStreamType::QpackEncoder),
            (&[0x03], UniStreamType::QpackDecoder),
            (
                &[0x40, 0x54, 0x04],
                UniStreamType::WebTransport { session_id: 4 },
            ),
            (&[0x21], UniStreamType::Unknown(0x21)),
        ];
        for (bytes, expected) in cases {
            let mut input = bytes;
            assert_eq!(
                UniStreamHeaderDecoder::new().decode(&mut input),
                Some(expected)
            );
            assert!(input.is_empty());
            let mut encoded = Vec::new();
            encode_uni_stream_type(expected, &mut encoded).unwrap();
            let mut input = encoded.as_slice();
            assert_eq!(
                UniStreamHeaderDecoder::new().decode(&mut input),
                Some(expected)
            );
        }
    }

    #[test]
    fn webtransport_uni_header_split_across_chunks() {
        let mut decoder = UniStreamHeaderDecoder::new();
        let mut first: &[u8] = &[0x40];
        assert_eq!(decoder.decode(&mut first), None);
        let mut second: &[u8] = &[0x54, 0x40];
        assert_eq!(decoder.decode(&mut second), None);
        let mut third: &[u8] = &[0x08, 0xff];
        assert_eq!(
            decoder.decode(&mut third),
            Some(UniStreamType::WebTransport { session_id: 8 })
        );
        assert_eq!(third, &[0xff], "payload stays in the input");
    }

    #[test]
    fn bidi_header_round_trips_through_the_frame_decoder() {
        let mut out = Vec::new();
        encode_webtransport_bidi_header(0, &mut out).unwrap();
        assert_eq!(out, [0x40, 0x41, 0x00]);
        out.push(0x99);
        let mut input = out.as_slice();
        assert_eq!(
            FrameDecoder::new().decode(&mut input),
            Ok(Some(Frame::WebTransportStream { session_id: 0 }))
        );
        assert_eq!(input, &[0x99]);
    }
}
