//! HTTP/3 frames (RFC 9114 §7) and SETTINGS.

use alloc::vec::Vec;

use super::frame_type;
use super::varint::{self, VarIntReader};
use crate::{Error, VarIntTooLarge};

/// The largest HEADERS frame payload accepted, before QPACK decoding.
pub const MAX_HEADERS_FRAME_LEN: usize = 16 * 1024;
/// The largest SETTINGS frame payload accepted.
pub const MAX_SETTINGS_FRAME_LEN: usize = 4 * 1024;
/// A GOAWAY, CANCEL_PUSH or MAX_PUSH_ID payload is a single varint.
const MAX_ID_FRAME_LEN: usize = 8;

/// One decoded frame. DATA payloads are streamed as borrowed chunks, so a
/// large DATA frame arrives as several `Data` items; the other frames are
/// buffered whole within their caps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Frame<'a> {
    /// A chunk of a DATA frame payload. An empty DATA frame yields one
    /// empty chunk; a non-empty one never does.
    Data(&'a [u8]),
    /// A HEADERS frame's QPACK field section.
    Headers(Vec<u8>),
    /// A SETTINGS frame.
    Settings(Settings),
    /// A GOAWAY frame with its stream or push id.
    GoAway(u64),
    /// A CANCEL_PUSH frame with its push id. Reported rather than skipped,
    /// like [`Frame::MaxPushId`], so a caller can enforce that it appears
    /// only on the control stream and check its id (RFC 9114 §7.2.3).
    CancelPush(u64),
    /// A MAX_PUSH_ID frame with its push id (RFC 9114 §7.2.7).
    MaxPushId(u64),
    /// The `0x41` signal that opens a WebTransport bidi stream, with its
    /// session id. Every later byte on the stream is application data, so
    /// stop feeding this decoder.
    WebTransportStream {
        /// The session (CONNECT stream) id.
        session_id: u64,
    },
}

/// Incremental frame decoder for one HTTP/3 stream.
///
/// Feed it every byte the stream delivers, in order, through
/// [`FrameDecoder::decode`]. Unknown and reserved frame types are skipped;
/// DATA payloads stream through without buffering. An error is fatal: close
/// the stream or connection with [`Error::code`] and drop the decoder.
#[derive(Clone, Debug, Default)]
pub struct FrameDecoder {
    state: State,
    reader: VarIntReader,
    buf: Vec<u8>,
    /// The type of the stream's first frame, once read; `0x41` is only
    /// legal as that first type.
    first_type: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default)]
enum State {
    #[default]
    Type,
    Length {
        ty: u64,
    },
    SessionId,
    Data {
        remaining: u64,
    },
    Buffer {
        ty: u64,
        len: usize,
    },
    Skip {
        remaining: u64,
    },
}

impl FrameDecoder {
    /// A decoder at the start of a stream.
    pub fn new() -> Self {
        Self::default()
    }

    /// Consumes bytes from the front of `input` until one frame (or DATA
    /// chunk) is complete, returning it, or returns `Ok(None)` once `input`
    /// is exhausted.
    pub fn decode<'a>(&mut self, input: &mut &'a [u8]) -> Result<Option<Frame<'a>>, Error> {
        loop {
            match self.state {
                State::Type => {
                    let Some(ty) = self.reader.read(input) else {
                        return Ok(None);
                    };
                    let first = self.first_type.is_none();
                    self.first_type.get_or_insert(ty);
                    if ty == frame_type::WEBTRANSPORT_STREAM {
                        if !first {
                            return Err(Error::Frame);
                        }
                        self.state = State::SessionId;
                    } else if is_forbidden(ty) {
                        return Err(Error::FrameUnexpected);
                    } else {
                        self.state = State::Length { ty };
                    }
                }
                State::SessionId => {
                    let Some(session_id) = self.reader.read(input) else {
                        return Ok(None);
                    };
                    // Nothing after this is framed; park in `Skip` so that a
                    // stray `decode` call cannot misparse application data.
                    self.state = State::Skip {
                        remaining: u64::MAX,
                    };
                    return Ok(Some(Frame::WebTransportStream { session_id }));
                }
                State::Length { ty } => {
                    let Some(len) = self.reader.read(input) else {
                        return Ok(None);
                    };
                    // Reported, not skipped, so callers can reject DATA
                    // where RFC 9114 forbids it whatever its length.
                    if ty == frame_type::DATA && len == 0 {
                        self.state = State::Type;
                        return Ok(Some(Frame::Data(&[])));
                    }
                    self.state = self.start_payload(ty, len)?;
                }
                // Never zero: an empty DATA frame is reported from `Length`.
                State::Data { remaining } => {
                    if input.is_empty() {
                        return Ok(None);
                    }
                    let chunk = take(input, remaining);
                    // Leave the frame with its last chunk, so the decoder is
                    // at a boundary as soon as that chunk is returned.
                    self.state = match remaining - chunk.len() as u64 {
                        0 => State::Type,
                        remaining => State::Data { remaining },
                    };
                    return Ok(Some(Frame::Data(chunk)));
                }
                State::Skip { remaining } => {
                    if remaining == 0 {
                        self.state = State::Type;
                        continue;
                    }
                    if input.is_empty() {
                        return Ok(None);
                    }
                    let skipped = take(input, remaining).len() as u64;
                    self.state = State::Skip {
                        remaining: remaining - skipped,
                    };
                }
                State::Buffer { ty, len } => {
                    let want = len - self.buf.len();
                    self.buf.extend_from_slice(take(input, want as u64));
                    if self.buf.len() < len {
                        return Ok(None);
                    }
                    self.state = State::Type;
                    let payload = core::mem::take(&mut self.buf);
                    return finish(ty, payload).map(Some);
                }
            }
        }
    }

    /// Whether the decoder sits between frames. A stream that ends anywhere
    /// else ended mid-frame, which RFC 9114 §7.1 makes `H3_FRAME_ERROR`.
    pub fn is_at_frame_boundary(&self) -> bool {
        matches!(self.state, State::Type) && self.reader.is_empty()
    }

    /// The type of the stream's first frame, once its type is read, even if
    /// that frame was skipped. A control stream checks it is SETTINGS
    /// (RFC 9114 §6.2.1).
    pub fn first_frame_type(&self) -> Option<u64> {
        self.first_type
    }

    fn start_payload(&mut self, ty: u64, len: u64) -> Result<State, Error> {
        let cap = match ty {
            frame_type::DATA => return Ok(State::Data { remaining: len }),
            frame_type::HEADERS => MAX_HEADERS_FRAME_LEN,
            frame_type::SETTINGS => MAX_SETTINGS_FRAME_LEN,
            frame_type::GOAWAY | frame_type::CANCEL_PUSH | frame_type::MAX_PUSH_ID => {
                MAX_ID_FRAME_LEN
            }
            _ => return Ok(State::Skip { remaining: len }),
        };
        let len = usize::try_from(len).ok().ok_or(Error::ExcessiveLoad)?;
        if len > cap {
            return Err(if cap == MAX_ID_FRAME_LEN {
                Error::Frame
            } else {
                Error::ExcessiveLoad
            });
        }
        // The buffer grows with what arrives: a declared length alone
        // reserves nothing.
        self.buf = Vec::new();
        Ok(State::Buffer { ty, len })
    }
}

/// HTTP/2-only frame types (RFC 9114 §7.2.8) and PUSH_PROMISE, which only a
/// server that was sent MAX_PUSH_ID may send. Neither side here enables push.
fn is_forbidden(ty: u64) -> bool {
    matches!(ty, 0x02 | 0x06 | 0x08 | 0x09) || ty == frame_type::PUSH_PROMISE
}

/// Takes at most `max` bytes off the front of `input`.
fn take<'a>(input: &mut &'a [u8], max: u64) -> &'a [u8] {
    let n = usize::try_from(max).unwrap_or(usize::MAX).min(input.len());
    let (chunk, rest) = input.split_at(n);
    *input = rest;
    chunk
}

fn finish(ty: u64, payload: Vec<u8>) -> Result<Frame<'static>, Error> {
    match ty {
        frame_type::HEADERS => Ok(Frame::Headers(payload)),
        frame_type::SETTINGS => Settings::decode_payload(&payload).map(Frame::Settings),
        _ => {
            let id = match varint::decode(&payload) {
                Some((id, used)) if used == payload.len() => id,
                _ => return Err(Error::Frame),
            };
            Ok(match ty {
                frame_type::CANCEL_PUSH => Frame::CancelPush(id),
                frame_type::MAX_PUSH_ID => Frame::MaxPushId(id),
                _ => Frame::GoAway(id),
            })
        }
    }
}

/// Appends a frame of type `ty` carrying `payload` to `out`.
pub fn encode_frame(ty: u64, payload: &[u8], out: &mut Vec<u8>) -> Result<(), VarIntTooLarge> {
    varint::encode(ty, out)?;
    varint::encode(payload.len() as u64, out)?;
    out.extend_from_slice(payload);
    Ok(())
}

/// Appends a GOAWAY frame carrying `id` to `out`.
pub fn encode_goaway(id: u64, out: &mut Vec<u8>) -> Result<(), VarIntTooLarge> {
    let mut payload = Vec::new();
    varint::encode(id, &mut payload)?;
    encode_frame(frame_type::GOAWAY, &payload, out)
}

/// The identifier/value pairs of a SETTINGS frame, in wire order, with no
/// identifier repeated.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Settings {
    entries: Vec<(u64, u64)>,
}

impl Settings {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets `id` to `value`, replacing an earlier value for the same id.
    pub fn set(&mut self, id: u64, value: u64) -> &mut Self {
        match self
            .entries
            .iter_mut()
            .find(|(existing, _)| *existing == id)
        {
            Some(entry) => entry.1 = value,
            None => self.entries.push((id, value)),
        }
        self
    }

    /// The value of `id`, if present.
    pub fn get(&self, id: u64) -> Option<u64> {
        self.entries
            .iter()
            .find(|(existing, _)| *existing == id)
            .map(|&(_, value)| value)
    }

    /// The pairs in wire order.
    pub fn iter(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.entries.iter().copied()
    }

    /// Decodes a SETTINGS frame payload. A repeated identifier or an
    /// HTTP/2-only one (`0x02`..=`0x05`) is [`Error::Settings`]; a truncated
    /// pair is [`Error::Frame`].
    pub fn decode_payload(mut payload: &[u8]) -> Result<Self, Error> {
        let mut settings = Self::new();
        while !payload.is_empty() {
            let (id, used) = varint::decode(payload).ok_or(Error::Frame)?;
            let rest = payload.get(used..).ok_or(Error::Frame)?;
            let (value, used) = varint::decode(rest).ok_or(Error::Frame)?;
            payload = rest.get(used..).ok_or(Error::Frame)?;
            if (0x02..=0x05).contains(&id) || settings.get(id).is_some() {
                return Err(Error::Settings);
            }
            settings.entries.push((id, value));
        }
        Ok(settings)
    }

    /// Appends these settings as a complete SETTINGS frame to `out`.
    pub fn encode_frame(&self, out: &mut Vec<u8>) -> Result<(), VarIntTooLarge> {
        let mut payload = Vec::new();
        for &(id, value) in &self.entries {
            varint::encode(id, &mut payload)?;
            varint::encode(value, &mut payload)?;
        }
        encode_frame(frame_type::SETTINGS, &payload, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h3::setting;

    fn decode_all<'a>(
        decoder: &mut FrameDecoder,
        mut input: &'a [u8],
    ) -> Result<Vec<Frame<'a>>, Error> {
        let mut frames = Vec::new();
        while let Some(frame) = decoder.decode(&mut input)? {
            frames.push(frame);
        }
        Ok(frames)
    }

    #[test]
    fn decodes_settings_headers_data_and_goaway() {
        let bytes = [
            0x04, 0x04, 0x08, 0x01, 0x33, 0x01, // SETTINGS 0x08=1, 0x33=1
            0x01, 0x03, 0x00, 0x00, 0xd9, // HEADERS :status 200
            0x00, 0x02, 0xaa, 0xbb, // DATA
            0x07, 0x01, 0x04, // GOAWAY 4
        ];
        let mut decoder = FrameDecoder::new();
        let frames = decode_all(&mut decoder, &bytes).unwrap();
        let mut settings = Settings::new();
        settings.set(setting::ENABLE_CONNECT_PROTOCOL, 1);
        settings.set(setting::H3_DATAGRAM, 1);
        assert_eq!(
            frames,
            [
                Frame::Settings(settings),
                Frame::Headers(alloc::vec![0x00, 0x00, 0xd9]),
                Frame::Data(&[0xaa, 0xbb]),
                Frame::GoAway(4),
            ]
        );
        assert!(decoder.is_at_frame_boundary());
    }

    #[test]
    fn an_empty_data_frame_is_reported() {
        let mut decoder = FrameDecoder::new();
        assert_eq!(
            decode_all(&mut decoder, &[0x00, 0x00, 0x00, 0x01, 0xaa]),
            Ok(alloc::vec![Frame::Data(&[]), Frame::Data(&[0xaa])])
        );
        assert!(decoder.is_at_frame_boundary());
    }

    #[test]
    fn frames_split_byte_by_byte_decode_the_same() {
        let bytes = [
            0x21, 0x02, 0xee, 0xee, 0x01, 0x03, 0x00, 0x00, 0xd9, 0x00, 0x02, 0xaa, 0xbb,
        ];
        let mut decoder = FrameDecoder::new();
        let mut headers = Vec::new();
        let mut data = Vec::new();
        for byte in bytes.chunks(1) {
            for frame in decode_all(&mut decoder, byte).unwrap() {
                match frame {
                    Frame::Headers(block) => headers = block,
                    Frame::Data(chunk) => data.extend_from_slice(chunk),
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
        assert_eq!(headers, [0x00, 0x00, 0xd9]);
        assert_eq!(data, [0xaa, 0xbb]);
    }

    #[test]
    fn unknown_frames_are_skipped_without_buffering() {
        // A reserved (GREASE) type 0x21 with a 1 MiB length claim.
        let mut decoder = FrameDecoder::new();
        let mut header: &[u8] = &[0x21, 0x80, 0x10, 0x00, 0x00];
        assert_eq!(decoder.decode(&mut header), Ok(None));
        let chunk = [0u8; 4096];
        for _ in 0..256 {
            let mut input: &[u8] = &chunk;
            assert_eq!(decoder.decode(&mut input), Ok(None));
        }
        assert!(decoder.is_at_frame_boundary());
    }

    #[test]
    fn webtransport_stream_signal_is_only_legal_first() {
        let mut decoder = FrameDecoder::new();
        let mut input: &[u8] = &[0x40, 0x41, 0x04, 0xde, 0xad];
        assert_eq!(
            decoder.decode(&mut input),
            Ok(Some(Frame::WebTransportStream { session_id: 4 }))
        );
        assert_eq!(input, &[0xde, 0xad]);

        let mut decoder = FrameDecoder::new();
        assert_eq!(
            decode_all(&mut decoder, &[0x00, 0x00, 0x40, 0x41, 0x04]),
            Err(Error::Frame)
        );
    }

    #[test]
    fn http2_frame_types_and_push_promise_are_unexpected() {
        for ty in [0x02, 0x05, 0x06, 0x08, 0x09] {
            let mut decoder = FrameDecoder::new();
            assert_eq!(
                decode_all(&mut decoder, &[ty, 0x00]),
                Err(Error::FrameUnexpected)
            );
        }
    }

    #[test]
    fn push_control_frames_are_reported_not_skipped() {
        // CANCEL_PUSH 1, then MAX_PUSH_ID 2^14 (a two-byte varint).
        let mut decoder = FrameDecoder::new();
        assert_eq!(
            decode_all(&mut decoder, &[0x03, 0x01, 0x01, 0x0d, 0x04, 0x80, 0x00, 0x40, 0x00]),
            Ok(alloc::vec![Frame::CancelPush(1), Frame::MaxPushId(1 << 14)])
        );
        // A trailing byte after the push id is malformed.
        let mut decoder = FrameDecoder::new();
        assert_eq!(
            decode_all(&mut decoder, &[0x0d, 0x02, 0x01, 0x00]),
            Err(Error::Frame)
        );
    }

    #[test]
    fn oversized_frames_are_rejected_before_buffering() {
        // HEADERS of 16 KiB + 1 and SETTINGS of 4 KiB + 1, payload never sent.
        let mut decoder = FrameDecoder::new();
        assert_eq!(
            decode_all(&mut decoder, &[0x01, 0x80, 0x00, 0x40, 0x01]),
            Err(Error::ExcessiveLoad)
        );
        let mut decoder = FrameDecoder::new();
        assert_eq!(
            decode_all(&mut decoder, &[0x04, 0x50, 0x01]),
            Err(Error::ExcessiveLoad)
        );
        let mut decoder = FrameDecoder::new();
        assert_eq!(decode_all(&mut decoder, &[0x07, 0x09]), Err(Error::Frame));
    }

    #[test]
    fn the_last_data_chunk_leaves_the_decoder_at_a_boundary() {
        let mut decoder = FrameDecoder::new();
        let mut input: &[u8] = &[0x00, 0x02, 0xaa, 0xbb];
        assert_eq!(
            decoder.decode(&mut input),
            Ok(Some(Frame::Data(&[0xaa, 0xbb])))
        );
        assert!(decoder.is_at_frame_boundary());
    }

    #[test]
    fn a_stream_ending_mid_frame_is_not_at_a_boundary() {
        let mut decoder = FrameDecoder::new();
        assert_eq!(
            decode_all(&mut decoder, &[0x01, 0x03, 0x00]),
            Ok(Vec::new())
        );
        assert!(!decoder.is_at_frame_boundary());
        let mut decoder = FrameDecoder::new();
        assert_eq!(decode_all(&mut decoder, &[0x40]), Ok(Vec::new()));
        assert!(!decoder.is_at_frame_boundary());
    }

    #[test]
    fn settings_reject_duplicates_http2_ids_and_truncation() {
        assert_eq!(
            Settings::decode_payload(&[0x08, 0x01, 0x08, 0x00]),
            Err(Error::Settings)
        );
        for id in 0x02..=0x05 {
            assert_eq!(Settings::decode_payload(&[id, 0x00]), Err(Error::Settings));
        }
        assert_eq!(Settings::decode_payload(&[0x08]), Err(Error::Frame));
        assert_eq!(Settings::decode_payload(&[0x08, 0x40]), Err(Error::Frame));
        // GOAWAY with trailing bytes is malformed.
        let mut decoder = FrameDecoder::new();
        assert_eq!(
            decode_all(&mut decoder, &[0x07, 0x02, 0x04, 0x00]),
            Err(Error::Frame)
        );
    }

    #[test]
    fn settings_encode_round_trips() {
        let mut settings = Settings::new();
        settings
            .set(setting::ENABLE_WEBTRANSPORT, 1)
            .set(setting::WT_INITIAL_MAX_DATA, 1 << 60)
            .set(setting::ENABLE_WEBTRANSPORT, 0);
        let mut out = Vec::new();
        settings.encode_frame(&mut out).unwrap();
        assert_eq!(
            out,
            [
                0x04, 0x0f, // SETTINGS, 15 bytes
                0xab, 0x60, 0x37, 0x42, 0x00, // ENABLE_WEBTRANSPORT = 0
                0x6b, 0x61, 0xd0, 0, 0, 0, 0, 0, 0, 0, // WT_INITIAL_MAX_DATA = 2^60
            ]
        );
        let mut decoder = FrameDecoder::new();
        assert_eq!(
            decode_all(&mut decoder, &out),
            Ok(alloc::vec![Frame::Settings(settings)])
        );
    }
}
