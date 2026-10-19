//! Capsules (RFC 9297 §3) on the WebTransport CONNECT stream.

use alloc::string::String;
use alloc::vec::Vec;

use super::varint::{self, VarIntReader};
use crate::{Error, VarIntTooLarge};

/// The largest capsule accepted. Unknown capsules up to this size are
/// skipped without buffering; larger ones are [`Error::ExcessiveLoad`].
pub const MAX_CAPSULE_LEN: usize = 64 * 1024;
/// The longest close reason the WebTransport drafts allow, in bytes.
pub const MAX_CLOSE_REASON_LEN: usize = 1024;

const CLOSE_WEBTRANSPORT_SESSION: u64 = 0x2843;
const WT_MAX_DATA: u64 = 0x190b_4d3d;
const WT_MAX_STREAMS_BIDI: u64 = 0x190b_4d3f;
const WT_MAX_STREAMS_UNI: u64 = 0x190b_4d40;

/// A capsule this codec understands. Others are skipped by the decoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Capsule {
    /// `CLOSE_WEBTRANSPORT_SESSION` (`0x2843`): the session is closing.
    CloseSession {
        /// The application error code.
        code: u32,
        /// A UTF-8 reason of at most [`MAX_CLOSE_REASON_LEN`] bytes.
        reason: String,
    },
    /// `WT_MAX_DATA`: the peer's new session data limit.
    MaxData(u64),
    /// `WT_MAX_STREAMS` (bidi): the peer's new bidi stream limit.
    MaxStreamsBidi(u64),
    /// `WT_MAX_STREAMS` (uni): the peer's new uni stream limit.
    MaxStreamsUni(u64),
}

impl Capsule {
    /// Appends this capsule to `out`. Wrap the result in a DATA frame to send
    /// it on the CONNECT stream. A close reason longer than
    /// [`MAX_CLOSE_REASON_LEN`] is cut at the last char boundary that fits.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), VarIntTooLarge> {
        let (ty, body) = match self {
            Capsule::CloseSession { code, reason } => {
                let mut cut = reason.len().min(MAX_CLOSE_REASON_LEN);
                while !reason.is_char_boundary(cut) {
                    cut -= 1;
                }
                let mut body = code.to_be_bytes().to_vec();
                body.extend_from_slice(reason.as_bytes().get(..cut).unwrap_or_default());
                (CLOSE_WEBTRANSPORT_SESSION, body)
            }
            Capsule::MaxData(value) => (WT_MAX_DATA, varint_bytes(*value)?),
            Capsule::MaxStreamsBidi(value) => (WT_MAX_STREAMS_BIDI, varint_bytes(*value)?),
            Capsule::MaxStreamsUni(value) => (WT_MAX_STREAMS_UNI, varint_bytes(*value)?),
        };
        varint::encode(ty, out)?;
        varint::encode(body.len() as u64, out)?;
        out.extend_from_slice(&body);
        Ok(())
    }
}

fn varint_bytes(value: u64) -> Result<Vec<u8>, VarIntTooLarge> {
    let mut out = Vec::new();
    varint::encode(value, &mut out)?;
    Ok(out)
}

/// Incremental capsule decoder for the CONNECT stream's DATA payloads.
///
/// Feed it every [`Frame::Data`](super::Frame::Data) chunk in order;
/// capsules may span DATA frames. Only start feeding it after the 2xx
/// response. An error is fatal to the session.
#[derive(Clone, Debug, Default)]
pub struct CapsuleDecoder {
    state: State,
    reader: VarIntReader,
    buf: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default)]
enum State {
    #[default]
    Type,
    Length {
        ty: u64,
    },
    Body {
        ty: u64,
        len: usize,
    },
    Skip {
        remaining: usize,
    },
}

impl CapsuleDecoder {
    /// A decoder at a capsule boundary.
    pub fn new() -> Self {
        Self::default()
    }

    /// Consumes bytes from the front of `input` until a known capsule is
    /// complete, returning it, or returns `Ok(None)` once `input` is
    /// exhausted.
    pub fn decode(&mut self, input: &mut &[u8]) -> Result<Option<Capsule>, Error> {
        loop {
            match self.state {
                State::Type => {
                    let Some(ty) = self.reader.read(input) else {
                        return Ok(None);
                    };
                    self.state = State::Length { ty };
                }
                State::Length { ty } => {
                    let Some(len) = self.reader.read(input) else {
                        return Ok(None);
                    };
                    let len = usize::try_from(len)
                        .ok()
                        .filter(|&len| len <= MAX_CAPSULE_LEN)
                        .ok_or(Error::ExcessiveLoad)?;
                    self.state = match ty {
                        CLOSE_WEBTRANSPORT_SESSION
                            if (4..=4 + MAX_CLOSE_REASON_LEN).contains(&len) =>
                        {
                            State::Body { ty, len }
                        }
                        WT_MAX_DATA | WT_MAX_STREAMS_BIDI | WT_MAX_STREAMS_UNI
                            if (1..=8).contains(&len) =>
                        {
                            State::Body { ty, len }
                        }
                        CLOSE_WEBTRANSPORT_SESSION
                        | WT_MAX_DATA
                        | WT_MAX_STREAMS_BIDI
                        | WT_MAX_STREAMS_UNI => return Err(Error::Message),
                        _ => State::Skip { remaining: len },
                    };
                }
                State::Body { ty, len } => {
                    let take = (len - self.buf.len()).min(input.len());
                    let (chunk, rest) = input.split_at(take);
                    self.buf.extend_from_slice(chunk);
                    *input = rest;
                    if self.buf.len() < len {
                        return Ok(None);
                    }
                    self.state = State::Type;
                    let body = core::mem::take(&mut self.buf);
                    return parse(ty, &body).map(Some);
                }
                State::Skip { remaining } => {
                    if remaining == 0 {
                        self.state = State::Type;
                        continue;
                    }
                    if input.is_empty() {
                        return Ok(None);
                    }
                    let take = remaining.min(input.len());
                    *input = input.get(take..).unwrap_or_default();
                    self.state = State::Skip {
                        remaining: remaining - take,
                    };
                }
            }
        }
    }

    /// Whether the decoder sits between capsules. A CONNECT stream that ends
    /// anywhere else ended mid-capsule, a malformed message.
    pub fn is_at_capsule_boundary(&self) -> bool {
        matches!(self.state, State::Type) && self.reader.is_empty()
    }
}

fn parse(ty: u64, body: &[u8]) -> Result<Capsule, Error> {
    if ty == CLOSE_WEBTRANSPORT_SESSION {
        let (code, reason) = body.split_first_chunk::<4>().ok_or(Error::Message)?;
        let reason = core::str::from_utf8(reason).ok().ok_or(Error::Message)?;
        return Ok(Capsule::CloseSession {
            code: u32::from_be_bytes(*code),
            reason: reason.into(),
        });
    }
    let value = match varint::decode(body) {
        Some((value, used)) if used == body.len() => value,
        _ => return Err(Error::Message),
    };
    Ok(match ty {
        WT_MAX_DATA => Capsule::MaxData(value),
        WT_MAX_STREAMS_BIDI => Capsule::MaxStreamsBidi(value),
        _ => Capsule::MaxStreamsUni(value),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(decoder: &mut CapsuleDecoder, mut input: &[u8]) -> Result<Vec<Capsule>, Error> {
        let mut capsules = Vec::new();
        while let Some(capsule) = decoder.decode(&mut input)? {
            capsules.push(capsule);
        }
        Ok(capsules)
    }

    #[test]
    fn decodes_close_and_flow_control_capsules() {
        let bytes = [
            0x68, 0x43, 0x07, 0x00, 0x00, 0x00, 0x07, b'b', b'y', b'e', // CLOSE 7 "bye"
            0x99, 0x0b, 0x4d, 0x3d, 0x02, 0x40, 0x64, // WT_MAX_DATA 100
            0x99, 0x0b, 0x4d, 0x3f, 0x01, 0x05, // WT_MAX_STREAMS bidi 5
            0x99, 0x0b, 0x4d, 0x40, 0x01, 0x06, // WT_MAX_STREAMS uni 6
        ];
        let capsules = decode_all(&mut CapsuleDecoder::new(), &bytes).unwrap();
        assert_eq!(
            capsules,
            [
                Capsule::CloseSession {
                    code: 7,
                    reason: "bye".into()
                },
                Capsule::MaxData(100),
                Capsule::MaxStreamsBidi(5),
                Capsule::MaxStreamsUni(6),
            ]
        );
        let mut encoded = Vec::new();
        for capsule in &capsules {
            capsule.encode(&mut encoded).unwrap();
        }
        // The encoder picks the shortest varint for 100, unlike the input.
        assert_eq!(
            decode_all(&mut CapsuleDecoder::new(), &encoded).unwrap(),
            capsules
        );
    }

    #[test]
    fn a_capsule_split_across_data_frames_reassembles() {
        let bytes = [0x68, 0x43, 0x07, 0x00, 0x00, 0x00, 0x07, b'b', b'y', b'e'];
        let mut decoder = CapsuleDecoder::new();
        let mut found = Vec::new();
        for chunk in bytes.chunks(3) {
            found.extend(decode_all(&mut decoder, chunk).unwrap());
            assert_eq!(decoder.is_at_capsule_boundary(), found.len() == 1);
        }
        assert_eq!(
            found,
            [Capsule::CloseSession {
                code: 7,
                reason: "bye".into()
            }]
        );
    }

    #[test]
    fn unknown_capsules_are_skipped_up_to_the_cap() {
        let mut decoder = CapsuleDecoder::new();
        // DATAGRAM (0x00) capsule of 64 KiB, then MAX_DATA.
        let mut header: &[u8] = &[0x00, 0x80, 0x01, 0x00, 0x00];
        assert_eq!(decoder.decode(&mut header), Ok(None));
        let body = [0u8; 1024];
        for _ in 0..64 {
            let mut input: &[u8] = &body;
            assert_eq!(decoder.decode(&mut input), Ok(None));
        }
        let mut tail: &[u8] = &[0x99, 0x0b, 0x4d, 0x3d, 0x01, 0x09];
        assert_eq!(decoder.decode(&mut tail), Ok(Some(Capsule::MaxData(9))));

        let mut decoder = CapsuleDecoder::new();
        assert_eq!(
            decode_all(&mut decoder, &[0x00, 0x80, 0x01, 0x00, 0x01]),
            Err(Error::ExcessiveLoad)
        );
    }

    #[test]
    fn malformed_known_capsules_are_message_errors() {
        let cases: [&[u8]; 5] = [
            &[0x68, 0x43, 0x03, 0, 0, 0],          // close shorter than its code
            &[0x68, 0x43, 0x80, 0x00, 0x04, 0x05], // reason past 1024 bytes
            &[0x68, 0x43, 0x05, 0, 0, 0, 0, 0xff], // reason not UTF-8
            &[0x99, 0x0b, 0x4d, 0x3d, 0x02, 0x05, 0x00], // trailing byte after varint
            &[0x99, 0x0b, 0x4d, 0x3f, 0x00],       // empty body
        ];
        for bytes in cases {
            assert_eq!(
                decode_all(&mut CapsuleDecoder::new(), bytes),
                Err(Error::Message),
                "{bytes:02x?}"
            );
        }
    }

    #[test]
    fn long_close_reasons_are_cut_at_a_char_boundary() {
        let reason: String = core::iter::repeat_n('é', 600).collect();
        let mut out = Vec::new();
        Capsule::CloseSession { code: 0, reason }
            .encode(&mut out)
            .unwrap();
        let decoded = decode_all(&mut CapsuleDecoder::new(), &out).unwrap();
        let [Capsule::CloseSession { reason, .. }] = decoded.as_slice() else {
            panic!("expected one close capsule, got {decoded:?}");
        };
        assert_eq!(reason.len(), MAX_CLOSE_REASON_LEN);
    }
}
