use thiserror::Error;

use crate::h3::code;

/// A decoding failure. Each one is fatal to the stream or connection it came
/// from; [`Error::code`] gives the HTTP/3 error code to close it with.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum Error {
    /// A frame was malformed: a bad length, a truncated payload, or `0x41`
    /// anywhere but the first bytes of a stream.
    #[error("malformed HTTP/3 frame")]
    Frame,
    /// A frame type that HTTP/3 forbids here (an HTTP/2-only type or
    /// PUSH_PROMISE).
    #[error("unexpected HTTP/3 frame")]
    FrameUnexpected,
    /// A SETTINGS frame repeated an identifier or used an HTTP/2-only one.
    #[error("invalid HTTP/3 SETTINGS")]
    Settings,
    /// The peer passed one of the encoded size caps.
    #[error("peer exceeded an HTTP/3 size cap")]
    ExcessiveLoad,
    /// A malformed capsule (RFC 9297 §3.3 treats it as a malformed message).
    #[error("malformed capsule")]
    Message,
    /// The QPACK field section was invalid, referenced the dynamic table, or
    /// passed the decoded size or field-count cap.
    #[error("QPACK decompression failed")]
    QpackDecompressionFailed,
    /// The peer's QPACK decoder stream carried an instruction that refers
    /// to a dynamic table this encoder never uses.
    #[error("invalid QPACK decoder stream instruction")]
    QpackDecoderStream,
}

impl Error {
    /// The HTTP/3 or QPACK error code to close the stream or connection with.
    pub fn code(self) -> u64 {
        match self {
            Error::Frame => code::H3_FRAME_ERROR,
            Error::FrameUnexpected => code::H3_FRAME_UNEXPECTED,
            Error::Settings => code::H3_SETTINGS_ERROR,
            Error::ExcessiveLoad => code::H3_EXCESSIVE_LOAD,
            Error::Message => code::H3_MESSAGE_ERROR,
            Error::QpackDecompressionFailed => code::QPACK_DECOMPRESSION_FAILED,
            Error::QpackDecoderStream => code::QPACK_DECODER_STREAM_ERROR,
        }
    }
}

/// An encoder was given a value above [`h3::varint::MAX`](crate::h3::varint::MAX).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
#[error("value does not fit a QUIC variable-length integer")]
pub struct VarIntTooLarge;
