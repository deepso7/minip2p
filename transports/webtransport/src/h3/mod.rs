//! HTTP/3 framing for WebTransport: varints, frames, SETTINGS, stream
//! headers, capsules and error codes.
//!
//! A typical server reads each client stream like this:
//!
//! - uni streams start with a [`UniStreamHeaderDecoder`]; a control stream
//!   then feeds a [`FrameDecoder`] whose first frame must be SETTINGS;
//! - bidi streams feed a [`FrameDecoder`] directly. A WebTransport stream
//!   yields [`Frame::WebTransportStream`] first and its remaining bytes are
//!   application data; the CONNECT stream yields HEADERS and then DATA, whose
//!   payloads feed a [`CapsuleDecoder`].
//!
//! ```
//! use minip2p_webtransport::h3::{Frame, FrameDecoder, UniStreamHeaderDecoder, UniStreamType};
//!
//! // A client control stream: the stream type, then SETTINGS.
//! let mut stream: &[u8] = &[0x00, 0x04, 0x02, 0x08, 0x01];
//! assert_eq!(UniStreamHeaderDecoder::new().decode(&mut stream), Some(UniStreamType::Control));
//! let mut frames = FrameDecoder::new();
//! let Some(Frame::Settings(settings)) = frames.decode(&mut stream)? else {
//!     panic!("expected SETTINGS");
//! };
//! assert_eq!(settings.get(0x08), Some(1));
//! # Ok::<(), minip2p_webtransport::Error>(())
//! ```

mod capsule;
mod frame;
mod stream;
pub mod varint;

pub use capsule::{Capsule, CapsuleDecoder, MAX_CAPSULE_LEN, MAX_CLOSE_REASON_LEN};
pub use frame::{
    Frame, FrameDecoder, MAX_HEADERS_FRAME_LEN, MAX_SETTINGS_FRAME_LEN, Settings, encode_frame,
    encode_goaway,
};
pub use stream::{
    UniStreamHeaderDecoder, UniStreamType, encode_uni_stream_type, encode_webtransport_bidi_header,
};

/// HTTP/3 frame types (RFC 9114 §7.2) plus WebTransport's bidi stream signal.
pub mod frame_type {
    pub const DATA: u64 = 0x00;
    pub const HEADERS: u64 = 0x01;
    pub const CANCEL_PUSH: u64 = 0x03;
    pub const SETTINGS: u64 = 0x04;
    pub const PUSH_PROMISE: u64 = 0x05;
    pub const GOAWAY: u64 = 0x07;
    pub const MAX_PUSH_ID: u64 = 0x0d;
    /// `WT_STREAM`: the first bytes of a WebTransport bidi stream, followed by
    /// the session id and then application data (no length).
    pub const WEBTRANSPORT_STREAM: u64 = 0x41;
}

/// HTTP/3 uni stream types (RFC 9114 §6.2, RFC 9204 §4.2, WebTransport).
pub mod stream_type {
    pub const CONTROL: u64 = 0x00;
    pub const PUSH: u64 = 0x01;
    pub const QPACK_ENCODER: u64 = 0x02;
    pub const QPACK_DECODER: u64 = 0x03;
    /// A WebTransport uni stream, followed by the session id.
    pub const WEBTRANSPORT: u64 = 0x54;
}

/// SETTINGS identifiers used by HTTP/3 WebTransport.
pub mod setting {
    pub const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
    pub const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
    pub const QPACK_BLOCKED_STREAMS: u64 = 0x07;
    /// RFC 9220 extended CONNECT.
    pub const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
    /// RFC 9297 HTTP datagrams.
    pub const H3_DATAGRAM: u64 = 0x33;
    /// WebTransport draft-02 (Chrome, Firefox).
    pub const ENABLE_WEBTRANSPORT: u64 = 0x2b60_3742;
    /// WebTransport draft-13/14 (Safari).
    pub const WT_MAX_SESSIONS: u64 = 0x14e9_cd29;
    pub const WT_INITIAL_MAX_DATA: u64 = 0x2b61;
    pub const WT_INITIAL_MAX_STREAMS_UNI: u64 = 0x2b64;
    pub const WT_INITIAL_MAX_STREAMS_BIDI: u64 = 0x2b65;
}

/// HTTP/3 (RFC 9114 §8.1), QPACK (RFC 9204 §6) and WebTransport session
/// error codes.
pub mod code {
    pub const H3_NO_ERROR: u64 = 0x100;
    pub const H3_GENERAL_PROTOCOL_ERROR: u64 = 0x101;
    pub const H3_INTERNAL_ERROR: u64 = 0x102;
    pub const H3_STREAM_CREATION_ERROR: u64 = 0x103;
    pub const H3_CLOSED_CRITICAL_STREAM: u64 = 0x104;
    pub const H3_FRAME_UNEXPECTED: u64 = 0x105;
    pub const H3_FRAME_ERROR: u64 = 0x106;
    pub const H3_EXCESSIVE_LOAD: u64 = 0x107;
    pub const H3_ID_ERROR: u64 = 0x108;
    pub const H3_SETTINGS_ERROR: u64 = 0x109;
    pub const H3_MISSING_SETTINGS: u64 = 0x10a;
    pub const H3_REQUEST_REJECTED: u64 = 0x10b;
    pub const H3_REQUEST_CANCELLED: u64 = 0x10c;
    pub const H3_REQUEST_INCOMPLETE: u64 = 0x10d;
    pub const H3_MESSAGE_ERROR: u64 = 0x10e;
    pub const H3_CONNECT_ERROR: u64 = 0x10f;
    pub const H3_VERSION_FALLBACK: u64 = 0x110;
    pub const QPACK_DECOMPRESSION_FAILED: u64 = 0x200;
    pub const QPACK_ENCODER_STREAM_ERROR: u64 = 0x201;
    pub const QPACK_DECODER_STREAM_ERROR: u64 = 0x202;
    /// A WebTransport session's flow control was violated (draft-14 §9.5).
    pub const WT_FLOW_CONTROL_ERROR: u64 = 0x045d_4487;
    /// Resets and stops a session's streams as the session ends
    /// (draft-14 §6). Draft-02 names no such code.
    pub const WT_SESSION_GONE: u64 = 0x170d_7b68;
}

/// The first HTTP/3 code of the WebTransport application error range.
const WT_CODE_FIRST: u64 = 0x52e4_a40f_a8db;
/// The last HTTP/3 code of the WebTransport application error range.
const WT_CODE_LAST: u64 = 0x52e5_ac98_3162;

/// Maps a WebTransport application error code to the HTTP/3 code that
/// carries it in RESET_STREAM and STOP_SENDING, skipping the reserved
/// (GREASE) codepoints.
pub fn webtransport_code_to_h3(code: u32) -> u64 {
    let n = u64::from(code);
    WT_CODE_FIRST + n + n / 0x1e
}

/// Maps an HTTP/3 code back to a WebTransport application error code, or
/// `None` if it lies outside the WebTransport range or on a reserved
/// codepoint.
pub fn h3_code_to_webtransport(code: u64) -> Option<u32> {
    if !(WT_CODE_FIRST..=WT_CODE_LAST).contains(&code) || (code - 0x21).is_multiple_of(0x1f) {
        return None;
    }
    let shifted = code - WT_CODE_FIRST;
    u32::try_from(shifted - shifted / 0x1f).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webtransport_codes_map_to_the_draft_range() {
        assert_eq!(webtransport_code_to_h3(0), 0x52e4_a40f_a8db);
        assert_eq!(webtransport_code_to_h3(u32::MAX), 0x52e5_ac98_3162);
        // Code 0x1e skips the reserved codepoint at first + 0x1e.
        assert_eq!(webtransport_code_to_h3(0x1d), 0x52e4_a40f_a8db + 0x1d);
        assert_eq!(webtransport_code_to_h3(0x1e), 0x52e4_a40f_a8db + 0x1f);
    }

    #[test]
    fn h3_codes_map_back_or_are_rejected() {
        for code in [0, 1, 0x1d, 0x1e, 0x1f, 255, 1_000_000, u32::MAX] {
            assert_eq!(
                h3_code_to_webtransport(webtransport_code_to_h3(code)),
                Some(code)
            );
        }
        assert_eq!(h3_code_to_webtransport(0x52e4_a40f_a8db + 0x1e), None);
        assert_eq!(h3_code_to_webtransport(0x52e4_a40f_a8da), None);
        assert_eq!(h3_code_to_webtransport(0x52e5_ac98_3163), None);
        assert_eq!(h3_code_to_webtransport(code::H3_NO_ERROR), None);
    }
}
