//! Bounded Sans-I/O implementation of the libp2p Yamux stream multiplexer.
//!
//! [`YamuxSession`] accepts ordered connection bytes and emits encoded Yamux
//! frames plus stream lifecycle events. It performs no I/O, owns no clock, and
//! remains fully caller-driven.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

extern crate alloc;

mod frame;
mod session;

use alloc::vec::Vec;

use minip2p_core::SansIoProtocol;
use thiserror::Error;

pub use frame::{
    FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN, Frame, FrameDecoder, FrameType, HEADER_LEN,
};
pub use session::YamuxSession;

/// Multistream-select protocol identifier for libp2p Yamux.
pub const YAMUX_PROTOCOL_ID: &str = "/yamux/1.0.0";

/// Yamux's specification-defined initial stream window (256 KiB).
pub const DEFAULT_RECEIVE_WINDOW: u32 = 256 * 1024;

/// Default maximum payload accepted in one inbound data frame (1 MiB).
pub const DEFAULT_MAX_FRAME_LEN: u32 = 1024 * 1024;

/// Default maximum number of simultaneously tracked streams.
pub const DEFAULT_MAX_STREAMS: usize = 256;

/// Default per-stream cap for data queued behind the remote window.
pub const DEFAULT_MAX_BUFFERED_SEND: usize = 256 * 1024;

/// Default aggregate cap for data queued behind remote windows.
pub const DEFAULT_MAX_TOTAL_BUFFERED_SEND: usize = 4 * 1024 * 1024;

/// Role of this side of a Yamux session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum YamuxRole {
    /// Initiating side; locally opened streams use odd IDs.
    Client,
    /// Accepting side; locally opened streams use even IDs.
    Server,
}

/// Resource limits and flow-control settings for one Yamux session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct YamuxConfig {
    /// Receive window maintained for every stream.
    ///
    /// Values below [`DEFAULT_RECEIVE_WINDOW`] are rejected because the peer
    /// is entitled to the specification-defined initial credit.
    pub receive_window: u32,
    /// Largest accepted inbound data-frame payload.
    pub max_frame_len: u32,
    /// Maximum number of simultaneously tracked inbound and outbound streams.
    pub max_streams: usize,
    /// Per-stream cap for bytes queued after its remote send window is spent.
    pub max_buffered_send: usize,
    /// Aggregate cap for queued send bytes across all streams.
    pub max_total_buffered_send: usize,
}

impl Default for YamuxConfig {
    fn default() -> Self {
        Self {
            receive_window: DEFAULT_RECEIVE_WINDOW,
            max_frame_len: DEFAULT_MAX_FRAME_LEN,
            max_streams: DEFAULT_MAX_STREAMS,
            max_buffered_send: DEFAULT_MAX_BUFFERED_SEND,
            max_total_buffered_send: DEFAULT_MAX_TOTAL_BUFFERED_SEND,
        }
    }
}

/// Input accepted through [`SansIoProtocol`] by [`YamuxSession`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum YamuxInput {
    /// Bytes received from the underlying ordered connection.
    Data(Vec<u8>),
}

/// Output produced by a [`YamuxSession`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum YamuxOutput {
    /// Encoded bytes that must be written to the underlying connection.
    Outbound(Vec<u8>),
    /// The remote opened a new multiplexed stream.
    IncomingStream {
        /// Remote-selected stream identifier.
        stream: u32,
    },
    /// Ordered application bytes received on a stream.
    Data {
        /// Stream carrying the bytes.
        stream: u32,
        /// Data-frame payload.
        data: Vec<u8>,
    },
    /// The remote sent `FIN`; no more inbound bytes will arrive on the stream.
    RemoteWriteClosed {
        /// Half-closed stream identifier.
        stream: u32,
    },
    /// A stream reached its terminal state or was reset.
    StreamClosed {
        /// Closed stream identifier.
        stream: u32,
    },
    /// The remote terminated the Yamux session.
    GoAwayReceived {
        /// Yamux GoAway code (`0` normal, `1` protocol, `2` internal).
        code: u32,
    },
}

/// Errors returned by Yamux framing, flow control, and stream operations.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum YamuxError {
    /// A configuration value violates a Yamux invariant.
    #[error("invalid Yamux configuration: {0}")]
    InvalidConfig(&'static str),
    /// A frame used an unsupported Yamux version.
    #[error("unsupported Yamux version {0}")]
    UnsupportedVersion(u8),
    /// A frame used an unknown type tag.
    #[error("unknown Yamux frame type {0}")]
    UnknownFrameType(u8),
    /// A frame used flags that are invalid for its type.
    #[error("invalid Yamux flags {flags:#06x} for {frame_type:?}")]
    InvalidFlags {
        /// Decoded frame type.
        frame_type: FrameType,
        /// Supplied flags.
        flags: u16,
    },
    /// A frame used stream zero or a non-zero stream where the opposite is required.
    #[error("invalid Yamux stream id {stream} for {frame_type:?}")]
    InvalidStreamId {
        /// Decoded frame type.
        frame_type: FrameType,
        /// Supplied stream identifier.
        stream: u32,
    },
    /// A data frame exceeded the configured header-level payload limit.
    #[error("Yamux data frame length {length} exceeds limit {max}")]
    FrameTooLarge {
        /// Length declared in the header.
        length: u32,
        /// Configured maximum.
        max: u32,
    },
    /// A locally constructed payload cannot fit in Yamux's `u32` length field.
    #[error("Yamux payload length cannot be represented")]
    FrameLengthOverflow,
    /// A frame violated stream lifecycle or role rules.
    #[error("Yamux protocol error: {0}")]
    Protocol(&'static str),
    /// Inbound data exceeded credit granted for its stream.
    #[error("Yamux stream {stream} exceeded its receive window")]
    ReceiveWindowExceeded {
        /// Offending stream identifier.
        stream: u32,
    },
    /// Remote window credit overflowed the representable send window.
    #[error("Yamux stream {stream} send window overflowed")]
    WindowOverflow {
        /// Offending stream identifier.
        stream: u32,
    },
    /// The configured stream capacity is already in use.
    #[error("maximum Yamux stream count reached")]
    TooManyStreams,
    /// The local role exhausted its same-parity `u32` stream IDs.
    #[error("Yamux stream IDs exhausted")]
    StreamsExhausted,
    /// An operation named a stream not tracked by this session.
    #[error("unknown Yamux stream {0}")]
    UnknownStream(u32),
    /// More data was sent after the local write side was closed.
    #[error("Yamux stream {0} write side is closed")]
    StreamWriteClosed(u32),
    /// A send would exceed a per-stream or aggregate queue cap.
    #[error("Yamux send buffer is full for stream {stream}")]
    SendBufferFull {
        /// Stream receiving the send.
        stream: u32,
        /// Bytes that would need to be queued by this call.
        attempted: usize,
        /// Configured per-stream queue cap.
        per_stream_limit: usize,
        /// Configured aggregate queue cap.
        total_limit: usize,
    },
    /// The local or remote side has sent GoAway.
    #[error("Yamux session is closed")]
    SessionClosed,
    /// A prior protocol error permanently failed this session.
    #[error("Yamux session has failed")]
    Failed,
}

impl SansIoProtocol for YamuxSession {
    type Input = YamuxInput;
    type Output = YamuxOutput;
    type Error = YamuxError;

    fn handle_input(&mut self, input: Self::Input) -> Result<(), Self::Error> {
        match input {
            YamuxInput::Data(bytes) => self.handle_data(&bytes),
        }
    }

    fn poll_output(&mut self) -> Option<Self::Output> {
        YamuxSession::poll_output(self)
    }

    fn is_idle(&self) -> bool {
        YamuxSession::is_idle(self)
    }
}
