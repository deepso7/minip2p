//! Bounded Sans-I/O implementation of the libp2p Yamux stream multiplexer.
//!
//! [`YamuxSession`] accepts ordered connection bytes and emits encoded Yamux
//! frames plus stream lifecycle events. It performs no I/O and never reads a
//! clock: the host supplies [`minip2p_core::platform::Now`] samples so a quiet
//! session can probe its peer with keepalive pings, and fail with
//! [`YamuxError::KeepaliveTimeout`] once one goes unanswered.
//!
//! Writes follow ADR 0012's backpressure contract: [`YamuxSession::send`]
//! accepts what fits the send caps and hands back the unsent tail as
//! [`YamuxError::Full`], frames are built only when the host pulls them, and
//! [`YamuxOutput::Writable`] says when a full stream can queue again.
//! Reads are credit-driven: a stream returns window credit only for bytes its
//! reader acknowledged with [`YamuxSession::ack`].

mod frame;
mod session;

use alloc::vec::Vec;

use minip2p_core::Bytes;
use thiserror::Error;

pub use frame::{
    FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN, Frame, FrameDecoder, FrameType, HEADER_LEN,
};
pub use session::YamuxSession;

/// Multistream-select protocol identifier for libp2p Yamux.
pub const YAMUX_PROTOCOL_ID: &str = "/yamux/1.0.0";

/// How long a session may go without receiving a frame before it probes
/// the peer with a keepalive ping.
///
/// Only received frames count: a session that keeps writing to a peer that
/// never answers still probes. The host drives keepalive through
/// [`YamuxSession::poll`] / [`YamuxSession::next_deadline`]; the session
/// never reads a clock of its own. 30 seconds matches go-libp2p yamux's
/// default `KeepAliveInterval`.
pub const KEEPALIVE_INTERVAL_MS: u64 = 30_000;

/// How long a due keepalive ping may wait to be handed off: pulled out of the
/// session by [`YamuxSession::poll_frame`] into the host's write path. A
/// write path backed up for longer fails the session with
/// [`YamuxError::KeepaliveTimeout`]. Matches go-libp2p yamux's
/// `ConnectionWriteTimeout`.
pub const KEEPALIVE_HANDOFF_TIMEOUT_MS: u64 = 10_000;

/// How long the peer has to acknowledge a handed-off keepalive ping before
/// the session fails with [`YamuxError::KeepaliveTimeout`]. Only an
/// acknowledgement carrying the ping's nonce counts.
pub const KEEPALIVE_ACK_TIMEOUT_MS: u64 = 10_000;

/// Yamux's specification-defined initial stream window (256 KiB).
pub const DEFAULT_RECEIVE_WINDOW: u32 = 256 * 1024;

/// Default largest payload this side puts in one data frame (1 MiB).
const DEFAULT_MAX_FRAME_LEN: u32 = 1024 * 1024;

/// Default maximum number of simultaneously tracked streams.
const DEFAULT_MAX_STREAMS: usize = 256;

/// Default per-stream cap for accepted bytes not yet pulled as frames.
const DEFAULT_MAX_BUFFERED_SEND: usize = 256 * 1024;

/// Default aggregate cap for accepted bytes not yet pulled as frames.
const DEFAULT_MAX_TOTAL_BUFFERED_SEND: usize = 4 * 1024 * 1024;

/// Default part of the aggregate send cap only control streams may fill.
const DEFAULT_CONTROL_STREAM_RESERVE: usize = 256 * 1024;

/// Default reserve for peer-provoked control frames awaiting a pull.
const DEFAULT_MAX_PENDING_CONTROL: usize = 1024;

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
    /// Receive window maintained for every stream, and its receive budget:
    /// the most delivered bytes it holds unacknowledged (ADR 0012).
    ///
    /// Values below [`DEFAULT_RECEIVE_WINDOW`] are rejected because the peer
    /// is entitled to the specification-defined initial credit.
    ///
    /// Also the largest inbound data-frame payload accepted: a peer may frame
    /// up to the credit it was granted, and anything larger already exceeds
    /// it, so the decoder rejects it as soon as its header arrives.
    pub receive_window: u32,
    /// Largest data-frame payload this side sends. Smaller frames let
    /// streams share the connection more evenly.
    pub max_frame_len: u32,
    /// Maximum number of simultaneously tracked inbound and outbound streams,
    /// counting closed streams that are still unsettled.
    pub max_streams: usize,
    /// Per-stream cap for bytes [`YamuxSession::send`] accepted that have not
    /// been pulled as frames yet, whether or not remote credit allows them.
    ///
    /// A `send` payload framed only in part is sliced, not copied, until its
    /// tail is shorter than half of what it was counted at; the tail then
    /// moves to a right-sized buffer. Queued sends therefore hold at most
    /// twice the bytes this cap and the total cap count.
    pub max_buffered_send: usize,
    /// Aggregate cap for accepted, unpulled send bytes across all streams.
    /// Must be greater than
    /// [`control_stream_reserve`](Self::control_stream_reserve).
    pub max_total_buffered_send: usize,
    /// Part of [`max_total_buffered_send`](Self::max_total_buffered_send)
    /// that only control streams may fill: those marked with
    /// [`YamuxSession::set_control`] (the swarm's ping, Identify and
    /// multistream negotiation streams). Application streams cannot starve
    /// them of it.
    pub control_stream_reserve: usize,
    /// How many control frames may wait to be pulled before a peer that
    /// provokes another reply (a ping acknowledgement, a reset) fails the
    /// session. Bounds what a peer that floods pings without reading can
    /// make this side buffer.
    pub max_pending_control: usize,
}

impl Default for YamuxConfig {
    fn default() -> Self {
        Self {
            receive_window: DEFAULT_RECEIVE_WINDOW,
            max_frame_len: DEFAULT_MAX_FRAME_LEN,
            max_streams: DEFAULT_MAX_STREAMS,
            max_buffered_send: DEFAULT_MAX_BUFFERED_SEND,
            max_total_buffered_send: DEFAULT_MAX_TOTAL_BUFFERED_SEND,
            control_stream_reserve: DEFAULT_CONTROL_STREAM_RESERVE,
            max_pending_control: DEFAULT_MAX_PENDING_CONTROL,
        }
    }
}

impl YamuxConfig {
    /// Checks the Yamux invariants [`YamuxSession::with_config`] enforces,
    /// returning the one that fails.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.receive_window < DEFAULT_RECEIVE_WINDOW {
            return Err("receive_window is below Yamux's initial 256 KiB credit");
        }
        if self.max_frame_len == 0 {
            return Err("max_frame_len must be greater than zero");
        }
        if self.max_buffered_send == 0 || self.max_total_buffered_send == 0 {
            return Err("send caps must be greater than zero");
        }
        if self.max_total_buffered_send <= self.control_stream_reserve {
            return Err("max_total_buffered_send must be greater than control_stream_reserve");
        }
        Ok(())
    }
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
    /// A stream whose `send` returned [`YamuxError::Full`] can queue again.
    ///
    /// One pending notification per armed stream: repeated Fulls before it
    /// fires coalesce into one. It fires when the stream can queue at least
    /// half of the smaller of [`YamuxConfig::max_buffered_send`] and the
    /// part of [`YamuxConfig::max_total_buffered_send`] it may fill (all of it
    /// for a control stream, all but
    /// [`YamuxConfig::control_stream_reserve`] otherwise). A non-zero reserve
    /// also caps a control stream's threshold at half the reserve, the room
    /// it may be left once application streams fill their share. Bytes
    /// leaving another stream
    /// free the shared cap, so this can fire for a stream that was blocked
    /// only by the total. It never fires after the stream's write side ended
    /// (`close_write`, reset, or close).
    Writable {
        /// Stream that can accept writes again.
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
    /// An acknowledgement named more bytes than the stream delivered and has
    /// not yet had acknowledged. Nothing was acknowledged.
    #[error(
        "cannot acknowledge {acked} bytes on Yamux stream {stream}: only {unacked} are unacknowledged"
    )]
    AckExceedsDelivered {
        /// Stream being acknowledged.
        stream: u32,
        /// Bytes the call tried to acknowledge.
        acked: usize,
        /// Bytes delivered and not yet acknowledged.
        unacked: usize,
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
    /// A send did not fit the stream's send caps. Retryable: the stream
    /// accepted everything before `unsent`, and [`YamuxOutput::Writable`]
    /// follows once it can queue again.
    #[error("Yamux stream {stream} is full; {} bytes unsent", unsent.len())]
    Full {
        /// Stream receiving the send.
        stream: u32,
        /// The exact suffix of the payload that was not accepted.
        unsent: Bytes,
    },
    /// The peer provoked more control replies than the reserve holds
    /// without reading them.
    #[error("Yamux control reserve of {limit} frames exhausted; peer is not reading")]
    ControlReserveExhausted {
        /// Configured [`YamuxConfig::max_pending_control`].
        limit: usize,
    },
    /// A keepalive ping was not handed off within
    /// [`KEEPALIVE_HANDOFF_TIMEOUT_MS`], or not acknowledged within
    /// [`KEEPALIVE_ACK_TIMEOUT_MS`] of its hand-off: the peer is presumed
    /// dead. Fatal: the session has failed.
    #[error("Yamux keepalive timed out; the peer did not answer a ping")]
    KeepaliveTimeout,
    /// The local or remote side has sent GoAway.
    #[error("Yamux session is closed")]
    SessionClosed,
    /// A prior protocol error permanently failed this session.
    #[error("Yamux session has failed")]
    Failed,
}
