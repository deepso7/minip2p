//! Actions the host must execute, events for the application, and the
//! caller-facing error types.

use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::PeerId;
use minip2p_transport::StreamId;

/// Correlates a [`PubsubAction::OpenStream`] with its
/// [`FloodsubAgent::stream_open_result`](crate::FloodsubAgent::stream_open_result) echo.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PubsubToken(pub(crate) u64);

/// I/O the driver must perform on the agent's behalf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PubsubAction {
    /// Call `Swarm::open_stream(&peer, &protocol_id)` and echo the result
    /// back via `stream_open_result(&peer, token, ..)` — both fields of
    /// this action, returned as-is.
    OpenStream {
        /// Token identifying this open in the result echo.
        token: PubsubToken,
        /// The peer to open toward.
        peer: PeerId,
        /// Always [`FLOODSUB_PROTOCOL_ID`](crate::FLOODSUB_PROTOCOL_ID).
        protocol_id: String,
    },
    /// Call `Swarm::send_stream(&peer, stream_id, data)`. Fire-and-forget.
    SendStream {
        /// The stream's peer.
        peer: PeerId,
        /// The stream to write to.
        stream_id: StreamId,
        /// The framed RPC bytes.
        data: Vec<u8>,
    },
    /// Call `Swarm::close_stream_write(&peer, stream_id)`. Fire-and-forget.
    CloseStreamWrite {
        /// The stream's peer.
        peer: PeerId,
        /// The stream whose write half to close.
        stream_id: StreamId,
    },
    /// Call `Swarm::reset_stream(&peer, stream_id)`. Fire-and-forget.
    ResetStream {
        /// The stream's peer.
        peer: PeerId,
        /// The stream to reset.
        stream_id: StreamId,
    },
}

/// Application-facing pubsub events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PubsubEvent {
    /// A verified, non-duplicate message on a topic we subscribe to.
    Message {
        /// The publisher (not necessarily the peer it arrived from).
        from: PeerId,
        /// Topics the message was published to.
        topics: Vec<String>,
        /// Application payload.
        data: Vec<u8>,
        /// The publisher's sequence number, as opaque bytes: go peers emit
        /// 8 big-endian bytes, rust-libp2p floodsub 20 random bytes.
        /// Together with `from` it identifies the message for dedup.
        seqno: Vec<u8>,
    },
    /// A peer announced a subscription.
    PeerSubscribed {
        /// The subscribing peer.
        peer: PeerId,
        /// The topic it subscribed to.
        topic: String,
    },
    /// A peer withdrew a subscription.
    PeerUnsubscribed {
        /// The unsubscribing peer.
        peer: PeerId,
        /// The topic it unsubscribed from.
        topic: String,
    },
    /// Already-accepted outbound work was discarded: per item for open
    /// failures, send timeouts, and streams closed before the frame went
    /// out; one aggregated event per peer when a disconnect or supersede
    /// drops the queue (the reason names the dropped count).
    OutboundFailure {
        /// The peer the work was addressed to.
        peer: PeerId,
        /// What was discarded and why.
        reason: String,
    },
    /// A peer broke the protocol: malformed frame or RPC, an oversized
    /// message, a subscription set past its bound (stream reset), or a
    /// message failing signature verification (message dropped, stream
    /// kept). Informational; no automatic disconnect.
    ProtocolViolation {
        /// The offending peer.
        peer: PeerId,
        /// Human-readable cause.
        reason: String,
    },
}

/// Why a topic was rejected, on subscribe and publish alike.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TopicError {
    /// Topics must be non-empty.
    #[error("topic must be non-empty")]
    Empty,
    /// Topics are bounded by [`MAX_TOPIC_LEN`](crate::MAX_TOPIC_LEN) bytes.
    #[error("topic exceeds the maximum length")]
    TooLong,
    /// Adding this topic would make the encoded subscription snapshot
    /// exceed half of [`MAX_RPC_SIZE`](crate::MAX_RPC_SIZE) — the bound
    /// that keeps every snapshot/diff RPC inside one legal frame.
    #[error("the subscription set would no longer fit in one RPC")]
    SetTooLarge,
}

/// Why a publish was refused.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PublishError {
    /// The topic failed validation.
    #[error(transparent)]
    Topic(#[from] TopicError),
    /// The encoded RPC would exceed [`MAX_RPC_SIZE`](crate::MAX_RPC_SIZE).
    #[error("message exceeds the maximum RPC size")]
    TooLarge,
    /// At least one recipient's outbound queue is full; nothing was
    /// enqueued anywhere (all-or-nothing).
    #[error("a recipient's outbound queue is full")]
    Backpressure,
}
