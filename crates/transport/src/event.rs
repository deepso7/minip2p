use alloc::boxed::Box;
use alloc::string::String;

use minip2p_core::{Bytes, Multiaddr, PeerId};

use crate::{ConnectionCloseReason, ConnectionEndpoint, ConnectionId, StreamId, TransportError};

/// Events emitted by a transport back to the host.
///
/// Per-connection variants box their [`ConnectionEndpoint`] (and
/// `previous_peer_id`) so the enum stays the size of the per-chunk stream
/// variants: every received chunk is a `StreamData` moved through the event
/// queues, while the boxed variants fire a few times per connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportEvent {
    /// Connection handshake completed. No stream events precede this.
    Connected {
        id: ConnectionId,
        endpoint: Box<ConnectionEndpoint>,
    },
    /// A locally-opened stream is open and may send; the peer has not
    /// necessarily seen it yet. Emitted after `open_stream()`, possibly much
    /// later: a transport that must wait for the peer's stream credit (QUIC,
    /// and WebTransport over it) emits it once the stream is opened. A stream
    /// reset or closed before then ends without it.
    StreamOpened {
        id: ConnectionId,
        stream_id: StreamId,
    },
    /// The remote peer opened a new stream. Precedes any `StreamData` for it.
    IncomingStream {
        id: ConnectionId,
        stream_id: StreamId,
    },
    /// Data received on a stream.
    StreamData {
        id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
    },
    /// A stream that reported [`TransportError::Full`](crate::TransportError::Full)
    /// can queue again.
    ///
    /// One pending notification per armed stream: repeated Fulls before it
    /// fires coalesce into one. It fires once the stream can queue at least
    /// half of the smaller of its stream and connection send caps, and never
    /// after the stream's write side has ended.
    StreamWritable {
        id: ConnectionId,
        stream_id: StreamId,
    },
    /// The remote peer half-closed its write side (FIN received).
    StreamRemoteWriteClosed {
        id: ConnectionId,
        stream_id: StreamId,
    },
    /// The remote peer asked us to stop sending (QUIC STOP_SENDING).
    ///
    /// Our write side is closed for good and any queued writes were dropped;
    /// the read side stays open, so `StreamData` and `StreamRemoteWriteClosed`
    /// may still follow. Emitted at most once per stream. Yamux has no
    /// equivalent, so byte-stream transports never emit it.
    StreamWriteStopped {
        id: ConnectionId,
        stream_id: StreamId,
        error_code: u64,
    },
    /// Both sides of the stream are closed. No further events for this stream.
    StreamClosed {
        id: ConnectionId,
        stream_id: StreamId,
    },
    /// The connection is fully closed, for `reason`. No further events for
    /// this connection, and any stream still open ended with it, possibly
    /// without a `StreamClosed` of its own.
    Closed {
        id: ConnectionId,
        reason: ConnectionCloseReason,
    },
    /// An error on a connection that did not end it. A failure that ends the
    /// connection is the `reason` of its `Closed` instead.
    Error { id: ConnectionId, message: String },
    /// A new inbound connection was accepted. `Connected` follows after handshake.
    IncomingConnection {
        id: ConnectionId,
        endpoint: Box<ConnectionEndpoint>,
    },
    /// A peer identity was bound to a connection.
    ///
    /// Transports may emit this after `Connected` when identity is learned as a
    /// post-handshake upgrade. Transports that verify identity during the
    /// handshake may also emit both `Connected` with the verified endpoint and
    /// this event so consumers that track identity-upgrade events have one
    /// consistent signal to observe.
    PeerIdentityVerified {
        id: ConnectionId,
        endpoint: Box<ConnectionEndpoint>,
        previous_peer_id: Option<Box<PeerId>>,
    },
    /// The transport is now listening on the given address.
    Listening { addr: Multiaddr },
    /// The listener on `addr` could not take an inbound connection (out of
    /// file descriptors, say), for `error`.
    ///
    /// A capability failure event: the listener stays open and the
    /// transport keeps retrying. Reported once per change in failure state;
    /// [`ListenerRecovered`](Self::ListenerRecovered) follows once a
    /// connection is accepted again.
    ListenerError {
        addr: Multiaddr,
        error: Box<TransportError>,
    },
    /// The listener on `addr` accepted a connection again after its last
    /// [`ListenerError`](Self::ListenerError).
    ListenerRecovered { addr: Multiaddr },
}

#[cfg(all(test, target_pointer_width = "64"))]
mod size_tests {
    /// Every received chunk moves through this enum as a `StreamData`: a cold
    /// variant that outgrows it should box its payload instead.
    #[test]
    fn stays_the_size_of_its_hot_variants() {
        assert!(core::mem::size_of::<super::TransportEvent>() <= 56);
    }
}
