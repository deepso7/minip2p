//! [`RelaySwarm`]: the narrow swarm surface
//! [`RelayServerAgent`](crate::RelayServerAgent) drives.

use minip2p_core::{Bytes, Multiaddr, PeerId};
use minip2p_swarm::{DriverError, EntropySource, SwarmCore, SwarmError};
use minip2p_transport::{ConnectionId, Transport, TransportError};

use crate::StreamKey;

/// Why a [`RelaySwarm`] command was refused: the swarm's own error.
///
/// A [`DriverError::Full`] on a forwarding write is backpressure, not a
/// failure: the relay holds its `unsent` tail and resends it on the
/// stream's `SwarmEvent::StreamWritable` (ADR 0012). A Full control message
/// fails like any other refused write.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct RelaySwarmError(#[from] pub DriverError);

/// The swarm operations the relay server needs.
///
/// The swarm is passed into every
/// [`RelayServerAgent`](crate::RelayServerAgent) call that can issue a
/// command and never stored; each command runs inline and its result is
/// applied before the call returns. Implemented for [`SwarmCore`].
pub trait RelaySwarm {
    /// The remote address of the connection `conn_id`, while the swarm holds
    /// it. Its first IP is the connection's admission key (ADR 0018).
    fn connection_remote_addr(&self, conn_id: ConnectionId) -> Option<&Multiaddr>;

    /// Opens an outbound stream on `peer`'s current connection and returns
    /// its exact identity. Negotiation completes later as
    /// `SwarmEvent::StreamReady`, or fails as a `SwarmEvent::Error` naming
    /// the stream (or, when the peer closes it first, a `StreamClosed`).
    fn open_stream(
        &mut self,
        peer: &PeerId,
        protocol_id: &str,
        now_ms: u64,
    ) -> Result<StreamKey, RelaySwarmError>;

    /// Writes `data` on a negotiated stream. A stream that takes only a
    /// prefix answers [`DriverError::Full`] with the exact `unsent` tail.
    fn send_stream(
        &mut self,
        peer: &PeerId,
        stream: StreamKey,
        data: Bytes,
        now_ms: u64,
    ) -> Result<(), RelaySwarmError>;

    /// Acknowledges `bytes` of `stream`'s delivered data as consumed, which
    /// returns receive credit to its sender (ADR 0012). The relay
    /// acknowledges control messages as it reads them and circuit payload
    /// only once the other leg accepts it, so a full leg pauses its sender;
    /// the host must not acknowledge claimed data itself. A stream or
    /// connection already gone released its bytes with it, so the swarm
    /// absorbs that failure.
    fn ack_stream(&mut self, stream: StreamKey, bytes: usize);

    /// Half-closes a stream's write side. Transport failures arrive later
    /// as swarm events.
    fn close_stream_write(
        &mut self,
        peer: &PeerId,
        stream: StreamKey,
        now_ms: u64,
    ) -> Result<(), RelaySwarmError>;

    /// Resets a stream. A stream or connection already gone counts as
    /// reset. Transport failures arrive later as swarm events.
    fn reset_stream(
        &mut self,
        peer: &PeerId,
        stream: StreamKey,
        now_ms: u64,
    ) -> Result<(), RelaySwarmError>;
}

impl<T: Transport, E: EntropySource> RelaySwarm for SwarmCore<T, E> {
    fn connection_remote_addr(&self, conn_id: ConnectionId) -> Option<&Multiaddr> {
        SwarmCore::connection_remote_addr(self, conn_id)
    }

    fn open_stream(
        &mut self,
        peer: &PeerId,
        protocol_id: &str,
        now_ms: u64,
    ) -> Result<StreamKey, RelaySwarmError> {
        let (conn_id, stream_id) = SwarmCore::open_stream(self, peer, protocol_id, now_ms)?;
        Ok(StreamKey { conn_id, stream_id })
    }

    fn send_stream(
        &mut self,
        peer: &PeerId,
        stream: StreamKey,
        data: Bytes,
        now_ms: u64,
    ) -> Result<(), RelaySwarmError> {
        Ok(SwarmCore::send_stream(
            self,
            peer,
            stream.conn_id,
            stream.stream_id,
            data,
            now_ms,
        )?)
    }

    fn ack_stream(&mut self, stream: StreamKey, bytes: usize) {
        match SwarmCore::ack_stream(self, stream.conn_id, stream.stream_id, bytes) {
            // A stream or connection that is gone (or torn down by this
            // ack's flush) released its bytes with it.
            Ok(())
            | Err(DriverError::Transport(
                TransportError::StreamNotFound { .. }
                | TransportError::ConnectionNotFound { .. }
                | TransportError::ConnectionClosed { .. }
                | TransportError::PollError { .. },
            )) => {}
            // Anything else (an ack past what was delivered, say) breaks the
            // agent's accounting.
            Err(error) => debug_assert!(false, "relay ack refused: {error}"),
        }
    }

    fn close_stream_write(
        &mut self,
        peer: &PeerId,
        stream: StreamKey,
        now_ms: u64,
    ) -> Result<(), RelaySwarmError> {
        Ok(SwarmCore::close_stream_write(
            self,
            peer,
            stream.conn_id,
            stream.stream_id,
            now_ms,
        )?)
    }

    fn reset_stream(
        &mut self,
        peer: &PeerId,
        stream: StreamKey,
        now_ms: u64,
    ) -> Result<(), RelaySwarmError> {
        match SwarmCore::reset_stream(self, peer, stream.conn_id, stream.stream_id, now_ms) {
            // A stream that is gone (or whose connection is) is already reset.
            Ok(()) | Err(DriverError::Swarm(SwarmError::StreamNotFound { .. })) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}
