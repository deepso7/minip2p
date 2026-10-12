//! [`NatSwarm`]: the narrow swarm surface [`NatAgent`](crate::NatAgent)
//! drives.
//!
//! The agent keeps no copy of connection or readiness state. It reads both
//! from the swarm passed into each call and issues swarm commands directly,
//! so only work the swarm cannot know about stays NAT-owned: why each dial
//! was made, which streams NAT owns, and how each path came to be.

use alloc::string::String;

use minip2p_core::{Bytes, PeerAddr, PeerId, Protocol};
use minip2p_swarm::{DriverError, EntropySource, HeldWrites, SwarmCore};
use minip2p_transport::{ConnectionId, StreamId, Transport};

use crate::types::NatToken;

/// How [`NatSwarm::dial`] admitted a dial.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialStart {
    /// A handshake was admitted on this connection. Admitted, not
    /// established: the outcome arrives later as
    /// `SwarmEvent::ConnectionEstablished` or `SwarmEvent::DialFailed`.
    Started(ConnectionId),
    /// The host parked a dial to a named (`/dns*`) address under the token
    /// passed to [`NatSwarm::dial`]. The host reports the outcome later
    /// through
    /// [`NatAgent::dial_result`](crate::NatAgent::dial_result), after
    /// checking [`NatAgent::deferred_dial_wanted`](crate::NatAgent::deferred_dial_wanted).
    Deferred,
}

/// Why a [`NatSwarm`] command was refused.
#[derive(Debug, thiserror::Error)]
pub enum NatSwarmError {
    /// The address names a host (`/dns*`), and this swarm dials only
    /// concrete `/ip4` and `/ip6` addresses. Hosts that resolve names park
    /// such dials instead (see [`DialStart::Deferred`]).
    #[error("named address {0} must be resolved before dialing")]
    NamedAddress(PeerAddr),
    /// The swarm refused the command.
    #[error(transparent)]
    Swarm(#[from] DriverError),
}

/// The swarm operations NAT traversal needs.
///
/// The swarm is passed into every [`NatAgent`](crate::NatAgent) call and never
/// stored. Implemented for [`SwarmCore`]; hosts that resolve names wrap it
/// in a small borrowing adapter that forwards the rest. Writes refused as
/// [`DriverError::Full`] need no host help: the agent holds and resends
/// them.
///
/// Reads may be ahead of the event the agent is handling (see the
/// "State snapshot" entry in `CONTEXT.md`). The agent uses them only to
/// decide whether a new command may start; ownership records follow the
/// exact connection ids carried by events.
pub trait NatSwarm {
    /// `peer`'s current established connection.
    /// [`ConnectionId::is_circuit`] classifies it as relayed or direct.
    fn connection(&self, peer: &PeerId) -> Option<ConnectionId>;

    /// `peer`'s current connection and the protocols it advertised, when
    /// that connection is ready. One coherent read: both describe the same
    /// connection.
    fn readiness(&self, peer: &PeerId) -> Option<(ConnectionId, &[String])>;

    /// Starts a dial. `token` is already registered by the agent, so a host
    /// that parks the dial can return [`DialStart::Deferred`] and report the
    /// outcome under that token at any later point.
    fn dial(&mut self, addr: &PeerAddr, token: NatToken) -> Result<DialStart, NatSwarmError>;

    /// Opens an outbound stream on `peer`'s current connection and returns
    /// its exact identity. Negotiation completes as `SwarmEvent::StreamReady`.
    fn open_stream(
        &mut self,
        peer: &PeerId,
        protocol_id: &str,
        now_ms: u64,
    ) -> Result<(ConnectionId, StreamId), NatSwarmError>;

    /// Writes `data` on a negotiated stream.
    fn send_stream(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
        now_ms: u64,
    ) -> Result<(), NatSwarmError>;

    /// Half-closes a stream's write side. Transport failures arrive later
    /// as swarm events.
    fn close_stream_write(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now_ms: u64,
    ) -> Result<(), NatSwarmError>;

    /// Resets a stream. Transport failures arrive later as swarm events.
    fn reset_stream(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now_ms: u64,
    ) -> Result<(), NatSwarmError>;

    /// Pings `peer` to keep its connection active.
    fn ping(&mut self, peer: &PeerId, now_ms: u64) -> Result<(), NatSwarmError>;
}

/// Whether `addr` names its host (`/dns`, `/dns4`, `/dns6`) instead of
/// giving an IP address.
pub fn is_named(addr: &PeerAddr) -> bool {
    matches!(
        addr.transport().protocols().first(),
        Some(Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_))
    )
}

/// The bare swarm dials concrete addresses only and rejects named ones with
/// [`NatSwarmError::NamedAddress`]. Writes a full stream refuses are
/// reported as [`DriverError::Full`]; the agent holds their tails and
/// resends them on the stream's Writable.
impl<T: Transport, E: EntropySource> NatSwarm for SwarmCore<T, E> {
    fn connection(&self, peer: &PeerId) -> Option<ConnectionId> {
        if self.is_peer_connected(peer) {
            self.connection_id(peer)
        } else {
            None
        }
    }

    fn readiness(&self, peer: &PeerId) -> Option<(ConnectionId, &[String])> {
        self.peer_readiness(peer)
            .map(|(conn_id, info)| (conn_id, info.protocols.as_slice()))
    }

    fn dial(&mut self, addr: &PeerAddr, _token: NatToken) -> Result<DialStart, NatSwarmError> {
        if is_named(addr) {
            return Err(NatSwarmError::NamedAddress(addr.clone()));
        }
        Ok(DialStart::Started(SwarmCore::dial(self, addr)?))
    }

    fn open_stream(
        &mut self,
        peer: &PeerId,
        protocol_id: &str,
        now_ms: u64,
    ) -> Result<(ConnectionId, StreamId), NatSwarmError> {
        Ok(SwarmCore::open_stream(self, peer, protocol_id, now_ms)?)
    }

    fn send_stream(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
        now_ms: u64,
    ) -> Result<(), NatSwarmError> {
        Ok(SwarmCore::send_stream(
            self, peer, conn_id, stream_id, data, now_ms,
        )?)
    }

    fn close_stream_write(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now_ms: u64,
    ) -> Result<(), NatSwarmError> {
        Ok(SwarmCore::close_stream_write(
            self, peer, conn_id, stream_id, now_ms,
        )?)
    }

    fn reset_stream(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now_ms: u64,
    ) -> Result<(), NatSwarmError> {
        Ok(SwarmCore::reset_stream(
            self, peer, conn_id, stream_id, now_ms,
        )?)
    }

    fn ping(&mut self, peer: &PeerId, now_ms: u64) -> Result<(), NatSwarmError> {
        Ok(SwarmCore::ping(self, peer, now_ms)?)
    }
}

/// Bytes NAT holds for one stream before it gives up on it. NAT messages
/// are a few hundred bytes; a peer that leaves this much unread is not
/// completing the exchange.
const MAX_HELD_PER_STREAM: usize = 64 * 1024;

/// Wraps the host's swarm for one agent call so writes it refuses as Full
/// are held, not lost (ADR 0012).
///
/// A held stream's later writes and its write-side close queue behind the
/// tail, and [`replay`](Self::replay) resends them on the stream's
/// Writable.
pub(crate) struct HoldingSwarm<'a> {
    pub(crate) inner: &'a mut dyn NatSwarm,
    pub(crate) held: &'a mut HeldWrites,
}

impl HoldingSwarm<'_> {
    /// Resends a writable stream's held tails, then its deferred close.
    /// Failures surface through the exchange deadlines and the swarm's
    /// events, as for the first write.
    pub(crate) fn replay(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now_ms: u64,
    ) {
        let Some(held) = self.held.take(conn_id, stream_id) else {
            return;
        };
        for data in held.tails {
            match self.send_stream(peer, conn_id, stream_id, data, now_ms) {
                Ok(()) | Err(_) => {}
            }
        }
        if held.close {
            match self.close_stream_write(peer, conn_id, stream_id, now_ms) {
                Ok(()) | Err(_) => {}
            }
        }
    }
}

impl NatSwarm for HoldingSwarm<'_> {
    fn connection(&self, peer: &PeerId) -> Option<ConnectionId> {
        self.inner.connection(peer)
    }

    fn readiness(&self, peer: &PeerId) -> Option<(ConnectionId, &[String])> {
        self.inner.readiness(peer)
    }

    fn dial(&mut self, addr: &PeerAddr, token: NatToken) -> Result<DialStart, NatSwarmError> {
        self.inner.dial(addr, token)
    }

    fn open_stream(
        &mut self,
        peer: &PeerId,
        protocol_id: &str,
        now_ms: u64,
    ) -> Result<(ConnectionId, StreamId), NatSwarmError> {
        self.inner.open_stream(peer, protocol_id, now_ms)
    }

    /// Writes `data`, or holds it behind the stream's unsent tail. A Full
    /// holds what the stream did not take; a stream holding more than
    /// [`MAX_HELD_PER_STREAM`] is reset.
    fn send_stream(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
        now_ms: u64,
    ) -> Result<(), NatSwarmError> {
        let counted = data.len();
        if self.held.is_held(conn_id, stream_id) {
            self.held.push(conn_id, stream_id, data, counted);
        } else {
            match self
                .inner
                .send_stream(peer, conn_id, stream_id, data, now_ms)
            {
                Ok(()) => {}
                Err(NatSwarmError::Swarm(DriverError::Full { unsent, .. })) => {
                    self.held.push(conn_id, stream_id, unsent, counted);
                }
                Err(error) => return Err(error),
            }
        }
        if self.held.held_bytes(conn_id, stream_id) > MAX_HELD_PER_STREAM {
            self.reset_stream(peer, conn_id, stream_id, now_ms)?;
        }
        Ok(())
    }

    /// Closes the write side now, or after the stream's held tails.
    fn close_stream_write(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now_ms: u64,
    ) -> Result<(), NatSwarmError> {
        if self.held.close_after(conn_id, stream_id) {
            return Ok(());
        }
        self.inner
            .close_stream_write(peer, conn_id, stream_id, now_ms)
    }

    /// Resets the stream, dropping whatever it still held.
    fn reset_stream(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now_ms: u64,
    ) -> Result<(), NatSwarmError> {
        self.held.forget_stream(conn_id, stream_id);
        self.inner.reset_stream(peer, conn_id, stream_id, now_ms)
    }

    fn ping(&mut self, peer: &PeerId, now_ms: u64) -> Result<(), NatSwarmError> {
        self.inner.ping(peer, now_ms)
    }
}
