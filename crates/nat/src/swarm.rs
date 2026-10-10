//! [`NatSwarm`]: the narrow swarm surface [`NatAgent`](crate::NatAgent)
//! drives.
//!
//! The agent keeps no copy of connection or readiness state. It reads both
//! from the swarm passed into each call and issues swarm commands directly,
//! so only work the swarm cannot know about stays NAT-owned: why each dial
//! was made, which streams NAT owns, and how each path came to be.

use alloc::string::String;

use minip2p_core::{Bytes, PeerAddr, PeerId, Protocol};
use minip2p_swarm::{DriverError, EntropySource, SwarmCore};
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
/// stored. Implemented for [`SwarmCore`]; hosts that resolve names or hold
/// write tails wrap it in a small borrowing adapter that forwards the rest.
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
/// reported as [`DriverError::Full`] and not retried; NAT control messages
/// are small, and each exchange's deadline ends one that stalls.
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
