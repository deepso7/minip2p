//! The dial → ready → open sequence shared by every NAT exchange that needs a
//! stream to an infrastructure peer: relay HOP CONNECT, the AutoNAT probe,
//! and relay reservation. Each caller owns the protocol exchange that runs
//! on the stream once it is opened.

use alloc::string::{String, ToString};

use minip2p_core::{PeerAddr, PeerId};
use minip2p_transport::{ConnectionId, StreamId};

use crate::agent::{DialPurpose, Shared};
use crate::swarm::NatSwarm;
use crate::types::Now;

/// Where an acquisition stands after a step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Acquired {
    /// Waiting for the peer's connection to become ready; a dial may be in
    /// flight. Continue with [`on_ready`].
    Waiting,
    /// The stream is allocated on this exact connection.
    Opened(ConnectionId, StreamId),
}

/// Why an acquisition step failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AcquireError {
    /// The swarm refused the dial.
    Dial(String),
    /// The ready connection does not advertise the protocol.
    Unsupported,
    /// The swarm refused the stream open.
    Open(String),
}

/// Starts acquiring a `protocol` stream to `target`'s peer. A ready peer
/// gets the stream at once. Otherwise the acquisition waits for readiness,
/// first dialing `target` unless the peer is connected or another machine's
/// session dial toward it is in flight (a second connection would replace the
/// first and end its streams). `dial_flight_ms` bounds that dial's gate.
pub(crate) fn start(
    target: &PeerAddr,
    protocol: &str,
    purpose: DialPurpose,
    dial_flight_ms: u64,
    swarm: &mut dyn NatSwarm,
    shared: &mut Shared,
    now: Now,
) -> Result<Acquired, AcquireError> {
    let peer = target.peer_id();
    if swarm.readiness(peer).is_some() {
        let (conn, stream) = open(peer, protocol, swarm, now)?;
        return Ok(Acquired::Opened(conn, stream));
    }
    if swarm.connection(peer).is_none() && !shared.session_dial_pending(peer, now) {
        shared
            .session_dial(swarm, purpose, target.clone(), now, dial_flight_ms)
            .map_err(AcquireError::Dial)?;
    }
    Ok(Acquired::Waiting)
}

/// Continues a waiting acquisition on `PeerReady(conn)`. `None` when `conn`
/// is no longer the peer's ready connection: its replacement announces its
/// own readiness later.
pub(crate) fn on_ready(
    peer: &PeerId,
    conn: ConnectionId,
    protocol: &str,
    swarm: &mut dyn NatSwarm,
    now: Now,
) -> Option<Result<Acquired, AcquireError>> {
    if swarm.readiness(peer).map(|(ready, _)| ready) != Some(conn) {
        return None;
    }
    Some(open(peer, protocol, swarm, now).map(|(conn, stream)| Acquired::Opened(conn, stream)))
}

/// Whether a wait for `peer`'s readiness can still end: the peer has a
/// connection, or a session dial toward it is in flight.
pub(crate) fn can_become_ready(
    peer: &PeerId,
    swarm: &dyn NatSwarm,
    shared: &Shared,
    now: Now,
) -> bool {
    swarm.connection(peer).is_some() || shared.session_dial_pending(peer, now)
}

/// Opens `protocol` on the peer's ready connection.
fn open(
    peer: &PeerId,
    protocol: &str,
    swarm: &mut dyn NatSwarm,
    now: Now,
) -> Result<(ConnectionId, StreamId), AcquireError> {
    let supported = swarm
        .readiness(peer)
        .is_some_and(|(_, protocols)| protocols.iter().any(|p| p == protocol));
    if !supported {
        return Err(AcquireError::Unsupported);
    }
    swarm
        .open_stream(peer, protocol, now.mono_ms)
        .map_err(|error| AcquireError::Open(error.to_string()))
}
