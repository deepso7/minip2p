//! A NAT client's side of its relay connection, for tests that join the
//! production [`NatAgent`] to the relay server.

use minip2p_core::platform::Now;
use minip2p_core::{PeerAddr, PeerId};
use minip2p_nat::{
    BridgeHandoff, DialStart, NatAgent, NatSwarm, NatSwarmError, NatToken, PromoteError,
};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{Bytes, ConnectionId, StreamId};

/// The client's one connection to the relay.
pub const CLIENT_RELAY_CONN: ConnectionId = ConnectionId::new(1);

fn at(ms: u64) -> Now {
    Now::from_millis(ms)
}

/// One NAT client's view of its relay connection: every dial lands on
/// `CLIENT_RELAY_CONN`, the next opened stream is `next_stream`, writes are
/// recorded for the test to carry to the relay server, and a promoted
/// bridge is adopted as `circuit`.
pub struct ClientSwarm {
    relay: PeerId,
    connected: bool,
    protocols: Option<Vec<String>>,
    pub next_stream: StreamId,
    sent: Vec<Vec<u8>>,
    circuit: ConnectionId,
    promoted: Option<BridgeHandoff>,
}

impl ClientSwarm {
    pub fn new(relay: &PeerId, circuit: ConnectionId) -> Self {
        Self {
            relay: relay.clone(),
            connected: false,
            protocols: None,
            next_stream: StreamId::new(0),
            sent: Vec::new(),
            circuit,
            promoted: None,
        }
    }

    /// The circuit the NAT agent's one bridge promotion was adopted as.
    pub fn promoted_circuit(&self) -> ConnectionId {
        assert!(
            self.promoted.is_some(),
            "NAT agent promotes the bridged stream"
        );
        self.circuit
    }

    pub fn take_sent(&mut self) -> Vec<u8> {
        assert_eq!(self.sent.len(), 1, "NAT agent sends one control message");
        self.sent.remove(0)
    }
}

impl NatSwarm for ClientSwarm {
    fn connection(&self, peer: &PeerId) -> Option<ConnectionId> {
        (*peer == self.relay && self.connected).then_some(CLIENT_RELAY_CONN)
    }

    fn readiness(&self, peer: &PeerId) -> Option<(ConnectionId, &[String])> {
        let protocols = self.protocols.as_deref().filter(|_| *peer == self.relay)?;
        Some((CLIENT_RELAY_CONN, protocols))
    }

    fn connection_remote_addr(&self, _conn_id: ConnectionId) -> Option<&minip2p_core::Multiaddr> {
        None
    }

    fn dial(&mut self, _addr: &PeerAddr, _token: NatToken) -> Result<DialStart, NatSwarmError> {
        Ok(DialStart::Started(CLIENT_RELAY_CONN))
    }

    fn open_stream(
        &mut self,
        _peer: &PeerId,
        _protocol_id: &str,
        _now_ms: u64,
    ) -> Result<(ConnectionId, StreamId), NatSwarmError> {
        Ok((CLIENT_RELAY_CONN, self.next_stream))
    }

    fn send_stream(
        &mut self,
        _peer: &PeerId,
        _conn_id: ConnectionId,
        _stream_id: StreamId,
        data: Bytes,
        _now_ms: u64,
    ) -> Result<(), NatSwarmError> {
        self.sent.push(data.to_vec());
        Ok(())
    }

    fn close_stream_write(
        &mut self,
        _peer: &PeerId,
        _conn_id: ConnectionId,
        _stream_id: StreamId,
        _now_ms: u64,
    ) -> Result<(), NatSwarmError> {
        Ok(())
    }

    fn reset_stream(
        &mut self,
        _peer: &PeerId,
        _conn_id: ConnectionId,
        _stream_id: StreamId,
        _now_ms: u64,
    ) -> Result<(), NatSwarmError> {
        Ok(())
    }

    fn ping(&mut self, _peer: &PeerId, _now_ms: u64) -> Result<(), NatSwarmError> {
        Ok(())
    }

    fn promote_bridge(
        &mut self,
        handoff: BridgeHandoff,
        _now_ms: u64,
    ) -> Result<ConnectionId, PromoteError> {
        self.promoted = Some(handoff);
        Ok(self.circuit)
    }
}

pub fn establish_relay_session(
    agent: &mut NatAgent,
    swarm: &mut ClientSwarm,
    relay: &PeerId,
    ms: u64,
) {
    swarm.connected = true;
    agent.handle_event(
        swarm,
        &SwarmEvent::ConnectionEstablished {
            peer_id: relay.clone(),
            conn_id: CLIENT_RELAY_CONN,
        },
        false,
        at(ms),
    );
    let protocols = vec![minip2p_nat::HOP_PROTOCOL_ID.to_owned()];
    swarm.protocols = Some(protocols.clone());
    agent.handle_event(
        swarm,
        &SwarmEvent::PeerReady {
            peer_id: relay.clone(),
            conn_id: CLIENT_RELAY_CONN,
            protocols,
        },
        false,
        at(ms),
    );
}

pub fn ready_client_hop(
    agent: &mut NatAgent,
    swarm: &mut ClientSwarm,
    relay: &PeerId,
    stream_id: StreamId,
    ms: u64,
) {
    agent.handle_event(
        swarm,
        &SwarmEvent::StreamReady {
            peer_id: relay.clone(),
            conn_id: CLIENT_RELAY_CONN,
            stream_id,
            protocol_id: minip2p_nat::HOP_PROTOCOL_ID.to_owned(),
            initiated_locally: true,
        },
        false,
        at(ms),
    );
}
