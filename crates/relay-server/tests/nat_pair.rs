//! Memory-only acceptance test joining the production NAT clients to the
//! production relay-server state machine through their public sans-I/O seams.
#![expect(
    clippy::panic,
    reason = "The helper functions assert the fixed action sequence of this acceptance test."
)]

use minip2p_core::platform::Now;
use minip2p_core::{ConnectId, Multiaddr, PeerAddr, PeerId};
use minip2p_nat::{
    BridgeHandoff, ConnectLegs, DialStart, NatAgent, NatConfig, NatEvent, NatSwarm, NatSwarmError,
    NatToken, Path, PromoteError, ReservationPolicy,
};
use minip2p_relay_server::{
    RelayServerAction, RelayServerAgent, RelayServerConfig, RelayServerEvent, StreamKey,
};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{Bytes, ConnectionId, StreamId};

const CLIENT_RELAY_CONN: ConnectionId = ConnectionId::new(1);
const SOURCE_RELAY_CONN: ConnectionId = ConnectionId::new(11);
const DESTINATION_RELAY_CONN: ConnectionId = ConnectionId::new(12);
const SOURCE_HOP: u64 = 101;
const RESERVE_HOP: u64 = 102;
const DESTINATION_STOP: u64 = 103;

fn peer(tag: &[u8]) -> PeerId {
    PeerId::from_public_key_protobuf(tag)
}

fn addr(value: &str) -> Multiaddr {
    value.parse().expect("valid test multiaddr")
}

fn at(ms: u64) -> Now {
    Now::from_millis(ms)
}

/// One NAT client's view of its relay connection: every dial lands on
/// `CLIENT_RELAY_CONN`, the next opened stream is `next_stream`, writes are
/// recorded for the test to carry to the relay server, and a promoted
/// bridge is adopted as `circuit`.
struct ClientSwarm {
    relay: PeerId,
    connected: bool,
    protocols: Option<Vec<String>>,
    next_stream: StreamId,
    sent: Vec<Vec<u8>>,
    circuit: ConnectionId,
    promoted: Option<BridgeHandoff>,
}

impl ClientSwarm {
    fn new(relay: &PeerId, circuit: ConnectionId) -> Self {
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
    fn promoted_circuit(&self) -> ConnectionId {
        assert!(
            self.promoted.is_some(),
            "NAT agent promotes the bridged stream"
        );
        self.circuit
    }

    fn take_sent(&mut self) -> Vec<u8> {
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

/// The relay's next I/O action, skipping its read acknowledgements.
fn relay_action(server: &mut RelayServerAgent) -> Option<RelayServerAction> {
    core::iter::from_fn(|| server.poll_action())
        .find(|action| !matches!(action, RelayServerAction::AckStream { .. }))
}

fn relay_send(server: &mut RelayServerAgent, ms: u64) -> (StreamKey, Vec<u8>) {
    let RelayServerAction::SendStream {
        token,
        stream,
        data,
        ..
    } = relay_action(server).expect("relay sends control bytes")
    else {
        panic!("expected relay SendStream action")
    };
    server.send_stream_result(token, Ok(()), at(ms));
    (stream, data.to_vec())
}

fn finish_relay_stream_cleanup(server: &mut RelayServerAgent, ms: u64) {
    while let Some(action) = relay_action(server) {
        match action {
            RelayServerAction::CloseStreamWrite { token, .. } => {
                server.close_stream_write_result(token, Ok(()), at(ms));
            }
            RelayServerAction::ResetStream { token, .. } => {
                server.reset_stream_result(token, Ok(()), at(ms));
            }
            other => panic!("unexpected relay action during cleanup: {other:?}"),
        }
    }
}

fn establish_relay_session(agent: &mut NatAgent, swarm: &mut ClientSwarm, relay: &PeerId, ms: u64) {
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

fn ready_client_hop(
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

fn ready_server_hop(
    server: &mut RelayServerAgent,
    client: &PeerId,
    conn_id: ConnectionId,
    stream_id: StreamId,
    ms: u64,
) {
    assert!(server.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: client.clone(),
            conn_id,
            stream_id,
            protocol_id: minip2p_nat::HOP_PROTOCOL_ID.to_owned(),
            initiated_locally: false,
        },
        false,
        at(ms),
    ));
}

#[test]
fn two_nat_agents_reserve_and_connect_through_the_real_relay_server() {
    let relay = peer(b"relay");
    let source = peer(b"source");
    let destination = peer(b"destination");
    let relay_addr = PeerAddr::new(addr("/ip4/203.0.113.1/udp/4001/quic-v1"), relay.clone())
        .expect("peer address");

    let mut server =
        RelayServerAgent::new(relay.clone(), RelayServerConfig::default()).expect("valid defaults");
    server
        .set_listener_addrs(vec![addr("/ip4/203.0.113.1/udp/4001/quic-v1")])
        .expect("usable relay address");
    for (client, conn_id) in [
        (source.clone(), SOURCE_RELAY_CONN),
        (destination.clone(), DESTINATION_RELAY_CONN),
    ] {
        server.handle_event(
            &SwarmEvent::ConnectionEstablished {
                peer_id: client,
                conn_id,
            },
            false,
            at(0),
        );
    }

    let mut destination_nat = NatAgent::new(
        destination.clone(),
        NatConfig {
            relays: vec![relay_addr.clone()],
            reservation_policy: ReservationPolicy::Always,
            force_relay: true,
            ..NatConfig::default()
        },
    );
    let mut destination_swarm = ClientSwarm::new(&relay, ConnectionId::new(202));
    let reserve_hop = StreamId::new(RESERVE_HOP);
    destination_swarm.next_stream = reserve_hop;
    destination_nat.handle_tick(&mut destination_swarm, at(0));
    establish_relay_session(&mut destination_nat, &mut destination_swarm, &relay, 2);
    assert!(destination_nat.owns_stream(CLIENT_RELAY_CONN, reserve_hop));
    ready_client_hop(
        &mut destination_nat,
        &mut destination_swarm,
        &relay,
        reserve_hop,
        4,
    );
    ready_server_hop(
        &mut server,
        &destination,
        DESTINATION_RELAY_CONN,
        reserve_hop,
        4,
    );
    let reserve_request = destination_swarm.take_sent();
    server.handle_event(
        &SwarmEvent::StreamData {
            peer_id: destination.clone(),
            conn_id: DESTINATION_RELAY_CONN,
            stream_id: reserve_hop,
            data: Bytes::from(reserve_request),
        },
        false,
        at(5),
    );
    let (_, reserve_response) = relay_send(&mut server, 6);
    destination_nat.handle_event(
        &mut destination_swarm,
        &SwarmEvent::StreamData {
            peer_id: relay.clone(),
            conn_id: CLIENT_RELAY_CONN,
            stream_id: reserve_hop,
            data: Bytes::from(reserve_response),
        },
        false,
        at(6),
    );
    finish_relay_stream_cleanup(&mut server, 6);
    assert!(destination_nat.active_reservation().is_some());
    assert_eq!(server.reservation_count(), 1);

    let mut source_nat = NatAgent::new(
        source.clone(),
        NatConfig {
            relays: vec![relay_addr],
            reservation_policy: ReservationPolicy::Never,
            force_relay: true,
            ..NatConfig::default()
        },
    );
    let connect_id = ConnectId::from_u64(1);
    let mut source_swarm = ClientSwarm::new(&relay, ConnectionId::new(201));
    let source_hop = StreamId::new(SOURCE_HOP);
    source_swarm.next_stream = source_hop;
    source_nat.connect(
        &mut source_swarm,
        connect_id,
        destination.clone(),
        ConnectLegs {
            direct_racing: false,
            allow_relay: true,
            target_addrs: Vec::new(),
            deadline_ms: None,
        },
        at(10),
    );
    establish_relay_session(&mut source_nat, &mut source_swarm, &relay, 12);
    assert!(source_nat.owns_stream(CLIENT_RELAY_CONN, source_hop));
    ready_client_hop(&mut source_nat, &mut source_swarm, &relay, source_hop, 14);
    ready_server_hop(&mut server, &source, SOURCE_RELAY_CONN, source_hop, 14);
    let connect_request = source_swarm.take_sent();
    server.handle_event(
        &SwarmEvent::StreamData {
            peer_id: source.clone(),
            conn_id: SOURCE_RELAY_CONN,
            stream_id: source_hop,
            data: Bytes::from(connect_request),
        },
        false,
        at(15),
    );

    let action = relay_action(&mut server).expect("relay opens STOP");
    let RelayServerAction::OpenStream {
        token,
        expected_conn_id,
        ..
    } = action
    else {
        panic!("expected relay OpenStream action, got {action:?}")
    };
    assert_eq!(expected_conn_id, DESTINATION_RELAY_CONN);
    let stop_key = StreamKey {
        conn_id: DESTINATION_RELAY_CONN,
        stream_id: StreamId::new(DESTINATION_STOP),
    };
    server.stream_open_result(token, Ok(stop_key), at(16));
    destination_nat.handle_event(
        &mut destination_swarm,
        &SwarmEvent::StreamReady {
            peer_id: relay.clone(),
            conn_id: CLIENT_RELAY_CONN,
            stream_id: StreamId::new(DESTINATION_STOP),
            protocol_id: minip2p_nat::STOP_PROTOCOL_ID.to_owned(),
            initiated_locally: false,
        },
        false,
        at(16),
    );
    let (_, stop_request) = relay_send(&mut server, 17);
    destination_nat.handle_event(
        &mut destination_swarm,
        &SwarmEvent::StreamData {
            peer_id: relay.clone(),
            conn_id: CLIENT_RELAY_CONN,
            stream_id: StreamId::new(DESTINATION_STOP),
            data: Bytes::from(stop_request),
        },
        false,
        at(17),
    );
    let stop_response = destination_swarm.take_sent();
    let destination_circuit = destination_swarm.promoted_circuit();
    server.handle_event(
        &SwarmEvent::StreamData {
            peer_id: destination.clone(),
            conn_id: DESTINATION_RELAY_CONN,
            stream_id: StreamId::new(DESTINATION_STOP),
            data: Bytes::from(stop_response),
        },
        false,
        at(18),
    );
    let (_, hop_response) = relay_send(&mut server, 19);
    source_nat.handle_event(
        &mut source_swarm,
        &SwarmEvent::StreamData {
            peer_id: relay.clone(),
            conn_id: CLIENT_RELAY_CONN,
            stream_id: source_hop,
            data: Bytes::from(hop_response),
        },
        false,
        at(19),
    );
    let source_circuit = source_swarm.promoted_circuit();

    finish_relay_stream_cleanup(&mut server, 19);
    let source_payload = b"payload from source".to_vec();
    server.handle_event(
        &SwarmEvent::StreamData {
            peer_id: source.clone(),
            conn_id: SOURCE_RELAY_CONN,
            stream_id: source_hop,
            data: Bytes::from(source_payload.clone()),
        },
        false,
        at(20),
    );
    let (forwarded_to_destination, data) = relay_send(&mut server, 20);
    assert_eq!(forwarded_to_destination, stop_key);
    assert_eq!(data, source_payload);

    let destination_payload = b"payload from destination".to_vec();
    server.handle_event(
        &SwarmEvent::StreamData {
            peer_id: destination.clone(),
            conn_id: DESTINATION_RELAY_CONN,
            stream_id: StreamId::new(DESTINATION_STOP),
            data: Bytes::from(destination_payload.clone()),
        },
        false,
        at(21),
    );
    let (forwarded_to_source, data) = relay_send(&mut server, 21);
    assert_eq!(forwarded_to_source.conn_id, SOURCE_RELAY_CONN);
    assert_eq!(forwarded_to_source.stream_id, source_hop);
    assert_eq!(data, destination_payload);

    source_nat.handle_event(
        &mut source_swarm,
        &SwarmEvent::ConnectionEstablished {
            peer_id: destination.clone(),
            conn_id: source_circuit,
        },
        true,
        at(20),
    );
    destination_nat.handle_event(
        &mut destination_swarm,
        &SwarmEvent::ConnectionEstablished {
            peer_id: source.clone(),
            conn_id: destination_circuit,
        },
        true,
        at(20),
    );

    // Per-relay progress (`RelayStarted`) comes first.
    assert!(matches!(
        core::iter::from_fn(|| source_nat.poll_event())
            .find(|event| !matches!(event, NatEvent::RelayStarted { .. })),
        Some(NatEvent::PathEstablished {
            connect_id: id,
            peer: _,
            path: Path::Relayed { .. },
        }) if id == connect_id
    ));
    assert!(matches!(
        destination_nat.poll_event(),
        Some(NatEvent::RelayReserved { .. })
    ));
    assert!(matches!(
        destination_nat.poll_event(),
        Some(NatEvent::InboundPathEstablished {
            peer: _,
            path: Path::Relayed { .. },
            ..
        })
    ));
    assert!(
        core::iter::from_fn(|| server.poll_event())
            .any(|event| matches!(event, RelayServerEvent::CircuitOpened { .. }))
    );
    assert_eq!(server.circuit_count(), 1);
}
