//! Memory-only acceptance test joining the production NAT clients to the
//! production relay-server state machine through their public sans-I/O seams.
#![expect(
    clippy::panic,
    reason = "The helper functions assert the fixed action sequence of this acceptance test."
)]

mod common;

use minip2p_core::platform::Now;
use minip2p_core::{ConnectId, Multiaddr, PeerAddr, PeerId};
use minip2p_nat::{ConnectLegs, NatAgent, NatConfig, NatEvent, Path, ReservationPolicy};
use minip2p_relay_server::{RelayServerConfig, RelayServerEvent, StreamKey};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{Bytes, ConnectionId, StreamId};

use common::mesh::{Mesh, member};
use common::nat_client::{
    CLIENT_RELAY_CONN, ClientSwarm, establish_relay_session, ready_client_hop,
};
use common::{Call, Node};

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

/// The one control or payload write the relay issued since the last call,
/// with no stream reset alongside it.
fn relay_send(server: &mut Node) -> (StreamKey, Vec<u8>) {
    let calls = server.calls();
    assert!(
        !calls.iter().any(|call| matches!(call, Call::Reset { .. })),
        "unexpected relay reset: {calls:?}"
    );
    let sends: Vec<_> = calls
        .into_iter()
        .filter_map(|call| match call {
            Call::Send { stream, data, .. } => Some((stream, data)),
            _ => None,
        })
        .collect();
    let [send] = &sends[..] else {
        panic!("expected one relay write, got {sends:?}")
    };
    send.clone()
}

fn ready_server_hop(
    server: &mut Node,
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

    let mut server = Node::unannounced(RelayServerConfig::default());
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
    let (_, reserve_response) = relay_send(&mut server);
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
    let stop_key = StreamKey {
        conn_id: DESTINATION_RELAY_CONN,
        stream_id: StreamId::new(DESTINATION_STOP),
    };
    server.swarm.next_open = Some(stop_key);
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
    assert_eq!(
        common::opened(&server.calls()),
        Some(stop_key),
        "relay opens STOP on the destination's reserved connection"
    );
    assert!(server.stop_ready(&destination, stop_key, at(16)));
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
    let (_, stop_request) = relay_send(&mut server);
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
    let (_, hop_response) = relay_send(&mut server);
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
    let (forwarded_to_destination, data) = relay_send(&mut server);
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
    let (forwarded_to_source, data) = relay_send(&mut server);
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

/// The one write node `i` of `mesh` issued to its clients since the last
/// call, with no stream reset alongside it.
fn mesh_send(mesh: &mut Mesh, i: usize) -> (StreamKey, Vec<u8>) {
    let calls = mesh.calls(i);
    assert!(
        !calls.iter().any(|call| matches!(call, Call::Reset { .. })),
        "unexpected relay reset: {calls:?}"
    );
    let sends: Vec<_> = calls
        .into_iter()
        .filter_map(|call| match call {
            Call::Send { stream, data, .. } => Some((stream, data)),
            _ => None,
        })
        .collect();
    let [send] = &sends[..] else {
        panic!("expected one relay write, got {sends:?}")
    };
    send.clone()
}

/// The same pair on a two-node relay mesh: the destination reserves on node
/// A, the source connects through node B, and B forwards the circuit to A
/// over the backbone. Neither client knows there are two nodes.
#[test]
fn two_nat_agents_on_different_mesh_nodes_connect_across_the_backbone() {
    const HOLDING: usize = 0;
    const ENTRY: usize = 1;
    let relay = peer(b"relay");
    let source = peer(b"source");
    let destination = peer(b"destination");
    let relay_addr = PeerAddr::new(addr("/ip4/192.0.2.1/udp/4001/quic-v1"), relay.clone())
        .expect("peer address");
    let mut mesh = Mesh::new(vec![RelayServerConfig::default(); 2]);
    mesh.nodes[HOLDING].establish(&destination, DESTINATION_RELAY_CONN);
    mesh.nodes[ENTRY].establish(&source, SOURCE_RELAY_CONN);

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
    ready_client_hop(
        &mut destination_nat,
        &mut destination_swarm,
        &relay,
        reserve_hop,
        4,
    );
    ready_server_hop(
        &mut mesh.nodes[HOLDING],
        &destination,
        DESTINATION_RELAY_CONN,
        reserve_hop,
        4,
    );
    let reserve_request = destination_swarm.take_sent();
    mesh.nodes[HOLDING].data(
        &destination,
        StreamKey {
            conn_id: DESTINATION_RELAY_CONN,
            stream_id: reserve_hop,
        },
        &reserve_request,
        at(5),
    );
    // The reservation's `Present` crosses the backbone.
    mesh.pump(at(5));
    let (_, reserve_response) = mesh_send(&mut mesh, HOLDING);
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
    assert!(destination_nat.active_reservation().is_some());

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
    ready_client_hop(&mut source_nat, &mut source_swarm, &relay, source_hop, 14);
    ready_server_hop(
        &mut mesh.nodes[ENTRY],
        &source,
        SOURCE_RELAY_CONN,
        source_hop,
        14,
    );
    let source_key = StreamKey {
        conn_id: SOURCE_RELAY_CONN,
        stream_id: source_hop,
    };
    let connect_request = source_swarm.take_sent();
    mesh.nodes[ENTRY].data(&source, source_key, &connect_request, at(15));
    // B forwards; A opens STOP on the destination's reserved connection.
    mesh.pump(at(15));
    let stop_key = common::opened(&mesh.calls(HOLDING)).expect("STOP open on the holding node");
    assert_eq!(stop_key.conn_id, DESTINATION_RELAY_CONN);
    assert!(mesh.nodes[HOLDING].stop_ready(&destination, stop_key, at(16)));
    mesh.pump(at(16));
    destination_nat.handle_event(
        &mut destination_swarm,
        &SwarmEvent::StreamReady {
            peer_id: relay.clone(),
            conn_id: CLIENT_RELAY_CONN,
            stream_id: stop_key.stream_id,
            protocol_id: minip2p_nat::STOP_PROTOCOL_ID.to_owned(),
            initiated_locally: false,
        },
        false,
        at(16),
    );
    let (_, stop_request) = mesh_send(&mut mesh, HOLDING);
    destination_nat.handle_event(
        &mut destination_swarm,
        &SwarmEvent::StreamData {
            peer_id: relay.clone(),
            conn_id: CLIENT_RELAY_CONN,
            stream_id: stop_key.stream_id,
            data: Bytes::from(stop_request),
        },
        false,
        at(17),
    );
    let stop_response = destination_swarm.take_sent();
    let destination_circuit = destination_swarm.promoted_circuit();
    mesh.nodes[HOLDING].data(&destination, stop_key, &stop_response, at(18));
    // A's forward `OK` reaches B, which answers the source's CONNECT.
    mesh.pump(at(18));
    let (_, hop_response) = mesh_send(&mut mesh, ENTRY);
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

    let source_payload = b"payload from source".to_vec();
    mesh.nodes[ENTRY].data(&source, source_key, &source_payload, at(20));
    mesh.pump(at(20));
    assert_eq!(mesh_send(&mut mesh, HOLDING), (stop_key, source_payload));
    let destination_payload = b"payload from destination".to_vec();
    mesh.nodes[HOLDING].data(&destination, stop_key, &destination_payload, at(21));
    mesh.pump(at(21));
    assert_eq!(
        mesh_send(&mut mesh, ENTRY),
        (source_key, destination_payload)
    );

    source_nat.handle_event(
        &mut source_swarm,
        &SwarmEvent::ConnectionEstablished {
            peer_id: destination.clone(),
            conn_id: source_circuit,
        },
        true,
        at(22),
    );
    destination_nat.handle_event(
        &mut destination_swarm,
        &SwarmEvent::ConnectionEstablished {
            peer_id: source.clone(),
            conn_id: destination_circuit,
        },
        true,
        at(22),
    );
    assert!(matches!(
        core::iter::from_fn(|| source_nat.poll_event())
            .find(|event| !matches!(event, NatEvent::RelayStarted { .. })),
        Some(NatEvent::PathEstablished {
            connect_id: id,
            path: Path::Relayed { .. },
            ..
        }) if id == connect_id
    ));
    assert!(matches!(
        core::iter::from_fn(|| destination_nat.poll_event())
            .find(|event| !matches!(event, NatEvent::RelayReserved { .. })),
        Some(NatEvent::InboundPathEstablished {
            path: Path::Relayed { .. },
            ..
        })
    ));
    for (node, via) in [(HOLDING, member(ENTRY)), (ENTRY, member(HOLDING))] {
        assert!(
            mesh.nodes[node].events().iter().any(|event| matches!(
                event,
                RelayServerEvent::CircuitOpened { via: Some(v), .. } if *v == via
            )),
            "node {node} opens the circuit via the other"
        );
        assert_eq!(mesh.nodes[node].circuit_count(), 1);
    }
}
