//! Memory-only acceptance test joining the production NAT clients to the
//! production relay-server state machine through their public sans-I/O seams.

use minip2p_core::{Multiaddr, PeerAddr, PeerId};
use minip2p_nat::{
    NatAction, NatAgent, NatConfig, NatEvent, Now as NatNow, Path, ReservationPolicy,
};
use minip2p_platform::Now as ServerNow;
use minip2p_relay_server::{
    RelayServerAction, RelayServerAgent, RelayServerConfig, RelayServerEvent, StreamKey,
};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, StreamId};

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

fn nat_now(ms: u64) -> NatNow {
    NatNow::from_mono(ms)
}

fn server_now(ms: u64) -> ServerNow {
    ServerNow::from_millis(ms)
}

fn drain_nat(agent: &mut NatAgent) -> Vec<NatAction> {
    core::iter::from_fn(|| agent.poll_action()).collect()
}

fn nat_open(actions: &[NatAction]) -> minip2p_nat::NatToken {
    actions
        .iter()
        .find_map(|action| match action {
            NatAction::OpenStream { token, .. } => Some(*token),
            _ => None,
        })
        .expect("NAT agent opens a control stream")
}

fn nat_dial(actions: &[NatAction]) -> minip2p_nat::NatToken {
    actions
        .iter()
        .find_map(|action| match action {
            NatAction::Dial { token, .. } => Some(*token),
            _ => None,
        })
        .expect("NAT agent dials the relay")
}

fn nat_send(actions: &[NatAction]) -> Vec<u8> {
    actions
        .iter()
        .find_map(|action| match action {
            NatAction::SendStream { data, .. } => Some(data.clone()),
            _ => None,
        })
        .expect("NAT agent sends control bytes")
}

fn nat_promote(actions: &[NatAction]) -> minip2p_nat::NatToken {
    actions
        .iter()
        .find_map(|action| match action {
            NatAction::PromoteBridge { token, .. } => Some(*token),
            _ => None,
        })
        .expect("NAT agent promotes the bridged stream")
}

fn relay_send(server: &mut RelayServerAgent, ms: u64) -> (StreamKey, Vec<u8>) {
    let RelayServerAction::SendStream {
        token,
        stream,
        data,
        ..
    } = server.poll_action().expect("relay sends control bytes")
    else {
        panic!("expected relay SendStream action")
    };
    server.send_stream_result(token, Ok(()), server_now(ms));
    (stream, data)
}

fn finish_relay_stream_cleanup(server: &mut RelayServerAgent, ms: u64) {
    while let Some(action) = server.poll_action() {
        match action {
            RelayServerAction::CloseStreamWrite { token, .. } => {
                server.close_stream_write_result(token, Ok(()), server_now(ms));
            }
            RelayServerAction::ResetStream { token, .. } => {
                server.reset_stream_result(token, Ok(()), server_now(ms));
            }
            other => panic!("unexpected relay action during cleanup: {other:?}"),
        }
    }
}

fn establish_relay_session(agent: &mut NatAgent, relay: &PeerId, ms: u64) {
    agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            peer_id: relay.clone(),
            conn_id: CLIENT_RELAY_CONN,
        },
        nat_now(ms),
    );
    agent.handle_event(
        &SwarmEvent::PeerReady {
            peer_id: relay.clone(),
            protocols: vec![minip2p_nat::HOP_PROTOCOL_ID.to_owned()],
        },
        nat_now(ms),
    );
}

fn ready_client_hop(agent: &mut NatAgent, relay: &PeerId, stream_id: StreamId, ms: u64) {
    agent.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: relay.clone(),
            conn_id: CLIENT_RELAY_CONN,
            stream_id,
            protocol_id: minip2p_nat::HOP_PROTOCOL_ID.to_owned(),
            initiated_locally: true,
        },
        nat_now(ms),
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
        server_now(ms),
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
            server_now(0),
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
    destination_nat.handle_tick(nat_now(0));
    let dial = nat_dial(&drain_nat(&mut destination_nat));
    destination_nat.dial_result(dial, Ok(CLIENT_RELAY_CONN), nat_now(1));
    establish_relay_session(&mut destination_nat, &relay, 2);
    let open = nat_open(&drain_nat(&mut destination_nat));
    let reserve_hop = StreamId::new(RESERVE_HOP);
    destination_nat.stream_open_result(open, Ok(reserve_hop), nat_now(3));
    ready_client_hop(&mut destination_nat, &relay, reserve_hop, 4);
    ready_server_hop(
        &mut server,
        &destination,
        DESTINATION_RELAY_CONN,
        reserve_hop,
        4,
    );
    let reserve_request = nat_send(&drain_nat(&mut destination_nat));
    server.handle_event(
        &SwarmEvent::StreamData {
            peer_id: destination.clone(),
            conn_id: DESTINATION_RELAY_CONN,
            stream_id: reserve_hop,
            data: reserve_request,
        },
        false,
        server_now(5),
    );
    let (_, reserve_response) = relay_send(&mut server, 6);
    destination_nat.handle_event(
        &SwarmEvent::StreamData {
            peer_id: relay.clone(),
            conn_id: CLIENT_RELAY_CONN,
            stream_id: reserve_hop,
            data: reserve_response,
        },
        nat_now(6),
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
    let connect_id = source_nat.connect(destination.clone(), vec![], nat_now(10));
    let dial = nat_dial(&drain_nat(&mut source_nat));
    source_nat.dial_result(dial, Ok(CLIENT_RELAY_CONN), nat_now(11));
    establish_relay_session(&mut source_nat, &relay, 12);
    let open = nat_open(&drain_nat(&mut source_nat));
    let source_hop = StreamId::new(SOURCE_HOP);
    source_nat.stream_open_result(open, Ok(source_hop), nat_now(13));
    ready_client_hop(&mut source_nat, &relay, source_hop, 14);
    ready_server_hop(&mut server, &source, SOURCE_RELAY_CONN, source_hop, 14);
    let connect_request = nat_send(&drain_nat(&mut source_nat));
    server.handle_event(
        &SwarmEvent::StreamData {
            peer_id: source.clone(),
            conn_id: SOURCE_RELAY_CONN,
            stream_id: source_hop,
            data: connect_request,
        },
        false,
        server_now(15),
    );

    let action = server.poll_action().expect("relay opens STOP");
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
    server.stream_open_result(token, Ok(stop_key), server_now(16));
    destination_nat.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: relay.clone(),
            conn_id: CLIENT_RELAY_CONN,
            stream_id: StreamId::new(DESTINATION_STOP),
            protocol_id: minip2p_nat::STOP_PROTOCOL_ID.to_owned(),
            initiated_locally: false,
        },
        nat_now(16),
    );
    let (_, stop_request) = relay_send(&mut server, 17);
    destination_nat.handle_event(
        &SwarmEvent::StreamData {
            peer_id: relay.clone(),
            conn_id: CLIENT_RELAY_CONN,
            stream_id: StreamId::new(DESTINATION_STOP),
            data: stop_request,
        },
        nat_now(17),
    );
    let destination_actions = drain_nat(&mut destination_nat);
    let stop_response = nat_send(&destination_actions);
    let destination_promote = nat_promote(&destination_actions);
    server.handle_event(
        &SwarmEvent::StreamData {
            peer_id: destination.clone(),
            conn_id: DESTINATION_RELAY_CONN,
            stream_id: StreamId::new(DESTINATION_STOP),
            data: stop_response,
        },
        false,
        server_now(18),
    );
    let (_, hop_response) = relay_send(&mut server, 19);
    source_nat.handle_event(
        &SwarmEvent::StreamData {
            peer_id: relay.clone(),
            conn_id: CLIENT_RELAY_CONN,
            stream_id: source_hop,
            data: hop_response,
        },
        nat_now(19),
    );
    let source_actions = drain_nat(&mut source_nat);
    let source_promote = nat_promote(&source_actions);

    finish_relay_stream_cleanup(&mut server, 19);
    let source_payload = b"payload from source".to_vec();
    server.handle_event(
        &SwarmEvent::StreamData {
            peer_id: source.clone(),
            conn_id: SOURCE_RELAY_CONN,
            stream_id: source_hop,
            data: source_payload.clone(),
        },
        false,
        server_now(20),
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
            data: destination_payload.clone(),
        },
        false,
        server_now(21),
    );
    let (forwarded_to_source, data) = relay_send(&mut server, 21);
    assert_eq!(forwarded_to_source.conn_id, SOURCE_RELAY_CONN);
    assert_eq!(forwarded_to_source.stream_id, source_hop);
    assert_eq!(data, destination_payload);

    let source_circuit = ConnectionId::new(201);
    source_nat.promote_result(source_promote, Ok(source_circuit), nat_now(20));
    source_nat.handle_event_with_disposition_classified(
        &SwarmEvent::ConnectionEstablished {
            peer_id: destination.clone(),
            conn_id: source_circuit,
        },
        true,
        nat_now(20),
    );
    let destination_circuit = ConnectionId::new(202);
    destination_nat.promote_result(destination_promote, Ok(destination_circuit), nat_now(20));
    destination_nat.handle_event_with_disposition_classified(
        &SwarmEvent::ConnectionEstablished {
            peer_id: source.clone(),
            conn_id: destination_circuit,
        },
        true,
        nat_now(20),
    );

    assert!(matches!(
        source_nat.poll_event(),
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
        })
    ));
    assert!(
        core::iter::from_fn(|| server.poll_event())
            .any(|event| matches!(event, RelayServerEvent::CircuitOpened { .. }))
    );
    assert_eq!(server.circuit_count(), 1);
}
