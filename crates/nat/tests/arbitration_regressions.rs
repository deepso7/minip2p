//! Focused lifecycle and stream-ownership regressions for Relayed-before-DCUtR.

mod common;

use common::*;

use minip2p_core::Multiaddr;
use minip2p_nat::{ConnectId, NatAction, NatConfig, NatEvent, Path, PromoteError};
use minip2p_relay::Status;
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, StreamId};

fn drive_to_bridged(h: &mut Harness) -> (ConnectId, StreamId, Vec<NatAction>) {
    let id = h
        .agent
        .connect(h.target.clone(), vec![maddr(TARGET_ADDR)], at(0));
    let actions = drain_actions(&mut h.agent);
    let direct = dial_token_for(&actions, &h.target);
    h.agent.dial_result(direct, Ok(ConnectionId::new(1)), at(5));
    h.agent.handle_tick(at(200));
    let actions = drain_actions(&mut h.agent);
    let relay = dial_token_for(&actions, &h.relay);
    h.agent
        .dial_result(relay, Ok(ConnectionId::new(2)), at(205));
    h.relay_session_ready(at(210));
    let actions = drain_actions(&mut h.agent);
    let stream = StreamId::new(7);
    h.agent
        .stream_open_result(open_stream_token(&actions), Ok(stream), at(215));
    h.stream_ready(stream, at(220));
    drain_actions(&mut h.agent);
    h.stream_data(stream, hop_status(Status::Ok), at(300));
    let promotion = drain_actions(&mut h.agent);
    (id, stream, promotion)
}

fn drive_to_relayed(h: &mut Harness) -> (ConnectId, ConnectionId) {
    let (id, _, promotion) = drive_to_bridged(h);
    let target = h.target.clone();
    let conn = complete_promotion(&mut h.agent, &target, &promotion, at(301));
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::PathEstablished { connect_id, path: Path::Relayed { .. }, .. }]
            if *connect_id == id
    ));
    (id, conn)
}

fn open_inbound_dcutr(h: &mut Harness, conn: ConnectionId, stream: StreamId) {
    h.agent.handle_event(
        &SwarmEvent::StreamReady {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            protocol_id: minip2p_nat::DCUTR_PROTOCOL_ID.into(),
            initiated_locally: false,
        },
        at(310),
    );
    assert!(h.agent.owns_stream(&h.target, stream));
}

#[test]
fn stalled_promoted_outbound_circuit_is_closed_at_connect_deadline() {
    let mut h = Harness::with_relay(NatConfig {
        connect_deadline_ms: 1_000,
        ..NatConfig::default()
    });
    let (id, _, promotion) = drive_to_bridged(&mut h);
    let conn = ConnectionId::new(TEST_CIRCUIT_ID);
    h.agent
        .promote_result(promote_token(&promotion), Ok(conn), at(301));

    h.agent.handle_tick(at(1_000));

    assert!(
        drain_actions(&mut h.agent).iter().any(
            |action| matches!(action, NatAction::CloseCircuit { conn_id } if *conn_id == conn)
        )
    );
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::ConnectFailed { connect_id, .. }] if *connect_id == id
    ));
}

#[test]
fn promotion_that_loses_to_a_direct_connection_waits_for_its_event() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, _, promotion) = drive_to_bridged(&mut h);
    let token = promote_token(&promotion);
    h.agent
        .promote_result(token, Err(PromoteError::PeerAlreadyDirect), at(301));
    assert!(drain_events(&mut h.agent).is_empty());

    h.target_connected(at(302));

    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::PathEstablished { connect_id, path: Path::DirectDialed, .. }]
            if *connect_id == id
    ));
}

#[test]
fn circuit_dialer_filters_peer_supplied_punch_targets() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (_, conn) = drive_to_relayed(&mut h);
    let stream = StreamId::new(90);
    open_inbound_dcutr(&mut h, conn, stream);
    let global = maddr("/ip4/9.9.9.9/udp/4002/quic-v1");
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            data: dcutr_connect_reply(&[
                maddr("/ip4/10.0.0.7/udp/4002/quic-v1"),
                maddr("/dns4/attacker.invalid/udp/4002/quic-v1"),
                maddr("/ip4/192.0.2.7/udp/4002/quic-v1"),
                global.clone(),
            ]),
        },
        at(311),
    );
    drain_actions(&mut h.agent);
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            data: dcutr_sync(),
        },
        at(312),
    );

    let dials: Vec<Multiaddr> = drain_actions(&mut h.agent)
        .into_iter()
        .filter_map(|action| match action {
            NatAction::Dial { addr, .. } if addr.peer_id() == &h.target => {
                Some(addr.transport().clone())
            }
            _ => None,
        })
        .collect();
    assert_eq!(dials, vec![global]);
}

#[test]
fn foreign_streams_do_not_mutate_an_active_dcutr_exchange() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (_, conn) = drive_to_relayed(&mut h);
    let owned = StreamId::new(90);
    open_inbound_dcutr(&mut h, conn, owned);
    let foreign = StreamId::new(91);

    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: foreign,
            data: b"foreign".to_vec(),
        },
        at(311),
    );

    assert!(drain_actions(&mut h.agent).is_empty());
    assert!(drain_events(&mut h.agent).is_empty());
    assert!(h.agent.owns_stream(&h.target, owned));
}

#[test]
fn cancelling_an_active_dcutr_resets_it_and_closes_the_circuit() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);
    let stream = StreamId::new(90);
    open_inbound_dcutr(&mut h, conn, stream);

    h.agent.cancel(id, at(311));

    let actions = drain_actions(&mut h.agent);
    assert!(has_reset_for(&actions, stream));
    assert!(
        actions.iter().any(
            |action| matches!(action, NatAction::CloseCircuit { conn_id } if *conn_id == conn)
        )
    );
    assert!(!h.agent.owns_stream(&h.target, stream));
    assert!(drain_events(&mut h.agent).is_empty());
}

#[test]
fn established_relay_loss_never_becomes_connect_failed() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (_, conn) = drive_to_relayed(&mut h);

    h.agent.handle_event_with_disposition_classified(
        &SwarmEvent::ConnectionClosed {
            conn_id: conn,
            peer_id: h.target.clone(),
            cause: minip2p_swarm::ConnectionCloseCause::Transport,
        },
        true,
        at(400),
    );
    h.agent.handle_tick(at(60_000));

    assert!(
        !drain_events(&mut h.agent)
            .iter()
            .any(|event| matches!(event, NatEvent::ConnectFailed { .. }))
    );
}

#[test]
fn failed_original_dial_does_not_settle_before_dcutr_starts() {
    let mut h = Harness::with_relay(NatConfig::default());
    let id = h
        .agent
        .connect(h.target.clone(), vec![maddr(TARGET_ADDR)], at(0));
    let actions = drain_actions(&mut h.agent);
    let direct = dial_token_for(&actions, &h.target);
    h.agent.handle_tick(at(200));
    let actions = drain_actions(&mut h.agent);
    let relay = dial_token_for(&actions, &h.relay);
    h.agent
        .dial_result(relay, Ok(ConnectionId::new(2)), at(205));
    h.relay_session_ready(at(210));
    let actions = drain_actions(&mut h.agent);
    let stream = StreamId::new(7);
    h.agent
        .stream_open_result(open_stream_token(&actions), Ok(stream), at(215));
    h.stream_ready(stream, at(220));
    drain_actions(&mut h.agent);
    h.stream_data(stream, hop_status(Status::Ok), at(300));
    let promotion = drain_actions(&mut h.agent);
    let target = h.target.clone();
    let conn = complete_promotion(&mut h.agent, &target, &promotion, at(301));
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::PathEstablished { connect_id, path: Path::Relayed { .. }, .. }]
            if *connect_id == id
    ));

    h.agent
        .dial_result(direct, Err("direct dial failed".into()), at(302));

    assert!(drain_events(&mut h.agent).is_empty());
    open_inbound_dcutr(&mut h, conn, StreamId::new(90));
}

#[test]
fn incomplete_dcutr_close_fails_and_resets_the_exchange() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);
    let stream = StreamId::new(90);
    open_inbound_dcutr(&mut h, conn, stream);

    h.agent.handle_event(
        &SwarmEvent::StreamClosed {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
        },
        at(311),
    );

    assert!(has_reset_for(&drain_actions(&mut h.agent), stream));
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [
            NatEvent::HolePunchFailed { connect_id, .. },
            NatEvent::FellBackToRelay { connect_id: fallback_id, .. }
        ] if *connect_id == id && *fallback_id == id
    ));
    assert!(h.agent.is_idle());
}

fn drive_dcutr_through_sync(
    h: &mut Harness,
    conn: ConnectionId,
    stream: StreamId,
) -> Vec<NatAction> {
    open_inbound_dcutr(h, conn, stream);
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            data: dcutr_connect_reply(&[maddr("/ip4/9.9.9.9/udp/4002/quic-v1")]),
        },
        at(311),
    );
    drain_actions(&mut h.agent);
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            data: dcutr_sync(),
        },
        at(312),
    );
    drain_actions(&mut h.agent)
}

#[test]
fn sync_resets_the_completed_dcutr_control_stream() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (_, conn) = drive_to_relayed(&mut h);
    let stream = StreamId::new(90);
    assert!(has_reset_for(
        &drive_dcutr_through_sync(&mut h, conn, stream),
        stream
    ));
}

#[test]
fn sync_makes_dcutr_one_shot() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (_, conn) = drive_to_relayed(&mut h);
    drive_dcutr_through_sync(&mut h, conn, StreamId::new(90));

    let second = StreamId::new(91);
    h.agent.handle_event(
        &SwarmEvent::StreamReady {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: second,
            protocol_id: minip2p_nat::DCUTR_PROTOCOL_ID.into(),
            initiated_locally: false,
        },
        at(313),
    );
    assert!(has_reset_for(&drain_actions(&mut h.agent), second));
}

#[test]
fn connect_deadline_reaps_an_active_dcutr_stream() {
    let mut h = Harness::with_relay(NatConfig {
        connect_deadline_ms: 1_000,
        ..NatConfig::default()
    });
    let (_, conn) = drive_to_relayed(&mut h);
    let stream = StreamId::new(90);
    open_inbound_dcutr(&mut h, conn, stream);

    h.agent.handle_tick(at(1_000));

    assert!(has_reset_for(&drain_actions(&mut h.agent), stream));
    assert!(!h.agent.owns_stream(&h.target, stream));
    drain_events(&mut h.agent);
    assert!(h.agent.is_idle());
}

#[test]
fn empty_filtered_dcutr_targets_fail_permanently() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);
    let stream = StreamId::new(90);
    open_inbound_dcutr(&mut h, conn, stream);
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            data: dcutr_connect_reply(&[maddr("/ip4/10.0.0.7/udp/4002/quic-v1")]),
        },
        at(311),
    );
    drain_actions(&mut h.agent);

    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            data: dcutr_sync(),
        },
        at(312),
    );

    assert!(has_reset_for(&drain_actions(&mut h.agent), stream));
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [
            NatEvent::HolePunchFailed { connect_id, reason, .. },
            NatEvent::FellBackToRelay { connect_id: fallback_id, .. }
        ] if *connect_id == id
            && *fallback_id == id
            && reason == "no dialable remote addresses in DCUtR CONNECT"
    ));
    assert!(h.agent.is_idle());
}
