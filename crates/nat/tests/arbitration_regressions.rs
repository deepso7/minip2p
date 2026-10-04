//! Focused lifecycle and stream-ownership regressions for Relayed-before-DCUtR.

mod common;

use common::*;

use minip2p_core::{ConnectId, Multiaddr, PeerAddr};
use minip2p_nat::{NatAction, NatConfig, NatEvent, Path, PromoteError};
use minip2p_relay::Status;
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, StreamId};

fn drive_to_bridged(h: &mut Harness) -> (ConnectId, StreamId, Vec<NatAction>) {
    let id = h.start(RACE, at(0));
    drain_actions(&mut h.agent);
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
fn punch_dial_failed_event_does_not_emit_connect_failed() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (_, conn) = drive_to_relayed(&mut h);
    let stream = StreamId::new(90);
    open_inbound_dcutr(&mut h, conn, stream);
    let punch = maddr("/ip4/9.9.9.9/udp/4002/quic-v1");
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            data: dcutr_connect_reply(std::slice::from_ref(&punch)),
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
    let actions = drain_actions(&mut h.agent);
    let punch_token = dial_token_for(&actions, &h.target);
    let punch_conn = ConnectionId::new(44);
    h.agent.dial_result(punch_token, Ok(punch_conn), at(313));
    drain_events(&mut h.agent);

    let punch_addr = PeerAddr::new(punch, h.target.clone()).expect("punch addr");
    assert!(h.agent.handle_event_with_disposition(
        &SwarmEvent::DialFailed {
            conn_id: punch_conn,
            addr: punch_addr,
            reason: "punch refused".into(),
        },
        at(314),
    ));
    let events = drain_events(&mut h.agent);
    assert!(
        events
            .iter()
            .all(|event| !matches!(event, NatEvent::ConnectFailed { .. })),
        "punch DialFailed is governed by the window; got {events:?}"
    );
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
fn promoted_circuit_closed_before_fallback_fails_the_leg() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);

    h.agent.handle_event_with_disposition_classified(
        &SwarmEvent::ConnectionClosed {
            conn_id: conn,
            peer_id: h.target.clone(),
        },
        true,
        at(400),
    );

    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::ConnectFailed {
            connect_id,
            error: minip2p_nat::NatError::DialFailed(reason),
            ..
        }] if *connect_id == id && reason == "promoted circuit closed"
    ));
}

#[test]
fn cancel_of_a_provisional_leg_closes_the_circuit() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);

    h.agent.cancel(id, at(400));

    assert!(
        drain_actions(&mut h.agent).iter().any(
            |action| matches!(action, NatAction::CloseCircuit { conn_id } if *conn_id == conn)
        )
    );
    assert!(drain_events(&mut h.agent).is_empty());
}

#[test]
fn cancel_drops_a_queued_relay_dial() {
    let mut h = Harness::with_relay(NatConfig::default());
    let id = h.start(RELAY_NOW, at(0));
    h.agent.cancel(id, at(1));
    let actions = drain_actions(&mut h.agent);
    assert_eq!(dial_count_for(&actions, &h.relay), 0);
    assert!(drain_events(&mut h.agent).is_empty());
}

#[test]
fn cancel_closes_an_in_flight_relay_dial() {
    let mut h = Harness::with_relay(NatConfig::default());
    let id = h.start(RELAY_NOW, at(0));
    let token = dial_token_for(&drain_actions(&mut h.agent), &h.relay);
    let conn = ConnectionId::new(2);
    h.agent.dial_result(token, Ok(conn), at(1));

    h.agent.cancel(id, at(2));
    assert!(
        drain_actions(&mut h.agent).iter().any(
            |action| matches!(action, NatAction::CloseCircuit { conn_id } if *conn_id == conn)
        )
    );

    h.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            conn_id: conn,
            peer_id: h.relay.clone(),
        },
        at(3),
    );
    assert!(drain_events(&mut h.agent).is_empty());
}

#[test]
fn cancel_drops_queued_punch_dials() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);
    open_inbound_dcutr(&mut h, conn, StreamId::new(90));
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: StreamId::new(90),
            data: dcutr_connect_reply(&[maddr("/ip4/9.9.9.9/udp/4002/quic-v1")]),
        },
        at(311),
    );
    drain_actions(&mut h.agent);
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: StreamId::new(90),
            data: dcutr_sync(),
        },
        at(312),
    );

    h.agent.cancel(id, at(313));
    let actions = drain_actions(&mut h.agent);
    assert_eq!(dial_count_for(&actions, &h.target), 0);
    assert!(
        actions.iter().any(
            |action| matches!(action, NatAction::CloseCircuit { conn_id } if *conn_id == conn)
        )
    );
    assert!(drain_events(&mut h.agent).is_empty());
}

#[test]
fn cancel_closes_an_in_flight_punch_dial() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);
    let actions = drive_dcutr_through_sync(&mut h, conn, StreamId::new(90));
    let punch_token = dial_token_for(&actions, &h.target);
    let punch_conn = ConnectionId::new(44);
    h.agent.dial_result(punch_token, Ok(punch_conn), at(313));

    h.agent.cancel(id, at(314));
    let after = drain_actions(&mut h.agent);
    assert!(after.iter().any(
        |action| matches!(action, NatAction::CloseCircuit { conn_id } if *conn_id == punch_conn)
    ));
    assert!(
        after.iter().any(
            |action| matches!(action, NatAction::CloseCircuit { conn_id } if *conn_id == conn)
        )
    );

    h.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            conn_id: punch_conn,
            peer_id: h.target.clone(),
        },
        at(315),
    );
    assert!(
        drain_events(&mut h.agent).is_empty(),
        "a punch must not connect the target after Cancelled"
    );
}

#[test]
fn cancel_then_late_punch_dial_result_closes_the_conn() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);
    let actions = drive_dcutr_through_sync(&mut h, conn, StreamId::new(90));
    let punch_token = dial_token_for(&actions, &h.target);

    h.agent.cancel(id, at(313));
    let _ = drain_actions(&mut h.agent);

    let punch_conn = ConnectionId::new(44);
    h.agent.dial_result(punch_token, Ok(punch_conn), at(314));
    assert!(drain_actions(&mut h.agent).iter().any(
        |action| matches!(action, NatAction::CloseCircuit { conn_id } if *conn_id == punch_conn)
    ));

    h.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            conn_id: punch_conn,
            peer_id: h.target.clone(),
        },
        at(315),
    );
    assert!(drain_events(&mut h.agent).is_empty());
}

#[test]
fn fallback_closes_an_in_flight_punch_dial() {
    let mut h = Harness::with_relay(NatConfig {
        punch_deadline_ms: 250,
        punch_max_retries: 0,
        ..NatConfig::default()
    });
    let (id, conn) = drive_to_relayed(&mut h);
    let actions = drive_dcutr_through_sync(&mut h, conn, StreamId::new(90));
    let punch_token = dial_token_for(&actions, &h.target);
    let punch_conn = ConnectionId::new(44);
    h.agent.dial_result(punch_token, Ok(punch_conn), at(313));

    h.agent.handle_tick(at(562));
    let after = drain_actions(&mut h.agent);
    assert!(after.iter().any(
        |action| matches!(action, NatAction::CloseCircuit { conn_id } if *conn_id == punch_conn)
    ));
    assert!(
        after.iter().all(
            |action| !matches!(action, NatAction::CloseCircuit { conn_id } if *conn_id == conn)
        ),
        "fallback must keep the provisional relay circuit"
    );
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [
            NatEvent::HolePunchFailed { connect_id, .. },
            NatEvent::FellBackToRelay { connect_id: fallback_id, .. }
        ] if *connect_id == id && *fallback_id == id
    ));

    h.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            conn_id: punch_conn,
            peer_id: h.target.clone(),
        },
        at(563),
    );
    assert!(
        drain_events(&mut h.agent).is_empty(),
        "a punch must not connect the target after FellBackToRelay"
    );

    h.agent.cancel(id, at(564));
    assert!(
        drain_actions(&mut h.agent).iter().all(
            |action| !matches!(action, NatAction::CloseCircuit { conn_id } if *conn_id == conn)
        ),
        "settled cancel after FellBackToRelay must stay a no-op"
    );
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

#[test]
fn established_during_punch_window_is_direct_dialed_unless_punch_conn() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);
    let stream = StreamId::new(90);
    let actions = drive_dcutr_through_sync(&mut h, conn, stream);
    let punch_token = dial_token_for(&actions, &h.target);
    let punch_conn = ConnectionId::new(44);
    h.agent.dial_result(punch_token, Ok(punch_conn), at(313));
    drain_events(&mut h.agent);

    // A late engine-owned candidate is DirectDialed even while a punch
    // window is open.
    h.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            conn_id: ConnectionId::new(99),
            peer_id: h.target.clone(),
        },
        at(314),
    );
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::PathUpgraded {
            connect_id,
            to: Path::DirectDialed,
            ..
        }] if *connect_id == id
    ));
}

#[test]
fn punch_conn_established_during_window_is_direct_punched() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);
    let stream = StreamId::new(90);
    let actions = drive_dcutr_through_sync(&mut h, conn, stream);
    let punch_token = dial_token_for(&actions, &h.target);
    let punch_conn = ConnectionId::new(44);
    h.agent.dial_result(punch_token, Ok(punch_conn), at(313));
    drain_events(&mut h.agent);

    h.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            conn_id: punch_conn,
            peer_id: h.target.clone(),
        },
        at(314),
    );
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::PathUpgraded {
            connect_id,
            to: Path::DirectPunched,
            ..
        }] if *connect_id == id
    ));
}

/// Hands the target's connection `old` over to the direct connection `new`.
fn replace_target(h: &mut Harness, old: ConnectionId, new: ConnectionId, t: u64) {
    h.agent.handle_event_with_disposition_classified(
        &SwarmEvent::ConnectionReplaced {
            peer_id: h.target.clone(),
            old,
            new,
        },
        new.is_circuit(),
        at(t),
    );
}

#[test]
fn direct_replacement_of_the_provisional_circuit_upgrades_once() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, circuit) = drive_to_relayed(&mut h);

    replace_target(&mut h, circuit, ConnectionId::new(50), 400);
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::PathUpgraded {
            connect_id,
            from: Path::Relayed { .. },
            to: Path::DirectDialed,
            ..
        }] if *connect_id == id
    ));
    assert_eq!(h.agent.path(&h.target), Some(&Path::DirectDialed));
}

#[test]
fn direct_replacement_after_the_attempt_ended_reports_against_its_origin() {
    let mut h = Harness::with_relay(NatConfig {
        force_relay: true,
        ..NatConfig::default()
    });
    let id = h.start(RELAY_NOW, at(0));
    let relay = dial_token_for(&drain_actions(&mut h.agent), &h.relay);
    h.agent.dial_result(relay, Ok(ConnectionId::new(2)), at(5));
    h.relay_session_ready(at(10));
    let stream = StreamId::new(7);
    let open = open_stream_token(&drain_actions(&mut h.agent));
    h.agent.stream_open_result(open, Ok(stream), at(15));
    h.stream_ready(stream, at(20));
    drain_actions(&mut h.agent);
    h.stream_data(stream, hop_status(Status::Ok), at(30));
    let promotion = drain_actions(&mut h.agent);
    let target = h.target.clone();
    let circuit = complete_promotion(&mut h.agent, &target, &promotion, at(31));
    drain_events(&mut h.agent);
    assert!(h.agent.is_idle(), "a forced relay attempt ends at Relayed");

    replace_target(&mut h, circuit, ConnectionId::new(50), 400);
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::PathUpgraded { connect_id, to: Path::DirectDialed, .. }] if *connect_id == id
    ));
    assert_eq!(h.agent.path(&h.target), Some(&Path::DirectDialed));
}

#[test]
fn direct_replacement_during_dcutr_never_resets_the_retired_stream_by_peer() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (_, circuit) = drive_to_relayed(&mut h);
    let dcutr = StreamId::new(3);
    open_inbound_dcutr(&mut h, circuit, dcutr);
    drain_actions(&mut h.agent);

    replace_target(&mut h, circuit, ConnectionId::new(50), 400);
    assert!(
        !drain_actions(&mut h.agent).iter().any(|action| matches!(
            action,
            NatAction::ResetStream { stream_id, .. } if *stream_id == dcutr
        )),
        "the DCUtR stream ended with the circuit; a reset by peer could hit the new connection"
    );
    assert!(!h.agent.owns_stream(&h.target, dcutr));
}

#[test]
fn circuit_replacing_the_promoted_circuit_keeps_the_attempt_alive() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, circuit) = drive_to_relayed(&mut h);
    let other_circuit = ConnectionId::new(TEST_CIRCUIT_ID + 1);

    replace_target(&mut h, circuit, other_circuit, 400);
    assert!(
        drain_events(&mut h.agent).is_empty(),
        "a relay-to-relay hand-over neither fails nor settles the attempt"
    );
    assert!(
        !h.agent.is_idle(),
        "the attempt still owns the relayed path"
    );

    // A later direct connection still upgrades the attempt's path.
    replace_target(&mut h, other_circuit, ConnectionId::new(50), 500);
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::PathUpgraded { connect_id, to: Path::DirectDialed, .. }] if *connect_id == id
    ));
}

#[test]
fn circuit_promoted_by_another_attempt_settles_the_displaced_one_as_relayed() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (first, circuit) = drive_to_relayed(&mut h);

    // A second attempt to the same peer bridges and promotes its own circuit
    // over the already-ready relay.
    let second = h.start(RELAY_NOW, at(310));
    let actions = drain_actions(&mut h.agent);
    let stream = StreamId::new(8);
    h.agent
        .stream_open_result(open_stream_token(&actions), Ok(stream), at(311));
    h.stream_ready(stream, at(312));
    drain_actions(&mut h.agent);
    h.stream_data(stream, hop_status(Status::Ok), at(313));
    let promotion = drain_actions(&mut h.agent);
    let other_circuit = ConnectionId::new(TEST_CIRCUIT_ID + 1);
    h.agent
        .promote_result(promote_token(&promotion), Ok(other_circuit), at(314));
    replace_target(&mut h, circuit, other_circuit, 315);
    drain_actions(&mut h.agent);
    let events = drain_events(&mut h.agent);
    assert!(
        events.iter().any(|event| matches!(
            event,
            NatEvent::FellBackToRelay { connect_id, .. } if *connect_id == first
        )),
        "the displaced attempt ends on its relayed path: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, NatEvent::ConnectFailed { .. })),
        "the peer stays connected, so no attempt fails: {events:?}"
    );

    h.agent.cancel(first, at(320));
    assert!(
        !drain_actions(&mut h.agent).iter().any(|action| matches!(
            action,
            NatAction::CloseCircuit { conn_id } if *conn_id == other_circuit
        )),
        "cancelling the first attempt must not close the second attempt's circuit"
    );

    h.agent.cancel(second, at(321));
    assert!(drain_actions(&mut h.agent).iter().any(|action| matches!(
        action,
        NatAction::CloseCircuit { conn_id } if *conn_id == other_circuit
    )));
}

#[test]
fn circuit_promoted_by_an_inbound_circuit_is_not_adopted_by_the_attempt() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (first, circuit) = drive_to_relayed(&mut h);

    // The target dials us through the same relay; our inbound circuit is
    // promoted and replaces the attempt's circuit.
    let stop = StreamId::new(40);
    h.agent.handle_event(
        &SwarmEvent::StreamReady {
            conn_id: ConnectionId::new(1),
            peer_id: h.relay.clone(),
            stream_id: stop,
            protocol_id: minip2p_nat::STOP_PROTOCOL_ID.into(),
            initiated_locally: false,
        },
        at(310),
    );
    let target = h.target.clone();
    h.stream_data(stop, stop_connect(&target), at(311));
    let promotion = drain_actions(&mut h.agent);
    let inbound_circuit = ConnectionId::new(TEST_CIRCUIT_ID + 1);
    h.agent
        .promote_result(promote_token(&promotion), Ok(inbound_circuit), at(312));
    replace_target(&mut h, circuit, inbound_circuit, 313);
    drain_actions(&mut h.agent);
    assert!(
        drain_events(&mut h.agent).iter().any(|event| matches!(
            event,
            NatEvent::FellBackToRelay { connect_id, .. } if *connect_id == first
        )),
        "the displaced attempt ends on its relayed path"
    );

    h.agent.cancel(first, at(320));
    assert!(
        !drain_actions(&mut h.agent).iter().any(|action| matches!(
            action,
            NatAction::CloseCircuit { conn_id } if *conn_id == inbound_circuit
        )),
        "cancelling the attempt must not close the inbound circuit"
    );
}
