//! Focused lifecycle and stream-ownership regressions for Relayed-before-DCUtR.

mod common;

use common::*;

use minip2p_core::{ConnectId, Multiaddr, PeerAddr};
use minip2p_nat::{MAX_PUNCH_CANDIDATES, NatConfig, NatEvent, Path, PromoteError, UpgradeStop};
use minip2p_relay::Status;
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{Bytes, ConnectionId, StreamId};

fn drive_to_bridged(h: &mut Harness) -> (ConnectId, StreamId, Vec<Out>) {
    let id = h.start(RACE, at(0));
    drain_actions(&mut h.agent);
    h.agent.handle_tick(at(200));
    drain_actions(&mut h.agent);
    h.relay_session_ready(at(210));
    let actions = drain_actions(&mut h.agent);
    let stream = opened_stream(&actions);
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
    open_inbound_dcutr_at(h, conn, stream, 310);
}

fn open_inbound_dcutr_at(h: &mut Harness, conn: ConnectionId, stream: StreamId, t: u64) {
    h.agent.handle_event(
        &SwarmEvent::StreamReady {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            protocol_id: minip2p_nat::DCUTR_PROTOCOL_ID.into(),
            initiated_locally: false,
        },
        false,
        at(t),
    );
    assert!(h.agent.owns_stream(conn, stream));
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
            data: Bytes::from(dcutr_connect_reply(&[
                maddr("/ip4/10.0.0.7/udp/4002/quic-v1"),
                maddr("/dns4/attacker.invalid/udp/4002/quic-v1"),
                maddr("/ip4/192.0.2.7/udp/4002/quic-v1"),
                global.clone(),
            ])),
        },
        false,
        at(311),
    );
    drain_actions(&mut h.agent);
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            data: Bytes::from(dcutr_sync()),
        },
        false,
        at(312),
    );

    let dials: Vec<Multiaddr> = drain_actions(&mut h.agent)
        .into_iter()
        .filter_map(|action| match action {
            Out::Dial { addr, .. } if addr.peer_id() == &h.target => Some(addr.transport().clone()),
            _ => None,
        })
        .collect();
    assert_eq!(dials, vec![global]);
}

/// A CONNECT naming hundreds of global addresses produces at most the cap's
/// worth of punch dials.
#[test]
fn circuit_dialer_caps_peer_supplied_punch_targets() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (_, conn) = drive_to_relayed(&mut h);
    let stream = StreamId::new(90);
    open_inbound_dcutr(&mut h, conn, stream);
    let addrs: Vec<Multiaddr> = (0..250)
        .map(|i| {
            maddr(&format!(
                "/ip4/9.9.{}.{}/udp/{}/quic-v1",
                i / 200,
                i % 200 + 1,
                4000 + i
            ))
        })
        .collect();
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            data: Bytes::from(dcutr_connect_reply(&addrs)),
        },
        false,
        at(311),
    );
    drain_actions(&mut h.agent);
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            data: Bytes::from(dcutr_sync()),
        },
        false,
        at(312),
    );

    let dials = drain_actions(&mut h.agent)
        .into_iter()
        .filter(|action| matches!(action, Out::Dial { addr, .. } if addr.peer_id() == &h.target))
        .count();
    assert!(
        (1..=MAX_PUNCH_CANDIDATES).contains(&dials),
        "{dials} punch dials"
    );
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
            data: Bytes::from(dcutr_connect_reply(std::slice::from_ref(&punch))),
        },
        false,
        at(311),
    );
    drain_actions(&mut h.agent);
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            data: Bytes::from(dcutr_sync()),
        },
        false,
        at(312),
    );
    let actions = drain_actions(&mut h.agent);
    let punch_conn = dial_conn_for(&actions, &h.target);
    drain_events(&mut h.agent);

    let punch_addr = PeerAddr::new(punch, h.target.clone()).expect("punch addr");
    assert!(h.agent.handle_event(
        &SwarmEvent::DialFailed {
            conn_id: punch_conn,
            addr: punch_addr,
            reason: "punch refused".into(),
        },
        false,
        at(314)
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
            data: Bytes::from_static(b"foreign"),
        },
        false,
        at(311),
    );

    assert!(drain_actions(&mut h.agent).is_empty());
    assert!(drain_events(&mut h.agent).is_empty());
    assert!(h.agent.owns_stream(conn, owned));
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
        actions
            .iter()
            .any(|action| matches!(action, Out::CloseCircuit { conn_id } if *conn_id == conn))
    );
    assert!(!h.agent.owns_stream(conn, stream));
    assert!(drain_events(&mut h.agent).is_empty());
}

#[test]
fn promoted_circuit_closed_before_fallback_fails_the_leg() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);

    h.agent.handle_event(
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
        drain_actions(&mut h.agent)
            .iter()
            .any(|action| matches!(action, Out::CloseCircuit { conn_id } if *conn_id == conn))
    );
    assert!(drain_events(&mut h.agent).is_empty());
}

#[test]
fn cancel_retires_a_parked_relay_dial() {
    let named = PeerAddr::new(
        maddr("/dns4/relay.example/udp/4001/quic-v1"),
        peer(b"relay-peer"),
    )
    .expect("valid named relay addr");
    let mut h = Harness::without_relay(NatConfig {
        relays: vec![named],
        reservation_policy: minip2p_nat::ReservationPolicy::Never,
        ..NatConfig::default()
    });
    h.agent.swarm.park_named = true;
    let id = h.start(RELAY_NOW, at(0));
    let token = dial_token_for(&drain_actions(&mut h.agent), &h.relay);

    h.agent.cancel(id, at(1));
    assert!(
        !h.agent.deferred_dial_wanted(token, at(2)),
        "a cancelled attempt no longer wants its parked dial"
    );
    h.agent.dial_result(token, Ok(ConnectionId::new(2)), at(3));
    assert!(drain_actions(&mut h.agent).is_empty());
    assert!(drain_events(&mut h.agent).is_empty());
}

#[test]
fn cancel_closes_an_in_flight_relay_dial() {
    let mut h = Harness::with_relay(NatConfig::default());
    let id = h.start(RELAY_NOW, at(0));
    let conn = dial_conn_for(&drain_actions(&mut h.agent), &h.relay);

    h.agent.cancel(id, at(2));
    assert!(
        drain_actions(&mut h.agent)
            .iter()
            .any(|action| matches!(action, Out::CloseCircuit { conn_id } if *conn_id == conn))
    );

    h.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            conn_id: conn,
            peer_id: h.relay.clone(),
        },
        false,
        at(3),
    );
    assert!(drain_events(&mut h.agent).is_empty());
}

#[test]
fn cancel_closes_an_in_flight_punch_dial() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);
    let actions = drive_dcutr_through_sync(&mut h, conn, StreamId::new(90));
    let punch_conn = dial_conn_for(&actions, &h.target);

    h.agent.cancel(id, at(314));
    let after = drain_actions(&mut h.agent);
    assert!(
        after.iter().any(
            |action| matches!(action, Out::CloseCircuit { conn_id } if *conn_id == punch_conn)
        )
    );
    assert!(
        after
            .iter()
            .any(|action| matches!(action, Out::CloseCircuit { conn_id } if *conn_id == conn))
    );

    h.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            conn_id: punch_conn,
            peer_id: h.target.clone(),
        },
        false,
        at(315),
    );
    assert!(
        drain_events(&mut h.agent).is_empty(),
        "a punch must not connect the target after Cancelled"
    );
}

#[test]
fn fallback_closes_an_in_flight_punch_dial() {
    let mut h = Harness::with_relay(NatConfig {
        punch_deadline_ms: 250,
        ..NatConfig::default()
    });
    let (id, conn) = drive_to_relayed(&mut h);
    drive_round_at(&mut h, conn, StreamId::new(88), 310);
    h.agent.handle_tick(at(562));
    drive_round_at(&mut h, conn, StreamId::new(89), 600);
    h.agent.handle_tick(at(852));
    let actions = drive_round_at(&mut h, conn, StreamId::new(90), 900);
    let punch_conn = dial_conn_for(&actions, &h.target);
    drain_events(&mut h.agent);

    h.agent.handle_tick(at(1_152));
    let after = drain_actions(&mut h.agent);
    assert!(
        after.iter().any(
            |action| matches!(action, Out::CloseCircuit { conn_id } if *conn_id == punch_conn)
        )
    );
    assert!(
        after
            .iter()
            .all(|action| !matches!(action, Out::CloseCircuit { conn_id } if *conn_id == conn)),
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
        false,
        at(1_153),
    );
    assert!(
        drain_events(&mut h.agent).is_empty(),
        "a punch must not connect the target after FellBackToRelay"
    );

    h.agent.cancel(id, at(1_154));
    assert!(
        drain_actions(&mut h.agent)
            .iter()
            .all(|action| !matches!(action, Out::CloseCircuit { conn_id } if *conn_id == conn)),
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
        false,
        at(311),
    );

    assert!(has_reset_for(&drain_actions(&mut h.agent), stream));
    // A failed round, not a settled attempt: the holder starts the next.
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::HolePunchFailed { connect_id, attempt: 1, .. }] if *connect_id == id
    ));
    assert!(!h.agent.is_idle());
}

fn drive_dcutr_through_sync(h: &mut Harness, conn: ConnectionId, stream: StreamId) -> Vec<Out> {
    drive_round_at(h, conn, stream, 310)
}

/// One holder round on `stream`: the stream opens at `t`, CONNECT arrives
/// at `t + 1` and SYNC at `t + 2`. Returns what the agent did on SYNC.
fn drive_round_at(h: &mut Harness, conn: ConnectionId, stream: StreamId, t: u64) -> Vec<Out> {
    open_inbound_dcutr_at(h, conn, stream, t);
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            data: Bytes::from(dcutr_connect_reply(&[maddr(
                "/ip4/9.9.9.9/udp/4002/quic-v1",
            )])),
        },
        false,
        at(t + 1),
    );
    drain_actions(&mut h.agent);
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            data: Bytes::from(dcutr_sync()),
        },
        false,
        at(t + 2),
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
fn the_holder_runs_three_rounds_and_each_failed_round_cancels_its_dials() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);

    let first = drive_round_at(&mut h, conn, StreamId::new(90), 310);
    let first_dial = dial_conn_for(&first, &h.target);
    h.agent.handle_tick(at(3_312));
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::HolePunchFailed { attempt: 1, .. }]
    ));
    // The failed window drops its unfinished dial before the next round.
    assert!(
        drain_actions(&mut h.agent)
            .iter()
            .any(|out| matches!(out, Out::CloseCircuit { conn_id } if *conn_id == first_dial))
    );

    let second = drive_round_at(&mut h, conn, StreamId::new(91), 3_400);
    assert_eq!(dial_count_for(&second, &h.target), 1);
    h.agent.handle_tick(at(6_402));
    drive_round_at(&mut h, conn, StreamId::new(92), 6_500);
    h.agent.handle_tick(at(9_502));

    // The third failed round settles on the Relayed path, keeping the
    // circuit.
    let events = drain_events(&mut h.agent);
    assert!(
        matches!(
            events.as_slice(),
            [
                NatEvent::HolePunchFailed { attempt: 2, .. },
                NatEvent::HolePunchFailed { attempt: 3, .. },
                NatEvent::FellBackToRelay {
                    connect_id,
                    reason: UpgradeStop::PunchFailed { rounds: 3 },
                    ..
                }
            ] if *connect_id == id
        ),
        "{events:?}"
    );
    assert!(
        drain_actions(&mut h.agent)
            .iter()
            .all(|out| !matches!(out, Out::CloseCircuit { conn_id } if *conn_id == conn))
    );

    // A fourth stream has no attempt to answer it.
    let fourth = StreamId::new(93);
    h.agent.handle_event(
        &SwarmEvent::StreamReady {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: fourth,
            protocol_id: minip2p_nat::DCUTR_PROTOCOL_ID.into(),
            initiated_locally: false,
        },
        false,
        at(9_600),
    );
    assert!(has_reset_for(&drain_actions(&mut h.agent), fourth));
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
            data: Bytes::from(dcutr_connect_reply(&[maddr(
                "/ip4/10.0.0.7/udp/4002/quic-v1",
            )])),
        },
        false,
        at(311),
    );
    drain_actions(&mut h.agent);

    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            data: Bytes::from(dcutr_sync()),
        },
        false,
        at(312),
    );

    assert!(has_reset_for(&drain_actions(&mut h.agent), stream));
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::HolePunchFailed { connect_id, reason, .. }] if *connect_id == id
            && reason == "no dialable remote addresses in DCUtR CONNECT"
    ));
}

#[test]
fn established_during_punch_window_is_direct_dialed_unless_punch_conn() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);
    let stream = StreamId::new(90);
    let actions = drive_dcutr_through_sync(&mut h, conn, stream);
    assert_ne!(dial_conn_for(&actions, &h.target), ConnectionId::new(99));
    drain_events(&mut h.agent);

    // A late engine-owned candidate is DirectDialed even while a punch
    // window is open.
    h.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            conn_id: ConnectionId::new(99),
            peer_id: h.target.clone(),
        },
        false,
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
    let punch_conn = dial_conn_for(&actions, &h.target);
    drain_events(&mut h.agent);

    h.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            conn_id: punch_conn,
            peer_id: h.target.clone(),
        },
        false,
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
    h.agent.handle_event(
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

    // A late close of the replaced circuit leaves the peer connected.
    h.agent.handle_event(
        &SwarmEvent::ConnectionClosed {
            peer_id: h.target.clone(),
            conn_id: circuit,
        },
        false,
        at(410),
    );
    assert_eq!(h.agent.path(&h.target), Some(&Path::DirectDialed));
}

#[test]
fn direct_replacement_after_the_attempt_ended_reports_against_its_origin() {
    let mut h = Harness::with_relay(NatConfig {
        force_relay: true,
        ..NatConfig::default()
    });
    let id = h.start(RELAY_NOW, at(0));
    drain_actions(&mut h.agent);
    h.relay_session_ready(at(10));
    let stream = opened_stream(&drain_actions(&mut h.agent));
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
            Out::ResetStream { stream_id, .. } if *stream_id == dcutr
        )),
        "the DCUtR stream ended with the circuit; a reset by peer could hit the new connection"
    );
    assert!(!h.agent.owns_stream(circuit, dcutr));
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
    assert!(
        matches!(h.agent.path(&h.target), Some(Path::Relayed { relay }) if *relay == h.relay),
        "the adopted circuit carries the attempt's relayed path"
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
    let stream = opened_stream(&actions);
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
            Out::CloseCircuit { conn_id } if *conn_id == other_circuit
        )),
        "cancelling the first attempt must not close the second attempt's circuit"
    );

    h.agent.cancel(second, at(321));
    assert!(drain_actions(&mut h.agent).iter().any(|action| matches!(
        action,
        Out::CloseCircuit { conn_id } if *conn_id == other_circuit
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
        false,
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
            Out::CloseCircuit { conn_id } if *conn_id == inbound_circuit
        )),
        "cancelling the attempt must not close the inbound circuit"
    );
}

#[test]
fn a_remote_that_never_starts_dcutr_settles_relayed_after_the_start_timeout() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);

    // The Relayed path became usable at t=301; the holder never opens DCUtR.
    h.agent.handle_tick(at(10_300));
    assert!(drain_events(&mut h.agent).is_empty());
    h.agent.handle_tick(at(10_301));
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::FellBackToRelay {
            connect_id,
            reason: UpgradeStop::StartTimeout { budget_ms: 10_000 },
            ..
        }] if *connect_id == id
    ));
    assert!(
        drain_actions(&mut h.agent)
            .iter()
            .all(|out| !matches!(out, Out::CloseCircuit { conn_id } if *conn_id == conn)),
        "the Relayed path stays"
    );
    assert!(h.agent.is_idle());
}

#[test]
fn a_stalled_exchange_settles_relayed_with_its_round() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);
    open_inbound_dcutr_at(&mut h, conn, StreamId::new(90), 1_000);

    h.agent.handle_tick(at(10_999));
    assert!(drain_events(&mut h.agent).is_empty());
    h.agent.handle_tick(at(11_000));
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::FellBackToRelay {
            connect_id,
            reason: UpgradeStop::ExchangeTimeout { round: 1, budget_ms: 10_000 },
            ..
        }] if *connect_id == id
    ));
}

#[test]
fn an_exchange_finishing_near_its_deadline_keeps_its_punch_window() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (_, conn) = drive_to_relayed(&mut h);
    let stream = StreamId::new(90);
    open_inbound_dcutr_at(&mut h, conn, stream, 1_000);
    for (data, t) in [
        (
            dcutr_connect_reply(&[maddr("/ip4/9.9.9.9/udp/4002/quic-v1")]),
            10_900,
        ),
        (dcutr_sync(), 10_950),
    ] {
        h.agent.handle_event(
            &SwarmEvent::StreamData {
                conn_id: conn,
                peer_id: h.target.clone(),
                stream_id: stream,
                data: Bytes::from(data),
            },
            false,
            at(t),
        );
    }
    drain_actions(&mut h.agent);

    // Past the 10 s exchange budget but inside the punch window: the
    // round is still running.
    h.agent.handle_tick(at(11_500));
    assert!(drain_events(&mut h.agent).is_empty());
    h.agent.handle_tick(at(13_950));
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::HolePunchFailed { attempt: 1, .. }]
    ));
}

#[test]
fn a_dcutr_stream_arriving_after_the_start_budget_settles_relayed() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);

    // The stream reaches the agent before the tick that would expire the
    // start budget (t=10_301).
    let stream = StreamId::new(90);
    h.agent.handle_event(
        &SwarmEvent::StreamReady {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            protocol_id: minip2p_nat::DCUTR_PROTOCOL_ID.into(),
            initiated_locally: false,
        },
        false,
        at(10_400),
    );
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::FellBackToRelay {
            connect_id,
            reason: UpgradeStop::StartTimeout { .. },
            ..
        }] if *connect_id == id
    ));
    assert!(has_reset_for(&drain_actions(&mut h.agent), stream));
}

#[test]
fn a_sync_arriving_after_the_exchange_budget_dials_nothing() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);
    let actions = drive_round_at(&mut h, conn, StreamId::new(90), 1_000);
    drain_events(&mut h.agent);
    assert_eq!(dial_count_for(&actions, &h.target), 1);

    let stream = StreamId::new(91);
    open_inbound_dcutr_at(&mut h, conn, stream, 2_000);
    drain_events(&mut h.agent);
    for (data, t) in [
        (
            dcutr_connect_reply(&[maddr("/ip4/9.9.9.9/udp/4002/quic-v1")]),
            2_001,
        ),
        // The exchange budget ended at t=12_000.
        (dcutr_sync(), 12_100),
    ] {
        h.agent.handle_event(
            &SwarmEvent::StreamData {
                conn_id: conn,
                peer_id: h.target.clone(),
                stream_id: stream,
                data: Bytes::from(data),
            },
            false,
            at(t),
        );
    }
    assert_eq!(dial_count_for(&drain_actions(&mut h.agent), &h.target), 0);
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::FellBackToRelay {
            connect_id,
            reason: UpgradeStop::ExchangeTimeout { round: 2, .. },
            ..
        }] if *connect_id == id
    ));
}

#[test]
fn settling_drops_the_attempts_undrained_outcomes() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);
    h.agent.handle_tick(at(10_301));
    // FellBackToRelay is queued but the host settles before draining it.
    h.agent.settled(id, Some(conn), at(10_302));
    assert!(
        drain_events(&mut h.agent)
            .iter()
            .all(|event| event.connect_id() != Some(id))
    );
}

#[test]
fn the_whole_upgrade_is_bounded() {
    let mut h = Harness::with_relay(NatConfig {
        upgrade_timeout_ms: 5_000,
        ..NatConfig::default()
    });
    let (id, conn) = drive_to_relayed(&mut h);
    drive_round_at(&mut h, conn, StreamId::new(90), 4_000);
    drain_events(&mut h.agent);

    // The punch window would run to t=7_002, past the 5 s upgrade budget.
    h.agent.handle_tick(at(5_301));
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::FellBackToRelay {
            connect_id,
            reason: UpgradeStop::UpgradeTimeout { budget_ms: 5_000 },
            ..
        }] if *connect_id == id
    ));
}

#[test]
fn no_attempt_event_follows_the_engine_settling() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, conn) = drive_to_relayed(&mut h);
    let actions = drive_round_at(&mut h, conn, StreamId::new(90), 310);
    let punch_conn = dial_conn_for(&actions, &h.target);
    drain_events(&mut h.agent);

    // The engine settles Connected on the circuit (its own deadline).
    h.agent.settled(id, Some(conn), at(400));
    let actions = drain_actions(&mut h.agent);
    assert!(
        actions
            .iter()
            .all(|out| !matches!(out, Out::CloseCircuit { conn_id } if *conn_id == conn)),
        "the kept connection stays open"
    );
    assert!(
        actions
            .iter()
            .any(|out| matches!(out, Out::CloseCircuit { conn_id } if *conn_id == punch_conn)),
        "the attempt's punch dial is dropped"
    );

    // Nothing the attempt owned can name it any more.
    h.agent.handle_tick(at(60_000));
    h.agent.handle_event(
        &SwarmEvent::ConnectionClosed {
            peer_id: h.target.clone(),
            conn_id: conn,
        },
        true,
        at(60_001),
    );
    assert!(
        drain_events(&mut h.agent)
            .iter()
            .all(|event| event.connect_id() != Some(id))
    );
    assert!(h.agent.is_idle());
}
