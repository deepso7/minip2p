//! Scripted dialer-race tests: no I/O, no clocks — every input is fed by
//! hand and every action/event asserted.

mod common;

use common::*;

use minip2p_core::{Multiaddr, PeerAddr};
use minip2p_nat::{ConnectId, NatAction, NatConfig, NatError, NatEvent, Path};
use minip2p_relay::{HOP_PROTOCOL_ID, Status};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, StreamId};

/// Drives a fresh connect attempt (with one direct candidate) through the
/// relay leg up to `Bridged`: direct dial at t0, stagger, relay dial, HOP
/// open/negotiate/CONNECT, STATUS:OK at t0+300.
///
/// Leaves the DCUtR CONNECT send action queued for the caller to drain. The
/// relay stream remains agent-owned until DCUtR has sent SYNC.
fn drive_to_bridged(h: &mut Harness, t0: u64) -> (ConnectId, StreamId) {
    let id = h
        .agent
        .connect(h.target.clone(), vec![maddr(TARGET_ADDR)], at(t0));
    let actions = drain_actions(&mut h.agent);
    let direct_token = dial_token_for(&actions, &h.target);
    h.agent
        .dial_result(direct_token, Ok(ConnectionId::new(1)), at(t0 + 5));

    h.agent.handle_tick(at(t0 + 200));
    let actions = drain_actions(&mut h.agent);
    let relay_token = dial_token_for(&actions, &h.relay);
    h.agent
        .dial_result(relay_token, Ok(ConnectionId::new(2)), at(t0 + 205));
    h.relay_session_ready(at(t0 + 210));

    let actions = drain_actions(&mut h.agent);
    let open_token = open_stream_token(&actions);
    let stream = StreamId::new(7);
    h.agent
        .stream_open_result(open_token, Ok(stream), at(t0 + 215));
    assert!(h.agent.owns_stream(&h.relay, stream));

    h.stream_ready(stream, at(t0 + 220));
    let actions = drain_actions(&mut h.agent);
    assert_eq!(send_stream_count(&actions), 1, "HOP CONNECT must be sent");

    h.stream_data(stream, hop_status(Status::Ok), at(t0 + 300));
    (id, stream)
}

fn advertised_dcutr_addrs(h: &mut Harness, t0: u64) -> Vec<Multiaddr> {
    drive_to_bridged(h, t0);
    let promotion = drain_actions(&mut h.agent);
    let target = h.target.clone();
    complete_promotion(&mut h.agent, &target, &promotion, at(t0 + 301));
    drain_events(&mut h.agent);
    let stream = StreamId::new(8_000 + t0);
    h.agent.handle_event(
        &SwarmEvent::StreamReady {
            conn_id: ConnectionId::new(TEST_CIRCUIT_ID),
            peer_id: target.clone(),
            stream_id: stream,
            protocol_id: minip2p_nat::DCUTR_PROTOCOL_ID.into(),
            initiated_locally: false,
        },
        at(t0 + 302),
    );
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: ConnectionId::new(TEST_CIRCUIT_ID),
            peer_id: target,
            stream_id: stream,
            data: dcutr_connect_reply(&[maddr(REMOTE_OBSERVED_ADDR)]),
        },
        at(t0 + 303),
    );
    dcutr_obs_addrs(&sent_data_on(&drain_actions(&mut h.agent), stream))
}

#[test]
fn direct_win_before_stagger_never_touches_the_relay() {
    let mut h = Harness::with_relay(NatConfig::default());
    let id = h
        .agent
        .connect(h.target.clone(), vec![maddr(TARGET_ADDR)], at(0));

    let actions = drain_actions(&mut h.agent);
    let token = dial_token_for(&actions, &h.target);
    assert_eq!(dial_count_for(&actions, &h.relay), 0);
    assert!(!has_hop_open(&actions));

    h.agent.dial_result(token, Ok(ConnectionId::new(1)), at(10));
    h.target_connected(at(50));

    let events = drain_events(&mut h.agent);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::PathEstablished { connect_id, path: Path::DirectDialed, .. }] if *connect_id == id
    ));

    // Ticking far past the stagger must not wake a relay leg.
    h.agent.handle_tick(at(1_000));
    let actions = drain_actions(&mut h.agent);
    assert!(
        actions.is_empty(),
        "no relay actions after a direct win: {actions:?}"
    );
    assert!(drain_events(&mut h.agent).is_empty());
    assert!(h.agent.is_idle());
}

#[test]
fn stagger_delays_the_relay_leg() {
    let mut h = Harness::with_relay(NatConfig::default());
    h.agent
        .connect(h.target.clone(), vec![maddr(TARGET_ADDR)], at(0));
    let actions = drain_actions(&mut h.agent);
    assert_eq!(dial_count_for(&actions, &h.target), 1);
    assert_eq!(dial_count_for(&actions, &h.relay), 0);

    // The stagger is the earliest pending deadline.
    assert_eq!(h.agent.next_timeout(0), Some(200));

    h.agent.handle_tick(at(199));
    assert!(drain_actions(&mut h.agent).is_empty());

    h.agent.handle_tick(at(200));
    let actions = drain_actions(&mut h.agent);
    assert_eq!(dial_count_for(&actions, &h.relay), 1);
}

#[test]
fn zero_stagger_races_both_legs_in_parallel() {
    let mut h = Harness::with_relay(NatConfig {
        relay_stagger_ms: 0,
        ..NatConfig::default()
    });
    h.agent
        .connect(h.target.clone(), vec![maddr(TARGET_ADDR)], at(0));
    let actions = drain_actions(&mut h.agent);
    assert_eq!(dial_count_for(&actions, &h.target), 1);
    assert_eq!(dial_count_for(&actions, &h.relay), 1);
}

#[test]
fn force_relay_skips_direct_dials_and_dcutr() {
    let mut h = Harness::with_relay(NatConfig {
        force_relay: true,
        ..NatConfig::default()
    });
    let id = h
        .agent
        .connect(h.target.clone(), vec![maddr(TARGET_ADDR)], at(0));
    let actions = drain_actions(&mut h.agent);
    assert_eq!(dial_count_for(&actions, &h.target), 0);
    assert_eq!(dial_count_for(&actions, &h.relay), 1);

    let relay_token = dial_token_for(&actions, &h.relay);
    h.agent
        .dial_result(relay_token, Ok(ConnectionId::new(2)), at(5));
    h.relay_session_ready(at(10));
    let open = drain_actions(&mut h.agent);
    let open_token = open_stream_token(&open);
    let stream = StreamId::new(41);
    h.agent.stream_open_result(open_token, Ok(stream), at(15));
    h.stream_ready(stream, at(20));
    drain_actions(&mut h.agent); // HOP CONNECT
    h.stream_data(stream, hop_status(Status::Ok), at(30));

    let promotion = drain_actions(&mut h.agent);
    assert_eq!(send_stream_count(&promotion), 0, "DCUtR was skipped");
    assert!(promotion.iter().any(|action| matches!(
        action,
        NatAction::PromoteBridge {
            role: minip2p_nat::BridgeRole::Initiator,
            ..
        }
    )));
    let target = h.target.clone();
    complete_promotion(&mut h.agent, &target, &promotion, at(31));
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::PathEstablished {
            connect_id,
            path: Path::Relayed { .. },
            ..
        }] if *connect_id == id
    ));
}

#[test]
fn default_connect_promotes_the_bridge_before_dcutr() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (_, stream) = drive_to_bridged(&mut h, 0);

    let actions = drain_actions(&mut h.agent);
    assert!(actions.iter().any(|action| matches!(
        action,
        NatAction::PromoteBridge {
            role: minip2p_nat::BridgeRole::Initiator,
            stream_id,
            ..
        } if *stream_id == stream
    )));
    assert_eq!(
        send_stream_count(&actions),
        0,
        "DCUtR starts on the promoted connection, not the raw bridge"
    );
}

#[test]
fn malformed_dcutr_keeps_the_established_relayed_path() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, _) = drive_to_bridged(&mut h, 0);
    let promotion = drain_actions(&mut h.agent);
    let target = h.target.clone();
    complete_promotion(&mut h.agent, &target, &promotion, at(301));
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::PathEstablished { connect_id, path: Path::Relayed { .. }, .. }]
            if *connect_id == id
    ));

    let stream = StreamId::new(9_001);
    h.agent.handle_event(
        &SwarmEvent::StreamReady {
            conn_id: ConnectionId::new(TEST_CIRCUIT_ID),
            peer_id: target.clone(),
            stream_id: stream,
            protocol_id: minip2p_nat::DCUTR_PROTOCOL_ID.into(),
            initiated_locally: false,
        },
        at(302),
    );
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: ConnectionId::new(TEST_CIRCUIT_ID),
            peer_id: target,
            stream_id: stream,
            data: b"\x13/multistream/1.0.0\n".to_vec(),
        },
        at(303),
    );

    let events = drain_events(&mut h.agent);
    assert!(matches!(
        events.as_slice(),
        [
            NatEvent::HolePunchFailed {
                connect_id,
                attempt: 1,
                ..
            },
            NatEvent::FellBackToRelay {
                connect_id: fallback_id,
                peer,
            }
        ] if *connect_id == id && *fallback_id == id && peer == &h.target
    ));
}

#[test]
fn force_relay_preserves_bytes_coalesced_behind_hop_success() {
    let mut h = Harness::with_relay(NatConfig {
        force_relay: true,
        ..NatConfig::default()
    });
    h.agent
        .connect(h.target.clone(), vec![maddr(TARGET_ADDR)], at(0));
    let actions = drain_actions(&mut h.agent);
    let relay_token = dial_token_for(&actions, &h.relay);
    h.agent
        .dial_result(relay_token, Ok(ConnectionId::new(2)), at(5));
    h.relay_session_ready(at(10));
    let open = drain_actions(&mut h.agent);
    let open_token = open_stream_token(&open);
    let stream = StreamId::new(41);
    h.agent.stream_open_result(open_token, Ok(stream), at(15));
    h.stream_ready(stream, at(20));
    drain_actions(&mut h.agent);

    let first_circuit_bytes = b"first noise-selection bytes".to_vec();
    let mut coalesced = hop_status(Status::Ok);
    coalesced.extend_from_slice(&first_circuit_bytes);
    h.stream_data(stream, coalesced, at(30));

    let promotion = drain_actions(&mut h.agent);
    assert_eq!(promoted_pending_data(&promotion), first_circuit_bytes);
}

#[test]
fn default_connect_preserves_noise_bytes_coalesced_behind_hop_success() {
    let mut h = Harness::with_relay(NatConfig::default());
    h.agent.connect(h.target.clone(), Vec::new(), at(0));
    let actions = drain_actions(&mut h.agent);
    let relay_token = dial_token_for(&actions, &h.relay);
    h.agent
        .dial_result(relay_token, Ok(ConnectionId::new(2)), at(5));
    h.relay_session_ready(at(10));
    let open = drain_actions(&mut h.agent);
    let stream = StreamId::new(42);
    h.agent
        .stream_open_result(open_stream_token(&open), Ok(stream), at(15));
    h.stream_ready(stream, at(20));
    drain_actions(&mut h.agent);

    let noise = b"\x13/multistream/1.0.0\n\x07/noise\n".to_vec();
    let mut coalesced = hop_status(Status::Ok);
    coalesced.extend_from_slice(&noise);
    h.stream_data(stream, coalesced, at(30));

    assert_eq!(promoted_pending_data(&drain_actions(&mut h.agent)), noise);
}

#[test]
fn no_direct_candidates_skip_the_stagger() {
    let mut h = Harness::with_relay(NatConfig::default());
    h.agent.connect(h.target.clone(), Vec::new(), at(0));
    let actions = drain_actions(&mut h.agent);
    assert_eq!(
        dial_count_for(&actions, &h.relay),
        1,
        "relay leg starts immediately when there is nothing to stagger against"
    );
}

#[test]
fn already_connected_peer_is_reported_without_starting_a_race() {
    let mut h = Harness::without_relay(NatConfig::default());
    h.target_connected(at(0));
    let id = h.agent.connect(h.target.clone(), Vec::new(), at(1));

    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::PathEstablished { connect_id, peer, path: Path::DirectDialed }]
            if *connect_id == id && *peer == h.target
    ));
    assert!(drain_actions(&mut h.agent).is_empty());
    assert!(h.agent.is_idle());
}

#[test]
fn unconfigured_peer_cannot_claim_an_inbound_stop_stream() {
    let mut h = Harness::without_relay(NatConfig::default());
    let attacker = peer(b"untrusted-peer");
    let stream = StreamId::new(88);
    let handled = h.agent.handle_event_with_disposition(
        &SwarmEvent::StreamReady {
            conn_id: minip2p_transport::ConnectionId::new(1),
            peer_id: attacker.clone(),
            stream_id: stream,
            protocol_id: minip2p_relay::STOP_PROTOCOL_ID.to_string(),
            initiated_locally: false,
        },
        at(0),
    );

    assert!(handled, "rejected NAT control streams stay internal");
    assert!(
        h.agent.owns_stream(&attacker, stream),
        "rejected stream remains owned until terminal close"
    );
    assert!(has_reset_for(&drain_actions(&mut h.agent), stream));

    assert!(h.agent.handle_event_with_disposition(
        &SwarmEvent::StreamData {
            conn_id: minip2p_transport::ConnectionId::new(1),
            peer_id: attacker.clone(),
            stream_id: stream,
            data: stop_connect(&h.target),
        },
        at(1),
    ));
    assert!(h.agent.handle_event_with_disposition(
        &SwarmEvent::StreamRemoteWriteClosed {
            conn_id: minip2p_transport::ConnectionId::new(1),
            peer_id: attacker.clone(),
            stream_id: stream,
        },
        at(2),
    ));
    assert!(h.agent.handle_event_with_disposition(
        &SwarmEvent::StreamClosed {
            conn_id: minip2p_transport::ConnectionId::new(1),
            peer_id: attacker.clone(),
            stream_id: stream,
        },
        at(3),
    ));
    assert!(!h.agent.owns_stream(&attacker, stream));
    assert!(drain_actions(&mut h.agent).is_empty());
    assert!(drain_events(&mut h.agent).is_empty());
}

#[test]
fn relay_supersede_does_not_abort_waiting_for_peer_ready() {
    let mut h = Harness::with_relay(NatConfig::default());
    h.agent.connect(h.target.clone(), Vec::new(), at(0));
    drain_actions(&mut h.agent); // relay dial

    h.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            conn_id: ConnectionId::new(1),
            peer_id: h.relay.clone(),
        },
        at(10),
    );
    h.agent.handle_event(
        &SwarmEvent::ConnectionClosed {
            conn_id: ConnectionId::new(1),
            peer_id: h.relay.clone(),
            cause: minip2p_swarm::ConnectionCloseCause::Transport,
        },
        at(11),
    );
    h.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            conn_id: ConnectionId::new(2),
            peer_id: h.relay.clone(),
        },
        at(12),
    );
    assert!(drain_events(&mut h.agent).is_empty());

    h.agent.handle_event(
        &SwarmEvent::PeerReady {
            peer_id: h.relay.clone(),
            protocols: vec![HOP_PROTOCOL_ID.into()],
        },
        at(13),
    );
    assert!(
        has_hop_open(&drain_actions(&mut h.agent)),
        "the replacement relay session must continue the waiting leg"
    );
}

#[test]
fn relay_supersede_does_not_abort_an_open_hop_request() {
    let mut h = Harness::with_relay(NatConfig::default());
    h.agent.connect(h.target.clone(), Vec::new(), at(0));
    drain_actions(&mut h.agent); // relay dial
    h.relay_session_ready(at(10));
    let open = drain_actions(&mut h.agent);
    let open_token = open_stream_token(&open);

    h.agent.handle_event(
        &SwarmEvent::ConnectionClosed {
            conn_id: ConnectionId::new(1),
            peer_id: h.relay.clone(),
            cause: minip2p_swarm::ConnectionCloseCause::Transport,
        },
        at(11),
    );
    h.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            conn_id: ConnectionId::new(2),
            peer_id: h.relay.clone(),
        },
        at(12),
    );
    assert!(drain_events(&mut h.agent).is_empty());

    let stream = StreamId::new(19);
    h.agent.stream_open_result(open_token, Ok(stream), at(13));
    assert!(
        h.agent.owns_stream(&h.relay, stream),
        "the HOP open result must remain owned after relay supersession"
    );
}

#[test]
fn bridge_close_before_dcutr_finishes_waits_for_live_direct_dials() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, stream) = drive_to_bridged(&mut h, 0);
    drain_actions(&mut h.agent);

    h.agent.handle_event(
        &SwarmEvent::StreamClosed {
            conn_id: minip2p_transport::ConnectionId::new(1),
            peer_id: h.relay.clone(),
            stream_id: stream,
        },
        at(310),
    );
    assert!(drain_events(&mut h.agent).is_empty());

    h.target_connected(at(320));
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::PathEstablished { connect_id, path: Path::DirectDialed, .. }]
            if *connect_id == id
    ));
}

#[test]
fn all_legs_failing_reports_connect_failed() {
    let mut h = Harness::with_relay(NatConfig::default());
    h.agent
        .connect(h.target.clone(), vec![maddr(TARGET_ADDR)], at(0));
    let actions = drain_actions(&mut h.agent);
    let direct_token = dial_token_for(&actions, &h.target);

    // Direct dial rejected synchronously; the relay leg is still pending.
    h.agent
        .dial_result(direct_token, Err("connection refused".into()), at(10));
    assert!(drain_events(&mut h.agent).is_empty());

    h.agent.handle_tick(at(200));
    let actions = drain_actions(&mut h.agent);
    let relay_token = dial_token_for(&actions, &h.relay);
    h.agent
        .dial_result(relay_token, Err("relay unreachable".into()), at(210));

    let events = drain_events(&mut h.agent);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::ConnectFailed {
            error: NatError::DialFailed(_),
            ..
        }]
    ));
    assert!(h.agent.is_idle());
}

#[test]
fn malformed_hop_response_fails_with_protocol_error() {
    let mut h = Harness::with_relay(NatConfig::default());
    h.agent.connect(h.target.clone(), Vec::new(), at(0));
    let actions = drain_actions(&mut h.agent);
    let relay_token = dial_token_for(&actions, &h.relay);
    h.agent
        .dial_result(relay_token, Ok(ConnectionId::new(2)), at(5));
    h.relay_session_ready(at(10));

    let actions = drain_actions(&mut h.agent);
    let open_token = open_stream_token(&actions);
    let stream = StreamId::new(3);
    h.agent.stream_open_result(open_token, Ok(stream), at(15));
    h.stream_ready(stream, at(20));
    drain_actions(&mut h.agent);

    // A complete frame whose payload is not a valid HopMessage.
    h.stream_data(stream, vec![0x05, b'j', b'u', b'n', b'k', b'!'], at(30));

    let events = drain_events(&mut h.agent);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::ConnectFailed {
            error: NatError::Protocol(_),
            ..
        }]
    ));
    let actions = drain_actions(&mut h.agent);
    assert!(
        has_reset_for(&actions, stream),
        "the dead HOP stream is reset"
    );
    assert!(!h.agent.owns_stream(&h.relay, stream));
    assert!(h.agent.is_idle());
}

#[test]
fn relay_refusal_fails_when_no_direct_leg_remains() {
    let mut h = Harness::with_relay(NatConfig::default());
    h.agent.connect(h.target.clone(), Vec::new(), at(0));
    let actions = drain_actions(&mut h.agent);
    let relay_token = dial_token_for(&actions, &h.relay);
    h.agent
        .dial_result(relay_token, Ok(ConnectionId::new(2)), at(5));
    h.relay_session_ready(at(10));

    let actions = drain_actions(&mut h.agent);
    let open_token = open_stream_token(&actions);
    let stream = StreamId::new(3);
    h.agent.stream_open_result(open_token, Ok(stream), at(15));
    h.stream_ready(stream, at(20));
    drain_actions(&mut h.agent);

    h.stream_data(stream, hop_status(Status::NoReservation), at(30));
    let events = drain_events(&mut h.agent);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::ConnectFailed {
            error: NatError::RelayRefused(_),
            ..
        }]
    ));
    let actions = drain_actions(&mut h.agent);
    assert!(
        has_reset_for(&actions, stream),
        "the refused HOP stream is reset"
    );
    assert!(h.agent.is_idle());
}

#[test]
fn duplicate_direct_connection_does_not_double_report() {
    let mut h = Harness::with_relay(NatConfig::default());
    h.agent
        .connect(h.target.clone(), vec![maddr(TARGET_ADDR)], at(0));
    drain_actions(&mut h.agent);
    h.target_connected(at(50));
    assert_eq!(drain_events(&mut h.agent).len(), 1);

    // A QUIC supersede re-emits ConnectionEstablished for the same peer.
    h.target_connected(at(60));
    assert!(drain_events(&mut h.agent).is_empty());
    assert!(drain_actions(&mut h.agent).is_empty());
}

#[test]
fn relay_leg_deadline_fails_a_stalled_leg() {
    let mut h = Harness::with_relay(NatConfig::default());
    h.agent.connect(h.target.clone(), Vec::new(), at(0));
    let actions = drain_actions(&mut h.agent);
    assert_eq!(dial_count_for(&actions, &h.relay), 1);

    // The relay never answers.
    h.agent.handle_tick(at(11_999));
    assert!(drain_events(&mut h.agent).is_empty());
    h.agent.handle_tick(at(12_000));
    let events = drain_events(&mut h.agent);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::ConnectFailed {
            error: NatError::Timeout,
            ..
        }]
    ));
    assert!(h.agent.is_idle());
}

#[test]
fn connect_deadline_fails_an_attempt_with_no_path() {
    let mut h = Harness::without_relay(NatConfig::default());
    h.agent
        .connect(h.target.clone(), vec![maddr(TARGET_ADDR)], at(0));
    let actions = drain_actions(&mut h.agent);
    let token = dial_token_for(&actions, &h.target);
    // The dial is accepted but the handshake never completes.
    h.agent.dial_result(token, Ok(ConnectionId::new(1)), at(5));

    h.agent.handle_tick(at(59_999));
    assert!(drain_events(&mut h.agent).is_empty());
    h.agent.handle_tick(at(60_000));
    let events = drain_events(&mut h.agent);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::ConnectFailed {
            error: NatError::Timeout,
            ..
        }]
    ));
    assert!(h.agent.is_idle());
}

#[test]
fn no_candidates_and_no_relay_fails_immediately() {
    let mut h = Harness::without_relay(NatConfig::default());
    let id = h.agent.connect(h.target.clone(), Vec::new(), at(0));
    let events = drain_events(&mut h.agent);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::ConnectFailed { connect_id, error: NatError::NoPathAvailable, .. }]
            if *connect_id == id
    ));
    assert!(h.agent.is_idle());
}

#[test]
fn direct_only_connect_never_arms_a_configured_relay() {
    let mut h = Harness::with_relay(NatConfig::default());
    let id = h.agent.connect_direct(h.target.clone(), Vec::new(), at(0));

    assert!(drain_actions(&mut h.agent).is_empty());
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::ConnectFailed {
            connect_id,
            error: NatError::NoPathAvailable,
            ..
        }] if *connect_id == id
    ));
    h.agent.handle_tick(at(1_000));
    assert!(drain_actions(&mut h.agent).is_empty());
    assert!(h.agent.is_idle());
}

#[test]
fn direct_only_connect_dials_candidates_without_relay_fallback() {
    let mut h = Harness::with_relay(NatConfig::default());
    h.agent
        .connect_direct(h.target.clone(), vec![maddr(TARGET_ADDR)], at(0));
    let actions = drain_actions(&mut h.agent);
    assert_eq!(dial_count_for(&actions, &h.target), 1);
    assert_eq!(dial_count_for(&actions, &h.relay), 0);

    h.agent.handle_tick(at(1_000));
    let actions = drain_actions(&mut h.agent);
    assert_eq!(dial_count_for(&actions, &h.relay), 0);
    assert!(!has_hop_open(&actions));
}

#[test]
fn wildcard_and_non_quic_candidates_are_filtered() {
    let mut h = Harness::without_relay(NatConfig::default());
    h.agent.connect(
        h.target.clone(),
        vec![
            maddr("/ip4/0.0.0.0/udp/4001/quic-v1"),
            maddr("/ip4/192.0.2.10/udp/4001"),
            maddr(TARGET_ADDR),
            maddr(TARGET_ADDR),
        ],
        at(0),
    );
    let actions = drain_actions(&mut h.agent);
    assert_eq!(
        dial_count_for(&actions, &h.target),
        1,
        "wildcards, non-QUIC shapes, and duplicates never get dialed"
    );
}

#[test]
fn identify_observed_addr_joins_dcutr_connect() {
    let mut h = Harness::with_relay(NatConfig::default());
    // The relay's identify tells us our public mapping before any attempt.
    identify_observed(
        &mut h.agent,
        &h.relay.clone(),
        &maddr(OUR_OBSERVED_ADDR),
        at(0),
    );

    let obs = advertised_dcutr_addrs(&mut h, 10);
    assert!(
        obs.contains(&maddr(LISTEN_ADDR)),
        "bound addresses stay in the CONNECT"
    );
    assert!(
        obs.contains(&maddr(OUR_OBSERVED_ADDR)),
        "the peer-observed public mapping must be advertised for the punch"
    );
}

#[test]
fn latest_observation_per_reporter_wins() {
    let stale = "/ip4/203.0.113.77/udp/1111/quic-v1";
    let mut h = Harness::with_relay(NatConfig::default());

    // Same reporter twice: only the fresh observation survives.
    let relay = h.relay.clone();
    identify_observed(&mut h.agent, &relay, &maddr(stale), at(0));
    identify_observed(&mut h.agent, &relay, &maddr(OUR_OBSERVED_ADDR), at(1));

    let obs = advertised_dcutr_addrs(&mut h, 10);
    assert!(obs.contains(&maddr(OUR_OBSERVED_ADDR)));
    assert!(!obs.contains(&maddr(stale)), "replaced observation leaks");
}

#[test]
fn reporter_disconnect_drops_its_observation() {
    let departed = "/ip4/203.0.113.88/udp/2222/quic-v1";
    let mut h = Harness::with_relay(NatConfig::default());

    // The relay reports a mapping, then its connection closes; the attempt
    // reconnects the relay, but the stale observation must not come back.
    let relay = h.relay.clone();
    h.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            conn_id: ConnectionId::new(1),
            peer_id: relay.clone(),
        },
        at(0),
    );
    identify_observed(&mut h.agent, &relay, &maddr(departed), at(0));
    h.agent.handle_event(
        &SwarmEvent::ConnectionClosed {
            conn_id: minip2p_transport::ConnectionId::new(1),
            peer_id: relay,
            cause: minip2p_swarm::ConnectionCloseCause::Transport,
        },
        at(1),
    );
    h.agent.handle_tick(at(1));
    h.agent.handle_tick(at(1));

    let obs = advertised_dcutr_addrs(&mut h, 10);
    assert_eq!(
        obs,
        vec![maddr(LISTEN_ADDR)],
        "dropped observation leaks into the CONNECT"
    );
}

#[test]
fn untracked_connection_close_is_ignored() {
    let mut h = Harness::without_relay(NatConfig::default());
    h.agent.handle_event(
        &SwarmEvent::ConnectionClosed {
            conn_id: ConnectionId::new(999),
            peer_id: peer(b"untracked-peer"),
            cause: minip2p_swarm::ConnectionCloseCause::Transport,
        },
        at(1),
    );

    assert!(drain_events(&mut h.agent).is_empty());
    assert!(drain_actions(&mut h.agent).is_empty());
    assert!(h.agent.is_idle());
}

#[test]
fn observed_addrs_from_untrusted_peers_are_ignored() {
    let attacker_chosen = "/ip4/198.51.100.200/udp/53/quic-v1";
    let mut h = Harness::with_relay(NatConfig::default());

    // Valid QUIC shapes, but neither reporter is a configured relay or
    // AutoNAT server — believing them would let any connected peer aim
    // punch-time UDP blasts at an address of its choosing.
    let target = h.target.clone();
    identify_observed(&mut h.agent, &target, &maddr(attacker_chosen), at(0));
    let other = peer(b"other-peer");
    identify_observed(&mut h.agent, &other, &maddr(attacker_chosen), at(1));

    let obs = advertised_dcutr_addrs(&mut h, 10);
    assert_eq!(
        obs,
        vec![maddr(LISTEN_ADDR)],
        "untrusted observation reached the CONNECT"
    );
}

#[test]
fn autonat_server_is_a_trusted_reporter() {
    let autonat = peer(b"autonat-server");
    let autonat_addr = PeerAddr::new(maddr("/ip4/203.0.113.60/udp/4009/quic-v1"), autonat.clone())
        .expect("valid autonat addr");
    let mut h = Harness::with_relay(NatConfig {
        autonat_servers: vec![autonat_addr],
        ..NatConfig::default()
    });
    identify_observed(&mut h.agent, &autonat, &maddr(OUR_OBSERVED_ADDR), at(0));

    let obs = advertised_dcutr_addrs(&mut h, 10);
    assert!(
        obs.contains(&maddr(OUR_OBSERVED_ADDR)),
        "a configured AutoNAT server's observation must be usable"
    );
}

#[test]
fn tcp_observation_does_not_replace_a_trusted_quic_punch_candidate() {
    let mut h = Harness::with_relay(NatConfig::default());
    let relay = h.relay.clone();
    identify_observed(&mut h.agent, &relay, &maddr(OUR_OBSERVED_ADDR), at(0));
    identify_observed(
        &mut h.agent,
        &relay,
        &maddr("/ip4/198.51.100.50/tcp/4001"),
        at(1),
    );

    let obs = advertised_dcutr_addrs(&mut h, 10);
    assert!(
        obs.contains(&maddr(OUR_OBSERVED_ADDR)),
        "a later TCP Identify observation must not evict the relay's QUIC mapping"
    );
}

#[test]
fn undecodable_observed_addr_bytes_are_ignored() {
    let mut h = Harness::with_relay(NatConfig::default());
    let relay = h.relay.clone();
    h.agent.handle_event(
        &SwarmEvent::IdentifyReceived {
            peer_id: relay,
            info: minip2p_swarm::IdentifyMessage {
                observed_addr: Some(vec![0xff, 0xff, 0xff]),
                ..minip2p_swarm::IdentifyMessage::default()
            },
        },
        at(0),
    );

    let obs = advertised_dcutr_addrs(&mut h, 10);
    assert_eq!(
        obs,
        vec![maddr(LISTEN_ADDR)],
        "only the validated bound address may be advertised"
    );
}

#[test]
fn non_quic_observed_addr_is_ignored() {
    let mut h = Harness::with_relay(NatConfig::default());
    // Well-formed but not a dialable QUIC transport.
    identify_observed(
        &mut h.agent,
        &h.relay.clone(),
        &maddr("/ip4/203.0.113.9/udp/4001"),
        at(0),
    );

    let obs = advertised_dcutr_addrs(&mut h, 10);
    assert_eq!(
        obs,
        vec![maddr(LISTEN_ADDR)],
        "only the validated bound address may be advertised"
    );
}
