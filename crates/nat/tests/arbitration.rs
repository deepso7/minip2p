//! Scripted dialer-race tests: no I/O, no clocks — every input is fed by
//! hand and every action/event asserted.

mod common;

use common::*;

use minip2p_core::{Multiaddr, PeerAddr};
use minip2p_nat::{ConnectId, NatAction, NatConfig, NatError, NatEvent, Path};
use minip2p_relay::Status;
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

/// Continues a bridged attempt through the DCUtR reply: punch dial + SYNC
/// go out, then the bridge is handed back to the application and announced.
fn drive_to_sync(h: &mut Harness, stream: StreamId, now_ms: u64) -> Vec<NatAction> {
    h.stream_data(
        stream,
        dcutr_connect_reply(&[maddr(REMOTE_OBSERVED_ADDR)]),
        at(now_ms),
    );
    let actions = drain_actions(&mut h.agent);
    assert_eq!(
        dial_count_for(&actions, &h.target),
        1,
        "one punch dial for the observed address"
    );
    assert_eq!(send_stream_count(&actions), 1, "SYNC must be sent");
    assert!(
        !h.agent.owns_stream(&h.relay, stream),
        "bridge belongs to the app once SYNC is out"
    );
    let events = drain_events(&mut h.agent);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::PathEstablished { path: Path::Relayed { stream_id, .. }, .. }]
            if *stream_id == stream
    ));
    actions
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
fn relayed_path_upgrades_to_direct_without_misattribution() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, stream) = drive_to_bridged(&mut h, 0);

    assert!(drain_events(&mut h.agent).is_empty());
    assert!(h.agent.owns_stream(&h.relay, stream));
    let actions = drain_actions(&mut h.agent);
    assert_eq!(
        send_stream_count(&actions),
        1,
        "DCUtR CONNECT goes out on the bridge"
    );

    drive_to_sync(&mut h, stream, 350);

    // The punch lands: the direct connection appears.
    h.target_connected(at(600));
    let events = drain_events(&mut h.agent);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::PathUpgraded {
            connect_id,
            from: Path::Relayed { .. },
            to: Path::DirectDialed,
            ..
        }] if *connect_id == id
    ));
    let actions = drain_actions(&mut h.agent);
    assert!(
        has_reset_for(&actions, stream),
        "the superseded bridge must be reset, never silently leaked"
    );
    assert!(h.agent.is_idle());
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
            peer_id: attacker.clone(),
            stream_id: stream,
            data: stop_connect(&h.target),
        },
        at(1),
    ));
    assert!(h.agent.handle_event_with_disposition(
        &SwarmEvent::StreamRemoteWriteClosed {
            peer_id: attacker.clone(),
            stream_id: stream,
        },
        at(2),
    ));
    assert!(h.agent.handle_event_with_disposition(
        &SwarmEvent::StreamClosed {
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
fn remote_write_close_during_dcutr_releases_relay_and_keeps_direct_dials_live() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, stream) = drive_to_bridged(&mut h, 0);
    drain_actions(&mut h.agent);

    h.agent.handle_event(
        &SwarmEvent::StreamRemoteWriteClosed {
            peer_id: h.relay.clone(),
            stream_id: stream,
        },
        at(310),
    );

    assert!(!h.agent.owns_stream(&h.relay, stream));
    assert!(drain_actions(&mut h.agent).is_empty());
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [
            NatEvent::HolePunchFailed { connect_id: failed, .. },
            NatEvent::PathEstablished {
                connect_id,
                path: Path::Relayed {
                    remote_write_closed: true,
                    ..
                },
                ..
            }
        ] if *failed == id && *connect_id == id
    ));

    h.target_connected(at(320));
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::PathUpgraded {
            connect_id,
            from: Path::Relayed {
                remote_write_closed: true,
                ..
            },
            to: Path::DirectDialed,
            ..
        }] if *connect_id == id
    ));
}

#[test]
fn relay_supersede_scrubs_old_stream_ids_without_resetting_the_new_connection() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (_, stream) = drive_to_bridged(&mut h, 0);
    drain_actions(&mut h.agent);
    assert!(h.agent.owns_stream(&h.relay, stream));

    h.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            peer_id: h.relay.clone(),
        },
        at(310),
    );

    assert!(!h.agent.owns_stream(&h.relay, stream));
    assert!(
        !has_reset_for(&drain_actions(&mut h.agent), stream),
        "a stale stream id must never reset a colliding stream on the replacement connection"
    );

    // The replacement connection may reuse the same stream id. Its event
    // must not be routed into the retired attempt.
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            peer_id: h.relay.clone(),
            stream_id: stream,
            data: b"new connection data".to_vec(),
        },
        at(311),
    );
    assert!(drain_actions(&mut h.agent).is_empty());
    assert!(drain_events(&mut h.agent).is_empty());
}

#[test]
fn bridge_close_before_dcutr_finishes_waits_for_live_direct_dials() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, stream) = drive_to_bridged(&mut h, 0);
    drain_actions(&mut h.agent);

    h.agent.handle_event(
        &SwarmEvent::StreamClosed {
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
fn released_bridge_close_cannot_be_reported_as_a_relay_fallback() {
    let mut h = Harness::with_relay(NatConfig {
        punch_max_retries: 0,
        ..NatConfig::default()
    });
    let (id, stream) = drive_to_bridged(&mut h, 0);
    drain_actions(&mut h.agent);
    drive_to_sync(&mut h, stream, 350);

    // The raw stream is application-owned, but the agent still observes its
    // terminal event to keep the direct-upgrade race honest.
    h.agent.handle_event(
        &SwarmEvent::StreamClosed {
            peer_id: h.relay.clone(),
            stream_id: stream,
        },
        at(400),
    );
    h.agent.handle_tick(at(3_350));
    let events = drain_events(&mut h.agent);
    assert!(matches!(
        events.as_slice(),
        [
            NatEvent::HolePunchFailed { .. },
            NatEvent::ConnectFailed { connect_id, .. },
        ] if *connect_id == id
    ));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, NatEvent::FellBackToRelay { .. }))
    );
}

#[test]
fn punch_exhaustion_falls_back_to_the_relay() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, stream) = drive_to_bridged(&mut h, 0);
    drain_actions(&mut h.agent);
    drive_to_sync(&mut h, stream, 350);

    // Default config: one window + two retries, 3s each.
    for (tick_ms, window) in [(3_350, 1u32), (6_350, 2)] {
        h.agent.handle_tick(at(tick_ms));
        let events = drain_events(&mut h.agent);
        assert!(matches!(
            events.as_slice(),
            [NatEvent::HolePunchFailed { attempt, .. }] if *attempt == window
        ));
        let actions = drain_actions(&mut h.agent);
        assert_eq!(
            dial_count_for(&actions, &h.target),
            1,
            "each retry re-dials the observed address"
        );
    }

    h.agent.handle_tick(at(9_350));
    let events = drain_events(&mut h.agent);
    assert!(matches!(
        events.as_slice(),
        [
            NatEvent::HolePunchFailed { attempt: 3, .. },
            NatEvent::FellBackToRelay { connect_id, .. },
        ] if *connect_id == id
    ));
    let actions = drain_actions(&mut h.agent);
    assert!(
        !has_reset_for(&actions, stream),
        "the surviving relayed path must not be reset"
    );
    assert!(!h.agent.owns_stream(&h.relay, stream));
    assert!(h.agent.is_idle());
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
fn initiator_reply_coalesced_with_application_data_preserves_remainder() {
    let mut h = Harness::with_relay(NatConfig::default());
    let id = h.agent.connect(h.target.clone(), Vec::new(), at(0));
    let actions = drain_actions(&mut h.agent);
    let relay_token = dial_token_for(&actions, &h.relay);
    h.agent
        .dial_result(relay_token, Ok(ConnectionId::new(2)), at(5));
    h.relay_session_ready(at(10));

    let actions = drain_actions(&mut h.agent);
    let open_token = open_stream_token(&actions);
    let stream = StreamId::new(9);
    h.agent.stream_open_result(open_token, Ok(stream), at(15));
    h.stream_ready(stream, at(20));
    drain_actions(&mut h.agent);

    // STATUS:OK and the responder's DCUtR CONNECT coalesced in one read:
    // the pipelined bytes must feed the just-created DCUtR machine inside
    // the same cascade.
    let app_data = b"application bytes after dcutr reply";
    let mut coalesced = hop_status(Status::Ok);
    coalesced.extend(dcutr_connect_reply(&[maddr(REMOTE_OBSERVED_ADDR)]));
    coalesced.extend_from_slice(app_data);
    h.stream_data(stream, coalesced, at(100));

    let events = drain_events(&mut h.agent);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::PathEstablished {
            connect_id,
            path: Path::Relayed { pending_data, .. },
            ..
        }] if *connect_id == id && pending_data == app_data
    ));
    let actions = drain_actions(&mut h.agent);
    assert_eq!(
        dial_count_for(&actions, &h.target),
        1,
        "punch dial issued from the pipelined reply"
    );
    assert_eq!(
        send_stream_count(&actions),
        2,
        "DCUtR CONNECT and SYNC both go out"
    );
    assert!(!h.agent.owns_stream(&h.relay, stream));

    h.target_connected(at(110));
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::PathUpgraded {
            connect_id,
            from: Path::Relayed { pending_data, .. },
            to: Path::DirectPunched,
            ..
        }] if *connect_id == id && pending_data.is_empty()
    ));
}

#[test]
fn oversized_dcutr_connect_falls_back_to_relay() {
    let mut h = Harness::with_relay(NatConfig::default());
    // Enough distinct addresses that the encoded DCUtR CONNECT exceeds the
    // 4 KiB frame cap, tripping the machine's deferred construction error.
    let addrs: Vec<Multiaddr> = (1u16..=400)
        .map(|port| maddr(&format!("/ip4/198.51.100.5/udp/{port}/quic-v1")))
        .collect();
    h.agent.set_listen_addrs(&addrs);

    let (id, stream) = drive_to_bridged(&mut h, 0);
    let events = drain_events(&mut h.agent);
    assert!(matches!(
        events.as_slice(),
        [
            NatEvent::PathEstablished { path: Path::Relayed { .. }, .. },
            NatEvent::HolePunchFailed { .. },
            NatEvent::FellBackToRelay { connect_id, .. },
        ] if *connect_id == id
    ));
    assert!(!h.agent.owns_stream(&h.relay, stream));
    assert!(h.agent.is_idle());
}

#[test]
fn foreign_stream_events_are_ignored_without_state_changes() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (_, stream) = drive_to_bridged(&mut h, 0);
    drain_events(&mut h.agent);
    drain_actions(&mut h.agent);

    // A stream the agent never opened — same peer, different id.
    let foreign = StreamId::new(1_234);
    assert!(!h.agent.owns_stream(&h.relay, foreign));
    h.stream_data(foreign, b"app data".to_vec(), at(320));

    // Same id as the bridge but on a different peer's connection.
    assert!(!h.agent.owns_stream(&h.target, stream));
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            peer_id: h.target.clone(),
            stream_id: stream,
            data: b"app data".to_vec(),
        },
        at(321),
    );

    assert!(drain_actions(&mut h.agent).is_empty());
    assert!(drain_events(&mut h.agent).is_empty());
    assert!(
        h.agent.owns_stream(&h.relay, stream),
        "bridge is still owned"
    );
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
fn cancel_mid_race_resets_streams_and_goes_quiet() {
    let mut h = Harness::with_relay(NatConfig::default());
    let (id, stream) = drive_to_bridged(&mut h, 0);
    drain_events(&mut h.agent);
    drain_actions(&mut h.agent);

    h.agent.cancel(id, at(320));
    let actions = drain_actions(&mut h.agent);
    assert!(has_reset_for(&actions, stream));
    assert!(drain_events(&mut h.agent).is_empty(), "cancel is silent");
    assert!(!h.agent.owns_stream(&h.relay, stream));

    // Late inputs for the dead attempt change nothing.
    h.stream_data(stream, hop_status(Status::Ok), at(330));
    h.target_connected(at(340));
    assert!(drain_actions(&mut h.agent).is_empty());
    assert!(drain_events(&mut h.agent).is_empty());
    assert!(h.agent.is_idle());
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

    let (_id, stream) = drive_to_bridged(&mut h, 10);
    let actions = drain_actions(&mut h.agent);
    let obs = dcutr_obs_addrs(&sent_data_on(&actions, stream));
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

    let (_id, stream) = drive_to_bridged(&mut h, 10);
    let actions = drain_actions(&mut h.agent);
    let obs = dcutr_obs_addrs(&sent_data_on(&actions, stream));
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
    identify_observed(&mut h.agent, &relay, &maddr(departed), at(0));
    h.agent
        .handle_event(&SwarmEvent::ConnectionClosed { peer_id: relay }, at(1));

    let (_id, stream) = drive_to_bridged(&mut h, 10);
    let actions = drain_actions(&mut h.agent);
    let obs = dcutr_obs_addrs(&sent_data_on(&actions, stream));
    assert_eq!(
        obs,
        vec![maddr(LISTEN_ADDR)],
        "dropped observation leaks into the CONNECT"
    );
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

    let (_id, stream) = drive_to_bridged(&mut h, 10);
    let actions = drain_actions(&mut h.agent);
    let obs = dcutr_obs_addrs(&sent_data_on(&actions, stream));
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

    let (_id, stream) = drive_to_bridged(&mut h, 10);
    let actions = drain_actions(&mut h.agent);
    let obs = dcutr_obs_addrs(&sent_data_on(&actions, stream));
    assert!(
        obs.contains(&maddr(OUR_OBSERVED_ADDR)),
        "a configured AutoNAT server's observation must be usable"
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

    let (_id, stream) = drive_to_bridged(&mut h, 10);
    let actions = drain_actions(&mut h.agent);
    let obs = dcutr_obs_addrs(&sent_data_on(&actions, stream));
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

    let (_id, stream) = drive_to_bridged(&mut h, 10);
    let actions = drain_actions(&mut h.agent);
    let obs = dcutr_obs_addrs(&sent_data_on(&actions, stream));
    assert_eq!(
        obs,
        vec![maddr(LISTEN_ADDR)],
        "only the validated bound address may be advertised"
    );
}
