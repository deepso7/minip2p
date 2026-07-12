//! Scripted responder-side tests: inbound STOP circuits, the DCUtR
//! responder exchange, punch-back dials, and the UDP blast schedule.

mod common;

use common::*;

use minip2p_core::PeerAddr;
use minip2p_nat::{NatAction, NatConfig, NatEvent};
use minip2p_relay::STOP_PROTOCOL_ID;
use minip2p_swarm::SwarmEvent;
use minip2p_transport::StreamId;

const STOP_STREAM: u64 = 40;

/// Inbound STOP is accepted only from a relay explicitly configured by the
/// application. The scripted responder tests use the harness's relay peer.
fn inbound_harness(mut config: NatConfig) -> Harness {
    config.reservation_policy = minip2p_nat::ReservationPolicy::Never;
    config.relays.push(
        PeerAddr::new(maddr(RELAY_TRANSPORT_ADDR), peer(b"relay-peer"))
            .expect("valid configured relay"),
    );
    Harness::without_relay(config)
}

/// Delivers an inbound STOP `StreamReady` (relay-initiated) to the agent.
fn inbound_stop_stream(h: &mut Harness, stream: StreamId, t: u64) {
    h.agent.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: h.relay.clone(),
            stream_id: stream,
            protocol_id: STOP_PROTOCOL_ID.to_string(),
            initiated_locally: false,
        },
        at(t),
    );
}

/// Drives a claimed circuit through CONNECT-accept and the DCUtR exchange
/// up to (but not including) SYNC.
fn drive_to_sync_ready(h: &mut Harness, stream: StreamId) {
    let target = h.target.clone();
    h.stream_data(stream, stop_connect(&target), at(10));
    let actions = drain_actions(&mut h.agent);
    assert_eq!(send_stream_count(&actions), 1, "STATUS:OK must be sent");

    // The initiator's DCUtR CONNECT (same shape as a reply).
    h.stream_data(
        stream,
        dcutr_connect_reply(&[maddr(REMOTE_OBSERVED_ADDR)]),
        at(20),
    );
    let actions = drain_actions(&mut h.agent);
    assert_eq!(
        send_stream_count(&actions),
        1,
        "our DCUtR CONNECT reply must be sent"
    );
}

#[test]
fn full_inbound_flow_punches_back_and_upgrades() {
    let mut h = inbound_harness(NatConfig::default());
    let stream = StreamId::new(STOP_STREAM);

    inbound_stop_stream(&mut h, stream, 0);
    assert!(h.agent.owns_stream(&h.relay, stream), "STOP stream claimed");

    drive_to_sync_ready(&mut h, stream);

    h.stream_data(stream, dcutr_sync(), at(30));
    let events = drain_events(&mut h.agent);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::InboundRelayCircuit { peer, stream_id, .. }]
            if *peer == h.target && *stream_id == stream
    ));
    let actions = drain_actions(&mut h.agent);
    assert_eq!(
        dial_count_for(&actions, &h.target),
        1,
        "simultaneous-open dial toward the initiator's observed address"
    );
    assert!(
        !h.agent.owns_stream(&h.relay, stream),
        "bridge belongs to the app after SYNC"
    );

    // First blast waits out the configured sync delay (50ms after SYNC).
    h.agent.handle_tick(at(79));
    assert_eq!(blast_count(&drain_actions(&mut h.agent)), 0);
    h.agent.handle_tick(at(80));
    let actions = drain_actions(&mut h.agent);
    assert_eq!(blast_count(&actions), 1);
    assert!(actions.iter().any(|a| matches!(
        a,
        NatAction::SendRandomUdp { target, payload_len: 32 }
            if *target == maddr(REMOTE_OBSERVED_ADDR)
    )));
    h.agent.handle_tick(at(180));
    assert_eq!(
        blast_count(&drain_actions(&mut h.agent)),
        1,
        "100ms cadence"
    );

    // The punch lands: blasts stop, the upgrade is announced.
    h.target_connected(at(250));
    let events = drain_events(&mut h.agent);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::InboundDirectUpgrade { peer }] if *peer == h.target
    ));
    h.agent.handle_tick(at(400));
    assert_eq!(blast_count(&drain_actions(&mut h.agent)), 0);
    assert!(h.agent.is_idle());
}

#[test]
fn sync_coalesced_with_application_data_preserves_the_bridge_remainder() {
    let mut h = inbound_harness(NatConfig::default());
    let stream = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stream, 0);
    drive_to_sync_ready(&mut h, stream);

    let app_data = b"first application bytes".to_vec();
    let mut coalesced = dcutr_sync();
    coalesced.extend_from_slice(&app_data);
    h.stream_data(stream, coalesced, at(30));

    let events = drain_events(&mut h.agent);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::InboundRelayCircuit {
            peer,
            stream_id,
            pending_data,
        }] if *peer == h.target && *stream_id == stream && *pending_data == app_data
    ));
}

#[test]
fn zero_blast_interval_is_clamped_to_one_millisecond() {
    let mut config = NatConfig::default();
    config.blast_interval_ms = 0;
    let mut h = inbound_harness(config);
    let stream = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stream, 0);
    drive_to_sync_ready(&mut h, stream);
    h.stream_data(stream, dcutr_sync(), at(30));
    drain_events(&mut h.agent);
    drain_actions(&mut h.agent);

    // The first due tick completes promptly (rather than repeatedly
    // scheduling the same instant forever), then the clamped cadence is 1ms.
    h.agent.handle_tick(at(80));
    assert_eq!(blast_count(&drain_actions(&mut h.agent)), 1);
    h.agent.handle_tick(at(81));
    assert_eq!(blast_count(&drain_actions(&mut h.agent)), 1);
}

#[test]
fn blast_schedule_exhausts_at_the_punch_deadline() {
    let mut h = inbound_harness(NatConfig::default());
    let stream = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stream, 0);
    drive_to_sync_ready(&mut h, stream);
    h.stream_data(stream, dcutr_sync(), at(30));
    drain_events(&mut h.agent);
    drain_actions(&mut h.agent);

    // Catch up through the whole window (deadline 30 + 3000).
    h.agent.handle_tick(at(3_100));
    assert!(blast_count(&drain_actions(&mut h.agent)) > 0);
    h.agent.handle_tick(at(3_200));
    assert_eq!(
        blast_count(&drain_actions(&mut h.agent)),
        0,
        "no blasts after the punch window"
    );

    // No direct connection ever arrives: the circuit lingers through the
    // initiator's retry window, then retires with no further events.
    h.agent.handle_tick(at(9_030));
    assert!(drain_events(&mut h.agent).is_empty());
    assert!(h.agent.is_idle());
}

#[test]
fn stalled_exchange_still_releases_the_bridge() {
    let mut h = inbound_harness(NatConfig::default());
    let stream = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stream, 0);
    let target = h.target.clone();
    h.stream_data(stream, stop_connect(&target), at(10));
    drain_actions(&mut h.agent);

    // The initiator never starts DCUtR; at the exchange deadline the
    // accepted bridge goes to the app punch-less.
    h.agent.handle_tick(at(12_000));
    let events = drain_events(&mut h.agent);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::InboundRelayCircuit { peer, .. }] if *peer == h.target
    ));
    let actions = drain_actions(&mut h.agent);
    assert_eq!(dial_count_for(&actions, &h.target), 0);
    assert_eq!(blast_count(&actions), 0);
    assert!(!h.agent.owns_stream(&h.relay, stream));
    assert!(h.agent.is_idle());
}

#[test]
fn remote_write_close_keeps_an_accepted_bridge_alive_until_handoff() {
    let mut h = inbound_harness(NatConfig::default());
    let stream = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stream, 0);
    let target = h.target.clone();
    h.stream_data(stream, stop_connect(&target), at(10));
    drain_actions(&mut h.agent);

    h.agent.handle_event(
        &SwarmEvent::StreamRemoteWriteClosed {
            peer_id: h.relay.clone(),
            stream_id: stream,
        },
        at(20),
    );
    assert!(h.agent.owns_stream(&h.relay, stream));
    assert!(!has_reset_for(&drain_actions(&mut h.agent), stream));

    // The half-close does not kill the local write half; hand the accepted
    // bridge to the app once the DCUtR exchange deadline expires.
    h.agent.handle_tick(at(12_000));
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::InboundRelayCircuit { peer, .. }] if *peer == h.target
    ));
}

#[test]
fn malformed_stop_connect_tears_the_circuit_down() {
    let mut h = inbound_harness(NatConfig::default());
    let stream = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stream, 0);

    // A STATUS frame where a CONNECT is required.
    h.stream_data(stream, hop_status(minip2p_relay::Status::Ok), at(10));
    let actions = drain_actions(&mut h.agent);
    assert!(has_reset_for(&actions, stream));
    assert!(drain_events(&mut h.agent).is_empty());
    assert!(!h.agent.owns_stream(&h.relay, stream));
    assert!(h.agent.is_idle());
}

#[test]
fn unparsable_source_peer_id_is_rejected() {
    let mut h = inbound_harness(NatConfig::default());
    let stream = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stream, 0);

    h.stream_data(stream, stop_connect_raw(vec![0xFF, 0x00, 0x01]), at(10));
    let actions = drain_actions(&mut h.agent);
    assert_eq!(
        send_stream_count(&actions),
        1,
        "a rejection STATUS goes back to the relay"
    );
    assert!(has_reset_for(&actions, stream));
    assert!(drain_events(&mut h.agent).is_empty());
    assert!(h.agent.is_idle());
}

#[test]
fn inbound_application_streams_are_never_claimed() {
    let mut h = inbound_harness(NatConfig::default());
    let stream = StreamId::new(STOP_STREAM);
    h.agent.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: h.relay.clone(),
            stream_id: stream,
            protocol_id: "/my-app/1.0.0".to_string(),
            initiated_locally: false,
        },
        at(0),
    );
    assert!(!h.agent.owns_stream(&h.relay, stream));
    assert!(drain_actions(&mut h.agent).is_empty());
    assert!(h.agent.is_idle());
}

#[test]
fn relay_disconnect_before_release_drops_the_circuit() {
    let mut h = inbound_harness(NatConfig::default());
    let stream = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stream, 0);
    let target = h.target.clone();
    h.stream_data(stream, stop_connect(&target), at(10));
    drain_actions(&mut h.agent);

    h.agent.handle_event(
        &SwarmEvent::ConnectionClosed {
            peer_id: h.relay.clone(),
        },
        at(20),
    );
    assert!(drain_events(&mut h.agent).is_empty());
    assert!(!h.agent.owns_stream(&h.relay, stream));
    assert!(h.agent.is_idle());
}
