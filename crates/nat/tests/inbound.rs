//! Scripted responder-side tests: inbound STOP circuits, the DCUtR
//! responder exchange, and the UDP blast schedule.

mod common;

use common::*;

use minip2p_core::PeerAddr;
use minip2p_nat::{
    AUTONAT_PROTOCOL_ID, DCUTR_PROTOCOL_ID, HOP_PROTOCOL_ID, NatAction, NatConfig, NatEvent,
    STOP_PROTOCOL_ID,
};
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
            conn_id: minip2p_transport::ConnectionId::new(1),
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
fn full_inbound_flow_blasts_and_upgrades() {
    let mut h = inbound_harness(NatConfig::default());
    let stream = StreamId::new(STOP_STREAM);

    inbound_stop_stream(&mut h, stream, 0);
    assert!(h.agent.owns_stream(&h.relay, stream), "STOP stream claimed");

    drive_to_sync_ready(&mut h, stream);

    h.stream_data(stream, dcutr_sync(), at(30));
    let actions = drain_actions(&mut h.agent);
    assert!(actions.iter().any(|action| matches!(
        action,
        NatAction::PromoteBridge {
            relay,
            stream_id,
            remote_peer,
            ..
        } if relay == &h.relay && *stream_id == stream && remote_peer == &h.target
    )));
    let target = h.target.clone();
    complete_promotion(&mut h.agent, &target, &actions, at(31));
    assert_eq!(
        dial_count_for(&actions, &h.target),
        0,
        "only the initiator dials; a responder dial would race it and the \
         superseded connection would lose its streams"
    );
    assert!(
        !h.agent.owns_stream(&h.relay, stream),
        "bridge belongs to the circuit transport after SYNC"
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
fn force_relay_promotes_immediately_after_stop_acceptance() {
    let mut h = inbound_harness(NatConfig {
        force_relay: true,
        ..NatConfig::default()
    });
    let stream = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stream, 0);
    let target = h.target.clone();
    h.stream_data(stream, stop_connect(&target), at(10));
    let actions = drain_actions(&mut h.agent);
    assert_eq!(
        send_stream_count(&actions),
        1,
        "only STOP STATUS:OK is sent"
    );
    assert!(actions.iter().any(|action| matches!(
        action,
        NatAction::PromoteBridge {
            role: minip2p_nat::BridgeRole::Responder,
            ..
        }
    )));
    complete_promotion(&mut h.agent, &target, &actions, at(11));
    assert!(h.agent.is_idle());
}

#[test]
fn force_relay_preserves_bytes_coalesced_behind_stop_connect() {
    let mut h = inbound_harness(NatConfig {
        force_relay: true,
        ..NatConfig::default()
    });
    let stream = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stream, 0);

    let application_data = b"first circuit transport bytes".to_vec();
    let mut coalesced = stop_connect(&h.target);
    coalesced.extend_from_slice(&application_data);
    h.stream_data(stream, coalesced, at(10));

    let actions = drain_actions(&mut h.agent);
    assert_eq!(send_stream_count(&actions), 1, "STOP STATUS:OK is sent");
    assert_eq!(promoted_pending_data(&actions), application_data);
}

#[test]
fn stalled_inbound_circuit_handshake_is_closed_at_its_deadline() {
    let mut h = inbound_harness(NatConfig {
        force_relay: true,
        circuit_handshake_timeout_ms: 5,
        ..NatConfig::default()
    });
    let stream = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stream, 0);
    let target = h.target.clone();
    h.stream_data(stream, stop_connect(&target), at(10));
    let actions = drain_actions(&mut h.agent);
    let conn_id = minip2p_transport::ConnectionId::new(TEST_CIRCUIT_ID);
    h.agent
        .promote_result(promote_token(&actions), Ok(conn_id), at(11));

    h.agent.handle_tick(at(16));
    assert!(
        drain_actions(&mut h.agent).iter().any(
            |action| matches!(action, NatAction::CloseCircuit { conn_id: id } if *id == conn_id)
        )
    );
    assert!(h.agent.is_idle());
}

#[test]
fn established_inbound_circuit_disarms_its_handshake_deadline() {
    let mut h = inbound_harness(NatConfig {
        force_relay: true,
        circuit_handshake_timeout_ms: 5,
        ..NatConfig::default()
    });
    let stream = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stream, 0);
    let target = h.target.clone();
    h.stream_data(stream, stop_connect(&target), at(10));
    let actions = drain_actions(&mut h.agent);
    let conn_id = complete_promotion(&mut h.agent, &target, &actions, at(11));
    drain_events(&mut h.agent);
    drain_actions(&mut h.agent);

    h.agent.handle_tick(at(100));
    assert!(
        !drain_actions(&mut h.agent).iter().any(
            |action| matches!(action, NatAction::CloseCircuit { conn_id: id } if *id == conn_id)
        ),
        "a ready inbound circuit must not be reclaimed by its old handshake deadline"
    );
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

    let actions = drain_actions(&mut h.agent);
    assert_eq!(promoted_pending_data(&actions), app_data);
}

#[test]
fn zero_blast_interval_is_clamped_to_one_millisecond() {
    let config = NatConfig {
        blast_interval_ms: 0,
        ..NatConfig::default()
    };
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
fn peer_supplied_punch_targets_must_be_global_unicast_ips() {
    let mut h = inbound_harness(NatConfig::default());
    let stream = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stream, 0);
    let target = h.target.clone();
    h.stream_data(stream, stop_connect(&target), at(10));
    drain_actions(&mut h.agent);

    let global_v4 = maddr("/ip4/8.8.8.8/udp/4001/quic-v1");
    let global_v6 = maddr("/ip6/2606:4700:4700::1111/udp/4001/quic-v1");
    let supplied = vec![
        global_v4.clone(),
        global_v6.clone(),
        maddr("/dns4/attacker.invalid/udp/4001/quic-v1"),
        maddr("/ip4/10.0.0.1/udp/4001/quic-v1"),
        maddr("/ip4/100.64.0.1/udp/4001/quic-v1"),
        maddr("/ip4/127.0.0.1/udp/4001/quic-v1"),
        maddr("/ip4/169.254.1.1/udp/4001/quic-v1"),
        maddr("/ip4/192.0.2.1/udp/4001/quic-v1"),
        maddr("/ip4/224.0.0.1/udp/4001/quic-v1"),
        maddr("/ip6/::1/udp/4001/quic-v1"),
        maddr("/ip6/fc00::1/udp/4001/quic-v1"),
        maddr("/ip6/fe80::1/udp/4001/quic-v1"),
        maddr("/ip6/2001:db8::1/udp/4001/quic-v1"),
        maddr("/ip6/ff02::1/udp/4001/quic-v1"),
    ];
    h.stream_data(stream, dcutr_connect_reply(&supplied), at(20));
    drain_actions(&mut h.agent);
    h.stream_data(stream, dcutr_sync(), at(30));
    drain_actions(&mut h.agent);

    h.agent.handle_tick(at(80));
    let actions = drain_actions(&mut h.agent);
    let blasted: Vec<_> = actions
        .iter()
        .filter_map(|action| match action {
            NatAction::SendRandomUdp { target, .. } => Some(target.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(blasted, vec![global_v4, global_v6]);
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
    let actions = drain_actions(&mut h.agent);
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, NatAction::PromoteBridge { .. }))
    );
    assert_eq!(dial_count_for(&actions, &h.target), 0);
    assert_eq!(blast_count(&actions), 0);
    assert!(!h.agent.owns_stream(&h.relay, stream));
    let target = h.target.clone();
    complete_promotion(&mut h.agent, &target, &actions, at(12_001));
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
            conn_id: minip2p_transport::ConnectionId::new(1),
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
    let actions = drain_actions(&mut h.agent);
    assert!(promotion_remote_write_closed(&actions));
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
            conn_id: minip2p_transport::ConnectionId::new(1),
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
fn inbound_unserved_nat_control_streams_are_reset_owned_and_consumed() {
    let mut h = inbound_harness(NatConfig::default());

    for (offset, protocol_id) in [
        HOP_PROTOCOL_ID,
        DCUTR_PROTOCOL_ID,
        AUTONAT_PROTOCOL_ID,
        STOP_PROTOCOL_ID,
    ]
    .into_iter()
    .enumerate()
    {
        let stream = StreamId::new(STOP_STREAM + offset as u64);
        // Even the configured relay may open only STOP. Use an untrusted
        // peer for STOP to cover its additional trust gate.
        let remote = if protocol_id == STOP_PROTOCOL_ID {
            h.target.clone()
        } else {
            h.relay.clone()
        };
        let conn_id = minip2p_transport::ConnectionId::new(10 + offset as u64);
        assert!(h.agent.handle_event_with_disposition(
            &SwarmEvent::StreamReady {
                conn_id,
                peer_id: remote.clone(),
                stream_id: stream,
                protocol_id: protocol_id.to_string(),
                initiated_locally: false,
            },
            at(offset as u64),
        ));
        assert!(h.agent.owns_stream(&remote, stream));
        let actions = drain_actions(&mut h.agent);
        assert!(
            has_reset_for(&actions, stream),
            "inbound {protocol_id} was not reset"
        );

        assert!(h.agent.handle_event_with_disposition(
            &SwarmEvent::StreamData {
                conn_id,
                peer_id: remote.clone(),
                stream_id: stream,
                data: b"rejected control data".to_vec(),
            },
            at(10 + offset as u64),
        ));
        assert!(drain_actions(&mut h.agent).is_empty());
        assert!(h.agent.handle_event_with_disposition(
            &SwarmEvent::StreamClosed {
                conn_id,
                peer_id: remote.clone(),
                stream_id: stream,
            },
            at(20 + offset as u64),
        ));
        assert!(!h.agent.owns_stream(&remote, stream));
    }

    assert!(drain_events(&mut h.agent).is_empty());
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
            conn_id: minip2p_transport::ConnectionId::new(1),
            peer_id: h.relay.clone(),
        },
        at(20),
    );
    assert!(drain_events(&mut h.agent).is_empty());
    assert!(!h.agent.owns_stream(&h.relay, stream));
    assert!(h.agent.is_idle());
}

#[test]
fn responder_reply_advertises_peer_observed_mapping() {
    let mut h = inbound_harness(NatConfig::default());
    // The relay's identify told us our public mapping earlier in the session.
    let relay = h.relay.clone();
    identify_observed(&mut h.agent, &relay, &maddr(OUR_OBSERVED_ADDR), at(0));

    let stream = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stream, 1);
    let target = h.target.clone();
    h.stream_data(stream, stop_connect(&target), at(10));
    drain_actions(&mut h.agent);

    h.stream_data(
        stream,
        dcutr_connect_reply(&[maddr(REMOTE_OBSERVED_ADDR)]),
        at(20),
    );
    let actions = drain_actions(&mut h.agent);
    let obs = dcutr_obs_addrs(&sent_data_on(&actions, stream));
    assert!(
        obs.contains(&maddr(LISTEN_ADDR)),
        "bound addresses stay in the reply"
    );
    assert!(
        obs.contains(&maddr(OUR_OBSERVED_ADDR)),
        "the reply must advertise our observed public mapping"
    );
}
