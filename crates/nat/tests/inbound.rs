//! Scripted responder-side tests: inbound STOP circuits, the DCUtR
//! responder exchange, and the UDP blast schedule.

mod common;

use common::*;

use minip2p_core::PeerAddr;
use minip2p_nat::{
    AUTONAT_PROTOCOL_ID, DCUTR_PROTOCOL_ID, HOP_PROTOCOL_ID, NatAction, NatConfig, NatEvent, Path,
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
    drain_events(&mut h.agent);
    assert!(h.agent.is_idle());
}

#[test]
fn default_inbound_promotes_immediately_after_stop_acceptance() {
    let mut h = inbound_harness(NatConfig::default());
    let stream = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stream, 0);
    let target = h.target.clone();

    h.stream_data(stream, stop_connect(&target), at(10));

    let actions = drain_actions(&mut h.agent);
    assert_eq!(send_stream_count(&actions), 1, "STATUS:OK must be sent");
    assert!(
        !actions.iter().any(|action| matches!(
            action,
            NatAction::OpenStream { protocol_id, .. } if protocol_id == DCUTR_PROTOCOL_ID
        )),
        "DCUtR must wait until the promoted circuit is connected"
    );
    assert!(actions.iter().any(|action| matches!(
        action,
        NatAction::PromoteBridge {
            role: minip2p_nat::BridgeRole::Responder,
            stream_id,
            remote_peer,
            ..
        } if *stream_id == stream && remote_peer == &target
    )));
}

#[test]
fn inbound_relay_path_opens_dcutr_after_the_circuit_is_connected() {
    let mut h = inbound_harness(NatConfig::default());
    let stream = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stream, 0);
    let target = h.target.clone();
    h.stream_data(stream, stop_connect(&target), at(10));
    let promotion = drain_actions(&mut h.agent);

    complete_promotion(&mut h.agent, &target, &promotion, at(11));

    let actions = drain_actions(&mut h.agent);
    assert!(actions.iter().any(|action| matches!(
        action,
        NatAction::OpenStream { peer, protocol_id, .. }
            if peer == &target && protocol_id == DCUTR_PROTOCOL_ID
    )));
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::InboundPathEstablished {
            path: Path::Relayed { .. },
            ..
        }]
    ));
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
