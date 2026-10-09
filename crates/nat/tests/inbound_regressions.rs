//! Focused inbound circuit and post-promotion DCUtR regressions.

mod common;

use common::*;

use minip2p_core::PeerAddr;
use minip2p_nat::{DCUTR_PROTOCOL_ID, NatConfig, NatEvent, Path, STOP_PROTOCOL_ID};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{Bytes, ConnectionId, StreamId};

const STOP_STREAM: u64 = 40;

fn inbound_harness(mut config: NatConfig) -> Harness {
    config.reservation_policy = minip2p_nat::ReservationPolicy::Never;
    config.relays.push(
        PeerAddr::new(maddr(RELAY_TRANSPORT_ADDR), peer(b"relay-peer"))
            .expect("valid configured relay"),
    );
    Harness::without_relay(config)
}

fn inbound_stop_stream(h: &mut Harness, stream: StreamId, t: u64) {
    h.agent.handle_event(
        &SwarmEvent::StreamReady {
            conn_id: ConnectionId::new(1),
            peer_id: h.relay.clone(),
            stream_id: stream,
            protocol_id: STOP_PROTOCOL_ID.into(),
            initiated_locally: false,
        },
        false,
        at(t),
    );
}

fn drive_to_relayed(h: &mut Harness) -> (ConnectionId, Vec<Out>) {
    let stop = StreamId::new(STOP_STREAM);
    inbound_stop_stream(h, stop, 0);
    let target = h.target.clone();
    h.stream_data(stop, stop_connect(&target), at(10));
    let promotion = drain_actions(&mut h.agent);
    let conn = complete_promotion(&mut h.agent, &target, &promotion, at(11));
    let events = drain_events(&mut h.agent);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::InboundPathEstablished {
            path: Path::Relayed { .. },
            ..
        }]
    ));
    (conn, drain_actions(&mut h.agent))
}

fn open_dcutr(h: &mut Harness, conn: ConnectionId, actions: &[Out]) -> StreamId {
    let stream = opened_stream(actions);
    h.agent.handle_event(
        &SwarmEvent::StreamReady {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            protocol_id: DCUTR_PROTOCOL_ID.into(),
            initiated_locally: true,
        },
        false,
        at(13),
    );
    stream
}

#[test]
fn silent_inbound_dcutr_exchange_times_out_and_resets_the_stream() {
    let mut h = inbound_harness(NatConfig {
        relay_leg_deadline_ms: 5,
        ..NatConfig::default()
    });
    let (conn, actions) = drive_to_relayed(&mut h);
    let stream = open_dcutr(&mut h, conn, &actions);
    drain_actions(&mut h.agent);

    h.agent.handle_tick(at(18));

    assert!(has_reset_for(&drain_actions(&mut h.agent), stream));
    assert!(!h.agent.owns_stream(conn, stream));
    assert!(h.agent.is_idle());
}

#[test]
fn failed_inbound_dcutr_open_ends_coordination_without_losing_the_relayed_path() {
    let mut h = inbound_harness(NatConfig::default());
    h.agent.swarm.refuse_opens = Some("DCUtR unavailable".into());
    let (_, actions) = drive_to_relayed(&mut h);

    assert!(matches!(
        actions.as_slice(),
        [Out::OpenStream { protocol_id, opened: None, .. }] if protocol_id == DCUTR_PROTOCOL_ID
    ));
    assert!(drain_actions(&mut h.agent).is_empty());
    assert!(drain_events(&mut h.agent).is_empty());
    assert!(h.agent.is_idle());
}

#[test]
fn early_closed_inbound_dcutr_exchange_resets_the_stream() {
    let mut h = inbound_harness(NatConfig::default());
    let (conn, actions) = drive_to_relayed(&mut h);
    let stream = open_dcutr(&mut h, conn, &actions);
    drain_actions(&mut h.agent);

    h.agent.handle_event(
        &SwarmEvent::StreamClosed {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
        },
        false,
        at(14),
    );

    assert!(has_reset_for(&drain_actions(&mut h.agent), stream));
    assert!(!h.agent.owns_stream(conn, stream));
    assert!(h.agent.is_idle());
}

#[test]
fn oversized_inbound_dcutr_connect_keeps_the_relayed_path() {
    let mut h = inbound_harness(NatConfig::default());
    let addrs: Vec<_> = (1u16..=400)
        .map(|port| maddr(&format!("/ip4/198.51.100.5/udp/{port}/quic-v1")))
        .collect();
    h.agent.set_listen_addrs(&addrs);
    let (conn, actions) = drive_to_relayed(&mut h);
    let stream = open_dcutr(&mut h, conn, &actions);

    assert!(has_reset_for(&drain_actions(&mut h.agent), stream));
    assert!(drain_events(&mut h.agent).is_empty());
    assert!(!h.agent.owns_stream(conn, stream));
    assert!(h.agent.is_idle());
}

fn answer_dcutr_at(h: &mut Harness, conn: ConnectionId, stream: StreamId, addrs: &[&str], t: u64) {
    let reply_addrs: Vec<_> = addrs.iter().map(|addr| maddr(addr)).collect();
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            data: Bytes::from(dcutr_connect_reply(&reply_addrs)),
        },
        false,
        at(t),
    );
}

#[test]
fn direct_connection_before_circuit_handshake_does_not_downgrade_the_path() {
    let mut h = inbound_harness(NatConfig::default());
    let stop = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stop, 0);
    let target = h.target.clone();
    h.stream_data(stop, stop_connect(&target), at(10));
    let promotion = drain_actions(&mut h.agent);
    let conn = ConnectionId::new(TEST_CIRCUIT_ID);
    h.agent
        .promote_result(promote_token(&promotion), Ok(conn), at(11));

    h.target_connected(at(12));
    h.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            conn_id: conn,
            peer_id: target,
        },
        true,
        at(13),
    );

    let events = drain_events(&mut h.agent);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, NatEvent::InboundDirectUpgrade { .. }))
    );
    assert!(!events.iter().any(|event| matches!(
        event,
        NatEvent::InboundPathEstablished {
            path: Path::Relayed { .. },
            ..
        }
    )));
}

#[test]
fn blast_schedule_starts_at_half_measured_rtt_and_respects_deadline() {
    let mut h = inbound_harness(NatConfig {
        blast_interval_ms: 100,
        punch_deadline_ms: 250,
        ..NatConfig::default()
    });
    let (conn, actions) = drive_to_relayed(&mut h);
    let stream = open_dcutr(&mut h, conn, &actions);
    drain_actions(&mut h.agent);
    answer_dcutr_at(&mut h, conn, stream, &["/ip4/8.8.8.8/udp/4001/quic-v1"], 20);
    drain_actions(&mut h.agent);

    // CONNECT was queued at t=13 and its reply arrived at t=20. Half the
    // measured 7 ms RTT rounds up to 4 ms, so the first blast is due at t=24.
    for (time, expected) in [(23, 0), (24, 1), (123, 0), (124, 1), (224, 1), (274, 0)] {
        h.agent.handle_tick(at(time));
        assert_eq!(
            blast_count(&drain_actions(&mut h.agent)),
            expected,
            "t={time}"
        );
    }
}

#[test]
fn zero_rtt_opens_udp_mapping_before_notifying_dialer() {
    let mut h = inbound_harness(NatConfig::default());
    let (conn, actions) = drive_to_relayed(&mut h);
    let stream = open_dcutr(&mut h, conn, &actions);
    drain_actions(&mut h.agent);

    // CONNECT was queued at t=13 and its reply arrived in the same clock
    // sample. The first blast leaves in the same cascade as SYNC, so the
    // mapping is open before SYNC can reach the remote and make it dial.
    answer_dcutr_at(&mut h, conn, stream, &["/ip4/8.8.8.8/udp/4001/quic-v1"], 13);
    let actions = drain_actions(&mut h.agent);

    assert_eq!(blast_count(&actions), 1);
    assert_eq!(send_stream_count(&actions), 1, "SYNC");
    h.agent.handle_tick(at(13));
    assert_eq!(blast_count(&drain_actions(&mut h.agent)), 0);
}

#[test]
fn measured_rtt_delay_cannot_consume_the_punch_window() {
    let mut h = inbound_harness(NatConfig {
        punch_deadline_ms: 3_000,
        ..NatConfig::default()
    });
    let (conn, actions) = drive_to_relayed(&mut h);
    let stream = open_dcutr(&mut h, conn, &actions);
    drain_actions(&mut h.agent);

    // CONNECT was queued at t=13. A reply at t=6_014 measures 6_001 ms,
    // whose half-RTT delay rounds up to 3_001 ms. The full punch window must
    // begin at t=9_015 rather than expiring before the first blast.
    answer_dcutr_at(
        &mut h,
        conn,
        stream,
        &["/ip4/8.8.8.8/udp/4001/quic-v1"],
        6_014,
    );
    drain_actions(&mut h.agent);
    h.agent.handle_tick(at(9_014));
    assert_eq!(blast_count(&drain_actions(&mut h.agent)), 0);
    h.agent.handle_tick(at(9_015));
    assert_eq!(blast_count(&drain_actions(&mut h.agent)), 1);
}

#[test]
fn zero_blast_interval_is_clamped_to_one_millisecond() {
    let mut h = inbound_harness(NatConfig {
        blast_interval_ms: 0,
        punch_deadline_ms: 10,
        ..NatConfig::default()
    });
    let (conn, actions) = drive_to_relayed(&mut h);
    let stream = open_dcutr(&mut h, conn, &actions);
    drain_actions(&mut h.agent);
    answer_dcutr_at(&mut h, conn, stream, &["/ip4/8.8.8.8/udp/4001/quic-v1"], 20);
    drain_actions(&mut h.agent);
    h.agent.handle_tick(at(26));
    assert_eq!(blast_count(&drain_actions(&mut h.agent)), 3);
}

#[test]
fn peer_supplied_punch_targets_must_be_global_unicast_quic_ips() {
    let mut h = inbound_harness(NatConfig::default());
    let (conn, actions) = drive_to_relayed(&mut h);
    let stream = open_dcutr(&mut h, conn, &actions);
    drain_actions(&mut h.agent);
    answer_dcutr_at(
        &mut h,
        conn,
        stream,
        &[
            "/ip4/10.0.0.1/udp/4001/quic-v1",
            "/ip4/8.8.8.8/udp/4001/quic-v1",
            "/ip4/8.8.4.4/tcp/4001",
        ],
        20,
    );
    let sync = drain_actions(&mut h.agent);
    assert!(has_reset_for(&sync, stream));
    assert!(!h.agent.owns_stream(conn, stream));
    h.agent.handle_tick(at(24));
    let targets: Vec<_> = drain_actions(&mut h.agent)
        .into_iter()
        .filter_map(|action| match action {
            Out::SendRandomUdp { target, .. } => Some(target),
            _ => None,
        })
        .collect();
    assert_eq!(targets, vec![maddr("/ip4/8.8.8.8/udp/4001/quic-v1")]);
}

#[test]
fn dcutr_connect_advertises_trusted_observation_but_not_tcp_listener() {
    let mut h = inbound_harness(NatConfig::default());
    h.agent
        .set_listen_addrs(&[maddr("/ip4/192.0.2.1/tcp/4001"), maddr(LISTEN_ADDR)]);
    let relay = h.relay.clone();
    identify_observed(&mut h.agent, &relay, &maddr(OUR_OBSERVED_ADDR), at(0));
    let (conn, actions) = drive_to_relayed(&mut h);
    let stream = open_dcutr(&mut h, conn, &actions);
    let connect = sent_data_on(&drain_actions(&mut h.agent), stream);
    let addrs = dcutr_obs_addrs(&connect);
    assert!(addrs.contains(&maddr(LISTEN_ADDR)));
    assert!(addrs.contains(&maddr(OUR_OBSERVED_ADDR)));
    assert!(!addrs.contains(&maddr("/ip4/192.0.2.1/tcp/4001")));
}

#[test]
fn relay_disconnect_before_stop_acceptance_drops_the_circuit() {
    let mut h = inbound_harness(NatConfig::default());
    let stop = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stop, 0);

    h.agent.handle_event(
        &SwarmEvent::ConnectionClosed {
            conn_id: ConnectionId::new(1),
            peer_id: h.relay.clone(),
        },
        false,
        at(1),
    );

    assert!(!h.agent.owns_stream(ConnectionId::new(1), stop));
    assert!(drain_events(&mut h.agent).is_empty());
}

#[test]
fn tcp_only_source_still_gets_the_relayed_path() {
    let mut h = inbound_harness(NatConfig::default());
    h.agent
        .set_listen_addrs(&[maddr("/ip4/192.0.2.1/tcp/4001")]);

    let (_, actions) = drive_to_relayed(&mut h);

    assert!(actions.iter().any(|action| matches!(
        action,
        Out::OpenStream { protocol_id, .. } if protocol_id == DCUTR_PROTOCOL_ID
    )));
}

#[test]
fn inbound_direct_replacement_after_the_circuit_finished_reports_the_upgrade() {
    let mut h = inbound_harness(NatConfig {
        force_relay: true,
        ..NatConfig::default()
    });
    let (circuit, _) = drive_to_relayed(&mut h);
    assert!(h.agent.is_idle(), "inbound handling finished at Relayed");

    let target = h.target.clone();
    h.agent.handle_event(
        &SwarmEvent::ConnectionReplaced {
            peer_id: target.clone(),
            old: circuit,
            new: ConnectionId::new(50),
        },
        false,
        at(20),
    );
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::InboundDirectUpgrade { peer }] if *peer == target
    ));
    assert_eq!(h.agent.path(&target), Some(&Path::DirectDialed));
}

#[test]
fn circuit_replacement_through_another_relay_updates_the_path_origin() {
    let relay_b = peer(b"relay-b");
    let mut config = NatConfig {
        force_relay: true,
        ..NatConfig::default()
    };
    config.relays.push(
        PeerAddr::new(maddr("/ip4/203.0.113.2/udp/4001/quic-v1"), relay_b.clone())
            .expect("valid second relay"),
    );
    let mut h = inbound_harness(config);
    let (circuit_a, _) = drive_to_relayed(&mut h);
    let target = h.target.clone();
    assert_eq!(
        h.agent.path(&target),
        Some(&Path::Relayed {
            relay: h.relay.clone()
        })
    );

    // The same peer reaches us again through relay B.
    let stop = StreamId::new(STOP_STREAM + 10);
    h.agent.handle_event(
        &SwarmEvent::StreamReady {
            conn_id: ConnectionId::new(3),
            peer_id: relay_b.clone(),
            stream_id: stop,
            protocol_id: STOP_PROTOCOL_ID.into(),
            initiated_locally: false,
        },
        false,
        at(20),
    );
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: ConnectionId::new(3),
            peer_id: relay_b.clone(),
            stream_id: stop,
            data: Bytes::from(stop_connect(&target)),
        },
        false,
        at(21),
    );
    let circuit_b = ConnectionId::new(TEST_CIRCUIT_ID + 1);
    let promotion = promote_token(&drain_actions(&mut h.agent));
    h.agent.promote_result(promotion, Ok(circuit_b), at(22));
    h.agent.handle_event(
        &SwarmEvent::ConnectionReplaced {
            peer_id: target.clone(),
            old: circuit_a,
            new: circuit_b,
        },
        true,
        at(23),
    );
    assert!(
        !drain_events(&mut h.agent).iter().any(|event| matches!(
            event,
            NatEvent::InboundDirectUpgrade { .. } | NatEvent::PathUpgraded { .. }
        )),
        "a relay-to-relay hand-over is not an upgrade"
    );
    assert_eq!(
        h.agent.path(&target),
        Some(&Path::Relayed { relay: relay_b })
    );
}

#[test]
fn inbound_circuit_replacing_a_direct_connection_announces_its_path() {
    let mut h = inbound_harness(NatConfig::default());
    let target = h.target.clone();
    let direct = ConnectionId::new(9);
    h.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            conn_id: direct,
            peer_id: target.clone(),
        },
        false,
        at(0),
    );
    let stop = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stop, 1);
    h.stream_data(stop, stop_connect(&target), at(10));
    let promotion = drain_actions(&mut h.agent);
    let circuit = ConnectionId::new(TEST_CIRCUIT_ID);
    h.agent
        .promote_result(promote_token(&promotion), Ok(circuit), at(11));

    h.agent.handle_event(
        &SwarmEvent::ConnectionReplaced {
            peer_id: target.clone(),
            old: direct,
            new: circuit,
        },
        true,
        at(12),
    );
    assert!(
        drain_events(&mut h.agent).iter().any(|event| matches!(
            event,
            NatEvent::InboundPathEstablished {
                path: Path::Relayed { .. },
                ..
            }
        )),
        "the retired direct connection must not make the circuit look redundant"
    );
    assert!(matches!(h.agent.path(&target), Some(Path::Relayed { .. })));
}

#[test]
fn inbound_dcutr_is_not_opened_once_a_direct_connection_replaced_the_circuit() {
    let mut h = inbound_harness(NatConfig::default());
    let stop = StreamId::new(STOP_STREAM);
    inbound_stop_stream(&mut h, stop, 0);
    let target = h.target.clone();
    h.stream_data(stop, stop_connect(&target), at(10));
    let promotion = drain_actions(&mut h.agent);
    let circuit = ConnectionId::new(TEST_CIRCUIT_ID);
    h.agent
        .promote_result(promote_token(&promotion), Ok(circuit), at(11));
    // The swarm is ahead: a direct connection already replaced the circuit
    // when its establishment reaches the agent.
    h.agent.swarm.connect(&target, ConnectionId::new(7));
    h.agent.deliver_late(
        &SwarmEvent::ConnectionEstablished {
            peer_id: target.clone(),
            conn_id: circuit,
        },
        true,
        at(11),
    );

    let actions = drain_actions(&mut h.agent);
    assert!(
        !actions.iter().any(|a| matches!(a, Out::OpenStream { .. })),
        "no DCUtR stream on the replacement: {actions:?}"
    );
    assert!(matches!(
        drain_events(&mut h.agent).as_slice(),
        [NatEvent::InboundPathEstablished {
            path: Path::Relayed { .. },
            ..
        }]
    ));
    assert!(h.agent.is_idle());
}
