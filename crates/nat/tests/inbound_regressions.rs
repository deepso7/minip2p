//! Focused inbound circuit and post-promotion DCUtR regressions.

mod common;

use common::*;

use minip2p_core::PeerAddr;
use minip2p_nat::{DCUTR_PROTOCOL_ID, NatAction, NatConfig, NatEvent, Path, STOP_PROTOCOL_ID};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, StreamId};

const STOP_STREAM: u64 = 40;
const CIRCUIT_STREAM: u64 = 41;

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
        at(t),
    );
}

fn drive_to_relayed(h: &mut Harness) -> (ConnectionId, Vec<NatAction>) {
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

fn open_dcutr(h: &mut Harness, conn: ConnectionId, actions: &[NatAction]) -> StreamId {
    let token = open_stream_token(actions);
    let stream = StreamId::new(CIRCUIT_STREAM);
    h.agent.stream_open_result(token, Ok(stream), at(12));
    h.agent.handle_event(
        &SwarmEvent::StreamReady {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            protocol_id: DCUTR_PROTOCOL_ID.into(),
            initiated_locally: true,
        },
        at(13),
    );
    stream
}

fn answer_dcutr(h: &mut Harness, conn: ConnectionId, stream: StreamId, addrs: &[&str]) {
    let reply_addrs: Vec<_> = addrs.iter().map(|addr| maddr(addr)).collect();
    h.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id: conn,
            peer_id: h.target.clone(),
            stream_id: stream,
            data: dcutr_connect_reply(&reply_addrs),
        },
        at(20),
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
    h.agent.handle_event_with_disposition_classified(
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
fn blast_schedule_respects_interval_and_deadline() {
    let mut h = inbound_harness(NatConfig {
        responder_sync_delay_ms: 0,
        blast_interval_ms: 100,
        punch_deadline_ms: 250,
        ..NatConfig::default()
    });
    let (conn, actions) = drive_to_relayed(&mut h);
    let stream = open_dcutr(&mut h, conn, &actions);
    drain_actions(&mut h.agent);
    answer_dcutr(&mut h, conn, stream, &["/ip4/8.8.8.8/udp/4001/quic-v1"]);
    drain_actions(&mut h.agent);

    for (time, expected) in [(20, 1), (119, 0), (120, 1), (220, 1), (320, 0)] {
        h.agent.handle_tick(at(time));
        assert_eq!(
            blast_count(&drain_actions(&mut h.agent)),
            expected,
            "t={time}"
        );
    }
}

#[test]
fn zero_blast_interval_is_clamped_to_one_millisecond() {
    let mut h = inbound_harness(NatConfig {
        responder_sync_delay_ms: 0,
        blast_interval_ms: 0,
        punch_deadline_ms: 2,
        ..NatConfig::default()
    });
    let (conn, actions) = drive_to_relayed(&mut h);
    let stream = open_dcutr(&mut h, conn, &actions);
    drain_actions(&mut h.agent);
    answer_dcutr(&mut h, conn, stream, &["/ip4/8.8.8.8/udp/4001/quic-v1"]);
    drain_actions(&mut h.agent);
    h.agent.handle_tick(at(22));
    assert_eq!(blast_count(&drain_actions(&mut h.agent)), 3);
}

#[test]
fn peer_supplied_punch_targets_must_be_global_unicast_quic_ips() {
    let mut h = inbound_harness(NatConfig {
        responder_sync_delay_ms: 0,
        ..NatConfig::default()
    });
    let (conn, actions) = drive_to_relayed(&mut h);
    let stream = open_dcutr(&mut h, conn, &actions);
    drain_actions(&mut h.agent);
    answer_dcutr(
        &mut h,
        conn,
        stream,
        &[
            "/ip4/10.0.0.1/udp/4001/quic-v1",
            "/ip4/8.8.8.8/udp/4001/quic-v1",
            "/ip4/8.8.4.4/tcp/4001",
        ],
    );
    drain_actions(&mut h.agent);
    h.agent.handle_tick(at(20));
    let targets: Vec<_> = drain_actions(&mut h.agent)
        .into_iter()
        .filter_map(|action| match action {
            NatAction::SendRandomUdp { target, .. } => Some(target),
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
            cause: minip2p_swarm::ConnectionCloseCause::Transport,
        },
        at(1),
    );

    assert!(!h.agent.owns_stream(&h.relay, stop));
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
        NatAction::OpenStream { protocol_id, .. } if protocol_id == DCUTR_PROTOCOL_ID
    )));
}
