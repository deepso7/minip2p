use std::str::FromStr;

use gungraun::prelude::*;
use minip2p_core::{Multiaddr, PeerId};
use minip2p_platform::Now;
use minip2p_relay::{
    HOP_PROTOCOL_ID, HopMessage, HopMessageType, Peer, Status, encode_frame, encode_stop_status,
};
use minip2p_relay_server::{
    CircuitCloseReason, RateLimit, RelayServerAction, RelayServerAgent, RelayServerConfig,
    RelayServerEvent, ReservationCloseReason, StreamKey,
};
use minip2p_swarm::{ConnectionCloseCause, SwarmEvent};
use minip2p_transport::{ConnectionId, StreamId};
use std::hint::black_box;

const PEERS: u64 = 128;
const EVENTS_PER_BATCH: usize = 100;

fn populated_agent() -> (RelayServerAgent, SwarmEvent, Now) {
    let now = Now::from_millis(1);
    let mut agent = RelayServerAgent::new(
        PeerId::from_public_key_protobuf(b"relay-server-bench-local"),
        RelayServerConfig::default(),
    )
    .expect("valid config");
    for index in 0..PEERS {
        let peer = PeerId::from_public_key_protobuf(&index.to_le_bytes());
        let conn_id = ConnectionId::new(index + 1);
        let stream_id = StreamId::new(1);
        agent.handle_event(
            &SwarmEvent::ConnectionEstablished {
                peer_id: peer.clone(),
                conn_id,
            },
            false,
            Now::from_millis(0),
        );
        assert!(agent.handle_event(
            &SwarmEvent::StreamReady {
                peer_id: peer,
                conn_id,
                stream_id,
                protocol_id: HOP_PROTOCOL_ID.into(),
                initiated_locally: false,
            },
            false,
            Now::from_millis(0)
        ));
    }
    agent.handle_tick(now);
    let event = SwarmEvent::StreamData {
        peer_id: PeerId::from_public_key_protobuf(b"relay-server-bench-unrelated"),
        conn_id: ConnectionId::new(PEERS + 1),
        stream_id: StreamId::new(1),
        data: Vec::new(),
    };
    (agent, event, now)
}

#[library_benchmark]
#[bench::relay_handle_event_same_now_128_pending_hops(populated_agent())]
fn relay_event(input: (RelayServerAgent, SwarmEvent, Now)) {
    let (mut agent, event, now) = input;
    for _ in 0..EVENTS_PER_BATCH {
        black_box(agent.handle_event(black_box(&event), false, black_box(now)));
    }
}

// --- 1k active reservations and 1k active circuits ---------------------------
//
// Reserved peers `r0..r999` each hold one connection. Ten source peers each
// hold one connection carrying 100 circuits, one to each of 100 distinct
// reserved peers. The first `EXPIRING` reservations are committed at
// `EARLY`, the rest at `NOW`, so one tick at `EXPIRY` expires exactly that
// batch. Every limit has headroom above 1k, and circuits outlive the
// reservation expiry, so the only due work is the batch under test.

const RESERVATIONS: u64 = 1_000;
const SOURCES: u64 = 10;
const CIRCUITS_PER_SOURCE: u64 = RESERVATIONS / SOURCES;
const EXPIRING: u64 = 100;
const RESERVATION_SECS: u64 = 3_600;
const EARLY: Now = Now::from_millis(1_000);
const NOW: Now = Now::from_millis(2_000);
const EXPIRY: Now = Now::from_millis(EARLY.monotonic_ms + RESERVATION_SECS * 1_000);
const HOP_STREAM: u64 = 1;
const STOP_STREAM: u64 = 2;

fn scale_config() -> RelayServerConfig {
    // Rate limits stay on so admission walks 1k+ live buckets, but none can
    // refill (and so none become due) inside the measured window.
    let limit = Some(RateLimit {
        capacity: 4_096,
        refill_interval_ms: 86_400_000,
    });
    RelayServerConfig {
        max_reservations: 2_048,
        reservation_duration_secs: RESERVATION_SECS,
        max_circuits: 2_048,
        max_circuits_per_peer: 2_048,
        max_circuit_duration_secs: 2 * RESERVATION_SECS,
        reservation_rate_limit_per_peer: limit,
        reservation_rate_limit_per_ip: limit,
        circuit_rate_limit_per_peer: limit,
        circuit_rate_limit_per_ip: limit,
        ..RelayServerConfig::default()
    }
}

fn peer(tag: &str, index: u64) -> PeerId {
    PeerId::from_public_key_protobuf(format!("relay-scale-{tag}-{index}").as_bytes())
}

fn reserved_conn(index: u64) -> ConnectionId {
    ConnectionId::new(index + 1)
}

fn source_conn(index: u64) -> ConnectionId {
    ConnectionId::new(RESERVATIONS + index + 1)
}

fn hop_frame(kind: HopMessageType, peer: Option<&PeerId>) -> Vec<u8> {
    encode_frame(
        &HopMessage {
            kind,
            peer: peer.map(|peer| Peer {
                id: peer.to_bytes(),
                addrs: Vec::new(),
            }),
            reservation: None,
            limit: None,
            status: None,
        }
        .encode(),
    )
}

fn open_hop(agent: &mut RelayServerAgent, peer_id: &PeerId, stream: StreamKey, now: Now) {
    assert!(agent.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: peer_id.clone(),
            conn_id: stream.conn_id,
            stream_id: stream.stream_id,
            protocol_id: HOP_PROTOCOL_ID.into(),
            initiated_locally: false,
        },
        false,
        now,
    ));
}

fn stream_data(peer_id: &PeerId, stream: StreamKey, data: Vec<u8>) -> SwarmEvent {
    SwarmEvent::StreamData {
        peer_id: peer_id.clone(),
        conn_id: stream.conn_id,
        stream_id: stream.stream_id,
        data,
    }
}

/// Acknowledges every queued send, half-close, and reset as accepted.
///
/// An unexpected STOP open stays pending, which fails the callers'
/// `is_idle` assertions.
fn ack_all(agent: &mut RelayServerAgent, now: Now) {
    while let Some(action) = agent.poll_action() {
        match action {
            RelayServerAction::SendStream { token, .. } => {
                agent.send_stream_result(token, Ok(()), now);
            }
            RelayServerAction::CloseStreamWrite { token, .. } => {
                agent.close_stream_write_result(token, Ok(()), now);
            }
            RelayServerAction::ResetStream { token, .. } => {
                agent.reset_stream_result(token, Ok(()), now);
            }
            RelayServerAction::OpenStream { .. } => {}
        }
    }
}

fn reserve(agent: &mut RelayServerAgent, index: u64, now: Now) {
    let peer_id = peer("reserved", index);
    let stream = StreamKey {
        conn_id: reserved_conn(index),
        stream_id: StreamId::new(HOP_STREAM),
    };
    agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            peer_id: peer_id.clone(),
            conn_id: stream.conn_id,
        },
        false,
        now,
    );
    open_hop(agent, &peer_id, stream, now);
    let request = stream_data(&peer_id, stream, hop_frame(HopMessageType::Reserve, None));
    assert!(agent.handle_event(&request, false, now));
    ack_all(agent, now);
    // The client closes its HOP stream once it has read the response.
    let closed = SwarmEvent::StreamClosed {
        peer_id,
        conn_id: stream.conn_id,
        stream_id: stream.stream_id,
    };
    assert!(agent.handle_event(&closed, false, now));
    assert!(matches!(
        agent.poll_event(),
        Some(RelayServerEvent::ReservationAccepted { renewed: false, .. })
    ));
    assert!(agent.is_idle());
}

fn connect(agent: &mut RelayServerAgent, source: u64, slot: u64, now: Now) {
    let source_peer = peer("source", source);
    let destination_index = source * CIRCUITS_PER_SOURCE + slot;
    let destination = peer("reserved", destination_index);
    let source_stream = StreamKey {
        conn_id: source_conn(source),
        stream_id: StreamId::new(slot + 1),
    };
    open_hop(agent, &source_peer, source_stream, now);
    let request = stream_data(
        &source_peer,
        source_stream,
        hop_frame(HopMessageType::Connect, Some(&destination)),
    );
    assert!(agent.handle_event(&request, false, now));
    let (token, expected_conn_id) = agent
        .poll_action()
        .and_then(|action| match action {
            RelayServerAction::OpenStream {
                token,
                expected_conn_id,
                ..
            } => Some((token, expected_conn_id)),
            _ => None,
        })
        .expect("CONNECT opens a STOP stream");
    let stop_stream = StreamKey {
        conn_id: expected_conn_id,
        stream_id: StreamId::new(STOP_STREAM),
    };
    agent.stream_open_result(token, Ok(stop_stream), now);
    ack_all(agent, now);
    // The destination accepts the STOP request; the HOP success follows.
    let accepted = stream_data(
        &destination,
        stop_stream,
        encode_stop_status(Status::Ok).expect("STOP status encodes"),
    );
    assert!(agent.handle_event(&accepted, false, now));
    ack_all(agent, now);
    assert!(matches!(
        agent.poll_event(),
        Some(RelayServerEvent::CircuitOpened { .. })
    ));
    assert!(agent.is_idle());
}

/// Builds the 1k-reservation, 1k-circuit agent and leaves it idle at `NOW`.
fn scale_agent() -> RelayServerAgent {
    let mut agent = RelayServerAgent::new(
        PeerId::from_public_key_protobuf(b"relay-server-bench-local"),
        scale_config(),
    )
    .expect("valid config");
    agent
        .replace_announce_addrs(vec![
            Multiaddr::from_str("/ip4/192.0.2.1/tcp/4001").expect("valid multiaddr"),
        ])
        .expect("valid announce address");
    for index in 0..RESERVATIONS {
        reserve(
            &mut agent,
            index,
            if index < EXPIRING { EARLY } else { NOW },
        );
    }
    for source in 0..SOURCES {
        agent.handle_event(
            &SwarmEvent::ConnectionEstablished {
                peer_id: peer("source", source),
                conn_id: source_conn(source),
            },
            false,
            NOW,
        );
        for slot in 0..CIRCUITS_PER_SOURCE {
            connect(&mut agent, source, slot, NOW);
        }
    }
    agent.handle_tick(NOW);
    assert_eq!(agent.reservation_count(), RESERVATIONS as usize);
    assert_eq!(agent.circuit_count(), RESERVATIONS as usize);
    assert!(agent.is_idle());
    agent
}

/// Adds a connected peer with a negotiated HOP stream and returns its RESERVE.
fn scale_agent_with_new_reserver() -> (RelayServerAgent, SwarmEvent) {
    let mut agent = scale_agent();
    let peer_id = peer("new", 0);
    let stream = StreamKey {
        conn_id: ConnectionId::new(RESERVATIONS + SOURCES + 1),
        stream_id: StreamId::new(HOP_STREAM),
    };
    agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            peer_id: peer_id.clone(),
            conn_id: stream.conn_id,
        },
        false,
        NOW,
    );
    open_hop(&mut agent, &peer_id, stream, NOW);
    let request = stream_data(&peer_id, stream, hop_frame(HopMessageType::Reserve, None));
    (agent, request)
}

fn scale_agent_and_closed_source() -> (RelayServerAgent, SwarmEvent) {
    let closed = SwarmEvent::ConnectionClosed {
        peer_id: peer("source", 0),
        conn_id: source_conn(0),
        cause: ConnectionCloseCause::Transport,
    };
    (scale_agent(), closed)
}

/// Asserts the measured tick found nothing due.
fn assert_unchanged(agent: RelayServerAgent) {
    assert_eq!(agent.reservation_count(), RESERVATIONS as usize);
    assert_eq!(agent.circuit_count(), RESERVATIONS as usize);
    assert!(agent.is_idle());
}

fn assert_batch_expired(mut agent: RelayServerAgent) {
    let mut expired = 0;
    while let Some(event) = agent.poll_event() {
        assert!(matches!(
            event,
            RelayServerEvent::ReservationClosed {
                reason: ReservationCloseReason::Expired,
                ..
            }
        ));
        expired += 1;
    }
    assert_eq!(expired, EXPIRING);
    assert_eq!(
        agent.reservation_count(),
        (RESERVATIONS - EXPIRING) as usize
    );
    assert_eq!(agent.circuit_count(), RESERVATIONS as usize);
}

fn assert_reservation_accepted((mut agent, _request): (RelayServerAgent, SwarmEvent)) {
    assert!(agent.poll_event().is_none(), "RESERVE must not be denied");
    ack_all(&mut agent, NOW);
    assert!(matches!(
        agent.poll_event(),
        Some(RelayServerEvent::ReservationAccepted { renewed: false, .. })
    ));
    assert_eq!(agent.reservation_count(), RESERVATIONS as usize + 1);
}

fn assert_circuits_torn_down((mut agent, _closed): (RelayServerAgent, SwarmEvent)) {
    let mut closed = 0;
    while let Some(event) = agent.poll_event() {
        assert!(matches!(
            event,
            RelayServerEvent::CircuitClosed {
                reason: CircuitCloseReason::ConnectionClosed { .. },
                ..
            }
        ));
        closed += 1;
    }
    assert_eq!(closed, CIRCUITS_PER_SOURCE);
    assert_eq!(
        agent.circuit_count(),
        (RESERVATIONS - CIRCUITS_PER_SOURCE) as usize
    );
    assert_eq!(agent.reservation_count(), RESERVATIONS as usize);
}

// Each benchmark returns its inputs so their drop and the assertions in
// `teardown` stay outside the measured region.

#[library_benchmark]
#[bench::relay_1k_next_timeout(args = (scale_agent()), teardown = assert_unchanged)]
fn relay_1k_next_timeout(agent: RelayServerAgent) -> RelayServerAgent {
    black_box(agent.next_timeout(black_box(NOW)));
    agent
}

#[library_benchmark]
#[bench::relay_1k_tick_idle(args = (scale_agent()), teardown = assert_unchanged)]
fn relay_1k_tick_idle(mut agent: RelayServerAgent) -> RelayServerAgent {
    agent.handle_tick(black_box(NOW));
    agent
}

#[library_benchmark]
#[bench::relay_1k_tick_expire_100(args = (scale_agent()), teardown = assert_batch_expired)]
fn relay_1k_tick_expire_100(mut agent: RelayServerAgent) -> RelayServerAgent {
    agent.handle_tick(black_box(EXPIRY));
    agent
}

#[library_benchmark]
#[bench::relay_1k_reserve_new_peer(
    args = (scale_agent_with_new_reserver()),
    teardown = assert_reservation_accepted
)]
fn relay_1k_reserve_new_peer(
    (mut agent, request): (RelayServerAgent, SwarmEvent),
) -> (RelayServerAgent, SwarmEvent) {
    black_box(agent.handle_event(black_box(&request), false, black_box(NOW)));
    (agent, request)
}

#[library_benchmark]
#[bench::relay_1k_close_connection_100_circuits(
    args = (scale_agent_and_closed_source()),
    teardown = assert_circuits_torn_down
)]
fn relay_1k_close_connection_100_circuits(
    (mut agent, closed): (RelayServerAgent, SwarmEvent),
) -> (RelayServerAgent, SwarmEvent) {
    black_box(agent.handle_event(black_box(&closed), false, black_box(NOW)));
    (agent, closed)
}

library_benchmark_group!(
    name = benches;
    benchmarks = relay_event,
        relay_1k_next_timeout,
        relay_1k_tick_idle,
        relay_1k_tick_expire_100,
        relay_1k_reserve_new_peer,
        relay_1k_close_connection_100_circuits
);
gungraun::main!(library_benchmark_groups = benches);
