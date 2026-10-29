use minip2p_swarm::ConnectionCloseReason;
use std::str::FromStr;

use gungraun::prelude::*;
use minip2p_core::platform::Now;
use minip2p_core::{Multiaddr, PeerId};
use minip2p_relay::STOP_PROTOCOL_ID;
use minip2p_relay::{
    HOP_PROTOCOL_ID, HopMessage, HopMessageType, Peer, Status, encode_frame, encode_stop_status,
};
use minip2p_relay_server::{
    CircuitCloseReason, CircuitLeg, RateLimit, RelayServerAgent, RelayServerConfig,
    RelayServerEvent, ReservationCloseReason, StreamKey,
};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{Bytes, ConnectionId, StreamId};
use std::hint::black_box;

#[path = "../tests/common/mod.rs"]
mod common;
use common::{Call, FakeSwarm};

const PEERS: u64 = 128;
const EVENTS_PER_BATCH: usize = 100;

fn populated_agent() -> (RelayServerAgent, FakeSwarm, SwarmEvent, Now) {
    let now = Now::from_millis(1);
    let mut agent = RelayServerAgent::new(
        PeerId::from_public_key_protobuf(b"relay-server-bench-local"),
        RelayServerConfig::default(),
    )
    .expect("valid config");
    let mut swarm = FakeSwarm::default();
    for index in 0..PEERS {
        let peer = PeerId::from_public_key_protobuf(&index.to_le_bytes());
        let conn_id = ConnectionId::new(index + 1);
        let stream_id = StreamId::new(1);
        let established = SwarmEvent::ConnectionEstablished {
            peer_id: peer.clone(),
            conn_id,
        };
        swarm.apply(&established);
        agent.handle_event(&mut swarm, &established, false, Now::from_millis(0));
        assert!(agent.handle_event(
            &mut swarm,
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
    agent.handle_tick(&mut swarm, now);
    let event = SwarmEvent::StreamData {
        peer_id: PeerId::from_public_key_protobuf(b"relay-server-bench-unrelated"),
        conn_id: ConnectionId::new(PEERS + 1),
        stream_id: StreamId::new(1),
        data: Bytes::from(Vec::new()),
    };
    (agent, swarm, event, now)
}

#[library_benchmark]
#[bench::relay_handle_event_same_now_128_pending_hops(populated_agent())]
fn relay_event(
    input: (RelayServerAgent, FakeSwarm, SwarmEvent, Now),
) -> (RelayServerAgent, FakeSwarm, SwarmEvent) {
    let (mut agent, mut swarm, event, now) = input;
    for _ in 0..EVENTS_PER_BATCH {
        black_box(agent.handle_event(&mut swarm, black_box(&event), false, black_box(now)));
    }
    // Returned so their teardown is not counted.
    (agent, swarm, event)
}

// --- N active reservations and N active circuits, at N = 100, 1k and 10k -----
//
// Reserved peers `r0..rN-1` each hold one connection. `N / 100` source peers
// each hold one connection carrying 100 circuits, one to each of 100 distinct
// reserved peers. The first `EXPIRING` reservations are committed at `EARLY`,
// the rest at `NOW`, so one tick at `EXPIRY` expires exactly that batch.
// Every limit has headroom above N, and circuits outlive the reservation
// expiry, so the only due work is the operation under test. Every scenario
// runs at each size: an instruction count that stays flat across sizes shows
// the operation does not scan the population.
//
// The agent runs its swarm commands inline, on the test suite's fake swarm,
// so the measured regions include the writes, acknowledgements, and resets
// an operation issues (and the fake's logging of them). Counts from before
// that change, when commands were queued for the host, are not comparable.

const CIRCUITS_PER_SOURCE: u64 = 100;
const EXPIRING: u64 = 100;
const RESERVATION_SECS: u64 = 3_600;
const EARLY: Now = Now::from_millis(1_000);
const NOW: Now = Now::from_millis(2_000);
const EXPIRY: Now = Now::from_millis(EARLY.monotonic_ms + RESERVATION_SECS * 1_000);
const HOP_STREAM: u64 = 1;
const STOP_STREAM: u64 = 2;

/// A populated agent, the fake swarm it drives, and its population size N.
struct Scale {
    agent: RelayServerAgent,
    swarm: FakeSwarm,
    size: u64,
}

impl Scale {
    fn handle(&mut self, event: &SwarmEvent, now: Now) -> bool {
        self.swarm.apply(event);
        self.agent.handle_event(&mut self.swarm, event, false, now)
    }
}

fn scale_config(size: u64) -> RelayServerConfig {
    // Rate limits stay on so admission walks N+ live buckets, but none can
    // refill (and so none become due) inside the measured window.
    let limit = Some(RateLimit {
        capacity: 4_096,
        refill_interval_ms: 86_400_000,
    });
    let headroom = 2 * size as usize + 16;
    RelayServerConfig {
        max_reservations: headroom,
        max_reservations_per_ip: headroom,
        reservation_duration_secs: RESERVATION_SECS,
        max_circuits: headroom,
        max_circuits_per_peer: headroom,
        max_circuits_per_ip: headroom,
        max_circuit_duration_secs: 2 * RESERVATION_SECS,
        reservation_rate_limit_per_peer: limit,
        reservation_rate_limit_per_ip: limit,
        circuit_rate_limit_per_peer: limit,
        circuit_rate_limit_per_ip: limit,
        max_rate_limit_entries: headroom,
        ..RelayServerConfig::default()
    }
}

fn peer(tag: &str, index: u64) -> PeerId {
    PeerId::from_public_key_protobuf(format!("relay-scale-{tag}-{index}").as_bytes())
}

fn sources(size: u64) -> u64 {
    size / CIRCUITS_PER_SOURCE
}

fn reserved_conn(index: u64) -> ConnectionId {
    ConnectionId::new(index + 1)
}

fn source_conn(size: u64, index: u64) -> ConnectionId {
    ConnectionId::new(size + index + 1)
}

/// A connection id no populated peer uses.
fn new_conn(size: u64) -> ConnectionId {
    ConnectionId::new(size + sources(size) + 1)
}

/// The HOP stream carrying a source's CONNECT for circuit `slot`.
fn source_stream(size: u64, source: u64, slot: u64) -> StreamKey {
    StreamKey {
        conn_id: source_conn(size, source),
        stream_id: StreamId::new(slot + 1),
    }
}

/// The STOP stream of the circuit to reserved peer `index`.
fn stop_stream(index: u64) -> StreamKey {
    StreamKey {
        conn_id: reserved_conn(index),
        stream_id: StreamId::new(STOP_STREAM),
    }
}

/// Establishes a connection from its own IPv4 address, so both the per-peer
/// and per-IP admission limiters see every peer.
fn establish(scale: &mut Scale, peer_id: &PeerId, conn_id: ConnectionId, now: Now) {
    let [a, b] = (conn_id.as_u64() as u16).to_be_bytes();
    let address =
        Multiaddr::from_str(&format!("/ip4/10.0.{a}.{b}/tcp/4001")).expect("valid multiaddr");
    scale.swarm.remote_addrs.insert(conn_id, address);
    scale.handle(
        &SwarmEvent::ConnectionEstablished {
            peer_id: peer_id.clone(),
            conn_id,
        },
        now,
    );
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

fn stream_ready(peer_id: &PeerId, stream: StreamKey, outbound: bool) -> SwarmEvent {
    SwarmEvent::StreamReady {
        peer_id: peer_id.clone(),
        conn_id: stream.conn_id,
        stream_id: stream.stream_id,
        protocol_id: if outbound {
            STOP_PROTOCOL_ID
        } else {
            HOP_PROTOCOL_ID
        }
        .into(),
        initiated_locally: outbound,
    }
}

fn open_hop(scale: &mut Scale, peer_id: &PeerId, stream: StreamKey, now: Now) {
    assert!(scale.handle(&stream_ready(peer_id, stream, false), now));
}

fn stream_data(peer_id: &PeerId, stream: StreamKey, data: Vec<u8>) -> SwarmEvent {
    SwarmEvent::StreamData {
        peer_id: peer_id.clone(),
        conn_id: stream.conn_id,
        stream_id: stream.stream_id,
        data: Bytes::from(data),
    }
}

fn reserve(scale: &mut Scale, index: u64, now: Now) {
    let peer_id = peer("reserved", index);
    let stream = StreamKey {
        conn_id: reserved_conn(index),
        stream_id: StreamId::new(HOP_STREAM),
    };
    establish(scale, &peer_id, stream.conn_id, now);
    open_hop(scale, &peer_id, stream, now);
    let request = stream_data(&peer_id, stream, hop_frame(HopMessageType::Reserve, None));
    assert!(scale.handle(&request, now));
    // The client closes its HOP stream once it has read the response.
    let closed = SwarmEvent::StreamClosed {
        peer_id,
        conn_id: stream.conn_id,
        stream_id: stream.stream_id,
    };
    assert!(scale.handle(&closed, now));
    assert!(matches!(
        scale.agent.poll_event(),
        Some(RelayServerEvent::ReservationAccepted { renewed: false, .. })
    ));
}

fn connect(scale: &mut Scale, source: u64, slot: u64, now: Now) {
    let source_peer = peer("source", source);
    let index = source * CIRCUITS_PER_SOURCE + slot;
    let destination = peer("reserved", index);
    let source_stream = source_stream(scale.size, source, slot);
    let stop_stream = stop_stream(index);
    open_hop(scale, &source_peer, source_stream, now);
    scale.swarm.next_open = Some(stop_stream);
    let request = stream_data(
        &source_peer,
        source_stream,
        hop_frame(HopMessageType::Connect, Some(&destination)),
    );
    assert!(scale.handle(&request, now));
    // The STOP stream negotiates and the destination accepts; the HOP
    // success follows.
    assert!(scale.handle(&stream_ready(&destination, stop_stream, true), now));
    let accepted = stream_data(
        &destination,
        stop_stream,
        encode_stop_status(Status::Ok).expect("STOP status encodes"),
    );
    assert!(scale.handle(&accepted, now));
    assert!(matches!(
        scale.agent.poll_event(),
        Some(RelayServerEvent::CircuitOpened { .. })
    ));
}

/// Builds the N-reservation, N-circuit agent and leaves it idle at `NOW`,
/// its command log empty.
fn scale_agent(size: u64) -> Scale {
    let mut agent = RelayServerAgent::new(
        PeerId::from_public_key_protobuf(b"relay-server-bench-local"),
        scale_config(size),
    )
    .expect("valid config");
    agent
        .replace_announce_addrs(vec![
            Multiaddr::from_str("/ip4/192.0.2.1/tcp/4001").expect("valid multiaddr"),
        ])
        .expect("valid announce address");
    let mut scale = Scale {
        agent,
        swarm: FakeSwarm::default(),
        size,
    };
    for index in 0..size {
        reserve(
            &mut scale,
            index,
            if index < EXPIRING { EARLY } else { NOW },
        );
    }
    for source in 0..sources(size) {
        establish(
            &mut scale,
            &peer("source", source),
            source_conn(size, source),
            NOW,
        );
        for slot in 0..CIRCUITS_PER_SOURCE {
            connect(&mut scale, source, slot, NOW);
        }
    }
    scale.agent.handle_tick(&mut scale.swarm, NOW);
    assert_eq!(scale.agent.reservation_count(), size as usize);
    assert_eq!(scale.agent.circuit_count(), size as usize);
    assert!(scale.agent.poll_event().is_none());
    scale.swarm.take_calls();
    scale
}

/// Adds a connected peer with a negotiated HOP stream and returns its RESERVE.
fn with_new_reserver(size: u64) -> (Scale, SwarmEvent) {
    let mut scale = scale_agent(size);
    let peer_id = peer("new", 0);
    let stream = StreamKey {
        conn_id: new_conn(size),
        stream_id: StreamId::new(HOP_STREAM),
    };
    establish(&mut scale, &peer_id, stream.conn_id, NOW);
    open_hop(&mut scale, &peer_id, stream, NOW);
    let request = stream_data(&peer_id, stream, hop_frame(HopMessageType::Reserve, None));
    (scale, request)
}

/// Adds a connected peer with a negotiated HOP stream and returns its CONNECT
/// to `r0`, which already terminates one circuit.
fn with_new_connector(size: u64) -> (Scale, SwarmEvent) {
    let mut scale = scale_agent(size);
    let peer_id = peer("new", 0);
    let stream = StreamKey {
        conn_id: new_conn(size),
        stream_id: StreamId::new(HOP_STREAM),
    };
    establish(&mut scale, &peer_id, stream.conn_id, NOW);
    open_hop(&mut scale, &peer_id, stream, NOW);
    let request = stream_data(
        &peer_id,
        stream,
        hop_frame(HopMessageType::Connect, Some(&peer("reserved", 0))),
    );
    (scale, request)
}

/// Returns a new HOP stream on the first source's connection, which already
/// carries 100 circuit legs.
fn with_new_hop_stream(size: u64) -> (Scale, SwarmEvent) {
    let event = stream_ready(
        &peer("source", 0),
        source_stream(size, 0, CIRCUITS_PER_SOURCE),
        false,
    );
    (scale_agent(size), event)
}

fn with_closed_source(size: u64) -> (Scale, SwarmEvent) {
    let closed = SwarmEvent::ConnectionClosed {
        peer_id: peer("source", 0),
        conn_id: source_conn(size, 0),
        reason: ConnectionCloseReason::Local,
    };
    (scale_agent(size), closed)
}

/// Returns the close of the last reserved peer's connection, which carries
/// one circuit's destination leg.
fn with_closed_destination(size: u64) -> (Scale, SwarmEvent) {
    let closed = SwarmEvent::ConnectionClosed {
        peer_id: peer("reserved", size - 1),
        conn_id: reserved_conn(size - 1),
        reason: ConnectionCloseReason::Local,
    };
    (scale_agent(size), closed)
}

/// Leaves every circuit's destination full, holding a forwarded byte as an
/// unsent tail, then returns the reset of the first circuit's source leg,
/// which drops its held tail and releases that byte's credit.
fn with_held_tails(size: u64) -> (Scale, SwarmEvent) {
    let mut scale = scale_agent(size);
    for source in 0..sources(size) {
        for slot in 0..CIRCUITS_PER_SOURCE {
            let index = source * CIRCUITS_PER_SOURCE + slot;
            scale.swarm.credit.insert(stop_stream(index), 0);
            let data = stream_data(
                &peer("source", source),
                source_stream(size, source, slot),
                vec![0],
            );
            assert!(scale.handle(&data, NOW));
        }
    }
    scale.swarm.take_calls();
    let stream = source_stream(size, 0, 0);
    let reset = SwarmEvent::StreamClosed {
        peer_id: peer("source", 0),
        conn_id: stream.conn_id,
        stream_id: stream.stream_id,
    };
    (scale, reset)
}

/// Asserts the measured operation changed nothing.
fn assert_unchanged(mut scale: Scale) {
    assert_eq!(scale.agent.reservation_count(), scale.size as usize);
    assert_eq!(scale.agent.circuit_count(), scale.size as usize);
    assert!(scale.agent.poll_event().is_none());
    assert!(scale.swarm.take_calls().is_empty());
}

fn assert_batch_expired(
    Scale {
        mut agent, size, ..
    }: Scale,
) {
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
    assert_eq!(agent.reservation_count(), (size - EXPIRING) as usize);
    assert_eq!(agent.circuit_count(), size as usize);
}

fn assert_reservation_accepted(
    (
        Scale {
            mut agent, size, ..
        },
        _,
    ): (Scale, SwarmEvent),
) {
    assert!(matches!(
        agent.poll_event(),
        Some(RelayServerEvent::ReservationAccepted { renewed: false, .. })
    ));
    assert_eq!(agent.reservation_count(), size as usize + 1);
}

fn assert_connect_admitted((mut scale, _): (Scale, SwarmEvent)) {
    assert!(
        scale.agent.poll_event().is_none(),
        "CONNECT must not be denied"
    );
    assert!(scale.swarm.take_calls().iter().any(|call| matches!(
        call,
        Call::Open {
            opened: Some(_),
            ..
        }
    )));
    assert_eq!(scale.agent.circuit_count(), scale.size as usize + 1);
}

fn assert_hop_admitted((mut scale, _): (Scale, SwarmEvent)) {
    // A refused stream would be reset.
    assert!(
        scale.swarm.take_calls().is_empty(),
        "the HOP stream must be admitted"
    );
    assert!(
        scale
            .agent
            .owns_stream(source_stream(scale.size, 0, CIRCUITS_PER_SOURCE))
    );
}

/// Asserts `closed` circuits closed for `reason`, and the surviving legs of
/// each were reset.
fn assert_circuits_closed(
    scale: &mut Scale,
    closed: u64,
    reason: CircuitCloseReason,
    reservation_closed: bool,
) {
    let mut circuits = 0;
    let mut reservations = 0;
    while let Some(event) = scale.agent.poll_event() {
        if let RelayServerEvent::CircuitClosed {
            reason: closed_for, ..
        } = event
        {
            assert_eq!(closed_for, reason);
            circuits += 1;
        } else {
            assert!(
                matches!(
                    event,
                    RelayServerEvent::ReservationClosed {
                        reason: ReservationCloseReason::ConnectionClosed,
                        ..
                    }
                ),
                "unexpected event {event:?}"
            );
            reservations += 1;
        }
    }
    assert_eq!(circuits, closed);
    assert_eq!(reservations, u64::from(reservation_closed));
    let mut resets = 0;
    for call in scale.swarm.take_calls() {
        if matches!(call, Call::Reset { .. }) {
            resets += 1;
        } else {
            assert!(
                matches!(call, Call::Ack { .. }),
                "unexpected command {call:?}"
            );
        }
    }
    assert_eq!(resets, closed);
}

fn assert_source_torn_down((mut scale, _): (Scale, SwarmEvent)) {
    assert_circuits_closed(
        &mut scale,
        CIRCUITS_PER_SOURCE,
        CircuitCloseReason::ConnectionClosed {
            leg: CircuitLeg::Source,
        },
        false,
    );
    let size = scale.size as usize;
    assert_eq!(
        scale.agent.circuit_count(),
        size - CIRCUITS_PER_SOURCE as usize
    );
    assert_eq!(scale.agent.reservation_count(), size);
}

fn assert_destination_torn_down((mut scale, _): (Scale, SwarmEvent)) {
    assert_circuits_closed(
        &mut scale,
        1,
        CircuitCloseReason::ConnectionClosed {
            leg: CircuitLeg::Destination,
        },
        true,
    );
    assert_eq!(scale.agent.circuit_count(), scale.size as usize - 1);
    assert_eq!(scale.agent.reservation_count(), scale.size as usize - 1);
}

fn assert_tail_dropped((mut scale, _): (Scale, SwarmEvent)) {
    assert_circuits_closed(
        &mut scale,
        1,
        CircuitCloseReason::StreamReset {
            leg: CircuitLeg::Source,
        },
        false,
    );
    assert_eq!(scale.agent.circuit_count(), scale.size as usize - 1);
}

// Each benchmark returns its inputs so their drop and the assertions in
// `teardown` stay outside the measured region.

#[library_benchmark]
#[bench::relay_100_next_deadline(args = (100), setup = scale_agent, teardown = assert_unchanged)]
#[bench::relay_1k_next_deadline(args = (1_000), setup = scale_agent, teardown = assert_unchanged)]
#[bench::relay_10k_next_deadline(args = (10_000), setup = scale_agent, teardown = assert_unchanged)]
fn relay_next_deadline(scale: Scale) -> Scale {
    black_box(scale.agent.next_deadline(black_box(NOW)));
    scale
}

#[library_benchmark]
#[bench::relay_100_tick_idle(args = (100), setup = scale_agent, teardown = assert_unchanged)]
#[bench::relay_1k_tick_idle(args = (1_000), setup = scale_agent, teardown = assert_unchanged)]
#[bench::relay_10k_tick_idle(args = (10_000), setup = scale_agent, teardown = assert_unchanged)]
fn relay_tick_idle(mut scale: Scale) -> Scale {
    scale.agent.handle_tick(&mut scale.swarm, black_box(NOW));
    scale
}

#[library_benchmark]
#[bench::relay_100_tick_expire_100(
    args = (100), setup = scale_agent, teardown = assert_batch_expired
)]
#[bench::relay_1k_tick_expire_100(
    args = (1_000), setup = scale_agent, teardown = assert_batch_expired
)]
#[bench::relay_10k_tick_expire_100(
    args = (10_000), setup = scale_agent, teardown = assert_batch_expired
)]
fn relay_tick_expire_100(mut scale: Scale) -> Scale {
    scale.agent.handle_tick(&mut scale.swarm, black_box(EXPIRY));
    scale
}

/// Feeds one prepared event to the populated agent.
fn feed((mut scale, event): (Scale, SwarmEvent)) -> (Scale, SwarmEvent) {
    black_box(scale.handle(black_box(&event), black_box(NOW)));
    (scale, event)
}

#[library_benchmark]
#[bench::relay_100_reserve_new_peer(
    args = (100), setup = with_new_reserver, teardown = assert_reservation_accepted
)]
#[bench::relay_1k_reserve_new_peer(
    args = (1_000), setup = with_new_reserver, teardown = assert_reservation_accepted
)]
#[bench::relay_10k_reserve_new_peer(
    args = (10_000), setup = with_new_reserver, teardown = assert_reservation_accepted
)]
fn relay_reserve_new_peer(input: (Scale, SwarmEvent)) -> (Scale, SwarmEvent) {
    feed(input)
}

#[library_benchmark]
#[bench::relay_100_connect_new_peer(
    args = (100), setup = with_new_connector, teardown = assert_connect_admitted
)]
#[bench::relay_1k_connect_new_peer(
    args = (1_000), setup = with_new_connector, teardown = assert_connect_admitted
)]
#[bench::relay_10k_connect_new_peer(
    args = (10_000), setup = with_new_connector, teardown = assert_connect_admitted
)]
fn relay_connect_new_peer(input: (Scale, SwarmEvent)) -> (Scale, SwarmEvent) {
    feed(input)
}

#[library_benchmark]
#[bench::relay_100_hop_admission(
    args = (100), setup = with_new_hop_stream, teardown = assert_hop_admitted
)]
#[bench::relay_1k_hop_admission(
    args = (1_000), setup = with_new_hop_stream, teardown = assert_hop_admitted
)]
#[bench::relay_10k_hop_admission(
    args = (10_000), setup = with_new_hop_stream, teardown = assert_hop_admitted
)]
fn relay_hop_admission(input: (Scale, SwarmEvent)) -> (Scale, SwarmEvent) {
    feed(input)
}

#[library_benchmark]
#[bench::relay_100_close_connection_100_circuits(
    args = (100), setup = with_closed_source, teardown = assert_source_torn_down
)]
#[bench::relay_1k_close_connection_100_circuits(
    args = (1_000), setup = with_closed_source, teardown = assert_source_torn_down
)]
#[bench::relay_10k_close_connection_100_circuits(
    args = (10_000), setup = with_closed_source, teardown = assert_source_torn_down
)]
fn relay_close_connection_100_circuits(input: (Scale, SwarmEvent)) -> (Scale, SwarmEvent) {
    feed(input)
}

#[library_benchmark]
#[bench::relay_100_close_destination_connection(
    args = (100), setup = with_closed_destination, teardown = assert_destination_torn_down
)]
#[bench::relay_1k_close_destination_connection(
    args = (1_000), setup = with_closed_destination, teardown = assert_destination_torn_down
)]
#[bench::relay_10k_close_destination_connection(
    args = (10_000), setup = with_closed_destination, teardown = assert_destination_torn_down
)]
fn relay_close_destination_connection(input: (Scale, SwarmEvent)) -> (Scale, SwarmEvent) {
    feed(input)
}

#[library_benchmark]
#[bench::relay_100_reset_holding_full_tails(
    args = (100), setup = with_held_tails, teardown = assert_tail_dropped
)]
#[bench::relay_1k_reset_holding_full_tails(
    args = (1_000), setup = with_held_tails, teardown = assert_tail_dropped
)]
#[bench::relay_10k_reset_holding_full_tails(
    args = (10_000), setup = with_held_tails, teardown = assert_tail_dropped
)]
fn relay_reset_holding_full_tails(input: (Scale, SwarmEvent)) -> (Scale, SwarmEvent) {
    feed(input)
}

library_benchmark_group!(
    name = benches;
    benchmarks = relay_event,
        relay_next_deadline,
        relay_tick_idle,
        relay_tick_expire_100,
        relay_reserve_new_peer,
        relay_connect_new_peer,
        relay_hop_admission,
        relay_close_connection_100_circuits,
        relay_close_destination_connection,
        relay_reset_holding_full_tails
);
gungraun::main!(library_benchmark_groups = benches);
