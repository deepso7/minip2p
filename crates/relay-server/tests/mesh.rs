//! Relay-mesh agents: three nodes with hand-carried backbone links, a
//! destination reserved on one and a dialer connecting through another.

mod common;

use minip2p_core::platform::Deadline;
use minip2p_core::platform::Now;
use minip2p_core::{ConnectId, PeerAddr, PeerId};
use minip2p_nat::{ConnectLegs, NatAgent, NatConfig, NatEvent, Path, ReservationPolicy};
use minip2p_relay_server::mesh::{DIRECTORY_PROTOCOL_ID, FORWARD_PROTOCOL_ID};
use minip2p_relay_server::{
    CircuitCloseReason, CircuitDirection, CircuitLeg, RateLimit, RelayServerConfig,
    RelayServerEvent, Status, StreamKey,
};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::ConnectionId;

use common::mesh::{Mesh, link, member};
use common::nat_client::{
    CLIENT_RELAY_CONN, ClientSwarm, establish_relay_session, ready_client_hop,
};
use common::{Call, acked, at, closes, key, opened, peer, resets, sends_on, unlimited_rates};

const A: usize = 0;
const B: usize = 1;
const C: usize = 2;

/// Alice's connection on whichever node she reserves on, and its stream.
const ALICE_CONN: u64 = 10;
/// Her second connection, to another node.
const ALICE_CONN_2: u64 = 11;
const BOB_CONN: u64 = 20;

fn alice() -> PeerId {
    peer(b"mesh-alice")
}

fn bob() -> PeerId {
    peer(b"mesh-bob")
}

fn bob_stream() -> StreamKey {
    key(BOB_CONN, 2)
}

fn mesh(configs: [RelayServerConfig; 3]) -> Mesh {
    Mesh::new(configs.into())
}

fn defaults() -> [RelayServerConfig; 3] {
    [unlimited_rates(), unlimited_rates(), unlimited_rates()]
}

/// A time sample with a UNIX clock, so claims carry distinct expiries.
fn at_unix(ms: u64, unix: u64) -> Now {
    Now::new(ms, unix)
}

fn opened_events(events: &[RelayServerEvent]) -> Vec<Option<PeerId>> {
    events
        .iter()
        .filter_map(|event| match event {
            RelayServerEvent::CircuitOpened { via, .. } => Some(via.clone()),
            _ => None,
        })
        .collect()
}

fn closed_reasons(events: &[RelayServerEvent]) -> Vec<CircuitCloseReason> {
    events
        .iter()
        .filter_map(|event| match event {
            RelayServerEvent::CircuitClosed { reason, via, .. } => {
                assert!(via.is_some(), "a forwarded circuit names its other node");
                Some(*reason)
            }
            _ => None,
        })
        .collect()
}

/// Bytes acknowledged on any stream of node-local connection `conn_id`.
fn acked_on(calls: &[Call], conn_id: ConnectionId) -> usize {
    calls
        .iter()
        .filter_map(|call| match call {
            Call::Ack { stream, bytes } if stream.conn_id == conn_id => Some(*bytes),
            _ => None,
        })
        .sum()
}

fn forward_opens(mesh: &Mesh, entry: usize, holding: usize) -> usize {
    mesh.opened(entry, holding, FORWARD_PROTOCOL_ID).len()
}

/// Who sends Bob's CONNECT.
#[derive(Clone, Copy, Debug)]
enum Dialer {
    /// Scripted HOP frames.
    Scripted,
    /// An unmodified `NatAgent` making one connect attempt, so the mesh
    /// must settle the CONNECT without a client retry.
    Nat,
}

const DIALERS: [Dialer; 2] = [Dialer::Scripted, Dialer::Nat];

/// Bob's side of one CONNECT to Alice through node `entry`, on
/// [`bob_stream`].
struct Bob {
    entry: usize,
    nat: Option<(NatAgent, ClientSwarm)>,
}

impl Bob {
    fn dial(mesh: &mut Mesh, entry: usize, dialer: Dialer, now: Now) -> Self {
        let Dialer::Nat = dialer else {
            mesh.connect(entry, &bob(), bob_stream(), &alice(), now);
            return Self { entry, nat: None };
        };
        // Every node runs as the one relay identity, `common::Node`'s.
        let relay = peer(b"relay");
        let relay_addr = PeerAddr::new(
            "/ip4/192.0.2.1/udp/4001/quic-v1"
                .parse()
                .expect("multiaddr"),
            relay.clone(),
        )
        .expect("peer address");
        let mut agent = NatAgent::new(
            bob(),
            NatConfig {
                relays: vec![relay_addr],
                reservation_policy: ReservationPolicy::Never,
                force_relay: true,
                ..NatConfig::default()
            },
        );
        let mut swarm = ClientSwarm::new(&relay, ConnectionId::new(201));
        let hop = bob_stream().stream_id;
        swarm.next_stream = hop;
        agent.connect(
            &mut swarm,
            ConnectId::from_u64(1),
            alice(),
            ConnectLegs {
                direct_racing: false,
                allow_relay: true,
                target_addrs: Vec::new(),
                deadline_ms: None,
            },
            now,
        );
        establish_relay_session(&mut agent, &mut swarm, &relay, now.monotonic_ms);
        ready_client_hop(&mut agent, &mut swarm, &relay, hop, now.monotonic_ms);
        let node = mesh.node(entry);
        node.establish(&bob(), bob_stream().conn_id);
        node.hop_ready(&bob(), bob_stream(), now);
        node.data(&bob(), bob_stream(), &swarm.take_sent(), now);
        mesh.pump(now);
        Self {
            entry,
            nat: Some((agent, swarm)),
        }
    }

    /// Asserts the entry node has not answered yet.
    fn assert_waiting(&self, mesh: &mut Mesh) {
        assert_eq!(mesh.hop_status(self.entry, bob_stream()).0, None);
    }

    /// Asserts the circuit opened: the entry answered `OK` and, for a
    /// `NatAgent`, its one attempt established a relayed path.
    fn assert_opened(self, mesh: &mut Mesh, now: Now) {
        let calls = mesh.calls(self.entry);
        assert_eq!(
            common::mesh::hop_status(&calls, bob_stream()).0,
            Some(Status::Ok)
        );
        let Some((mut agent, mut swarm)) = self.nat else {
            return;
        };
        let reply = sends_on(&calls, bob_stream()).remove(0);
        agent.handle_event(
            &mut swarm,
            &SwarmEvent::StreamData {
                peer_id: peer(b"relay"),
                conn_id: CLIENT_RELAY_CONN,
                stream_id: bob_stream().stream_id,
                data: reply.into(),
            },
            false,
            now,
        );
        let circuit = swarm.promoted_circuit();
        agent.handle_event(
            &mut swarm,
            &SwarmEvent::ConnectionEstablished {
                peer_id: alice(),
                conn_id: circuit,
            },
            true,
            now,
        );
        let established = core::iter::from_fn(|| agent.poll_event())
            .find(|event| !matches!(event, NatEvent::RelayStarted { .. }));
        assert!(
            matches!(
                established,
                Some(NatEvent::PathEstablished {
                    path: Path::Relayed { .. },
                    ..
                })
            ),
            "{established:?}"
        );
    }
}

/// Bob on `entry` reaches Alice reserved on `holding`; returns Alice's STOP
/// stream on `holding`.
fn open_forwarded(
    mesh: &mut Mesh,
    entry: usize,
    holding: usize,
    bob: &PeerId,
    stream: StreamKey,
) -> StreamKey {
    mesh.connect(entry, bob, stream, &alice(), at(0));
    let stop = mesh.answer_stop(holding, &alice(), Status::Ok, at(0));
    assert_eq!(mesh.hop_status(entry, stream).0, Some(Status::Ok));
    assert_eq!(
        opened_events(&mesh.node(entry).events()),
        [Some(member(holding))]
    );
    assert_eq!(
        opened_events(&mesh.node(holding).events()),
        [Some(member(entry))]
    );
    stop
}

#[test]
fn forwarded_circuit_carries_bytes_both_ways_with_backpressure_and_half_close() {
    let mut mesh = mesh(defaults());
    mesh.reserve(A, &alice(), key(ALICE_CONN, 1), at(0));
    let stop = open_forwarded(&mut mesh, B, A, &bob(), bob_stream());
    let forward_at_a = Mesh::remote(B, mesh.opened(B, A, FORWARD_PROTOCOL_ID)[0]);

    // Bob to Alice, with Alice's STOP stream taking two bytes at first: the
    // holding node acknowledges the backbone only for what Alice took.
    mesh.nodes[A].swarm.credit.insert(stop, 2);
    mesh.nodes[B].data(&bob(), bob_stream(), b"abcdef", at(1));
    mesh.pump(at(1));
    assert_eq!(
        acked(&mesh.calls(B), bob_stream()),
        6,
        "the backbone took it all"
    );
    let calls = mesh.calls(A);
    assert_eq!(sends_on(&calls, stop), [b"abcdef".to_vec()]);
    assert_eq!(acked(&calls, forward_at_a), 2);
    mesh.nodes[A].swarm.credit.remove(&stop);
    mesh.nodes[A].writable(&alice(), stop, at(2));
    mesh.pump(at(2));
    let calls = mesh.calls(A);
    assert_eq!(sends_on(&calls, stop), [b"cdef".to_vec()]);
    assert_eq!(acked(&calls, forward_at_a), 4);

    // Alice to Bob, with Bob's stream taking three bytes at first: the entry
    // node acknowledges the backbone only for what Bob took.
    mesh.nodes[B].swarm.credit.insert(bob_stream(), 3);
    mesh.nodes[A].data(&alice(), stop, b"uvwxyz", at(3));
    mesh.pump(at(3));
    assert_eq!(acked(&mesh.calls(A), stop), 6);
    let calls = mesh.calls(B);
    assert_eq!(sends_on(&calls, bob_stream()), [b"uvwxyz".to_vec()]);
    assert_eq!(acked_on(&calls, link(A)), 3);
    mesh.nodes[B].swarm.credit.remove(&bob_stream());
    mesh.nodes[B].writable(&bob(), bob_stream(), at(4));
    mesh.pump(at(4));
    let calls = mesh.calls(B);
    assert_eq!(sends_on(&calls, bob_stream()), [b"xyz".to_vec()]);
    assert_eq!(acked_on(&calls, link(A)), 3);

    // Bob's half-close reaches Alice after his bytes.
    mesh.nodes[B].half_close(&bob(), bob_stream(), at(5));
    mesh.pump(at(5));
    assert_eq!(closes(&mesh.calls(A)), [stop]);
    // Alice's reaches Bob, and both nodes close the circuit cleanly.
    mesh.nodes[A].half_close(&alice(), stop, at(6));
    mesh.pump(at(6));
    assert_eq!(closes(&mesh.calls(B)), [bob_stream()]);
    for node in [A, B] {
        assert_eq!(
            closed_reasons(&mesh.nodes[node].events()),
            [CircuitCloseReason::Eof]
        );
        assert_eq!(mesh.nodes[node].circuit_count(), 0);
    }
}

#[test]
fn a_reset_crosses_the_backbone() {
    let mut mesh = mesh(defaults());
    mesh.reserve(A, &alice(), key(ALICE_CONN, 1), at(0));
    let stop = open_forwarded(&mut mesh, B, A, &bob(), bob_stream());

    mesh.nodes[A].stream_closed(&alice(), stop, at(1));
    mesh.pump(at(1));
    assert_eq!(resets(&mesh.calls(B)), [bob_stream()]);
    let reset = CircuitCloseReason::StreamReset {
        leg: CircuitLeg::Destination,
    };
    for node in [A, B] {
        assert_eq!(closed_reasons(&mesh.nodes[node].events()), [reset]);
        assert_eq!(mesh.nodes[node].circuit_count(), 0);
    }
}

#[test]
fn holding_node_without_the_reservation_answers_no_reservation_and_the_entry_passes_it_on() {
    let mut mesh = mesh(defaults());
    mesh.reserve(A, &alice(), key(ALICE_CONN, 1), at(0));
    // Alice leaves A before A's `Gone` reaches B.
    mesh.hold_directory(A, B);
    mesh.nodes[A].close_connection(&alice(), ConnectionId::new(ALICE_CONN), 1);
    mesh.pump(at(1));
    mesh.nodes[A].events();

    mesh.connect(B, &bob(), bob_stream(), &alice(), at(2));
    assert_eq!(forward_opens(&mesh, B, A), 1, "B still trusted A's claim");
    assert_eq!(
        mesh.hop_status(B, bob_stream()).0,
        Some(Status::NoReservation)
    );
    assert!(matches!(
        mesh.nodes[A].events()[..],
        [RelayServerEvent::CircuitDenied {
            ref source_peer_id,
            status: Status::NoReservation,
            ..
        }] if *source_peer_id == bob()
    ));
    assert_eq!(mesh.nodes[B].circuit_count(), 0);
}

/// How the stale node is set up in [`a_stale_claim_tried_first_falls_through_to_the_live_one`].
#[derive(Clone, Copy, Debug)]
enum Stale {
    Idle,
    Paused,
    AtCapacity,
}

#[test]
fn an_unchanged_client_reaches_a_peer_reserved_on_another_node() {
    for dialer in DIALERS {
        let mut mesh = mesh(defaults());
        mesh.reserve(A, &alice(), key(ALICE_CONN, 1), at(0));
        let bob = Bob::dial(&mut mesh, B, dialer, at(1));
        mesh.answer_stop(A, &alice(), Status::Ok, at(1));
        bob.assert_opened(&mut mesh, at(1));
    }
}

#[test]
fn the_newer_claim_is_tried_first_during_a_move() {
    for dialer in DIALERS {
        let mut mesh = mesh(defaults());
        // Alice holds a reservation on A, then a newer one on B; both are
        // live.
        mesh.reserve(A, &alice(), key(ALICE_CONN, 1), at_unix(0, 1_000));
        mesh.reserve(B, &alice(), key(ALICE_CONN_2, 1), at_unix(0, 2_000));

        let bob = Bob::dial(&mut mesh, C, dialer, at(1));
        assert_eq!(forward_opens(&mesh, C, B), 1);
        assert_eq!(forward_opens(&mesh, C, A), 0);
        mesh.answer_stop(B, &alice(), Status::Ok, at(1));
        bob.assert_opened(&mut mesh, at(1));
    }
}

#[test]
fn a_stale_claim_tried_first_falls_through_to_the_live_one() {
    for (stale, dialer) in [Stale::Idle, Stale::Paused, Stale::AtCapacity]
        .into_iter()
        .flat_map(|stale| DIALERS.map(|dialer| (stale, dialer)))
    {
        let mut configs = defaults();
        if let Stale::AtCapacity = stale {
            configs[A].max_circuits = 0;
        }
        let mut mesh = mesh(configs);
        // Alice moved from B to A, so A's claim is newer; then she left A
        // before A's `Gone` reached C.
        mesh.reserve(B, &alice(), key(ALICE_CONN_2, 1), at_unix(0, 1_000));
        mesh.reserve(A, &alice(), key(ALICE_CONN, 1), at_unix(0, 2_000));
        mesh.hold_directory(A, C);
        mesh.nodes[A].close_connection(&alice(), ConnectionId::new(ALICE_CONN), 1);
        mesh.pump(at(1));
        if let Stale::Paused = stale {
            mesh.nodes[A].set_accepting(false);
        }

        let bob = Bob::dial(&mut mesh, C, dialer, at(2));
        assert_eq!(forward_opens(&mesh, C, A), 1, "{stale:?}: A first");
        assert_eq!(forward_opens(&mesh, C, B), 1, "{stale:?}: then B");
        mesh.answer_stop(B, &alice(), Status::Ok, at(2));
        assert_eq!(opened_events(&mesh.nodes[C].events()), [Some(member(B))]);
        bob.assert_opened(&mut mesh, at(2));
    }
}

#[test]
fn a_connect_during_a_snapshot_waits_for_synced() {
    for dialer in DIALERS {
        let mut mesh = Mesh::with_held(defaults().into(), &[(B, C)]);
        mesh.reserve(B, &alice(), key(ALICE_CONN, 1), at(0));

        let bob = Bob::dial(&mut mesh, C, dialer, at(1));
        bob.assert_waiting(&mut mesh);
        assert_eq!(mesh.nodes[C].circuit_count(), 1);

        mesh.release_directory(B, C, at(2));
        mesh.answer_stop(B, &alice(), Status::Ok, at(2));
        bob.assert_opened(&mut mesh, at(2));
    }
}

#[test]
fn a_connect_waiting_on_a_member_whose_link_drops_has_no_reservation() {
    let mut mesh = Mesh::with_held(defaults().into(), &[(B, C)]);
    mesh.reserve(B, &alice(), key(ALICE_CONN, 1), at(0));
    mesh.connect(C, &bob(), bob_stream(), &alice(), at(1));

    mesh.nodes[C].close_connection(&member(B), link(B), 2);
    mesh.pump(at(2));
    assert_eq!(
        mesh.hop_status(C, bob_stream()).0,
        Some(Status::NoReservation)
    );
    assert_eq!(mesh.nodes[C].circuit_count(), 0);
}

#[test]
fn a_lost_link_drops_the_members_entries() {
    let mut mesh = mesh(defaults());
    mesh.reserve(A, &alice(), key(ALICE_CONN, 1), at(0));
    mesh.nodes[B].close_connection(&member(A), link(A), 1);
    mesh.pump(at(1));

    mesh.connect(B, &bob(), bob_stream(), &alice(), at(2));
    assert_eq!(forward_opens(&mesh, B, A), 0);
    assert_eq!(
        mesh.hop_status(B, bob_stream()).0,
        Some(Status::NoReservation)
    );
}

#[test]
fn a_reset_directory_stream_reopens_after_a_second_and_resyncs() {
    for dialer in DIALERS {
        let mut mesh = mesh(defaults());
        mesh.reserve(A, &alice(), key(ALICE_CONN, 1), at(0));
        mesh.reset_directory(A, B, at(10));
        assert_eq!(
            mesh.nodes[A].next_deadline(at(10)),
            Some(Deadline::from_millis(1_010))
        );

        // B dropped A's entries and waits for A's next snapshot.
        let bob = Bob::dial(&mut mesh, B, dialer, at(20));
        bob.assert_waiting(&mut mesh);

        mesh.nodes[A].handle_tick(at(1_010));
        mesh.pump(at(1_010));
        assert_eq!(mesh.opened(A, B, DIRECTORY_PROTOCOL_ID).len(), 2);
        mesh.answer_stop(A, &alice(), Status::Ok, at(1_010));
        bob.assert_opened(&mut mesh, at(1_010));
    }
}

#[test]
fn the_entry_node_spends_the_rate_token_and_applies_the_dialers_limits() {
    let once = Some(RateLimit {
        capacity: 1,
        refill_interval_ms: 1_000_000,
    });
    let mut configs = defaults();
    configs[A].circuit_rate_limit_per_peer = once;
    configs[B].circuit_rate_limit_per_peer = once;
    let mut mesh = mesh(configs);
    mesh.reserve(A, &alice(), key(ALICE_CONN, 1), at(0));
    open_forwarded(&mut mesh, B, A, &bob(), bob_stream());

    // A spent no token on Bob: another entry node still gets him through.
    open_forwarded(&mut mesh, C, A, &bob(), key(BOB_CONN + 1, 2));
    // B did: Bob's next CONNECT there is refused before any forward.
    mesh.connect(B, &bob(), key(BOB_CONN, 4), &alice(), at(1));
    assert_eq!(
        mesh.hop_status(B, key(BOB_CONN, 4)).0,
        Some(Status::ResourceLimitExceeded)
    );
    assert_eq!(forward_opens(&mesh, B, A), 1);
}

#[test]
fn the_holding_node_applies_the_destinations_limits_without_falling_through() {
    let mut configs = defaults();
    configs[A].max_circuits_per_peer = 1;
    let mut mesh = mesh(configs);
    // Alice is claimed by C and, newer, by A.
    mesh.reserve(C, &alice(), key(ALICE_CONN_2, 1), at_unix(0, 1_000));
    mesh.reserve(A, &alice(), key(ALICE_CONN, 1), at_unix(0, 2_000));
    open_forwarded(&mut mesh, B, A, &bob(), bob_stream());

    let carol = peer(b"mesh-carol");
    mesh.connect(B, &carol, key(BOB_CONN + 1, 2), &alice(), at(1));
    assert_eq!(
        mesh.hop_status(B, key(BOB_CONN + 1, 2)).0,
        Some(Status::ResourceLimitExceeded)
    );
    assert_eq!(forward_opens(&mesh, B, C), 0, "A's decision stands");
}

#[test]
fn pause_on_either_node_refuses() {
    let mut mesh = mesh(defaults());
    mesh.reserve(A, &alice(), key(ALICE_CONN, 1), at(0));

    mesh.nodes[B].set_accepting(false);
    mesh.connect(B, &bob(), bob_stream(), &alice(), at(1));
    assert_eq!(
        mesh.hop_status(B, bob_stream()).0,
        Some(Status::PermissionDenied)
    );
    assert_eq!(forward_opens(&mesh, B, A), 0);

    mesh.nodes[B].set_accepting(true);
    mesh.nodes[A].set_accepting(false);
    mesh.connect(B, &bob(), key(BOB_CONN, 4), &alice(), at(2));
    assert_eq!(forward_opens(&mesh, B, A), 1);
    assert_eq!(
        mesh.hop_status(B, key(BOB_CONN, 4)).0,
        Some(Status::PermissionDenied)
    );
}

#[test]
fn both_nodes_enforce_the_entry_nodes_limits() {
    let limited = |bytes, secs| RelayServerConfig {
        max_circuit_bytes: bytes,
        max_circuit_duration_secs: secs,
        ..unlimited_rates()
    };
    // A (holding) is the strictest; B's limits are looser; C has none.
    let mut mesh = mesh([limited(16, 5), limited(32, 10), limited(0, 0)]);
    mesh.reserve(A, &alice(), key(ALICE_CONN, 1), at(0));
    let via_b = open_forwarded(&mut mesh, B, A, &bob(), bob_stream());
    let via_c = open_forwarded(&mut mesh, C, A, &bob(), key(BOB_CONN, 4));

    // Past A's own 16 bytes, within B's 32: the circuit stays open.
    mesh.nodes[B].data(&bob(), bob_stream(), &[1; 20], at(1));
    mesh.nodes[C].data(&bob(), key(BOB_CONN, 4), &[1; 40], at(1));
    mesh.pump(at(1));
    let calls = mesh.calls(A);
    assert_eq!(sends_on(&calls, via_b).concat().len(), 20);
    assert_eq!(sends_on(&calls, via_c).concat().len(), 40);
    for node in [A, B, C] {
        assert_eq!(closed_reasons(&mesh.nodes[node].events()), []);
    }
    // Past B's 32: both B and A close the circuit through B.
    mesh.nodes[B].data(&bob(), bob_stream(), &[2; 20], at(2));
    mesh.pump(at(2));
    let byte_limit = CircuitCloseReason::ByteLimit {
        direction: CircuitDirection::SourceToDestination,
    };
    assert_eq!(closed_reasons(&mesh.nodes[A].events()), [byte_limit]);
    assert_eq!(closed_reasons(&mesh.nodes[B].events()), [byte_limit]);

    // Durations: A does not close at its own 5 s, and a circuit through B
    // closes on both nodes at B's 10 s.
    let via_b = open_forwarded(&mut mesh, B, A, &bob(), key(BOB_CONN, 6));
    mesh.nodes[A].handle_tick(at(5_000));
    assert_eq!(closed_reasons(&mesh.nodes[A].events()), []);
    for node in [A, B, C] {
        mesh.nodes[node].handle_tick(at(10_000));
    }
    assert_eq!(
        closed_reasons(&mesh.nodes[A].events()),
        [CircuitCloseReason::DurationLimit]
    );
    assert_eq!(
        closed_reasons(&mesh.nodes[B].events()),
        [CircuitCloseReason::DurationLimit]
    );
    assert_eq!(
        closed_reasons(&mesh.nodes[C].events()),
        [],
        "C has no limit"
    );
    assert_eq!(mesh.nodes[A].circuit_count(), 1, "the one through C");
    let _ = via_b;
}

#[test]
fn a_forward_that_times_out_fails_and_leaves_no_state() {
    let config = RelayServerConfig {
        control_stream_timeout_ms: 1_000,
        ..unlimited_rates()
    };
    let mut mesh = mesh([config.clone(), config.clone(), config]);
    mesh.reserve(A, &alice(), key(ALICE_CONN, 1), at(0));
    mesh.connect(B, &bob(), bob_stream(), &alice(), at(0));
    let stop = opened(&mesh.calls(A)).expect("A opens STOP");
    let forward = mesh.opened(B, A, FORWARD_PROTOCOL_ID)[0];

    // Alice never answers.
    mesh.nodes[B].handle_tick(at(1_000));
    mesh.pump(at(1_000));
    assert_eq!(
        mesh.hop_status(B, bob_stream()).0,
        Some(Status::ConnectionFailed)
    );
    // A gave the STOP stream up; it is gone once the swarm closes it.
    mesh.nodes[A].stream_closed(&alice(), stop, at(1_000));
    for node in [A, B] {
        assert_eq!(mesh.nodes[node].circuit_count(), 0);
    }
    assert!(!mesh.nodes[A].owns_stream(stop));
    assert!(!mesh.nodes[A].owns_stream(Mesh::remote(B, forward)));
    assert!(!mesh.nodes[B].owns_stream(forward));
}

#[test]
fn non_members_are_refused_on_the_backbone_and_on_mesh_protocols() {
    let mut mesh = mesh(defaults());
    let stranger = peer(b"mesh-stranger");
    let node = &mut mesh.nodes[A];

    let backbone = ConnectionId::namespaced(minip2p_transport::ConnectionNamespace::MESH_IPV4, 9)
        .expect("in range");
    node.establish(&stranger, backbone);
    assert_eq!(
        node.calls(),
        [Call::CloseConnection {
            peer: stranger.clone(),
            conn_id: backbone,
        }]
    );
    assert!(matches!(
        node.events()[..],
        [RelayServerEvent::Error(ref error)]
            if error.kind == minip2p_relay_server::RelayServerRuntimeErrorKind::Mesh
    ));

    // A mesh protocol over a public connection is not a member's either.
    let public = key(30, 1);
    node.establish(&stranger, public.conn_id);
    assert!(node.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: stranger.clone(),
            conn_id: public.conn_id,
            stream_id: public.stream_id,
            protocol_id: FORWARD_PROTOCOL_ID.into(),
            initiated_locally: false,
        },
        false,
        at(1),
    ));
    assert_eq!(resets(&node.calls()), [public]);
    assert!(node.owns_stream(public), "claimed until it closes");
}
