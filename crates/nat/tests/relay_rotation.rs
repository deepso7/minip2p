//! Relay-leg rotation: one connect attempt tries each configured relay in
//! turn, each within its share of the relay-leg deadline.

mod common;

use common::*;

use minip2p_core::{PeerAddr, PeerId};
use minip2p_nat::{
    ConnectLegs, NatConfig, NatError, NatEvent, Path, PromoteError, ReservationPolicy,
};
use minip2p_relay::{HOP_PROTOCOL_ID, Status};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{Bytes, ConnectionId, StreamId};

struct World {
    agent: Node,
    target: PeerId,
    a: PeerId,
    b: PeerId,
}

fn relay_addr(addr: &str, relay: &PeerId) -> PeerAddr {
    PeerAddr::new(maddr(addr), relay.clone()).expect("valid relay addr")
}

/// An agent configured with relays `[A, B]` and no reservations.
fn two_relays() -> World {
    relays_with(|a, b| {
        vec![
            relay_addr("/ip4/203.0.113.1/udp/4001/quic-v1", a),
            relay_addr("/ip4/203.0.113.2/udp/4001/quic-v1", b),
        ]
    })
}

/// An agent configured with the relay entries `relays(A, B)` returns.
fn relays_with(relays: impl FnOnce(&PeerId, &PeerId) -> Vec<PeerAddr>) -> World {
    let a = peer(b"relay-a");
    let b = peer(b"relay-b");
    let config = NatConfig {
        relays: relays(&a, &b),
        reservation_policy: ReservationPolicy::Never,
        ..NatConfig::default()
    };
    let mut agent = Node::new(peer(b"local-peer"), config);
    agent.set_listen_addrs(&[maddr(LISTEN_ADDR)]);
    World {
        agent,
        target: peer(b"target-peer"),
        a,
        b,
    }
}

/// The connection and address of the dial to `peer` in `actions`.
fn dial_for(actions: &[Out], peer: &PeerId) -> (ConnectionId, PeerAddr) {
    actions
        .iter()
        .find_map(|action| match action {
            Out::Dial {
                addr,
                conn: Some(conn),
                ..
            } if addr.peer_id() == peer => Some((*conn, addr.clone())),
            _ => None,
        })
        .expect("expected a started dial to the peer")
}

/// Feeds the swarm's report that the dial on `conn` to `addr` failed.
fn dial_failed(w: &mut World, (conn_id, addr): (ConnectionId, PeerAddr), reason: &str, now: u64) {
    w.agent.handle_event(
        &SwarmEvent::DialFailed {
            conn_id,
            addr,
            reason: reason.into(),
        },
        false,
        at(now),
    );
}

/// Connects `relay` on `conn_id`, completes identify, and runs the HOP
/// CONNECT exchange up to the relay's STATUS reply. Returns the HOP stream.
fn hop_exchange(
    w: &mut World,
    relay: &PeerId,
    conn_id: ConnectionId,
    status: Status,
    now: u64,
) -> StreamId {
    w.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            peer_id: relay.clone(),
            conn_id,
        },
        false,
        at(now),
    );
    w.agent.handle_event(
        &SwarmEvent::PeerReady {
            peer_id: relay.clone(),
            conn_id,
            protocols: vec![HOP_PROTOCOL_ID.to_string()],
        },
        false,
        at(now),
    );
    let stream = opened_stream_for(&drain_actions(&mut w.agent), relay);
    w.agent.handle_event(
        &SwarmEvent::StreamReady {
            conn_id,
            peer_id: relay.clone(),
            stream_id: stream,
            protocol_id: HOP_PROTOCOL_ID.to_string(),
            initiated_locally: true,
        },
        false,
        at(now),
    );
    drain_actions(&mut w.agent);
    w.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id,
            peer_id: relay.clone(),
            stream_id: stream,
            data: Bytes::from(hop_status(status)),
        },
        false,
        at(now),
    );
    stream
}

/// Asserts the bridge promotes and the attempt reports a path through `relay`.
fn assert_relayed_via(w: &mut World, relay: &PeerId, now: u64) {
    let actions = drain_actions(&mut w.agent);
    assert!(
        actions.iter().any(|action| matches!(
            action,
            Out::PromoteBridge { relay: r, .. } if r == relay
        )),
        "the bridge through {relay} must be promoted"
    );
    let target = w.target.clone();
    complete_promotion(&mut w.agent, &target, &actions, at(now));
    assert!(matches!(
        drain_events(&mut w.agent).as_slice(),
        [NatEvent::PathEstablished { path: Path::Relayed { relay: r }, .. }] if r == relay
    ));
}

#[test]
fn stalled_first_relay_hands_over_after_its_share() {
    let mut w = two_relays();
    let target = w.target.clone();
    let _ = start(&mut w.agent, 1, target, RELAY_NOW, at(0));
    let actions = drain_actions(&mut w.agent);
    assert_eq!(dial_count_for(&actions, &w.a), 1);
    assert_eq!(dial_count_for(&actions, &w.b), 0);

    // A never answers. Its share is half of the 12 s relay-leg deadline.
    w.agent.handle_tick(at(5_999));
    assert_eq!(dial_count_for(&drain_actions(&mut w.agent), &w.b), 0);
    w.agent.handle_tick(at(6_000));
    let actions = drain_actions(&mut w.agent);
    assert_eq!(dial_count_for(&actions, &w.b), 1);
    assert!(
        drain_events(&mut w.agent).is_empty(),
        "the leg is still live"
    );

    let b = w.b.clone();
    let b_conn = dial_conn_for(&actions, &b);
    hop_exchange(&mut w, &b, b_conn, Status::Ok, 6_500);
    assert_relayed_via(&mut w, &b, 6_501);
}

#[test]
fn shares_fit_a_caller_deadline_shorter_than_the_leg_deadline() {
    let mut w = two_relays();
    let target = w.target.clone();
    let legs = ConnectLegs {
        deadline_ms: Some(4_000),
        ..RELAY_NOW
    };
    let _ = start(&mut w.agent, 1, target, legs, at(0));
    drain_actions(&mut w.agent);

    // The attempt gives up at 4 s, so A gets 2 s rather than 6 s.
    w.agent.handle_tick(at(2_000));
    assert_eq!(dial_count_for(&drain_actions(&mut w.agent), &w.b), 1);
    w.agent.handle_tick(at(4_000));
    assert!(matches!(
        drain_events(&mut w.agent).as_slice(),
        [NatEvent::ConnectFailed {
            error: NatError::Timeout,
            ..
        }]
    ));
}

#[test]
fn relay_the_target_is_known_through_goes_first() {
    let mut w = two_relays();
    let target = w.target.clone();
    let unconfigured = peer(b"relay-c");
    let legs = ConnectLegs {
        target_addrs: vec![
            maddr(&format!(
                "/ip4/203.0.113.3/udp/4001/quic-v1/p2p/{unconfigured}/p2p-circuit"
            )),
            maddr(TARGET_ADDR),
            maddr(&format!(
                "/ip4/203.0.113.2/udp/4001/quic-v1/p2p/{}/p2p-circuit",
                w.b
            )),
        ],
        ..RELAY_NOW
    };
    let _ = start(&mut w.agent, 1, target, legs, at(0));
    let actions = drain_actions(&mut w.agent);
    assert_eq!(dial_count_for(&actions, &w.b), 1, "B is tried first");
    assert_eq!(dial_count_for(&actions, &w.a), 0);
    assert_eq!(
        dial_count_for(&actions, &unconfigured),
        0,
        "only configured relays are eligible"
    );

    let b = w.b.clone();
    let b_conn = dial_conn_for(&actions, &b);
    hop_exchange(&mut w, &b, b_conn, Status::NoReservation, 10);
    assert_eq!(
        dial_count_for(&drain_actions(&mut w.agent), &w.a),
        1,
        "A follows in config order"
    );
}

#[test]
fn late_dial_failure_from_an_abandoned_relay_is_ignored() {
    let mut w = two_relays();
    let target = w.target.clone();
    let _ = start(&mut w.agent, 1, target, RELAY_NOW, at(0));
    let a_dial = dial_for(&drain_actions(&mut w.agent), &w.a);
    w.agent.handle_tick(at(6_000));
    let actions = drain_actions(&mut w.agent);
    assert_eq!(dial_count_for(&actions, &w.b), 1);

    dial_failed(&mut w, a_dial, "relay A finally gave up", 6_100);
    assert!(
        drain_events(&mut w.agent).is_empty(),
        "B's leg is untouched"
    );
    assert_eq!(dial_count_for(&drain_actions(&mut w.agent), &w.a), 0);

    let b = w.b.clone();
    let b_conn = dial_conn_for(&actions, &b);
    hop_exchange(&mut w, &b, b_conn, Status::Ok, 6_200);
    assert_relayed_via(&mut w, &b, 6_201);
}

#[test]
fn dial_failure_after_the_relay_became_ready_is_ignored() {
    let mut w = two_relays();
    let target = w.target.clone();
    let _ = start(&mut w.agent, 1, target, RELAY_NOW, at(0));
    let a_dial = dial_for(&drain_actions(&mut w.agent), &w.a);

    // Another connection to A lands and becomes ready; the leg opens HOP.
    w.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            peer_id: w.a.clone(),
            conn_id: ConnectionId::new(9),
        },
        false,
        at(10),
    );
    w.agent.handle_event(
        &SwarmEvent::PeerReady {
            peer_id: w.a.clone(),
            conn_id: ConnectionId::new(9),
            protocols: vec![HOP_PROTOCOL_ID.to_string()],
        },
        false,
        at(10),
    );
    assert!(has_hop_open(&drain_actions(&mut w.agent)));

    // The attempt's own dial to A fails afterwards.
    dial_failed(&mut w, a_dial, "replaced", 20);
    assert_eq!(
        dial_count_for(&drain_actions(&mut w.agent), &w.b),
        0,
        "the HOP on A is kept"
    );
    assert!(drain_events(&mut w.agent).is_empty());
}

#[test]
fn dial_failure_while_the_relay_is_connected_waits_for_peer_ready() {
    let mut w = two_relays();
    let target = w.target.clone();
    let _ = start(&mut w.agent, 1, target, RELAY_NOW, at(0));
    let a_dial = dial_for(&drain_actions(&mut w.agent), &w.a);

    // Another connection to A lands; identify has not finished yet.
    w.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            peer_id: w.a.clone(),
            conn_id: ConnectionId::new(9),
        },
        false,
        at(10),
    );
    dial_failed(&mut w, a_dial, "replaced", 20);
    assert_eq!(dial_count_for(&drain_actions(&mut w.agent), &w.b), 0);
    assert!(drain_events(&mut w.agent).is_empty());

    w.agent.handle_event(
        &SwarmEvent::PeerReady {
            peer_id: w.a.clone(),
            conn_id: ConnectionId::new(9),
            protocols: vec![HOP_PROTOCOL_ID.to_string()],
        },
        false,
        at(30),
    );
    assert!(
        has_hop_open(&drain_actions(&mut w.agent)),
        "A's HOP path is used"
    );
}

#[test]
fn no_reservation_at_first_relay_moves_to_the_next() {
    let mut w = two_relays();
    let target = w.target.clone();
    let _ = start(&mut w.agent, 1, target, RELAY_NOW, at(0));
    let (a, b) = (w.a.clone(), w.b.clone());
    let a_conn = dial_conn_for(&drain_actions(&mut w.agent), &a);

    let refused = hop_exchange(&mut w, &a, a_conn, Status::NoReservation, 10);
    let actions = drain_actions(&mut w.agent);
    assert!(has_reset_for(&actions, refused), "A's HOP stream is reset");
    assert_eq!(dial_count_for(&actions, &b), 1, "B is tried next");
    assert!(
        drain_events(&mut w.agent).is_empty(),
        "the leg is still live"
    );

    hop_exchange(&mut w, &b, dial_conn_for(&actions, &b), Status::Ok, 20);
    assert_relayed_via(&mut w, &b, 21);
}

#[test]
fn leg_fails_with_the_last_relays_error_after_trying_all() {
    let mut w = two_relays();
    let target = w.target.clone();
    let _ = start(&mut w.agent, 1, target, RELAY_NOW, at(0));
    let a_dial = dial_for(&drain_actions(&mut w.agent), &w.a);
    dial_failed(&mut w, a_dial, "relay A unreachable", 10);
    assert!(
        drain_events(&mut w.agent).is_empty(),
        "B has not been tried yet"
    );
    let actions = drain_actions(&mut w.agent);
    assert_eq!(dial_count_for(&actions, &w.b), 1);

    let b = w.b.clone();
    hop_exchange(
        &mut w,
        &b,
        dial_conn_for(&actions, &b),
        Status::NoReservation,
        20,
    );
    assert!(matches!(
        drain_events(&mut w.agent).as_slice(),
        [NatEvent::ConnectFailed { error: NatError::RelayRefused(reason), .. }]
            if reason.contains("NoReservation")
    ));
    drain_actions(&mut w.agent);
    assert!(w.agent.is_idle());
}

#[test]
fn failed_promotion_at_first_relay_moves_to_the_next() {
    let mut w = two_relays();
    let target = w.target.clone();
    let _ = start(&mut w.agent, 1, target, RELAY_NOW, at(0));
    let (a, b) = (w.a.clone(), w.b.clone());
    let a_conn = dial_conn_for(&drain_actions(&mut w.agent), &a);

    hop_exchange(&mut w, &a, a_conn, Status::Ok, 10);
    let token = promote_token(&drain_actions(&mut w.agent));
    w.agent.promote_result(
        token,
        Err(PromoteError::Failed("secure-mux handshake failed".into())),
        at(20),
    );
    let actions = drain_actions(&mut w.agent);
    assert_eq!(dial_count_for(&actions, &b), 1);
    assert!(
        drain_events(&mut w.agent).is_empty(),
        "the leg is still live"
    );

    hop_exchange(&mut w, &b, dial_conn_for(&actions, &b), Status::Ok, 30);
    assert_relayed_via(&mut w, &b, 31);
}

#[test]
fn circuit_closing_before_it_establishes_moves_to_the_next_relay() {
    let mut w = two_relays();
    let target = w.target.clone();
    let _ = start(&mut w.agent, 1, target.clone(), RELAY_NOW, at(0));
    let (a, b) = (w.a.clone(), w.b.clone());
    let a_conn = dial_conn_for(&drain_actions(&mut w.agent), &a);

    hop_exchange(&mut w, &a, a_conn, Status::Ok, 10);
    let token = promote_token(&drain_actions(&mut w.agent));
    let circuit = ConnectionId::new(TEST_CIRCUIT_ID);
    w.agent.promote_result(token, Ok(circuit), at(20));
    w.agent.handle_event(
        &SwarmEvent::ConnectionClosed {
            peer_id: target,
            conn_id: circuit,
        },
        true,
        at(30),
    );
    assert_eq!(dial_count_for(&drain_actions(&mut w.agent), &b), 1);
    assert!(
        drain_events(&mut w.agent).is_empty(),
        "the leg is still live"
    );
}

#[test]
fn relay_addresses_are_tried_until_the_relay_is_reached() {
    let mut w = relays_with(|a, b| {
        vec![
            relay_addr("/ip4/203.0.113.1/udp/4001/quic-v1", a),
            relay_addr("/ip4/203.0.113.1/tcp/4001", a),
            relay_addr("/ip4/203.0.113.2/udp/4001/quic-v1", b),
        ]
    });
    let tcp = relay_addr("/ip4/203.0.113.1/tcp/4001", &w.a);
    let target = w.target.clone();
    let _ = start(&mut w.agent, 1, target, RELAY_NOW, at(0));
    let quic_dial = dial_for(&drain_actions(&mut w.agent), &w.a);
    dial_failed(&mut w, quic_dial, "QUIC unreachable", 10);
    let tcp_conn = drain_actions(&mut w.agent)
        .iter()
        .find_map(|action| match action {
            Out::Dial {
                addr,
                conn: Some(conn),
                ..
            } if *addr == tcp => Some(*conn),
            _ => None,
        })
        .expect("A's TCP address is tried next");

    // Reached over TCP, A refuses: its addresses are spent, B is next.
    let (a, b) = (w.a.clone(), w.b.clone());
    hop_exchange(&mut w, &a, tcp_conn, Status::NoReservation, 20);
    let actions = drain_actions(&mut w.agent);
    assert_eq!(dial_count_for(&actions, &b), 1);
    assert!(!has_hop_open(&actions), "A is not asked again");
}

#[test]
fn a_relays_addresses_split_its_share_not_the_next_relays() {
    // A's second address is listed after B; it is still tried with A.
    let mut w = relays_with(|a, b| {
        vec![
            relay_addr("/ip4/203.0.113.1/udp/4001/quic-v1", a),
            relay_addr("/ip4/203.0.113.2/udp/4001/quic-v1", b),
            relay_addr("/ip4/203.0.113.1/tcp/4001", a),
        ]
    });
    let target = w.target.clone();
    let _ = start(&mut w.agent, 1, target, RELAY_NOW, at(0));
    drain_actions(&mut w.agent);

    // A never answers on either address; together they use A's half of the
    // 12 s leg, and B still gets the other half.
    w.agent.handle_tick(at(3_000));
    w.agent.handle_tick(at(5_999));
    assert_eq!(dial_count_for(&drain_actions(&mut w.agent), &w.b), 0);
    w.agent.handle_tick(at(6_000));
    assert_eq!(dial_count_for(&drain_actions(&mut w.agent), &w.b), 1);
    assert!(
        drain_events(&mut w.agent).is_empty(),
        "the leg is still live"
    );
}

#[test]
fn late_failure_of_a_relays_first_address_dials_its_next() {
    let mut w = relays_with(|a, b| {
        vec![
            relay_addr("/ip4/203.0.113.1/udp/4001/quic-v1", a),
            relay_addr("/ip4/203.0.113.1/tcp/4001", a),
            relay_addr("/ip4/203.0.113.2/udp/4001/quic-v1", b),
        ]
    });
    let tcp = relay_addr("/ip4/203.0.113.1/tcp/4001", &w.a);
    let target = w.target.clone();
    let _ = start(&mut w.agent, 1, target, RELAY_NOW, at(0));
    let quic_dial = dial_for(&drain_actions(&mut w.agent), &w.a);

    // The QUIC address's part (half of A's 6 s share) elapses with the dial
    // still in flight; the TCP entry waits on it rather than dialing A a
    // second time.
    w.agent.handle_tick(at(3_000));
    assert_eq!(dial_count_for(&drain_actions(&mut w.agent), &w.a), 0);

    dial_failed(&mut w, quic_dial, "QUIC gave up", 3_100);
    assert!(
        drain_actions(&mut w.agent)
            .iter()
            .any(|action| matches!(action, Out::Dial { addr, .. } if *addr == tcp)),
        "the TCP address is dialed, not skipped"
    );
    assert!(
        drain_events(&mut w.agent).is_empty(),
        "the leg is still live"
    );
}
