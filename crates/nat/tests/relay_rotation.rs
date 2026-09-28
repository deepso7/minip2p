//! Relay-leg rotation: one connect attempt tries each configured relay in
//! turn, each within its share of the relay-leg deadline.

mod common;

use common::*;

use minip2p_core::{PeerAddr, PeerId};
use minip2p_nat::{
    ConnectLegs, NatAction, NatAgent, NatConfig, NatError, NatEvent, Path, PromoteError,
    ReservationPolicy,
};
use minip2p_relay::{HOP_PROTOCOL_ID, Status};
use minip2p_swarm::{ConnectionCloseCause, SwarmEvent};
use minip2p_transport::{ConnectionId, StreamId};

struct World {
    agent: NatAgent,
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
    let mut agent = NatAgent::new(peer(b"local-peer"), config);
    agent.set_listen_addrs(&[maddr(LISTEN_ADDR)]);
    World {
        agent,
        target: peer(b"target-peer"),
        a,
        b,
    }
}

/// Connects `relay` on `conn`, completes identify, and runs the HOP CONNECT
/// exchange up to the relay's STATUS reply. Returns the HOP stream.
fn hop_exchange(w: &mut World, relay: &PeerId, conn: u64, status: Status, now: u64) -> StreamId {
    let conn_id = ConnectionId::new(conn);
    w.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            peer_id: relay.clone(),
            conn_id,
        },
        at(now),
    );
    w.agent.handle_event(
        &SwarmEvent::PeerReady {
            peer_id: relay.clone(),
            protocols: vec![HOP_PROTOCOL_ID.to_string()],
        },
        at(now),
    );
    let token = open_stream_token_for(&drain_actions(&mut w.agent), relay);
    let stream = StreamId::new(conn * 10);
    w.agent.stream_open_result(token, Ok(stream), at(now));
    w.agent.handle_event(
        &SwarmEvent::StreamReady {
            conn_id,
            peer_id: relay.clone(),
            stream_id: stream,
            protocol_id: HOP_PROTOCOL_ID.to_string(),
            initiated_locally: true,
        },
        at(now),
    );
    drain_actions(&mut w.agent);
    w.agent.handle_event(
        &SwarmEvent::StreamData {
            conn_id,
            peer_id: relay.clone(),
            stream_id: stream,
            data: hop_status(status),
        },
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
            NatAction::PromoteBridge { relay: r, .. } if r == relay
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
    assert_eq!(dial_count_for(&drain_actions(&mut w.agent), &w.b), 1);
    assert!(
        drain_events(&mut w.agent).is_empty(),
        "the leg is still live"
    );

    let b = w.b.clone();
    hop_exchange(&mut w, &b, 3, Status::Ok, 6_500);
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
    hop_exchange(&mut w, &b, 3, Status::NoReservation, 10);
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
    let a_token = dial_token_for(&drain_actions(&mut w.agent), &w.a);
    w.agent.handle_tick(at(6_000));
    assert_eq!(dial_count_for(&drain_actions(&mut w.agent), &w.b), 1);

    w.agent
        .dial_result(a_token, Err("relay A finally gave up".into()), at(6_100));
    assert!(
        drain_events(&mut w.agent).is_empty(),
        "B's leg is untouched"
    );

    let b = w.b.clone();
    hop_exchange(&mut w, &b, 3, Status::Ok, 6_200);
    assert_relayed_via(&mut w, &b, 6_201);
}

#[test]
fn no_reservation_at_first_relay_moves_to_the_next() {
    let mut w = two_relays();
    let target = w.target.clone();
    let _ = start(&mut w.agent, 1, target, RELAY_NOW, at(0));
    drain_actions(&mut w.agent);

    let (a, b) = (w.a.clone(), w.b.clone());
    let refused = hop_exchange(&mut w, &a, 2, Status::NoReservation, 10);
    let actions = drain_actions(&mut w.agent);
    assert!(has_reset_for(&actions, refused), "A's HOP stream is reset");
    assert_eq!(dial_count_for(&actions, &b), 1, "B is tried next");
    assert!(
        drain_events(&mut w.agent).is_empty(),
        "the leg is still live"
    );

    hop_exchange(&mut w, &b, 3, Status::Ok, 20);
    assert_relayed_via(&mut w, &b, 21);
}

#[test]
fn leg_fails_with_the_last_relays_error_after_trying_all() {
    let mut w = two_relays();
    let target = w.target.clone();
    let _ = start(&mut w.agent, 1, target, RELAY_NOW, at(0));
    let token = dial_token_for(&drain_actions(&mut w.agent), &w.a);
    w.agent
        .dial_result(token, Err("relay A unreachable".into()), at(10));
    assert!(
        drain_events(&mut w.agent).is_empty(),
        "B has not been tried yet"
    );
    assert_eq!(dial_count_for(&drain_actions(&mut w.agent), &w.b), 1);

    let b = w.b.clone();
    hop_exchange(&mut w, &b, 3, Status::NoReservation, 20);
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
    drain_actions(&mut w.agent);

    let (a, b) = (w.a.clone(), w.b.clone());
    hop_exchange(&mut w, &a, 2, Status::Ok, 10);
    let token = promote_token(&drain_actions(&mut w.agent));
    w.agent.promote_result(
        token,
        Err(PromoteError::Failed("secure-mux handshake failed".into())),
        at(20),
    );
    assert_eq!(dial_count_for(&drain_actions(&mut w.agent), &b), 1);
    assert!(
        drain_events(&mut w.agent).is_empty(),
        "the leg is still live"
    );

    hop_exchange(&mut w, &b, 3, Status::Ok, 30);
    assert_relayed_via(&mut w, &b, 31);
}

#[test]
fn circuit_closing_before_it_establishes_moves_to_the_next_relay() {
    let mut w = two_relays();
    let target = w.target.clone();
    let _ = start(&mut w.agent, 1, target.clone(), RELAY_NOW, at(0));
    drain_actions(&mut w.agent);

    let (a, b) = (w.a.clone(), w.b.clone());
    hop_exchange(&mut w, &a, 2, Status::Ok, 10);
    let token = promote_token(&drain_actions(&mut w.agent));
    let circuit = ConnectionId::new(TEST_CIRCUIT_ID);
    w.agent.promote_result(token, Ok(circuit), at(20));
    w.agent.handle_event(
        &SwarmEvent::ConnectionClosed {
            peer_id: target,
            conn_id: circuit,
            cause: ConnectionCloseCause::Transport,
        },
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
    let token = dial_token_for(&drain_actions(&mut w.agent), &w.a);
    w.agent
        .dial_result(token, Err("QUIC unreachable".into()), at(10));
    assert!(
        drain_actions(&mut w.agent)
            .iter()
            .any(|action| matches!(action, NatAction::Dial { addr, .. } if *addr == tcp)),
        "A's TCP address is tried next"
    );

    // Reached over TCP, A refuses: its addresses are spent, B is next.
    let (a, b) = (w.a.clone(), w.b.clone());
    hop_exchange(&mut w, &a, 2, Status::NoReservation, 20);
    let actions = drain_actions(&mut w.agent);
    assert_eq!(dial_count_for(&actions, &b), 1);
    assert!(!has_hop_open(&actions), "A is not asked again");
}
