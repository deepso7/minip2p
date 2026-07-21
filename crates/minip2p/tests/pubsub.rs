//! Loopback e2e for the `pubsub` feature: real QUIC endpoints exchanging
//! floodsub RPCs. Agent-level edge cases live in `crates/pubsub/tests`;
//! these prove the facade wiring (driver, event interception, API).

#![cfg(feature = "pubsub")]

use std::time::{Duration, Instant};

use minip2p::{Endpoint, Event, PubsubError, PubsubEvent};

#[cfg(feature = "nat")]
#[path = "../../../tests/support/relay.rs"]
mod relay_support;

const TOPIC: &str = "loopback-chat";

fn pubsub_endpoint() -> Endpoint {
    Endpoint::builder()
        .pubsub()
        .bind_quic("127.0.0.1:0")
        .expect("bind loopback endpoint")
}

/// Drives all endpoints once with a short budget, collecting pubsub events
/// and asserting no floodsub stream events leak to the application.
fn drive(endpoints: &mut [&mut Endpoint]) -> Vec<Vec<PubsubEvent>> {
    let mut collected = vec![Vec::new(); endpoints.len()];
    for (i, endpoint) in endpoints.iter_mut().enumerate() {
        if let Some(event) = endpoint
            .next_event(Duration::from_millis(20))
            .expect("endpoint drives")
        {
            assert!(
                !matches!(
                    &event,
                    Event::StreamReady { protocol_id, .. }
                        if protocol_id == minip2p::FLOODSUB_PROTOCOL_ID
                ),
                "floodsub streams must be invisible to the app: {event:?}"
            );
        }
        collected[i].extend(endpoint.take_pubsub_events());
    }
    collected
}

/// Waits until `condition` returns true while driving all endpoints,
/// accumulating everyone's pubsub events.
fn drive_until(
    endpoints: &mut [&mut Endpoint],
    deadline: Duration,
    mut condition: impl FnMut(&[Vec<PubsubEvent>]) -> bool,
) -> Vec<Vec<PubsubEvent>> {
    let mut all: Vec<Vec<PubsubEvent>> = vec![Vec::new(); endpoints.len()];
    let until = Instant::now() + deadline;
    while !condition(&all) {
        assert!(Instant::now() < until, "condition not met in time: {all:?}");
        let step = drive(endpoints);
        for (acc, new) in all.iter_mut().zip(step) {
            acc.extend(new);
        }
    }
    all
}

fn saw_message(events: &[PubsubEvent], data: &[u8]) -> bool {
    events
        .iter()
        .any(|e| matches!(e, PubsubEvent::Message { data: got, .. } if got.as_slice() == data))
}

fn saw_subscription(events: &[PubsubEvent], topic: &str) -> bool {
    events
        .iter()
        .any(|e| matches!(e, PubsubEvent::PeerSubscribed { topic: got, .. } if got == topic))
}

#[test]
fn two_endpoints_exchange_messages_over_real_quic() {
    let mut a = pubsub_endpoint();
    let mut b = pubsub_endpoint();
    let b_addr = b.listen().expect("b listens");
    a.listen().expect("a listens");

    a.subscribe(TOPIC).expect("a subscribes");
    b.subscribe(TOPIC).expect("b subscribes");
    a.dial(&b_addr).expect("a dials b");

    // Both sides learn of each other's subscription first (floodsub has no
    // history: publishing before that would vanish).
    drive_until(&mut [&mut a, &mut b], Duration::from_secs(15), |all| {
        saw_subscription(&all[0], TOPIC) && saw_subscription(&all[1], TOPIC)
    });

    a.publish(TOPIC, b"a to b").expect("a publishes");
    let all = drive_until(&mut [&mut a, &mut b], Duration::from_secs(15), |all| {
        saw_message(&all[1], b"a to b")
    });
    assert!(
        !saw_message(&all[0], b"a to b"),
        "no self-delivery: {all:?}"
    );

    b.publish(TOPIC, b"b to a").expect("b publishes");
    drive_until(&mut [&mut a, &mut b], Duration::from_secs(15), |all| {
        saw_message(&all[0], b"b to a")
    });
}

#[test]
fn star_center_forwards_between_leaves() {
    let mut hub = pubsub_endpoint();
    let mut alice = pubsub_endpoint();
    let mut bob = pubsub_endpoint();
    let hub_addr = hub.listen().expect("hub listens");
    alice.listen().expect("alice listens");
    bob.listen().expect("bob listens");

    hub.subscribe(TOPIC).expect("hub subscribes");
    alice.subscribe(TOPIC).expect("alice subscribes");
    bob.subscribe(TOPIC).expect("bob subscribes");
    alice.dial(&hub_addr).expect("alice dials hub");
    bob.dial(&hub_addr).expect("bob dials hub");

    // The hub must know both leaves' subscriptions, and each leaf the
    // hub's, before a publish can traverse the star.
    drive_until(
        &mut [&mut hub, &mut alice, &mut bob],
        Duration::from_secs(20),
        |all| {
            all[0]
                .iter()
                .filter(|e| matches!(e, PubsubEvent::PeerSubscribed { .. }))
                .count()
                >= 2
                && saw_subscription(&all[1], TOPIC)
                && saw_subscription(&all[2], TOPIC)
        },
    );

    // Alice's message reaches bob THROUGH the hub (they are not connected),
    // and the hub delivers it locally too. Exactly once each.
    alice.publish(TOPIC, b"across the star").expect("publishes");
    let all = drive_until(
        &mut [&mut hub, &mut alice, &mut bob],
        Duration::from_secs(20),
        |all| saw_message(&all[0], b"across the star") && saw_message(&all[2], b"across the star"),
    );
    let bob_copies = all[2]
        .iter()
        .filter(|e| matches!(e, PubsubEvent::Message { data, .. } if data.as_slice() == b"across the star"))
        .count();
    assert_eq!(bob_copies, 1, "seen-cache dedup: {all:?}");
    assert!(
        !saw_message(&all[1], b"across the star"),
        "no self-delivery"
    );
}

#[test]
fn unsubscribe_stops_delivery() {
    let mut a = pubsub_endpoint();
    let mut b = pubsub_endpoint();
    let b_addr = b.listen().expect("b listens");
    a.listen().expect("a listens");

    a.subscribe(TOPIC).expect("a subscribes");
    b.subscribe(TOPIC).expect("b subscribes");
    a.dial(&b_addr).expect("a dials b");
    drive_until(&mut [&mut a, &mut b], Duration::from_secs(15), |all| {
        saw_subscription(&all[0], TOPIC) && saw_subscription(&all[1], TOPIC)
    });

    // B withdraws; A must observe it and stop sending.
    assert!(b.unsubscribe(TOPIC).expect("unsubscribe"));
    drive_until(&mut [&mut a, &mut b], Duration::from_secs(15), |all| {
        all[0]
            .iter()
            .any(|e| matches!(e, PubsubEvent::PeerUnsubscribed { topic, .. } if topic == TOPIC))
    });

    a.publish(TOPIC, b"into the void")
        .expect("publish succeeds");
    // Drive for a while: nothing may arrive at B.
    let until = Instant::now() + Duration::from_secs(2);
    while Instant::now() < until {
        let all = drive(&mut [&mut a, &mut b]);
        assert!(
            !saw_message(&all[1], b"into the void"),
            "B unsubscribed and must not receive"
        );
    }
}

#[test]
fn pubsub_methods_error_when_not_enabled() {
    let mut plain = Endpoint::builder()
        .bind_quic("127.0.0.1:0")
        .expect("bind loopback endpoint");
    assert!(matches!(
        plain.subscribe(TOPIC),
        Err(PubsubError::NotEnabled)
    ));
    assert!(matches!(
        plain.publish(TOPIC, b"x".to_vec()),
        Err(PubsubError::NotEnabled)
    ));
    assert!(matches!(
        plain.next_pubsub_event(Duration::from_millis(1)),
        Err(PubsubError::NotEnabled)
    ));
    assert!(plain.take_pubsub_events().is_empty());
}

#[test]
fn next_pubsub_event_buffers_application_events() {
    let mut a = pubsub_endpoint();
    let mut b = pubsub_endpoint();
    let b_addr = b.listen().expect("b listens");
    a.listen().expect("a listens");

    a.subscribe(TOPIC).expect("a subscribes");
    b.subscribe(TOPIC).expect("b subscribes");
    a.dial(&b_addr).expect("a dials b");

    // Drive B in the background-ish loop while A waits specifically for a
    // pubsub event; A's connection events must survive into next_event.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut got = None;
    while got.is_none() {
        assert!(Instant::now() < deadline, "no pubsub event in time");
        got = a
            .next_pubsub_event(Duration::from_millis(20))
            .expect("a waits");
        let _ = b.next_event(Duration::from_millis(20)).expect("b drives");
    }
    assert!(matches!(got, Some(PubsubEvent::PeerSubscribed { .. })));

    // The ConnectionEstablished that arrived during the focused wait was
    // buffered, not dropped.
    let mut saw_connect = false;
    let drain_deadline = Instant::now() + Duration::from_secs(5);
    while !saw_connect && Instant::now() < drain_deadline {
        if let Some(event) = a
            .next_event(Duration::from_millis(20))
            .expect("a drains buffered events")
        {
            saw_connect |= matches!(event, Event::ConnectionEstablished { .. });
        }
    }
    assert!(saw_connect, "application events must be buffered, not lost");
}

#[cfg(feature = "nat")]
#[test]
fn pubsub_flows_over_relay_and_reannounces_after_direct_supersede() {
    use minip2p::{NatConfig, NatEvent, Path, ReservationPolicy};

    let relay = relay_support::RelayServer::spawn();
    let relay_addr = relay.addr().clone();
    let mut b = Endpoint::builder()
        .pubsub()
        .relay(relay_addr.clone())
        .nat_config(NatConfig {
            force_relay: true,
            reservation_policy: ReservationPolicy::Always,
            ..NatConfig::default()
        })
        .bind_quic("127.0.0.1:0")
        .expect("bind responder");
    let b_addr = b.listen().expect("responder listens");
    let b_peer = b.peer_id().clone();
    b.subscribe(TOPIC).expect("responder subscribes");

    let reserve_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(Instant::now() < reserve_deadline, "reservation timed out");
        let _ = b
            .next_event(Duration::from_millis(20))
            .expect("drive reservation");
        if b.take_nat_events().iter().any(
            |event| matches!(event, NatEvent::RelayReserved { relay, .. } if relay == relay_addr.peer_id()),
        ) {
            break;
        }
        relay.assert_healthy();
    }

    let mut a = Endpoint::builder()
        .pubsub()
        .relay(relay_addr)
        .nat_config(NatConfig {
            force_relay: true,
            reservation_policy: ReservationPolicy::Never,
            ..NatConfig::default()
        })
        .bind_quic("127.0.0.1:0")
        .expect("bind initiator");
    a.listen().expect("initiator listens");
    a.subscribe(TOPIC).expect("initiator subscribes");
    let connect_id = a.connect(&b_peer).expect("relay-only connect");

    drive_until(&mut [&mut a, &mut b], Duration::from_secs(15), |all| {
        saw_subscription(&all[0], TOPIC) && saw_subscription(&all[1], TOPIC)
    });
    let nat = a.take_nat_events();
    assert!(nat.iter().any(|event| matches!(
        event,
        NatEvent::PathEstablished {
            connect_id: found,
            peer,
            path: Path::Relayed { relay: found_relay },
        } if *found == connect_id && peer == &b_peer && found_relay == relay.addr().peer_id()
    )));
    let circuit_id = *a
        .swarm()
        .transport()
        .circuit_ids()
        .first()
        .expect("active circuit");

    a.publish(TOPIC, b"over relay").expect("publish over relay");
    drive_until(&mut [&mut a, &mut b], Duration::from_secs(10), |all| {
        saw_message(&all[1], b"over relay")
    });

    // A direct connection supersedes the ready circuit. The public sequence
    // must close the old id before establishing the replacement, and the
    // floodsub driver must re-open and re-announce subscriptions.
    a.dial(&b_addr).expect("manual direct upgrade");
    let upgrade_deadline = Instant::now() + Duration::from_secs(15);
    let mut a_sequence = Vec::new();
    let mut a_resubscribed = false;
    let mut b_resubscribed = false;
    while !a_resubscribed || !b_resubscribed {
        assert!(
            Instant::now() < upgrade_deadline,
            "pubsub did not recover after supersede: {a_sequence:?}"
        );
        if let Some(event) = a
            .next_event(Duration::from_millis(20))
            .expect("drive initiator upgrade")
        {
            match event {
                Event::ConnectionClosed { peer_id, conn_id } if peer_id == b_peer => {
                    a_sequence.push(("closed", conn_id));
                }
                Event::ConnectionEstablished { peer_id, conn_id } if peer_id == b_peer => {
                    a_sequence.push(("established", conn_id));
                }
                _ => {}
            }
        }
        let _ = b
            .next_event(Duration::from_millis(20))
            .expect("drive responder upgrade");
        a_resubscribed |= a.take_pubsub_events().iter().any(
            |event| matches!(event, PubsubEvent::PeerSubscribed { topic, .. } if topic == TOPIC),
        );
        b_resubscribed |= b.take_pubsub_events().iter().any(
            |event| matches!(event, PubsubEvent::PeerSubscribed { topic, .. } if topic == TOPIC),
        );
        relay.assert_healthy();
    }
    assert!(
        matches!(
            a_sequence.as_slice(),
            [("closed", closed), ("established", direct), ..]
                if *closed == circuit_id && direct.as_u64() & (1 << 63) == 0
        ),
        "supersede ordering: {a_sequence:?}"
    );
    assert!(a.swarm().transport().circuit_ids().is_empty());
    a.publish(TOPIC, b"after upgrade")
        .expect("publish after upgrade");
    drive_until(&mut [&mut a, &mut b], Duration::from_secs(10), |all| {
        saw_message(&all[1], b"after upgrade")
    });
}
