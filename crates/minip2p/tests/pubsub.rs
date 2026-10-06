//! Loopback e2e for the `pubsub` feature: real QUIC endpoints exchanging
//! pubsub RPCs. Agent-level edge cases live in `crates/pubsub/tests`; these
//! prove gossipsub endpoint wiring.

#![cfg(all(feature = "pubsub", feature = "std"))]

use std::time::{Duration, Instant};

use minip2p::{
    Endpoint, EndpointEvent, GossipsubConfig, GossipsubError, GossipsubEvent, TransportError,
};

#[path = "../../../tests/support/endpoint.rs"]
mod endpoint_support;
use endpoint_support::NextEvent;

const TOPIC: &str = "loopback-chat";

fn pubsub_endpoint() -> Endpoint {
    Endpoint::builder()
        .gossipsub()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint")
}

fn is_gossipsub_protocol(protocol_id: &str) -> bool {
    minip2p::GOSSIPSUB_PROTOCOL_IDS.contains(&protocol_id)
}

/// Drives all endpoints once with a short budget, collecting pubsub events
/// and asserting no pubsub stream events leak to the application.
fn drive(endpoints: &mut [&mut Endpoint]) -> Vec<Vec<GossipsubEvent>> {
    let mut collected = vec![Vec::new(); endpoints.len()];
    for (endpoint, events) in endpoints.iter_mut().zip(&mut collected) {
        match endpoint
            .next_event(Duration::from_millis(20))
            .expect("endpoint drives")
        {
            Some(EndpointEvent::Gossipsub(event)) => events.push(event),
            Some(event) => assert!(
                !matches!(
                    &event,
                    EndpointEvent::StreamReady { protocol_id, .. }
                        if is_gossipsub_protocol(protocol_id)
                ),
                "pubsub streams must be invisible to the app: {event:?}"
            ),
            None => {}
        }
    }
    collected
}

/// Waits until `condition` returns true while driving all endpoints,
/// accumulating everyone's pubsub events.
fn drive_until(
    endpoints: &mut [&mut Endpoint],
    deadline: Duration,
    mut condition: impl FnMut(&[Vec<GossipsubEvent>]) -> bool,
) -> Vec<Vec<GossipsubEvent>> {
    let mut all: Vec<Vec<GossipsubEvent>> = vec![Vec::new(); endpoints.len()];
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

fn saw_message(events: &[GossipsubEvent], data: &[u8]) -> bool {
    events
        .iter()
        .any(|e| matches!(e, GossipsubEvent::Message { data: got, .. } if got.as_slice() == data))
}

fn saw_subscription(events: &[GossipsubEvent], topic: &str) -> bool {
    events
        .iter()
        .any(|e| matches!(e, GossipsubEvent::PeerSubscribed { topic: got, .. } if got == topic))
}

#[test]
fn two_endpoints_exchange_messages_over_real_quic() {
    let mut a = pubsub_endpoint();
    let mut b = pubsub_endpoint();
    let b_addr = b.listen().expect("b listens");
    a.listen().expect("a listens");

    a.subscribe(TOPIC).expect("a subscribes");
    b.subscribe(TOPIC).expect("b subscribes");
    a.connect(&b_addr).expect("a connects to b");

    // Both sides learn of each other's subscription first.
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
    alice.connect(&hub_addr).expect("alice connects to hub");
    bob.connect(&hub_addr).expect("bob connects to hub");

    // The hub must know both leaves' subscriptions, and each leaf the
    // hub's, before a publish can traverse the star.
    drive_until(
        &mut [&mut hub, &mut alice, &mut bob],
        Duration::from_secs(20),
        |all| {
            all[0]
                .iter()
                .filter(|e| matches!(e, GossipsubEvent::PeerSubscribed { .. }))
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
        .filter(|e| matches!(e, GossipsubEvent::Message { data, .. } if data.as_slice() == b"across the star"))
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
    a.connect(&b_addr).expect("a connects to b");
    drive_until(&mut [&mut a, &mut b], Duration::from_secs(15), |all| {
        saw_subscription(&all[0], TOPIC) && saw_subscription(&all[1], TOPIC)
    });

    // B withdraws; A must observe it and stop sending.
    assert!(b.unsubscribe(TOPIC).expect("unsubscribe"));
    drive_until(&mut [&mut a, &mut b], Duration::from_secs(15), |all| {
        all[0]
            .iter()
            .any(|e| matches!(e, GossipsubEvent::PeerUnsubscribed { topic, .. } if topic == TOPIC))
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
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");
    assert!(matches!(
        plain.subscribe(TOPIC),
        Err(GossipsubError::NotEnabled)
    ));
    assert!(matches!(
        plain.publish(TOPIC, b"x".to_vec()),
        Err(GossipsubError::NotEnabled)
    ));
}

#[test]
fn invalid_gossipsub_config_fails_before_transport_bind() {
    let error = Endpoint::builder()
        .gossipsub_config(GossipsubConfig {
            heartbeat_interval_ms: 0,
            ..GossipsubConfig::default()
        })
        // TEST-NET-1 is never a local address, so this bind would fail.
        .listen_on("/ip4/192.0.2.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .err()
        .expect("invalid pubsub config");
    assert!(matches!(
        error,
        minip2p::Error::Transport(TransportError::InvalidConfig { ref reason })
            if reason.contains("heartbeat_interval_ms")
    ));
}
