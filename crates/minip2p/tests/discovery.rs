//! Loopback facade coverage for pubsub peer discovery.

#![cfg(feature = "discovery")]

use std::time::{Duration, Instant};

use minip2p::{DiscoveryConfig, DiscoveryEvent, Endpoint, Event, GossipsubConfig, PubsubEvent};

const DISCOVERY_TOPIC: &str = "/minip2p/test/loopback-discovery";

fn discovery_endpoint() -> Endpoint {
    Endpoint::builder()
        .discovery_config(DiscoveryConfig {
            topic: DISCOVERY_TOPIC.into(),
            beacon_interval_ms: 100,
            peer_ttl_ms: 2_000,
            auto_dial: false,
            ..DiscoveryConfig::default()
        })
        .expect("valid discovery config")
        .bind_quic("127.0.0.1:0")
        .expect("bind loopback endpoint")
}

fn slow_heartbeat_discovery_endpoint() -> Endpoint {
    Endpoint::builder()
        .pubsub_config(GossipsubConfig {
            heartbeat_interval_ms: 60_000,
            ..GossipsubConfig::default()
        })
        .discovery_config(DiscoveryConfig {
            topic: DISCOVERY_TOPIC.into(),
            beacon_interval_ms: 100,
            peer_ttl_ms: 2_000,
            auto_dial: false,
            ..DiscoveryConfig::default()
        })
        .expect("valid discovery config")
        .bind_quic("127.0.0.1:0")
        .expect("bind loopback endpoint")
}

fn assert_no_discovery_pubsub(events: Vec<PubsubEvent>) {
    for event in events {
        let leaked = match &event {
            PubsubEvent::Message { topics, .. } => {
                topics.iter().any(|topic| topic == DISCOVERY_TOPIC)
            }
            PubsubEvent::PeerSubscribed { topic, .. }
            | PubsubEvent::PeerUnsubscribed { topic, .. } => topic == DISCOVERY_TOPIC,
            _ => false,
        };
        assert!(!leaked, "discovery pubsub event leaked: {event:?}");
    }
}

#[test]
fn beacons_do_not_leak_to_the_application() {
    let mut a = discovery_endpoint();
    let mut b = discovery_endpoint();
    let a_addr = a.listen().expect("a listens");
    let b_addr = b.listen().expect("b listens");
    let a_peer = a.peer_id().clone();
    let b_peer = b.peer_id().clone();
    a.dial(&b_addr).expect("a dials b");

    let deadline = Instant::now() + Duration::from_secs(15);
    while a.known_peers().iter().all(|known| known.peer != b_peer)
        || b.known_peers().iter().all(|known| known.peer != a_peer)
    {
        assert!(Instant::now() < deadline, "discovery timed out");
        let _ = a.next_event(Duration::from_millis(20)).expect("a drives");
        let _ = b.next_event(Duration::from_millis(20)).expect("b drives");
        assert_no_discovery_pubsub(a.take_pubsub_events());
        assert_no_discovery_pubsub(b.take_pubsub_events());
    }

    let a_seen_by_b = b
        .known_peers()
        .into_iter()
        .find(|known| known.peer == a_peer)
        .expect("b knows a");
    let b_seen_by_a = a
        .known_peers()
        .into_iter()
        .find(|known| known.peer == b_peer)
        .expect("a knows b");
    assert!(a_seen_by_b.addrs.contains(a_addr.transport()));
    assert!(b_seen_by_a.addrs.contains(b_addr.transport()));
    assert_no_discovery_pubsub(a.take_pubsub_events());
    assert_no_discovery_pubsub(b.take_pubsub_events());
}

#[test]
fn star_beacons_relay_before_the_first_gossipsub_heartbeat() {
    let mut hub = slow_heartbeat_discovery_endpoint();
    let mut a = slow_heartbeat_discovery_endpoint();
    let mut b = slow_heartbeat_discovery_endpoint();
    let hub_addr = hub.listen().expect("hub listens");
    a.listen().expect("a listens");
    b.listen().expect("b listens");
    let hub_peer = hub.peer_id().clone();
    let a_peer = a.peer_id().clone();
    let b_peer = b.peer_id().clone();
    a.dial(&hub_addr).expect("a dials hub");
    b.dial(&hub_addr).expect("b dials hub");

    let deadline = Instant::now() + Duration::from_secs(15);
    while a.known_peers().iter().all(|known| known.peer != b_peer)
        || b.known_peers().iter().all(|known| known.peer != a_peer)
    {
        assert!(
            Instant::now() < deadline,
            "cross-leaf discovery waited for a 60s heartbeat"
        );
        let _ = hub
            .next_event(Duration::from_millis(20))
            .expect("hub drives");
        let _ = a.next_event(Duration::from_millis(20)).expect("a drives");
        let _ = b.next_event(Duration::from_millis(20)).expect("b drives");
    }

    assert_eq!(a.connected_peers(), vec![hub_peer.clone()]);
    assert_eq!(b.connected_peers(), vec![hub_peer]);
    assert_no_discovery_pubsub(hub.take_pubsub_events());
    assert_no_discovery_pubsub(a.take_pubsub_events());
    assert_no_discovery_pubsub(b.take_pubsub_events());
}

#[test]
fn next_discovery_event_buffers_application_events() {
    let mut a = discovery_endpoint();
    let mut b = discovery_endpoint();
    a.listen().expect("a listens");
    let b_addr = b.listen().expect("b listens");
    let b_peer = b.peer_id().clone();
    a.dial(&b_addr).expect("a dials b");

    let deadline = Instant::now() + Duration::from_secs(15);
    let discovered = loop {
        assert!(Instant::now() < deadline, "discovery event timed out");
        if let Some(event) = a
            .next_discovery_event(Duration::from_millis(20))
            .expect("focused discovery wait")
        {
            break event;
        }
        let _ = b.next_event(Duration::from_millis(20)).expect("b drives");
    };
    assert!(matches!(
        discovered,
        DiscoveryEvent::PeerDiscovered { peer, .. } if peer == b_peer
    ));

    let drain_deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_connection = false;
    while !saw_connection && Instant::now() < drain_deadline {
        if let Some(event) = a
            .next_event(Duration::from_millis(20))
            .expect("drain buffered application event")
        {
            saw_connection = matches!(event, Event::ConnectionEstablished { .. });
        }
        let _ = b.next_event(Duration::from_millis(20)).expect("b drives");
    }
    assert!(
        saw_connection,
        "focused wait must preserve connection events"
    );
}
