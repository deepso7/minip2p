//! Loopback endpoint coverage for pubsub peer discovery.

#![cfg(feature = "discovery")]

use std::time::{Duration, Instant};

use minip2p::{
    BeaconConfig, ConnectOutcome, DiscoveryEvent, Endpoint, Event, GossipsubConfig, GossipsubEvent,
    PeerDiscoveryConfig,
};

const DISCOVERY_TOPIC: &str = "/minip2p/test/loopback-discovery";

fn discovery_endpoint() -> Endpoint {
    Endpoint::builder()
        .discovery_config(BeaconConfig {
            topic: DISCOVERY_TOPIC.into(),
            beacon_interval_ms: 100,
            ..BeaconConfig::default()
        })
        .expect("valid discovery config")
        .peer_discovery_config(PeerDiscoveryConfig {
            beacon_peer_ttl_ms: 2_000,
            auto_dial: false,
            ..PeerDiscoveryConfig::default()
        })
        .expect("valid peer discovery config")
        .bind_quic("127.0.0.1:0")
        .expect("bind loopback endpoint")
}

fn slow_heartbeat_discovery_endpoint() -> Endpoint {
    Endpoint::builder()
        .gossipsub_config(GossipsubConfig {
            heartbeat_interval_ms: 60_000,
            ..GossipsubConfig::default()
        })
        .discovery_config(BeaconConfig {
            topic: DISCOVERY_TOPIC.into(),
            beacon_interval_ms: 100,
            ..BeaconConfig::default()
        })
        .expect("valid discovery config")
        .peer_discovery_config(PeerDiscoveryConfig {
            beacon_peer_ttl_ms: 2_000,
            auto_dial: false,
            ..PeerDiscoveryConfig::default()
        })
        .expect("valid peer discovery config")
        .bind_quic("127.0.0.1:0")
        .expect("bind loopback endpoint")
}

/// Fails if an Endpoint event carries discovery-owned beacon-topic traffic.
fn assert_no_discovery_gossipsub(event: Option<Event>) {
    let Some(Event::Gossipsub(event)) = event else {
        return;
    };
    let leaked = match &event {
        GossipsubEvent::Message { topics, .. } => {
            topics.iter().any(|topic| topic == DISCOVERY_TOPIC)
        }
        GossipsubEvent::PeerSubscribed { topic, .. }
        | GossipsubEvent::PeerUnsubscribed { topic, .. } => topic == DISCOVERY_TOPIC,
        _ => false,
    };
    assert!(!leaked, "discovery pubsub event leaked: {event:?}");
}

/// Checks every event still queued on `endpoint` for beacon-topic leaks.
fn assert_queue_has_no_discovery_gossipsub(endpoint: &mut Endpoint) {
    while let Some(event) = endpoint
        .next_event(Duration::ZERO)
        .expect("drain queued events")
    {
        assert_no_discovery_gossipsub(Some(event));
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
        assert_no_discovery_gossipsub(a.next_event(Duration::from_millis(20)).expect("a drives"));
        assert_no_discovery_gossipsub(b.next_event(Duration::from_millis(20)).expect("b drives"));
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
    assert_queue_has_no_discovery_gossipsub(&mut a);
    assert_queue_has_no_discovery_gossipsub(&mut b);
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
        assert_no_discovery_gossipsub(
            hub.next_event(Duration::from_millis(20))
                .expect("hub drives"),
        );
        assert_no_discovery_gossipsub(a.next_event(Duration::from_millis(20)).expect("a drives"));
        assert_no_discovery_gossipsub(b.next_event(Duration::from_millis(20)).expect("b drives"));
    }

    assert_eq!(a.connected_peers(), vec![hub_peer.clone()]);
    assert_eq!(b.connected_peers(), vec![hub_peer]);
    assert_queue_has_no_discovery_gossipsub(&mut hub);
    assert_queue_has_no_discovery_gossipsub(&mut a);
    assert_queue_has_no_discovery_gossipsub(&mut b);
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

#[test]
fn connect_uses_known_discovery_book_addresses() {
    let mut hub = slow_heartbeat_discovery_endpoint();
    let mut a = slow_heartbeat_discovery_endpoint();
    let mut b = slow_heartbeat_discovery_endpoint();
    let hub_addr = hub.listen().expect("hub listens");
    a.listen().expect("a listens");
    b.listen().expect("b listens");
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
            "cross-leaf discovery timed out before connect"
        );
        let _ = hub
            .next_event(Duration::from_millis(20))
            .expect("hub drives");
        let _ = a.next_event(Duration::from_millis(20)).expect("a drives");
        let _ = b.next_event(Duration::from_millis(20)).expect("b drives");
    }

    assert!(
        !a.connected_peers().contains(&b_peer),
        "a must not already have a direct connection to b"
    );
    let id = a.connect(&b_peer).expect("connect by peer id");
    let connect_deadline = Instant::now() + Duration::from_secs(15);
    let mut settled = None;
    while settled.is_none() {
        assert!(
            Instant::now() < connect_deadline,
            "connect via discovery book timed out"
        );
        if let Some(Event::ConnectSettled {
            connect_id,
            outcome,
            ..
        }) = a.next_event(Duration::from_millis(20)).expect("a drives")
            && connect_id == id
        {
            settled = Some(outcome);
        }
        let _ = hub
            .next_event(Duration::from_millis(20))
            .expect("hub drives");
        let _ = b.next_event(Duration::from_millis(20)).expect("b drives");
    }
    assert!(
        matches!(settled, Some(ConnectOutcome::Connected { .. })),
        "expected Connected via book addresses, got {settled:?}"
    );
    assert!(a.connected_peers().contains(&b_peer));
}
