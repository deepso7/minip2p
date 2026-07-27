//! Host-multicast integration coverage for mDNS discovery.

#![cfg(feature = "mdns")]

use std::time::{Duration, Instant};

use minip2p::{Endpoint, PeerDiscoveryConfig};

fn endpoint() -> Endpoint {
    Endpoint::builder()
        .mdns()
        .peer_discovery_config(PeerDiscoveryConfig {
            dial_tie_break: true,
            ..PeerDiscoveryConfig::default()
        })
        .expect("valid shared discovery policy")
        .bind_quic("127.0.0.1:0")
        .expect("bind mDNS endpoint")
}

#[test]
#[ignore = "requires host multicast delivery on UDP 5353"]
fn two_endpoints_discover_and_connect_without_bootstrap() {
    let mut a = endpoint();
    let mut b = endpoint();
    a.listen().expect("a listens");
    b.listen().expect("b listens");
    let a_peer = a.peer_id().clone();
    let b_peer = b.peer_id().clone();

    let deadline = Instant::now() + Duration::from_secs(15);
    while !a.connected_peers().contains(&b_peer) || !b.connected_peers().contains(&a_peer) {
        assert!(Instant::now() < deadline, "mDNS discovery timed out");
        let _ = a
            .next_event(Duration::from_millis(20))
            .expect("drive endpoint a");
        let _ = b
            .next_event(Duration::from_millis(20))
            .expect("drive endpoint b");
    }

    assert!(a.known_peers().iter().any(|known| known.peer == b_peer));
    assert!(b.known_peers().iter().any(|known| known.peer == a_peer));
    a.shutdown().expect("a sends goodbyes");
    b.shutdown().expect("b sends goodbyes");
}
