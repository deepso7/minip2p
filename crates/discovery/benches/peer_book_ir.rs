use gungraun::prelude::*;
use minip2p_core::platform::Now;
use minip2p_core::{Multiaddr, PeerId};
use minip2p_discovery::{DiscoveryEvent, Observation, PeerDiscoveryAgent, PeerDiscoveryConfig};
use minip2p_identity::{KeyType, PublicKey};
use std::hint::black_box;

const PEERS: usize = 128;
const ADDRS_PER_PEER: usize = 16;
/// Peers whose sources fall due in the sparse-expiry bench.
const SPARSE_DUE: usize = 4;
const BEACON_TTL_MS: u64 = 1_000;
const MDNS_TTL_MS: u64 = 60_000;

fn peer(index: usize) -> PeerId {
    PeerId::from_public_key(&PublicKey::new(KeyType::Ed25519, vec![index as u8; 32]))
}

fn addrs(index: usize, host: usize) -> Vec<Multiaddr> {
    (0..ADDRS_PER_PEER)
        .map(|offset| {
            let port = 10_000 + ((index * ADDRS_PER_PEER + offset) % 50_000) as u16;
            format!("/ip4/192.0.{host}.{}/udp/{port}/quic-v1", (index % 250) + 1)
                .parse()
                .expect("address")
        })
        .collect()
}

fn agent(beacon_peer_ttl_ms: u64) -> PeerDiscoveryAgent {
    PeerDiscoveryAgent::new(
        peer(usize::MAX),
        PeerDiscoveryConfig {
            auto_dial: false,
            beacon_peer_ttl_ms,
            max_observed_ttl_ms: MDNS_TTL_MS,
            ..PeerDiscoveryConfig::default()
        },
    )
    .expect("valid config")
}

fn populated(ttl_ms: u64) -> PeerDiscoveryAgent {
    let mut agent = agent(ttl_ms);
    for index in 0..PEERS {
        agent.observe_beacon(
            Observation {
                peer: peer(index),
                addrs: addrs(index, 2),
            },
            0,
        );
    }
    agent
}

/// Every peer holds beacon and mDNS records; only the first
/// [`SPARSE_DUE`] peers' sources are old enough to expire at
/// `BEACON_TTL_MS`.
fn sparse() -> PeerDiscoveryAgent {
    let mut agent = agent(BEACON_TTL_MS);
    for index in 0..PEERS {
        let seen_ms = if index < SPARSE_DUE { 0 } else { BEACON_TTL_MS };
        let mdns_ttl_ms = if index < SPARSE_DUE {
            BEACON_TTL_MS
        } else {
            MDNS_TTL_MS
        };
        agent.observe_beacon(
            Observation {
                peer: peer(index),
                addrs: addrs(index, 2),
            },
            seen_ms,
        );
        agent.observe_mdns(
            peer(index),
            addrs(index, 3)
                .into_iter()
                .map(|addr| (addr, mdns_ttl_ms))
                .collect(),
            0,
        );
    }
    while agent.poll_event().is_some() {}
    agent
}

/// The populated book keeps its undrained discoveries, as before this
/// bench moved setup out of the measurement.
fn assert_idle(agent: PeerDiscoveryAgent) {
    assert_eq!(agent.pending_event_count(), PEERS);
    assert_eq!(agent.known_peers().len(), PEERS);
}

/// Expiring every undrained discovery cancels it instead of queueing an expiry.
fn assert_all_expired(agent: PeerDiscoveryAgent) {
    assert_eq!(agent.pending_event_count(), 0);
    assert!(agent.known_peers().is_empty());
}

fn assert_sparse_expired(mut agent: PeerDiscoveryAgent) {
    let mut expired = 0;
    while let Some(event) = agent.poll_event() {
        assert!(matches!(event, DiscoveryEvent::PeerExpired { .. }));
        expired += 1;
    }
    assert_eq!(expired, SPARSE_DUE);
    assert_eq!(agent.known_peers().len(), PEERS - SPARSE_DUE);
}

#[library_benchmark]
#[bench::tick_active(args = (u64::MAX / 2), setup = populated, teardown = assert_idle)]
fn tick_active(mut agent: PeerDiscoveryAgent) -> PeerDiscoveryAgent {
    agent.handle_tick(black_box(1));
    agent
}

#[library_benchmark]
#[bench::tick_expire(args = (1), setup = populated, teardown = assert_all_expired)]
fn tick_expire(mut agent: PeerDiscoveryAgent) -> PeerDiscoveryAgent {
    agent.handle_tick(black_box(1));
    black_box(agent.pending_event_count());
    agent
}

#[library_benchmark]
#[bench::tick_expire_sparse(setup = sparse, teardown = assert_sparse_expired)]
fn tick_expire_sparse(mut agent: PeerDiscoveryAgent) -> PeerDiscoveryAgent {
    agent.handle_tick(black_box(BEACON_TTL_MS));
    black_box(agent.pending_event_count());
    agent
}

#[library_benchmark]
#[bench::next_deadline(args = (u64::MAX / 2), setup = populated, teardown = assert_idle)]
fn next_deadline(agent: PeerDiscoveryAgent) -> PeerDiscoveryAgent {
    black_box(agent.next_deadline(black_box(Now::from_millis(1))));
    agent
}

library_benchmark_group!(
    name = benches;
    benchmarks = tick_active, tick_expire, tick_expire_sparse, next_deadline
);
gungraun::main!(library_benchmark_groups = benches);
