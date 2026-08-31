use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use minip2p_core::{Multiaddr, PeerId};
use minip2p_discovery::{Observation, PeerDiscoveryAgent, PeerDiscoveryConfig};
use minip2p_identity::{KeyType, PublicKey};
use std::hint::black_box;

const PEERS: usize = 128;
const ADDRS_PER_PEER: usize = 16;

fn peer(index: usize) -> PeerId {
    PeerId::from_public_key(&PublicKey::new(KeyType::Ed25519, vec![index as u8; 32]))
}

fn addrs(index: usize) -> Vec<Multiaddr> {
    (0..ADDRS_PER_PEER)
        .map(|offset| {
            let port = 10_000 + ((index * ADDRS_PER_PEER + offset) % 50_000) as u16;
            format!("/ip4/192.0.2.{}/udp/{port}/quic-v1", (index % 250) + 1)
                .parse()
                .expect("valid benchmark address")
        })
        .collect()
}

fn populated(ttl_ms: u64) -> PeerDiscoveryAgent {
    let config = PeerDiscoveryConfig {
        auto_dial: false,
        beacon_peer_ttl_ms: ttl_ms,
        ..PeerDiscoveryConfig::default()
    };
    let mut agent = PeerDiscoveryAgent::new(peer(usize::MAX), config).expect("valid config");
    for index in 0..PEERS {
        agent.observe_beacon(
            Observation {
                peer: peer(index),
                addrs: addrs(index),
            },
            0,
        );
    }
    agent
}

fn peer_book(c: &mut Criterion) {
    let mut active = populated(u64::MAX / 2);
    let mut group = c.benchmark_group("peer_book_128_peers_16_addrs");
    group.bench_function("tick_active", |b| {
        b.iter(|| active.handle_tick(black_box(1)));
    });
    group.bench_function("tick_expire", |b| {
        b.iter_batched(
            || populated(1),
            |mut agent| {
                agent.handle_tick(black_box(1));
                black_box(agent.pending_event_count());
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("next_timeout", |b| {
        b.iter(|| black_box(active.next_timeout(black_box(1))));
    });
    group.finish();
}

criterion_group!(benches, peer_book);
criterion_main!(benches);
