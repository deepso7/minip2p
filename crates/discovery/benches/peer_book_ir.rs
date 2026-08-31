use gungraun::prelude::*;
use minip2p_core::{Multiaddr, PeerId};
use minip2p_discovery::{Observation, PeerDiscoveryAgent, PeerDiscoveryConfig};
use minip2p_identity::{KeyType, PublicKey};
use std::hint::black_box;

const PEERS: usize = 128;
const ADDRS_PER_PEER: usize = 16;

fn peer(index: usize) -> PeerId {
    PeerId::from_public_key(&PublicKey::new(KeyType::Ed25519, vec![index as u8; 32]))
}

fn populated(ttl_ms: u64) -> PeerDiscoveryAgent {
    let mut agent = PeerDiscoveryAgent::new(
        peer(usize::MAX),
        PeerDiscoveryConfig {
            auto_dial: false,
            beacon_peer_ttl_ms: ttl_ms,
            ..PeerDiscoveryConfig::default()
        },
    )
    .expect("valid config");
    for index in 0..PEERS {
        let addrs: Vec<Multiaddr> = (0..ADDRS_PER_PEER)
            .map(|offset| {
                let port = 10_000 + ((index * ADDRS_PER_PEER + offset) % 50_000) as u16;
                format!("/ip4/192.0.2.{}/udp/{port}/quic-v1", (index % 250) + 1)
                    .parse()
                    .expect("address")
            })
            .collect();
        agent.observe_beacon(
            Observation {
                peer: peer(index),
                addrs,
            },
            0,
        );
    }
    agent
}

#[library_benchmark]
#[bench::tick_active(populated(u64::MAX / 2))]
fn tick_active(mut agent: PeerDiscoveryAgent) {
    agent.handle_tick(black_box(1));
}

#[library_benchmark]
#[bench::tick_expire(populated(1))]
fn tick_expire(mut agent: PeerDiscoveryAgent) {
    agent.handle_tick(black_box(1));
    black_box(agent.pending_event_count());
}

#[library_benchmark]
#[bench::next_timeout(populated(u64::MAX / 2))]
fn next_timeout(agent: PeerDiscoveryAgent) {
    black_box(agent.next_timeout(black_box(1)));
}

library_benchmark_group!(name = benches; benchmarks = tick_active, tick_expire, next_timeout);
gungraun::main!(library_benchmark_groups = benches);
