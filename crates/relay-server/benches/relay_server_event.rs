use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use minip2p_core::PeerId;
use minip2p_platform::Now;
use minip2p_relay::HOP_PROTOCOL_ID;
use minip2p_relay_server::{RelayServerAgent, RelayServerConfig};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, StreamId};

const PEERS: u64 = 128;
const EVENTS_PER_BATCH: usize = 100;

fn populated_agent(now: Now) -> (RelayServerAgent, SwarmEvent) {
    let local = PeerId::from_public_key_protobuf(b"relay-server-bench-local");
    let mut agent = RelayServerAgent::new(local, RelayServerConfig::default())
        .expect("default relay server configuration is valid");

    for index in 0..PEERS {
        let peer = PeerId::from_public_key_protobuf(&index.to_le_bytes());
        let conn_id = ConnectionId::new(index + 1);
        let stream_id = StreamId::new(1);
        agent.handle_event(
            &SwarmEvent::ConnectionEstablished {
                peer_id: peer.clone(),
                conn_id,
            },
            false,
            Now::from_millis(0),
        );
        assert!(agent.handle_event(
            &SwarmEvent::StreamReady {
                peer_id: peer,
                conn_id,
                stream_id,
                protocol_id: HOP_PROTOCOL_ID.into(),
                initiated_locally: false,
            },
            false,
            Now::from_millis(0),
        ));
    }

    agent.handle_tick(now);
    let inert = SwarmEvent::StreamData {
        peer_id: PeerId::from_public_key_protobuf(b"relay-server-bench-unrelated"),
        conn_id: ConnectionId::new(PEERS + 1),
        stream_id: StreamId::new(1),
        data: Vec::new(),
    };
    (agent, inert)
}

fn relay_server_event(c: &mut Criterion) {
    let now = Now::from_millis(1);
    c.bench_function("relay_handle_event_same_now_128_pending_hops", |b| {
        b.iter_batched(
            || populated_agent(now),
            |(mut agent, inert)| {
                for _ in 0..EVENTS_PER_BATCH {
                    black_box(agent.handle_event(black_box(&inert), false, black_box(now)));
                }
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, relay_server_event);
criterion_main!(benches);
