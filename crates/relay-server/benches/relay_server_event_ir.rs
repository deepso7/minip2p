use gungraun::prelude::*;
use minip2p_core::PeerId;
use minip2p_platform::Now;
use minip2p_relay::HOP_PROTOCOL_ID;
use minip2p_relay_server::{RelayServerAgent, RelayServerConfig};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, StreamId};
use std::hint::black_box;

const PEERS: u64 = 128;
const EVENTS_PER_BATCH: usize = 100;

fn populated_agent() -> (RelayServerAgent, SwarmEvent, Now) {
    let now = Now::from_millis(1);
    let mut agent = RelayServerAgent::new(
        PeerId::from_public_key_protobuf(b"relay-server-bench-local"),
        RelayServerConfig::default(),
    )
    .expect("valid config");
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
            Now::from_millis(0)
        ));
    }
    agent.handle_tick(now);
    let event = SwarmEvent::StreamData {
        peer_id: PeerId::from_public_key_protobuf(b"relay-server-bench-unrelated"),
        conn_id: ConnectionId::new(PEERS + 1),
        stream_id: StreamId::new(1),
        data: Vec::new(),
    };
    (agent, event, now)
}

#[library_benchmark]
#[bench::relay_handle_event_same_now_128_pending_hops(populated_agent())]
fn relay_event(input: (RelayServerAgent, SwarmEvent, Now)) {
    let (mut agent, event, now) = input;
    for _ in 0..EVENTS_PER_BATCH {
        black_box(agent.handle_event(black_box(&event), false, black_box(now)));
    }
}

library_benchmark_group!(name = benches; benchmarks = relay_event);
gungraun::main!(library_benchmark_groups = benches);
